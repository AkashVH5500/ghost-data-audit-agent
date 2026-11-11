"""Evidence normalisation.

Every supported evidence format (SQL snapshots with replicas, JSON bundles, service
exports, ledgers, structured logs, text handovers, and transcribed media) is turned into a
flat list of :class:`Obs` observations:

    "At time ``ts`` evidence file ``file_id`` showed resource ``rid`` of ``kind`` in
     ``state`` and tied to these identity ``tokens``."

The module is purely descriptive; deciding whether a state is compliant happens in
``policy.py``.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .logparse import parse_log
from .util import (name_token, norm_phone, parse_ts, tokens_from_text,
                   tokens_from_values)

# --------------------------------------------------------------------------------------
# vocabulary
# --------------------------------------------------------------------------------------

PREFIX_SYSTEM = [
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("support_", "support_platform"),
    ("analytics_", "analytics_platform"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("data_flow_", "integration_service"),
    ("audit_record_", "security_service"),
    ("tombstone_", "identity_service"),
    ("legal_hold_", "legal_service"),
    ("marketing_", "marketing_platform"),
    ("email_delivery_", "email_delivery_service"),
    ("cache_", "cache_service"),
    ("object_", "object_storage"),
    ("telemetry_", "telemetry_service"),
]

SYSTEM_KIND = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "export_service": "USER_EXPORT",
    "backup_service": "BACKUP_ARCHIVE",
    "integration_service": "DATA_FLOW",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "legal_service": "LEGAL_HOLD_RECORD",
    "marketing_platform": "MARKETING_PROFILE",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "cache_service": "CACHE_ENTRY",
    "object_storage": "SUPPORT_ATTACHMENT",
    "telemetry_service": "PRODUCT_TELEMETRY",
}


def system_for(rid: str) -> Optional[str]:
    for p, s in PREFIX_SYSTEM:
        if rid.startswith(p):
            return s
    return None


@dataclass
class Obs:
    file_id: str
    ts: str                      # ISO time at which the state was observed
    system: str
    rid: str
    kind: str
    state: str                   # vocabulary: see STATE_RANK
    tokens: Set[str] = field(default_factory=set)
    weak: Set[str] = field(default_factory=set)   # names (never used to link on their own)
    meta: Dict[str, str] = field(default_factory=dict)
    seq: int = 0                 # position among this file's observations of the same system

    def key(self):
        return (self.system, self.rid)


# "worse" states win when two copies of one record are seen in the same snapshot
STATE_RANK = {
    "FOUND": 5, "IDENTIFIABLE": 5, "ACTIVE": 5,
    "REDACTED": 2, "ANONYMIZED": 2, "BLOCKED": 2, "DISABLED": 2,
    "NOT_FOUND": 0,
}

LEDGER_STATES = {"FOUND", "NOT_FOUND", "IDENTIFIABLE", "REDACTED", "ANONYMIZED", "ACTIVE", "BLOCKED", "DISABLED"}


def _truthy(v) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y"):
        return True
    if s in ("false", "0", "no", "n"):
        return False
    return None


def _present(v) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip().lower() not in ("", "null", "none", "[redacted]")
    return True


def _toks(*vals) -> Set[str]:
    out: Set[str] = set()
    for v in vals:
        if isinstance(v, str) and _present(v):
            out |= tokens_from_text(v)
    return out


def _weak(*vals) -> Set[str]:
    out = set()
    for v in vals:
        t = name_token(v) if isinstance(v, str) else None
        if t:
            out.add(t)
    return out


# --------------------------------------------------------------------------------------
# record-level interpreters
# --------------------------------------------------------------------------------------

def ledger_obs(rec: dict, file_id: str, ts: str) -> Optional[Obs]:
    rid = rec.get("resource_id")
    if not rid:
        return None
    system = rec.get("system") or system_for(rid)
    if not system:
        return None
    kind = rec.get("record_type") or SYSTEM_KIND.get(system, "UNKNOWN")
    state = str(rec.get("result") or rec.get("state") or "").upper()
    if state not in LEDGER_STATES:
        return None
    subj = rec.get("subject_reference") or rec.get("lookup_value") or rec.get("subject_ref") or ""
    return Obs(file_id, rec.get("recorded_at") or ts, system, rid, kind, state, _toks(subj))


def record_obs(rec: dict, system: str, collection: str, file_id: str, ts: str) -> Optional[Obs]:
    """Interpret a bundle / replica style record according to its collection."""
    rid = rec.get("resource_id")
    if not rid:
        return None
    col = collection
    if col == "operational_record_history" or "record_type" in rec:
        return ledger_obs(rec, file_id, ts)
    if col == "customer_profiles":
        status = str(rec.get("account_status") or "").upper()
        tk = _toks(rec.get("customer_reference"), rec.get("email"), rec.get("email_hash"), rec.get("phone"))
        return Obs(file_id, ts, "account_service", rid, "USER_PROFILE", "FOUND", tk,
                   _weak(rec.get("full_name")), {"status": status})
    if col == "customer_search_documents":
        d = rec.get("document") or rec
        tk = _toks(d.get("customer_reference"), d.get("email"), d.get("email_hash"), d.get("phone"))
        return Obs(file_id, ts, "search_service", rid, "SEARCH_INDEX_ENTRY", "FOUND", tk,
                   _weak(d.get("display_name")))
    if col == "security_audit_events":
        return Obs(file_id, ts, "security_service", rid, "SECURITY_AUDIT_LOG", "FOUND",
                   _toks(rec.get("subject_reference")), set(), {"retention": rec.get("retention_until", "")})
    if col == "customer_analytics_reports":
        ident = any(_present(rec.get(k)) for k in ("user_id", "email", "phone", "email_hash", "customer_reference"))
        tk = _toks(rec.get("user_id"), rec.get("customer_reference"), rec.get("email"),
                   rec.get("email_hash"), rec.get("phone"))
        return Obs(file_id, ts, "analytics_platform", rid, "ANALYTICS_PROFILE",
                   "IDENTIFIABLE" if ident else "ANONYMIZED", tk)
    if col == "connector_configurations":
        en = _truthy(rec.get("enabled"))
        return Obs(file_id, ts, "integration_service", rid, "DATA_FLOW", "ACTIVE" if en else "DISABLED",
                   _toks(rec.get("subject_selector")))
    if col == "support_conversations":
        text = rec.get("message_text") or ""
        found = tokens_from_text(text)
        red = ("[redacted]" in text.lower()) and not found
        tk = _toks(rec.get("subject_reference")) | found
        return Obs(file_id, ts, "support_platform", rid, "SUPPORT_MESSAGE",
                   "REDACTED" if red else "IDENTIFIABLE", tk)
    if col == "ticket_attachments":
        return Obs(file_id, ts, "support_platform", rid, "SUPPORT_ATTACHMENT", "FOUND",
                   _toks(rec.get("uploaded_by"), rec.get("subject_reference")))
    if col == "backup_catalog":
        ra = _truthy(rec.get("restore_allowed"))
        return Obs(file_id, ts, "backup_service", rid, "BACKUP_ARCHIVE", "ACTIVE" if ra else "BLOCKED",
                   _toks(rec.get("subject_reference")))
    if col == "customer_export_jobs":
        av = _truthy(rec.get("download_available"))
        return Obs(file_id, ts, "export_service", rid, "USER_EXPORT", "FOUND" if av is not False else "NOT_FOUND",
                   _toks(rec.get("owner_email"), rec.get("customer_reference")))
    if col == "retained_order_records":
        return Obs(file_id, ts, "legal_service", rid, "LEGAL_HOLD_RECORD", "FOUND",
                   _toks(rec.get("subject_reference")), set(), {"retained_until": rec.get("retained_until", "")})
    if col == "deleted_customer_references":
        ident = any(_present(rec.get(k)) for k in ("name", "email", "phone", "email_hash"))
        tk = _toks(rec.get("subject_reference"), rec.get("email"), rec.get("email_hash"), rec.get("phone"))
        return Obs(file_id, ts, "identity_service", rid, "ACCOUNT_TOMBSTONE",
                   "IDENTIFIABLE" if ident else "REDACTED", tk, _weak(rec.get("name")))
    return None


def service_export_obs(sysname: str, coll: str, rec: dict, file_id: str, default_ts: str) -> List[Obs]:
    ts = rec.get("observed_at") or default_ts
    rid = rec.get("resource_id")
    out: List[Obs] = []
    if coll == "profile_lookups":
        prof = rec.get("profile") or {}
        absent = rec.get("status_code") == 404 or not prof
        tk = _toks(*(prof.get(k) for k in ("customer_reference", "email", "email_hash", "phone")))
        out.append(Obs(file_id, ts, "account_service", rid, "USER_PROFILE",
                       "NOT_FOUND" if absent else "FOUND", tk, _weak(prof.get("full_name"))))
    elif coll == "profiles":
        ident = any(_present(rec.get(k)) for k in ("customer_reference", "email", "email_hash", "phone"))
        tk = _toks(*(rec.get(k) for k in ("customer_reference", "email", "email_hash", "phone")))
        out.append(Obs(file_id, ts, "analytics_platform", rid, "ANALYTICS_PROFILE",
                       "IDENTIFIABLE" if ident else "ANONYMIZED", tk))
    elif coll == "restore_entries":
        ra = _truthy(rec.get("restore_allowed"))
        tk = _toks(rec.get("customer_email"), rec.get("customer_reference"))
        out.append(Obs(file_id, ts, "backup_service", rid, "BACKUP_ARCHIVE", "ACTIVE" if ra else "BLOCKED", tk))
    elif coll == "exports":
        out.append(Obs(file_id, ts, "export_service", rid, "USER_EXPORT", "FOUND",
                       _toks(rec.get("owner_email"), rec.get("customer_reference"), rec.get("owner_phone"))))
    elif coll == "connectors":
        en = _truthy(rec.get("enabled"))
        out.append(Obs(file_id, ts, "integration_service", rid, "DATA_FLOW", "ACTIVE" if en else "DISABLED",
                       _toks(rec.get("customer_email"), rec.get("customer_reference"))))
    elif coll == "index_queries":
        docs = (rec.get("hits") or {}).get("documents") or []
        hit = (rec.get("hits") or {}).get("total", len(docs)) > 0
        tk = _toks(rec.get("query"))
        weak = set()
        for d in docs:
            tk |= _toks(*(d.get(k) for k in ("customer_reference", "email", "email_hash", "phone")))
            weak |= _weak(d.get("display_name"))
        out.append(Obs(file_id, ts, "search_service", rid, "SEARCH_INDEX_ENTRY",
                       "FOUND" if hit else "NOT_FOUND", tk, weak))
    elif coll == "audit_records":
        out.append(Obs(file_id, ts, "security_service", rid, "SECURITY_AUDIT_LOG", "FOUND",
                       _toks(rec.get("subject_reference")), set(), {"retention": rec.get("retention_until", "")}))
    elif coll == "tickets":
        ident = any(_present(rec.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
        tk = _toks(rec.get("customer_reference"), rec.get("requester_email"), rec.get("requester_phone"))
        out.append(Obs(file_id, ts, "support_platform", rid, "SUPPORT_MESSAGE",
                       "IDENTIFIABLE" if ident else "REDACTED", tk, _weak(rec.get("requester_name"))))
    return out


# --------------------------------------------------------------------------------------
# file-level extractors
# --------------------------------------------------------------------------------------

def from_json(path: str, file_id: str, captured: str) -> List[Obs]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        doc = json.load(fh)
    out: List[Obs] = []
    if isinstance(doc, dict) and "snapshots" in doc:
        for snap in doc["snapshots"]:
            ts = snap.get("captured_at") or captured
            ds = snap.get("data_store", "")
            if ds in SYSTEM_KIND:      # a complete listing of the store: absence from it is meaningful
                out.append(Obs(file_id, ts, ds, "__scope__", "SCOPE", "FOUND"))
            for rec in snap.get("records", []):
                o = record_obs(rec, snap.get("data_store", ""), snap.get("collection", ""), file_id, ts)
                if o:
                    out.append(o)
    elif isinstance(doc, dict) and "service_exports" in doc:
        for sysname, colls in doc["service_exports"].items():
            for coll, recs in colls.items():
                for rec in recs:
                    out.extend(service_export_obs(sysname, coll, rec, file_id, doc.get("exported_at", captured)))
    elif isinstance(doc, dict) and isinstance(doc.get("records"), list):
        ts = doc.get("captured_at") or doc.get("exported_at") or captured
        for rec in doc["records"]:
            if "record_type" in rec:
                o = ledger_obs(rec, file_id, ts)
            else:
                coll = doc.get("collection", "")
                o = record_obs(rec, doc.get("source", ""), coll, file_id, ts)
            if o:
                out.append(o)
    return out


def from_sql(path: str, file_id: str, captured: str) -> List[Obs]:
    text = open(path, encoding="utf-8", errors="replace").read()
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    try:
        con.executescript(text)
    except sqlite3.Error:
        # tolerate partial scripts: execute statement by statement
        for stmt in text.split(";\n"):
            try:
                con.execute(stmt)
            except sqlite3.Error:
                pass
    m = re.search(r"Captured at:\s*(\S+)", text) or re.search(r"snapshot_completed_at=(\S+)", text)
    cap = m.group(1) if m else captured
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope: Dict[str, str] = {}
    if "snapshot_scope" in tables:
        scope = {r[0]: r[1] for r in con.execute("select origin_system, captured_at from snapshot_scope")}
    out: List[Obs] = []
    for t in tables:
        cols = [r[1] for r in con.execute(f"pragma table_info({t})")]
        rows = [dict(r) for r in con.execute(f"select * from {t}")]
        if t == "snapshot_scope":
            continue
        if "record_json" in cols:
            for r in rows:
                try:
                    rec = json.loads(r["record_json"])
                except ValueError:
                    continue
                o = record_obs(rec, r.get("origin_system", ""), r.get("collection_name", ""), file_id,
                               r.get("updated_at") or cap)
                if o:
                    o.meta["table"] = t
                    out.append(o)
        elif t.startswith("customer_profiles"):
            for r in rows:
                out.append(Obs(file_id, r.get("updated_at") or cap, "account_service", r["resource_id"], "USER_PROFILE",
                               "FOUND", _toks(r.get("customer_reference"), r.get("user_id"), r.get("email"),
                                              r.get("email_hash"), r.get("phone")),
                               _weak(r.get("full_name")), {"status": str(r.get("account_status")), "table": t}))
        elif t == "customer_search_documents":
            for r in rows:
                out.append(Obs(file_id, r["updated_at"], "search_service", r["resource_id"], "SEARCH_INDEX_ENTRY", "FOUND",
                               _toks(r.get("customer_reference"), r.get("email"), r.get("email_hash"), r.get("phone")),
                               _weak(r.get("display_name")), {"table": t}))
        elif t == "search_documents_primary":
            for r in rows:
                out.append(Obs(file_id, r.get("indexed_at") or cap, "search_service", r["resource_id"], "SEARCH_INDEX_ENTRY",
                               "FOUND", _toks(r.get("email"), r.get("source_resource_id")),
                               _weak(r.get("display_name")), {"source": str(r.get("source_resource_id"))}))
        elif t == "customer_analytics_profiles":
            for r in rows:
                ident = any(_present(r.get(k)) for k in ("customer_reference", "email", "phone", "email_hash"))
                out.append(Obs(file_id, r["updated_at"], "analytics_platform", r["resource_id"], "ANALYTICS_PROFILE",
                               "IDENTIFIABLE" if ident else "ANONYMIZED",
                               _toks(r.get("customer_reference"), r.get("email"), r.get("email_hash"), r.get("phone"))))
        elif t == "support_records":
            for r in rows:
                ident = any(_present(r.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
                out.append(Obs(file_id, r["updated_at"], "support_platform", r["resource_id"], "SUPPORT_MESSAGE",
                               "IDENTIFIABLE" if ident else "REDACTED",
                               _toks(r.get("customer_reference"), r.get("requester_email"), r.get("requester_phone")),
                               _weak(r.get("requester_name"))))
        elif t == "customer_exports":
            for r in rows:
                out.append(Obs(file_id, r["updated_at"], "export_service", r["resource_id"], "USER_EXPORT", "FOUND",
                               _toks(r.get("customer_reference"), r.get("owner_email"), r.get("owner_phone"))))
        elif t == "connector_subscriptions":
            for r in rows:
                out.append(Obs(file_id, r["updated_at"], "integration_service", r["resource_id"], "DATA_FLOW",
                               "ACTIVE" if _truthy(r.get("enabled")) else "DISABLED",
                               _toks(r.get("customer_reference"), r.get("customer_email"))))
        elif t == "backup_restore_entries":
            for r in rows:
                out.append(Obs(file_id, r["updated_at"], "backup_service", r["resource_id"], "BACKUP_ARCHIVE",
                               "ACTIVE" if _truthy(r.get("restore_allowed")) else "BLOCKED",
                               _toks(r.get("customer_reference"), r.get("customer_email"))))
        elif t == "security_audit_records":
            for r in rows:
                out.append(Obs(file_id, r["updated_at"], "security_service", r["resource_id"], "SECURITY_AUDIT_LOG", "FOUND",
                               _toks(r.get("subject_reference")), set(), {"retention": str(r.get("retention_until"))}))
    # record per-system snapshot scope as pseudo-observations (used for absence inference)
    for sysname, ts in scope.items():
        out.append(Obs(file_id, ts, sysname, "__scope__", "SCOPE", "FOUND"))
    # tables present => coverage for absence inference
    for t in tables:
        sysname = {
            "customer_profiles": "account_service", "customer_search_documents": "search_service",
            "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
            "customer_exports": "export_service", "connector_subscriptions": "integration_service",
            "backup_restore_entries": "backup_service", "security_audit_records": "security_service",
            "search_documents_primary": "search_service",
        }.get(t)
        if t.startswith("customer_profiles") and not sysname:
            sysname = "account_service"
        if sysname and not any(o.rid == "__scope__" and o.system == sysname for o in out):
            out.append(Obs(file_id, cap, sysname, "__scope__", "SCOPE", "FOUND"))
    if any("record_json" in [r[1] for r in con.execute(f"pragma table_info({t})")] for t in tables):
        origins = {o.system for o in out if o.rid != "__scope__"}
        # collection coverage of replica snapshots
        for sysname in {r[0] for t in tables if "record_json" in [c[1] for c in con.execute(f"pragma table_info({t})")]
                        for r in con.execute(f"select distinct origin_system from {t}")}:
            if not any(o.rid == "__scope__" and o.system == sysname for o in out):
                out.append(Obs(file_id, cap, sysname, "__scope__", "SCOPE", "FOUND"))
        if "customer_data_primary" in tables or any("replica" in t for t in tables):
            for sysname in ("account_service", "search_service", "analytics_platform", "support_platform",
                            "security_service", "integration_service", "backup_service", "export_service"):
                if not any(o.rid == "__scope__" and o.system == sysname for o in out):
                    out.append(Obs(file_id, cap, sysname, "__scope__", "SCOPE", "FOUND"))
    return out


def from_ledger_text(path: str, file_id: str, captured: str) -> List[Obs]:
    """Plain-text handover: ``ts | system | resource | TYPE | RESULT | subject``"""
    out: List[Obs] = []
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = [p.strip() for p in line.strip().lstrip("-").split("|")]
        if len(parts) >= 6 and parse_ts(parts[0]):
            ts, system, rid, kind, result, subject = parts[:6]
            if result.upper() in LEDGER_STATES:
                out.append(Obs(file_id, ts, system, rid, kind, result.upper(), _toks(subject)))
    return out


# --------------------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------------------

def _first(rec: dict, *keys) -> Optional[str]:
    for k in keys:
        v = rec.get(k)
        if v is not None and str(v).strip() != "":
            return str(v)
    return None


def from_log(path: str, file_id: str, captured: str) -> List[Obs]:
    recs = parse_log(open(path, encoding="utf-8", errors="replace").read())
    out: List[Obs] = []
    # correlate request/trace ids: lookup_key from *_started lines applies to later lines
    trace_tokens: Dict[str, Set[str]] = {}
    for r in recs:
        tid = r.get("trace_id") or r.get("requestId")
        if tid:
            # any field of any line in the trace may carry the subject key (lookup_key, subject_ref,
            # subject_key, owner_key, ...), so collect identity tokens from every value
            vals = [v for k, v in r.items() if k not in ("message_text", "_line", "ts") and isinstance(v, str)]
            trace_tokens.setdefault(tid, set()).update(_toks(*vals))
    for r in recs:
        ev = r.get("event", "")
        rid = r.get("resource_id")
        ts = r.get("ts") or captured
        if ev == "record_lookup":
            o = ledger_obs({"resource_id": rid, "system": r.get("system"), "record_type": r.get("record_type"),
                            "result": r.get("result"), "subject_reference": r.get("subject_reference"),
                            "recorded_at": ts}, file_id, ts)
            if o:
                out.append(o)
            continue
        if not rid or ev.endswith("_started"):
            continue
        tid = r.get("trace_id") or r.get("requestId")
        tk = set(trace_tokens.get(tid, set())) if tid else set()
        tk |= _toks(*(r.get(k) for k in ("lookup_key", "correlation_key", "customer_email", "customer_reference",
                                         "email", "phone", "email_hash", "owner_email", "requester_email",
                                         "requester_phone", "subject_reference", "subject_ref", "matched_value",
                                         "query", "match_key")))
        weak = _weak(r.get("requester_name"))
        sysname = system_for(rid)
        o: Optional[Obs] = None
        if ev == "profile_lookup_completed":
            absent = r.get("rows") == "0" or r.get("http_status") == "404"
            o = Obs(file_id, ts, "account_service", rid, "USER_PROFILE", "NOT_FOUND" if absent else "FOUND", tk, weak)
        elif ev == "index_query_completed":
            miss = (r.get("result", "").lower() in ("miss", "none", "empty")) or r.get("total_hits") == "0"
            o = Obs(file_id, ts, "search_service", rid, "SEARCH_INDEX_ENTRY", "NOT_FOUND" if miss else "FOUND", tk)
        elif ev == "message_pii_scan":
            o = Obs(file_id, ts, "support_platform", rid, "SUPPORT_MESSAGE", "IDENTIFIABLE", tk)
        elif ev == "attachment_pii_scan":
            o = Obs(file_id, ts, "support_platform", rid, "SUPPORT_ATTACHMENT", "FOUND", tk, set(),
                    {"file": r.get("file", "")})
        elif ev == "message_read":
            text = r.get("message_text", "")
            found = tokens_from_text(text)
            red = "[redacted]" in text.lower() and not found
            o = Obs(file_id, ts, "support_platform", rid, "SUPPORT_MESSAGE", "REDACTED" if red else "IDENTIFIABLE",
                    tk | found)
        elif ev == "support_ticket_read_completed":
            ident = any(_present(r.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
            o = Obs(file_id, ts, "support_platform", rid, "SUPPORT_MESSAGE", "IDENTIFIABLE" if ident else "REDACTED",
                    tk, weak)
        elif ev == "contact_query_completed" and rid.startswith("support_"):
            o = Obs(file_id, ts, "support_platform", rid, "SUPPORT_ATTACHMENT",
                    "FOUND" if r.get("rows") not in ("0", None) else "NOT_FOUND", tk)
        elif ev in ("connector_heartbeat", "connector_config_loaded", "connector_config_read_completed"):
            en = _truthy(r.get("enabled"))
            o = Obs(file_id, ts, "integration_service", rid, "DATA_FLOW", "ACTIVE" if en else "DISABLED", tk)
        elif ev == "audit_record_read_completed":
            o = Obs(file_id, ts, "security_service", rid, "SECURITY_AUDIT_LOG",
                    "NOT_FOUND" if r.get("rows") == "0" else "FOUND", tk, set(),
                    {"retention": r.get("retention_until", "")})
        elif ev == "analytics_identity_scan":
            o = Obs(file_id, ts, "analytics_platform", rid, "ANALYTICS_PROFILE", "IDENTIFIABLE", tk)
        elif ev == "analytics_profile_read":
            ident = r.get("direct_identifiers") not in ("0", None) or _present(r.get("email")) or _present(r.get("phone"))
            o = Obs(file_id, ts, "analytics_platform", rid, "ANALYTICS_PROFILE", "IDENTIFIABLE" if ident else "ANONYMIZED", tk)
        elif ev == "analytics_profile_read_completed":
            ident = any(_present(r.get(k)) for k in ("customer_reference", "email", "phone", "email_hash"))
            o = Obs(file_id, ts, "analytics_platform", rid, "ANALYTICS_PROFILE", "IDENTIFIABLE" if ident else "ANONYMIZED", tk)
        elif ev == "contact_lookup_completed":
            o = Obs(file_id, ts, "analytics_platform", rid, "MARKETING_PROFILE",
                    "NOT_FOUND" if r.get("rows") == "0" else "FOUND", tk)
        elif ev == "restore_candidate_evaluated":
            el = _truthy(r.get("eligible"))
            blk = _truthy(r.get("deletion_block"))
            o = Obs(file_id, ts, "backup_service", rid, "BACKUP_ARCHIVE", "ACTIVE" if (el and not blk) else "BLOCKED", tk)
        elif ev == "restore_authorization_completed":
            allow = (r.get("decision", "").lower() in ("allow", "allowed", "permit", "grant"))
            o = Obs(file_id, ts, "backup_service", rid, "BACKUP_ARCHIVE", "ACTIVE" if allow else "BLOCKED", tk)
        elif ev == "restore_policy_read_completed":
            o = Obs(file_id, ts, "backup_service", rid, "BACKUP_ARCHIVE",
                    "ACTIVE" if _truthy(r.get("restore_allowed")) else "BLOCKED", tk)
        elif ev in ("export_download_check_completed", "export_metadata_read_completed"):
            av = _truthy(r.get("available"))
            o = Obs(file_id, ts, "export_service", rid, "USER_EXPORT", "FOUND" if av is not False else "NOT_FOUND", tk)
        if o is not None:
            out.append(o)
    # lines that carry just a profile lookup without trace tokens remain unlinked (orphans)
    return out


# --------------------------------------------------------------------------------------
# corpus loader
# --------------------------------------------------------------------------------------

@dataclass
class EvidenceFile:
    file_id: str
    path: str
    origin: str
    captured_at: str


def load_manifest(dataset_dir: str) -> List[EvidenceFile]:
    rows = []
    with open(os.path.join(dataset_dir, "evidence_files.csv"), newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append(EvidenceFile(r["file_id"], r["file_path"], r["origin"], r["captured_at"]))
    return rows


def load_observations(dataset_dir: str, media_cache: Optional[Dict[str, List[dict]]] = None):
    """Return (observations, manifest). ``media_cache`` maps file_id -> transcribed ledger rows."""
    manifest = load_manifest(dataset_dir)
    obs: List[Obs] = []
    for ef in manifest:
        start = len(obs)
        full = os.path.join(dataset_dir, ef.path)
        if not os.path.exists(full):
            continue
        ext = os.path.splitext(full)[1].lower()
        try:
            if ext == ".json":
                obs.extend(from_json(full, ef.file_id, ef.captured_at))
            elif ext == ".sql":
                obs.extend(from_sql(full, ef.file_id, ef.captured_at))
            elif ext == ".log":
                obs.extend(from_log(full, ef.file_id, ef.captured_at))
            elif ext == ".txt":
                obs.extend(from_ledger_text(full, ef.file_id, ef.captured_at))
        except Exception as exc:  # keep the audit running even if one artefact is malformed
            print(f"[warn] could not parse {ef.file_id} ({ef.path}): {exc}")
        if ext in (".png", ".jpg", ".jpeg", ".pdf") and media_cache:
            for rec in media_cache.get(ef.file_id, []):
                toks = _toks(" ".join(rec.get("identifiers", [])))
                obs.append(Obs(ef.file_id, ef.captured_at, rec["system"], rec["resource_id"], rec["kind"],
                               rec["state"], toks, set(), {"note": rec.get("note", "")}))
        per_system: Dict[str, int] = {}
        for o in obs[start:]:
            o.seq = per_system.get(o.system, 0)
            per_system[o.system] = o.seq + 1
    return obs, manifest
