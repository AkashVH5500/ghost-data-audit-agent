"""Structural validator for ``output.csv`` (no reference answers needed).

Checks every rule of the output contract that can be verified from participant-visible data:

* exact header, one row per request, rows sorted by ``case_id``
* ``deletion_status`` vocabulary; ``NOT_APPLICABLE`` <=> ``steps_json == []``
* each step has exactly the seven fields, ``step_no`` 1..n, phase/operation/state vocabulary
* phase order FINDING -> REMEDIATION -> VERIFICATION; inside a phase the documented operation
  order, then ``system_id``, then ``resource_id`` ascending
* ``COMPLETE``: only VERIFICATION steps, every one citing evidence captured at/before ``audit_at``
* ``INCOMPLETE``: findings cite evidence captured at/before ``audit_at``; remediation and
  verification steps use an empty ``evidence_id``; every finding has a remediation step and every
  remediated record has a verification step
* no cited evidence id is unknown to ``evidence_files.csv`` / ``system_activity.csv`` / ``user_audit_log.csv``

Usage: python3 code/evaluation/validate.py [--output PATH] [--requests PATH]
Exit status is non-zero when any violation is found.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "code"))

from ghost.policy import FINDING_ORDER, OP_STATE, REMEDIATION_ORDER, VERIFICATION_ORDER  # noqa: E402
from ghost.util import parse_ts  # noqa: E402

FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
ORDER = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER, "VERIFICATION": VERIFICATION_ORDER}
PHASE_OF = {op: ph for ph, ops in ORDER.items() for op in ops}
FIND_TO_REM = {
    "REPORT_REMAINING_RECORD": "DELETE_RECORD", "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE",
}
REM_TO_VER = {
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def validate(output_path, requests_path, dataset):
    errors = []
    reqs = {r["case_id"]: r for r in load_csv(requests_path)}
    with open(output_path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(fh)
        header = next(rd)
        rows = list(rd)
    if header != ["case_id", "deletion_status", "steps_json"]:
        errors.append(f"bad header {header}")
    ids = [r[0] for r in rows]
    if ids != sorted(ids):
        errors.append("rows are not sorted by case_id")
    if len(ids) != len(set(ids)):
        errors.append("duplicate case_id rows")
    if set(ids) != set(reqs):
        errors.append(f"case_id mismatch: missing={sorted(set(reqs) - set(ids))[:5]} extra={sorted(set(ids) - set(reqs))[:5]}")
    manifest = {r["file_id"]: parse_ts(r["captured_at"]) for r in load_csv(os.path.join(dataset, "evidence_files.csv"))}
    acts = {r["activity_id"]: parse_ts(r["event_time"]) for r in load_csv(os.path.join(dataset, "system_activity.csv"))}
    audits = {r["audit_id"]: parse_ts(r["event_time"]) for r in load_csv(os.path.join(dataset, "user_audit_log.csv"))}
    known = {**manifest, **acts, **audits}

    for cid, status, blob in rows:
        e = lambda m: errors.append(f"{cid}: {m}")
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            e(f"bad status {status}")
        try:
            steps = json.loads(blob)
        except ValueError:
            e("steps_json is not valid JSON")
            continue
        if not isinstance(steps, list):
            e("steps_json is not an array")
            continue
        if (status == "NOT_APPLICABLE") != (steps == []):
            e("NOT_APPLICABLE must be exactly the empty array (and only it)")
        if status == "INCOMPLETE" and not steps:
            e("INCOMPLETE without any step")
        req = reqs.get(cid)
        audit_dt = parse_ts(req["audit_at"]) if req else None
        prev_key = None
        for i, s in enumerate(steps, 1):
            if set(s) != FIELDS:
                e(f"step {i}: fields {sorted(s)}")
                continue
            if s["step_no"] != i:
                e(f"step {i}: step_no {s['step_no']}")
            op, ph = s["operation"], s["phase"]
            if PHASE_OF.get(op) != ph:
                e(f"step {i}: operation {op} not allowed in phase {ph}")
            if OP_STATE.get(op) != s["state"]:
                e(f"step {i}: state {s['state']} does not match {op}")
            key = (PHASES.index(ph) if ph in PHASES else 9, ORDER.get(ph, []).index(op) if op in ORDER.get(ph, []) else 9,
                   s["system_id"], s["resource_id"])
            if prev_key and key < prev_key:
                e(f"step {i}: out of order ({key} after {prev_key})")
            prev_key = key
            ev = s["evidence_id"]
            if status == "COMPLETE":
                if ph != "VERIFICATION":
                    e(f"step {i}: COMPLETE contains a {ph} step")
                if not ev:
                    e(f"step {i}: COMPLETE verification without evidence")
            if status == "INCOMPLETE" and ph != "FINDING" and ev:
                e(f"step {i}: {ph} step must have empty evidence_id")
            if status == "INCOMPLETE" and ph == "FINDING" and not ev:
                e(f"step {i}: finding without evidence")
            if ev:
                if ev not in known:
                    e(f"step {i}: unknown evidence id {ev}")
                elif audit_dt and known[ev] and known[ev] > audit_dt:
                    e(f"step {i}: evidence {ev} was recorded after audit_at")
        if status == "INCOMPLETE":
            have = {(s["phase"], s["operation"], s["system_id"], s["resource_id"]) for s in steps if set(s) == FIELDS}
            for ph, op, sy, rid in list(have):
                if op in FIND_TO_REM and ("REMEDIATION", FIND_TO_REM[op], sy, rid) not in have:
                    e(f"finding {op} {sy}/{rid} has no remediation step")
                if ph == "FINDING" and op == "REPORT_EXPOSED_PII":
                    if not any(("REMEDIATION", r, sy, rid) in have for r in ("REDACT_RECORD", "ANONYMIZE_RECORD")):
                        e(f"finding REPORT_EXPOSED_PII {sy}/{rid} has no redact/anonymize step")
                if ph == "REMEDIATION" and ("VERIFICATION", REM_TO_VER[op], sy, rid) not in have:
                    e(f"remediation {op} {sy}/{rid} has no verification step")
    return errors, len(rows)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--requests", default=os.path.join(ROOT, "dataset", "deletion_requests.csv"))
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    a = ap.parse_args(argv)
    errors, n = validate(a.output, a.requests, a.dataset)
    print(f"validated {n} rows: {len(errors)} violation(s)")
    for m in errors[:50]:
        print("  -", m)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
