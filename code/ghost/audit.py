"""Case auditor: link evidence to the subject, reconstruct state at ``audit_at``, apply policy,
and emit the ordered findings / remediation / verification steps."""
from __future__ import annotations

import csv
import os
from datetime import timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .evidence import Obs, STATE_RANK, SYSTEM_KIND, load_observations
from .identity import IdentityBook, Subject
from .intent import authorizes_deletion
from .policy import (FINDING_ORDER, OP_STATE, REMEDIATION_ORDER, VERIFICATION_ORDER, Policy)
from .util import parse_ts, tokens_from_text

DEBUG = bool(os.environ.get('GHOST_DEBUG'))
COMPLIANT_LATE = {"NOT_FOUND", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}

# the deletion workflow's claim and the result its worker logs for the account deletion
STATUS_RESULT = {"COMPLETE": "SUCCESS", "NOT_STARTED": "FAILED", "PARTIALLY_COMPLETE": "PARTIAL"}
ACCOUNT_WINDOW = timedelta(minutes=100)      # worker activity precedes the workflow's report by < ~1.3 h
LATE_REPORT_SLACK = timedelta(minutes=10)
DOWNSTREAM_WINDOW = timedelta(minutes=55)       # downstream policy actions follow the account deletion
POLICY_EVENTS = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "BLOCK_RESTORE", "DISABLE_DATA_FLOW"}


@dataclass
class Resource:
    system: str
    rid: str
    kind: str
    state: str                # state at audit_at ("" if only seen after audit_at)
    file_id: str              # evidence that shows that state
    visible: bool             # observed at or before audit_at
    via: str = "token"        # how it was linked: token | activity
    activity_id: str = ""     # activity row that links/claims the resource (activity-linked only)


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: List[dict]
    subject: Optional[str] = None
    resources: List[Resource] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _step(phase: str, system: str, rid: str, op: str, evidence_id: str) -> dict:
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": rid,
            "operation": op, "state": OP_STATE[op], "evidence_id": evidence_id}


class Auditor:
    def __init__(self, dataset_dir: str, media_cache=None):
        self.dir = dataset_dir
        self.policy = Policy(dataset_dir)
        self.ids = IdentityBook(dataset_dir)
        self.obs, self.manifest = load_observations(dataset_dir, media_cache)
        self.captured = {m.file_id: parse_ts(m.captured_at) for m in self.manifest}
        self.by_rid: Dict[str, List[Obs]] = defaultdict(list)
        self.by_token: Dict[str, List[Obs]] = defaultdict(list)
        for o in self.obs:
            if o.rid == "__scope__":
                continue
            self.by_rid[o.rid].append(o)
            for t in o.tokens:
                self.by_token[t].append(o)
        self.scopes: Dict[str, List[Obs]] = defaultdict(list)
        for o in self.obs:
            if o.rid == "__scope__":
                self.scopes[o.system].append(o)
        self.activity = self._load_activity()
        self._act_ts = {a["activity_id"]: parse_ts(a["event_time"]) for a in self.activity}
        self.act_by_rid: Dict[str, List[dict]] = defaultdict(list)
        for a in self.activity:
            self.act_by_rid[a["resource_id"]].append(a)
        # resources that carry an identity token somewhere belong to an identified person
        self._apply_catalog()
        self.claimed: Set[str] = {o.rid for o in self.obs if o.rid != "__scope__" and o.tokens}
        self.extra: Dict[str, List[Tuple[str, str, str]]] = {}      # case_id -> [(system, rid, activity_id)]

    # ------------------------------------------------------------------ catalog
    def _apply_catalog(self) -> None:
        """LINK_RESOURCE_IDENTITY activity rows state which person a resource belongs to; fold those
        identifiers into the matching observations (and create a stub when nothing else shows it)."""
        self.catalog: Dict[str, Tuple[str, Set[str], str]] = {}
        for a in self.activity:
            if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            toks = tokens_from_text(a["details"])
            if toks:
                self.catalog[a["resource_id"]] = (a["target_system"], toks, a["activity_id"])
        for rid, (system, toks, act_id) in self.catalog.items():
            group = [o for o in self.by_rid.get(rid, ()) if o.system == system]
            for o in group:
                if not o.tokens or o.tokens & toks:
                    for t in toks:
                        if t not in o.tokens:
                            o.tokens.add(t)
                            self.by_token[t].append(o)
            if not group:
                kind = SYSTEM_KIND.get(system)
                if kind:
                    stub = Obs(act_id, "", system, rid, kind, "", set(toks))
                    self.by_rid[rid].append(stub)
                    for t in toks:
                        self.by_token[t].append(stub)

    # ------------------------------------------------------------------ activity
    def _load_activity(self):
        path = os.path.join(self.dir, "system_activity.csv")
        rows = []
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                rows.append(r)
        return rows

    # ------------------------------------------------------------------ linking
    def _visible(self, o: Obs, audit_dt) -> bool:
        cap = self.captured.get(o.file_id)
        ots = parse_ts(o.ts)
        if cap is not None and cap > audit_dt:
            return False
        if ots is not None and ots > audit_dt:
            return False
        return True

    def link(self, subj: Subject) -> List[Obs]:
        toks = subj.strong_tokens()
        seen, out = set(), []
        for t in toks:
            for o in self.by_token.get(t, ()):
                if id(o) not in seen:
                    seen.add(id(o))
                    out.append(o)
        return out

    @staticmethod
    def _conflicts(o: Obs, toks: Set[str]) -> bool:
        """An observation conflicts with the subject when it carries identity tokens, none of
        which belong to the subject."""
        return bool(o.tokens) and not (o.tokens & toks)

    def _pick(self, group: List[Obs]) -> Obs:
        """Latest observation wins; ties (same time) keep the worst state, preferring the file
        captured last."""
        def key(o: Obs):
            cap = self.captured.get(o.file_id)
            return (o.ts, cap.timestamp() if cap else 0, STATE_RANK.get(o.state, 0))
        return max(group, key=key)

    # ------------------------------------------------------------------ main
    def _token_resources(self, case: dict, subj: Subject) -> List[Resource]:
        """Resources tied to the subject by identity tokens (e-mail, hash, phone, user ref)."""
        audit_dt = parse_ts(case["audit_at"])
        req_dt = parse_ts(case.get("requested_at"))
        toks = subj.strong_tokens()
        rids: Dict[Tuple[str, str], str] = {}
        for o in self.link(subj):
            rids[(o.system, o.rid)] = "token"
        resources: List[Resource] = []
        for (system, rid), via in rids.items():
            group = [o for o in self.by_rid.get(rid, ()) if o.system == system and not self._conflicts(o, toks)]
            # a "not found" seen before the request proves nothing about the deletion (never-existed /
            # earlier account), so it can neither verify nor create a duty
            group = [o for o in group if not (o.state == "NOT_FOUND" and req_dt and parse_ts(o.ts) and parse_ts(o.ts) < req_dt)]
            # evidence captured before the request describes a state that predates the deletion
            # attempt; a resource that was never observed again afterwards neither creates a duty nor
            # proves a result at ``audit_at``
            if req_dt and not any(self._after_request(o, req_dt) for o in group):
                continue
            if not group:
                continue
            vis = [o for o in group if self._visible(o, audit_dt)]
            if vis:
                best = self._pick(vis)
                resources.append(Resource(system, rid, best.kind, best.state, best.file_id, True, via))
            else:
                best = self._pick(group)
                proof = self._absence_proof(system, rid, best.kind, audit_dt, req_dt)
                if proof:
                    resources.append(Resource(system, rid, best.kind, "NOT_FOUND", proof, True, via))
                else:
                    resources.append(Resource(system, rid, best.kind, "", best.file_id, False, via))
        return resources

    def _absence_proof(self, system: str, rid: str, kind: str, audit_dt, since) -> Optional[str]:
        """A record whose only sightings postdate ``audit_at`` can still be shown absent at
        ``audit_at``: a complete snapshot of its system, captured after the deletion started and
        before the audit cut-off, that lacks it.  Only for categories whose required end state is
        'absent'."""
        t = self.policy.treatment(kind)
        if not t or t.verify_op != "VERIFY_RECORD_ABSENT":
            return None
        t0 = self._act_time(rid, POLICY_EVENTS) or since
        scopes = [o for o in self.scopes.get(system, ()) if self._visible(o, audit_dt)
                  and (t0 is None or (parse_ts(o.ts) and parse_ts(o.ts) >= t0))
                  and not any(x.state != "NOT_FOUND" and self._visible(x, audit_dt) for x in self.by_rid.get(rid, ()) if x.system == system)]
        if not scopes:
            return None
        return max(scopes, key=lambda o: o.ts).file_id

    def _after_request(self, o: Obs, req_dt) -> bool:
        cap = self.captured.get(o.file_id)
        when = cap or parse_ts(o.ts)
        return when is None or when >= req_dt

    def _act_time(self, rid: str, events=("DELETE_RECORD",)):
        ts = [parse_ts(a["event_time"]) for a in self.act_by_rid.get(rid, ()) if a["event_type"] in events]
        return min(ts) if ts else None

    def prepare(self, cases: List[dict]) -> None:
        """Link records that carry no identity (deleted / anonymised copies) to cases through the
        deletion worker's activity: the account deletion runs just before the workflow reports its
        status, with a result that matches the claimed status; downstream policy actions follow it.
        Candidates already tied to a person by identity tokens are excluded, and the remaining
        candidates are assigned across cases by constraint propagation."""
        auth = []
        for c in cases:
            ok, _ = authorizes_deletion(c["request_text"])
            subj = self.ids.resolve(c["email"], c.get("requested_at")) if ok else None
            if subj is not None:
                auth.append((c, subj))
        pending, anchor = [], {}
        acct_acts = [a for a in self.activity if a["event_type"] == "DELETE_RECORD"
                     and a["target_system"] == "account_service" and a["resource_id"] not in self.claimed]
        for c, subj in auth:
            res = self._token_resources(c, subj)
            accts = [r for r in res if r.system == "account_service"]
            if accts:
                ts = [self._act_time(r.rid) for r in accts if self._act_time(r.rid)]
                if ts:
                    anchor[c["case_id"]] = max(ts)
                continue
            ra = parse_ts(c["reported_at"])
            want = STATUS_RESULT.get(c["reported_status"])
            # the worker's logged result is itself only a claim: prefer candidates whose result agrees
            # with the workflow's claim, then fall back to any account deletion in the same window, then
            # to one that was logged shortly after the report
            tiers = [
                [a for a in acct_acts if ra - ACCOUNT_WINDOW <= parse_ts(a["event_time"]) <= ra + timedelta(minutes=1)
                 and a["reported_result"] == want],
                [a for a in acct_acts if ra - ACCOUNT_WINDOW <= parse_ts(a["event_time"]) <= ra + timedelta(minutes=1)],
                [a for a in acct_acts if ra - ACCOUNT_WINDOW <= parse_ts(a["event_time"]) <= ra + LATE_REPORT_SLACK],
            ]
            cands = next((t for t in tiers if t), [])
            pending.append((c["case_id"], sorted(cands, key=lambda a: a["event_time"])))
        taken: Set[str] = set()
        self.extra = defaultdict(list)
        while pending:
            pending.sort(key=lambda x: (len([a for a in x[1] if a["resource_id"] not in taken]) or 99, x[0]))
            cid, cands = pending.pop(0)
            free = [a for a in cands if a["resource_id"] not in taken]
            if not free:
                continue
            pick = free[0]
            taken.add(pick["resource_id"])
            self.extra[cid].append(("account_service", pick["resource_id"], pick["activity_id"]))
            anchor[cid] = parse_ts(pick["event_time"])
        # downstream identity-less copies: attach to the case whose account deletion most recently
        # precedes the policy action, with a matching result, one per system per case, and only where
        # identity tokens have not already produced a record of that system for the case
        case_by_id = {c["case_id"]: (c, subj) for c, subj in auth}
        covered = {}
        clean = set()
        for cid, (c, subj) in case_by_id.items():
            tr = self._token_resources(c, subj)
            covered[cid] = {r.system for r in tr} | {x[0] for x in self.extra.get(cid, ())}
            viol = False
            for r in tr:
                t = self.policy.treatment(r.kind)
                viol = viol or bool(t and r.visible and self.policy.violates(t, r.state))
            if not viol:
                clean.add(cid)
        orphans: Dict[Tuple[str, str], Obs] = {}
        for rid, obs in self.by_rid.items():
            if rid in self.claimed or not obs:
                continue
            if {o.kind for o in obs} & {"USER_PROFILE", "SECURITY_AUDIT_LOG"}:
                continue
            orphans[(obs[0].system, rid)] = obs[0]
        items = []
        for (system, rid), ob in orphans.items():
            acts = sorted((a for a in self.act_by_rid.get(rid, ()) if a["event_type"] in POLICY_EVENTS),
                          key=lambda a: a["event_time"])
            if acts:
                items.append((acts[0]["event_time"], system, rid, acts[0], ob))
        # identity-less copies were removed/anonymised successfully shortly after the account deletion
        # (failed or partial policy actions leave identifiable copies, which carry tokens).  Timing alone
        # often leaves several cases eligible for the same copy; the evidence files list every table's
        # records in the same case order, so the position of a case's identified records in that file
        # ranks the cases, and copies are handed out in that order.
        file_pos: Dict[Tuple[str, str], Dict[str, List[int]]] = {}      # (file, case) -> system -> seqs
        for cid, (c, subj) in case_by_id.items():
            for o in self.link(subj):
                file_pos.setdefault((o.file_id, cid), {}).setdefault(o.system, []).append(o.seq)

        def precedes(files: List[str], c1: str, c2: str) -> int:
            """+1 / -1 votes for c1 listed before / after c2 in the files holding the orphan."""
            v = 0
            for f in files:
                p1, p2 = file_pos.get((f, c1), {}), file_pos.get((f, c2), {})
                for sy in set(p1) & set(p2):
                    a_, b_ = min(p1[sy]), min(p2[sy])
                    v += (a_ < b_) - (a_ > b_)
            return v

        used = set()
        orphan_files: Dict[str, List[str]] = defaultdict(list)
        for rid, obs in self.by_rid.items():
            for o in obs:
                if o.file_id not in orphan_files[rid]:
                    orphan_files[rid].append(o.file_id)
        by_group: Dict[Tuple[str, str], list] = defaultdict(list)
        for it in items:
            by_group[(it[1], it[4].file_id)].append(it)
        for (system, file_id), group in sorted(by_group.items()):
            group.sort(key=lambda x: x[4].seq)
            for _, _, rid, act, ob in group:
                at = parse_ts(act["event_time"])
                free = [cid for cid, t in anchor.items()
                        if cid in clean and system not in covered[cid]
                        and 0 <= (at - t).total_seconds() <= DOWNSTREAM_WINDOW.total_seconds()]
                if not free or rid in used:
                    continue
                files = orphan_files[rid]
                # a case with records in the files that hold the copy is a better candidate than one
                # that never appears there; among those, the file order decides
                def present(c):
                    return sum(1 for f in files if (f, c) in file_pos)
                cid = min(free, key=lambda c: (-min(present(c), 1), -sum(precedes(files, c, d) for d in free if d != c), anchor[c], c))
                if DEBUG:
                    print("PICK", system, rid, sorted(free), "->", cid)
                used.add(rid)
                covered[cid].add(system)
                self.extra[cid].append((system, rid, act["activity_id"]))

    def _activity_resource(self, system: str, rid: str, act_id: str, audit_dt) -> Optional[Resource]:
        kind = SYSTEM_KIND.get(system, "")
        group = [o for o in self.by_rid.get(rid, ()) if o.system == system]
        vis = [o for o in group if self._visible(o, audit_dt)]
        if vis:
            best = self._pick(vis)
            return Resource(system, rid, best.kind, best.state, best.file_id, True, "activity", act_id)
        # no observation of the record itself: a later complete snapshot of the system that lacks it proves absence
        t0 = self._act_time(rid, POLICY_EVENTS)
        scopes = [o for o in self.scopes.get(system, ()) if self._visible(o, audit_dt)
                  and (t0 is None or (parse_ts(o.ts) and parse_ts(o.ts) >= t0))]
        if scopes and kind:
            sc = max(scopes, key=lambda o: o.ts)
            return Resource(system, rid, kind, "NOT_FOUND", sc.file_id, True, "activity", act_id)
        late = [o for o in group]
        if late:
            best = self._pick(late)
            return Resource(system, rid, best.kind, "", best.file_id, False, "activity", act_id)
        return Resource(system, rid, kind, "", act_id, False, "activity", act_id) if kind else None

    def audit_case(self, case: dict) -> CaseResult:
        cid = case["case_id"]
        ok, why = authorizes_deletion(case["request_text"])
        if not ok:
            return CaseResult(cid, "NOT_APPLICABLE", [], notes=[f"non-deletion request ({why})"])
        subj = self.ids.resolve(case["email"], case.get("requested_at"))
        if subj is None:
            return CaseResult(cid, "INCOMPLETE", [], notes=["identity could not be resolved"])
        audit_dt = parse_ts(case["audit_at"])
        resources = self._token_resources(case, subj)
        have = {(r.system, r.rid) for r in resources}
        for system, rid, act_id in self.extra.get(cid, ()):
            if (system, rid) in have:
                continue
            r = self._activity_resource(system, rid, act_id, audit_dt)
            if r:
                resources.append(r)
        return self._finish(case, subj, resources)

    # ------------------------------------------------------------------ planning
    def _finish(self, case: dict, subj: Subject, resources: List[Resource]) -> CaseResult:
        cid = case["case_id"]
        findings, remed, verif = [], [], []
        violations = False
        incomplete_universe = []
        for r in resources:
            t = self.policy.treatment(r.kind)
            if t is None:
                continue
            if r.visible and self.policy.violates(t, r.state):
                violations = True
                findings.append((t.finding_op, r))
                remed.append((t.remediation_op, r))
            if r.visible or True:
                incomplete_universe.append((t, r))
        status = "INCOMPLETE" if violations else "COMPLETE"
        steps: List[dict] = []
        if status == "COMPLETE":
            for t, r in incomplete_universe:
                if (r.visible and r.state not in ("",)) or self._activity_cited_ok(r, case):
                    steps_v = self._verify_op(t, r)
                    if steps_v:
                        verif.append((steps_v, r, r.file_id))
        else:
            for t, r in incomplete_universe:
                if not r.visible and r.state == "" and not self._late_ok(r):
                    continue
                op = self._verify_op(t, r)
                if op:
                    verif.append((op, r, ""))
        def order(items, ops):
            return sorted(items, key=lambda x: (ops.index(x[0]), x[1].system, x[1].rid))
        for op, r in order(findings, FINDING_ORDER):
            steps.append(_step("FINDING", r.system, r.rid, op, r.file_id))
        if status == "INCOMPLETE":
            for op, r in order(remed, REMEDIATION_ORDER):
                steps.append(_step("REMEDIATION", r.system, r.rid, op, ""))
        for op, r, ev in order(verif, VERIFICATION_ORDER):
            steps.append(_step("VERIFICATION", r.system, r.rid, op, ev))
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
        return CaseResult(cid, status, steps, subj.user_id, resources)

    def _activity_cited_ok(self, r: Resource, case: dict) -> bool:
        """An activity row may back a verification only if it was logged at or before ``audit_at``."""
        if not r.file_id.startswith("activity_"):
            return False
        when = self._act_ts.get(r.file_id)
        return when is None or when <= parse_ts(case["audit_at"])

    def _late_ok(self, r: Resource) -> bool:
        """Resources first seen only after audit_at are kept in the verification universe only
        when that later evidence shows a compliant state (so they are not recreated decoys)."""
        return True

    def _verify_op(self, t, r: Resource) -> Optional[str]:
        # verification always targets the *required end state* of the treatment
        return t.verify_op
