"""Additional evaluation cases created by us (no reference answers exist for them).

Each test states an invariant that must hold for a correct auditor and derives its expected result
from first principles or from the agent's own answer for the unmodified case:

C1  multilingual intent         non-deletion / negated-deletion requests -> NOT_APPLICABLE ``[]``;
                                plain deletion requests stay authorised
C2  historical e-mail           a request made with a user's *previous* address resolves to the same
                                user and yields the same status/steps as the current address
C3  claims are not proof        rotating ``reported_status`` of every request must not change the
                                resulting ``deletion_status``
C4  later evidence is ignored   moving ``audit_at`` back to the request time must never cite
                                evidence captured after the new ``audit_at``
C5  non-deletion overrides      a request with stolen-looking evidence (a real case's e-mail) but
                                an access-only text is NOT_APPLICABLE even though a ghost record exists

Usage: python3 code/evaluation/custom_cases.py [--json]
"""
from __future__ import annotations

import copy
import csv
import json
import os
import sys
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "code"))

from ghost.audit import Auditor  # noqa: E402
from ghost.identity import IdentityBook  # noqa: E402
from ghost.intent import authorizes_deletion  # noqa: E402
from ghost.media import load_media_cache  # noqa: E402
from ghost.util import parse_ts  # noqa: E402

DATASET = os.path.join(ROOT, "dataset")


def rows(name):
    with open(os.path.join(DATASET, name), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def run_all(cases):
    aud = Auditor(DATASET, load_media_cache(DATASET))
    aud.prepare(cases)
    return {c["case_id"]: aud.audit_case(c) for c in cases}, aud


def c1_intent():
    expect_na = [
        "Please send me a copy of my data. I do not want to delete anything.",
        "No quiero eliminar mi cuenta, solo cambiar mi teléfono.",
        "Je ne veux pas supprimer mon compte, je voudrais seulement une copie de mes données.",
        "Ich möchte mein Konto nicht löschen, bitte nur die Adresse ändern.",
        "Não quero excluir minha conta; só preciso corrigir meu sobrenome.",
        "Non voglio cancellare l'account, vorrei solo disiscrivermi dalla newsletter.",
        "Unsubscribe me from marketing emails. Keep my account.",
    ]
    expect_del = [
        "Please delete my account and all personal data.",
        "Por favor, elimina mi cuenta de forma permanente.",
        "Bitte löschen Sie mein Konto und alle Daten.",
        "Je demande la suppression de mon compte.",
        "アカウントを削除してください。",
        "Quero excluir minha conta e meus dados.",
    ]
    out = []
    for t in expect_na:
        out.append((authorizes_deletion(t)[0] is False, "NOT_APPLICABLE", t))
    for t in expect_del:
        out.append((authorizes_deletion(t)[0] is True, "authorised", t))
    return out


def c2_historical_email(cases):
    ids = IdentityBook(DATASET)
    out = []
    for c in cases:
        subj = ids.resolve(c["email"], c["requested_at"])
        if subj and c["email"].strip().lower() != subj.current_email:
            out.append(c)
    if not out:
        return [], 0
    base, _ = run_all(cases)
    variants = []
    for c in out:
        v = copy.deepcopy(c)
        v["email"] = ids.resolve(c["email"], c["requested_at"]).current_email
        variants.append(v)
    by = {c["case_id"]: c for c in cases}
    for v in variants:
        by[v["case_id"]] = v
    alt, _ = run_all(list(by.values()))
    results = []
    for c in out:
        a, b = base[c["case_id"]], alt[c["case_id"]]
        results.append((a.status == b.status and a.steps == b.steps, c["case_id"], a.status))
    return results, len(out)


def c3_claim_rotation(cases):
    base, _ = run_all(cases)
    rot = {"COMPLETE": "NOT_STARTED", "NOT_STARTED": "PARTIALLY_COMPLETE", "PARTIALLY_COMPLETE": "COMPLETE"}
    flipped = []
    for c in cases:
        v = dict(c)
        v["reported_status"] = rot.get(c["reported_status"], c["reported_status"])
        flipped.append(v)
    alt, _ = run_all(flipped)
    same = sum(base[k].status == alt[k].status for k in base)
    same_steps = sum(base[k].steps == alt[k].steps for k in base)
    return same, same_steps, len(base)


def c4_future_evidence(cases):
    aud = Auditor(DATASET, load_media_cache(DATASET))
    variants = []
    for c in cases:
        v = dict(c)
        v["audit_at"] = (parse_ts(c["requested_at"]) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        variants.append(v)
    aud.prepare(variants)
    manifest = {m.file_id: parse_ts(m.captured_at) for m in aud.manifest}
    acts = {a["activity_id"]: parse_ts(a["event_time"]) for a in aud.activity}
    bad = 0
    checked = 0
    for v in variants:
        res = aud.audit_case(v)
        cut = parse_ts(v["audit_at"])
        for s in res.steps:
            ev = s["evidence_id"]
            if not ev:
                continue
            checked += 1
            when = manifest.get(ev) or acts.get(ev)
            if when and when > cut:
                bad += 1
    return bad, checked


def c5_access_only_over_real_case(cases):
    out = []
    for c in cases[:40]:
        v = dict(c)
        v["request_text"] = "Please send me a copy of the personal data you hold about me. I want to keep my account."
        res = Auditor.audit_case.__get__(AUD)(v)
        out.append(res.status == "NOT_APPLICABLE" and res.steps == [])
    return out


AUD = None


def main(argv=None):
    global AUD
    cases = rows("deletion_requests.csv")
    AUD = Auditor(DATASET, load_media_cache(DATASET))
    AUD.prepare(cases)
    report = {}
    c1 = c1_intent()
    report["C1_multilingual_intent"] = {"passed": sum(ok for ok, *_ in c1), "total": len(c1),
                                        "failures": [t for ok, _, t in c1 if not ok]}
    c2, n2 = c2_historical_email(cases)
    report["C2_historical_email"] = {"cases_with_historical_email": n2, "passed": sum(ok for ok, *_ in c2),
                                     "failures": [cid for ok, cid, _ in c2 if not ok]}
    same, same_steps, n3 = c3_claim_rotation(cases)
    report["C3_claims_are_not_proof"] = {"status_unchanged": same, "steps_unchanged": same_steps, "total": n3}
    bad, checked = c4_future_evidence(cases)
    report["C4_later_evidence_ignored"] = {"citations_after_audit_at": bad, "citations_checked": checked}
    c5 = c5_access_only_over_real_case(cases)
    report["C5_access_only_over_real_case"] = {"passed": sum(c5), "total": len(c5)}
    if "--json" in (argv or sys.argv[1:]):
        print(json.dumps(report, indent=2))
    else:
        for k, v in report.items():
            print(k, v)
    return report


if __name__ == "__main__":
    main()
