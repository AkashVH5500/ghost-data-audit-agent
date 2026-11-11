"""Evaluation harness.

Compares a predictions CSV with a reference CSV (``dataset/sample_output.csv`` for the public
samples) and reports:

* case-level deletion_status accuracy (+ confusion matrix)
* row-level exact match (status + full steps list)
* step-level precision / recall / F1 (steps matched on phase+system+resource+operation)
* field-level accuracy over aligned steps (each of the seven step fields)
* sequence accuracy (exact ordering / longest-common-subsequence ratio)

Usage:
    python3 code/evaluation/main.py [--pred PATH] [--ref PATH] [--verbose]
Default: runs the agent on dataset/sample_deletion_requests.csv and scores it against
dataset/sample_output.csv.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "code"))

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["case_id"]: r for r in csv.DictReader(fh)}


def skey(s):
    return (s["phase"], s["system_id"], s["resource_id"], s["operation"])


def lcs(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[m][n]


def score(pred, ref, verbose=False):
    cases = sorted(ref)
    status_ok = 0
    row_exact = 0
    tp = fp = fn = 0
    field_hits = Counter()
    field_total = 0
    seq_exact = 0
    lcs_sum = 0.0
    conf = Counter()
    bad = []
    for c in cases:
        r = ref[c]
        p = pred.get(c)
        rs = json.loads(r["steps_json"])
        ps = json.loads(p["steps_json"]) if p else []
        ok = bool(p) and p["deletion_status"] == r["deletion_status"]
        conf[(r["deletion_status"], p["deletion_status"] if p else "MISSING")] += 1
        status_ok += ok
        rk = [skey(s) for s in rs]
        pk = [skey(s) for s in ps]
        rc, pc = Counter(rk), Counter(pk)
        inter = sum((rc & pc).values())
        tp += inter
        fp += sum(pc.values()) - inter
        fn += sum(rc.values()) - inter
        # field-level accuracy over steps present in both
        pmap = {skey(s): s for s in ps}
        for s in rs:
            k = skey(s)
            field_total += 1
            if k in pmap:
                for f in FIELDS:
                    field_hits[f] += int(pmap[k][f] == s[f])
        exact = ok and rs == ps
        row_exact += exact
        seq_exact += int(rk == pk)
        denom = max(len(rk), len(pk), 1)
        lcs_sum += lcs(rk, pk) / denom
        if not exact:
            bad.append(c)
    n = len(cases)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    res = {
        "cases": n,
        "status_accuracy": status_ok / n,
        "row_exact_match": row_exact / n,
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "field_accuracy": {f: (field_hits[f] / field_total if field_total else 1.0) for f in FIELDS},
        "sequence_exact": seq_exact / n,
        "sequence_lcs_ratio": lcs_sum / n,
        "confusion": {f"{a}->{b}": v for (a, b), v in sorted(conf.items())},
        "mismatched_cases": bad,
    }
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred")
    ap.add_argument("--ref", default=os.path.join(ROOT, "dataset", "sample_output.csv"))
    ap.add_argument("--requests", default=os.path.join(ROOT, "dataset", "sample_deletion_requests.csv"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--isolated", action="store_true", help="audit only the requests file (no joint context)")
    args = ap.parse_args(argv)
    pred_path = args.pred
    if not pred_path:
        from ghost.runner import run
        pred_path = os.path.join(HERE, "sample_predictions.csv")
        req_path = args.requests
        if not args.isolated:
            # The activity stream is global: decoy records of a sample case may be claimed by a real
            # request, so audit the samples jointly with deletion_requests.csv (same data the final
            # run sees) and score only the sample cases.
            req_path = os.path.join(HERE, "_joint_requests.csv")
            with open(args.requests, newline="", encoding="utf-8") as fh:
                rd = csv.DictReader(fh)
                rows = list(rd)
                cols = rd.fieldnames
            with open(os.path.join(ROOT, "dataset", "deletion_requests.csv"), newline="", encoding="utf-8") as fh:
                have = {r["case_id"] for r in rows}
                rows += [r for r in csv.DictReader(fh) if r["case_id"] not in have]
            with open(req_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\n")
                w.writeheader()
                w.writerows(rows)
        run(os.path.join(ROOT, "dataset"), req_path, pred_path)
        if not args.isolated:
            os.remove(req_path)
    res = score(load(pred_path), load(args.ref))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for k, v in res.items():
            print(f"{k}: {v}")
    return res


if __name__ == "__main__":
    main()
