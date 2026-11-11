"""Show per-case step differences between a prediction CSV and a reference CSV."""
import csv, json, sys, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
pred = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "code/evaluation/sample_predictions.csv")
ref = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "dataset/sample_output.csv")
only = set(sys.argv[3:])
L = lambda p: {r["case_id"]: r for r in csv.DictReader(open(p, newline=""))}
P, R = L(pred), L(ref)
k = lambda s: (s["phase"][:3], s["system_id"], s["resource_id"], s["operation"], s["evidence_id"])
for c in sorted(R):
    if only and c not in only: continue
    rs, ps = json.loads(R[c]["steps_json"]), json.loads(P[c]["steps_json"])
    rk, pk = [k(s) for s in rs], [k(s) for s in ps]
    if rk == pk and R[c]["deletion_status"] == P[c]["deletion_status"]: continue
    print(f"--- {c} ref={R[c]['deletion_status']} pred={P[c]['deletion_status']}")
    for x in rk:
        if x not in pk: print("  MISSING", x)
    for x in pk:
        if x not in rk: print("  EXTRA  ", x)
    if sorted(rk) == sorted(pk): print("  ORDER differs")
