#!/usr/bin/env python3
"""Ghost Data deletion-audit agent.

Usage:  python3 code/main.py [--requests PATH] [--out PATH] [--trace PATH]
Reads dataset/, writes <repo>/output.csv (518 rows sorted by case_id).
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from ghost.runner import run  # noqa: E402
from ghost.media import load_media_cache  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    ap.add_argument("--requests", default=None)
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--trace", default=None)
    a = ap.parse_args()
    req = a.requests or os.path.join(a.dataset, "deletion_requests.csv")
    res = run(a.dataset, req, a.out, load_media_cache(a.dataset), a.trace)
    from collections import Counter
    print(f"wrote {len(res)} rows to {a.out}: {dict(Counter(r.status for r in res))}")


if __name__ == "__main__":
    main()
