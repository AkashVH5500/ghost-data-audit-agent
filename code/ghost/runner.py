"""Batch runner: audit every request and write ``output.csv``."""
from __future__ import annotations

import csv
import json
import os
from typing import Optional

from .audit import Auditor
from .media import load_media_cache


def run(dataset_dir: str, requests_path: str, out_path: str, media_cache=None, trace_path: Optional[str] = None):
    aud = Auditor(dataset_dir, media_cache if media_cache is not None else load_media_cache(dataset_dir))
    with open(requests_path, newline="", encoding="utf-8") as fh:
        cases = list(csv.DictReader(fh))
    aud.prepare(cases)
    results = [aud.audit_case(c) for c in cases]
    results.sort(key=lambda r: r.case_id)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            w.writerow([r.case_id, r.status, json.dumps(r.steps, ensure_ascii=False, separators=(",", ":"))])
    if trace_path:
        with open(trace_path, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(f"## {r.case_id} {r.status} subject={r.subject}\n")
                for n in r.notes:
                    fh.write(f"   note: {n}\n")
                for x in r.resources:
                    fh.write(f"   {x.system}/{x.rid} kind={x.kind} state={x.state or '-'} ev={x.file_id} "
                             f"visible={x.visible} via={x.via}\n")
    return results
