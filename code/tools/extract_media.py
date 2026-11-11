#!/usr/bin/env python3
"""Regenerate ``code/cache/media_extractions.json`` from the PNG screenshots / PDF documents.

The audit itself is deterministic and never calls a model; it consumes the cache this tool writes.
For every image or PDF listed in ``evidence_files.csv`` a vision-capable model is asked to transcribe
*only what the artefact displays* (resource id, system, record kind, visible state, identifiers
shown, a short note) -- no verdicts.

NOTE: the cache shipped with this submission was produced by reading each of the 14 artefacts that carry resource rows (15 PNG/PDF files in total) with
a vision-capable model during development and recording the rows by hand; this script automates the same transcription through the Anthropic Messages API but
was NOT executed to produce the shipped cache (no API key in the build environment).

Usage:  ANTHROPIC_API_KEY=... python3 code/tools/extract_media.py [--model claude-sonnet-5-5] [--force]
"""
import argparse
import base64
import csv
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CACHE = os.path.join(ROOT, "code", "cache", "media_extractions.json")
PROMPT = (
    "You are transcribing a business artefact (screenshot or document) from an e-commerce company's "
    "internal tools. Return ONLY a JSON array. One object per resource row shown, with keys: "
    "resource_id (e.g. support_001, object_19, tombstone_17), system (one of account_service, "
    "search_service, support_platform, object_storage, export_service, analytics_platform, "
    "marketing_platform, integration_service, backup_service, security_service, identity_service, "
    "legal_service), kind (one of the data categories USER_PROFILE, SEARCH_INDEX_ENTRY, "
    "SUPPORT_MESSAGE, SUPPORT_ATTACHMENT, ANALYTICS_PROFILE, USER_EXPORT, MARKETING_PROFILE, "
    "SECURITY_AUDIT_LOG, BACKUP_ARCHIVE, ACCOUNT_TOMBSTONE, DATA_FLOW, LEGAL_HOLD_RECORD), state "
    "(FOUND, NOT_FOUND, IDENTIFIABLE, REDACTED, ANONYMIZED, ACTIVE, BLOCKED or DISABLED -- describing "
    "what is visible), identifiers (every e-mail, phone, user_id shown for that row; [] if none), "
    "note (one short factual sentence). Do not decide whether anything should be deleted."
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="claude-sonnet-5-5")
    ap.add_argument("--force", action="store_true", help="re-extract files already in the cache")
    a = ap.parse_args()
    try:
        import anthropic
    except ImportError:
        sys.exit("pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("set ANTHROPIC_API_KEY (read from the environment only)")
    client = anthropic.Anthropic()
    cache = {"_provenance": "", "files": {}}
    if os.path.exists(CACHE):
        cache = json.load(open(CACHE, encoding="utf-8"))
    with open(os.path.join(ROOT, "dataset", "evidence_files.csv"), newline="", encoding="utf-8") as fh:
        manifest = list(csv.DictReader(fh))
    for r in manifest:
        path = os.path.join(ROOT, "dataset", r["file_path"])
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".png", ".pdf") or (r["file_id"] in cache["files"] and not a.force):
            continue
        data = base64.b64encode(open(path, "rb").read()).decode()
        block = ({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
                 if ext == ".png" else
                 {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": data}})
        msg = client.messages.create(model=a.model, max_tokens=2000, temperature=0,
                                     messages=[{"role": "user", "content": [block, {"type": "text", "text": PROMPT}]}])
        text = msg.content[0].text.strip()
        text = text[text.index("["): text.rindex("]") + 1]
        cache["files"][r["file_id"]] = json.loads(text)
        print(r["file_id"], r["file_path"], len(cache["files"][r["file_id"]]), "rows",
              msg.usage.input_tokens, "in /", msg.usage.output_tokens, "out")
    cache["_provenance"] = f"Transcribed by {a.model} via code/tools/extract_media.py"
    json.dump(cache, open(CACHE, "w", encoding="utf-8"), indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
