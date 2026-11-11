"""Generic parser for the heterogeneous log formats found in the evidence corpus.

Handles three shapes:
  * ``<ts> level=X service=Y key=value key="quoted value"`` lines
  * CloudWatch-like lines whose payload sits in ``message="... key=\\"value\\" ..."``
  * JSON lines (one object per line)
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S+)')


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
        v = v.replace('\\"', '"').replace("\\\\", "\\")
    return v


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in KV_RE.findall(text):
        out[k] = _unquote(v)
    return out


def parse_line(line: str) -> Optional[Dict[str, str]]:
    line = line.strip()
    if not line:
        return None
    ts_prefix = None
    pm = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(\{.*\})\s*$", line)
    if pm:                       # "<ts> {json}" lines
        ts_prefix, line = pm.group(1), pm.group(2)
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            flat: Dict[str, str] = {}
            _flatten(obj, "", flat)
            if "ts" not in flat:
                for key in ("timestamp", "time", "@timestamp", "event_time"):
                    if key in flat:
                        flat["ts"] = flat[key]
                        break
            if ts_prefix and "ts" not in flat:
                flat["ts"] = ts_prefix
            return flat
    m = TS_RE.search(line)
    rec = parse_kv(line)
    # nested payload (message="...")
    msg = rec.get("message")
    if msg and "=" in msg:
        nested = parse_kv(msg)
        for k, v in nested.items():
            rec.setdefault(k, v)
    if m:
        rec["ts"] = m.group(0)
    return rec


def _flatten(obj, prefix: str, out: Dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}{k}" if not prefix else f"{prefix}.{k}", out)
            # also expose leaf names un-prefixed when not already set
            if not isinstance(v, (dict, list)):
                out.setdefault(k, "" if v is None else str(v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten(v, f"{prefix}[{i}]", out)
    else:
        out[prefix] = "" if obj is None else str(obj)


def parse_log(text: str) -> List[Dict[str, str]]:
    recs = []
    for i, line in enumerate(text.splitlines()):
        r = parse_line(line)
        if r is not None:
            r["_line"] = str(i + 1)
            recs.append(r)
    return recs
