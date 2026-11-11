"""Small shared helpers: time handling, identifier normalisation, hashing."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Iterable, Optional, Set

EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
HASH_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])")
USER_RE = re.compile(r"\buser_\d+\b")
PHONE_RE = re.compile(r"\+\d[\d\s().\-]{6,}\d")


def parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    try:
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_email(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def norm_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    return digits


def tokens_from_text(text: str) -> Set[str]:
    """Extract identity tokens (emails, hashes, user refs, phones) from free text."""
    out: Set[str] = set()
    if not text:
        return out
    for m in EMAIL_RE.findall(text):
        out.add("e:" + m.lower())
    for m in HASH_RE.findall(text):
        if not m.startswith("0" * 16):
            out.add("h:" + m.lower())
    for m in USER_RE.findall(text):
        out.add("u:" + m.lower())
    for m in PHONE_RE.findall(text):
        d = norm_phone(m)
        if len(d) >= 8:
            out.add("p:" + d)
    return out


def tokens_from_values(values: Iterable) -> Set[str]:
    out: Set[str] = set()
    for v in values:
        if isinstance(v, str):
            out |= tokens_from_text(v)
    return out


def name_token(value: Optional[str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return None
    v = " ".join(value.split()).strip().lower()
    if not v or v in ("null", "none", "[redacted]"):
        return None
    return "n:" + v
