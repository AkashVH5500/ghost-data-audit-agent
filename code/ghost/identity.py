"""Identity resolution: request e-mail -> user, plus every current and historical identifier."""
from __future__ import annotations

import csv
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .util import norm_phone, parse_ts, sha256_email


@dataclass
class Subject:
    user_id: str
    name: str = ""
    emails: Set[str] = field(default_factory=set)       # current + historical (lower-case)
    hashes: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    current_email: str = ""

    def strong_tokens(self) -> Set[str]:
        t = {"u:" + self.user_id}
        t |= {"e:" + e for e in self.emails}
        t |= {"h:" + h for h in self.hashes}
        t |= {"p:" + p for p in self.phones}
        return t

    def weak_tokens(self) -> Set[str]:
        return {"n:" + " ".join(self.name.lower().split())} if self.name else set()


class IdentityBook:
    def __init__(self, dataset_dir: str):
        self.subjects: Dict[str, Subject] = {}
        self.by_email: Dict[str, List[str]] = defaultdict(list)
        self.audit_by_user: Dict[str, List[dict]] = defaultdict(list)
        with open(os.path.join(dataset_dir, "user_identities.csv"), newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                s = Subject(r["user_id"], r.get("name", ""))
                em = r["email"].strip().lower()
                s.emails.add(em)
                s.current_email = em
                if r.get("email_hash"):
                    s.hashes.add(r["email_hash"].strip().lower())
                s.hashes.add(sha256_email(em))
                if r.get("phone"):
                    s.phones.add(norm_phone(r["phone"]))
                self.subjects[s.user_id] = s
                self.by_email[em].append(s.user_id)
        path = os.path.join(dataset_dir, "user_audit_log.csv")
        if os.path.exists(path):
            with open(path, newline="", encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    s = self.subjects.get(r["user_id"])
                    if not s:
                        continue
                    self.audit_by_user[r["user_id"]].append(r)
                    f, old, new = r["field_name"], r["old_value"], r["new_value"]
                    if f == "email":
                        for v in (old, new):
                            v = v.strip().lower()
                            if v:
                                s.emails.add(v)
                                s.hashes.add(sha256_email(v))
                                if s.user_id not in self.by_email[v]:
                                    self.by_email[v].append(s.user_id)
                    elif f == "email_hash":
                        for v in (old, new):
                            if v:
                                s.hashes.add(v.strip().lower())
                    elif f == "phone":
                        for v in (old, new):
                            if v:
                                s.phones.add(norm_phone(v))

    def resolve(self, email: str, at: Optional[str] = None) -> Optional[Subject]:
        """Resolve a request e-mail (current or historical) to its subject.

        If several users have ever held the address, prefer the one who held it at ``at``
        (the audit log gives the change timeline); otherwise the current holder.
        """
        e = email.strip().lower()
        cands = self.by_email.get(e, [])
        if not cands:
            return None
        if len(cands) == 1:
            return self.subjects[cands[0]]
        t = parse_ts(at) if at else None
        best = None
        for uid in cands:
            holds = self._holds_at(uid, e, t)
            if holds:
                best = uid
        if best is None:
            best = next((u for u in cands if self.subjects[u].current_email == e), cands[0])
        return self.subjects[best]

    def _holds_at(self, uid: str, email: str, t) -> bool:
        s = self.subjects[uid]
        if t is None:
            return s.current_email == email
        # reconstruct the e-mail held at time t by unwinding the audit log from the current value
        cur = s.current_email
        for r in sorted((r for r in self.audit_by_user.get(uid, []) if r["field_name"] == "email"),
                        key=lambda r: r["event_time"], reverse=True):
            when = parse_ts(r["event_time"])
            if when and when > t:
                cur = r["old_value"].strip().lower()
        return cur == email
