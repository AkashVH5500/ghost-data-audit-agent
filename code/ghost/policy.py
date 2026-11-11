"""Deletion policy (``deletion_rules.csv``) applied to a resource state.

The rules file is loaded at start-up and drives which treatment each data category gets;
the step vocabulary mirrors the problem statement.  Nothing here is case specific.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, Optional

# data category (rule file) for each evidence "kind"
KIND_CATEGORY = {
    "USER_PROFILE": "USER_PROFILE",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY": "CACHE_ENTRY",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
    "USER_EXPORT": "USER_EXPORT",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "DATA_FLOW": "DATA_FLOW",           # not a data category: a process, always disabled
}

# the "exposed" state for each treatment
EXPOSED = {"DELETE": "FOUND", "REDACT": "IDENTIFIABLE", "ANONYMIZE": "IDENTIFIABLE"}

FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]

OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


@dataclass
class Treatment:
    category: str
    action: str                      # DELETE | REDACT | ANONYMIZE | RETAIN | DISABLE | BLOCK
    finding_op: Optional[str]
    remediation_op: Optional[str]
    verify_op: str


class Policy:
    def __init__(self, dataset_dir: str):
        self.rules: Dict[str, dict] = {}
        with open(os.path.join(dataset_dir, "deletion_rules.csv"), newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                self.rules[r["data_category"]] = r

    def action(self, category: str) -> str:
        r = self.rules.get(category)
        return r["required_action"] if r else "DELETE"

    def treatment(self, kind: str) -> Optional[Treatment]:
        if kind == "DATA_FLOW":
            return Treatment("DATA_FLOW", "DISABLE", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW",
                             "VERIFY_DATA_FLOW_DISABLED")
        cat = KIND_CATEGORY.get(kind)
        if cat is None:
            return None
        act = self.action(cat)
        if cat == "BACKUP_ARCHIVE":       # RETAIN, but restore access must be blocked
            return Treatment(cat, "BLOCK", "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")
        if act == "DELETE":
            return Treatment(cat, act, "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
        if act == "REDACT":
            return Treatment(cat, act, "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED")
        if act == "ANONYMIZE":
            return Treatment(cat, act, "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")
        if act == "RETAIN":
            return Treatment(cat, act, None, None, "VERIFY_RECORD_PRESENT")
        return None

    def violates(self, t: Treatment, state: str) -> bool:
        """Is a resource in ``state`` out of compliance for treatment ``t``?"""
        if t.action == "RETAIN":
            return False
        if t.action == "DELETE":
            return state == "FOUND"
        if t.action in ("REDACT", "ANONYMIZE"):
            return state == "IDENTIFIABLE"
        if t.action == "DISABLE":
            return state == "ACTIVE"
        if t.action == "BLOCK":
            return state == "ACTIVE"
        return False
