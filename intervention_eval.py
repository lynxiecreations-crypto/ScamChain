"""Intervention-policy benchmark for ScamChain.

The benchmark uses synthetic attack prefixes to test whether the policy chooses
an intervention at the earliest available defensive stage and avoids acting on
benign traffic. Labels encode a documented policy, not model predictions.
"""
from __future__ import annotations
from copy import deepcopy
from data import make_cases
from engine import detect_signals, intervention, evidence_completeness

EXPECTED_BY_TYPES = [
    ("BENEFICIARY_CREATED", "BENEFICIARY_CREATION"),
    ("OTP_REQUEST", "OTP_REQUEST"),
    ("URL_OPENED", "SUSPICIOUS_URL"),
    ("MESSAGE_RECEIVED", "MESSAGE"),
]


def _expected(events):
    types = {e.event_type for e in events}
    if not types:
        return "NONE"
    comp = evidence_completeness(events)
    if comp["status"] == "INSUFFICIENT":
        return "EVIDENCE_REVIEW"
    if comp["status"] == "PARTIAL" and "BENEFICIARY_CREATED" not in types and "TRANSACTION_INITIATED" not in types:
        return "EVIDENCE_REVIEW"
    for typ, stage in EXPECTED_BY_TYPES:
        if typ in types:
            return stage
    return "NONE"


def _prefix_cases():
    cases = make_cases()
    rows = []
    for c in cases:
        # Every prefix is an independent observation point.
        if c.case_id.startswith("C"):
            for k in range(1, len(c.events) + 1):
                events = deepcopy(c.events[:k])
                signals = detect_signals(c, set(), 0.0)
                # Recompute signal evidence from the observed prefix only.
                probe = deepcopy(c)
                probe.events = events
                signals = detect_signals(probe, set(), 0.0)
                pred = intervention(events, signals)
                rows.append((c.case_id, k, _expected(events), pred["stage"]))
        else:
            signals = detect_signals(c, set(), 0.0)
            pred = intervention(c.events, signals)
            rows.append((c.case_id, len(c.events), "NONE", pred["stage"]))
    return rows


def evaluate():
    rows = _prefix_cases()
    scam_rows = [r for r in rows if r[0].startswith("C")]
    correct = sum(r[2] == r[3] for r in scam_rows)
    benign = [r for r in rows if r[0].startswith("B")]
    unnecessary = sum(r[3] != "NONE" for r in benign)
    return {
        "benchmark": "synthetic policy benchmark",
        "observations": len(rows),
        "scam_observations": len(scam_rows),
        "intervention_stage_accuracy": round(correct / max(1, len(scam_rows)), 3),
        "unnecessary_intervention_rate": round(unnecessary / max(1, len(benign)), 3),
        "benign_observations": len(benign),
        "policy": "beneficiary > OTP > suspicious URL > message > none",
    }
