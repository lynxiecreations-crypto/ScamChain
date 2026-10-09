"""Adversarial robustness benchmark for ScamChain.

Synthetic stress tests only. It measures robustness of the implemented pipeline to:
- benign lookalikes with scam-like language
- partial/incomplete attack evidence
- event-order noise (input shuffled, timestamps preserved)
- missing evidence text
- rotated identifiers (no entity reuse)

This benchmark does not claim real-world performance.
"""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

from models import Entity, Event, Case
from engine import reconstruct, detect_signals, risk_fusion, campaign_similarity

ATTACK = [
    "MESSAGE_RECEIVED", "URL_OPENED", "CREDENTIAL_REQUEST", "OTP_REQUEST",
    "LOGIN", "BENEFICIARY_CREATED", "TRANSACTION_INITIATED", "TRANSACTION_COMPLETED"
]
BENIGN = [
    "MESSAGE_RECEIVED", "URL_OPENED", "LOGIN", "TRANSACTION_INITIATED", "TRANSACTION_COMPLETED"
]
STAGE_EXPECTED = {
    "MESSAGE_RECEIVED": "SOCIAL_ENGINEERING", "URL_OPENED": "TRUST_ESTABLISHMENT",
    "CREDENTIAL_REQUEST": "CREDENTIAL_CAPTURE", "OTP_REQUEST": "CREDENTIAL_CAPTURE",
    "LOGIN": "ACCOUNT_COMPROMISE", "BENEFICIARY_CREATED": "BENEFICIARY_DIVERSION",
    "TRANSACTION_INITIATED": "FINANCIAL_TRANSFER", "TRANSACTION_COMPLETED": "FINANCIAL_TRANSFER"
}


def _make(case_id, seq, start, attack=True, rotated=True, noisy=False, missing_evidence=False):
    events = []
    for i, typ in enumerate(seq):
        ts = (start + timedelta(minutes=[0, 4, 7, 9, 13, 17, 20, 21][i])).isoformat()
        eid = f"{case_id}_E{i}"
        if attack:
            ev_text = {
                "MESSAGE_RECEIVED": "Bank security alert: your account will be blocked immediately.",
                "URL_OPENED": "Open the verification link to restore access.",
                "CREDENTIAL_REQUEST": "Enter your netbanking credentials.",
                "OTP_REQUEST": "Share OTP immediately to restore access.",
                "LOGIN": "New device login observed.",
                "BENEFICIARY_CREATED": "New beneficiary added.",
                "TRANSACTION_INITIATED": "Transfer initiated.",
                "TRANSACTION_COMPLETED": "Transfer completed.",
            }[typ]
        else:
            ev_text = {
                "MESSAGE_RECEIVED": "Your monthly banking statement is ready.",
                "URL_OPENED": "Open the bank's official website to view your statement.",
                "LOGIN": "Routine login from a recognized device.",
                "TRANSACTION_INITIATED": "Scheduled utility payment initiated.",
                "TRANSACTION_COMPLETED": "Scheduled utility payment completed.",
            }[typ]
        if missing_evidence and i % 2 == 0:
            ev = []
        else:
            ev = [ev_text]
        prefix = case_id if rotated else "SHARED"
        ents = [f"{prefix}_PHONE", f"{prefix}_DOMAIN"] if typ in {"MESSAGE_RECEIVED", "URL_OPENED"} else [f"{prefix}_ACC"]
        events.append(Event(eid, ts, typ, f"{prefix}_ACTOR", f"{prefix}_TARGET", ents, ev, .95))
    if noisy:
        rng = np.random.default_rng(3)
        rng.shuffle(events)  # timestamps remain authoritative; reconstruct should recover order.
    entities = []
    for j, eid in enumerate(sorted({x for e in events for x in e.entities})):
        typ = "PHONE" if "PHONE" in eid else "DOMAIN" if "DOMAIN" in eid else "ACCOUNT"
        entities.append(Entity(eid, typ, eid.lower()))
    return Case(case_id, f"V_{case_id}", events[0].timestamp, "adversarial-synthetic", events, entities, [], {}, [])


def _attack_observed_score(c):
    sig = detect_signals(c, set(), 0.0)
    risk = risk_fusion(sig)
    return risk["score"], sig


def evaluate(seed=19):
    rng = np.random.default_rng(seed)
    rows = []
    # 30 adversarial benign lookalikes: urgency/security context but legitimate workflow.
    for i in range(30):
        c = _make(f"AB{i:02d}", BENIGN, datetime(2026, 10, 5, 9, 0) + timedelta(minutes=i), attack=False, rotated=True,
                  missing_evidence=(i % 3 == 0))
        # Inject scam-like wording without creating scam event types.
        if i % 2 == 0:
            c.events[0].evidence = ["Security notice: review your account immediately to avoid service interruption."]
        rows.append(("benign", c))
    # 30 partial attacks: progressively reveal prefixes; the attack should become detectable.
    partial = []
    for i in range(30):
        k = int(rng.integers(2, len(ATTACK) + 1))
        c = _make(f"PA{i:02d}", ATTACK[:k], datetime(2026, 10, 6, 9, 0) + timedelta(minutes=i), attack=True, rotated=True,
                  missing_evidence=(i % 4 == 0))
        partial.append(c)
        rows.append(("partial", c))
    # 20 reordered full attacks: input order is scrambled, timestamps are unchanged.
    reordered = [_make(f"RO{i:02d}", ATTACK, datetime(2026, 10, 7, 9, 0) + timedelta(minutes=i), attack=True, rotated=True, noisy=True) for i in range(20)]
    rows.extend(("reordered", c) for c in reordered)

    benign_scores = [_attack_observed_score(c)[0] for kind, c in rows if kind == "benign"]
    partial_scores = [_attack_observed_score(c)[0] for kind, c in rows if kind == "partial"]
    full_scores = [_attack_observed_score(c)[0] for kind, c in rows if kind == "reordered"]

    # A fixed intervention threshold aligned with the engine's HIGH RISK policy.
    benign_fpr = float(np.mean(np.asarray(benign_scores) >= 35))
    partial_detected = float(np.mean(np.asarray(partial_scores) >= 35))
    shuffled_ok = all(reconstruct(c.events) == [
        "SOCIAL_ENGINEERING", "TRUST_ESTABLISHMENT", "CREDENTIAL_CAPTURE", "ACCOUNT_COMPROMISE",
        "BENEFICIARY_DIVERSION", "FINANCIAL_TRANSFER"
    ] for c in reordered)

    # Identifier rotation test: same attack family, unique identifiers; similarity must come from behavior.
    rotated_pairs = [
        campaign_similarity(reordered[i], reordered[i + 1]) for i in range(0, len(reordered) - 1, 2)
    ]

    return {
        "benchmark": "synthetic-adversarial-robustness",
        "seed": seed,
        "adversarial_benign_cases": len(benign_scores),
        "partial_attack_cases": len(partial_scores),
        "reordered_attack_cases": len(full_scores),
        "adversarial_benign_false_positive_rate_at_review_threshold": round(benign_fpr, 3),
        "partial_attack_detection_rate_at_review_threshold": round(partial_detected, 3),
        "reordered_attack_chain_accuracy": round(float(shuffled_ok), 3),
        "rotated_identifier_pair_similarity_mean": round(float(np.mean(rotated_pairs)), 3),
        "rotated_identifier_pair_similarity_min": round(float(np.min(rotated_pairs)), 3),
        "threshold": 35,
        "interpretation": "Synthetic robustness checks only; not production performance."
    }
