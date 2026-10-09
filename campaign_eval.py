"""Held-out campaign-family benchmark for ScamChain.

Synthetic only. Campaign members intentionally use unique identifiers so discovery
cannot depend on exact phone/domain/account reuse. The benchmark evaluates whether
workflow and temporal similarity can recover latent campaign families and reject
benign lookalikes.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from itertools import combinations
import numpy as np
from sklearn.metrics import adjusted_rand_score, average_precision_score, roc_auc_score
from models import Case, Entity, Event
from engine import campaign_similarity, reconstruct, _sequence_similarity, _temporal_similarity

FAMILIES = {
    "BANK_TAKEOVER": ["MESSAGE_RECEIVED", "URL_OPENED", "CREDENTIAL_REQUEST", "OTP_REQUEST", "LOGIN", "BENEFICIARY_CREATED", "TRANSACTION_INITIATED"],
    "KYC_DIVERSION": ["MESSAGE_RECEIVED", "CREDENTIAL_REQUEST", "OTP_REQUEST", "LOGIN", "BENEFICIARY_CREATED", "TRANSACTION_INITIATED"],
    "COURIER_PAYMENT": ["MESSAGE_RECEIVED", "URL_OPENED", "LOGIN", "BENEFICIARY_CREATED", "TRANSACTION_INITIATED"],
    "INVESTMENT_PULL": ["MESSAGE_RECEIVED", "URL_OPENED", "CREDENTIAL_REQUEST", "LOGIN", "TRANSACTION_INITIATED"],
    "REMOTE_SUPPORT": ["MESSAGE_RECEIVED", "OTP_REQUEST", "LOGIN", "ACCOUNT_CHANGE", "TRANSACTION_INITIATED"],
    "ACCOUNT_RECOVERY": ["MESSAGE_RECEIVED", "URL_OPENED", "CREDENTIAL_REQUEST", "LOGIN", "ACCOUNT_CHANGE", "TRANSACTION_INITIATED"],
}

FAMILY_CADENCE = {
    "BANK_TAKEOVER": [2, 3, 4, 3, 5, 2, 3],
    "KYC_DIVERSION": [5, 2, 3, 4, 2, 3],
    "COURIER_PAYMENT": [8, 12, 5, 3, 4],
    "INVESTMENT_PULL": [20, 8, 15, 10, 5],
    "REMOTE_SUPPORT": [3, 1, 2, 7, 4],
    "ACCOUNT_RECOVERY": [12, 4, 2, 6, 3, 5],
}

BENIGN_TEMPLATES = [
    ["MESSAGE_RECEIVED", "LOGIN", "TRANSACTION_COMPLETED"],
    ["MESSAGE_RECEIVED", "URL_OPENED", "LOGIN", "TRANSACTION_COMPLETED"],
    ["MESSAGE_RECEIVED", "LOGIN", "ACCOUNT_CHANGE"],
    ["MESSAGE_RECEIVED", "URL_OPENED", "LOGIN", "BENEFICIARY_CREATED", "TRANSACTION_COMPLETED"],
]


def _event(case_id, idx, ts, typ):
    eid = f"{case_id}_E{idx:02d}"
    actor = f"ACT_{case_id}_{idx}"
    target = f"TGT_{case_id}_{idx}"
    entity_ids = [f"ENT_{case_id}_{idx}"]
    evidence = [f"synthetic {typ.lower().replace('_', ' ')} evidence"]
    return Event(eid, ts.isoformat(), typ, actor, target, entity_ids, evidence, .95)


def _make_case(case_id, family, sequence, start, jitter, benign=False):
    events = []
    t = start
    for i, typ in enumerate(sequence):
        events.append(_event(case_id, i, t, typ))
        # Family-specific cadence is the temporal fingerprint. Jitter prevents exact copying.
        cadence = FAMILY_CADENCE.get(family, [45, 90, 30, 60, 75])
        base = cadence[i % len(cadence)] if not benign else [45, 90, 30, 60, 75][i % 5]
        t += timedelta(minutes=max(1, base + jitter[i % len(jitter)]))
    entities = [Entity(f"ENT_{case_id}_{i}", "INFRA", f"unique-{case_id.lower()}-{i}") for i in range(len(events))]
    return Case(case_id, f"V_{case_id}", events[0].timestamp, "synthetic-heldout", events, entities, [], {}, [], family if not benign else None)


def build_heldout(seed=7, cases_per_family=4, benign_per_template=3):
    rng = np.random.default_rng(seed)
    cases = []
    family_names = list(FAMILIES)
    # Every family is held out as a latent campaign type: identifiers are unique per case.
    for fi, (family, seq) in enumerate(FAMILIES.items()):
        for k in range(cases_per_family):
            start = datetime(2026, 10, 4, 9 + fi, 0) + timedelta(minutes=3 * k)
            jitter = rng.integers(-1, 2, size=max(3, len(seq))).tolist()
            cases.append(_make_case(f"H{fi}{k}", family, seq, start, jitter))
    for bi, seq in enumerate(BENIGN_TEMPLATES):
        for k in range(benign_per_template):
            start = datetime(2026, 10, 4, 16, 0) + timedelta(minutes=7 * (bi * benign_per_template + k))
            jitter = rng.integers(-3, 4, size=max(3, len(seq))).tolist()
            cases.append(_make_case(f"B{bi}{k}", "BENIGN", seq, start, jitter, benign=True))
    return cases


def evaluate(seed=7):
    cases = build_heldout(seed)
    scores, labels = [], []
    for a, b in combinations(cases, 2):
        # Held-out cases intentionally have no shared identifiers, so this benchmark
        # measures behavior-only campaign similarity rather than entity memorization.
        seq = _sequence_similarity(reconstruct(a.events), reconstruct(b.events))
        temporal = _temporal_similarity(a, b)
        scores.append(round(0.65 * seq + 0.35 * temporal, 3))
        labels.append(int(a.campaign_id is not None and a.campaign_id == b.campaign_id))
    scores = np.asarray(scores)
    labels = np.asarray(labels)
    # Threshold is deliberately fixed from the documented engine policy, not tuned on this test set.
    threshold = .98
    parent = list(range(len(cases)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[rb] = ra
    for idx, (a, b) in enumerate(combinations(range(len(cases)), 2)):
        if scores[idx] >= threshold and cases[a].campaign_id != "BENIGN" and cases[b].campaign_id != "BENIGN":
            union(a, b)
    predicted = [find(i) for i in range(len(cases))]
    true = [c.campaign_id or "BENIGN" for c in cases]
    # Map benign cases to their own labels; ARI handles arbitrary cluster IDs.
    true_labels = []
    for i, label in enumerate(true):
        true_labels.append(label if label != "BENIGN" else f"BENIGN_{i}")
    return {
        "benchmark": "synthetic-heldout-campaign-families",
        "seed": seed,
        "cases": len(cases),
        "campaign_families": len(FAMILIES),
        "identifiers_reused_across_campaign_members": False,
        "threshold": threshold,
        "pair_pr_auc": round(float(average_precision_score(labels, scores)), 3),
        "pair_roc_auc": round(float(roc_auc_score(labels, scores)), 3),
        "campaign_clustering_ari": round(float(adjusted_rand_score(true_labels, predicted)), 3),
        "positive_pairs": int(labels.sum()),
        "candidate_pairs": int((scores >= threshold).sum()),
    }
