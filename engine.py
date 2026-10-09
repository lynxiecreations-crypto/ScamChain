from collections import defaultdict
from datetime import datetime
from itertools import combinations

SIGNALS = [
    ("URGENCY", "communication"),
    ("THREAT_LANGUAGE", "communication"),
    ("AUTHORITY_IMPERSONATION", "communication"),
    ("CREDENTIAL_OTP_SOLICITATION", "communication"),
    ("IDENTITY_INCONSISTENCY", "identity"),
    ("KNOWN_ENTITY_IMPERSONATION", "identity"),
    ("NEW_UNVERIFIED_IDENTITY", "identity"),
    ("MALICIOUS_URL", "infrastructure"),
    ("DOMAIN_REPUTATION", "infrastructure"),
    ("INFRASTRUCTURE_REUSE", "infrastructure"),
    ("SUSPICIOUS_IP_DEVICE", "infrastructure"),
    ("UNUSUAL_VICTIM_BEHAVIOR", "behavioral"),
    ("NEW_BENEFICIARY", "behavioral"),
    ("TRANSACTION_DEVIATION", "behavioral"),
    ("SUSPICIOUS_EVENT_ORDER", "temporal"),
    ("COMPRESSED_WORKFLOW", "temporal"),
    ("CROSS_CASE_ENTITY_REUSE", "graph"),
    ("ATTACK_PATTERN_SIMILARITY", "graph"),
]

STAGE_MAP = {
    "MESSAGE_RECEIVED": "SOCIAL_ENGINEERING",
    "URL_OPENED": "TRUST_ESTABLISHMENT",
    "CREDENTIAL_REQUEST": "CREDENTIAL_CAPTURE",
    "OTP_REQUEST": "CREDENTIAL_CAPTURE",
    "LOGIN": "ACCOUNT_COMPROMISE",
    "BENEFICIARY_CREATED": "BENEFICIARY_DIVERSION",
    "TRANSACTION_INITIATED": "FINANCIAL_TRANSFER",
    "TRANSACTION_COMPLETED": "FINANCIAL_TRANSFER",
}

EXPECTED_ATTACK_STAGES = [
    "SOCIAL_ENGINEERING", "TRUST_ESTABLISHMENT", "CREDENTIAL_CAPTURE",
    "ACCOUNT_COMPROMISE", "BENEFICIARY_DIVERSION", "FINANCIAL_TRANSFER"
]

def _dt(s):
    return datetime.fromisoformat(s)

def reconstruct(events):
    ordered = sorted(events, key=lambda x: x.timestamp)
    stages = []
    for e in ordered:
        stage = STAGE_MAP.get(e.event_type)
        if stage and (not stages or stages[-1] != stage):
            stages.append(stage)
    return stages

def temporal_features(events):
    ordered = sorted(events, key=lambda x: x.timestamp)
    if len(ordered) < 2:
        return 0.0, 0.0
    minutes = (_dt(ordered[-1].timestamp) - _dt(ordered[0].timestamp)).total_seconds() / 60
    compressed = 1.0 if minutes <= 30 else max(0.0, 1 - minutes / 180)
    types = [e.event_type for e in ordered]
    suspicious_order = int("CREDENTIAL_REQUEST" in types and "BENEFICIARY_CREATED" in types and types.index("CREDENTIAL_REQUEST") < types.index("BENEFICIARY_CREATED"))
    return float(suspicious_order), round(compressed, 3)

def evidence_completeness(events, signals=None):
    """Estimate how completely observed evidence supports the canonical attack chain.

    Separate from scam risk: a case may be high-risk while the observed chain is
    incomplete. The score is a triage/uncertainty indicator, not fraud probability.
    """
    stages = reconstruct(events)
    if not events:
        return {"score": 0.0, "status": "INSUFFICIENT", "observed_stages": [], "missing_stages": EXPECTED_ATTACK_STAGES}
    observed = set(stages)
    stage_coverage = len(observed & set(EXPECTED_ATTACK_STAGES)) / len(EXPECTED_ATTACK_STAGES)
    evidence_stages = set()
    for e in events:
        if e.evidence and STAGE_MAP.get(e.event_type):
            evidence_stages.add(STAGE_MAP[e.event_type])
    evidence_stage_coverage = len(evidence_stages & observed) / max(1, len(observed))
    event_confidence = sum(e.confidence for e in events) / len(events)
    # Stage coverage dominates. Evidence quality is monotonic as new stages appear,
    # and cannot erase confidence merely because a later event lacks text evidence.
    score = round(100 * (0.80 * stage_coverage + 0.15 * evidence_stage_coverage + 0.05 * event_confidence), 1)
    missing = [x for x in EXPECTED_ATTACK_STAGES if x not in stages]
    status = "COMPLETE" if score >= 75 and len(missing) <= 1 else "PARTIAL" if score >= 35 else "INSUFFICIENT"
    return {"score": score, "status": status, "observed_stages": stages, "missing_stages": missing}



def stage_provenance(events, signals=None):
    """Return evidence-backed provenance for every reconstructed attack stage."""
    ordered = sorted(events, key=lambda x: x.timestamp)
    by_stage = defaultdict(list)
    for e in ordered:
        stage = STAGE_MAP.get(e.event_type)
        if stage:
            by_stage[stage].append(e)

    signal_map = defaultdict(list)
    for sig in signals or []:
        for eid in sig.get("evidence", []):
            signal_map[eid].append(sig["signal"])

    rows = []
    for stage in EXPECTED_ATTACK_STAGES:
        evs = by_stage.get(stage, [])
        if not evs:
            rows.append({
                "stage": stage, "status": "MISSING", "confidence": 0.0,
                "event_ids": [], "evidence_ids": [], "supporting_signals": [],
                "rationale": "No observed event maps to this attack stage."
            })
            continue
        event_conf = sum(e.confidence for e in evs) / len(evs)
        evidence_coverage = sum(bool(e.evidence) for e in evs) / len(evs)
        signal_support = len({x for e in evs for x in signal_map.get(e.event_id, [])})
        signal_factor = min(1.0, signal_support / 2.0)
        # Evidence and event confidence support the inference; signal support is a
        # secondary corroboration and cannot compensate for missing stage evidence.
        conf = 100 * (0.60 * event_conf + 0.25 * evidence_coverage + 0.15 * signal_factor)
        evidence_ids = sorted({e.event_id for e in evs if e.evidence})
        signals_supported = sorted({x for e in evs for x in signal_map.get(e.event_id, [])})
        rows.append({
            "stage": stage,
            "status": "OBSERVED",
            "confidence": round(conf, 1),
            "event_ids": [e.event_id for e in evs],
            "evidence_ids": evidence_ids,
            "supporting_signals": signals_supported,
            "rationale": f"Observed {len(evs)} event(s) mapped to {stage}."
        })
    return rows


def evidence_gaps(events, signals=None):
    """Explain which missing stages/evidence would most improve reconstruction."""
    provenance = stage_provenance(events, signals)
    missing = [x for x in provenance if x["status"] == "MISSING"]
    gaps = []
    for row in missing:
        stage = row["stage"]
        event_types = [k for k, v in STAGE_MAP.items() if v == stage]
        gaps.append({
            "stage": stage,
            "priority": "HIGH" if stage in {"CREDENTIAL_CAPTURE", "ACCOUNT_COMPROMISE", "BENEFICIARY_DIVERSION", "FINANCIAL_TRANSFER"} else "MEDIUM",
            "expected_event_types": event_types,
            "request": f"Seek corroborating evidence for {stage.lower().replace('_',' ')}.",
        })
    return gaps


def attack_replay(events, signals=None):
    """Produce a chronological, evidence-linked replay of the observed workflow."""
    signal_map = defaultdict(list)
    for sig in signals or []:
        for eid in sig.get("evidence", []):
            signal_map[eid].append(sig["signal"])
    replay=[]
    for idx, e in enumerate(sorted(events, key=lambda x: x.timestamp), 1):
        stage=STAGE_MAP.get(e.event_type, "UNMAPPED")
        replay.append({
            "step": idx, "event_id": e.event_id, "timestamp": e.timestamp,
            "event_type": e.event_type, "stage": stage,
            "actor": e.actor, "target": e.target, "entities": e.entities,
            "evidence": e.evidence, "signals": sorted(set(signal_map.get(e.event_id, []))),
            "confidence": round(e.confidence, 3),
        })
    return replay


def counterfactual_analysis(events, signals=None):
    """Measure how removal of each event changes evidence completeness."""
    base = evidence_completeness(events, signals)
    rows=[]
    for removed in events:
        remaining=[e for e in events if e.event_id != removed.event_id]
        comp=evidence_completeness(remaining, None)
        base_stages=set(base["observed_stages"])
        new_stages=set(comp["observed_stages"])
        rows.append({
            "removed_event_id": removed.event_id,
            "removed_event_type": removed.event_type,
            "removed_stage": STAGE_MAP.get(removed.event_type, "UNMAPPED"),
            "baseline_completeness": base["score"],
            "counterfactual_completeness": comp["score"],
            "completeness_drop": round(base["score"] - comp["score"], 1),
            "stages_lost": sorted(base_stages - new_stages),
            "critical": bool(base_stages - new_stages),
        })
    return sorted(rows, key=lambda x: (-x["completeness_drop"], x["removed_event_id"]))


def investigation_explanation(events, signals=None):
    comp=evidence_completeness(events, signals)
    prov=stage_provenance(events, signals)
    gaps=evidence_gaps(events, signals)
    replay=attack_replay(events, signals)
    cf=counterfactual_analysis(events, signals)
    return {
        "evidence_completeness": comp,
        "stage_provenance": prov,
        "evidence_gaps": gaps,
        "attack_replay": replay,
        "counterfactual_events": cf,
        "critical_events": [x for x in cf if x["critical"]],
    }

def detect_signals(case, cross_case_entity_ids=None, attack_similarity=0.0):
    evidence_text = [x.lower() for ev in case.events for x in ev.evidence]
    text = " ".join(evidence_text)
    types = {e.event_type for e in case.events}
    entities = {e.entity_id for e in case.entities}
    suspicious_order, compressed = temporal_features(case.events)
    reused = entities & set(cross_case_entity_ids or [])
    vals = {
        "URGENCY": 1.0 if any(x in text for x in ["urgent", "immediately", "within 10 minutes"]) else 0.0,
        "THREAT_LANGUAGE": 1.0 if any(x in text for x in ["blocked", "legal action", "suspended"]) else 0.0,
        "AUTHORITY_IMPERSONATION": 1.0 if any(x in text for x in ["bank security", "police", "government", "rbi"]) else 0.0,
        "CREDENTIAL_OTP_SOLICITATION": 1.0 if {"CREDENTIAL_REQUEST", "OTP_REQUEST"} & types else 0.0,
        "IDENTITY_INCONSISTENCY": 1.0 if "identity mismatch" in text else 0.0,
        "KNOWN_ENTITY_IMPERSONATION": 1.0 if "impersonat" in text else 0.0,
        "NEW_UNVERIFIED_IDENTITY": 1.0 if ("MESSAGE_RECEIVED" in types and any(x.type == "PHONE" for x in case.entities) and any(any(k in ev for k in ["new", "unverified", "unknown"]) for ev in evidence_text)) else 0.0,
        "MALICIOUS_URL": 1.0 if ("URL_OPENED" in types and any(x.type == "DOMAIN" and any(k in x.value.lower() for k in ["secure", "verify", "account", "login"]) for x in case.entities) and any(any(k in ev.lower() for k in ["malicious", "look-alike", "verification domain", "new verification"]) for ev in evidence_text)) else 0.0,
        "DOMAIN_REPUTATION": 1.0 if any(x.type == "DOMAIN" and any(k in x.value.lower() for k in ["secure", "verify", "account"]) for x in case.entities) else 0.0,
        "INFRASTRUCTURE_REUSE": 1.0 if reused else 0.0,
        "SUSPICIOUS_IP_DEVICE": 1.0 if any(x.type in {"IP", "DEVICE"} for x in case.entities) and "LOGIN" in types else 0.0,
        "UNUSUAL_VICTIM_BEHAVIOR": 1.0 if ("LOGIN" in types and "TRANSACTION_INITIATED" in types and any(any(k in ev for k in ["new device", "unknown device", "unrecognized"]) for ev in evidence_text)) else 0.0,
        "NEW_BENEFICIARY": 1.0 if "BENEFICIARY_CREATED" in types else 0.0,
        "TRANSACTION_DEVIATION": 1.0 if ("TRANSACTION_INITIATED" in types and ("BENEFICIARY_CREATED" in types or any(any(k in ev for k in ["unusual", "deviation", "new beneficiary", "unexpected"]) for ev in evidence_text))) else 0.0,
        "SUSPICIOUS_EVENT_ORDER": suspicious_order,
        "COMPRESSED_WORKFLOW": compressed,
        "CROSS_CASE_ENTITY_REUSE": 1.0 if reused else 0.0,
        "ATTACK_PATTERN_SIMILARITY": attack_similarity,
    }
    out = []
    for name, domain in SIGNALS:
        v = vals[name]
        if v > 0:
            evidence = []
            for ev in case.events:
                if name in ev.evidence or (name == "NEW_BENEFICIARY" and ev.event_type == "BENEFICIARY_CREATED") or (name == "MALICIOUS_URL" and ev.event_type == "URL_OPENED"):
                    evidence.append(ev.event_id)
                if name in {"INFRASTRUCTURE_REUSE", "CROSS_CASE_ENTITY_REUSE"} and reused and set(ev.entities) & reused:
                    evidence.append(ev.event_id)
            evidence = sorted(set(evidence))
            out.append({"signal": name, "domain": domain, "value": round(v, 3), "severity": round(v, 3), "confidence": 0.92, "evidence": evidence})
    return out


def risk_fusion(signals):
    domains = defaultdict(list)
    for s in signals:
        domains[s["domain"]].append(s["severity"] * s["confidence"])
    domain_scores = {d: round(min(100, sum(v) / max(1, len(v)) * 100), 1) for d, v in domains.items()}
    for d in ["communication", "identity", "infrastructure", "behavioral", "temporal", "graph"]:
        domain_scores.setdefault(d, 0.0)
    weights = {"communication": .15, "identity": .10, "infrastructure": .20, "behavioral": .20, "temporal": .15, "graph": .20}
    score = sum(domain_scores[d] * weights[d] for d in weights)
    signal_names = {s["signal"] for s in signals}
    # Stage-aware contextual uplift catches early workflow escalation without
    # turning generic urgency into a fraud verdict. It requires multiple distinct
    # attack-stage cues and therefore remains separate from raw signal count.
    stage_context = 0.0
    if "communication" in domain_scores and domain_scores["communication"] >= 70:
        if "infrastructure" in domain_scores and domain_scores["infrastructure"] >= 20:
            stage_context = 8.0
        if "behavioral" in domain_scores and domain_scores["behavioral"] >= 45:
            stage_context = 12.0
        # Credential/OTP solicitation is itself a distinct escalation stage.
        # Treating it as workflow context lets partial attacks surface for review
        # before downstream financial evidence exists.
        if "CREDENTIAL_OTP_SOLICITATION" in signal_names and stage_context == 0.0:
            stage_context = 8.0
    domain_scores["workflow_context"] = stage_context
    score = round(min(100.0, score + stage_context), 1)
    policy = "HIGH RISK" if score >= 65 else "REVIEW" if score >= 35 else "NORMAL"
    return {"score": score, "policy": policy, "components": domain_scores}


def intervention(events, signals):
    types = {e.event_type for e in events}
    signal_names = {s["signal"] for s in signals}
    completeness = evidence_completeness(events, signals)
    actionable = signal_names - {"COMPRESSED_WORKFLOW"}
    if not actionable:
        return {"stage": "NONE", "action": "No intervention", "reason": "No actionable scam signal detected.", "evidence_status": completeness["status"]}
    # Do not overstate a partial chain. Escalate for evidence review rather than taking
    # an irreversible action when the observed evidence is incomplete.
    if completeness["status"] == "INSUFFICIENT":
        return {"stage": "EVIDENCE_REVIEW", "action": "Collect corroborating evidence", "reason": "Signals are present but the observed attack chain is too incomplete for a stronger intervention.", "evidence_status": completeness["status"]}
    if completeness["status"] == "PARTIAL" and "BENEFICIARY_CREATED" not in types and "TRANSACTION_INITIATED" not in types:
        return {"stage": "EVIDENCE_REVIEW", "action": "Step-up verification / analyst review", "reason": "Suspicious activity is present, but downstream attack stages are not yet observed.", "evidence_status": completeness["status"]}
    if "BENEFICIARY_CREATED" in types and "NEW_BENEFICIARY" in signal_names:
        return {"stage": "BENEFICIARY_CREATION", "action": "Step-up verification / beneficiary hold", "reason": "Suspicious preceding workflow plus new beneficiary signal.", "evidence_status": completeness["status"]}
    if "OTP_REQUEST" in types:
        return {"stage": "OTP_REQUEST", "action": "Trusted-channel verification", "reason": "Credential-capture stage detected before financial action.", "evidence_status": completeness["status"]}
    if "URL_OPENED" in types:
        return {"stage": "SUSPICIOUS_URL", "action": "Quarantine / warning", "reason": "Suspicious URL appears before downstream account activity.", "evidence_status": completeness["status"]}
    return {"stage": "MESSAGE", "action": "User warning", "reason": "Initial suspicious communication detected.", "evidence_status": completeness["status"]}


def _sequence_similarity(sa, sb):
    # Order-aware normalized LCS: shared stages in the same attack order matter.
    if not sa or not sb:
        return 0.0
    dp = [[0] * (len(sb) + 1) for _ in range(len(sa) + 1)]
    for i, x in enumerate(sa, 1):
        for j, y in enumerate(sb, 1):
            dp[i][j] = dp[i - 1][j - 1] + 1 if x == y else max(dp[i - 1][j], dp[i][j - 1])
    return dp[-1][-1] / max(len(sa), len(sb))


def _relative_intervals(events):
    ordered = sorted(events, key=lambda x: x.timestamp)
    if len(ordered) < 2:
        return []
    return [round((_dt(b.timestamp) - _dt(a.timestamp)).total_seconds() / 60, 2) for a, b in zip(ordered, ordered[1:])]


def _temporal_similarity(a, b):
    ia, ib = _relative_intervals(a.events), _relative_intervals(b.events)
    if not ia or not ib:
        return 0.0
    n = min(len(ia), len(ib))
    # Compare normalized interval shapes rather than absolute duration.
    sa, sb = sum(ia[:n]), sum(ib[:n])
    if sa == 0 or sb == 0:
        return 0.0
    na = [x / sa for x in ia[:n]]
    nb = [x / sb for x in ib[:n]]
    return max(0.0, 1 - sum(abs(x-y) for x, y in zip(na, nb)) / n)


def campaign_similarity(a, b):
    ea, eb = {e.entity_id for e in a.entities}, {e.entity_id for e in b.entities}
    overlap = len(ea & eb) / max(1, len(ea | eb))
    seq = _sequence_similarity(reconstruct(a.events), reconstruct(b.events))
    temporal = _temporal_similarity(a, b)
    score = 0.50 * overlap + 0.35 * seq + 0.15 * temporal
    return round(score, 3)


def campaign_evidence(a, b):
    shared = sorted({e.entity_id for e in a.entities} & {e.entity_id for e in b.entities})
    reasons = []
    if shared:
        reasons.append("shared entities: " + ", ".join(shared))
    if _sequence_similarity(reconstruct(a.events), reconstruct(b.events)) >= 0.5:
        reasons.append("workflow similarity")
    if _temporal_similarity(a, b) >= 0.7:
        reasons.append("temporal similarity")
    return reasons


def campaign_replay(cases, campaign_id):
    """Replay a detected campaign across cases using normalized stages and timestamps."""
    members = [c for c in cases if c.campaign_id == campaign_id]
    rows = []
    for c in members:
        for step in attack_replay(c.events, c.signals):
            rows.append({"campaign_id": campaign_id, "case_id": c.case_id, **step})
    return sorted(rows, key=lambda x: (x["timestamp"], x["case_id"], x["step"]))


def campaign_stage_matrix(cases, campaign_id):
    """Summarize stage coverage and confidence across campaign members."""
    members = [c for c in cases if c.campaign_id == campaign_id]
    matrix = []
    for stage in EXPECTED_ATTACK_STAGES:
        per_case = []
        for c in members:
            prov = {x["stage"]: x for x in stage_provenance(c.events, c.signals)}[stage]
            per_case.append({"case_id": c.case_id, "status": prov["status"], "confidence": prov["confidence"], "event_ids": prov["event_ids"]})
        observed = [x for x in per_case if x["status"] == "OBSERVED"]
        matrix.append({
            "stage": stage,
            "case_count": len(observed),
            "coverage": round(len(observed) / max(1, len(members)), 3),
            "mean_confidence": round(sum(x["confidence"] for x in observed) / max(1, len(observed)), 1),
            "cases": per_case,
        })
    return matrix


def campaign_intervention(cases, campaign_id):
    """Find the earliest observed intervention opportunity common to a campaign."""
    members = [c for c in cases if c.campaign_id == campaign_id]
    candidates = []
    for c in members:
        intr = c.risk.get("intervention", {})
        stage = intr.get("stage", "NONE")
        if stage != "NONE":
            idx = EXPECTED_ATTACK_STAGES.index(stage) if stage in EXPECTED_ATTACK_STAGES else len(EXPECTED_ATTACK_STAGES)
            candidates.append({"case_id": c.case_id, "stage": stage, "stage_index": idx, "action": intr.get("action"), "reason": intr.get("reason")})
    if not candidates:
        return {"stage": "NONE", "action": "No campaign-level intervention identified.", "supporting_cases": []}
    min_idx = min(x["stage_index"] for x in candidates)
    earliest = [x for x in candidates if x["stage_index"] == min_idx]
    return {"stage": earliest[0]["stage"], "action": earliest[0]["action"], "supporting_cases": [x["case_id"] for x in earliest], "case_observations": candidates}


def campaign_investigation(cases, campaign_id):
    members = [c for c in cases if c.campaign_id == campaign_id]
    if not members:
        return {"campaign_id": campaign_id, "case_count": 0, "cases": [], "stage_matrix": [], "replay": [], "intervention": {"stage": "NONE"}}
    shared = set.intersection(*[{e.entity_id for e in c.entities} for c in members]) if len(members) > 1 else set()
    pair_reasons = []
    for a, b in combinations(members, 2):
        pair_reasons.append({"case_a": a.case_id, "case_b": b.case_id, "similarity": campaign_similarity(a, b), "evidence": campaign_evidence(a, b)})
    return {
        "campaign_id": campaign_id,
        "case_count": len(members),
        "cases": [c.case_id for c in members],
        "shared_entities": sorted(shared),
        "pair_evidence": pair_reasons,
        "stage_matrix": campaign_stage_matrix(cases, campaign_id),
        "replay": campaign_replay(cases, campaign_id),
        "intervention": campaign_intervention(cases, campaign_id),
    }
