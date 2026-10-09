"""Live intake pipeline for ScamChain's interactive investigation workbench.

Rule-based evidence extraction is combined with the existing 18-signal engine and
persisted synthetic-demo classifier. This is a research prototype, not a production
fraud verdict or a replacement for bank controls.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import re
import hashlib
import uuid

from models import Entity, Event, Case
from engine import detect_signals, risk_fusion, intervention, reconstruct, investigation_explanation
from ml import score_case

def _id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.lower().strip().encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}_{digest}"

def _domain(url: str) -> str:
    raw = url.strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else "https://" + raw
    try:
        return (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return ""

def _suspicious_domain(domain: str) -> bool:
    if not domain:
        return False
    cues = ("verify", "secure", "account", "login", "update", "kyc", "banking", "support")
    return any(cue in domain for cue in cues) or domain.endswith((".zip", ".top", ".click", ".work"))

def analyze_submission(payload: dict, known_cases: list[Case]) -> dict:
    message = str(payload.get("message", ""))[:6000].strip()
    url = str(payload.get("url", ""))[:1000].strip()
    sender = str(payload.get("sender", ""))[:200].strip()
    beneficiary = str(payload.get("beneficiary", ""))[:200].strip()
    has_login = bool(payload.get("new_device_login", False))
    has_beneficiary = bool(payload.get("beneficiary_created", False))
    has_transfer = bool(payload.get("transfer_initiated", False))
    if not message and not url and not sender:
        raise ValueError("Enter at least a message, URL, or sender identifier.")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    base = now
    events: list[Event] = []
    entities: list[Entity] = []
    entity_by_value: dict[str, str] = {}
    def add_entity(kind: str, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        key = value.lower()
        if key not in entity_by_value:
            eid = _id(kind, value)
            entity_by_value[key] = eid
            entities.append(Entity(eid, kind, value))
        return entity_by_value[key]
    def add_event(i: int, typ: str, actor: str, target: str, eids: list[str], evidence: list[str], mins: int):
        events.append(Event(f"IN{i:02d}", (base + timedelta(minutes=mins)).isoformat(), typ,
                            actor, target, [x for x in eids if x], evidence, 0.92))

    sender_id = add_entity("PHONE", sender) if sender else ""
    domain = _domain(url)
    domain_id = add_entity("DOMAIN", domain) if domain else ""
    url_id = add_entity("URL", url) if url else ""
    if beneficiary:
        add_entity("BENEFICIARY", beneficiary)
    account_id = add_entity("ACCOUNT", "Submitted account (synthetic placeholder)")
    device_id = add_entity("DEVICE", "Unrecognized device") if has_login else ""
    ip_id = add_entity("IP", "Unrecognized source IP") if has_login else ""

    message_low = message.lower()
    evidence_msg = [message] if message else ["Sender/URL submitted without message text."]
    if any(x in message_low for x in ("impersonat", "bank security", "rbi", "police", "government", "account will be blocked")):
        evidence_msg.append("Possible trusted-brand or authority impersonation cue.")
    if any(x in message_low for x in ("urgent", "immediately", "within ", "blocked", "suspended", "legal action")):
        evidence_msg.append("Urgency or threat language detected.")
    add_event(1, "MESSAGE_RECEIVED", sender_id or "UNKNOWN_SENDER", "USER",
              [sender_id, _id("MSG", message or sender)], evidence_msg, 0)

    cursor = 1
    if url:
        cursor += 1
        url_evidence = [f"Submitted URL: {url}"]
        if _suspicious_domain(domain):
            url_evidence.append("New verification domain / look-alike infrastructure cue; verify domain ownership independently.")
        add_event(cursor, "URL_OPENED", "USER", url_id, [url_id, domain_id], url_evidence, 3)
    if any(x in message_low for x in ("password", "credentials", "netbanking", "login details", "user id", "userid")):
        cursor += 1
        add_event(cursor, "CREDENTIAL_REQUEST", url_id or sender_id or "MESSAGE", "USER",
                   [url_id, sender_id], ["Credential or password solicitation language in submitted message."], 5)
    if any(x in message_low for x in ("otp", "one-time password", "verification code", "share code")):
        cursor += 1
        add_event(cursor, "OTP_REQUEST", sender_id or url_id or "MESSAGE", "USER",
                   [sender_id, url_id], ["One-time code / verification-code solicitation language in submitted message."], 6)
    if has_login:
        cursor += 1
        add_event(cursor, "LOGIN", ip_id, account_id, [ip_id, device_id, account_id],
                   ["User indicated a new-device or unfamiliar login after the suspicious contact."], 10)
    if has_beneficiary:
        cursor += 1
        ben_id = add_entity("BENEFICIARY", beneficiary or "New beneficiary (identifier not supplied)")
        add_event(cursor, "BENEFICIARY_CREATED", account_id, ben_id, [account_id, ben_id],
                   ["User indicated a new beneficiary was created."], 12)
    if has_transfer:
        cursor += 1
        ben_id = add_entity("BENEFICIARY", beneficiary or "New beneficiary (identifier not supplied)")
        tx_id = add_entity("TRANSACTION", "Submitted transaction (synthetic placeholder)")
        add_event(cursor, "TRANSACTION_INITIATED", account_id, ben_id, [account_id, ben_id, tx_id],
                   ["User indicated a transfer was initiated."], 13)

    # Correlate against demo cases using normalized entity values, never just IDs.
    known_values = {e.value.lower(): e.entity_id for c in known_cases for e in c.entities}
    reused_ids = [eid for e in entities if (eid := known_values.get(e.value.lower()))]
    signals = detect_signals(type("SubmittedCase", (), {"events": events, "entities": entities})(),
                             cross_case_entity_ids=reused_ids)
    fused = risk_fusion(signals)
    intervention_result = intervention(events, signals)
    attack_chain = reconstruct(events)
    # The classifier is a separate synthetic-data demo signal; do not present it as a real-world probability.
    case = Case(
        case_id="LIVE-" + now.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6].upper(),
        victim_id="SUBMITTED-USER",
        created_at=now.isoformat(),
        source="Interactive analyst intake",
        events=events, entities=entities, signals=signals,
        risk={**fused, "intervention": intervention_result},
        attack_chain=attack_chain,
        campaign_id=None,
    )
    try:
        ml_score = score_case(case)
        model_status = "synthetic_demo_model"
    except Exception as exc:
        ml_score = None
        model_status = f"model_unavailable: {type(exc).__name__}"
    explain = investigation_explanation(events, signals)
    signal_rows = sorted(signals, key=lambda x: (x["severity"] * x["confidence"], x["signal"]), reverse=True)
    next_steps = []
    if any(s["signal"] in {"CREDENTIAL_OTP_SOLICITATION", "AUTHORITY_IMPERSONATION"} for s in signals):
        next_steps.append("Do not share OTPs, passwords, PINs, or remote-access permissions; verify through the institution's official app or number.")
    if domain and _suspicious_domain(domain):
        next_steps.append("Do not revisit the submitted URL. Check the registrable domain through a trusted source; URL wording alone does not prove maliciousness.")
    if has_login:
        next_steps.append("If this login was not yours, use the bank's official channel to secure the account and revoke unknown sessions.")
    if has_beneficiary or has_transfer:
        next_steps.append("Contact the bank through its official channel immediately to ask about beneficiary holds, transfer recall, and account protection.")
    if not next_steps:
        next_steps.append("Gather the original message headers, verified sender identity, and any event timestamps before escalating.")
    return {
        "case": case.to_dict(),
        "assessment": {
            "risk_score": fused["score"], "policy": fused["policy"],
            "signal_count": len(signals), "model_score": ml_score,
            "model_score_label": "Synthetic-demo classifier score (not a real-world fraud probability)",
            "model_status": model_status,
            "evidence_completeness": explain["evidence_completeness"],
            "stage_provenance": explain["stage_provenance"],
            "evidence_gaps": explain["evidence_gaps"],
            "attack_replay": explain["attack_replay"],
            "counterfactual_events": explain["counterfactual_events"],
            "intervention": intervention_result,
            "signals": signal_rows,
            "next_steps": next_steps,
            "caveat": "Prototype triage only. Inputs are processed by heuristic rules plus a classifier trained on synthetic data. Confirm findings independently; do not automate financial blocking from this result."
        }
    }
