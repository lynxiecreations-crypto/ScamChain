from data import make_cases
from engine import campaign_similarity, reconstruct


def test_case_count_and_temporal_reconstruction():
    cases = make_cases()
    assert len(cases) == 4
    assert reconstruct(cases[0].events)[0] == "SOCIAL_ENGINEERING"
    assert "BENEFICIARY_DIVERSION" in reconstruct(cases[0].events)


def test_campaign_discovery_is_not_hardcoded():
    cases = make_cases()
    assert cases[0].campaign_id == "CMP-001"
    assert cases[1].campaign_id == "CMP-001"
    assert cases[2].campaign_id == "CMP-001"
    assert cases[3].campaign_id is None
    assert campaign_similarity(cases[0], cases[1]) >= 0.25
    assert campaign_similarity(cases[0], cases[3]) < 0.40


def test_risk_and_intervention():
    cases = make_cases()
    assert cases[0].risk["score"] > cases[3].risk["score"]
    assert cases[0].risk["policy"] == "HIGH RISK"
    assert cases[3].risk["policy"] == "NORMAL"
    assert cases[0].risk["intervention"]["stage"] == "BENEFICIARY_CREATION"


def test_18_signal_catalog_is_represented():
    cases = make_cases()
    positive = {s["signal"] for c in cases for s in c.signals}
    expected = {
        "URGENCY", "THREAT_LANGUAGE", "AUTHORITY_IMPERSONATION", "CREDENTIAL_OTP_SOLICITATION",
        "NEW_UNVERIFIED_IDENTITY", "MALICIOUS_URL", "DOMAIN_REPUTATION", "INFRASTRUCTURE_REUSE",
        "SUSPICIOUS_IP_DEVICE", "UNUSUAL_VICTIM_BEHAVIOR", "NEW_BENEFICIARY", "TRANSACTION_DEVIATION",
        "SUSPICIOUS_EVENT_ORDER", "COMPRESSED_WORKFLOW", "CROSS_CASE_ENTITY_REUSE", "ATTACK_PATTERN_SIMILARITY",
    }
    assert expected <= positive


def test_benign_case_has_no_intervention():
    cases = make_cases()
    assert cases[3].risk["intervention"]["stage"] == "NONE"
