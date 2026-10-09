from data import make_cases
from engine import investigation_explanation, stage_provenance, evidence_gaps, counterfactual_analysis

def test_provenance_links_observed_stages_to_events():
    c=make_cases()[0]
    rows=stage_provenance(c.events,c.signals)
    assert len(rows)==6
    assert all(r["status"]=="OBSERVED" for r in rows)
    assert all(r["event_ids"] for r in rows)

def test_gaps_for_partial_case():
    c=make_cases()[0]
    rows=stage_provenance(c.events[:3], c.signals)
    gaps=evidence_gaps(c.events[:3], c.signals)
    assert any(r["stage"]=="ACCOUNT_COMPROMISE" and r["status"]=="MISSING" for r in rows)
    assert any(g["stage"]=="ACCOUNT_COMPROMISE" for g in gaps)

def test_counterfactual_identifies_stage_critical_events():
    c=make_cases()[0]
    rows=counterfactual_analysis(c.events,c.signals)
    assert any(r["removed_stage"]=="BENEFICIARY_DIVERSION" and r["critical"] for r in rows)
    assert any(r["removed_stage"]=="FINANCIAL_TRANSFER" for r in rows)

def test_full_investigation_explanation():
    c=make_cases()[0]
    x=investigation_explanation(c.events,c.signals)
    assert len(x["attack_replay"])==len(c.events)
    assert x["evidence_completeness"]["status"]=="COMPLETE"
    assert x["critical_events"]

def test_stage_context_uplift_requires_distinct_domains():
    from adversarial_eval import _make, ATTACK, BENIGN, _attack_observed_score
    from datetime import datetime
    early=_make("EARLY", ATTACK[:3], datetime(2026,10,6,9), attack=True, rotated=True, missing_evidence=False)
    benign=_make("GOOD", BENIGN, datetime(2026,10,5,9), attack=False, rotated=True, missing_evidence=False)
    benign.events[0].evidence=["Security notice: review your account immediately to avoid service interruption."]
    assert _attack_observed_score(early)[0] >= 35
    assert _attack_observed_score(benign)[0] < 35
