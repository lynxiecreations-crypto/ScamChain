from data import make_cases
from engine import EXPECTED_ATTACK_STAGES, campaign_investigation


def test_campaign_investigation_has_replay_and_stage_matrix():
    cases = make_cases()
    cid = next(c.campaign_id for c in cases if c.campaign_id)
    d = campaign_investigation(cases, cid)
    assert d['case_count'] >= 2
    assert len(d['replay']) >= d['case_count'] * 5
    assert len(d['stage_matrix']) == len(EXPECTED_ATTACK_STAGES)
    assert all(x['coverage'] > 0 for x in d['stage_matrix'][:5])
    assert d['pair_evidence']


def test_campaign_replay_is_temporally_ordered_and_intervention_is_explained():
    cases = make_cases()
    cid = next(c.campaign_id for c in cases if c.campaign_id)
    d = campaign_investigation(cases, cid)
    assert all(d['replay'][i]['timestamp'] <= d['replay'][i+1]['timestamp'] for i in range(len(d['replay'])-1))
    assert d['intervention']['stage'] != 'NONE'
    assert d['intervention']['supporting_cases']
