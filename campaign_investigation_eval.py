from data import make_cases
from engine import EXPECTED_ATTACK_STAGES, campaign_investigation


def benchmark():
    cases = make_cases()
    cid = next(c.campaign_id for c in cases if c.campaign_id)
    d = campaign_investigation(cases, cid)
    coverage = {x['stage']: x['coverage'] for x in d['stage_matrix']}
    return {
        'campaign_id': cid,
        'case_count': d['case_count'],
        'replay_steps': len(d['replay']),
        'stage_coverage_complete': all(coverage[s] > 0 for s in EXPECTED_ATTACK_STAGES[:5]),
        'pair_evidence_count': len(d['pair_evidence']),
        'earliest_intervention_stage': d['intervention']['stage'],
        'cross_case_replay_ordered': all(d['replay'][i]['timestamp'] <= d['replay'][i+1]['timestamp'] for i in range(len(d['replay'])-1)),
    }

if __name__ == '__main__':
    print(benchmark())
