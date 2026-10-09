from data import make_cases
from ml import evaluate, score_case


def test_synthetic_ml_ablation_has_incremental_layers():
    out = evaluate(seed=42)
    assert out['benchmark'] == 'synthetic'
    assert out['rows'] == 1200
    assert out['split'] == 'grouped train/validation/test'
    results = {r['model']: r for r in out['results']}
    assert all(r['test_cases'] > 0 and r['validation_cases'] > 0 for r in results.values())
    assert results['B: ML + temporal']['pr_auc'] >= results['A: ML only']['pr_auc']
    assert results['C: ML + temporal + graph']['pr_auc'] >= results['B: ML + temporal']['pr_auc']
    assert all(0 <= r['brier'] <= 0.25 for r in results.values())


def test_case_scoring_separates_demo_scam_and_benign():
    cases = make_cases()
    scam = score_case(cases[0])
    benign = score_case(cases[3])
    assert 0 <= scam <= 1
    assert 0 <= benign <= 1
    assert scam > benign


def test_heldout_campaign_benchmark_is_identifier_independent():
    from campaign_eval import evaluate as evaluate_campaigns
    out = evaluate_campaigns(seed=7)
    assert out['identifiers_reused_across_campaign_members'] is False
    assert out['campaign_families'] == 6
    assert out['pair_pr_auc'] >= 0.55
    assert out['campaign_clustering_ari'] >= 0.75


def test_intervention_policy_benchmark():
    from intervention_eval import evaluate as evaluate_intervention
    out = evaluate_intervention()
    assert out['intervention_stage_accuracy'] == 1.0
    assert out['unnecessary_intervention_rate'] == 0.0
