from adversarial_eval import evaluate

def test_adversarial_benchmark_contract():
    r=evaluate(seed=19)
    assert r["adversarial_benign_cases"] == 30
    assert r["partial_attack_cases"] == 30
    assert r["reordered_attack_cases"] == 20
    assert r["reordered_attack_chain_accuracy"] == 1.0
    assert 0 <= r["adversarial_benign_false_positive_rate_at_review_threshold"] <= 1
    assert 0 <= r["partial_attack_detection_rate_at_review_threshold"] <= 1
    assert r["rotated_identifier_pair_similarity_mean"] > 0.45
