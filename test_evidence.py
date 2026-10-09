from evidence_eval import evaluate
from engine import evidence_completeness
from models import Event

def test_evidence_benchmark_monotonic():
    r=evaluate(); assert r['monotonic_completeness'] is True; assert len(r['rows'])==8

def test_empty_evidence_is_insufficient():
    assert evidence_completeness([])['status']=='INSUFFICIENT'
