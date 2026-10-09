"""Synthetic benchmark for provenance, replay, and counterfactual evidence reasoning."""
from datetime import datetime, timedelta
from models import Entity, Event, Case
from engine import investigation_explanation

FULL=["MESSAGE_RECEIVED","URL_OPENED","CREDENTIAL_REQUEST","OTP_REQUEST","LOGIN","BENEFICIARY_CREATED","TRANSACTION_INITIATED","TRANSACTION_COMPLETED"]

def make(seq, blank_event=None):
    ev=[]
    for i,t in enumerate(seq):
        evidence=[] if i == blank_event else [t.lower().replace("_"," ")]
        ev.append(Event(f"P{i+1}",(datetime(2026,10,8,9,0)+timedelta(minutes=i*3)).isoformat(),t,"ACTOR","TARGET",["E"],evidence,.95))
    return Case("PX","VX",ev[0].timestamp,"benchmark",ev,[Entity("E","ACCOUNT","E")],[],{},[],None)

def evaluate():
    full=make(FULL)
    x=investigation_explanation(full.events, [])
    observed=[r for r in x["stage_provenance"] if r["status"]=="OBSERVED"]
    provenance_coverage=round(len(observed)/6,3)
    critical=[r for r in x["counterfactual_events"] if r["critical"]]
    # Group counterfactual: remove all events mapped to each canonical stage.
    stage_events={
        "SOCIAL_ENGINEERING":{"MESSAGE_RECEIVED"},
        "TRUST_ESTABLISHMENT":{"URL_OPENED"},
        "CREDENTIAL_CAPTURE":{"CREDENTIAL_REQUEST","OTP_REQUEST"},
        "ACCOUNT_COMPROMISE":{"LOGIN"},
        "BENEFICIARY_DIVERSION":{"BENEFICIARY_CREATED"},
        "FINANCIAL_TRANSFER":{"TRANSACTION_INITIATED","TRANSACTION_COMPLETED"},
    }
    checks=[]
    for stage, types in stage_events.items():
        remaining=[e for e in full.events if e.event_type not in types]
        y=investigation_explanation(remaining, [])
        checks.append(stage not in y["evidence_completeness"]["observed_stages"])
    return {
        "benchmark":"synthetic-provenance-replay-counterfactual",
        "provenance_coverage":provenance_coverage,
        "critical_event_count":len(critical),
        "stage_counterfactual_checks_passed":sum(checks),
        "stage_counterfactual_checks_total":len(checks),
        "replay_steps":len(x["attack_replay"]),
        "evidence_gap_count":len(x["evidence_gaps"]),
        "interpretation":"Synthetic explainability benchmark only; provenance confidence is not fraud probability."
    }
