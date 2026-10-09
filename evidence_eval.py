"""Synthetic evidence-completeness benchmark."""
from datetime import datetime, timedelta
from models import Entity, Event, Case
from engine import evidence_completeness, intervention

FULL=["MESSAGE_RECEIVED","URL_OPENED","CREDENTIAL_REQUEST","OTP_REQUEST","LOGIN","BENEFICIARY_CREATED","TRANSACTION_INITIATED","TRANSACTION_COMPLETED"]

def make(seq, missing=False):
    ev=[]
    for i,t in enumerate(seq):
        evidence=[] if (missing and i%2==0) else [t.lower().replace('_',' ')]
        ev.append(Event(f"E{i}",(datetime(2026,10,8,9,0)+timedelta(minutes=i*3)).isoformat(),t,"A","B",["A"],evidence,.95))
    return Case("X","V",ev[0].timestamp,"benchmark",ev,[Entity("A","ACCOUNT","A")],[],{},[],None)

def evaluate():
    prefixes=[FULL[:k] for k in range(1,len(FULL)+1)]
    rows=[]
    for k,seq in enumerate(prefixes,1):
        c=make(seq,missing=(k%3==0)); comp=evidence_completeness(c.events,[]); iv=intervention(c.events,[])
        rows.append({"observed_events":k,"completeness":comp,"intervention":iv})
    monotonic=all(rows[i]["completeness"]["score"] <= rows[i+1]["completeness"]["score"] for i in range(len(rows)-1))
    return {"benchmark":"synthetic-evidence-completeness","rows":rows,"monotonic_completeness":monotonic,"interpretation":"Synthetic uncertainty/triage benchmark only; not production performance."}
