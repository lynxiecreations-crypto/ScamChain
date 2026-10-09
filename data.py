from models import Entity, Event, Case
from engine import detect_signals, reconstruct, risk_fusion, intervention, campaign_similarity, campaign_evidence, evidence_completeness


def event(i, ts, typ, actor, target, entities, evidence, conf=.97):
    return Event(i, ts, typ, actor, target, entities, evidence, conf)


def make_cases():
    specs = [
        ("C001", "V001", [
            event("E001","2026-10-03T09:01:00","MESSAGE_RECEIVED","PHONE_A","V001",["PHONE_A","MSG_1"],["Bank security alert: your account will be blocked immediately.","Known bank branding impersonated."]),
            event("E002","2026-10-03T09:04:00","URL_OPENED","V001","URL_A",["URL_A","DOMAIN_A"],["https://secure-bank-verify.example/login","New verification domain."]),
            event("E003","2026-10-03T09:07:00","CREDENTIAL_REQUEST","URL_A","V001",["URL_A"],["Enter netbanking credentials to prevent suspension."]),
            event("E004","2026-10-03T09:09:00","OTP_REQUEST","PHONE_A","V001",["PHONE_A"],["Share OTP immediately to restore access."]),
            event("E005","2026-10-03T09:13:00","LOGIN","IP_A","ACC_1",["IP_A","DEVICE_A","ACC_1"],["New device login following credential request."]),
            event("E006","2026-10-03T09:15:00","BENEFICIARY_CREATED","ACC_1","BEN_X",["ACC_1","BEN_X"],["New beneficiary created 2 minutes after login."]),
            event("E007","2026-10-03T09:16:00","TRANSACTION_INITIATED","ACC_1","BEN_X",["ACC_1","BEN_X","TX_1"],["Transfer initiated immediately after beneficiary creation."]),
            event("E008","2026-10-03T09:17:00","TRANSACTION_COMPLETED","ACC_1","BEN_X",["TX_1","BEN_X"],["Funds transferred."]),
        ], [Entity("PHONE_A","PHONE","+91-90000-10001"),Entity("DOMAIN_A","DOMAIN","secure-bank-verify.example"),Entity("URL_A","URL","https://secure-bank-verify.example/login"),Entity("IP_A","IP","198.51.100.10"),Entity("DEVICE_A","DEVICE","DEV-A"),Entity("ACC_1","ACCOUNT","ACC-001"),Entity("BEN_X","BENEFICIARY","BEN-X")]),
        ("C014", "V014", [
            event("E101","2026-10-03T10:21:00","MESSAGE_RECEIVED","PHONE_A","V014",["PHONE_A","MSG_14"],["Bank security team: verify immediately or account will be blocked.","Impersonated bank identity."]),
            event("E102","2026-10-03T10:25:00","URL_OPENED","V014","URL_B",["URL_B","DOMAIN_B"],["https://account-verify.example/auth","Look-alike verification domain."]),
            event("E103","2026-10-03T10:28:00","CREDENTIAL_REQUEST","URL_B","V014",["URL_B"],["Credential verification required."]),
            event("E104","2026-10-03T10:30:00","OTP_REQUEST","PHONE_A","V014",["PHONE_A"],["OTP required immediately."]),
            event("E105","2026-10-03T10:35:00","LOGIN","IP_A","ACC_14",["IP_A","DEVICE_B","ACC_14"],["New device login."]),
            event("E106","2026-10-03T10:37:00","BENEFICIARY_CREATED","ACC_14","BEN_Y",["ACC_14","BEN_Y"],["New beneficiary created."]),
            event("E107","2026-10-03T10:38:00","TRANSACTION_INITIATED","ACC_14","BEN_Y",["ACC_14","BEN_Y","TX_14"],["Transfer initiated after beneficiary creation."]),
        ], [Entity("PHONE_A","PHONE","+91-90000-10001"),Entity("DOMAIN_B","DOMAIN","account-verify.example"),Entity("URL_B","URL","https://account-verify.example/auth"),Entity("IP_A","IP","198.51.100.10"),Entity("DEVICE_B","DEVICE","DEV-B"),Entity("ACC_14","ACCOUNT","ACC-014"),Entity("BEN_Y","BENEFICIARY","BEN-Y")]),
        ("C029", "V029", [
            event("E201","2026-10-03T11:42:00","MESSAGE_RECEIVED","PHONE_Y","V029",["PHONE_Y","MSG_29"],["Government verification notice: complete immediately or service will be suspended."]),
            event("E202","2026-10-03T11:46:00","URL_OPENED","V029","URL_A",["URL_A","DOMAIN_A"],["https://secure-bank-verify.example/login","Same infrastructure observed in another case."]),
            event("E203","2026-10-03T11:49:00","CREDENTIAL_REQUEST","URL_A","V029",["URL_A"],["Enter credentials for verification."]),
            event("E204","2026-10-03T11:52:00","LOGIN","IP_C","ACC_29",["IP_C","DEVICE_C","ACC_29"],["New device login after credential request."]),
            event("E205","2026-10-03T11:54:00","BENEFICIARY_CREATED","ACC_29","BEN_X",["ACC_29","BEN_X"],["Beneficiary reused from another incident."]),
            event("E206","2026-10-03T11:55:00","TRANSACTION_INITIATED","ACC_29","BEN_X",["ACC_29","BEN_X","TX_29"],["Transfer initiated."]),
        ], [Entity("PHONE_Y","PHONE","+91-90000-10029"),Entity("DOMAIN_A","DOMAIN","secure-bank-verify.example"),Entity("URL_A","URL","https://secure-bank-verify.example/login"),Entity("IP_C","IP","198.51.100.29"),Entity("DEVICE_C","DEVICE","DEV-C"),Entity("ACC_29","ACCOUNT","ACC-029"),Entity("BEN_X","BENEFICIARY","BEN-X")]),
        ("B007", "V007", [
            event("E301","2026-10-03T12:10:00","MESSAGE_RECEIVED","BANK","V007",["MSG_301"],["Your monthly statement is ready in the official banking app."]),
            event("E302","2026-10-03T12:12:00","LOGIN","V007","ACC_7",["ACC_7"],["Routine login from known device."]),
            event("E303","2026-10-03T12:15:00","TRANSACTION_COMPLETED","ACC_7","MERCHANT_7",["ACC_7","TX_7"],["Routine merchant payment."]),
        ], [Entity("ACC_7","ACCOUNT","ACC-007")]),
    ]
    cases=[]
    all_entities = []
    for cid, vid, events, entities in specs:
        c=Case(cid,vid,events[0].timestamp,"synthetic",events,entities,[],{},[],None)
        all_entities.append(set(x.entity_id for x in entities))
        cases.append(c)
    counts={}
    for c in cases:
        for e in c.entities:
            counts[e.entity_id]=counts.get(e.entity_id,0)+1
    # Compute case-specific reused entities and pairwise campaign evidence.
    reused_by_case = []
    for c in cases:
        other_entities = {e.entity_id for x in cases if x is not c for e in x.entities}
        reused_by_case.append(other_entities)

    pair_scores = {}
    for i, a in enumerate(cases):
        for j in range(i + 1, len(cases)):
            b = cases[j]
            score = campaign_similarity(a, b)
            pair_scores[(i, j)] = score

    # Connected components over campaign-similar suspicious cases.
    parent = list(range(len(cases)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for (i, j), score in pair_scores.items():
        if cases[i].case_id.startswith("C") and cases[j].case_id.startswith("C") and score >= 0.40:
            union(i, j)

    roots = {}
    next_id = 1
    for i, c in enumerate(cases):
        root = find(i)
        if root != i or any(find(j) == root for j in range(len(cases)) if j != i):
            if root not in roots:
                roots[root] = f"CMP-{next_id:03d}"
                next_id += 1
            c.campaign_id = roots[root]

    for i, c in enumerate(cases):
        similarity = max((score for (a, b), score in pair_scores.items() if a == i or b == i), default=0.0)
        c.signals = detect_signals(c, reused_by_case[i], similarity if c.campaign_id else 0.0)
        c.attack_chain = reconstruct(c.events)
        c.risk = risk_fusion(c.signals)
        c.risk["evidence_completeness"] = evidence_completeness(c.events, c.signals)
        c.risk["intervention"] = intervention(c.events, c.signals)
        c.risk["campaign_similarity"] = similarity

    return cases
