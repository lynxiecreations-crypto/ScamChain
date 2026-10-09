from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from ml import evaluate, score_case, ensure_model_artifact
from data import make_cases
from campaign_eval import evaluate as evaluate_campaigns
from intervention_eval import evaluate as evaluate_interventions
from adversarial_eval import evaluate as evaluate_adversarial
from evidence_eval import evaluate as evaluate_evidence
from provenance_eval import evaluate as evaluate_provenance
from campaign_investigation_eval import benchmark as evaluate_campaign_investigation
from engine import investigation_explanation, campaign_investigation
from live_analysis import analyze_submission
from evidence_hub import router as evidence_router
from defense_lab import router as defense_router

app=FastAPI(title="ScamChain v2.7 Campaign Investigation")
app.include_router(evidence_router)
app.include_router(defense_router)
cases=make_cases()

@app.get("/", include_in_schema=False)
def home():
    """Send the public root URL to the interactive scam-analysis workflow."""
    return RedirectResponse(url="/simulator", status_code=307)

# In-memory live investigations from the interactive judge demo; not mixed into offline benchmark metrics.
live_cases = []

@app.get("/api/cases")
def api_cases():
    return [c.to_dict() for c in cases]

@app.get("/api/cases/{case_id}")
def api_case(case_id:str):
    for c in cases:
        if c.case_id==case_id: return c.to_dict()
    raise HTTPException(404,"Case not found")


@app.post("/api/analyze")
def api_analyze(payload: dict):
    """Analyze submitted evidence and retain the latest live case for the connected graph."""
    try:
        result = analyze_submission(payload, cases)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        import logging
        logging.getLogger("scamchain.analysis").exception("Live analysis failed")
        raise HTTPException(status_code=500, detail="Analysis could not complete. Please retry with a shorter message or URL.")
    live_case = result.get("case", {})
    if live_case:
        live_cases[:] = [c for c in live_cases if c.get("case_id") != live_case.get("case_id")]
        live_cases.insert(0, live_case)
        del live_cases[25:]
    result["case_link"] = "/threat-map?case=" + str(live_case.get("case_id", ""))
    return result

@app.get("/api/health")
def api_health():
    """Readiness endpoint for UI diagnostics and deployment checks."""
    return {"status": "ok", "service": "ScamChain", "analysis": True,
            "seeded_cases": len(cases), "live_cases_in_this_process": len(live_cases)}

@app.get("/api/live-cases")
def api_live_cases():
    """Recent interactive cases only; isolated from offline benchmark data."""
    return live_cases

@app.get("/api/live-graph")
def api_live_graph():
    """Combine the seeded graph with entities/events from submitted live investigations."""
    base = api_graph()
    nodes = {n["id"]: dict(n) for n in base["nodes"]}
    edges = list(base["edges"])
    for case in live_cases:
        cid = case.get("case_id", "LIVE")
        for entity in case.get("entities", []):
            eid = entity.get("entity_id")
            if not eid:
                continue
            node = nodes.setdefault(eid, {"id": eid, "type": entity.get("type", "ENTITY"),
                                          "label": entity.get("value", eid), "case_ids": []})
            if cid not in node["case_ids"]:
                node["case_ids"].append(cid)
        for event in case.get("events", []):
            entity_ids = [eid for eid in event.get("entities", []) if eid in nodes]
            for i in range(len(entity_ids) - 1):
                edges.append({"source": entity_ids[i], "target": entity_ids[i + 1],
                              "relation": event.get("event_type", "LIVE_EVENT"),
                              "evidence": event.get("event_id", "LIVE_EVIDENCE"),
                              "observed_at": event.get("timestamp"), "confidence": event.get("confidence", 0.0),
                              "case_id": cid, "live": True})
    return {"nodes": list(nodes.values()), "edges": edges,
            "live_case_count": len(live_cases),
            "latest_live_case_id": live_cases[0].get("case_id") if live_cases else None}

@app.get("/api/graph")
def api_graph():
    nodes={}
    edges=[]
    for c in cases:
        for e in c.entities:
            nodes[e.entity_id]={"id":e.entity_id,"type":e.type,"label":e.value,"case_ids":[]}
        for e in c.events:
            for eid in e.entities:
                if eid in nodes: nodes[eid]["case_ids"].append(c.case_id)
            if len(e.entities)>=2:
                for i in range(len(e.entities)-1):
                    edges.append({"source":e.entities[i],"target":e.entities[i+1],"relation":e.event_type,"evidence":e.event_id,"observed_at":e.timestamp,"confidence":e.confidence,"case_id":c.case_id})
    return {"nodes":list(nodes.values()),"edges":edges}

@app.get("/api/campaigns")
def api_campaigns():
    groups={}
    for c in cases:
        if c.campaign_id: groups.setdefault(c.campaign_id,[]).append(c)
    out=[]
    from engine import campaign_similarity, campaign_evidence
    for cid, cs in groups.items():
        shared=[]
        pair_scores=[]
        evidence=set()
        for i, a in enumerate(cs):
            for b in cs[i+1:]:
                shared += list({e.entity_id for e in a.entities} & {e.entity_id for e in b.entities})
                pair_scores.append(campaign_similarity(a, b))
                evidence.update(campaign_evidence(a, b))
        confidence = round(sum(pair_scores) / max(1, len(pair_scores)), 3)
        out.append({
            "campaign_id": cid,
            "cases": [c.case_id for c in cs],
            "shared_entities": sorted(set(shared)),
            "confidence": confidence,
            "evidence": sorted(evidence),
        })
    return out

@app.get("/api/model-status")
def model_status():
    _, metadata = ensure_model_artifact()
    return {"status": "loaded", "training_data": metadata.get("training_data"),
            "model_type": metadata.get("model_type"),
            "training_rows": metadata.get("training_rows"),
            "warning": metadata.get("warning")}


@app.get("/api/ml")
def api_ml():
    return evaluate(seed=42)

@app.get("/api/campaign-benchmark")
def api_campaign_benchmark():
    return evaluate_campaigns(seed=7)

@app.get("/api/intervention-benchmark")
def api_intervention_benchmark():
    return evaluate_interventions()

@app.get("/api/adversarial-benchmark")
def api_adversarial_benchmark():
    return evaluate_adversarial(seed=19)

@app.get("/api/evidence-benchmark")
def api_evidence_benchmark():
    return evaluate_evidence()

@app.get("/api/provenance-benchmark")
def api_provenance_benchmark():
    return evaluate_provenance()

@app.get("/api/cases/{case_id}/investigation")
def api_investigation(case_id: str):
    c = next((x for x in cases if x.case_id == case_id), None)
    if c is None:
        raise HTTPException(404, "Case not found")
    return {"case_id": case_id, **investigation_explanation(c.events, c.signals)}

@app.get("/api/ml/{case_id}")
def api_ml_case(case_id: str):
    c = next((x for x in cases if x.case_id == case_id), None)
    if c is None:
        return {"error": "case not found"}
    return {"case_id": case_id, "ml_scam_probability": score_case(c)}

@app.get("/api/summary")
def api_summary():
    campaigns={c.campaign_id for c in cases if c.campaign_id}
    entities={e.entity_id for c in cases for e in c.entities}
    relationships=sum(max(0,len(e.entities)-1) for c in cases for e in c.events)
    high=sum(c.risk["policy"]=="HIGH RISK" for c in cases)
    return {"cases":len(cases),"entities":len(entities),"relationships":relationships,"campaigns":len(campaigns),"high_risk":high}

HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScamChain</title><style>
*{box-sizing:border-box}body{margin:0;background:#07111f;color:#e6edf7;font:14px Inter,system-ui,sans-serif}header{padding:22px 30px;border-bottom:1px solid #1b2a3e;display:flex;justify-content:space-between}h1{margin:0;font-size:25px}small,.muted{color:#8ea1b7}.tag{color:#7dd3fc}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:20px 30px}.card{background:#0d1a2a;border:1px solid #1d3046;border-radius:12px;padding:17px}.metric{font-size:27px;font-weight:700;margin-top:5px}.layout{display:grid;grid-template-columns:390px 1fr;gap:16px;padding:0 30px 30px}.panel{background:#0d1a2a;border:1px solid #1d3046;border-radius:12px;padding:18px}.case{padding:13px;border:1px solid #1d3046;border-radius:9px;margin:8px 0;cursor:pointer}.case:hover{border-color:#38bdf8}.risk{float:right;padding:3px 7px;border-radius:12px;font-size:11px}.HIGH{background:#5b1b2a;color:#ff9caf}.REVIEW{background:#574719;color:#ffd978}.NORMAL{background:#16462e;color:#8df0b3}.tabs{display:flex;gap:7px;margin-bottom:15px}.tabs button{background:#122238;color:#9fb2c8;border:1px solid #263d58;padding:8px 12px;border-radius:7px;cursor:pointer}.tabs button.active{color:white;border-color:#38bdf8}.chain{display:flex;flex-wrap:wrap;gap:7px;align-items:center}.stage{background:#122238;border:1px solid #28415d;padding:9px 10px;border-radius:8px}.arrow{color:#38bdf8}.sig{display:inline-block;margin:4px;padding:5px 8px;border-radius:6px;background:#17283d}.evidence{margin:7px 0;padding:9px;background:#091522;border-left:3px solid #38bdf8}.graph{height:470px;position:relative;overflow:hidden;background:#091522;border-radius:9px;border:1px solid #172b41}.node{position:absolute;padding:8px 10px;border-radius:9px;background:#12263d;border:1px solid #31506f;font-size:11px;transform:translate(-50%,-50%);max-width:140px;text-align:center}.node b{display:block;color:#7dd3fc;font-size:9px}.edge{position:absolute;height:1px;background:#31506f;transform-origin:0 0}.footer{padding:0 30px 25px;color:#6f8298}@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}}

/* Judge-demo visual system: cinematic operations console */
body{background:radial-gradient(ellipse at 8% -10%,#143a50 0%,transparent 42%),radial-gradient(ellipse at 92% 12%,#271a43 0%,transparent 30%),#050914;background-attachment:fixed}
header{background:rgba(5,10,22,.88);border-bottom:1px solid #25455b;box-shadow:0 10px 35px #0005}
.mark{background:linear-gradient(145deg,#123c51,#17213c);box-shadow:0 0 28px #3ed8f033;border-color:#3ad2e8}
.brand h1{letter-spacing:1.2px}.status{box-shadow:0 0 18px #36df9a18}
.wrap{max-width:1580px}.hero{padding:23px 24px;border:1px solid #28435c;border-radius:18px;background:linear-gradient(115deg,#0c2134dd,#101027bb);box-shadow:inset 0 1px #ffffff0b,0 18px 45px #0002}
.hero h2{font-size:clamp(29px,3.3vw,44px);background:linear-gradient(90deg,#f2fbff,#70eaff 65%,#b6a0ff);background-clip:text;color:transparent}
.metric,.panel{background:linear-gradient(145deg,rgba(16,31,52,.96),rgba(8,15,29,.98));border-color:#243d56;box-shadow:0 12px 32px #0002,inset 0 1px #ffffff08;transition:border-color .2s,transform .2s}
.metric:hover,.panel:hover{border-color:#3a6880}.metric strong{font-variant-numeric:tabular-nums}.metric:first-child strong{color:#75e9ff}.metric:nth-child(2) strong{color:#b6a0ff}.metric:nth-child(3) strong{color:#76e8b8}
.sectionlabel{letter-spacing:2px}.panel h3{font-size:16px;letter-spacing:.1px}
.btn{box-shadow:0 5px 20px #06bcd51c;transition:transform .18s,filter .18s}.btn:hover{transform:translateY(-1px)}.btn.secondary:hover{border-color:#398aa0;color:#e8fbff}
.field textarea,.field input{background:#050c18;border-color:#273f59}.field textarea::placeholder,.field input::placeholder{color:#506680}
.pill{background:#0a192a;border-color:#2b435b}.chain{gap:7px}.stage{background:linear-gradient(145deg,#122b40,#11152a);border-color:#31526b;box-shadow:inset 0 1px #ffffff08}.stage b{letter-spacing:1px}
.signal{background:linear-gradient(145deg,#0e1c2d,#0a1220);border-color:#2a4058}.signal:hover{border-color:#40839a}
.risk-HIGH{box-shadow:0 0 22px #ff667f20}.risk-REVIEW{box-shadow:0 0 22px #ffc85714}.risk-NORMAL{box-shadow:0 0 22px #5fe0ae14}
#simulation{margin:0 0 16px;border:1px solid #3a587b;background:radial-gradient(ellipse at 0 0,#12384a 0%,transparent 55%),linear-gradient(135deg,#111a33,#0b1222);border-radius:17px;padding:20px;box-shadow:0 15px 45px #0003}
.simtop{display:flex;align-items:start;justify-content:space-between;gap:14px}.simtop h3{font-size:19px;margin:3px 0 7px}.simtop p{max-width:720px;line-height:1.6;color:#9fb3cc;margin:0;font-size:12px}
.simstate{font-size:10px;letter-spacing:1px;color:#ffda83;border:1px solid #6c552b;background:#332816;padding:8px 10px;border-radius:8px;white-space:nowrap}
.simgrid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(240px,.8fr);gap:16px;margin-top:17px}.simtrack{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:7px}
.simnode{min-height:84px;border:1px solid #263d56;background:#0a1424;border-radius:10px;padding:10px 8px;opacity:.64;position:relative;transition:all .25s}
.simnode .num{font-size:10px;color:#65809e}.simnode b{display:block;font-size:10px;margin-top:9px;line-height:1.35;color:#b9c9df}
.simnode.active{opacity:1;border-color:#5ee7ff;background:linear-gradient(145deg,#12364a,#101d32);box-shadow:0 0 23px #5ee7ff1e}.simnode.done{opacity:1;border-color:#2d7b6a}.simnode.done .num{color:#70edba}.simnode.alert{border-color:#e45d79;box-shadow:0 0 23px #e45d7920}.simfeed{border:1px solid #263c56;border-radius:11px;padding:13px;background:#07111f;min-height:122px}.simfeed .live{font-size:10px;color:#5ee7ff;letter-spacing:1.3px}.simfeed h4{margin:9px 0 6px;font-size:13px}.simfeed p{font-size:11px;line-height:1.5;color:#9fb2c9;margin:0}.simfoot{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:13px}.simfoot small{font-size:10px;color:#7188a2;line-height:1.5}.simbar{height:4px;border-radius:5px;background:#1b2b40;overflow:hidden;margin-top:13px}.simbar span{display:block;height:100%;width:0;background:linear-gradient(90deg,#50d7f1,#8f8bff,#ff728d);transition:width .35s}
#simAlert{display:none;border:1px solid #9d3c54;background:linear-gradient(90deg,#3b1425,#1b1220);border-radius:10px;padding:12px;margin-top:12px;color:#ffb4c1;font-size:12px;line-height:1.5}
@media(max-width:950px){.simgrid{grid-template-columns:1fr}.simtrack{grid-template-columns:repeat(3,minmax(0,1fr))}.hero{padding:18px}}
@media(max-width:560px){.simtrack{grid-template-columns:repeat(2,minmax(0,1fr))}.simtop{display:block}.simstate{display:inline-block;margin-top:12px}.simfoot{align-items:start;flex-direction:column}}

/* Ambient particle field + polished cyber-console layer */
/* Immersive live cyber atmosphere */
#scamchain-particles{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.82}
#scamchain-ambient{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden;background:radial-gradient(600px circle at var(--mx,50%) var(--my,40%),rgba(32,119,173,.105),transparent 62%)}
#scamchain-ambient:before{content:"";position:absolute;inset:-45%;background:conic-gradient(from 0deg at 50% 50%,transparent 0deg,rgba(15,113,156,.12) 48deg,transparent 105deg,rgba(98,63,176,.11) 180deg,transparent 245deg,rgba(33,133,173,.09) 305deg,transparent 360deg);filter:blur(76px);animation:scamchain-aurora 34s linear infinite}
#scamchain-ambient:after{content:"";position:absolute;inset:0;opacity:.15;background-image:linear-gradient(rgba(93,176,220,.075) 1px,transparent 1px),linear-gradient(90deg,rgba(93,176,220,.075) 1px,transparent 1px);background-size:54px 54px;mask-image:linear-gradient(to bottom,black,transparent 90%)}
@keyframes scamchain-aurora{0%{transform:rotate(0deg) scale(1)}50%{transform:rotate(180deg) scale(1.13)}100%{transform:rotate(360deg) scale(1)}}
body{background-color:#050a14!important}
body>header,body>main{position:relative;z-index:1}
body>div:not(#scamchain-ambient){position:relative;z-index:1}
body:has(#scamchain-particles){background-image:radial-gradient(ellipse at 50% 0%,rgba(9,26,45,.4),transparent 62%)!important}
header{background:rgba(5,12,24,.68)!important;backdrop-filter:blur(18px)}
.panel,.scenario,.metric,.card{backdrop-filter:blur(12px)}
@media(prefers-reduced-motion:reduce){#scamchain-ambient:before{animation:none}*{scroll-behavior:auto!important}}

:root{color-scheme:dark;--glow:#58e5f7}
body{position:relative;isolation:isolate;background:radial-gradient(ellipse at 14% -12%,rgba(22,105,145,.23),transparent 42%),radial-gradient(ellipse at 88% 12%,rgba(94,54,160,.17),transparent 36%),#050a14!important}
#scamchain-particles{position:fixed;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none;opacity:.72}
header{background:rgba(7,17,31,.72)!important;backdrop-filter:blur(18px);position:relative}
.card,.panel{background:linear-gradient(145deg,rgba(16,32,51,.88),rgba(8,19,33,.9))!important;border-color:rgba(102,163,194,.18)!important;box-shadow:0 12px 36px rgba(0,0,0,.12);transition:border-color .22s,transform .22s,box-shadow .22s}
.card:hover,.panel:hover{border-color:rgba(88,229,247,.35)!important;box-shadow:0 16px 44px rgba(0,0,0,.22),0 0 0 1px rgba(88,229,247,.035)}
.metric{letter-spacing:-.035em;background:linear-gradient(100deg,#eafcff,#79eaff 70%,#b8a4ff);background-clip:text;-webkit-background-clip:text;color:transparent}
.case{background:rgba(7,18,32,.55);transition:all .2s}
.case:hover{transform:translateY(-2px);box-shadow:0 0 24px rgba(56,189,248,.08)}
button{transition:transform .18s,border-color .18s,background .18s}button:hover{border-color:#58e5f7!important;transform:translateY(-1px)}
::selection{background:rgba(65,209,239,.28)}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}

/* SCAMCHAIN / LIVE VISUAL ATMOSPHERE */
#scamchain-ambient{position:fixed;inset:-15%;z-index:0;pointer-events:none;overflow:hidden;opacity:.95;background:radial-gradient(ellipse at 15% 25%,rgba(12,107,145,.15),transparent 38%),radial-gradient(ellipse at 85% 20%,rgba(101,61,176,.15),transparent 38%),radial-gradient(ellipse at 52% 92%,rgba(9,82,120,.12),transparent 43%);filter:saturate(1.15)}
#scamchain-ambient:before,#scamchain-ambient:after{content:"";position:absolute;inset:-35%;pointer-events:none}
#scamchain-ambient:before{background:conic-gradient(from 0deg at 50% 50%,transparent 0deg,rgba(26,150,195,.10) 45deg,transparent 105deg,rgba(121,82,211,.12) 185deg,transparent 250deg,rgba(22,178,190,.08) 315deg,transparent 360deg);filter:blur(80px);animation:sc-aurora 32s linear infinite}
#scamchain-ambient:after{inset:0;opacity:.19;background-image:linear-gradient(rgba(90,173,215,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(90,173,215,.08) 1px,transparent 1px);background-size:52px 52px;mask-image:linear-gradient(to bottom,black,transparent 92%)}
@keyframes sc-aurora{0%{transform:rotate(0deg) scale(1)}50%{transform:rotate(180deg) scale(1.12)}100%{transform:rotate(360deg) scale(1)}}
#scamchain-particles{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.88}
#scamchain-mode{position:fixed;right:16px;bottom:15px;z-index:20;border:1px solid rgba(98,215,241,.36);background:rgba(5,15,29,.78);backdrop-filter:blur(14px);color:#9beeff;border-radius:999px;padding:9px 13px;font:600 10px ui-monospace,monospace;letter-spacing:1px;cursor:pointer;box-shadow:0 0 28px rgba(41,182,219,.13);transition:all .2s}
#scamchain-mode:hover{border-color:#8beeff;color:#fff;box-shadow:0 0 28px rgba(41,182,219,.24);transform:translateY(-2px)}
body>header,body>.grid,body>main,body>.footer,body>div:not(#scamchain-ambient),body>section{position:relative;z-index:1}
body{background-color:#050914!important;background-attachment:fixed!important}
header{background:rgba(5,12,24,.68)!important;backdrop-filter:blur(18px)}
body[data-visual-mode="cyber-rain"] #scamchain-ambient:after{opacity:.08}
body[data-visual-mode="aurora-field"] #scamchain-ambient:before{animation-duration:18s;filter:blur(60px)}
@media(max-width:600px){#scamchain-mode{right:10px;bottom:10px;padding:8px 10px;font-size:9px}}
@media(prefers-reduced-motion:reduce){#scamchain-ambient:before{animation:none}#scamchain-mode{transition:none}}
</style></head><body><header><div><h1>ScamChain <span class="tag">v2.7</span></h1><div class="muted">Connect the Signals. Expose the Scam. · <a href="/evidence" style="color:#75e9ff;text-decoration:none;font-weight:700">Open Real-World Evidence Lab ↗</a> · <a href="/simulator" style="color:#75e9ff;text-decoration:none;font-weight:700">Live Simulator ↗</a> · <a href="/validation" style="color:#75e9ff;text-decoration:none;font-weight:700">Model Validation ↗</a> · <a href="/threat-map" style="color:#75e9ff;text-decoration:none;font-weight:700">Live Threat Graph ↗</a> · <a href="/defense-lab" style="color:#75e9ff;text-decoration:none;font-weight:700">Counterfactual Defense Lab ↗</a></div></div><div class="muted">Synthetic investigation environment</div></header><div class="grid" id="metrics"></div><main class="layout"><section class="panel"><div class="tabs"><button id="casesTab" class="active">Cases</button><button id="campaignTab">Campaigns</button><button id="mlTab">ML Evaluation</button><button id="campaignBenchTab">Campaign Benchmark</button><button id="riskTab">Risk & Intervention</button><button id="advTab">Adversarial</button><button id="evidenceTab">Evidence Confidence</button><button id="provenanceTab">Provenance & Replay</button><button id="campaignReplayTab">Campaign Replay</button></div><div id="list"></div></section><section class="panel"><div id="detail"></div></section></main><div class="footer">All evidence is synthetic. Scores are prototype outputs, not production fraud decisions.</div><script>
let cases=[],campaigns=[],current=null;const $=x=>document.getElementById(x);
async function load(){[cases,campaigns]=await Promise.all([fetch('/api/cases').then(r=>r.json()),fetch('/api/campaigns').then(r=>r.json())]);let s=await fetch('/api/summary').then(r=>r.json());$('metrics').innerHTML=Object.entries({Cases:s.cases,Entities:s.entities,Relationships:s.relationships,Campaigns:s.campaigns,'High Risk':s.high_risk}).map(([k,v])=>`<div class="card"><div class="muted">${k}</div><div class="metric">${v}</div></div>`).join('');renderCases();show(cases[0]);}
function renderCases(){ $('list').innerHTML=cases.map(c=>`<div class="case" onclick="show(cases.find(x=>x.case_id==='${c.case_id}'))"><span class="risk ${c.risk.policy.replace(' ','')}">${c.risk.policy}</span><b>${c.case_id}</b><div class="muted">${c.victim_id} · ${c.events.length} events</div><div class="muted">${c.attack_chain.join(' → ')}</div></div>`).join('');}
async function renderML(){ let d=await fetch('/api/ml').then(r=>r.json()); $('list').innerHTML=`<div class=\"card\"><b>Synthetic ablation</b><p class=\"muted\">These are benchmark results, not production performance.</p></div>`+d.results.map(r=>`<div class=\"case\"><b>${r.model}</b><div>Precision ${r.precision} · Recall ${r.recall} · F1 ${r.f1} · PR-AUC ${r.pr_auc}</div><div class=\"muted\">${r.train_cases} train / ${r.test_cases} test</div></div>`).join('')}
async function renderCampaignBenchmark(){ let d=await fetch('/api/campaign-benchmark').then(r=>r.json()); $('list').innerHTML=`<div class="card"><b>Held-out campaign families</b><p class="muted">Synthetic benchmark; campaign members use unique identifiers.</p><div>ROC-AUC ${d.pair_roc_auc} · PR-AUC ${d.pair_pr_auc} · ARI ${d.campaign_clustering_ari}</div><div class="muted">${d.cases} cases · ${d.campaign_families} latent campaigns · threshold ${d.threshold}</div></div><div class="case"><b>What this tests</b><p>Whether workflow + temporal similarity can recover campaign structure without memorizing reused phone/domain/account identifiers.</p></div>`}
async function renderRisk(){ let [m,i]=await Promise.all([fetch('/api/ml').then(r=>r.json()),fetch('/api/intervention-benchmark').then(r=>r.json())]); let full=m.results.find(r=>r.model==='D: full fused model'); $('list').innerHTML=`<div class="card"><b>Risk calibration</b><p class="muted">Held-out synthetic test set.</p><div>ECE <b>${m.calibration.ece}</b> · Brier <b>${full.brier}</b></div></div><div class="card"><b>Intervention policy</b><p class="muted">${i.policy}</p><div>Stage accuracy <b>${i.intervention_stage_accuracy}</b> · Unnecessary intervention rate <b>${i.unnecessary_intervention_rate}</b></div><div class="muted">${i.scam_observations} scam observations · ${i.benign_observations} benign observations</div></div>`}
async function renderEvidence(){ let d=await fetch('/api/evidence-benchmark').then(r=>r.json()); $('list').innerHTML=`<div class="card"><b>Evidence completeness</b><p class="muted">Risk and evidence completeness are intentionally separate.</p><div>Monotonicity: <b>${d.monotonic_completeness}</b></div></div>`+d.rows.map(r=>`<div class="case"><b>${r.observed_events} observed events</b><div>Completeness <b>${r.completeness.score}</b> · ${r.completeness.status}</div><div class="muted">Missing: ${r.completeness.missing_stages.join(' → ')||'none'}</div><div class="muted">Intervention: ${r.intervention.stage} — ${r.intervention.action}</div></div>`).join('')}
async function renderProvenance(){ let d=await fetch('/api/provenance-benchmark').then(r=>r.json()); $('list').innerHTML=`<div class="card"><b>Evidence provenance benchmark</b><p class="muted">Synthetic explainability benchmark.</p><div>Provenance coverage <b>${d.provenance_coverage}</b> · Replay steps <b>${d.replay_steps}</b></div><div>Critical events <b>${d.critical_event_count}</b> · Counterfactual checks <b>${d.stage_counterfactual_checks_passed}/${d.stage_counterfactual_checks_total}</b></div></div><div class="card"><b>What this tests</b><p>Every reconstructed stage must point to observable evidence; removing a stage-defining event should change the reconstructed chain.</p></div>`}
async function renderAdversarial(){ let d=await fetch('/api/adversarial-benchmark').then(r=>r.json()); $('list').innerHTML=`<div class="card"><b>Adversarial robustness</b><p class="muted">Synthetic stress test; not production performance.</p><div>Benign FPR ${d.adversarial_benign_false_positive_rate_at_review_threshold} · Partial attack detection ${d.partial_attack_detection_rate_at_review_threshold} · Reordered chain accuracy ${d.reordered_attack_chain_accuracy}</div></div><div class="card"><b>Infrastructure rotation</b><p>Mean pair similarity ${d.rotated_identifier_pair_similarity_mean} · Minimum ${d.rotated_identifier_pair_similarity_min}</p><p class="muted">Pairs use unique identifiers, so similarity is driven by workflow/temporal behavior.</p></div><div class="case"><b>Stress dimensions</b><p>Benign lookalikes · partial attacks · shuffled event input · missing evidence · rotated identifiers</p></div>`}
async function renderCampaignReplay(){let cid=campaigns[0]?.campaign_id;if(!cid){$('list').innerHTML='<div class="card">No detected campaign.</div>';return}let d=await fetch('/api/campaigns/'+cid+'/investigation').then(r=>r.json());$('list').innerHTML=`<div class="card"><b>Campaign ${d.campaign_id}</b><p class="muted">${d.case_count} cases · shared entities: ${d.shared_entities.join(', ')||'none'}</p><p>Campaign-level earliest intervention: <b>${d.intervention.stage}</b> — ${d.intervention.action}</p></div><div class="card"><b>Stage coverage</b>${d.stage_matrix.map(x=>`<div class="evidence"><b>${x.stage}</b> · ${Math.round(x.coverage*100)}% case coverage · mean confidence ${x.mean_confidence}%</div>`).join('')}</div><div class="card"><b>Cross-case replay</b>${d.replay.map(x=>`<div class="evidence"><b>${x.timestamp.slice(11,19)} · ${x.case_id} · ${x.stage}</b> · ${x.event_type}<br><span class="muted">${x.event_id} · confidence ${x.confidence}</span></div>`).join('')}</div><div class="card"><b>Pair evidence</b>${d.pair_evidence.map(x=>`<div class="evidence"><b>${x.case_a} ↔ ${x.case_b}</b> · similarity ${x.similarity}<br>${x.evidence.join(' · ')||'No explicit supporting rationale'}</div>`).join('')}</div>`}
function renderCampaigns(){ $('list').innerHTML=campaigns.map(c=>`<div class="case"><b>${c.campaign_id}</b><div class="muted">${c.cases.join(' · ')}</div><p>Confidence: ${c.confidence}</p><div>${c.evidence.map(x=>`<span class="sig">${x}</span>`).join('')}</div><p class="muted">Shared: ${c.shared_entities.join(', ')}</p></div>`).join('');}
async function show(c){current=c;let x=await fetch('/api/cases/'+c.case_id+'/investigation').then(r=>r.json());$('detail').innerHTML=`<h2>${c.case_id} <span class="risk ${c.risk.policy.replace(' ','')}">${c.risk.policy} · ${c.risk.score}/100</span></h2><p class="muted">${c.source} · ${c.created_at} · Campaign: ${c.campaign_id||'none'}</p><h3>Reconstructed attack</h3><div class="chain">${c.attack_chain.map((st,i)=>`<span class="stage">${st}</span>${i<c.attack_chain.length-1?'<span class="arrow">→</span>':''}`).join('')}</div><h3>Evidence completeness</h3><div class="card"><b>${x.evidence_completeness.score}/100 · ${x.evidence_completeness.status}</b><div class="muted">Missing: ${x.evidence_completeness.missing_stages.join(' → ')||'none'}</div></div><h3>Stage provenance</h3>${x.stage_provenance.map(r=>`<div class="evidence"><b>${r.stage}</b> <span class="muted">${r.status} · ${r.confidence}%</span><br><span class="muted">Events: ${r.event_ids.join(', ')||'none'} · Evidence: ${r.evidence_ids.join(', ')||'none'}</span><br>${r.rationale}</div>`).join('')}<h3>Evidence gaps</h3>${x.evidence_gaps.length?x.evidence_gaps.map(g=>`<div class="evidence"><b>${g.priority}</b> · ${g.stage}<br>${g.request}<br><span class="muted">Expected: ${g.expected_event_types.join(', ')}</span></div>`).join(''):'<div class="muted">No missing canonical stages.</div>'}<h3>Attack Replay</h3>${x.attack_replay.map(r=>`<div class="evidence"><b>${r.step}. ${r.timestamp.slice(11,19)} · ${r.stage}</b> · ${r.event_type}<br><span class="muted">${r.event_id} · confidence ${r.confidence} · signals ${r.signals.join(', ')||'none'}</span><br>${r.evidence.join(' ')||'No textual evidence attached.'}</div>`).join('')}<h3>Counterfactual critical events</h3>${x.counterfactual_events.filter(r=>r.critical).slice(0,8).map(r=>`<div class="evidence"><b>${r.removed_event_id}</b> · ${r.removed_event_type} · ${r.removed_stage}<br>Completeness drop: ${r.completeness_drop} · stages lost: ${r.stages_lost.join(', ')}</div>`).join('')}<h3>Risk components</h3><div>${Object.entries(c.risk.components).map(([k,v])=>`<span class="sig">${k}: ${v}</span>`).join('')}</div><h3>Signals</h3><div>${c.signals.map(s=>`<span class="sig">${s.signal}</span>`).join('')||'<span class="muted">No positive signals</span>'}</div><h3>Earliest effective intervention</h3><div class="evidence"><b>${c.risk.intervention.stage}</b><br>${c.risk.intervention.action}<br><span class="muted">${c.risk.intervention.reason}</span></div><h3>Attack Graph</h3><div class="graph" id="graph"></div>`;drawGraph(c)}

async function drawGraph(c){let g=await fetch('/api/graph').then(r=>r.json());let ids=[...new Set(c.entities.map(e=>e.entity_id))];let nodes=ids.map(id=>g.nodes.find(n=>n.id===id)).filter(Boolean);let pos={};nodes.forEach((n,i)=>{let a=2*Math.PI*i/nodes.length;pos[n.id]=[50+38*Math.cos(a),50+37*Math.sin(a)]});let html='';g.edges.filter(e=>ids.includes(e.source)&&ids.includes(e.target)).forEach(e=>{let a=pos[e.source],b=pos[e.target];let x=a[0]*3.7,y=a[1]*3.7,dx=(b[0]-a[0])*3.7,dy=(b[1]-a[1])*3.7,len=Math.hypot(dx,dy),ang=Math.atan2(dy,dx)*180/Math.PI;html+=`<div class="edge" style="left:${x}px;top:${y}px;width:${len}px;transform:rotate(${ang}deg)" title="${e.relation}"></div>`});nodes.forEach(n=>{let [x,y]=pos[n.id];html+=`<div class="node" style="left:${x}%;top:${y}%"><b>${n.type}</b>${n.label}</div>`});$('graph').innerHTML=html}
function clearTabs(active){['casesTab','campaignTab','mlTab','campaignBenchTab','riskTab','advTab','evidenceTab','provenanceTab','campaignReplayTab'].forEach(id=>$(id).classList.toggle('active',id===active))}
$('casesTab').onclick=()=>{renderCases();clearTabs('casesTab')};$('campaignTab').onclick=()=>{renderCampaigns();clearTabs('campaignTab')};$('mlTab').onclick=()=>{renderML();clearTabs('mlTab')};$('campaignBenchTab').onclick=()=>{renderCampaignBenchmark();clearTabs('campaignBenchTab')};$('riskTab').onclick=()=>{renderRisk();clearTabs('riskTab')};$('advTab').onclick=()=>{renderAdversarial();clearTabs('advTab')};$('evidenceTab').onclick=()=>{renderEvidence();clearTabs('evidenceTab')};$('provenanceTab').onclick=()=>{renderProvenance();clearTabs('provenanceTab')};$('campaignReplayTab').onclick=()=>{renderCampaignReplay();clearTabs('campaignReplayTab')};load();
</script><div id="scamchain-ambient" aria-hidden="true"></div><canvas id="scamchain-particles" aria-hidden="true"></canvas><button id="scamchain-mode" type="button" aria-label="Change animated background" title="Switch animated background">✦ LIVE VISUALS · NETWORK</button><script>(()=>{const c=document.getElementById('scamchain-particles'),ambient=document.getElementById('scamchain-ambient'),btn=document.getElementById('scamchain-mode');if(!c||!c.getContext)return;const ctx=c.getContext('2d',{alpha:true});let w=0,h=0,dpr=1,raf=0,last=0,mode=0,points=[],drops=[],mouse={x:-9999,y:-9999};const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;const modes=['NETWORK','CYBER RAIN','AURORA FIELD'];function resize(){dpr=Math.min(devicePixelRatio||1,1.6);w=c.width=Math.floor(innerWidth*dpr);h=c.height=Math.floor(innerHeight*dpr);c.style.width=innerWidth+'px';c.style.height=innerHeight+'px';points=Array.from({length:Math.min(105,Math.floor(innerWidth/13))},()=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.24*dpr,vy:(Math.random()-.5)*.24*dpr,r:(.5+Math.random()*1.5)*dpr,a:.15+Math.random()*.38,p:Math.random()*6.28,purple:Math.random()<.12}));drops=Array.from({length:Math.min(68,Math.floor(innerWidth/21))},()=>({x:Math.random()*w,y:Math.random()*h,s:(1.1+Math.random()*3.4)*dpr,n:5+Math.floor(Math.random()*13),a:.15+Math.random()*.4}));}function network(){const reach=145*dpr;for(let i=0;i<points.length;i++){const p=points[i];if(!reduce){p.x+=p.vx;p.y+=p.vy;p.p+=.012;if(p.x<0)p.x=w;if(p.x>w)p.x=0;if(p.y<0)p.y=h;if(p.y>h)p.y=0}const pulse=.7+.3*Math.sin(p.p);ctx.beginPath();ctx.arc(p.x,p.y,p.r*(p.purple?1.5:1),0,Math.PI*2);ctx.fillStyle=p.purple?'rgba(174,142,255,'+(p.a*pulse)+')':'rgba(96,226,250,'+p.a+')';ctx.shadowBlur=p.purple?10*dpr:5*dpr;ctx.shadowColor=p.purple?'#a78bfa':'#43d7ef';ctx.fill();ctx.shadowBlur=0;for(let j=i+1;j<points.length;j++){const q=points[j],dist=Math.hypot(p.x-q.x,p.y-q.y);if(dist<reach){ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);ctx.strokeStyle='rgba(74,183,226,'+(.15*(1-dist/reach))+')';ctx.lineWidth=.7*dpr;ctx.stroke()}}const md=Math.hypot(p.x-mouse.x*dpr,p.y-mouse.y*dpr);if(md<135*dpr){ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(mouse.x*dpr,mouse.y*dpr);ctx.strokeStyle='rgba(167,139,250,'+(.25*(1-md/(135*dpr)))+')';ctx.stroke()}}}function rain(){ctx.font=(11*dpr)+'px ui-monospace,monospace';for(const p of drops){if(!reduce)p.y+=p.s*dpr*2.5;if(p.y>h+40*dpr){p.y=-Math.random()*h;p.x=Math.random()*w}for(let k=0;k<p.n;k++){const yy=p.y-k*14*dpr;if(yy<0||yy>h)continue;const alpha=p.a*(1-k/p.n);ctx.fillStyle='rgba('+(k===0?'120,250,220':'57,190,168')+','+alpha+')';ctx.fillText(['0','1','·','/','×','∷'][Math.floor((k+p.x)%6)],p.x,yy)}}}function aurora(){const t=performance.now()*.00008;for(let i=0;i<5;i++){const xx=(.18+.17*i+.12*Math.sin(t+i))*w,yy=(.25+.23*Math.cos(t*1.3+i))*h,g=ctx.createRadialGradient(xx,yy,0,xx,yy,Math.max(w,h)*.36);const hue=i%2?'153,113,255':'37,190,229';g.addColorStop(0,'rgba('+hue+',.095)');g.addColorStop(1,'rgba('+hue+',0)');ctx.fillStyle=g;ctx.fillRect(0,0,w,h)}if(!reduce){for(const p of points){p.x+=p.vx*.4;p.y+=p.vy*.4;if(p.x<0)p.x=w;if(p.x>w)p.x=0;if(p.y<0)p.y=h;if(p.y>h)p.y=0;ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,6.283);ctx.fillStyle='rgba(145,220,255,.3)';ctx.fill()}}}function draw(t){raf=requestAnimationFrame(draw);if(reduce&&t-last<800)return;last=t;ctx.clearRect(0,0,w,h);if(mode===0)network();else if(mode===1)rain();else aurora()}function setMode(){mode=(mode+1)%modes.length;document.body.dataset.visualMode=modes[mode].toLowerCase().replace(' ','-');btn.textContent='✦ LIVE VISUALS · '+modes[mode];if(ambient)ambient.dataset.mode=modes[mode].toLowerCase().replace(' ','-')}btn&&btn.addEventListener('click',setMode);addEventListener('resize',resize,{passive:true});addEventListener('pointermove',e=>{mouse.x=e.clientX;mouse.y=e.clientY;if(ambient){ambient.style.setProperty('--mx',(e.clientX/innerWidth*100)+'%');ambient.style.setProperty('--my',(e.clientY/innerHeight*100)+'%')}},{passive:true});resize();draw(0)})();</script></body></html>'''
