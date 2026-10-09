from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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

app=FastAPI(title="ScamChain v2.7 Campaign Investigation")
app.include_router(evidence_router)
cases=make_cases()

@app.get("/api/cases")
def api_cases():
    return [c.to_dict() for c in cases]

@app.get("/api/cases/{case_id}")
def api_case(case_id:str):
    for c in cases:
        if c.case_id==case_id: return c.to_dict()
    raise HTTPException(404,"Case not found")

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
</style></head><body><header><div><h1>ScamChain <span class="tag">v2.7</span></h1><div class="muted">Connect the Signals. Expose the Scam. · <a href="/evidence" style="color:#75e9ff;text-decoration:none;font-weight:700">Open Real-World Evidence Lab ↗</a> · <a href="/simulator" style="color:#75e9ff;text-decoration:none;font-weight:700">Live Simulator ↗</a> · <a href="/validation" style="color:#75e9ff;text-decoration:none;font-weight:700">Model Validation ↗</a></div></div><div class="muted">Synthetic investigation environment</div></header><div class="grid" id="metrics"></div><main class="layout"><section class="panel"><div class="tabs"><button id="casesTab" class="active">Cases</button><button id="campaignTab">Campaigns</button><button id="mlTab">ML Evaluation</button><button id="campaignBenchTab">Campaign Benchmark</button><button id="riskTab">Risk & Intervention</button><button id="advTab">Adversarial</button><button id="evidenceTab">Evidence Confidence</button><button id="provenanceTab">Provenance & Replay</button><button id="campaignReplayTab">Campaign Replay</button></div><div id="list"></div></section><section class="panel"><div id="detail"></div></section></main><div class="footer">All evidence is synthetic. Scores are prototype outputs, not production fraud decisions.</div><script>
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
</script></body></html>'''

@app.get("/api/campaign-investigation-benchmark")
def campaign_investigation_benchmark():
    return evaluate_campaign_investigation()

@app.get("/api/campaigns/{campaign_id}/investigation")
def campaign_investigation_api(campaign_id: str):
    return campaign_investigation(cases, campaign_id)

@app.get("/legacy",response_class=HTMLResponse)
def legacy_home(): return HTML



@app.post("/api/simulate")
def api_simulate():
    """Deterministic end-to-end demo. Every stage is analyzed by the real intake pipeline."""
    scenario = [
        {"id":"S1","phase":"EMAIL RECEIVED","title":"Impersonation email arrives","description":"A message claims the bank account will be suspended and creates urgency.","payload":{"message":"URGENT: Bank security alert. Your account will be blocked today. Verify your netbanking password immediately at https://secure-bank-verify.example/login and share the OTP to restore access.","url":"","sender":"security-alert@bank-verify.example","beneficiary":"","new_device_login":False,"beneficiary_created":False,"transfer_initiated":False}},
        {"id":"S2","phase":"LINK INSPECTED","title":"Credential-harvesting link identified","description":"The URL and message are evaluated together; no link is opened by the scanner.","payload":{"message":"URGENT: Bank security alert. Your account will be blocked today. Verify your netbanking password immediately and share the OTP to restore access.","url":"https://secure-bank-verify.example/login","sender":"security-alert@bank-verify.example","beneficiary":"","new_device_login":False,"beneficiary_created":False,"transfer_initiated":False}},
        {"id":"S3","phase":"CREDENTIAL ATTEMPT","title":"Password / OTP solicitation correlated","description":"The content requests authentication secrets. The engine raises a user-protection recommendation.","payload":{"message":"URGENT: Bank security alert. Verify your netbanking password and share the OTP / verification code immediately.","url":"https://secure-bank-verify.example/login","sender":"security-alert@bank-verify.example","beneficiary":"","new_device_login":False,"beneficiary_created":False,"transfer_initiated":False}},
        {"id":"S4","phase":"ACCOUNT SIGNAL","title":"Unfamiliar login reported","description":"A reported new-device login adds a downstream compromise indicator.","payload":{"message":"URGENT: Bank security alert. Verify your netbanking password and share the OTP immediately.","url":"https://secure-bank-verify.example/login","sender":"security-alert@bank-verify.example","beneficiary":"","new_device_login":True,"beneficiary_created":False,"transfer_initiated":False}},
        {"id":"S5","phase":"BENEFICIARY CHANGE","title":"New payee added","description":"A new beneficiary after credential pressure raises the urgency of investigation.","payload":{"message":"URGENT: Bank security alert. Verify your netbanking password and share the OTP immediately.","url":"https://secure-bank-verify.example/login","sender":"security-alert@bank-verify.example","beneficiary":"fraud-demo@upi","new_device_login":True,"beneficiary_created":True,"transfer_initiated":False}},
        {"id":"S6","phase":"TRANSFER RISK","title":"Potential money movement detected","description":"The final simulation stage demonstrates a linked transfer-risk alert and incident response.","payload":{"message":"URGENT: Bank security alert. Verify your netbanking password and share the OTP immediately.","url":"https://secure-bank-verify.example/login","sender":"security-alert@bank-verify.example","beneficiary":"fraud-demo@upi","new_device_login":True,"beneficiary_created":True,"transfer_initiated":True}}
    ]
    results = []
    for step in scenario:
        analysis = analyze_submission(step["payload"], cases)
        a = analysis["assessment"]
        results.append({
            "id": step["id"], "phase": step["phase"], "title": step["title"],
            "description": step["description"], "risk_score": a["risk_score"],
            "policy": a["policy"], "signal_count": a["signal_count"],
            "signals": [s["signal"] for s in a["signals"]],
            "attack_chain": analysis["case"]["attack_chain"],
            "next_steps": a["next_steps"],
            "assessment": a, "case": analysis["case"]
        })
    return {
        "scenario": "BANK_IMPERSONATION_TO_BENEFICIARY_DIVERSION",
        "label": "Synthetic end-to-end simulation",
        "steps": results,
        "disclaimer": "Simulated scenario and synthetic data. No real inbox, URL, file, bank account, or transaction was accessed. Demonstrates the analysis pipeline; it does not prove background protection is installed."
    }

@app.post("/api/analyze")
def analyze_api(payload: dict):
    try:
        return analyze_submission(payload, cases)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

@app.get("/", response_class=HTMLResponse)
def live_workbench():
    return LIVE_HTML

LIVE_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScamChain | Investigation Workbench</title>
<style>
:root{--bg:#070d18;--panel:#0d1727;--line:#223149;--text:#edf4ff;--muted:#91a3bd;--cyan:#5ee7ff;--red:#ff667f;--amber:#ffc857;--green:#5fe0ae}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#10283a 0%,var(--bg) 44%);color:var(--text);font:14px Inter,system-ui,sans-serif}header{height:76px;display:flex;align-items:center;justify-content:space-between;padding:0 4vw;border-bottom:1px solid var(--line);background:#07101bdd;position:sticky;top:0;z-index:3;backdrop-filter:blur(12px)}.brand{display:flex;gap:12px;align-items:center}.mark{width:38px;height:38px;border:1px solid #3d8195;border-radius:11px;display:grid;place-items:center;color:var(--cyan);font-size:20px}.brand h1{margin:0;font-size:20px;letter-spacing:.2px}.sub{font-size:11px;color:var(--muted);margin-top:4px}.status{font-size:11px;color:var(--green);border:1px solid #245c4e;background:#102b2a;padding:7px 10px;border-radius:20px}.wrap{max-width:1500px;margin:auto;padding:26px 4vw 45px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:end;margin-bottom:22px}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:2px;text-transform:uppercase}.hero h2{font-size:clamp(25px,3vw,39px);margin:9px 0 8px;letter-spacing:-1px}.hero p{color:var(--muted);margin:0;max-width:720px;line-height:1.6}.pills{display:flex;gap:8px;flex-wrap:wrap}.pill{border:1px solid var(--line);background:#0b1728;padding:7px 10px;border-radius:8px;color:#b9c9df;font-size:11px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}.metric,.panel{border:1px solid var(--line);background:linear-gradient(145deg,#101d30,#0a1322);border-radius:14px}.metric{padding:16px}.metric .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}.metric strong{display:block;font-size:27px;margin-top:8px}.metric .hint{font-size:11px;color:var(--muted);margin-top:5px}.columns{display:grid;grid-template-columns:minmax(320px,.82fr) minmax(0,1.4fr);gap:15px;align-items:start}.panel{padding:20px;min-width:0}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:16px}.panel h3{font-size:15px;margin:0}.sectionlabel{font-size:10px;letter-spacing:1.5px;color:var(--cyan);text-transform:uppercase;margin-bottom:7px}.field{margin:13px 0}.field label{display:block;color:#c2d1e4;font-size:12px;margin-bottom:7px}.field textarea,.field input{width:100%;background:#07111e;border:1px solid #263a53;color:var(--text);border-radius:9px;padding:11px 12px;font:13px inherit;outline:none}.field textarea{min-height:108px;resize:vertical;line-height:1.5}.field input:focus,.field textarea:focus{border-color:#42bcd3;box-shadow:0 0 0 3px #42bcd31b}.checkrow{display:grid;grid-template-columns:1fr 1fr;gap:8px}.check{display:flex;align-items:center;gap:8px;border:1px solid var(--line);padding:10px;border-radius:9px;color:#bdcbe0;font-size:12px}.check input{accent-color:#38cde5}.btn{cursor:pointer;border:1px solid #2b7586;background:linear-gradient(120deg,#0d4659,#116278);color:#effcff;border-radius:9px;padding:12px 15px;font-weight:650;font-size:12px}.btn:hover{filter:brightness(1.15)}.btn.secondary{background:#101c2d;border-color:var(--line);color:#c9d8ea}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.note{font-size:11px;color:var(--muted);line-height:1.6;margin-top:12px}.rightstack{display:grid;gap:15px}.empty{min-height:230px;display:grid;place-items:center;text-align:center;color:var(--muted);padding:30px}.empty .big{font-size:32px;color:#315a71;margin-bottom:12px}.resulthead{display:flex;align-items:start;justify-content:space-between;gap:14px}.riskbadge{padding:8px 12px;border-radius:9px;font-weight:800;letter-spacing:.6px;font-size:11px}.risk-HIGH{color:#ff9cab;background:#451b2a;border:1px solid #783144}.risk-REVIEW{color:#ffda83;background:#3b311a;border:1px solid #6b5427}.risk-NORMAL{color:#80edbd;background:#14382e;border:1px solid #28634d}.score{font-size:38px;font-weight:800;letter-spacing:-1px}.muted{color:var(--muted)}.small{font-size:11px}.bar{height:7px;background:#1b2a3d;border-radius:10px;overflow:hidden;margin-top:12px}.bar>span{display:block;height:100%;background:linear-gradient(90deg,#40c7e5,#ffc857,#ff667f);border-radius:10px}.blocktitle{margin:21px 0 10px;font-size:12px;color:#d9e7f8}.chain{display:flex;align-items:stretch;gap:6px;flex-wrap:wrap}.stage{font-size:10px;padding:9px;border:1px solid #294158;background:#101f31;border-radius:8px;max-width:160px}.stage b{display:block;color:var(--cyan);font-size:9px;margin-bottom:5px}.arrow{color:#4baec2;align-self:center}.signalgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.signal{border:1px solid var(--line);border-radius:9px;padding:10px;background:#0a1422}.signal b{font-size:11px;display:block;overflow-wrap:anywhere}.signal span{font-size:10px;color:var(--muted)}.timeline{display:grid;gap:8px}.event{display:grid;grid-template-columns:62px 1fr;gap:10px;padding:11px;border-left:2px solid #2b8ea4;background:#091421;border-radius:0 8px 8px 0}.time{color:var(--cyan);font-size:10px;padding-top:2px}.event b{font-size:11px}.event p{margin:5px 0 0;color:var(--muted);font-size:11px;line-height:1.5;overflow-wrap:anywhere}.kv{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.kv div{border:1px solid var(--line);padding:10px;border-radius:8px}.kv small{display:block;color:var(--muted);font-size:10px}.kv b{display:block;margin-top:5px;font-size:14px}.gaprow,.nextstep{padding:10px 11px;border:1px solid var(--line);border-radius:8px;margin:7px 0;background:#0a1422;font-size:11px;line-height:1.5}.gaprow b{color:var(--amber)}.nextstep{border-left:3px solid var(--green)}.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;font-size:11px}.table th,.table td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}.table th{color:var(--muted);font-weight:500}.caveat{border:1px solid #604f2c;background:#231e13;color:#e5d4a7;padding:12px;border-radius:9px;font-size:11px;line-height:1.6;margin-top:14px}.footer{color:#6f8299;font-size:10px;line-height:1.6;margin-top:20px}.loading{opacity:.65;pointer-events:none}.hide{display:none!important}@media(max-width:950px){.columns{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.hero{display:block}.pills{margin-top:14px}}@media(max-width:560px){header{padding:0 4vw}.wrap{padding:20px 4vw}.metrics{gap:8px}.metric{padding:12px}.metric strong{font-size:23px}.panel{padding:14px}.signalgrid,.kv{grid-template-columns:1fr}.checkrow{grid-template-columns:1fr 1fr}}
</style></head><body>
<header><div class="brand"><div class="mark">⛓</div><div><h1>SCAMCHAIN <span style="color:var(--cyan)">/</span> BEYOND BINARY</h1><div class="sub">Explainable financial scam workflow investigation</div></div></div><div class="status">● ANALYSIS ENGINE ONLINE</div></header>
<div class="wrap"><div class="hero"><div><div class="eyebrow">Connect the signals. Expose the scam.</div><h2>Investigation Workbench</h2><p>Submit evidence, correlate 18 signal families, reconstruct the suspected attack sequence, and inspect why each stage was inferred. No automatic blocking; an analyst remains in control.</p></div><div class="pills"><span class="pill">18 signal families</span><span class="pill">Temporal reconstruction</span><span class="pill">Evidence provenance</span><span class="pill">Campaign correlation</span></div></div>
<div class="metrics"><div class="metric"><div class="label">Case library</div><strong id="mCases">—</strong><div class="hint">Synthetic reference incidents</div></div><div class="metric"><div class="label">Known entities</div><strong id="mEntities">—</strong><div class="hint">Across reference cases</div></div><div class="metric"><div class="label">Campaign clusters</div><strong id="mCampaigns">—</strong><div class="hint">Shared patterns & infrastructure</div></div><div class="metric"><div class="label">Model state</div><strong style="font-size:20px" id="mModel">CHECKING</strong><div class="hint">Synthetic-trained demo classifier</div></div></div>

<section id="simulation">
 <div class="simtop"><div><div class="sectionlabel">Live demo / attack replay</div><h3>Watch a scam unfold — signal by signal</h3><p>A judge-facing, deterministic simulation: a bank-impersonation email moves through link inspection, credential solicitation, unfamiliar login, beneficiary creation and transfer risk. Each stage calls the same backend analysis pipeline used by manual intake.</p></div><span class="simstate" id="simStatus">● SIMULATION READY</span></div>
 <div class="simgrid"><div><div class="simtrack" id="simTrack"><div class="simnode"><div class="num">STAGE 01</div><b>Inbound email</b></div><div class="simnode"><div class="num">STAGE 02</div><b>Link inspection</b></div><div class="simnode"><div class="num">STAGE 03</div><b>Credential attempt</b></div><div class="simnode"><div class="num">STAGE 04</div><b>Account signal</b></div><div class="simnode"><div class="num">STAGE 05</div><b>New beneficiary</b></div><div class="simnode"><div class="num">STAGE 06</div><b>Transfer risk</b></div></div><div class="simbar"><span id="simProgress"></span></div></div>
 <div class="simfeed" id="simFeed"><div class="live">SYSTEM EVENT STREAM</div><h4>Ready to replay the attack chain</h4><p>Run the simulation to see evidence accumulate, the risk assessment update, and a user-protection alert appear.</p></div></div>
 <div id="simAlert"><b>SCAMCHAIN ALERT</b> — Multi-stage financial scam indicators correlated. Stop interaction, do not share secrets, and verify through the bank's official channel.</div>
 <div class="simfoot"><small>SIMULATED DATA · No real email inbox, file, URL, bank account or transaction is accessed.<br>This is a demonstration of the analysis pipeline, not proof of a resident background monitor.</small><div class="actions" style="margin-top:0"><button class="btn" id="runSim">▶ Run full simulation</button><button class="btn secondary" id="resetSim">Reset replay</button></div></div>
</section>
<div class="columns"><section class="panel" id="intake"><div class="panelhead"><div><div class="sectionlabel">01 / Evidence intake</div><h3>Analyze a suspicious interaction</h3></div><span class="pill">Live request</span></div>
<div class="field"><label for="message">Message / email / chat text</label><textarea id="message" placeholder="Paste the suspicious message. Example: Bank security: your account will be blocked. Verify your netbanking password and OTP immediately…"></textarea></div>
<div class="field"><label for="url">Suspicious URL (if present)</label><input id="url" placeholder="https://account-verify.example/login"></div>
<div class="field"><label for="sender">Sender phone / email / handle</label><input id="sender" placeholder="+91… or sender@example.com"></div>
<div class="field"><label for="beneficiary">Beneficiary / UPI ID (optional)</label><input id="beneficiary" placeholder="example@upi or masked beneficiary ID"></div>
<div class="field"><label>Observed downstream events</label><div class="checkrow"><label class="check"><input type="checkbox" id="login"> Unknown device login</label><label class="check"><input type="checkbox" id="benef"> New beneficiary added</label><label class="check"><input type="checkbox" id="transfer"> Transfer initiated</label></div></div>
<div class="actions"><button class="btn" id="analyze">Analyze evidence →</button><button class="btn secondary" id="sample">Load attack-chain example</button><button class="btn secondary" id="clear">Clear</button></div><div id="error" class="note" role="status"></div><div class="note">Only submit test or appropriately redacted evidence. The demo does not contact URLs, send messages, query bank accounts, or execute transactions.</div></section>
<div class="rightstack"><section class="panel" id="overview"><div class="panelhead"><div><div class="sectionlabel">02 / Decision support</div><h3>Evidence assessment</h3></div><span class="pill" id="caseid">Awaiting input</span></div><div class="empty"><div><div class="big">⌁</div><b style="color:#dbe8f8">The chain starts with evidence.</b><p class="small">Submit a message, URL, or sender to generate a fresh case assessment.</p></div></div></section>
<section class="panel"><div class="panelhead"><div><div class="sectionlabel">03 / Reference intelligence</div><h3>Existing synthetic cases</h3></div><button class="btn secondary" id="loadcases">Refresh</button></div><div id="caseList" class="small muted">Loading reference cases…</div></section></div></div>
<div class="footer">ScamChain is a prototype for research and demonstration. All built-in case data and classifier training samples are synthetic. Risk score is a rule-fusion triage score; the classifier score is trained on synthetic data and is not a real-world fraud probability. Findings require independent verification.</div></div>
<script>
const $=id=>document.getElementById(id);let cases=[];
async function boot(){try{const [summary,all,model]=await Promise.all([fetch('/api/summary').then(r=>r.json()),fetch('/api/cases').then(r=>r.json()),fetch('/api/model-status').then(r=>r.json())]);cases=all;$('mCases').textContent=summary.cases;$('mEntities').textContent=summary.entities;$('mCampaigns').textContent=summary.campaigns;$('mModel').textContent=model.status==='loaded'?'READY':'CHECK';$('caseList').innerHTML=cases.map(c=>'<div class="gaprow"><b>'+esc(c.case_id)+'</b> · <span class="riskbadge risk-'+esc(c.risk.policy.replace(' ','-'))+'">'+esc(c.risk.policy)+'</span><div class="muted" style="margin-top:5px">'+esc(c.attack_chain.join(' → ')||'No canonical stages')+'</div><button class="btn secondary" style="margin-top:8px;padding:7px 9px" onclick="loadReference(\''+esc(c.case_id)+'\')">Inspect example</button></div>').join('')}catch(e){$('mModel').textContent='RETRY';$('caseList').textContent='Reference service is still starting. Refresh shortly.'}}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
$('sample').onclick=()=>{$('message').value='Bank security: your account will be blocked immediately. Verify your netbanking password and share the OTP to restore access.';$('url').value='https://secure-bank-verify.example/login';$('sender').value='+91-90000-10001';$('beneficiary').value='beneficiary-demo@upi';$('login').checked=true;$('benef').checked=true;$('transfer').checked=true;$('error').textContent='Synthetic attack-chain example loaded. Click Analyze evidence to run the pipeline.'};
$('clear').onclick=()=>{['message','url','sender','beneficiary'].forEach(x=>$(x).value='');['login','benef','transfer'].forEach(x=>$(x).checked=false);$('error').textContent='';};
$('loadcases').onclick=boot;
$('analyze').onclick=async()=>{const btn=$('analyze');btn.disabled=true;btn.textContent='Analyzing evidence…';$('intake').classList.add('loading');$('error').textContent='';try{const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:$('message').value,url:$('url').value,sender:$('sender').value,beneficiary:$('beneficiary').value,new_device_login:$('login').checked,beneficiary_created:$('benef').checked,transfer_initiated:$('transfer').checked})});const data=await r.json();if(!r.ok)throw new Error(data.detail||'Analysis failed');render(data)}catch(e){$('error').textContent=e.message||'Could not analyze this submission.'}finally{btn.disabled=false;btn.textContent='Analyze evidence →';$('intake').classList.remove('loading')}};
function render(d){const a=d.assessment,c=d.case;$('caseid').textContent=c.case_id;const overview=$('overview');overview.innerHTML='<div class="panelhead"><div><div class="sectionlabel">02 / Decision support</div><h3>Assessment result</h3></div><span class="pill">'+esc(c.case_id)+'</span></div><div class="resulthead"><div><div class="muted small">Rule-fusion triage score</div><div class="score">'+a.risk_score+'<span class="muted" style="font-size:15px"> / 100</span></div></div><span class="riskbadge risk-'+esc(a.policy.replace(' ','-'))+'">'+esc(a.policy)+'</span></div><div class="bar"><span style="width:'+Math.max(0,Math.min(100,a.risk_score))+'%"></span></div><div class="kv" style="margin-top:14px"><div><small>Positive signals</small><b>'+a.signal_count+'</b></div><div><small>Evidence coverage</small><b>'+esc(a.evidence_completeness.score)+' / 100</b></div><div><small>Classifier score*</small><b>'+(a.model_score===null?'Unavailable':Math.round(a.model_score*100)+'%')+'</b></div></div><div class="note">'+esc(a.model_score_label)+' · separate synthetic model output.</div><div class="blocktitle">Reconstructed attack workflow</div><div class="chain">'+(c.attack_chain.length?c.attack_chain.map((s,i)=>'<div class="stage"><b>STAGE '+String(i+1).padStart(2,'0')+'</b>'+esc(s.replaceAll('_',' '))+'</div>').join('<span class="arrow">→</span>'):'<span class="muted small">No canonical attack stages inferred yet.</span>')+'</div><div class="blocktitle">Detected signals / evidence</div><div class="signalgrid">'+(a.signals.length?a.signals.map(s=>'<div class="signal"><b>'+esc(s.signal.replaceAll('_',' '))+'</b><span>'+esc(s.domain)+' · intensity '+Math.round(s.value*100)+'% · '+s.evidence.length+' evidence refs</span></div>').join(''):'<div class="signal muted">No positive signal fired on the submitted evidence. Absence of a signal does not prove safety.</div>')+'</div><div class="blocktitle">Chronological replay</div><div class="timeline">'+(a.attack_replay.length?a.attack_replay.map(e=>'<div class="event"><div class="time">'+esc(e.timestamp.slice(11,19))+'</div><div><b>'+esc(e.event_type.replaceAll('_',' '))+'</b><p>'+esc(e.evidence.join(' · '))+'<br>Event '+esc(e.event_id)+' · '+esc(e.stage.replaceAll('_',' '))+'</p></div></div>').join(''):'<div class="muted small">No events to replay.</div>')+'</div><div class="blocktitle">Stage provenance & missing evidence</div><div class="tablewrap"><table class="table"><thead><tr><th>Stage</th><th>Status</th><th>Confidence</th><th>Evidence refs</th></tr></thead><tbody>'+a.stage_provenance.map(p=>'<tr><td>'+esc(p.stage.replaceAll('_',' '))+'</td><td>'+esc(p.status)+'</td><td>'+esc(p.confidence)+'%</td><td>'+esc(p.evidence_ids.join(', ')||'None observed')+'</td></tr>').join('')+'</tbody></table></div>'+(a.evidence_gaps.length?'<div class="blocktitle">Evidence gaps to resolve</div>'+a.evidence_gaps.map(g=>'<div class="gaprow"><b>'+esc(g.priority)+' · '+esc(g.stage.replaceAll('_',' '))+'</b><br>'+esc(g.request)+'</div>').join(''):'')+'<div class="blocktitle">Recommended next steps</div>'+a.next_steps.map(s=>'<div class="nextstep">'+esc(s)+'</div>').join('')+'<div class="caveat">'+esc(a.caveat)+'</div>';overview.scrollIntoView({behavior:'smooth',block:'start'})}
function loadReference(id){const c=cases.find(x=>x.case_id===id);if(!c)return;$('message').value=c.events.filter(e=>e.event_type==='MESSAGE_RECEIVED').flatMap(e=>e.evidence).join(' ');$('url').value=(c.entities.find(e=>e.type==='URL')||{}).value||'';$('sender').value=(c.entities.find(e=>e.type==='PHONE')||{}).value||'';$('beneficiary').value=(c.entities.find(e=>e.type==='BENEFICIARY')||{}).value||'';$('login').checked=c.events.some(e=>e.event_type==='LOGIN');$('benef').checked=c.events.some(e=>e.event_type==='BENEFICIARY_CREATED');$('transfer').checked=c.events.some(e=>e.event_type==='TRANSACTION_INITIATED');$('error').textContent='Loaded fields from '+id+' as an intake example. Submit to run a fresh assessment.';$('intake').scrollIntoView({behavior:'smooth'})}

async function runSimulation(){const btn=$('runSim');btn.disabled=true;$('simStatus').textContent='● RUNNING PIPELINE';$('simAlert').style.display='none';$('simProgress').style.width='0%';$('simTrack').querySelectorAll('.simnode').forEach(n=>n.className='simnode');$('simFeed').innerHTML='<div class="live">SYSTEM EVENT STREAM</div><h4>Connecting evidence signals…</h4><p>Running each simulated incident stage through the backend engine.</p>';try{const res=await fetch('/api/simulate',{method:'POST'});const data=await res.json();if(!res.ok)throw new Error(data.detail||'Simulation request failed');for(let i=0;i<data.steps.length;i++){const s=data.steps[i],nodes=$('simTrack').querySelectorAll('.simnode');nodes.forEach((n,j)=>{n.className='simnode'+(j<i?' done':j===i?' active':'')});$('simProgress').style.width=((i+1)/data.steps.length*100)+'%';$('simFeed').innerHTML='<div class="live">● '+esc(s.phase)+' · '+(i+1)+'/'+data.steps.length+'</div><h4>'+esc(s.title)+'</h4><p>'+esc(s.description)+'</p><div style="display:flex;gap:7px;flex-wrap:wrap;margin-top:10px"><span class="pill">Risk '+s.risk_score+'/100</span><span class="pill">'+esc(s.policy)+'</span><span class="pill">'+s.signal_count+' signals</span></div>';if(i===data.steps.length-1){nodes[i].className='simnode alert';$('simAlert').style.display='block';$('simStatus').textContent='● ALERT GENERATED';}await new Promise(resolve=>setTimeout(resolve,720));}const final=data.steps[data.steps.length-1];render({assessment:final.assessment,case:final.case});$('simFeed').innerHTML+='<p style="margin-top:10px;color:#70edba">Replay complete. Final evidence assessment loaded below for judge inspection.</p>';$('simStatus').textContent='● REPLAY COMPLETE';}catch(e){$('simStatus').textContent='● SIMULATION ERROR';$('simFeed').innerHTML='<div class="live">BACKEND RESPONSE</div><h4>Could not run simulation</h4><p>'+esc(e.message)+'</p>';}finally{btn.disabled=false;btn.textContent='↻ Run simulation again';}}
function resetSimulation(){$('simStatus').textContent='● SIMULATION READY';$('simProgress').style.width='0%';$('simAlert').style.display='none';$('simTrack').querySelectorAll('.simnode').forEach(n=>n.className='simnode');$('simFeed').innerHTML='<div class="live">SYSTEM EVENT STREAM</div><h4>Ready to replay the attack chain</h4><p>Run the simulation to see evidence accumulate, the risk assessment update, and a user-protection alert appear.</p>';$('runSim').textContent='▶ Run full simulation';}
$('runSim').onclick=runSimulation;$('resetSim').onclick=resetSimulation;
boot();
</script></body></html>'''
