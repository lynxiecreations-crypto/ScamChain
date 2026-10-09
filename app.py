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

app=FastAPI(title="ScamChain v2.7 Campaign Investigation")
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
</style></head><body><header><div><h1>ScamChain <span class="tag">v2.7</span></h1><div class="muted">Connect the Signals. Expose the Scam.</div></div><div class="muted">Synthetic investigation environment</div></header><div class="grid" id="metrics"></div><main class="layout"><section class="panel"><div class="tabs"><button id="casesTab" class="active">Cases</button><button id="campaignTab">Campaigns</button><button id="mlTab">ML Evaluation</button><button id="campaignBenchTab">Campaign Benchmark</button><button id="riskTab">Risk & Intervention</button><button id="advTab">Adversarial</button><button id="evidenceTab">Evidence Confidence</button><button id="provenanceTab">Provenance & Replay</button><button id="campaignReplayTab">Campaign Replay</button></div><div id="list"></div></section><section class="panel"><div id="detail"></div></section></main><div class="footer">All evidence is synthetic. Scores are prototype outputs, not production fraud decisions.</div><script>
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

@app.get("/",response_class=HTMLResponse)
def home(): return HTML
