from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

router = APIRouter()

class DefenseRequest(BaseModel):
    scenario: str = "upi"
    controls: dict[str, bool] = Field(default_factory=dict)

SCENARIOS = {
    "upi": {
        "name": "UPI collect-request impersonation",
        "stages": [
            ("Message received", "A payment request arrives with urgent language.", "message"),
            ("Identity mismatch", "The sender claims to represent a known service but identity is not verified.", "identity"),
            ("Payment request", "The flow asks the recipient to approve a collect request.", "payment"),
            ("Approval attempt", "The recipient is pressured to approve before checking details.", "approval"),
            ("Funds at risk", "If approved, money may leave the account.", "transfer"),
        ],
        "impact": 8500
    },
    "phishing": {
        "name": "Credential-harvesting link",
        "stages": [
            ("Message received", "A delivery or account warning prompts immediate action.", "message"),
            ("Suspicious link", "The message points to an unverified destination.", "link"),
            ("Lookalike identity", "The destination imitates a trusted brand.", "identity"),
            ("Credential entry", "The victim is asked to enter a password or one-time code.", "credential"),
            ("Account takeover risk", "Stolen credentials could enable unauthorized access.", "account"),
        ],
        "impact": 12000
    },
    "beneficiary": {
        "name": "Social engineering + new beneficiary",
        "stages": [
            ("Conversation begins", "A caller or message creates urgency or fear.", "message"),
            ("Authority pressure", "The sender claims an account or family member is in danger.", "identity"),
            ("New beneficiary", "The victim is directed to add an unfamiliar payee.", "beneficiary"),
            ("Transfer initiated", "A transfer is prepared to the new beneficiary.", "transfer"),
            ("Potential financial loss", "Funds could be difficult to recover after transfer.", "loss"),
        ],
        "impact": 25000
    }
}

CONTROL_RULES = {
    "message_check": {"blocks": ["message"], "label": "Message inspection"},
    "identity_verify": {"blocks": ["identity"], "label": "Identity verification"},
    "link_guard": {"blocks": ["link", "credential"], "label": "Link / credential guard"},
    "payment_pause": {"blocks": ["payment", "approval", "beneficiary", "transfer"], "label": "High-risk payment pause"},
    "new_payee_check": {"blocks": ["beneficiary"], "label": "New-beneficiary verification"},
}

@router.post("/api/defense-simulate")
def defense_simulate(req: DefenseRequest):
    scenario = SCENARIOS.get(req.scenario, SCENARIOS["upi"])
    enabled = [key for key, value in req.controls.items() if value and key in CONTROL_RULES]
    intercepted = None
    timeline = []
    for idx, (title, description, kind) in enumerate(scenario["stages"]):
        matching = [CONTROL_RULES[k]["label"] for k in enabled if kind in CONTROL_RULES[k]["blocks"]]
        blocked = bool(matching) and intercepted is None
        if blocked:
            intercepted = {"stage": idx, "title": title, "controls": matching}
        timeline.append({
            "step": idx + 1, "title": title, "description": description, "kind": kind,
            "status": "intercepted" if blocked else ("after_interception" if intercepted else "reachable"),
            "controls": matching
        })
    prevented = intercepted is not None
    return {
        "scenario": req.scenario if req.scenario in SCENARIOS else "upi",
        "scenario_name": scenario["name"],
        "controls_enabled": enabled,
        "timeline": timeline,
        "intercepted": intercepted,
        "outcome": "simulated_intercept" if prevented else "uninterrupted_attack_path",
        "stages_reached": (intercepted["stage"] + 1) if prevented else len(timeline),
        "total_stages": len(timeline),
        "illustrative_exposure_inr": scenario["impact"],
        "illustrative_exposure_avoided_inr": scenario["impact"] if prevented else 0,
        "method_note": "Deterministic scenario simulation, not a measured prediction, real transaction, or guarantee that a control would stop a real attack."
    }

@router.get("/defense-lab", response_class=HTMLResponse)
def defense_lab_page():
    return HTMLResponse(r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScamChain · Counterfactual Defense Lab</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#12364c 0,transparent 42%),radial-gradient(ellipse at 90% 8%,#261b48 0,transparent 35%),#050914;color:#e6f2ff;font:14px Inter,system-ui,sans-serif}a{color:#70e8f7;text-decoration:none}.top{padding:23px max(18px,calc((100vw - 1240px)/2));border-bottom:1px solid #234056;background:#071321c9;backdrop-filter:blur(15px)}.eyebrow{font:10px monospace;letter-spacing:2px;color:#71e7f7}h1{font-size:clamp(27px,4vw,39px);margin:10px 0}p{line-height:1.6;color:#9db1c8}.links{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px;font-size:12px}main{max-width:1240px;margin:auto;padding:22px 18px 55px}.hero{border:1px solid #31526b;border-radius:16px;padding:20px;background:linear-gradient(115deg,#102b40d9,#141329c9);box-shadow:0 15px 40px #0003}.hero h2{font-size:clamp(23px,3vw,34px);margin:4px 0 8px}.tag{display:inline-block;border:1px solid #31546d;border-radius:99px;padding:5px 9px;color:#9ceeff;font:10px monospace}.layout{display:grid;grid-template-columns:330px minmax(0,1fr);gap:15px;margin-top:15px}.panel{border:1px solid #223c54;border-radius:14px;padding:17px;background:linear-gradient(145deg,#0f2034ed,#081321ed);min-width:0}.panel h3{margin:0 0 12px;font-size:15px}.scenarios{display:grid;gap:8px}.scenario{border:1px solid #28445c;background:#091626;border-radius:10px;padding:12px;text-align:left;color:#d9ebfc;cursor:pointer}.scenario.active{border-color:#5ce4f7;background:#102c40;box-shadow:0 0 20px #51d8f418}.scenario b{display:block;font-size:12px}.scenario small{display:block;color:#8da7c1;margin-top:5px;line-height:1.45}.control{display:flex;align-items:start;gap:10px;padding:12px 0;border-bottom:1px solid #1c3045}.control:last-child{border-bottom:0}.control input{accent-color:#56e2f4;width:17px;height:17px;margin-top:2px}.control b{display:block;font-size:12px}.control small{display:block;color:#8ea6c0;font-size:11px;line-height:1.5;margin-top:4px}.btn{margin-top:14px;border:1px solid #367e95;background:linear-gradient(110deg,#123c51,#1c2b4b);color:#e8fbff;border-radius:9px;padding:12px 15px;font-weight:700;cursor:pointer;width:100%}.btn:disabled{opacity:.5;cursor:wait}.resultgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px;margin-bottom:14px}.stat{border:1px solid #223d55;background:#081626;border-radius:10px;padding:12px}.num{font-size:24px;font-weight:800;color:#7ce9fa}.label{font-size:10px;color:#8fa8c0;margin-top:4px}.timeline{display:grid;gap:8px}.stage{display:grid;grid-template-columns:32px minmax(0,1fr) auto;gap:10px;align-items:start;border:1px solid #243b52;background:#081522;border-radius:10px;padding:12px}.stage.intercepted{border-color:#42d7a0;background:linear-gradient(100deg,#0d302c,#0b1b28);box-shadow:0 0 22px #3dd7a012}.stage.after_interception{opacity:.48}.step{width:27px;height:27px;border-radius:8px;background:#132d42;display:grid;place-items:center;color:#8cecff;font:11px monospace}.stage h4{margin:0;font-size:12px}.stage p{font-size:11px;margin:5px 0 0}.state{font:9px monospace;letter-spacing:.6px;border:1px solid #304d63;border-radius:99px;padding:5px 7px;color:#a9c0d5;white-space:nowrap}.intercepted .state{border-color:#287f68;color:#7af0be}.notice{border-left:3px solid #e7bc65;background:#211d14;padding:12px;margin-top:14px;color:#e8d5a3;font-size:11px;line-height:1.6}.empty{padding:30px 15px;text-align:center;border:1px dashed #31506a;border-radius:11px;color:#8ea6bf}.reason{font-size:12px;color:#9eb5cb;margin-top:10px}.reason strong{color:#7ce9fa}.footer{font-size:10px;color:#6e8299;margin-top:16px}@media(max-width:850px){.layout{grid-template-columns:1fr}.resultgrid{grid-template-columns:repeat(3,1fr)}}@media(max-width:500px){.resultgrid{grid-template-columns:1fr}.stage{grid-template-columns:28px minmax(0,1fr)}.stage .state{grid-column:2;justify-self:start}}

/* Premium product finish */
:root{--ink:#eaf3ff;--muted:#91a7c0;--line:rgba(117,174,210,.17);--cyan:#72e7f7;--violet:#b4a0ff}
body{font-family:Inter,ui-sans-serif,system-ui,sans-serif;letter-spacing:-.012em;background:radial-gradient(ellipse at 0% 0%,rgba(22,105,145,.24),transparent 38%),radial-gradient(ellipse at 100% 0%,rgba(95,65,169,.18),transparent 32%),linear-gradient(180deg,#050914,#070d19 58%,#050914)}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.14;background-image:linear-gradient(rgba(130,185,222,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(130,185,222,.06) 1px,transparent 1px);background-size:52px 52px;mask-image:linear-gradient(to bottom,black,transparent 80%)}
.top{position:relative;border-bottom:1px solid var(--line);background:rgba(5,12,24,.72);box-shadow:0 18px 50px #0002}
.eyebrow,.tag,.state,.label,.step{font-family:ui-monospace,SFMono-Regular,monospace}
.eyebrow{color:var(--cyan);font-size:10px;letter-spacing:2.4px}
h1{font-weight:800;letter-spacing:-.045em}
main{position:relative}
.hero{background:linear-gradient(120deg,rgba(15,40,58,.92),rgba(18,18,42,.87));border-color:rgba(114,231,247,.24);box-shadow:0 20px 60px #0003,inset 0 1px rgba(255,255,255,.06);padding:clamp(22px,3vw,34px);position:relative;overflow:hidden}
.hero:after{content:"";position:absolute;width:280px;height:280px;right:-90px;top:-150px;border-radius:50%;background:rgba(89,210,245,.12);filter:blur(40px);pointer-events:none}
.hero h2{letter-spacing:-.045em;font-weight:800;background:linear-gradient(90deg,#f3fbff 5%,#79eaff 68%,#b9a6ff);background-clip:text;color:transparent}
.tag{background:rgba(8,23,39,.6);border-color:rgba(114,231,247,.24);font-size:9px;letter-spacing:1.1px}
.panel{background:linear-gradient(145deg,rgba(14,29,48,.91),rgba(7,15,28,.94));border-color:var(--line);box-shadow:0 16px 44px #0002,inset 0 1px rgba(255,255,255,.035);backdrop-filter:blur(18px)}
.panel h3{font-weight:800;letter-spacing:-.025em}
.scenario{transition:transform .18s,border-color .18s,background .18s;line-height:1.5}
.scenario:hover{transform:translateY(-1px);border-color:rgba(114,231,247,.48)}
.scenario.active{border-color:var(--cyan);background:linear-gradient(110deg,rgba(17,57,75,.95),rgba(15,29,50,.95));box-shadow:0 0 0 1px rgba(114,231,247,.08),0 12px 30px #02060c66}
.control{cursor:pointer}.control:hover b{color:#fff}.control input{accent-color:var(--cyan)}
.btn{font-size:12px;letter-spacing:.01em;border-radius:10px;background:linear-gradient(110deg,#12617a,#303b76);border-color:rgba(114,231,247,.45);box-shadow:0 8px 25px rgba(22,173,207,.12);transition:transform .18s,filter .18s,box-shadow .18s}
.btn:hover{transform:translateY(-1px);filter:brightness(1.12);box-shadow:0 10px 30px rgba(22,173,207,.2)}
.btn:focus-visible,.scenario:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.stat{background:linear-gradient(145deg,rgba(8,22,38,.95),rgba(9,17,31,.92));border-color:var(--line)}
.num{font-size:clamp(20px,2.2vw,27px);letter-spacing:-.04em}
.stage{background:linear-gradient(100deg,rgba(8,21,35,.94),rgba(9,18,32,.94));border-color:var(--line);transition:opacity .2s,border-color .2s}
.stage h4{font-size:12px;font-weight:800;letter-spacing:-.01em}
.stage.intercepted{border-color:rgba(74,230,177,.7);box-shadow:inset 3px 0 #4ae6b1,0 8px 25px #0002}
.step{border:1px solid rgba(114,231,247,.12)}
.notice{border-left-color:#f0c66d;background:linear-gradient(100deg,rgba(64,47,19,.55),rgba(28,25,22,.65));border-top:1px solid rgba(240,198,109,.12);border-right:1px solid rgba(240,198,109,.08);border-bottom:1px solid rgba(240,198,109,.08);border-radius:0 9px 9px 0}
.empty{background:rgba(5,14,26,.45);border-color:rgba(117,174,210,.25)}
.links a{color:#9ceefa;transition:color .15s}.links a:hover{color:white}
.footer{font-family:ui-monospace,SFMono-Regular,monospace;font-size:9px;letter-spacing:.03em}
@media(max-width:700px){.top{padding:20px 18px}.hero h2{line-height:1.1}.panel{padding:14px}.links{gap:12px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{transition:none!important;scroll-behavior:auto!important}}
</style></head><body>
<header class="top"><div class="eyebrow">BEYOND BINARY / SCAMCHAIN INTELLIGENCE</div><h1>Counterfactual Defense Lab</h1><p style="max-width:800px;margin:0">Don't just detect a scam. Test where a defense would interrupt its workflow, compare controls, and inspect the remaining attack path.</p><nav class="links"><a href="/">← Workbench</a><a href="/simulator">Attack Simulator</a><a href="/threat-map">Threat Graph</a><a href="/evidence">Evidence Lab</a><a href="/validation">Validation</a></nav></header>
<main><section class="hero"><span class="tag">INTERACTIVE · SCENARIO ENGINE</span><h2>What would stop the chain?</h2><p style="max-width:900px;margin:0">Choose a scam workflow, enable defensive controls, then run the same chain again. ScamChain highlights the earliest simulated interception and shows which later stages become unreachable in this scenario.</p></section>
<div class="layout"><aside><section class="panel"><h3>01 / Choose a scenario</h3><div class="scenarios" id="scenarios">
<button class="scenario active" data-scenario="upi"><b>UPI collect-request impersonation</b><small>Urgent payment request → approval pressure → potential loss</small></button>
<button class="scenario" data-scenario="phishing"><b>Credential-harvesting link</b><small>Suspicious URL → lookalike page → credential exposure</small></button>
<button class="scenario" data-scenario="beneficiary"><b>New-beneficiary manipulation</b><small>Social pressure → unfamiliar payee → transfer risk</small></button></div></section>
<section class="panel" style="margin-top:14px"><h3>02 / Enable controls</h3>
<label class="control"><input type="checkbox" data-control="message_check"><span><b>Message inspection</b><small>Check urgency, language, and suspicious context before acting.</small></span></label>
<label class="control"><input type="checkbox" data-control="identity_verify"><span><b>Identity verification</b><small>Verify sender identity through an independent trusted channel.</small></span></label>
<label class="control"><input type="checkbox" data-control="link_guard"><span><b>Link / credential guard</b><small>Inspect untrusted destinations and block credential submission in the scenario.</small></span></label>
<label class="control"><input type="checkbox" data-control="payment_pause"><span><b>High-risk payment pause</b><small>Pause approval or transfer for a separate check.</small></span></label>
<label class="control"><input type="checkbox" data-control="new_payee_check"><span><b>New-beneficiary verification</b><small>Verify a newly added payee before continuing.</small></span></label>
<button class="btn" id="run">▶ Run counterfactual</button><button class="btn" id="reset" style="background:#0a1727;border-color:#2a4359">Reset controls</button></section></aside>
<section class="panel"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><h3 style="margin:0">03 / Attack-chain outcome</h3><span class="tag" id="status">READY TO SIMULATE</span></div><div class="resultgrid" style="margin-top:14px"><div class="stat"><div class="num" id="reached">—</div><div class="label">Stages reached</div></div><div class="stat"><div class="num" id="blocked">—</div><div class="label">Earliest interception</div></div><div class="stat"><div class="num" id="exposure">—</div><div class="label">Illustrative exposure avoided</div></div></div><div id="result"><div class="empty">Enable one or more controls and run the scenario to see its simulated outcome.</div></div><div class="notice"><b>Important:</b> this is a deterministic educational simulation, not a measured efficacy claim. The rupee amount is an illustrative scenario value, not an expected loss, live transaction, or guaranteed saving. Controls do not contact banks, inspect a device, or block real payments.</div><div class="footer">Scenario logic and control mapping are explicit and inspectable. No account, inbox, URL, or transaction is accessed.</div></section></div></main>
<script>
const $=id=>document.getElementById(id);let scenario="upi";const money=n=>"₹"+Number(n||0).toLocaleString("en-IN");
document.querySelectorAll("[data-scenario]").forEach(b=>b.addEventListener("click",()=>{scenario=b.dataset.scenario;document.querySelectorAll("[data-scenario]").forEach(x=>x.classList.toggle("active",x===b));$("status").textContent="SCENARIO CHANGED";}));
$("reset").onclick=()=>{document.querySelectorAll("[data-control]").forEach(x=>x.checked=false);$("result").innerHTML='<div class="empty">Controls reset. Run again to compare the uninterrupted path.</div>';$("reached").textContent="—";$("blocked").textContent="—";$("exposure").textContent="—";$("status").textContent="READY TO SIMULATE";};
$("run").onclick=async()=>{const b=$("run"),controls={};document.querySelectorAll("[data-control]").forEach(x=>controls[x.dataset.control]=x.checked);b.disabled=true;$("status").textContent="SIMULATING";try{const r=await fetch("/api/defense-simulate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scenario,controls})});const d=await r.json();if(!r.ok)throw Error(d.detail||("HTTP "+r.status));$("reached").textContent=d.stages_reached+" / "+d.total_stages;$("blocked").textContent=d.intercepted?d.intercepted.title:"None";$("exposure").textContent=money(d.illustrative_exposure_avoided_inr);$("status").textContent=d.intercepted?"SIMULATED INTERCEPTION":"CHAIN UNINTERRUPTED";$("result").innerHTML='<div class="reason"><strong>'+d.scenario_name+'</strong><br>'+(d.intercepted?"Earliest control hit: "+d.intercepted.controls.join(", ")+". Remaining stages are shown as unreachable in this scenario.":"No enabled control matched a stage in this scenario. The modeled path remains uninterrupted.")+'</div><div class="timeline" style="margin-top:12px">'+d.timeline.map(s=>'<article class="stage '+s.status+'"><div class="step">'+s.step.toString().padStart(2,"0")+'</div><div><h4>'+s.title+'</h4><p>'+s.description+'</p>'+(s.controls.length?'<p style="color:#7af0be">Matching control: '+s.controls.join(", ")+'</p>':'')+'</div><span class="state">'+s.status.replaceAll("_"," ").toUpperCase()+'</span></article>').join("")+'</div><p class="reason">'+d.method_note+'</p>';}catch(e){$("status").textContent="REQUEST FAILED";$("result").innerHTML='<div class="empty">Simulation failed: '+String(e.message).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))+'. Please retry.</div>';}finally{b.disabled=false;}};
</script></body></html>""")
