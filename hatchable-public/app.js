(function(){
'use strict';
var $=function(id){return document.getElementById(id)};
var state={events:[],analysis:null,correlation:null,seq:0};var latestQuickRisk=null;
var titles={overview:['Connect the signals.','A single message is a clue. A connected sequence can reveal the attack workflow.'],quickcheck:['Pause. Paste. Understand.','Screen a suspicious message, inspect its warning signs, and choose safer next steps.'],intake:['Build the case.','Add evidence events, inspect indicators, and correlate the timeline.'],graph:['Explore the suspected workflow.','Inspect event nodes, shared entities and inferred stages.'],evidence:['Trace every conclusion.','Review the evidence, reasoning, uncertainty and missing corroboration.'],simulator:['Experience the scam.','Interact with fictional messages and see plain-language warnings before exploring the suspected attack chain.']};
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function toast(s){var t=$('toast');t.textContent=s;t.classList.remove('hidden');clearTimeout(window.__scToast);window.__scToast=setTimeout(function(){t.classList.add('hidden')},2800)}
function nav(view){if(!titles[view])return;document.querySelectorAll('.view').forEach(function(x){x.classList.toggle('active',x.id===view)});document.querySelectorAll('[data-view]').forEach(function(x){x.classList.toggle('active',x.dataset.view===view)});$('pageTitle').innerHTML= view==='overview'?'Connect the signals.<br><span>Expose the scam.</span>':esc(titles[view][0]);$('pageSubtitle').textContent=titles[view][1];location.hash=view;if(view==='graph')drawGraph();if(view==='evidence')renderLedger()}
document.querySelectorAll('[data-view]').forEach(function(b){b.addEventListener('click',function(){nav(b.dataset.view)})});
document.querySelectorAll('[data-go]').forEach(function(b){b.addEventListener('click',function(){nav(b.dataset.go)})});
if(titles[location.hash.slice(1)])nav(location.hash.slice(1));
function fmtTime(t){return new Date(t).toLocaleString()}
function getTimestamp(){var v=$('eventTime').value;return v?new Date(v).getTime():Date.now()}
function extractEntities(text){
 var a=[], seen={};
 function add(type,value){value=String(value||'').trim().toLowerCase().replace(/[.,!?;:)]+$/,'');if(!value)return;var k=type+'|'+value;if(!seen[k]){seen[k]=1;a.push({type:type,value:value})}}
 (text.match(/https?:\/\/[^\s<>"']+|(?:www\.)[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s]*)?|\b[a-z0-9-]+\.(?:com|in|net|org|io|co|xyz|top|click|icu|example)\b(?:\/[^\s]*)?/ig)||[]).forEach(function(v){add('URL / domain',v.replace(/^https?:\/\//i,'').replace(/^www\./i,''))});
 (text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/ig)||[]).forEach(function(v){add('Email',v)});
 (text.match(/(?:\+?\d[\d ()-]{8,}\d)/g)||[]).forEach(function(v){var n=v.replace(/\D/g,'');if(n.length>=10&&n.length<=13)add('Phone',n)});
 (text.match(/\b[a-z0-9._-]{2,}@[a-z]{2,}\b/ig)||[]).forEach(function(v){if(!/^[^@]+@[^@]+\.[a-z]{2,}$/i.test(v))add('UPI ID',v)});
 return a;
}
function classifyStages(text){
 var t=text.toLowerCase(),out=[];
 var rules=[
 {name:'Impersonation / trust pretext',re:/\b(bank|sbi|hdfc|icici|axis|customer care|support team|police|customs|courier|government|official|account department)\b/},
 {name:'Urgency / pressure',re:/\b(urgent|immediately|today|within \d+|last warning|will be blocked|suspend(ed|ed)?|expire|final notice)\b/},
 {name:'URL / click action',re:/https?:\/\/|\bwww\.|\b[a-z0-9-]+\.(com|in|net|org|xyz|top|click|icu|example)\b/},
 {name:'Credential request',re:/\b(password|login|credentials|user id|pin|cvv|account verification|sign in)\b/},
 {name:'OTP / verification-code request',re:/\b(otp|one.time password|verification code|security code)\b/},
 {name:'Device / remote-access request',re:/\b(apk|install (this|the) app|remote access|screen share|anydesk|teamviewer)\b/},
 {name:'Payment / authorization action',re:/\b(upi|collect request|approve (the )?request|send money|transfer|payment|beneficiary|qr code|debit|credited)\b/}
 ];
 rules.forEach(function(r){if(r.re.test(t))out.push(r.name)});return out;
}
function singleScreen(text){
 var t=text.toLowerCase(),rules=[
 {re:/urgent|immediately|today|within \d+ hours|final warning|will be blocked|suspend|expire/,n:'Urgency or threat pressure',d:'Pressure language is present; inspect the sender and context.' ,w:18},
 {re:/otp|one.time password|password|pin|cvv|credentials|login|verify your kyc|account verification/,n:'Credential or secret-related language',d:'The text references sensitive account information or verification.',w:22},
 {re:/upi|collect request|approve.*request|send money|payment request|beneficiar|transfer/,n:'Payment or authorization language',d:'A financial action is referenced; no transaction has been verified.',w:18},
 {re:/https?:\/\/|www\.|\b[a-z0-9-]+\.(com|in|net|org|xyz|top|click|icu|example)\b/,n:'URL / domain present',d:'A URL was extracted; this does not mean its reputation was checked.',w:15},
 {re:/bank|customer care|support team|police|customs|courier|refund|prize|reward|official/,n:'Authority / reward pretext',d:'An authority or reward framing appears and should be independently verified.',w:10},
 {re:/apk|remote access|screen share|anydesk|teamviewer|install.*app/,n:'Device access or installation request',d:'The text references a potentially high-impact device action.',w:20}
 ],hits=[],score=8;
 rules.forEach(function(r){if(r.re.test(t)){hits.push({title:r.n,detail:r.d});score+=r.w}});
 if(!hits.length)hits.push({title:'No configured high-signal pattern found',detail:'This is not a safety verdict. The item may still be suspicious outside these rules.'});
 score=Math.min(94,score);
 return {score:score,level:score>=60?'HIGH INDICATOR':score>=32?'ELEVATED INDICATOR':'LOW SIGNAL',risk:score>=60?'high':score>=32?'mid':'low',signals:hits,method:'Local transparent phrase rules',advice:['Verify the sender through an independent official channel.','Never share OTPs, PINs or passwords with a caller or message sender.','Do not approve an unexpected payment or install an untrusted app.']};
}
function quickLocalCheck(text){
 var t=text.toLowerCase(),hits=[],score=8;
 function hit(test,title,detail,weight){if(test){hits.push({title:title,detail:detail});score+=weight}}
 hit(/urgent|immediately|today|blocked|suspend|expire|disconnect/.test(t),'Urgency or threat pressure','A deadline or threat may be pushing you to act quickly.',18);
 hit(/otp|one.time password|password|pin|cvv|credentials|login|kyc/.test(t),'Credential or secret-related language','The message refers to sensitive account information or verification codes.',22);
 hit(/upi|collect request|approve.*request|send money|payment request|beneficiar|transfer|refund/.test(t),'Payment or authorization request','A financial action is mentioned; no transaction has been verified.',18);
 hit(t.indexOf('http')>=0||t.indexOf('www.')>=0||t.indexOf('.com')>=0||t.indexOf('.in')>=0||t.indexOf('.net')>=0||t.indexOf('.org')>=0||t.indexOf('.xyz')>=0,'Link or domain present','A link is present, but this local check does not verify its reputation.',15);
 hit(/bank|customer care|support team|police|customs|courier|prize|reward|official/.test(t),'Authority or reward framing','Verify the claimed organisation or reward independently.',10);
 hit(/apk|remote access|screen share|anydesk|teamviewer|install.*app/.test(t),'Device access or installation request','The message references a high-impact device action.',20);
 if(!hits.length)hits.push({title:'No configured high-signal pattern found',detail:'This is not a safety verdict. Context and sender identity are not verified.'});
 score=Math.min(94,score);
 return {score:score,level:score>=60?'HIGH CONCERN':score>=32?'CHECK CAREFULLY':'NO STRONG SIGNAL FOUND',risk:score>=60?'high':score>=32?'mid':'low',signals:hits};
}
$('quickAnalyze').addEventListener('click',async function(){
 var text=$('quickText').value.trim();if(!text){toast('Paste a message to check first.');return}
 var r=quickLocalCheck(text),method='Local-only browser rules',extra='';
 $('quickAnalyze').disabled=true;$('quickAnalyze').textContent='Checking…';
 try{
  if($('quickConnect').checked){
   var resp=await fetch('/api/bridge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'analyze',payload:{text:text,type:$('quickChannel').value,context:'User-initiated ScamChain Quick Check'}})});
   var j=await resp.json();
   if(j.ok&&j.data){
    var x=j.data.result||j.data.analysis||j.data,ass=x.assessment||{},raw=Number(ass.risk_score!=null?ass.risk_score:(x.risk&&x.risk.score));
    if(Number.isFinite(raw)){r.score=Math.max(0,Math.min(100,raw));r.level=raw>=60?'HIGH CONCERN':raw>=32?'CHECK CAREFULLY':'LOWER SIGNAL';r.risk=raw>=60?'high':raw>=32?'mid':'low';}
    var sig=ass.signals||x.signals||(x.case&&x.case.signals)||[];
    if(sig.length)r.signals=sig.map(function(s){return {title:s.signal||s.title||s.name||'Backend signal',detail:s.evidence&&s.evidence.length?s.evidence.join('; '):(s.rationale||s.detail||('Signal domain: '+(s.domain||'not specified')))}}).slice(0,8);
    var chain=x.case&&x.case.attack_chain||x.attack_chain||[];
    if(chain.length)extra+='<div class="finding-group"><h4>Candidate attack-chain stages</h4>'+chain.map(function(s){return finding(String(s).replace(/_/g,' '),'Backend-generated candidate stage; not proof that the stage occurred.','?')}).join('')+'</div>';
    var gaps=ass.evidence_gaps||x.evidence_gaps||[];
    if(gaps.length)extra+='<div class="finding-group"><h4>Evidence still missing</h4>'+gaps.slice(0,5).map(function(g){return finding(g.stage||'Corroboration needed',g.request||'More evidence is needed to verify this stage.','!')}).join('')+'</div>';
    method='Connected ScamChain backend';
    if(ass.model_status==='synthetic_demo_model')extra+='<p class="fineprint"><b>Model disclosure:</b> the connected backend labels its classifier as a synthetic-demo model. Its score is not a calibrated real-world fraud probability.</p>';
   }else{extra='<p class="fineprint">Connected analysis did not return a usable result; local screening is shown instead.</p>'}
  }
 }catch(e){extra='<p class="fineprint">Connected service unavailable; local screening is shown instead.</p>'}
 finally{$('quickAnalyze').disabled=false;$('quickAnalyze').textContent='Check this message ↗'}
 latestQuickRisk=r.risk;$('quickResultTitle').textContent=r.level;$('quickRisk').textContent=r.level;$('quickRisk').className='risk-chip risk-'+r.risk;var helpTitle=$('victimHelpTitle'),helpText=$('victimHelpText');if(helpTitle&&helpText){if(r.risk==='high'){helpTitle.textContent='High concern indicators found — have you acted?';helpText.textContent='This is not proof of fraud or loss. Select what happened below to reveal the right response and any urgent contact options.';$('victimHelpPanel').classList.add('victim-help-alert')}else{helpTitle.textContent='Worried you may have been scammed?';helpText.textContent='Choose what happened to see the safest next step. A high indicator alone does not mean money was lost.';$('victimHelpPanel').classList.remove('victim-help-alert')}}
 var html='<p class="fineprint">Method: '+esc(method)+'. Indicator score: '+r.score+'/100. This is not a calibrated fraud probability and does not verify sender identity or URL reputation.</p><div class="finding-group"><h4>Why it was flagged</h4>'+r.signals.map(function(s){return finding(s.title,s.detail,'!')}).join('')+'</div><div class="finding-group"><h4>Safer next steps</h4>'+['Do not share OTPs, PINs or passwords.','Verify the sender using a number or app you find independently.','Do not approve an unexpected payment or install a remote-access app.'].map(function(s){return finding('Recommended action',s,'→')}).join('')+'</div>'+extra;
 $('quickResultBody').className='';$('quickResultBody').innerHTML=html;
});
function updateVictimHelp(){
 var action=$('victimAction').value, result=$('victimHelpResult'),call=$('call1930'),report=$('reportCybercrime'),title=$('victimHelpTitle'),copy=$('victimHelpText');
 var urgent=['money','shared','installed'].indexOf(action)>=0;
 call.classList.toggle('hidden',!urgent);report.classList.toggle('hidden',!urgent);
 if(action==='money'){
  title.textContent='Act quickly: a payment may be at risk';
  copy.textContent='If you sent money or approved a suspicious UPI request, contact your bank/payment provider through its official app or number and call 1930 promptly. Do not pay anyone promising recovery.';
  result.textContent='1. Call 1930 now if this is suspected financial cyber fraud. 2. Contact your bank/UPI app through official channels and ask them to secure the account or transaction. 3. Preserve transaction IDs, messages and screenshots. 4. File or update the official cybercrime report.';
 }else if(action==='shared'){
  title.textContent='Protect the exposed account now';
  copy.textContent='Sharing an OTP, PIN, password or bank details can expose an account, but loss is not confirmed. Use a trusted device and official bank/service channels immediately.';
  result.textContent='Change exposed passwords from a trusted device, ask the bank/service to secure sessions and payment methods, and inspect recent activity. If money was taken or financial fraud is suspected, call 1930 promptly. Never share another OTP with a caller.';
 }else if(action==='installed'){
  title.textContent='Stop possible remote access';
  copy.textContent='If you installed an unknown app or allowed screen sharing, treat the device and accounts as potentially exposed until checked.';
  result.textContent='Disconnect from the internet if remote control may still be active. Do not open banking apps on that device. From another trusted device, contact your bank if financial access may be exposed, remove the untrusted app safely, and preserve evidence. If money was lost or financial fraud is suspected, call 1930.';
 }else if(action==='clicked'){
  title.textContent='Clicked a link? Reduce further exposure';
  copy.textContent='A click alone does not prove your account was compromised. What you entered or installed matters.';
  result.textContent='Close the page. Do not download anything or enter more details. If you entered a password, change it from a trusted device; if you shared an OTP or bank details, choose that option above. Watch for bank alerts and preserve the message/link.';
 }else{
  title.textContent=latestQuickRisk==='high'?'High concern indicators found — have you acted?':'Worried you may have been scammed?';
  copy.textContent=latestQuickRisk==='high'?'A high indicator is not proof of fraud or loss. Choose the action you actually took to reveal tailored next steps.':'Choose what happened to see the safest next step. A suspicious message alone does not mean money was lost.';
  result.textContent='Do not reply, click further links, share codes or approve requests. Verify the sender independently through an official app, website or phone number you find yourself.';
 }
}
$('victimAction').addEventListener('change',updateVictimHelp);
updateVictimHelp();
function eventCard(e,i,remove){
 return '<article class="event-card"><div class="event-card-head"><span class="event-tag">EVENT '+String(i+1).padStart(2,'0')+'</span><span class="event-tag">'+esc(e.channel)+'</span><span class="event-time">'+esc(fmtTime(e.timestamp))+'</span>'+(remove?'<button class="remove-event" data-remove="'+esc(e.id)+'">Remove ×</button>':'')+'</div><div class="event-content">'+esc(e.text)+'</div>'+(e.ref?'<div class="event-ref">REF: '+esc(e.ref)+'</div>':'')+'</article>';
}
function renderEvents(){
 $('listCount').textContent=state.events.length+' EVENT'+(state.events.length===1?'':'S');
 $('eventCounter').textContent='EVENT '+String(state.events.length+1).padStart(2,'0');
 $('eventList').innerHTML=state.events.length?state.events.slice().sort(function(a,b){return a.timestamp-b.timestamp}).map(function(e,i){return eventCard(e,i,true)}).join(''):'<div class="empty-state">Your evidence records will appear here.</div>';
 updateMetrics();
}
function addEvent(data){
 var text=(data&&data.text)||$('eventText').value.trim();if(!text){toast('Enter evidence content first.');return}
 state.events.push({id:'EV-'+Date.now()+'-'+(++state.seq),channel:(data&&data.channel)||$('eventChannel').value,timestamp:(data&&data.timestamp)||getTimestamp(),text:text,ref:(data&&data.ref)||$('eventRef').value.trim()});
 if(!data){$('eventText').value='';$('eventRef').value=''}
 state.correlation=null;renderEvents();renderCorrelationEmpty();drawGraph();renderLedger();toast('Evidence event added. Re-correlate to refresh the storyline.');
}
$('addEvent').addEventListener('click',function(){addEvent()});
$('eventList').addEventListener('click',function(ev){var b=ev.target.closest('[data-remove]');if(!b)return;state.events=state.events.filter(function(x){return x.id!==b.dataset.remove});state.correlation=null;renderEvents();renderCorrelationEmpty();drawGraph();renderLedger()});
$('eventTime').value=new Date(Date.now()-new Date().getTimezoneOffset()*60000).toISOString().slice(0,16);
$('analyzeSingle').addEventListener('click',async function(){
 var text=$('eventText').value.trim();if(!text){toast('Enter evidence content first.');return}
 var r=singleScreen(text),source='Local-only browser rules';
 if($('useBackend').checked){
  try{var resp=await fetch('/api/bridge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'analyze',payload:{text:text,type:$('eventChannel').value,context:'Single-item screening from ScamChain Nexus'}})});var j=await resp.json();if(j.ok&&j.data){var x=j.data.result||j.data.analysis||j.data;var raw=Number((x.assessment&&x.assessment.risk_score)||x.risk_score||x.score);if(Number.isFinite(raw)){r.score=Math.max(0,Math.min(100,raw));r.level=r.score>=60?'HIGH INDICATOR':r.score>=32?'ELEVATED INDICATOR':'LOW SIGNAL';r.risk=r.score>=60?'high':r.score>=32?'mid':'low';source='Connected ScamChain backend';}}}catch(e){source='Local rules (connected backend unavailable)'}
 }
 $('singleResult').classList.remove('hidden');$('singleResult').innerHTML='<div class="event-card-head"><b>Single-item screening</b><span class="risk-chip risk-'+r.risk+'">'+esc(r.level)+'</span><span class="counter">'+r.score+'/100 indicator index</span></div><div class="fineprint">Method: '+esc(source)+'. This score is not a calibrated fraud probability.</div>'+r.signals.map(function(s){return '<div class="finding"><span class="finding-mark">!</span><div><b>'+esc(s.title)+'</b><small>'+esc(s.detail)+'</small></div></div>'}).join('')+'<div class="fineprint">A single item can be screened, but a multi-stage chain requires separate evidence events and corroboration.</div>';
});
$('resetCase').addEventListener('click',function(){state.events=[];state.analysis=null;state.correlation=null;renderEvents();renderCorrelationEmpty();drawGraph();renderLedger();toast('Case cleared.')});
function loadDemo(){
 var now=Date.now();state.events=[];
 [
 ['SMS / messaging','Fictional bank support message: Your KYC will expire today. Verify immediately at https://secure-kyc-check.example',now-1800000,'DEMO-01'],
 ['Web / URL','Fictional login page asks for account login, password and OTP at https://secure-kyc-check.example/login',now-1200000,'DEMO-02'],
 ['Support interaction','Fictional caller claims to be bank customer care and asks the recipient to share the verification code.',now-600000,'DEMO-03'],
 ['Payment / transaction event','Fictional follow-up asks the recipient to approve a UPI collect request and add a new beneficiary. No transaction record supplied.',now-120000,'DEMO-04']
 ].forEach(function(x){addEvent({channel:x[0],text:x[1],timestamp:x[2],ref:x[3]})});
 state.correlation=null;renderCorrelationEmpty();toast('Loaded four fictional events. No real URL or transaction was queried.');
}
$('loadDemo').addEventListener('click',function(){loadDemo();correlate();toast('Fictional case reconstructed. Select any timeline step to inspect its evidence.')});
function correlate(){
 if(!state.events.length){toast('Add evidence before correlating.');return}
 var ordered=state.events.slice().sort(function(a,b){return a.timestamp-b.timestamp});
 var entities={},stages={},perEvent=[],edges=[],gaps=[],indicators=[],score=8;
 ordered.forEach(function(e,i){
  var ents=extractEntities(e.text),ss=classifyStages(e.text);
  perEvent.push({event:e,entities:ents,stages:ss});
  ents.forEach(function(en){var k=en.type+'|'+en.value;if(!entities[k])entities[k]={type:en.type,value:en.value,events:[]};entities[k].events.push(i)});
  ss.forEach(function(s){if(!stages[s])stages[s]={name:s,events:[]};stages[s].events.push(i)});
 });
 var shared=Object.keys(entities).map(function(k){return entities[k]}).filter(function(x){return x.events.length>1});
 shared.forEach(function(x){edges.push({kind:'shared',from:x.events[0],to:x.events[x.events.length-1],label:x.type+': '+x.value})});
 var stageList=Object.keys(stages).map(function(k){return stages[k]});
 var joined=ordered.map(function(e){return e.channel+' '+e.text}).join(' ');
 var one=singleScreen(joined);indicators=one.signals.slice();score=Math.min(95,8+indicators.length*8+shared.length*12+Math.max(0,stageList.length-1)*4+(ordered.length>1?6:0));
 var times=[];for(var i=1;i<ordered.length;i++){times.push({from:ordered[i-1].timestamp,to:ordered[i].timestamp,seconds:Math.max(0,Math.round((ordered[i].timestamp-ordered[i-1].timestamp)/1000))})}
 if(!shared.length)gaps.push({title:'No exact shared entity found',detail:'No URL, email, or phone value repeats across events. Other relationships are not assumed.'});
 if(ordered.length<2)gaps.push({title:'Insufficient event count',detail:'A single event cannot establish a multi-stage attack chain. Add separate corroborating evidence.'});
 if(!ordered.some(function(e){return /transaction id|transaction reference|debited|credited|bank statement|transaction record/i.test(e.text)}))gaps.push({title:'Financial outcome unverified',detail:'No corroborating transaction record was supplied. Do not infer that funds moved.'});
 if(!ordered.some(function(e){return e.timestamp}))gaps.push({title:'Timestamp uncertainty',detail:'Add reliable timestamps; event order alone does not establish causality.'});
 if(!stageList.length)gaps.push({title:'No candidate attack stages found',detail:'Configured phrase rules found no known stage. Absence of a match does not establish safety.'});
 state.correlation={ordered:ordered,entities:Object.keys(entities).map(function(k){return entities[k]}),shared:shared,stages:stageList,times:times,edges:edges,gaps:gaps,indicators:indicators,score:score,level:score>=60?'HIGH INDICATOR':score>=32?'ELEVATED INDICATOR':'LOW SIGNAL',risk:score>=60?'high':score>=32?'mid':'low',method:'Exact entity overlap + timestamp ordering + transparent phrase rules'};
 renderCorrelation();drawGraph();renderLedger();updateMetrics();nav('graph');toast('Correlation complete. Inferred stages remain hypotheses.');
}
$('correlate').addEventListener('click',correlate);
function renderCorrelationEmpty(){$('correlationBadge').textContent='NOT RUN';$('correlationOutput').className='empty-state';$('correlationOutput').textContent='Add two or more evidence items for a meaningful cross-event correlation. A single event can still be screened, but it cannot establish a multi-stage chain.';var so=$('storylineOutput');if(so){so.className='empty-state';so.textContent='Correlation is out of date. Select Correlate & reconstruct to rebuild the storyline.'}$('storyStatus').textContent='AWAITING CORRELATION';var tt=$('threatTreeOutput');if(tt){tt.className='threat-tree-output';tt.innerHTML='<div class="empty-state">Evidence changed. Re-correlate to rebuild the threat tree.</div>'}$('threatTreeStatus').textContent='AWAITING CORRELATION';updateMetrics()}
function finding(title,detail,mark){return '<div class="finding"><span class="finding-mark">'+(mark||'•')+'</span><div><b>'+esc(title)+'</b><small>'+esc(detail)+'</small></div></div>'}
function treeMitigation(name){
 var s=String(name||'').toLowerCase();
 if(/impersonation|trust/.test(s))return 'Break the trust step: verify the organisation using its official app, website or a number you sourced independently.';
 if(/urgency|pressure/.test(s))return 'Break the pressure step: pause. A deadline is not a reason to bypass verification.';
 if(/url|click/.test(s))return 'Break the link step: do not enter details. Navigate to the official service yourself instead of using the message link.';
 if(/credential|otp|verification|password|pin/.test(s))return 'Protect account access: never share OTPs, PINs or passwords. If shared, contact the bank or service through official channels immediately.';
 if(/device|remote/.test(s))return 'Stop remote access: disconnect the device from the network if remote control may be active, remove the untrusted app safely, and contact the bank from another trusted device if accounts may be exposed.';
 if(/payment|beneficiar|upi|transaction/.test(s))return 'Break the money step: do not approve a request to receive money. If you sent money or approved a suspicious payment, contact your bank and call India cyber-fraud helpline 1930 promptly.';
 return 'Verify independently and preserve the original message, sender details and timestamps. Do not assume this stage occurred without corroborating evidence.';
}
function renderThreatTree(c){
 var out=$('threatTreeOutput');if(!out)return;
 if(!c||!c.ordered||!c.ordered.length){out.innerHTML='<div class="empty-state">No correlated evidence. Add events and select Correlate & reconstruct.</div>';$('threatTreeStatus').textContent='NOT BUILT';return}
 var stages=(c.stages||[]).slice().sort(function(a,b){return Math.min.apply(null,a.events)-Math.min.apply(null,b.events)});
 var branches=stages.map(function(st,i){
  var evs=st.events.map(function(idx){return {event:c.ordered[idx],index:idx}}).filter(function(x){return !!x.event});
  var shared=(c.shared||[]).filter(function(en){return en.events.some(function(idx){return st.events.indexOf(idx)>=0})});
  return {stage:st.name,events:evs,shared:shared,idx:i,first:evs.length?evs[0].index:999};
 });
 var covered={};branches.forEach(function(b){b.events.forEach(function(e){covered[e.index]=true})});
 var unclassified=c.ordered.map(function(e,i){return {event:e,index:i}}).filter(function(e){return !covered[e.index]});
 var html='<div class="threat-tree-root"><span class="tree-node-kicker">ROOT · CASE HYPOTHESIS</span><b>Possible multi-stage scam workflow</b><small>'+c.ordered.length+' evidence events · '+branches.length+' candidate stage branches · '+c.shared.length+' exact shared entities</small><p>This tree maps observed clues to possible stages. Branch order is based on timestamps and does not prove causation or attacker intent.</p></div><div class="tree-trunk" aria-hidden="true"></div><div class="threat-tree-branches">';
 branches.forEach(function(b){
  var evText=b.events.length?b.events.map(function(x){return 'E'+String(x.index+1).padStart(2,'0')}).join(', '):'No linked event';
  var support=b.events.length+' matching event'+(b.events.length===1?'':'s')+' · '+b.shared.length+' shared-entity link'+(b.shared.length===1?'':'s');
  html+='<article class="tree-branch"><div class="tree-connector" aria-hidden="true"></div><button type="button" class="tree-branch-button" data-tree-stage="'+b.idx+'"><span class="tree-branch-num">STAGE '+String(b.idx+1).padStart(2,'0')+'</span><b>'+esc(b.stage)+'</b><span class="tree-support">'+esc(support)+'</span><span class="tree-branch-refs">Evidence: '+esc(evText)+'</span><span class="tree-click-hint">Inspect evidence ↓</span></button><div class="tree-branch-detail hidden" id="treeBranchDetail'+b.idx+'"><p class="tree-mitigation"><b>Defensive breakpoint:</b> '+esc(treeMitigation(b.stage))+'</p>'+b.events.map(function(x){return '<div class="tree-evidence"><b>E'+String(x.index+1).padStart(2,'0')+' · '+esc(x.event.channel)+'</b><small>'+esc(fmtTime(x.event.timestamp))+' · '+esc(x.event.ref||x.event.id||'no reference')+'</small><p>'+esc(x.event.text)+'</p></div>'}).join('')+(b.shared.length?'<div class="tree-shared-note"><b>Concrete overlap to inspect:</b> '+b.shared.map(function(x){return esc(x.type+': '+x.value)}).join(' · ')+'</div>':'<div class="tree-shared-note">No exact shared entity attached to this branch. This stage is a phrase-rule match only.</div>')+'</div></article>';
 });
 if(unclassified.length){html+='<article class="tree-branch tree-unclassified"><div class="tree-connector" aria-hidden="true"></div><button type="button" class="tree-branch-button" data-tree-stage="unclassified"><span class="tree-branch-num">REVIEW BRANCH</span><b>Evidence not mapped to a configured stage</b><span class="tree-support">'+unclassified.length+' event(s) · no matching stage rule</span><span class="tree-branch-refs">Evidence: '+unclassified.map(function(x){return 'E'+String(x.index+1).padStart(2,'0')}).join(', ')+'</span><span class="tree-click-hint">Inspect evidence ↓</span></button><div class="tree-branch-detail hidden" id="treeBranchDetailUnclassified"><p class="tree-mitigation">Do not interpret the lack of a rule match as evidence of safety. Review context and add corroborating evidence.</p>'+unclassified.map(function(x){return '<div class="tree-evidence"><b>E'+String(x.index+1).padStart(2,'0')+' · '+esc(x.event.channel)+'</b><small>'+esc(fmtTime(x.event.timestamp))+' · '+esc(x.event.ref||x.event.id||'no reference')+'</small><p>'+esc(x.event.text)+'</p></div>'}).join('')+'</div></article>'}
 html+='</div><div class="tree-outcome"><span class="tree-node-kicker">LEAF · POTENTIAL IMPACT TO VERIFY</span><b>Account exposure or financial loss — unconfirmed</b><p>'+esc((c.gaps||[]).some(function(g){return /financial outcome/i.test(g.title)})?'No transaction record was supplied. Verify with the bank or official account activity; this case does not prove money moved.':'Check independent bank/account records before concluding that access or money was affected.')+'</p><div class="tree-leaf-actions"><span>PREVENT: pause · verify · protect codes</span><span>IF MONEY WAS SENT: contact bank + call 1930</span></div></div><p class="tree-disclaimer">Branch support is evidence coverage, not a likelihood percentage. A stage match means configured words were found; it does not prove the action happened.</p>';
 out.className='threat-tree-output';out.innerHTML=html;
 $('threatTreeStatus').textContent=branches.length+' BRANCHES · '+unclassified.length+' REVIEW EVENTS';
}
$('threatTreeOutput').addEventListener('click',function(ev){
 var b=ev.target.closest('[data-tree-stage]');if(!b)return;
 var key=b.dataset.treeStage,detail=$('treeBranchDetail'+key.charAt(0).toUpperCase()+key.slice(1));
 if(!detail&&key!=='unclassified')detail=$('treeBranchDetail'+key);
 if(!detail)return;
 var opening=detail.classList.contains('hidden');
 document.querySelectorAll('.tree-branch-detail').forEach(function(x){x.classList.add('hidden')});
 document.querySelectorAll('.tree-branch-button').forEach(function(x){x.setAttribute('aria-expanded','false')});
 if(opening){detail.classList.remove('hidden');b.setAttribute('aria-expanded','true')}
});
function renderCorrelation(){
 var c=state.correlation;if(!c)return;
 $('correlationBadge').textContent=c.shared.length+' SHARED ENTITIES';
 var html='<div class="event-card-head"><span class="risk-chip risk-'+c.risk+'">'+esc(c.level)+'</span><span class="counter">INDICATOR INDEX '+c.score+'/100</span><span class="counter">'+c.ordered.length+' EVENTS</span></div><p class="fineprint">Transparent prototype index—not a calibrated fraud probability. Method: '+esc(c.method)+'.</p>';
 html+='<div class="finding-group"><h4>Correlated timeline</h4>'+c.ordered.map(function(e,i){return finding(String(i+1).padStart(2,'0')+' · '+e.channel,fmtTime(e.timestamp)+' — '+(classifyStages(e.text)[0]||'Evidence event')+' — '+e.text,'→')}).join('')+'</div>';
 html+='<div class="finding-group"><h4>Shared entities ('+c.shared.length+')</h4>'+(c.shared.length?c.shared.map(function(x){return finding(x.type,x.value+' · appears in '+x.events.length+' evidence items','↔')}).join(''):finding('No exact repeated entities','No exact URL, email or phone value was found across the submitted events.','—'))+'</div>';
 html+='<div class="finding-group"><h4>Candidate stages ('+c.stages.length+')</h4>'+(c.stages.length?c.stages.map(function(x){return finding(x.name,'Rule-derived hypothesis; appears in '+x.events.length+' event(s). This does not prove the stage occurred.','?')}).join(''):finding('No candidate stages','No configured phrase rule matched.','—'))+'</div>';
 html+='<div class="finding-group"><h4>Evidence gaps / corroboration needed</h4>'+c.gaps.map(function(g){return finding(g.title,g.detail,'!')}).join('')+'</div>';
 $('correlationOutput').className='';$('correlationOutput').innerHTML=html;
 $('overviewSnapshot').className='';$('overviewSnapshot').innerHTML='<div class="event-card-head"><span class="risk-chip risk-'+c.risk+'">'+esc(c.level)+'</span><span class="counter">'+c.ordered.length+' EVENTS</span></div>'+finding('Shared entities',String(c.shared.length)+' exact repeated entity values','↔')+finding('Candidate stages',String(c.stages.length)+' rule-derived stage labels','?')+finding('Evidence gaps',String(c.gaps.length)+' unresolved corroboration items','!');
 $('activeCase').textContent='CASE SC-'+String(c.ordered.length).padStart(3,'0');
 renderStoryline(c);renderThreatTree(c);
}
function explainStage(name,text){
 var s=(name+' '+text).toLowerCase();
 if(/impersonation|trust pretext/.test(s))return 'The first message or contact claims a trusted role. This establishes the story the sender wants the recipient to believe; it does not verify who sent it.';
 if(/urgency|pressure/.test(s))return 'The wording adds a deadline or threat. That pressure can reduce the time available to verify the request.';
 if(/url|click action/.test(s))return 'A link is present in the evidence. The page reputation has not been checked here; the link may be the bridge from the message to a data-collection step.';
 if(/credential request/.test(s))return 'The text refers to login details or account secrets. If a user enters them on an unverified page, account access could be exposed; this case does not prove anyone entered them.';
 if(/otp|verification-code/.test(s))return 'A one-time code or verification secret is mentioned. Sharing it can allow an attacker to complete an action, but this evidence alone does not show that a code was shared.';
 if(/device|remote-access/.test(s))return 'The evidence points to installing software or granting device access. If followed, this could expose messages or accounts; no device compromise is confirmed.';
 if(/payment|authorization/.test(s))return 'A payment or authorization action is mentioned. The request may be the intended financial step, but a real payment requires an authoritative transaction record.';
 return 'This event contributes context. Its role in the wider sequence remains uncertain until it is corroborated.';
}
function likelyNextRisk(c,last){
 var s=last.stages.join(' ').toLowerCase(),t=last.event.text.toLowerCase();
 if(/payment|authorization/.test(s)||/upi|collect request|beneficiar|transfer|payment/.test(t))return {title:'Possible next risk to watch: financial loss',detail:'Check for a transaction ID, debit/credit entry and recipient details. The current case does not confirm that money moved.'};
 if(/otp|credential/.test(s)||/otp|password|pin|login/.test(t))return {title:'Possible next risk to watch: account misuse',detail:'Look for independently verified sign-in alerts, session changes or bank notifications. Do not infer account access from a request alone.'};
 if(/device|remote-access/.test(s)||/anydesk|teamviewer|remote access|screen share|apk/.test(t))return {title:'Possible next risk to watch: device or account exposure',detail:'Seek evidence of installation or an active remote session. A request to install an app is not proof it was installed.'};
 if(/url|click action/.test(s)||/https?:\/\/|www\./.test(t))return {title:'Possible next risk to watch: data capture',detail:'Check whether the recipient opened the page or entered information. A URL in a message does not prove the page was visited.'};
 return {title:'Possible next risk to watch: follow-up escalation',detail:'Verify the claimed identity independently and watch for a request for money, codes, account details or device access.'};
}
function renderStoryline(c){
 var out=$('storylineOutput');if(!out)return;
 $('storyStatus').textContent=c.ordered.length+' EVENTS · '+c.stages.length+' STAGE TYPES';
 var steps=c.ordered.map(function(e,i){
  var ss=classifyStages(e.text),idx=c.ordered.indexOf(e),linked=c.shared.filter(function(en){return en.events.indexOf(idx)>=0}),when=fmtTime(e.timestamp);
  var role=i===0?'START · FIRST RECORDED CONTACT':i===c.ordered.length-1?'LATEST OBSERVED EVENT':'MIDDLE · POSSIBLE ESCALATION';
  var relation=i===0?'This is the earliest event in the submitted timeline.':linked.length?'This event shares '+linked.map(function(x){return x.type+' “'+x.value+'”'}).join(', ')+' with other event(s), providing a concrete link to inspect.':'This event follows the previous timestamp, but no exact shared entity links them. Treat the relationship as a hypothesis, not proof.';
  return '<article class="story-step"><div class="story-rail"><span class="story-number">'+String(i+1).padStart(2,'0')+'</span><span class="story-line"></span></div><div class="story-card"><div class="story-card-top"><span class="story-role">'+role+'</span><time>'+esc(when)+'</time></div><h4>'+esc(ss[0]||'Evidence event · role not classified')+'</h4><p>'+esc(explainStage(ss[0]||'',e.text))+'</p><div class="story-evidence"><b>Observed evidence</b><span>'+esc(e.channel)+' · '+esc(e.ref||e.id||'no reference supplied')+'</span><blockquote>'+esc(e.text)+'</blockquote></div><div class="story-link-note"><b>'+(i===0?'Why it starts here':'How it connects')+'</b><span>'+esc(relation)+'</span></div>'+(ss.length>1?'<div class="story-tags">'+ss.slice(1).map(function(s){return '<span>'+esc(s)+'</span>'}).join('')+'</div>':'')+'</div></article>';
 }).join('');
 var first=c.ordered[0],last=c.ordered[c.ordered.length-1],next=likelyNextRisk(c,c.perEvent?c.perEvent[c.perEvent.length-1]:{event:last,stages:classifyStages(last.text)}),sharedNote=c.shared.length?'Exact overlap found for '+c.shared.map(function(x){return x.type+': '+x.value}).join('; ')+'.':'No exact repeated URL, email or phone entity was found. The order is chronological only; common ownership or causality is not established.';
 var gapHtml=c.gaps.map(function(g){return '<li><b>'+esc(g.title)+'</b> — '+esc(g.detail)+'</li>'}).join('');
 out.innerHTML='<div class="story-summary-grid"><article><small>WHERE IT STARTS</small><b>'+esc(classifyStages(first.text)[0]||first.channel)+'</b><p>Earliest submitted evidence · '+esc(fmtTime(first.timestamp))+'</p></article><article><small>WHERE IT CURRENTLY ENDS</small><b>'+esc(classifyStages(last.text)[0]||last.channel)+'</b><p>Latest submitted evidence · '+esc(fmtTime(last.timestamp))+'</p></article><article><small>WHAT LINKS THE EVENTS</small><b>'+c.shared.length+' exact shared entities</b><p>'+esc(sharedNote)+'</p></article></div><div class="story-flow">'+steps+'</div><div class="story-next"><div class="eyebrow">FORWARD-LOOKING RISK · NOT A PREDICTION</div><h4>'+esc(next.title)+'</h4><p>'+esc(next.detail)+'</p></div><div class="story-gaps"><h4>What we still cannot claim</h4><ul>'+gapHtml+'</ul><p>Chronological order describes when evidence was recorded. It does not prove one event caused another. The chain is a reviewable hypothesis, not a verified accusation.</p></div>';
}
function updateMetrics(){
 var c=state.correlation;$('metricEvents').textContent=String(state.events.length).padStart(2,'0');$('metricEntities').textContent=String(c?c.shared.length:0).padStart(2,'0');$('metricStages').textContent=String(c?c.stages.length:0).padStart(2,'0');$('metricStatus').textContent=c?'Correlated':'Ready';
 if(!c){$('overviewSnapshot').className='empty-state';$('overviewSnapshot').textContent=state.events.length?'Evidence collected. Correlate the case to see the investigation snapshot.':'No evidence has been added. Start a case or load the fictional example.';$('activeCase').textContent=state.events.length?'CASE IN PROGRESS':'NO ACTIVE CASE'}
}
function svgEl(tag,attrs,text){var e=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.keys(attrs||{}).forEach(function(k){e.setAttribute(k,attrs[k])});if(text!=null)e.textContent=text;return e}
function drawGraph(){
 var svg=$('caseGraph');while(svg.firstChild)svg.removeChild(svg.firstChild);var c=state.correlation;
 if(!c||!c.ordered.length){svg.appendChild(svgEl('text',{x:500,y:245,'text-anchor':'middle',fill:'#8192ac','font-size':'15'},'Correlate evidence to construct the case graph'));$('graphSummary').textContent='No case correlated yet. Add evidence to generate a case-linked graph.';$('nodeInspector').textContent='Select a graph node to inspect its provenance.';$('timeline').innerHTML='<div class="empty-state">No timeline available.</div>';return}
 var nodes=[],edges=[],n=c.ordered.length,centerY=250,left=95,right=905,spacing=n>1?(right-left)/(n-1):0;
 c.ordered.forEach(function(e,i){nodes.push({id:'event-'+i,type:'event',x:n===1?500:left+i*spacing,y:145,label:'EVENT '+(i+1),sub:e.channel,desc:e.text,source:fmtTime(e.timestamp)})});
 c.shared.forEach(function(en,j){var x=180+(j%4)*210,y=340+Math.floor(j/4)*78;nodes.push({id:'entity-'+j,type:'entity',x:x,y:y,label:en.type,sub:en.value,desc:'Exact entity value repeated across evidence items '+en.events.map(function(i){return i+1}).join(', '),source:'Exact string overlap'});en.events.forEach(function(i){edges.push({from:'event-'+i,to:'entity-'+j,kind:'shared'})})});
 c.stages.forEach(function(st,j){var x=120+(j%4)*245,y=45+Math.floor(j/4)*55;nodes.push({id:'stage-'+j,type:'stage',x:x,y:y,label:'CANDIDATE STAGE',sub:st.name,desc:'Rule-based hypothesis from phrase matches in evidence items '+st.events.map(function(i){return i+1}).join(', '),source:'Inferred · deterministic phrase rule'});st.events.forEach(function(i){edges.push({from:'event-'+i,to:'stage-'+j,kind:'inferred'})})});
 nodes.forEach(function(a){if(a.type==='event'){var nxt=nodes.find(function(b){return b.type==='event'&&Number(b.id.split('-')[1])===Number(a.id.split('-')[1])+1});if(nxt)edges.push({from:a.id,to:nxt.id,kind:'sequence'})}});
 var byId={};nodes.forEach(function(x){byId[x.id]=x});
 edges.forEach(function(e){var a=byId[e.from],b=byId[e.to];if(!a||!b)return;svg.appendChild(svgEl('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,class:'graph-edge '+(e.kind==='shared'?'shared':e.kind==='inferred'?'inferred':'')}))});
 nodes.forEach(function(nd){var g=svgEl('g',{class:'graph-node '+nd.type,tabindex:'0',role:'button','aria-label':nd.label+' '+nd.sub});g.appendChild(svgEl('circle',{cx:nd.x,cy:nd.y,r:nd.type==='event'?31:nd.type==='entity'?25:23}));g.appendChild(svgEl('text',{x:nd.x,y:nd.y-2},nd.label.length>20?nd.label.slice(0,19)+'…':nd.label));g.appendChild(svgEl('text',{x:nd.x,y:nd.y+12,class:'node-sub'},nd.sub.length>24?nd.sub.slice(0,23)+'…':nd.sub));function inspect(){ $('nodeInspector').innerHTML='<b>'+esc(nd.label)+'</b><br>'+esc(nd.sub)+'<br><span class="muted">'+esc(nd.source)+'</span><br>'+esc(nd.desc)}g.addEventListener('click',inspect);g.addEventListener('keydown',function(ev){if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();inspect()}});svg.appendChild(g)});
 $('graphSummary').textContent=nodes.length+' nodes · '+edges.length+' links · inferred links are dashed';
 $('timeline').innerHTML=c.ordered.map(function(e,i){return '<div class="timeline-item"><span class="timeline-dot"></span><div><b>'+String(i+1).padStart(2,'0')+' · '+esc(e.channel)+'</b><small>'+esc(fmtTime(e.timestamp))+'</small><p>'+esc(e.text)+'</p></div></div>'}).join('');
}
function renderLedger(){
 var c=state.correlation;
 $('ledgerCount').textContent=state.events.length+' ITEMS';
 $('ledgerEvents').innerHTML=state.events.length?state.events.slice().sort(function(a,b){return a.timestamp-b.timestamp}).map(function(e,i){return eventCard(e,i,false)}).join(''):'<div class="empty-state">No evidence records yet.</div>';
 if(!c){$('riskReasoning').className='empty-state';$('riskReasoning').textContent='Correlate evidence to see the case reasoning.';return}
 $('riskReasoning').className='';$('riskReasoning').innerHTML='<div class="event-card-head"><span class="risk-chip risk-'+c.risk+'">'+esc(c.level)+'</span><span class="counter">'+c.score+'/100 INDEX</span></div><p class="fineprint">The score is an illustrative index derived from configured rule matches, repeated entities and candidate stages. It is not a probability of fraud.</p><div class="finding-group"><h4>Supporting indicators</h4>'+c.indicators.map(function(s){return finding(s.title,s.detail,'!')}).join('')+'</div><div class="finding-group"><h4>Stage provenance</h4>'+c.stages.map(function(s){return finding(s.name,'INFERRED from configured phrase rules. Matching text is visible in the evidence list.','?')}).join('')+'</div><div class="finding-group"><h4>Missing evidence</h4>'+c.gaps.map(function(g){return finding(g.title,g.detail,'!')}).join('')+'</div><div class="finding-group"><h4>Recommended handling</h4>'+['Verify claimed identities independently.','Do not share secrets or approve unexpected payment requests.','Corroborate financial outcomes with an authoritative transaction record.','Require human review before taking consequential action.'].map(function(s){return finding('Next step',s,'→')}).join('')+'</div>';
}
$('exportCase').addEventListener('click',function(){
 var payload={product:'ScamChain',team:'Beyond Binary',exported_at:new Date().toISOString(),case_status:state.correlation?'correlated':'evidence_intake',events:state.events.map(function(e){return {id:e.id,channel:e.channel,timestamp:new Date(e.timestamp).toISOString(),reference:e.ref||null,text:e.text}}),correlation:state.correlation?{score_index:state.correlation.score,score_is_probability:false,level:state.correlation.level,method:state.correlation.method,entities:state.correlation.entities,shared_entities:state.correlation.shared,candidate_stages:state.correlation.stages,evidence_gaps:state.correlation.gaps,temporal_intervals:state.correlation.times}:null,limitations:['Rule-based prototype; not trained-model inference in browser.','No live URL reputation or external threat-intelligence verification.','Exact overlap does not establish ownership or causality.','No transaction is verified unless corroborating evidence is supplied.']};
 var blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='scamchain-case.json';a.click();setTimeout(function(){URL.revokeObjectURL(url)},1000);toast('Case JSON exported.');
});
function renderHealth(){fetch('/api/bridge?action=health').then(function(r){return r.json()}).then(function(j){$('serviceStatus').textContent=j.ok?'Connected backend available':'Local engine ready'}).catch(function(){$('serviceStatus').textContent='Local engine ready'})}
renderHealth();renderEvents();renderLedger();drawGraph();
function setupTour(){
 var steps=[
  {view:'overview',target:'.hero-copy',title:'Welcome to ScamChain',text:'ScamChain is a guided scam-investigation prototype by Beyond Binary. It helps you check a suspicious message, collect separate pieces of evidence, and review how those pieces may fit into a sequence. It does not silently monitor your phone, SMS, calls, WhatsApp or banking apps.'},
  {view:'overview',target:'.victim-help-panel',title:'First: get help if this is happening now',text:'If you think you are currently being targeted, stop interacting and verify the sender through a separate official channel. Choose what happened in this dashboard panel to reveal relevant steps. If money may have been lost in India, call 1930 promptly and contact your bank or UPI provider. The call button opens your device dialler; it does not place a call automatically.'},
  {view:'quickcheck',target:'#quickcheck .quickcheck-layout',title:'1. Quick Check — screen one message',text:'Paste the suspicious text and choose its channel, then select Check this message. Local phrase rules run in this browser and show the indicators they matched. They are screening clues, not proof that something is a scam or safe. Keep passwords, OTPs, full account numbers and private unrelated details out of the text.'},
  {view:'quickcheck',target:'#quickConnect',title:'2. Understand the privacy switch',text:'Connected analysis is OFF unless you opt in. If you turn it on, the message text is sent to the ScamChain backend for this request. The connected classifier currently identifies itself as a synthetic-demo model; do not treat its output as a validated real-world fraud verdict. You can use local screening without sending the text.'},
  {view:'intake',target:'.form-panel',title:'3. Evidence intake — one event per record',text:'Add each message, URL, call or payment-related event as a separate record. Set the source channel and observed time; add a reference if you have one. Use fictional or redacted details. Never record secrets such as an OTP, PIN, password or full account number. Screen this item for a single-event review, or add it to the case.'},
  {view:'intake',target:'.correlate-footer',title:'4. Correlate only after collecting evidence',text:'When you have multiple relevant records, choose Correlate & reconstruct. ScamChain orders the records by timestamp, checks configured phrase rules and looks for exact repeated entities such as URLs or email addresses. With only one event, it can screen that item but cannot establish a multi-stage chain.'},
  {view:'graph',target:'.storyline-panel',title:'5. Reconstructed storyline — follow the timeline',text:'Read from the earliest submitted event to the latest. Each card shows the original evidence, its timestamp, a candidate stage and the reason it may matter. Shared exact strings are concrete overlaps to inspect; when no shared entity exists, the timeline is chronology only. Time order does not prove that one event caused another.'},
  {view:'graph',target:'.threat-tree-panel',title:'6. Threat tree — root, branches, evidence',text:'The root is the overall suspected workflow. Each branch is a candidate stage matched by configured phrase rules; select a branch to open its supporting records and defensive breakpoint. The leaf outcome remains unconfirmed unless authoritative evidence supports it. Branch counts show evidence coverage, not probability, and a phrase match does not prove the action occurred.'},
  {view:'evidence',target:'.ledger-grid',title:'7. Evidence ledger — separate fact from inference',text:'Use the ledger to inspect the original records, supporting indicators and evidence gaps. “Observed” means present in submitted content; “linked” means an exact entity value repeats; “inferred” means a rule suggested a candidate stage. The displayed score is an illustrative index, not a calibrated chance of fraud. Review the underlying evidence before making decisions.'},
  {view:'simulator',target:'.sim-layout',title:'8. Simulation Lab — practise safely',text:'Choose a fictional scenario, then interact with the mock phone, message, browser or payment screen. The lab demonstrates the kind of warning and safer next step ScamChain is designed to explain. These scenarios are scripted examples; links do not open real websites and no real payment or report is submitted.'},
  {view:'simulator',target:'.recovery-panel',title:'9. Recovery Guide — choose what happened',text:'If you clicked a link, shared a secret, installed an app or sent money, choose the matching option to see a tailored checklist. Contact your bank or payment provider using official details, preserve messages and transaction references, and avoid anyone asking for a fee to recover money. In India, call 1930 promptly if financial fraud may have occurred; use cybercrime.gov.in for reporting. This guide does not contact your bank or submit a report.'},
  {view:'overview',target:'.bottom-grid',title:'10. Know the boundaries — then investigate',text:'ScamChain is a review aid, not an authority that declares guilt or guarantees safety. The current browser workflow uses transparent rules and scripted examples; it does not represent live URL reputation checks, continuous device monitoring or validated trained-model inference. Treat warnings seriously, verify independently, and require human review before consequential action. You can restart this tour anytime with Help tour.'}
 ];var idx=0,overlay=$('tourOverlay'),spot=$('tourSpotlight'),card=overlay.querySelector('.tour-card'),active=false;
 function close(){active=false;overlay.classList.add('hidden');overlay.setAttribute('aria-hidden','true');document.body.classList.remove('tour-open');document.querySelectorAll('.tour-target').forEach(function(e){e.classList.remove('tour-target')});try{localStorage.setItem('scamchainTourSeen','1')}catch(e){}}
 function show(){var s=steps[idx];nav(s.view);document.querySelectorAll('.tour-target').forEach(function(e){e.classList.remove('tour-target')});var target=document.querySelector(s.target);if(target){target.classList.add('tour-target');target.scrollIntoView({behavior:'auto',block:'center',inline:'nearest'});var r=target.getBoundingClientRect(),pad=7;spot.style.left=Math.max(6,r.left-pad)+'px';spot.style.top=Math.max(6,r.top-pad)+'px';spot.style.width=Math.min(window.innerWidth-12,r.width+pad*2)+'px';spot.style.height=Math.min(window.innerHeight-12,r.height+pad*2)+'px';spot.style.display='block';}else{spot.style.display='none'}
 $('tourTitle').textContent=s.title;$('tourText').textContent=s.text;$('tourCount').textContent='STEP '+(idx+1)+' OF '+steps.length;$('tourProgressBar').style.width=((idx+1)/steps.length*100)+'%';$('tourBack').disabled=idx===0;$('tourNext').textContent=idx===steps.length-1?'Finish ✓':'Next →';$('tourSkip').textContent=idx===steps.length-1?'Close tour':'Skip tour';
 var tr=card.getBoundingClientRect(),targetRect=target?target.getBoundingClientRect():null,gap=16,cardW=Math.min(window.innerWidth-24,window.innerWidth<700?360:480);card.style.width=cardW+'px';card.style.left='auto';card.style.right='16px';card.style.bottom='auto';if(window.innerWidth<700){card.style.left='12px';card.style.right='12px';card.style.width='auto';if(targetRect&&targetRect.top+targetRect.height/2<window.innerHeight/2){card.style.top='auto';card.style.bottom='12px';}else{card.style.top='12px';card.style.bottom='auto';}}else{var cardH=Math.min(tr.height,window.innerHeight-32),placeTop=targetRect&&targetRect.top+targetRect.height/2>window.innerHeight/2?16:Math.max(16,window.innerHeight-cardH-16);if(targetRect&&placeTop<targetRect.bottom+gap&&placeTop+cardH>targetRect.top-gap){placeTop=targetRect.top>window.innerHeight-targetRect.bottom?16:Math.max(16,window.innerHeight-cardH-16);}card.style.top=Math.max(16,Math.min(window.innerHeight-cardH-16,placeTop))+'px';card.style.bottom='auto';}}
 function start(){idx=0;active=true;overlay.classList.remove('hidden');overlay.setAttribute('aria-hidden','false');document.body.classList.add('tour-open');show();$('tourNext').focus();}
 $('tourNext').addEventListener('click',function(){if(idx<steps.length-1){idx++;show()}else{close();try{localStorage.setItem('scamchainTourSeen','1')}catch(e){}toast('Tour complete. You can restart it with Help tour.')}});
 $('tourBack').addEventListener('click',function(){if(idx>0){idx--;show()}});$('tourSkip').addEventListener('click',function(){close();try{localStorage.setItem('scamchainTourSeen','1')}catch(e){}});$('tourClose').addEventListener('click',close);$('restartTour').addEventListener('click',start);
 window.addEventListener('resize',function(){if(active)show()});window.addEventListener('keydown',function(e){if(!active)return;if(e.key==='Escape'){close()}else if(e.key==='ArrowRight'&&idx<steps.length-1){idx++;show()}else if(e.key==='ArrowLeft'&&idx>0){idx--;show()}});
 var seen=false;try{seen=localStorage.getItem('scamchainTourSeen')==='1'}catch(e){}if(!seen)setTimeout(start,450);
}
setupTour();
})();