"""Source-backed evidence hub for ScamChain.

Official Indian cyber-fraud figures are transcribed from PIB/MHA publications.
Public message samples are fetched from a research dataset at request time; if
the source is unavailable, the endpoint reports that honestly rather than
substituting fabricated examples.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import csv, io, json

router = APIRouter()

STATS = [
    {"year": 2021, "complaints": 262846, "amount_crore": 551},
    {"year": 2022, "complaints": 694446, "amount_crore": 2290},
    {"year": 2023, "complaints": 1310357, "amount_crore": 7465},
    {"year": 2024, "complaints": 1918835, "amount_crore": 22848},
    {"year": 2025, "complaints": 2402579, "amount_crore": 22495},
]
SOURCES = [
    {"name":"Government of India — Ministry of Home Affairs / I4C (PIB)", "type":"Official reported financial-cyber-fraud statistics", "url":"https://www.pib.gov.in/PressReleasePage.aspx?PRID=2226441&lang=2&reg=3", "note":"NCRP complaints and amount reported for 2021–2025. These are reported complaints/losses, not a count of all scams or a detector benchmark."},
    {"name":"PhishTank (Cisco Talos)", "type":"Community-verified phishing URL intelligence", "url":"https://data.dev.phishtank.com/", "note":"Phishing URL feed/API; availability and verification status vary over time."},
    {"name":"Combined Labeled Smishing Dataset", "type":"Public labeled SMS research corpus", "url":"https://github.com/shaghayegh-hp/Smishing_Dataset", "note":"Repository describes messages labeled as smishing/non-smishing; labels are research annotations, not government-confirmed incidents."},
    {"name":"LegitPhish (Data in Brief, 2025)", "type":"Manually verified URL benchmark", "url":"https://pmc.ncbi.nlm.nih.gov/articles/PMC12538017/", "note":"Published dataset reports 101,219 labeled URLs: 63,678 phishing and 37,540 legitimate."},
]

@router.get("/api/research-evidence")
def research_evidence():
    return {"official_statistics": STATS, "sources": SOURCES,
            "statistics_as_of": "2025 year-end figures, published by Government of India",
            "interpretation": "Official reported complaints and reported amounts are impact context, not classifier performance."}

@router.get("/api/public-message-samples")
def public_message_samples():
    url = "https://raw.githubusercontent.com/shaghayegh-hp/Smishing_Dataset/main/Combined-Labeled-Dataset.csv"
    try:
        req = Request(url, headers={"User-Agent":"ScamChain-research-prototype/1.0"})
        with urlopen(req, timeout=8) as response:
            raw = response.read(5_000_000).decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(raw))
        fields = reader.fieldnames or []
        message_key = next((f for f in fields if f.lower().strip() in ("message","text","sms","sms_text")), None)
        smish_key = next((f for f in fields if "smishing" in f.lower()), None)
        spam_key = next((f for f in fields if "spam" in f.lower() or "label" in f.lower()), None)
        if not message_key:
            return {"status":"source_schema_changed","source_url":url,"count":0,"samples":[],"note":"Public source was reachable, but the message column could not be identified. No sample data was fabricated."}
        rows=[]
        seen=set()
        for row in reader:
            msg=(row.get(message_key) or "").strip()
            if len(msg)<12 or msg in seen: continue
            seen.add(msg)
            label=(row.get(smish_key) or row.get(spam_key) or "").strip()
            if label.lower() in ("1","smishing","phishing","spam","true","yes"):
                rows.append({"message":msg[:700],"label":"dataset-labelled smishing/spam","label_field":smish_key or spam_key})
            if len(rows)>=8: break
        return {"status":"live_source_loaded" if rows else "no_positive_rows_found","source_name":"Combined Labeled Smishing Dataset","source_url":"https://github.com/shaghayegh-hp/Smishing_Dataset","raw_data_url":url,"count":len(rows),"samples":rows,"note":"These are examples from a public research corpus. The dataset's labels are not independently re-verified by ScamChain."}
    except (URLError, HTTPError, TimeoutError, UnicodeError, csv.Error) as exc:
        return {"status":"source_unavailable","source_url":"https://github.com/shaghayegh-hp/Smishing_Dataset","count":0,"samples":[],"note":"Could not fetch the public dataset from the deployed server right now. No synthetic messages are shown as real evidence.","error":type(exc).__name__}

@router.get("/evidence", response_class=HTMLResponse)
def evidence_page():
    return HTMLResponse(r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScamChain | Evidence Lab</title><style>
*{box-sizing:border-box}body{margin:0;background:#060b16;color:#e7effb;font:14px system-ui, sans-serif}header{padding:24px max(20px,calc((100vw - 1200px)/2));border-bottom:1px solid #25384f;background:#0a1221}a{color:#74e4f7}main{max-width:1200px;margin:auto;padding:26px 20px}.eyebrow{color:#6de2f4;font-size:11px;letter-spacing:2px}h1{margin:8px 0;font-size:32px}h2{font-size:19px}.sub{color:#9aacc3;line-height:1.6}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}.card{background:#0d192b;border:1px solid #263a53;border-radius:13px;padding:17px;margin:12px 0}.num{font-size:27px;font-weight:750;color:#7ce8f5}.small{font-size:12px;color:#9aacc3;line-height:1.6}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;border-bottom:1px solid #263a53;padding:10px;font-size:12px}.msg{padding:13px;border:1px solid #31435b;background:#080f1c;border-radius:9px;margin:10px 0;white-space:pre-wrap;line-height:1.6}.tag{display:inline-block;color:#ffdc8c;border:1px solid #6a552b;padding:3px 7px;border-radius:6px;font-size:10px}.source{padding:12px 0;border-bottom:1px solid #24364c}.btn{background:#1b455a;color:#e8fbff;border:1px solid #398ba0;border-radius:8px;padding:10px 13px;cursor:pointer;font-weight:650}.warn{border-left:3px solid #ffc857;padding:10px 13px;background:#211b10;color:#f6dba0;font-size:12px;line-height:1.6}@media(max-width:700px){.metrics{grid-template-columns:1fr}.table{display:block;overflow:auto}}
</style></head><body><header><div class="eyebrow">BEYOND BINARY / SCAMCHAIN</div><h1>Real-World Evidence Lab</h1><div class="sub">Source-backed impact statistics, public message samples, and traceable research datasets.</div><p><a href="/">← Return to investigation workbench</a></p></header><main><div class="warn">Evidence integrity rule: official impact statistics are not detection accuracy. Public dataset labels are not automatically ground truth. If a live source fails, this page reports that failure instead of inventing samples.</div><section class="card"><div class="eyebrow">01 / NATIONAL IMPACT</div><h2>Reported financial cyber-fraud complaints in India</h2><p class="sub">Government of India NCRP/I4C figures, 2021–2025. Amounts are reported losses in ₹ crore.</p><div class="metrics" id="metrics"></div><div id="stats"></div><p class="small">Source: <a href="https://www.pib.gov.in/PressReleasePage.aspx?PRID=2226441&lang=2&reg=3" target="_blank" rel="noreferrer">Press Information Bureau / Ministry of Home Affairs</a>. Reported complaint counts can reflect changes in reporting and should not be interpreted as the total number of all scams.</p></section><section class="card"><div class="eyebrow">02 / REAL MESSAGE CORPUS</div><h2>Publicly labeled smishing examples</h2><p class="sub">Fetched on demand from a public research dataset. Messages appear only if the source returns rows; we do not substitute generated examples.</p><button class="btn" id="load">Fetch public samples</button><div id="samples" class="small" style="margin-top:14px">Not loaded yet. Click the button to request the source dataset.</div></section><section class="card"><div class="eyebrow">03 / TRACEABLE SOURCES</div><h2>Research and threat-intelligence sources</h2><div id="sources"></div></section><section class="card"><div class="eyebrow">04 / VALIDATION STANDARD</div><h2>What we will measure against labeled data</h2><div class="metrics"><div><div class="num">Precision</div><div class="small">Of messages flagged, how many are labeled scams?</div></div><div><div class="num">Recall</div><div class="small">Of labeled scam messages, how many did the detector catch?</div></div><div><div class="num">False-positive rate</div><div class="small">How often legitimate messages are incorrectly flagged.</div></div></div><p class="small">The app currently does not claim these are measured metrics for real-world data. They must be computed from a held-out labeled test set, with duplicates removed and source/date documented.</p></section></main><script>
const fmt=n=>new Intl.NumberFormat('en-IN').format(n);
async function init(){try{const d=await fetch('/api/research-evidence').then(r=>r.json());const s=d.official_statistics;const latest=s[s.length-1];document.getElementById('metrics').innerHTML='<div><div class="num">'+fmt(latest.complaints)+'</div><div class="small">Financial-fraud complaints in 2025</div></div><div><div class="num">₹'+fmt(latest.amount_crore)+' crore</div><div class="small">Amount reported in 2025</div></div><div><div class="num">₹8,189+ crore</div><div class="small">Reported amount saved through CFCFRMS by 31 Dec 2025</div></div>';document.getElementById('stats').innerHTML='<table class="table"><thead><tr><th>Year</th><th>Complaints</th><th>Amount reported</th></tr></thead><tbody>'+s.map(x=>'<tr><td>'+x.year+'</td><td>'+fmt(x.complaints)+'</td><td>₹'+fmt(x.amount_crore)+' crore</td></tr>').join('')+'</tbody></table>';document.getElementById('sources').innerHTML=d.sources.map(x=>'<div class="source"><b>'+x.name+'</b><div class="small">'+x.type+'</div><div class="small">'+x.note+'</div><a href="'+x.url+'" target="_blank" rel="noreferrer">Open source ↗</a></div>').join('')}catch(e){document.getElementById('stats').textContent='Could not load official evidence metadata.'}}
document.getElementById('load').onclick=async()=>{const box=document.getElementById('samples');box.textContent='Fetching the public research corpus…';try{const d=await fetch('/api/public-message-samples').then(r=>r.json());box.innerHTML='<p><b>Status:</b> '+d.status+' · <b>Rows returned:</b> '+d.count+'</p><p>'+d.note+'</p>'+(d.samples||[]).map((x,i)=>'<div class="msg"><span class="tag">DATASET LABEL: '+x.label+'</span><p><b>Sample '+(i+1)+'</b></p>'+String(x.message).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))+'</div>').join('')+'<p><a href="'+d.source_url+'" target="_blank" rel="noreferrer">Inspect original dataset ↗</a></p>'}catch(e){box.textContent='Source request failed. No message examples were fabricated.'}};
init();
</script></body></html>""")
