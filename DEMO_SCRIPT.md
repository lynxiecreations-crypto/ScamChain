# ScamChain — 5-Minute Judge Demo

## Core line
**Connect the Signals. Expose the Scam.**

> ScamChain does not stop at “is this suspicious?” It reconstructs the attack, connects related incidents, shows the evidence behind each inference, and identifies where intervention was possible.

## Demo setup
Use the built-in synthetic dataset:
- C001 — bank impersonation → verification URL → credential/OTP capture → new-device login → beneficiary → transfer
- C014 — similar workflow with a different URL/account/beneficiary
- C029 — different opening identity, but overlapping infrastructure/beneficiary and similar workflow
- B007 — benign banking activity as a negative control

All entities and events are synthetic.

## 0:00–0:30 — Command Center
**Say:**
“Here are four incidents. Three are high-risk and one is benign. The important point is that ScamChain is not treating each message independently.”

Show:
- Cases
- risk status
- evidence completeness
- campaign assignment

Do not start with the graph. Start with the investigation question.

## 0:30–1:10 — Open C001
**Say:**
“C001 starts with a pressure message. Four minutes later there is a verification URL, then credential and OTP requests, then a new-device login, a new beneficiary, and a transfer.”

Show the timeline and stage reconstruction:
1. SOCIAL_ENGINEERING
2. TRUST_ESTABLISHMENT
3. CREDENTIAL_CAPTURE
4. ACCOUNT_COMPROMISE
5. BENEFICIARY_DIVERSION
6. FINANCIAL_TRANSFER

Then open evidence provenance.

**Say:**
“Each inferred stage has supporting event IDs. The model is not asking the investigator to trust an unexplained label.”

## 1:10–1:50 — Partial evidence
Open the evidence/provenance view.

**Say:**
“Now remove downstream evidence. ScamChain distinguishes evidence completeness from scam risk. Partial evidence is not automatically treated as a completed fraud.”

Show:
- observed stages
- missing stages
- stage confidence
- evidence gaps

**Key line:**
“Uncertainty is represented explicitly rather than hidden inside one score.”

## 1:50–2:30 — Campaign reveal
Open Campaigns / Campaign Replay.

**Say:**
“C014 initially looks like a separate incident. C029 looks different again. Campaign intelligence asks whether the workflow, timing, infrastructure, and entity relationships form a common pattern.”

Reveal:
**C001 + C014 + C029 → CMP-001**

Then show the campaign evidence rationale.

**Important qualification:**
“The demo cases deliberately contain reusable infrastructure to make the investigation visible. Separately, our held-out campaign benchmark removes identifier reuse to test whether clustering can still recover campaign structure from behavior.”

## 2:30–3:20 — Cross-case attack replay
Open Campaign Replay.

**Say:**
“Instead of three disconnected timelines, the investigator now sees one cross-case replay.”

Show chronological events across C001, C014, C029.

Point out:
- repeated social-engineering pattern
- repeated credential/verification workflow
- infrastructure overlap
- beneficiary overlap
- timing/order similarity

**Key line:**
“The graph is analytical here: every relationship is backed by evidence, timestamp, and confidence.”

## 3:20–4:00 — Intervention
Open Risk & Intervention.

**Say:**
“The question is no longer only ‘was this a scam?’ It is ‘where could we have interrupted it?’”

Show:
**BENEFICIARY_CREATION → Step-up verification / beneficiary hold**

Explain that earlier signals can also support warnings/verification, while the benchmark evaluates the documented intervention policy.

## 4:00–4:35 — Technical validation
Open ML / Campaign Benchmark / Adversarial / Provenance tabs.

Use only these headline numbers:
- Full-fusion F1: **0.985**
- Full-fusion PR-AUC: **0.999**
- Campaign clustering ARI: **0.847**
- Partial-attack detection: **0.933**
- Adversarial-benign FPR: **0.000**
- Provenance coverage: **1.000**

Immediately say:
“All of these are synthetic prototype benchmarks. They demonstrate internal behavior and ablations, not production performance.”

## 4:35–5:00 — Close
**Say exactly:**
“Traditional fraud detection asks whether an event is suspicious. ScamChain asks how the events connect. It reconstructs the attack, links incidents into campaigns, preserves the evidence behind each inference, and identifies where intervention was possible.”

**Final line:**
> **ScamChain doesn't just detect the scam. It reconstructs the chain behind it.**

## If judges ask “Why not just use an LLM?”
Answer:
“The LLM can help extract entities and evidence from unstructured content, but the core investigation logic is deterministic and structured: temporal ordering, entity resolution, graph relationships, calibrated risk, provenance, and explicit intervention policy. That makes the result auditable and testable.”

## If judges ask “How do you avoid false campaign links?”
Answer:
“We do not claim same attacker from one shared field. Campaign evidence combines workflow similarity, temporal behavior, infrastructure and graph signals. The held-out benchmark deliberately removes identifier reuse among campaign members.”

## If judges ask “What happens with incomplete evidence?”
Answer:
“Evidence completeness is separate from fraud probability. Missing stages are surfaced explicitly, and partial chains can be routed for evidence review rather than being presented as fully reconstructed attacks.”

## If judges ask “Can this work beyond banking?”
Answer:
“Yes at the architecture level. The canonical stages and signal mappings are domain-configurable; the same engine can model account takeover, payment fraud, support impersonation, delivery scams, or other multi-stage workflows after domain-specific event mappings are defined.”
