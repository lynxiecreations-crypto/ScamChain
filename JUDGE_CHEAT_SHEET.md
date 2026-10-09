# Judge Cheat Sheet

## 15-second pitch
ScamChain is an AI-assisted cyber investigation engine that reconstructs multi-stage scam workflows from fragmented evidence and connects related incidents into explainable campaigns.

## 3 technical differentiators
1. **Temporal reasoning** — sequence matters, not just isolated signals.
2. **Cross-case graph intelligence** — related incidents can form campaign evidence.
3. **Evidence provenance** — every inferred stage points back to supporting events and exposes missing evidence.

## 3 numbers
- Full fused F1: **0.985** synthetic held-out test.
- Campaign clustering ARI: **0.847** on held-out synthetic campaign families with identifier reuse removed.
- Partial attack detection: **0.933** synthetic adversarial benchmark.

## One caveat to volunteer
“These are synthetic benchmarks for a research prototype; they are not production accuracy claims.”

## If asked about LLMs
Use an LLM for extraction/normalization where useful; keep the investigation graph, temporal logic, provenance and intervention policy structured and auditable.

## If asked about scale
The current implementation is intentionally compact. Production scale would require streaming ingestion, durable graph storage, distributed feature computation, model monitoring, privacy controls and analyst workflow integration.

## Closing sentence
**ScamChain doesn't just detect the scam. It reconstructs the chain behind it.**
