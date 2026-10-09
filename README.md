# ScamChain — Connect the Signals. Expose the Scam.

ScamChain is an explainable cyber-fraud investigation prototype that reconstructs multi-stage scam workflows from fragmented evidence and connects related incidents into campaigns.

## Pipeline

Evidence → extraction/entity resolution → 18 signals → ML risk → temporal reasoning → graph → campaign discovery → provenance → attack replay → intervention

## v2.7 capabilities

- 18-signal detection across communication, identity, infrastructure, behavioral, temporal and graph domains
- ML risk scoring with grouped validation/test splitting and calibration metrics
- Temporal attack reconstruction across six canonical stages
- Entity/case graph with evidence, timestamp and confidence on relationships
- Held-out campaign benchmark with identifier reuse removed
- Evidence completeness separate from fraud risk
- Stage-level provenance and confidence
- Evidence gap analysis, attack replay, campaign replay and counterfactual analysis
- Adversarial robustness evaluation
- Intervention recommendations with human-in-the-loop framing
- FastAPI API + investigator dashboard

## Run locally

```bash
pip install -r requirements.txt
python -m uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

## Validate

```bash
pytest -q
```

## Benchmark warning

All benchmark data and metrics are synthetic prototype measurements. They are intended to test system behavior, ablations, robustness and policy consistency. They must not be interpreted as production fraud-detection performance.

## Project status

Repository initialised. Source modules, UI, evaluation scripts, model artifact and judge materials are being published in the next commit.