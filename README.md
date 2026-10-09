# ScamChain — Connect the Signals. Expose the Scam.

**Beyond Binary** · AI-assisted cyber-fraud investigation prototype

ScamChain correlates suspicious communication, identity, infrastructure, behavioral, temporal and graph signals to reconstruct multi-stage scam workflows, connect related cases into campaigns, show supporting evidence, and recommend human-reviewed intervention points.

> **Prototype limitation:** The packaged classifier is trained on synthetic data. It demonstrates the ML inference path; it is not a production fraud model and must not be used to make real financial decisions.

## What is included

- 18-signal investigation engine
- Persisted calibrated Random Forest model artifact (`artifacts/scamchain_rf.joblib`)
- Model metadata and reproducible synthetic-model training script
- Temporal attack-chain reconstruction
- Evidence-backed entity/case graph and campaign discovery
- Stage-level provenance, evidence gaps, attack replay and counterfactual checks
- Human-in-the-loop intervention recommendations
- FastAPI service and investigator dashboard
- Synthetic ML, campaign and adversarial benchmark scripts
- Automated tests and a deterministic demo dataset

## Requirements

- Python 3.10+ (Python 3.11 recommended)
- pip

## Run locally

### Windows (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_model.py
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_model.py
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. API documentation is available at **http://127.0.0.1:8000/docs**.

The model artifact is included for convenience. `python train_model.py --force` regenerates it from the deterministic synthetic benchmark generator. Keep the artifact and its metadata together.

## Validate

```bash
pytest -q
```

## Useful endpoints

- `GET /api/summary`
- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `GET /api/cases/{case_id}/investigation`
- `GET /api/graph`
- `GET /api/campaigns`
- `GET /api/campaigns/{campaign_id}/investigation`
- `GET /api/model-status`
- `GET /api/ml`
- `GET /api/ml/{case_id}`
- `GET /api/campaign-benchmark`
- `GET /api/campaign-investigation-benchmark`
- `GET /api/intervention-benchmark`
- `GET /api/adversarial-benchmark`
- `GET /api/evidence-benchmark`
- `GET /api/provenance-benchmark`

## Demo cases

- `C001` — suspicious workflow
- `C014` — related workflow
- `C029` — related workflow
- `B007` — benign control

The demonstration groups the three suspicious cases into campaign `CMP-001`.

## Evaluation integrity

All datasets and benchmark values in this repository are **synthetic prototype measurements**. They test implementation behavior, ablations and policy consistency; they do not establish real-world accuracy or generalization. The model has not been trained or validated on real bank/UPI incident data, live threat intelligence is not integrated, and entity resolution is simplified.

## Repository layout

```text
app.py                         FastAPI API + investigator dashboard
engine.py                      Signals, reconstruction, graph and investigation logic
ml.py                          Synthetic benchmark, persisted model loading and scoring
train_model.py                 Train/save demonstration model artifact
artifacts/                     Model artifact + metadata
data.py                        Deterministic synthetic demonstration cases
*_eval.py                      Benchmark/evaluation modules
test_*.py                      Automated tests
DEMO_SCRIPT.md                 Guided demo sequence
TECHNICAL_REPORT.md            Architecture, methodology and limitations
JUDGE_CHEAT_SHEET.md           Judge Q&A notes
BENCHMARK_RESULTS.json         Headline synthetic benchmark results
```

## Responsible-use note

ScamChain is a research/hackathon prototype. Scores and intervention suggestions are decision support only. Do not connect it to payment rails, automatically freeze accounts, or treat its output as a verified fraud finding without independent review and real-world validation.

## Team

**Beyond Binary**

> ScamChain doesn't just detect the scam. It reconstructs the chain behind it.
