# ScamChain — Technical Evaluation & Hackathon Report

## 1. Executive summary

ScamChain is an explainable cyber-fraud investigation prototype that converts fragmented multi-channel evidence into a reconstructed attack chain and cross-case campaign view.

The system combines:

**Evidence extraction → 18-signal detection → ML risk scoring → temporal reasoning → entity graph → campaign discovery → evidence provenance → attack replay → intervention analysis**

The central design principle is that a scam is often a workflow rather than a single suspicious event. ScamChain therefore models relationships among messages, URLs, identities, devices, accounts, beneficiaries and transactions over time.

## 2. Problem framing

A single message can be ambiguous. A sequence such as:

`impersonation → verification URL → credential request → OTP → new-device login → beneficiary creation → transfer`

is materially more informative because the events reinforce one another temporally and structurally.

ScamChain is designed around five investigation questions:

1. What signals are present?
2. What attack stage does each event represent?
3. How do events and entities connect?
4. Are multiple incidents part of the same campaign pattern?
5. Where could intervention have occurred?

## 3. Architecture

```text
                    ┌──────────────────────┐
                    │  Evidence / Events   │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Extraction + Entity  │
                    │ Resolution           │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │ 18-Signal Engine     │
                    └──────────┬───────────┘
                               ↓
              ┌────────────────┴────────────────┐
              ↓                                 ↓
    ┌────────────────────┐            ┌────────────────────┐
    │ Temporal Reasoning │            │ Entity / Case Graph│
    └─────────┬──────────┘            └─────────┬──────────┘
              └────────────────┬────────────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Risk + Stage Fusion  │
                    └──────────┬───────────┘
                               ↓
       ┌───────────────────────┼────────────────────────┐
       ↓                       ↓                        ↓
 Campaign Discovery     Evidence Provenance      Intervention
       ↓                       ↓                        ↓
       └───────────────────────┼────────────────────────┘
                               ↓
                    ┌──────────────────────┐
                    │ Investigator UI/API  │
                    └──────────────────────┘
```

## 4. Signal model

The prototype uses 18 signals grouped into six domains:

| Domain | Signals |
|---|---|
| Communication | URGENCY, THREAT_LANGUAGE, AUTHORITY_IMPERSONATION, CREDENTIAL_OTP_SOLICITATION |
| Identity | IDENTITY_INCONSISTENCY, KNOWN_ENTITY_IMPERSONATION, NEW_UNVERIFIED_IDENTITY |
| Infrastructure | MALICIOUS_URL, DOMAIN_REPUTATION, INFRASTRUCTURE_REUSE, SUSPICIOUS_IP_DEVICE |
| Behavioral | UNUSUAL_VICTIM_BEHAVIOR, NEW_BENEFICIARY, TRANSACTION_DEVIATION |
| Temporal | SUSPICIOUS_EVENT_ORDER, COMPRESSED_WORKFLOW |
| Graph | CROSS_CASE_ENTITY_REUSE, ATTACK_PATTERN_SIMILARITY |

Each signal can retain evidence IDs, severity and confidence.

## 5. Temporal attack reconstruction

The canonical attack model is:

`SOCIAL_ENGINEERING → TRUST_ESTABLISHMENT → CREDENTIAL_CAPTURE → ACCOUNT_COMPROMISE → BENEFICIARY_DIVERSION → FINANCIAL_TRANSFER`

The engine does not simply sort timestamps. Event types, evidence and order are mapped into stages, allowing partial chains and missing downstream evidence to be represented.

## 6. Graph intelligence

Core entity types include:

`PERSON, PHONE, EMAIL, DOMAIN, URL, IP, DEVICE, ACCOUNT, BENEFICIARY, TRANSACTION, ORGANIZATION, MESSAGE, CASE`

Relationships include:

`contacted, sent, hosted_on, redirected_to, logged_in_from, created, transferred_to, targeted, connected_to, observed_in, reused_in, similar_to`

Relationships carry evidence, timestamp and confidence so the graph can be audited.

## 7. Campaign discovery

Campaign discovery uses a combination of:

- shared entities where available
- normalized workflow similarity
- temporal similarity
- infrastructure similarity
- graph evidence

The system uses pairwise similarity and connected components in the prototype. It deliberately avoids claiming “same attacker” merely because two incidents share one identifier.

### Held-out campaign benchmark

The benchmark contains **36 cases across 6 latent campaign families**. Campaign members deliberately use unique identifiers.

| Metric | Result |
|---|---:|
| Pair ROC-AUC | **0.983** |
| Pair PR-AUC | **0.600** |
| Campaign clustering ARI | **0.847** |
| Identifier reuse across campaign members | **No** |

These are synthetic research-prototype measurements.

## 8. ML evaluation

The ML benchmark uses grouped train/validation/test splitting and validation-based threshold selection. The prototype reports calibrated probabilities and both classification and calibration metrics.

| Model | F1 | PR-AUC | ROC-AUC | Brier |
|---|---:|---:|---:|---:|
| ML only | 0.865 | 0.944 | 0.928 | 0.112 |
| ML + temporal | 0.955 | 0.987 | 0.987 | 0.038 |
| ML + temporal + graph | 0.992 | 1.000 | 1.000 | 0.007 |
| Full fused model | **0.985** | **0.999** | **0.999** | **0.008** |

Full-fusion ECE: **0.020**.

The ablation is important because it tests whether sequence and graph information add signal beyond surface features.

## 9. Evidence confidence and provenance

ScamChain intentionally separates **risk** from **evidence completeness**.

Evidence completeness tracks how much of the canonical attack chain is actually observed. It is not a probability that the incident is fraudulent.

Example progression on the synthetic full-chain benchmark:

| Observed events | Completeness | Status |
|---:|---:|---|
| 1 | 33.1 | INSUFFICIENT |
| 2 | 46.4 | PARTIAL |
| 3 | 49.8 | PARTIAL |
| 4 | 59.8 | PARTIAL |
| 5 | 73.1 | PARTIAL |
| 6 | 80.4 | COMPLETE |
| 7 | 99.8 | COMPLETE |
| 8 | 99.8 | COMPLETE |

The provenance layer maps reconstructed stages back to concrete event/evidence IDs. This is intended to make model output auditable by an investigator.

## 10. Adversarial robustness

Synthetic stress tests cover:

- adversarial benign lookalikes
- partial attacks
- shuffled event input
- missing evidence
- rotated identifiers

Current results:

| Stress test | Result |
|---|---:|
| Adversarial benign FPR | **0.000** |
| Partial-attack detection | **0.933** |
| Reordered attack-chain accuracy | **1.000** |
| Rotated-identifier pair similarity | **0.500 mean / 0.500 min** |

The rotated-identifier test is designed to ensure campaign similarity does not depend only on exact identifier reuse.

## 11. Intervention model

The prototype encodes a documented defensive policy:

`beneficiary creation > OTP request > suspicious URL > message > none`

Interventions are defensive recommendations, not autonomous financial actions.

Synthetic policy benchmark:

- 22 observations
- 21 scam observations
- 1 benign observation
- intervention-stage accuracy: **1.000**
- unnecessary intervention rate: **0.000**

These metrics measure consistency with the encoded policy, not real-world effectiveness.

## 12. Campaign demonstration

The built-in demonstration contains:

- **C001** — complete bank-impersonation workflow
- **C014** — related workflow with different URL/account/beneficiary
- **C029** — related workflow with different opening identity and partial event sequence
- **B007** — benign control

The three suspicious cases are grouped into **CMP-001** in the demo dataset.

Campaign replay contains **21 cross-case event steps** and covers all six canonical stages.

The campaign-level intervention summary identifies:

**BENEFICIARY_CREATION → Step-up verification / beneficiary hold**

This is the demo policy output, not a claim that this is universally optimal in production.

## 13. Human-in-the-loop design

ScamChain is designed as an investigation aid:

**AI/system:** extract, correlate, reconstruct, explain, surface campaign evidence, recommend intervention.

**Human investigator:** validate evidence, resolve ambiguity, approve operational action.

The prototype intentionally avoids presenting model scores as unquestionable decisions.

## 14. Limitations

The current system is a hackathon/research prototype.

Key limitations:

1. Evaluation data is synthetic.
2. Real-world class imbalance and distribution shift are not represented adequately.
3. Entity resolution is simplified.
4. Threat-intelligence feeds are not live.
5. The campaign graph is not yet evaluated against real incident-response datasets.
6. The canonical six-stage workflow is configurable but not universal.
7. Production deployment would require privacy, security, governance, audit logging and human-approval controls.

## 15. What is technically differentiated

The project is not positioned as another generic scam-message classifier. Its differentiating technical loop is:

**fragmented evidence → temporal attack reconstruction → graph correlation → campaign discovery → provenance → counterfactual intervention**

The system therefore supports investigation across incidents rather than only classification of individual messages.

## 16. Final judge takeaway

> **ScamChain doesn't just detect the scam. It reconstructs the chain behind it.**

The strongest demonstration is the transition from three apparently separate cases to one explainable campaign, followed by an evidence-backed replay and an explicit intervention point.
