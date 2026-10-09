"""Leakage-aware synthetic ML benchmark for ScamChain.

This is a prototype benchmark only. It uses grouped synthetic data, a validation
split for threshold selection, and a held-out test split for final metrics.
"""
from __future__ import annotations
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.calibration import CalibratedClassifierCV
from engine import SIGNALS

SIGNAL_NAMES = [x[0] for x in SIGNALS]


def build_benchmark(n_per_class=600, seed=42):
    rng = np.random.default_rng(seed)
    n = n_per_class * 2
    y = np.r_[np.ones(n_per_class, dtype=int), np.zeros(n_per_class, dtype=int)]
    X = np.zeros((n, 18), dtype=float)

    X[:n_per_class, :14] = rng.beta(2.4, 2.0, (n_per_class, 14))
    X[n_per_class:, :14] = rng.beta(1.8, 2.6, (n_per_class, 14))
    X[:n_per_class, 14] = rng.beta(4.0, 2.0, n_per_class)
    X[n_per_class:, 14] = rng.beta(1.5, 4.0, n_per_class)
    X[:n_per_class, 15] = rng.beta(3.5, 2.0, n_per_class)
    X[n_per_class:, 15] = rng.beta(1.5, 4.0, n_per_class)
    X[:n_per_class, 16] = rng.beta(4.5, 1.8, n_per_class)
    X[n_per_class:, 16] = rng.beta(1.2, 5.0, n_per_class)
    X[:n_per_class, 17] = rng.beta(3.5, 2.2, n_per_class)
    X[n_per_class:, 17] = rng.beta(1.4, 4.5, n_per_class)

    # Latent groups make the split case-family aware rather than row-random.
    # Samples within a group share a small latent offset, but labels remain fixed.
    groups = np.arange(n) // 10
    offsets = rng.normal(0, 0.06, (groups.max() + 1, 18))
    X = np.clip(X + offsets[groups], 0, 1)
    return X, y, groups


def _metrics(y, p, threshold=.5):
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        'precision': round(precision_score(y, pred, zero_division=0), 3),
        'recall': round(recall_score(y, pred, zero_division=0), 3),
        'f1': round(f1_score(y, pred, zero_division=0), 3),
        'pr_auc': round(average_precision_score(y, p), 3),
        'roc_auc': round(roc_auc_score(y, p), 3),
        'brier': round(brier_score_loss(y, p), 3),
        'threshold': round(float(threshold), 3),
        'false_positives': int(fp),
        'false_negatives': int(fn),
    }



def expected_calibration_error(y, p, bins=10):
    y = np.asarray(y)
    p = np.asarray(p)
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    rows = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if not np.any(mask):
            continue
        conf = float(np.mean(p[mask]))
        acc = float(np.mean(y[mask]))
        frac = float(np.mean(mask))
        ece += frac * abs(acc - conf)
        rows.append({"lower": round(float(lo),2), "upper": round(float(hi),2),
                     "count": int(np.sum(mask)), "confidence": round(conf,3), "empirical_rate": round(acc,3)})
    return round(float(ece), 3), rows

def _fit_predict(X_train, y_train, X_val, y_val, X_test, seed):
    base = RandomForestClassifier(
        n_estimators=220, max_depth=5, min_samples_leaf=5,
        random_state=seed, class_weight='balanced'
    )
    model = CalibratedClassifierCV(base, method='sigmoid', cv=3)
    model.fit(X_train, y_train)
    val_p = model.predict_proba(X_val)[:, 1]
    # Choose threshold on validation only; test remains untouched.
    thresholds = np.linspace(.20, .80, 61)
    scores = [(f1_score(y_val, val_p >= t, zero_division=0), t) for t in thresholds]
    threshold = max(scores, key=lambda z: (z[0], -abs(z[1]-.5)))[1]
    return model.predict_proba(X_test)[:, 1], model, float(threshold)


def evaluate(seed=42):
    X, y, groups = build_benchmark(seed=seed)
    gss = GroupShuffleSplit(n_splits=1, test_size=.20, random_state=seed)
    trainval_idx, test_idx = next(gss.split(X, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=.25, random_state=seed + 1)
    tr_rel, val_rel = next(gss2.split(trainval_idx, y[trainval_idx], groups[trainval_idx]))
    train_idx, val_idx = trainval_idx[tr_rel], trainval_idx[val_rel]

    configs = {
        'A: ML only': list(range(14)),
        'B: ML + temporal': list(range(16)),
        'C: ML + temporal + graph': list(range(18)),
    }
    results = []
    for name, cols in configs.items():
        p, _, threshold = _fit_predict(X[train_idx][:, cols], y[train_idx],
                                        X[val_idx][:, cols], y[val_idx],
                                        X[test_idx][:, cols], seed)
        results.append({'model': name, **_metrics(y[test_idx], p, threshold),
                        'train_cases': len(train_idx), 'validation_cases': len(val_idx),
                        'test_cases': len(test_idx)})

    interaction = np.column_stack([X[:, 14] * X[:, 16], X[:, 15] * X[:, 17]])
    XD = np.hstack([X, interaction])
    p, _, threshold = _fit_predict(XD[train_idx], y[train_idx], XD[val_idx], y[val_idx], XD[test_idx], seed)
    results.append({'model': 'D: full fused model', **_metrics(y[test_idx], p, threshold),
                    'train_cases': len(train_idx), 'validation_cases': len(val_idx),
                    'test_cases': len(test_idx)})

    # Calibration is evaluated on the same untouched test predictions from the
    # full fused model. This reports probability quality separately from ranking.
    ece, calibration = expected_calibration_error(y[test_idx], p)
    full_metrics = results[-1]
    full_metrics['ece'] = ece
    return {
        'benchmark': 'synthetic', 'seed': seed, 'rows': int(len(y)),
        'split': 'grouped train/validation/test',
        'calibration': {'ece': ece, 'bins': calibration},
        'feature_groups': {
            'surface': SIGNAL_NAMES[:14], 'temporal': SIGNAL_NAMES[14:16],
            'graph': SIGNAL_NAMES[16:18],
            'fusion_interactions': ['temporal_x_graph_1', 'temporal_x_graph_2'],
        }, 'results': results,
    }


MODEL_PATH = Path(__file__).resolve().parent / "artifacts" / "scamchain_rf.joblib"
MODEL_META_PATH = Path(__file__).resolve().parent / "artifacts" / "model_metadata.json"


def fit_deployment_model(seed=42):
    """Fit a reproducible demo model on synthetic data.

    This artifact demonstrates the inference pipeline only. It is not trained
    on real fraud reports and must not be described as production-ready.
    """
    X, y, groups = build_benchmark(seed=seed)
    interaction = np.column_stack([X[:, 14] * X[:, 16], X[:, 15] * X[:, 17]])
    XD = np.hstack([X, interaction])
    model = CalibratedClassifierCV(
        RandomForestClassifier(
            n_estimators=220, max_depth=5, min_samples_leaf=5,
            random_state=seed, class_weight="balanced"
        ), method="sigmoid", cv=3
    )
    model.fit(XD, y)
    metadata = {
        "artifact": MODEL_PATH.name,
        "model_type": "CalibratedClassifierCV(RandomForestClassifier)",
        "training_data": "synthetic",
        "training_rows": int(len(y)),
        "seed": seed,
        "features": SIGNAL_NAMES + ["temporal_x_graph_1", "temporal_x_graph_2"],
        "warning": "Prototype-only model trained on synthetic data; not for production decisions."
    }
    return model, metadata


def ensure_model_artifact(force_retrain=False):
    """Load the packaged model; train/save it if absent or explicitly requested."""
    if MODEL_PATH.exists() and MODEL_META_PATH.exists() and not force_retrain:
        return joblib.load(MODEL_PATH), json.loads(MODEL_META_PATH.read_text())
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    model, metadata = fit_deployment_model()
    joblib.dump(model, MODEL_PATH)
    MODEL_META_PATH.write_text(json.dumps(metadata, indent=2) + "\n")
    return model, metadata


def score_case(case, seed=42):
    """Score a case using the persisted artifact (never retrain per request)."""
    model, _ = ensure_model_artifact()
    signals = {s["signal"]: float(s["value"]) for s in case.signals}
    row = np.asarray([signals.get(name, 0.0) for name in SIGNAL_NAMES], dtype=float).reshape(1, -1)
    interaction = np.asarray([[row[0, 14] * row[0, 16], row[0, 15] * row[0, 17]]])
    features = np.hstack([row, interaction])
    return round(float(model.predict_proba(features)[0, 1]), 3)
