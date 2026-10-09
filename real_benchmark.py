"""Reproducible held-out evaluation using public, labeled research datasets.

Important: dataset label quality and representativeness are inherited from the
source. This benchmark is a text/URL baseline, not the existing ScamChain
multi-signal case model, and its results must not be presented as production
performance.
"""
from __future__ import annotations
import csv, io, json, time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score, balanced_accuracy_score

SMS_URL = "https://raw.githubusercontent.com/shaghayegh-hp/Smishing_Dataset/main/Combined-Labeled-Dataset.csv"
URL_URL = "https://raw.githubusercontent.com/Hassan-Albattra/EdgePhish-5G/main/dataset/sample/urls_sample_1000.csv"
_cache = {"result": None, "at": 0}

def _fetch(url: str, max_bytes: int = 25_000_000) -> bytes:
    req = Request(url, headers={"User-Agent": "ScamChain-Research-Benchmark/1.0"})
    with urlopen(req, timeout=20) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Dataset exceeded safe download limit")
    return data

def _read_csv(raw: bytes) -> list[dict]:
    decoded = raw.decode("utf-8-sig", errors="replace")
    sample = decoded[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return list(csv.DictReader(io.StringIO(decoded), dialect=dialect))

def _col(row: dict, options: tuple[str, ...]):
    lookup = {str(k).strip().lower(): k for k in row}
    for opt in options:
        if opt in lookup:
            return lookup[opt]
    return None

def _normalise_binary(value, positive_words, negative_words):
    s = str(value).strip().lower()
    if s in positive_words: return 1
    if s in negative_words: return 0
    try:
        n = int(float(s))
        if n in (0, 1): return n
    except Exception:
        pass
    return None

def _evaluate(name, source_url, rows, text_cols, label_cols, positive_words, negative_words, label_note, min_rows=80):
    if not rows:
        raise ValueError("The source returned no CSV rows")
    text_key = _col(rows[0], text_cols)
    label_key = _col(rows[0], label_cols)
    if not text_key or not label_key:
        raise ValueError("Dataset columns changed; expected text and label columns were not found")
    cleaned, seen = [], set()
    for row in rows:
        text = str(row.get(text_key) or "").strip()
        label = _normalise_binary(row.get(label_key), positive_words, negative_words)
        if len(text) < 4 or label is None:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append((text, label))
    counts = Counter(y for _, y in cleaned)
    if len(cleaned) < min_rows or counts[0] < 20 or counts[1] < 20:
        raise ValueError(f"Not enough usable examples after cleaning (rows={len(cleaned)}, class_counts={dict(counts)})")
    X = [x for x, _ in cleaned]
    y = [label for _, label in cleaned]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=50000, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42))
    ])
    started = time.time()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "name": name, "status": "evaluated", "source_url": source_url,
        "source_rows_received": len(rows), "unique_labeled_rows": len(cleaned),
        "train_rows": len(X_train), "test_rows": len(X_test),
        "class_balance": {"negative": counts[0], "positive": counts[1]},
        "positive_class": "smishing/spam" if "SMS" in name else "phishing URL",
        "label_note": label_note, "split": "stratified 75/25 holdout; random_state=42; exact duplicates removed before split",
        "metrics": {
            "accuracy": round(accuracy_score(y_test, pred), 4),
            "balanced_accuracy": round(balanced_accuracy_score(y_test, pred), 4),
            "precision": round(precision_score(y_test, pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, pred, zero_division=0), 4),
            "f1": round(f1_score(y_test, pred, zero_division=0), 4),
            "false_positive_rate": round(fpr, 4),
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp)
        },
        "model": "character TF-IDF + LogisticRegression; trained during benchmark",
        "runtime_seconds": round(time.time() - started, 2)
    }

def run_real_benchmarks(force=False):
    now = time.time()
    if not force and _cache["result"] and now - _cache["at"] < 3600:
        return _cache["result"]
    out = {"benchmark_type": "public labeled dataset baseline", "generated_at_unix": int(now),
           "methodology": "Deduplicate exact text before split; stratified held-out test set; train a baseline only on the training partition; report confusion matrix and standard metrics. Results do not validate ScamChain's multi-signal workflow model.",
           "results": [], "errors": []}
    try:
        sms_rows = _read_csv(_fetch(SMS_URL))
        out["results"].append(_evaluate(
            "SMS smishing research corpus", SMS_URL, sms_rows,
            ("message", "text", "sms", "sms_text"),
            ("smishing label", "smishing_label", "label"),
            {"1", "smishing", "phishing", "true", "yes"},
            {"0", "ham", "non-smishing", "legitimate", "false", "no"},
            "The source README says labels were assigned using frequent smishing-related keywords across five public sources. This is a labeled research corpus, not a set of independently confirmed fraud incidents."
        ))
    except Exception as exc:
        out["errors"].append({"dataset":"SMS smishing research corpus","source_url":SMS_URL,"error":type(exc).__name__,"detail":str(exc)[:240]})
    try:
        url_rows = _read_csv(_fetch(URL_URL, 8_000_000))
        out["results"].append(_evaluate(
            "Phishing URL sample (EdgePhish-5G)", URL_URL, url_rows,
            ("url", "URL", "domain"),
            ("label", "class", "type"),
            {"1", "phishing", "phish", "malicious", "true", "yes"},
            {"0", "legitimate", "benign", "safe", "false", "no"},
            "Public 1,000-row research sample described by its repository as 500 phishing and 500 legitimate URLs. Labels and collection quality are inherited from the dataset authors."
        ))
    except Exception as exc:
        out["errors"].append({"dataset":"Phishing URL sample (EdgePhish-5G)","source_url":URL_URL,"error":type(exc).__name__,"detail":str(exc)[:240]})
    out["status"] = "completed" if out["results"] else "no_dataset_evaluated"
    _cache["result"], _cache["at"] = out, now
    return out
