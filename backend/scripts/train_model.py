"""Train and version ByteForce URL models from synthetic or authorized labelled data."""
import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from detection.model_registry import MODELS_DIR, register_model

LABELS = {
    "BENIGN": ["/", "/about", "/search?q=weather", "/api/notices?page=2", "/profile/settings"],
    "SQL_INJECTION": ["/search?q=' or '1'='1", "/item?id=1 union select sample from records", "/report?x=1--"],
    "XSS": ["/feedback?q=<script>alert(1)</script>", "/view?x=<img onerror=demo>", "/next?x=javascript:demo"],
    "DIRECTORY_TRAVERSAL": ["/download?f=../../../../etc/passwd", "/read?f=..\\..\\boot.ini"],
    "COMMAND_INJECTION": ["/lookup?host=demo.test;whoami", "/tool?x=$(echo sample)", "/run?q=sample|id"],
    "SSRF": ["/preview?url=http://127.0.0.1/admin", "/proxy?target=http://10.0.0.8/", "/go?host=localhost"],
    "LFI": ["/view?page=../../../etc/passwd", "/include?file=php://filter/sample", "/read?template=../../proc/self/status"],
}


def synthetic_dataset():
    random.seed(2908); texts, labels = [], []
    hosts = ["portal.example.test", "shop.example.test", "authorized-site.local", "api.example.test", "app.example.test"]
    # A production classifier sees far more normal traffic than attacks. Give
    # the educational baseline varied benign paths so host names and routine
    # query syntax are not accidentally treated as attack features.
    benign_paths = [
        "/", "/about", "/contact", "/products", "/products?page={n}", "/search?q=weather+{n}",
        "/api/notices?page={n}", "/profile/settings", "/assets/main.css", "/health", "/orders/{n}",
        "/docs/getting-started", "/news?category=technology&page={n}", "/login", "/logout",
    ]
    for index in range(1680):
        path = random.choice(benign_paths).format(n=index % 97)
        texts.append(f"https://{random.choice(hosts)}{path}"); labels.append("BENIGN")
    for label, examples in LABELS.items():
        if label == "BENIGN":
            continue
        for index in range(120):
            base = random.choice(examples)
            texts.append(f"https://{random.choice(hosts)}{base}{'&' if '?' in base else '?'}sample={index}")
            labels.append(label)
    return pd.DataFrame({"url": texts, "label": labels})


def load_dataset(path: str | None) -> tuple[pd.DataFrame, str]:
    if not path:
        return synthetic_dataset(), "synthetic-prototype"
    frame = pd.read_csv(path)
    url_column = "url" if "url" in frame.columns else "uri" if "uri" in frame.columns else None
    if not url_column or "label" not in frame.columns:
        raise ValueError("Training CSV requires url (or uri) and label columns.")
    frame = frame.rename(columns={url_column: "url"}).dropna(subset=["url", "label"])
    counts = frame["label"].value_counts()
    if len(frame) < 100 or counts.min() < 10:
        raise ValueError("Use at least 100 reviewed records and 10 examples per class.")
    return frame, str(Path(path).resolve())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", help="Authorized reviewed CSV with url/uri and label columns")
    parser.add_argument("--version", help="Model version; defaults to UTC timestamp")
    parser.add_argument("--no-activate", action="store_true")
    args = parser.parse_args()
    frame, source = load_dataset(args.dataset)
    if args.dataset and "timestamp" in frame.columns:
        frame = frame.sort_values("timestamp"); split = int(len(frame) * .75)
        train, test = frame.iloc[:split], frame.iloc[split:]
        if set(test.label) - set(train.label):
            raise ValueError("Time split leaves unseen classes in the test set; collect more reviewed data.")
        x_train, y_train, x_test, y_test = train.url, train.label, test.url, test.label
    else:
        x_train, x_test, y_train, y_test = train_test_split(frame.url, frame.label, test_size=.25, random_state=42, stratify=frame.label)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=50000, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced")),
    ])
    model.fit(x_train, y_train); predicted = model.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predicted, average="weighted", zero_division=0)
    labels = sorted(frame.label.unique())
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predicted)), 4), "precision": round(float(precision), 4),
        "recall": round(float(recall), 4), "f1": round(float(f1), 4), "labels": labels,
        "per_class": classification_report(y_test, predicted, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=labels).tolist(), "train_records": len(x_train), "test_records": len(x_test),
    }
    version = args.version or datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    path = MODELS_DIR / f"byteforce-{version}.joblib"; joblib.dump(model, path)
    baseline = {"average_url_length": round(float(frame.url.str.len().mean()), 2), "threat_rate": round(float((frame.label != "BENIGN").mean()), 4)}
    register_model(version, path, metrics, source, baseline, not args.no_activate)
    print(json.dumps({"version": version, "path": str(path), "training_source": source, "active": not args.no_activate, "metrics": metrics, "baseline": baseline}, indent=2))


if __name__ == "__main__":
    main()
