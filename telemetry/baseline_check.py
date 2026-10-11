#!/usr/bin/env python3
"""
Sanity check for The Range's telemetry: can a simple model separate malicious
from benign using only the behavioural features? If yes, the dataset is a valid
foundation for the Sentinel detector (repo [1]). This is deliberately a weak
baseline — Sentinel does the real modelling. Run after generate.py.
"""
from __future__ import annotations

import csv
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

FEATURES = ["status", "bytes_in", "latency_ms", "requests_last_10s",
            "distinct_paths_last_60s", "payload_entropy"]


def load(path: Path):
    X, y = [], []
    with path.open() as f:
        for row in csv.DictReader(f):
            X.append([float(row[k]) for k in FEATURES])
            y.append(int(row["label"]))
    return np.array(X), np.array(y)


def main() -> None:
    csvp = Path("data/telemetry.csv")
    if not csvp.exists():
        raise SystemExit("run `python telemetry/generate.py` first")
    X, y = load(csvp)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=0)
    clf = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced")
    clf.fit(Xtr, ytr)
    proba = clf.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("Baseline RandomForest on behavioural features")
    print(f"ROC-AUC: {roc_auc_score(yte, proba):.3f}\n")
    print(classification_report(yte, pred, target_names=["benign", "malicious"], digits=3))
    print("Feature importances (what the model leans on):")
    for name, imp in sorted(zip(FEATURES, clf.feature_importances_), key=lambda kv: -kv[1]):
        print(f"  {name:<26} {imp:.3f}")
    print("\nNote: high separability here is expected — the honest challenge Sentinel")
    print("must face is evasive traffic (see repo [2] Mirage), not this clean split.")


if __name__ == "__main__":
    main()
