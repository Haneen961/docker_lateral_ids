"""
Train a Random Forest classifier on a labeled flow-feature CSV.

CSV schema:
    src, window_end, pkt_count, byte_count, avg_pkt_size, std_pkt_size,
    unique_dst_ips, unique_dst_ports, syn_count, syn_ack_count,
    fin_rst_count, flow_duration, pkts_per_sec, ssh_attempts, label

Output: joblib bundle {"model": rf, "feature_names": [...], "classes": [...]}
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.features import FEATURE_NAMES  # noqa: E402

log = logging.getLogger(__name__)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to labeled CSV")
    ap.add_argument("--out", default="models/rf_model.pkl")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--cv", type=int, default=5, help="CV folds (0 to disable)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    df = pd.read_csv(args.data)
    missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing columns: {missing}")

    log.info(
        "Loaded %d rows | label distribution: %s",
        len(df),
        df["label"].value_counts().to_dict(),
    )

    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].astype(str).to_numpy()

    Xtr, Xte, ytr, yte = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        n_jobs=-1,
        class_weight="balanced",
        random_state=args.seed,
    )

    if args.cv and len(np.unique(ytr)) > 1:
        skf = StratifiedKFold(n_splits=args.cv, shuffle=True, random_state=args.seed)
        cv_res = cross_validate(
            rf,
            Xtr,
            ytr,
            cv=skf,
            scoring=["accuracy", "precision_macro", "recall_macro", "f1_macro"],
            n_jobs=-1,
        )
        for k, v in cv_res.items():
            if k.startswith("test_"):
                log.info("CV %s: %.4f ± %.4f", k, v.mean(), v.std())

    rf.fit(Xtr, ytr)
    yhat = rf.predict(Xte)
    log.info("Holdout report:%s", classification_report(yte, yhat, digits=4))
    log.info(
        "Confusion matrix (rows=true, cols=pred):%s",
        confusion_matrix(yte, yhat, labels=sorted(np.unique(y))),
    )

    # Feature importances
    imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: -x[1])
    log.info(
        "Top features: %s",
        json.dumps([(n, round(float(v), 4)) for n, v in imp], indent=2),
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": rf,
            "feature_names": FEATURE_NAMES,
            "classes": list(rf.classes_),
            "importances": [(n, float(v)) for n, v in imp],
        },
        out,
    )
    log.info("Saved model to %s", out)


if __name__ == "__main__":
    main()
