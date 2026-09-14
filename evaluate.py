"""
Offline evaluation: Threshold vs ML on a labeled CSV.

Reports per detector:
  - Precision, Recall, F1, FPR (BENIGN = negative)
  - Mean inference latency (ms / sample)
  - Approximate CPU% during evaluation
  - Per-rule trigger counts for the threshold detector (so you can see which
    rule fired for which attack family — useful when comparing evasion variants)
"""
from __future__ import annotations

import argparse
import logging
import time
from collections import Counter
from pathlib import Path


import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.features import FEATURE_NAMES, FlowFeatures  # noqa: E402
from src.threshold_detector import ThresholdDetector   # noqa: E402

log = logging.getLogger(__name__)


def _row_to_features(row: pd.Series) -> FlowFeatures:
    return FlowFeatures(
        src=str(row.get("src", "?")),
        window_end=float(row.get("window_end", 0.0)),
        pkt_count=int(row["pkt_count"]),
        byte_count=int(row["byte_count"]),
        avg_pkt_size=float(row["avg_pkt_size"]),
        std_pkt_size=float(row["std_pkt_size"]),
        pkt_len_max=float(row["pkt_len_max"]),
        pkt_len_mean=float(row["pkt_len_mean"]),
        bwd_pkt_len_mean=float(row["bwd_pkt_len_mean"]),
        bwd_pkt_len_max=float(row["bwd_pkt_len_max"]),
        unique_dst_ips=int(row["unique_dst_ips"]),
        unique_dst_ports=int(row["unique_dst_ports"]),
        unique_udp_dst_ports=int(row["unique_udp_dst_ports"]),
        short_unique_ports=int(row["short_unique_ports"]),
        syn_count=int(row["syn_count"]),
        syn_ack_count=int(row["syn_ack_count"]),
        fin_rst_count=int(row["fin_rst_count"]),
        psh_flag_count=int(row["psh_flag_count"]),
        no_reply_ratio=float(row["no_reply_ratio"]),
        ssh_attempts=int(row["ssh_attempts"]),
    )


def _binary(y) -> np.ndarray:
    return np.array([0 if str(v).upper() == "BENIGN" else 1 for v in y])


def _metrics(name: str, y_true, y_pred, total_ms: float, n: int,
             cpu: float) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0,
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / max(fp + tn, 1)
    log.info("[%s] P=%.4f R=%.4f F1=%.4f FPR=%.4f (TP=%d FP=%d FN=%d TN=%d)",
             name, p, r, f1, fpr, tp, fp, fn, tn)
    return {
        "detector": name,
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "latency_ms_per_sample": round(total_ms / max(n, 1), 4),
        "cpu_percent": round(cpu, 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", default="models/rf_model.pkl")
    # Threshold knobs (must match runtime defaults)
    ap.add_argument("--port-scan-threshold", type=int, default=12,
                    help="Short-window TCP unique ports (aggressive)")
    ap.add_argument("--long-port-scan-threshold", type=int, default=25,
                    help="Long-window TCP unique ports (stealth)")
    ap.add_argument("--udp-scan-threshold", type=int, default=5)
    ap.add_argument("--no-reply-min-syn", type=int, default=15)
    ap.add_argument("--no-reply-ratio", type=float, default=0.75)
    ap.add_argument("--ssh-brute-threshold", type=int, default=8)
    ap.add_argument("--ml-proba", type=float, default=0.7)
    ap.add_argument("--out", default="data/evaluation_report.csv")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    df = pd.read_csv(args.data)
    missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing required columns: {missing}")

    y = df["label"].astype(str).to_numpy()
    y_bin = _binary(y)
    proc = psutil.Process()

    # ---------------------- Threshold ----------------------
    th = ThresholdDetector(
        port_scan_threshold=args.port_scan_threshold,
        long_port_scan_threshold=args.long_port_scan_threshold,
        udp_scan_threshold=args.udp_scan_threshold,
        no_reply_min_syn=args.no_reply_min_syn,
        no_reply_ratio=args.no_reply_ratio,
        ssh_brute_threshold=args.ssh_brute_threshold,
        cooldown_sec=0.0,    # disable cooldown for offline scoring
    )
    th_pred = np.zeros(len(df), dtype=int)
    rule_counter: Counter = Counter()
    rule_by_label: dict = {}
    proc.cpu_percent(None)
    t0 = time.perf_counter()
    for i, row in df.iterrows():
        feats = _row_to_features(row)
        det = th.check(feats)
        if det is not None:
            th_pred[i] = 1
            rule_counter[det.rule] += 1
            key = (str(row["label"]), det.rule)
            rule_by_label[key] = rule_by_label.get(key, 0) + 1
    t_th = (time.perf_counter() - t0) * 1000.0
    cpu_th = proc.cpu_percent(None)
    log.info("Threshold rule counts: %s", dict(rule_counter))
    log.info("Threshold rule x label: %s", rule_by_label)

    # ---------------------- ML ----------------------
    ml_metrics = None
    if Path(args.model).exists():
        bundle = joblib.load(args.model)
        model = bundle["model"]
        classes = list(bundle.get("classes", model.classes_))
        feat_names = bundle.get("feature_names", FEATURE_NAMES)
        if list(feat_names) != FEATURE_NAMES:
            log.warning("Model feature order differs — using stored order")
        X = df[list(feat_names)].to_numpy(dtype=float)
        proc.cpu_percent(None)
        t0 = time.perf_counter()
        probs = model.predict_proba(X)
        t_ml = (time.perf_counter() - t0) * 1000.0
        cpu_ml = proc.cpu_percent(None)
        atk_idx = [i for i, c in enumerate(classes) if str(c).upper() != "BENIGN"]
        atk_p = probs[:, atk_idx].sum(axis=1) if atk_idx else np.zeros(len(df))
        ml_pred = (atk_p >= args.ml_proba).astype(int)
        ml_metrics = _metrics("ML", y_bin, ml_pred, t_ml, len(df), cpu_ml)
    else:
        log.warning("Model %s not found — skipping ML evaluation", args.model)

    th_metrics = _metrics("Threshold", y_bin, th_pred, t_th, len(df), cpu_th)
    rows = [th_metrics] + ([ml_metrics] if ml_metrics else [])
    out_df = pd.DataFrame(rows)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_path, index=False)
    log.info("%s", out_df.to_string(index=False))
    log.info("Report saved to %s", out_path)


if __name__ == "__main__":
    main()

