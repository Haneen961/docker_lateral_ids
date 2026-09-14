"""
Map CIC-IDS2017 flow CSVs onto our 18-feature schema (matches src/features.py).

Each CIC row is a single bidirectional flow → becomes one row here.
Labels kept: BENIGN, PortScan, SSH-Patator. Everything else is dropped.

Works with BOTH:
  - "TrafficLabelling" CSVs (have Source IP + Protocol)
  - "MachineLearningCVE"  CSVs (no Source IP, no Protocol — defaults applied)

Feature mapping (CIC column → ours):
   pkt_count             ← Total Fwd Packets + Total Backward Packets
   byte_count            ← Total Length of Fwd + Bwd Packets
   avg_pkt_size          ← "Average Packet Size"            (IGR paper #11)
   std_pkt_size          ← "Packet Length Std"
   pkt_len_max           ← "Max Packet Length"              (IGR paper #13)
   pkt_len_mean          ← "Packet Length Mean"             (IGR paper #10)
   bwd_pkt_len_mean      ← "Bwd Packet Length Mean"         (IGR paper #3)
   bwd_pkt_len_max       ← "Bwd Packet Length Max"          (IGR paper #9)
   unique_dst_ips        ← 1   (each CIC row = one flow → one dst)
   unique_dst_ports      ← 1 if TCP else 0
   unique_udp_dst_ports  ← 1 if Protocol == 17 (UDP) else 0
   short_unique_ports    ← 1 if TCP else 0
   syn_count             ← "SYN Flag Count"
   syn_ack_count         ← min("SYN Flag Count", "ACK Flag Count")
   fin_rst_count         ← "FIN Flag Count" + "RST Flag Count"
   psh_flag_count        ← "PSH Flag Count"                  (IGR paper #1)
   no_reply_ratio        ← 1.0 if SYN>0 and SYN_ACK==0 else 0.0   (heuristic)
   ssh_attempts          ← SYN if "Destination Port" == 22 else 0

Notes:
  - unique_dst_ports etc. are 1 per row because CIC rows are already aggregated
    to single flows. This is OK because the ML model still learns from the
    16 other features (packet sizes, flags, no_reply_ratio, etc.). Aggregation-
    based features (multiple ports per source) become useful only on the
    live-lab dataset, not on CIC.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Iterable, List

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.features import FEATURE_NAMES  # noqa: E402

log = logging.getLogger(__name__)

KEEP_LABELS = {"BENIGN", "PortScan", "SSH-Patator"}


def _iter_csvs(src: Path) -> Iterable[Path]:
    if src.is_file():
        yield src
        return
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".csv", ""}:
            yield p


def _normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    return df


def _col(df: pd.DataFrame, name: str, default=0):
    """Return Series for column name or a Series of default."""
    if name in df.columns:
        return df[name]
    return pd.Series([default] * len(df), index=df.index)


# Columns that are TRULY required (anything else has a sensible default).
REQUIRED_COLS = {"Label"}


def _build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df[df["Label"].isin(KEEP_LABELS)].copy()
    if df.empty:
        return df

    fwd_pkts = pd.to_numeric(_col(df, "Total Fwd Packets"), errors="coerce").fillna(0)
    bwd_pkts = pd.to_numeric(_col(df, "Total Backward Packets"), errors="coerce").fillna(0)
    fwd_b = pd.to_numeric(_col(df, "Total Length of Fwd Packets"), errors="coerce").fillna(0)
    bwd_b = pd.to_numeric(_col(df, "Total Length of Bwd Packets"), errors="coerce").fillna(0)

    syn = pd.to_numeric(_col(df, "SYN Flag Count"), errors="coerce").fillna(0)
    ack = pd.to_numeric(_col(df, "ACK Flag Count"), errors="coerce").fillna(0)
    fin = pd.to_numeric(_col(df, "FIN Flag Count"), errors="coerce").fillna(0)
    rst = pd.to_numeric(_col(df, "RST Flag Count"), errors="coerce").fillna(0)
    psh = pd.to_numeric(_col(df, "PSH Flag Count"), errors="coerce").fillna(0)

    dport = pd.to_numeric(_col(df, "Destination Port"), errors="coerce").fillna(0).astype(int)
    # MachineLearningCVE files don't carry "Protocol" — default to TCP (6).
    proto = pd.to_numeric(_col(df, "Protocol", default=6), errors="coerce").fillna(6).astype(int)

    avg_pkt_sz = pd.to_numeric(_col(df, "Average Packet Size"), errors="coerce").fillna(0)
    pkt_len_max = pd.to_numeric(_col(df, "Max Packet Length"), errors="coerce").fillna(0)
    pkt_len_mean = pd.to_numeric(_col(df, "Packet Length Mean"), errors="coerce").fillna(0)
    pkt_len_std = pd.to_numeric(_col(df, "Packet Length Std"), errors="coerce").fillna(0)
    bwd_mean = pd.to_numeric(_col(df, "Bwd Packet Length Mean"), errors="coerce").fillna(0)
    bwd_max = pd.to_numeric(_col(df, "Bwd Packet Length Max"), errors="coerce").fillna(0)

    syn_ack = np.minimum(syn, ack)
    udp_mask = (proto == 17).astype(int)
    no_reply = np.where((syn > 0) & (syn_ack == 0), 1.0, 0.0)
    ssh_attempts = np.where(dport == 22, syn, 0)

    src_ip = _col(df, "Source IP", "0.0.0.0").astype(str)
    # In MachineLearningCVE files Source IP is absent — synthesize a stable
    # pseudo-IP per row so 'src' isn't all "0.0.0.0" (matters for some stats).
    if "Source IP" not in df.columns:
        src_ip = pd.Series([f"cic-{i}" for i in range(len(df))], index=df.index)

    out = pd.DataFrame({
        "src": src_ip,
        "window_end": 0.0,
        "pkt_count": (fwd_pkts + bwd_pkts).astype(int),
        "byte_count": (fwd_b + bwd_b).astype(int),
        "avg_pkt_size": avg_pkt_sz.astype(float),
        "std_pkt_size": pkt_len_std.astype(float),
        "pkt_len_max": pkt_len_max.astype(float),
        "pkt_len_mean": pkt_len_mean.astype(float),
        "bwd_pkt_len_mean": bwd_mean.astype(float),
        "bwd_pkt_len_max": bwd_max.astype(float),
        "unique_dst_ips": 1,
        "unique_dst_ports": (1 - udp_mask).astype(int),       # TCP flows → 1; UDP → 0
        "unique_udp_dst_ports": udp_mask,
        "short_unique_ports": (1 - udp_mask).astype(int),
        "syn_count": syn.astype(int),
        "syn_ack_count": syn_ack.astype(int),
        "fin_rst_count": (fin + rst).astype(int),
        "psh_flag_count": psh.astype(int),
        "no_reply_ratio": no_reply.astype(float),
        "ssh_attempts": ssh_attempts.astype(int),
        "label": df["Label"].values,
    })
    # Replace inf and clip
    for c in FEATURE_NAMES:
        out[c] = out[c].replace([np.inf, -np.inf], np.nan).fillna(0)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Map CIC-IDS2017 CSVs to the 18-feature schema used by this IDS")
    ap.add_argument("--src", required=True,
                    help="CIC-IDS2017 CSV file OR a directory containing them")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--max-benign", type=int, default=200_000,
                    help="Cap BENIGN rows so the class isn't overwhelming")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    parts: List[pd.DataFrame] = []
    src = Path(args.src)
    for p in _iter_csvs(src):
        log.info("Reading %s", p)
        try:
            df = pd.read_csv(p, low_memory=False, encoding="latin-1")
        except Exception as e:
            log.warning("  skip (parse error): %s", e)
            continue
        df = _normalize_cols(df)
        if "Label" not in df.columns:
            log.warning("  skip (no Label column): %s", p.name)
            continue
        sub = _build_features(df)
        if sub.empty:
            log.warning("  skip (no matching labels): %s", p.name)
            continue
        log.info("  → %d rows kept | %s",
                 len(sub), sub["label"].value_counts().to_dict())
        parts.append(sub)

    if not parts:
        raise SystemExit("No matching CIC rows found.")

    full = pd.concat(parts, ignore_index=True)
    benign = full[full["label"] == "BENIGN"]
    attack = full[full["label"] != "BENIGN"]
    if len(benign) > args.max_benign:
        benign = benign.sample(args.max_benign, random_state=42)
    full = pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=42)

    cols = ["src", "window_end", *FEATURE_NAMES, "label"]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    full[cols].to_csv(out, index=False)
    log.info("Wrote %d rows → %s", len(full), out)
    log.info("Final label distribution: %s",
             full["label"].value_counts().to_dict())


if __name__ == "__main__":
    main()
