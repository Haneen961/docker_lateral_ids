"""
Realistic offline synthetic dataset — includes EVASION variants so the model
learns stealth, slow, UDP, decoy, version, and specific-port scans.

Output schema matches src/features.FEATURE_NAMES (18 features).
"""
from __future__ import annotations

import argparse
import logging
import random
import sys
from pathlib import Path
from typing import List

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.features import FEATURE_NAMES  # noqa: E402

log = logging.getLogger(__name__)


def _row(label: str, src: str, base: dict) -> dict:
    out = {"src": src, "window_end": 0.0, "label": label}
    out.update({k: base.get(k, 0) for k in FEATURE_NAMES})
    return out


def gen(n_benign: int, n_scan: int, n_brute: int,
        seed: int = 7, noise: float = 0.04) -> pd.DataFrame:
    rng = random.Random(seed)
    rows: List[dict] = []

    def j(x, pct=0.15):
        return max(0.0, x * (1.0 + rng.uniform(-pct, pct)))

    # ---------------- BENIGN ----------------
    for _ in range(n_benign):
        k = rng.random()
        src = f"10.0.0.{rng.randint(2, 50)}"
        if k < 0.65:                      # plain web traffic
            pkts = rng.randint(10, 60)
            ports = rng.choice([1, 1, 2, 3])
            psh = rng.randint(2, 20)
            bwd_mean = rng.uniform(400, 1200)
            bwd_max = bwd_mean * rng.uniform(1.0, 1.3)
            avg = rng.uniform(300, 1400)
            base = dict(
                pkt_count=pkts, byte_count=int(pkts * avg),
                avg_pkt_size=j(avg), std_pkt_size=j(rng.uniform(50, 300), 0.3),
                pkt_len_max=j(avg * 1.4), pkt_len_mean=j(avg),
                bwd_pkt_len_mean=j(bwd_mean), bwd_pkt_len_max=j(bwd_max),
                unique_dst_ips=rng.choice([1, 1, 2, 3]),
                unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=ports,
                syn_count=rng.randint(1, 5),
                syn_ack_count=rng.randint(1, 5),
                fin_rst_count=rng.randint(0, 4),
                psh_flag_count=psh,
                no_reply_ratio=rng.uniform(0.0, 0.2),
                ssh_attempts=0,
            )
        elif k < 0.80:                    # monitoring agent — multi-port but talks back
            pkts = rng.randint(40, 150)
    
            ports = rng.randint(5, 18)
            base = dict(
                pkt_count=pkts, byte_count=int(pkts * 300),
                avg_pkt_size=j(300), std_pkt_size=j(150, 0.3),
                pkt_len_max=j(900), pkt_len_mean=j(300),
                bwd_pkt_len_mean=j(250), bwd_pkt_len_max=j(800),
                unique_dst_ips=rng.choice([1, 2]),
                unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=rng.randint(2, 6),
                syn_count=rng.randint(5, 20),
                syn_ack_count=rng.randint(5, 20),       # gets replies
                fin_rst_count=rng.randint(2, 8),
                psh_flag_count=rng.randint(10, 40),
                no_reply_ratio=rng.uniform(0.0, 0.3),
                ssh_attempts=0,
            )
        else:                              # benign DNS / NTP (UDP) — few ports
            base = dict(
                pkt_count=rng.randint(20, 80), byte_count=rng.randint(2000, 8000),
                avg_pkt_size=j(120), std_pkt_size=j(40, 0.3),
                pkt_len_max=j(300), pkt_len_mean=j(120),
                bwd_pkt_len_mean=j(120), bwd_pkt_len_max=j(300),
                unique_dst_ips=rng.choice([1, 2]),
                unique_dst_ports=0, unique_udp_dst_ports=rng.randint(1, 2),
                short_unique_ports=0,
                syn_count=0, syn_ack_count=0, fin_rst_count=0,
                psh_flag_count=0, no_reply_ratio=0.0, ssh_attempts=0,
            )
        rows.append(_row("BENIGN", src, base))

    # ---------------- PortScan (incl. evasion) ----------------
    for _ in range(n_scan):
        src = f"10.0.0.{rng.randint(100, 130)}"
        variant = rng.choice([
            "aggressive", "mass", "stealth_slow", "random", "specific",
            "fragmented", "decoy", "version",
        ])
        if variant in ("aggressive", "mass"):
            ports = rng.randint(500, 5000)
            base = dict(
                pkt_count=ports, byte_count=ports * 60,
                avg_pkt_size=j(60, 0.05), std_pkt_size=j(2, 0.5),
                pkt_len_max=j(80), pkt_len_mean=j(60),
                bwd_pkt_len_mean=j(60), bwd_pkt_len_max=j(80),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=min(ports, rng.randint(200, 2000)),
                syn_count=ports, syn_ack_count=rng.randint(0, ports // 50),
                fin_rst_count=rng.randint(ports // 4, ports // 2),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.85, 1.0), ssh_attempts=0,
            )
        elif variant == "stealth_slow":               # T1, --scan-delay 1s
            ports = rng.randint(30, 250)
            base = dict(
                pkt_count=ports, byte_count=ports * 60,
                avg_pkt_size=j(60, 0.05), std_pkt_size=j(2, 0.5),
                pkt_len_max=j(80), pkt_len_mean=j(60),
                bwd_pkt_len_mean=j(60), bwd_pkt_len_max=j(80),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=rng.randint(1, 6),     # KEY: short window low
                syn_count=ports, syn_ack_count=rng.randint(0, ports // 50),
                fin_rst_count=rng.randint(ports // 4, ports // 2),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.85, 1.0), ssh_attempts=0,
            )
        elif variant == "random":
            ports = rng.randint(300, 600)
            base = dict(
                pkt_count=ports, byte_count=ports * 60,
                avg_pkt_size=j(60, 0.05), std_pkt_size=j(2, 0.5),
                pkt_len_max=j(80), pkt_len_mean=j(60),
                bwd_pkt_len_mean=j(60), bwd_pkt_len_max=j(80),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=min(ports, rng.randint(100, 400)),
                syn_count=ports, syn_ack_count=rng.randint(0, ports // 50),
                fin_rst_count=rng.randint(ports // 4, ports // 2),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.85, 1.0), ssh_attempts=0,
            )
        elif variant == "specific":                  # 4-10 targeted ports
            ports = rng.randint(4, 12)
            base = dict(
                pkt_count=ports, byte_count=ports * 60,
                avg_pkt_size=j(60, 0.05), std_pkt_size=j(2, 0.5),
                pkt_len_max=j(80), pkt_len_mean=j(60),
                bwd_pkt_len_mean=j(60), bwd_pkt_len_max=j(80),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=ports,
                syn_count=ports, syn_ack_count=rng.randint(0, max(1, ports // 4)),
                fin_rst_count=rng.randint(0, ports),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.6, 0.95), ssh_attempts=0,
            )
        elif variant == "fragmented":
            ports = rng.randint(200, 1000)
            base = dict(
                pkt_count=ports * 2, byte_count=ports * 40,
                avg_pkt_size=j(20, 0.1), std_pkt_size=j(2, 0.5),  # tiny frags
                pkt_len_max=j(40), pkt_len_mean=j(20),
                bwd_pkt_len_mean=j(40), bwd_pkt_len_max=j(60),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=min(ports, rng.randint(100, 500)),
                syn_count=ports, syn_ack_count=rng.randint(0, ports // 50),
                fin_rst_count=rng.randint(ports // 4, ports // 2),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.85, 1.0), ssh_attempts=0,
            )
        elif variant == "decoy":
            ports = rng.randint(500, 1000)
            base = dict(
                pkt_count=ports, byte_count=ports * 60,
                avg_pkt_size=j(60, 0.05), std_pkt_size=j(2, 0.5),
                pkt_len_max=j(80), pkt_len_mean=j(60),
                bwd_pkt_len_mean=j(60), bwd_pkt_len_max=j(80),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=rng.randint(50, 200),
                syn_count=ports, syn_ack_count=rng.randint(0, ports // 50),
                fin_rst_count=rng.randint(ports // 4, ports // 2),
                psh_flag_count=0,
                no_reply_ratio=rng.uniform(0.9, 1.0), ssh_attempts=0,
            )
        else:                                         # version scan -sV  (4 ports + payload)
            ports = rng.randint(3, 8)
            base = dict(
                pkt_count=rng.randint(30, 80), byte_count=rng.randint(2000, 6000),
                avg_pkt_size=j(150), std_pkt_size=j(80, 0.3),
                pkt_len_max=j(800), pkt_len_mean=j(150),
                bwd_pkt_len_mean=j(200), bwd_pkt_len_max=j(900),
                unique_dst_ips=1, unique_dst_ports=ports, unique_udp_dst_ports=0,
                short_unique_ports=ports,
                syn_count=ports, syn_ack_count=rng.randint(1, ports),
                fin_rst_count=rng.randint(0, ports),
                psh_flag_count=rng.randint(5, 20),
                no_reply_ratio=rng.uniform(0.3, 0.8), ssh_attempts=0,
            )
        rows.append(_row("PortScan", src, base))

    # UDP scan variant
    for _ in range(max(1, n_scan // 8)):
        uports = rng.randint(6, 50)
        base = dict(
            pkt_count=uports, byte_count=uports * 80,
            avg_pkt_size=j(80), std_pkt_size=j(10, 0.5),
            pkt_len_max=j(100), pkt_len_mean=j(80),
            bwd_pkt_len_mean=j(100), bwd_pkt_len_max=j(200),
            unique_dst_ips=1, unique_dst_ports=0, unique_udp_dst_ports=uports,
            short_unique_ports=0,
            syn_count=0, syn_ack_count=0, fin_rst_count=0,
            psh_flag_count=0, no_reply_ratio=0.0, ssh_attempts=0,
        )
        rows.append(_row("PortScan", f"10.0.0.{rng.randint(130, 150)}", base))

    # ---------------- SSH-Patator ----------------
    for _ in range(n_brute):
        att = rng.randint(8, 100) if rng.random() > 0.15 else rng.randint(5, 12)
        pkts = att * 3
        base = dict(
            pkt_count=pkts, byte_count=pkts * 80,
            avg_pkt_size=j(80, 0.1), std_pkt_size=j(5, 0.4),
            pkt_len_max=j(120), pkt_len_mean=j(80),
            bwd_pkt_len_mean=j(80), bwd_pkt_len_max=j(120),
            unique_dst_ips=1, unique_dst_ports=1, unique_udp_dst_ports=0,
            short_unique_ports=1,
            syn_count=att, syn_ack_count=rng.randint(att // 2, att),
            fin_rst_count=rng.randint(att // 2, att),
            psh_flag_count=rng.randint(att, att * 3),
            no_reply_ratio=rng.uniform(0.0, 0.3),
            ssh_attempts=att,
        )
        rows.append(_row("SSH-Patator", f"10.0.0.{rng.randint(200, 220)}", base))

    # Label noise
    labels = ["BENIGN", "PortScan", "SSH-Patator"]
    n_noise = int(len(rows) * noise)
    for idx in rng.sample(range(len(rows)), n_noise):
        rows[idx]["label"] = rng.choice([lab for lab in labels if lab != rows[idx]["label"]])

    rng.shuffle(rows)
    cols = ["src", "window_end", *FEATURE_NAMES, "label"]
    return pd.DataFrame(rows)[cols]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rows", type=int, default=6000)
    ap.add_argument("--noise", type=float, default=0.04)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    n = args.rows
    n_b = n // 2
    n_s = (n - n_b) // 2
    n_h = n - n_b - n_s
    df = gen(n_b, n_s, n_h, noise=args.noise)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    log.info("Wrote %d rows -> %s | %s",
             len(df), args.out, df["label"].value_counts().to_dict())


if __name__ == "__main__":
    main()

