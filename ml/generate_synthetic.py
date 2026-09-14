"""
Generate a labeled flow CSV by capturing REAL packets from the Docker bridge
while running attack scripts in phases.

Pipeline per phase:
  1. Sniff continuously (Scapy AsyncSniffer) on `--iface`.
  2. Run the phase's shell script (e.g. lab/scripts/run_portscan.sh).
  3. Every second, snapshot the 18-feature vector for each source IP.
  4. Rows from the attacker's IP get the phase's label;
     rows from any other IP stay BENIGN.

Output CSV schema matches `src.features.FEATURE_NAMES` (18 features) so the
file is directly usable by `ml/train.py`.

Usage example (multi-phase capture):

  sudo python ml/generate_synthetic.py \
      --iface br-xxx \
      --attacker ids-attacker \
      --victim   ids-victim   \
      --out data/lab_flows.csv \
      --phase  "BENIGN:lab/scripts/benign_traffic.sh:60" \
      --phase  "PortScan:lab/scripts/run_portscan.sh:30" \
      --phase  "PortScan:lab/scripts/run_stealth_scan.sh:90" \
      --phase  "PortScan:lab/scripts/run_random_scan.sh:30" \
      --phase  "PortScan:lab/scripts/run_decoy_scan.sh:30" \
      --phase  "PortScan:lab/scripts/run_fragmented_scan.sh:60" \
      --phase  "PortScan:lab/scripts/run_mass_scan.sh:20" \
      --phase  "PortScan:lab/scripts/run_specific_scan.sh:15" \
      --phase  "PortScan:lab/scripts/run_versionscan.sh:30" \
      --phase  "PortScan:lab/scripts/run_udp_scan.sh:30" \
      --phase  "PortScan:lab/scripts/run_udpscan.sh:30" \
      --phase  "PortScan:lab/scripts/run_idle_scan.sh:30" \
      --phase  "PortScan:lab/scripts/run_chained_attack.sh:60" \
      --phase  "PortScan:lab/scripts/run_distributed_attack.sh:60" \
      --phase  "SSH-Patator:lab/scripts/run_ssh_brute.sh:60" \
      --phase  "SSH-Patator:lab/scripts/run_ssh_variants.sh:60" \
      --phase  "SSH-Patator:lab/scripts/run_slow_brute.sh:120" \
      --phase  "SSH-Patator:lab/scripts/run_distributed_brute.sh:60"
"""
from __future__ import annotations

import argparse
import csv
import logging
import queue
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.capture import PacketRecord                    # noqa: E402
from src.features import FEATURE_NAMES, SlidingWindowAggregator  # noqa: E402

log = logging.getLogger(__name__)


@dataclass
class Phase:
    label: str
    script: str
    duration: int


def parse_phase(spec: str) -> Phase:
    parts = spec.split(":", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"--phase must be LABEL:SCRIPT:DURATION, got: {spec}")
    label, script, dur = parts
    if not Path(script).exists():
        log.warning("Script not found yet: %s (will fail at run time)", script)
    return Phase(label=label.strip(), script=script.strip(), duration=int(dur))


def container_ip(name: str) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
             name],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        ).strip()
        for ip in out.split():
            if ip:
                return ip
    except subprocess.SubprocessError:
        pass
    return None


def start_sniffer(iface: str, on_pkt):
    from scapy.all import AsyncSniffer, IP, TCP, UDP

    def _h(pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        sp = dp = 0
        proto = "OTHER"
        flags = 0
        if TCP in pkt:
            proto = "TCP"
            sp = int(pkt[TCP].sport)
            dp = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            sp = int(pkt[UDP].sport) 
            dp = int(pkt[UDP].dport)
        on_pkt(PacketRecord(
            ts=time.time(), src=ip.src, dst=ip.dst,
            sport=sp, dport=dp, proto=proto, flags=flags, length=int(ip.len),
        ))

    s = AsyncSniffer(iface=iface, filter="ip", prn=_h, store=False)
    s.start()
    log.info("Scapy AsyncSniffer started on %s", iface)
    return s


def snapshot_rows(agg: SlidingWindowAggregator, label: str,
                  attacker_ip: str) -> List[dict]:
    rows = []
    for f in agg.snapshot():
        d = f.to_dict()
        d["label"] = label if (label != "BENIGN" and d["src"] == attacker_ip) else \
                     ("BENIGN" if label == "BENIGN" else "BENIGN")
        if label == "BENIGN":
            d["label"] = "BENIGN"
        rows.append(d)
    return rows


def run_phase(phase: Phase, sniffer_q: "queue.Queue[PacketRecord]",
              agg: SlidingWindowAggregator,
              attacker_ip: str, rows: list) -> None:
    log.info("=== PHASE %s | %s | %ds ===", phase.label, phase.script, phase.duration)
    proc = subprocess.Popen(["bash", phase.script],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + phase.duration
    last_snap = 0.0
    while time.time() < end:
        # drain queue
        drained = 0
        try:
            while drained < 5000:
                pkt = sniffer_q.get_nowait()
                agg.add(pkt)
                drained += 1
        except queue.Empty:
            pass
        if time.time() - last_snap >= 1.0:
            last_snap = time.time()
            agg.evict_stale()
            for r in agg.snapshot():
                d = r.to_dict()
                d["label"] = (
                    phase.label if (phase.label != "BENIGN" and d["src"] == attacker_ip)
                    else "BENIGN"
                )
                rows.append(d)
        time.sleep(0.05)
    # Stop the script if still running (long-running ones like loops)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    log.info("    captured %d snapshot rows so far", len(rows))


def main():
    ap = argparse.ArgumentParser(
        description="Capture real packets while running attack scripts → labeled CSV")
    ap.add_argument("--iface", required=True, help="Docker bridge interface, e.g. br-XXX or docker0")
    ap.add_argument("--attacker", default="ids-attacker", help="Attacker container name")
    ap.add_argument("--victim",   default="ids-victim",   help="Victim container name (just logged)")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--phase", action="append", required=True, type=parse_phase,
                    help="LABEL:SCRIPT:DURATION  (repeat for multiple phases)")
    ap.add_argument("--window", type=float, default=120.0,
                    help="Long sliding window in seconds")
    ap.add_argument("--short-window", type=float, default=5.0,
                    help="Short sliding window in seconds")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    atk_ip = container_ip(args.attacker)
    vic_ip = container_ip(args.victim)
    log.info("Attacker=%s ip=%s | Victim=%s ip=%s",
             args.attacker, atk_ip, args.victim, vic_ip)
    if atk_ip is None:
        log.error("Could not resolve attacker IP — is the lab running?")
        return 2

    pkt_q: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=200_000)
    agg = SlidingWindowAggregator(window_sec=args.window,
                                  short_window_sec=args.short_window)

    def on_pkt(rec: PacketRecord) -> None:
        try:
            pkt_q.put_nowait(rec)
        except queue.Full:
            pass

    try:
        sniffer = start_sniffer(args.iface, on_pkt)
    except PermissionError:
        log.error("Need root (CAP_NET_RAW) for sniffing")
        return 2
    except ImportError:
        log.error("Scapy not installed — pip install scapy")
        return 2

    rows: list = []
    try:
        for phase in args.phase:
            run_phase(phase, pkt_q, agg, atk_ip, rows)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    if not rows:
        log.error("No rows captured — check interface and lab health")
        return 1

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    header = ["src", "window_end", *FEATURE_NAMES, "label"]
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, 0) for k in header})

    # Summary
    from collections import Counter
    cnt = Counter(r["label"] for r in rows)
    log.info("Wrote %d rows to %s | %s", len(rows), args.out, dict(cnt))
    return 0


if __name__ == "__main__":
    sys.exit(main())

