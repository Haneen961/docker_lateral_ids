"""
Orchestrator — wires sniffer → aggregator → detectors → mitigator.

Run modes:
  threshold : rule-based only
  ml        : Random Forest only
  hybrid    : both run in parallel; ANY positive triggers mitigation
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from .alerts import AlertSink
from .capture import BridgeSniffer
from .features import SlidingWindowAggregator, IncomingAggregator
from .mitigation import Mitigator
from .threshold_detector import ThresholdDetector

LOG_FMT = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Docker Lateral Movement IDS")
    p.add_argument("--iface", default="docker0", help="Network interface to sniff")
    p.add_argument("--bpf", default="ip", help="BPF filter")
    p.add_argument("--mode", choices=["threshold", "ml", "hybrid"], default="hybrid")
    p.add_argument("--direction", choices=["outgoing", "incoming"], default="outgoing",
                   help="outgoing = attribute to sources (legacy); "
                        "incoming = attribute to attackers via destinations (recommended)")
    p.add_argument("--model", default="models/rf_model.pkl", help="RF model path (for ml/hybrid)")
    p.add_argument("--window", type=float, default=5.0, help="Sliding window seconds")
    p.add_argument("--port-scan-threshold", type=int, default=20)
    p.add_argument("--ssh-brute-threshold", type=int, default=10)
    p.add_argument("--ml-proba", type=float, default=0.7)
    p.add_argument("--tick", type=float, default=1.0, help="Detection tick seconds")
    p.add_argument("--alerts-log", default="data/alerts.jsonl")
    p.add_argument("--dry-run", action="store_true", help="Do not actually stop containers")
    p.add_argument("--whitelist", nargs="*", default=[], help="Container names/IDs to never stop")
    p.add_argument("--mute-after-stop", type=float, default=300.0,
                   help="After a container is stopped, suppress all alerts for that "
                        "source IP for N seconds (default 300). Prevents repeated "
                        "alerts on stale packets that are still in the long window.")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=LOG_FMT,
    )
    log = logging.getLogger("ids.main")

    sniffer = BridgeSniffer(iface=args.iface, bpf=args.bpf)
    if args.direction == "incoming":
        agg = IncomingAggregator(window_sec=args.window)
        log.info("Using INCOMING aggregator — attribute to attackers via destinations")
    else:
        agg = SlidingWindowAggregator(window_sec=args.window)
        log.info("Using OUTGOING aggregator (legacy) — attribute to sources")
    sink = AlertSink(path=args.alerts_log)
    mit = Mitigator(dry_run=args.dry_run, whitelist=args.whitelist)

    th_det = None
    ml_det = None
    if args.mode in ("threshold", "hybrid"):
        th_det = ThresholdDetector(
            port_scan_threshold=args.port_scan_threshold,
            ssh_brute_threshold=args.ssh_brute_threshold,
        )
    if args.mode in ("ml", "hybrid"):
        if not Path(args.model).exists():
            log.error("Model not found at %s — train it first (ml/train.py)", args.model)
            return 2
        from .ml_detector import MLDetector  # lazy import (sklearn)
        ml_det = MLDetector(model_path=args.model, proba_threshold=args.ml_proba)

    running = {"v": True}

    def _stop(*_):
        running["v"] = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    sniffer.start()
    log.info("IDS running in mode=%s on iface=%s", args.mode, args.iface)

    # src_ip -> timestamp until which we suppress alerts for that source
    muted_until: dict = {}

    last_tick = time.time()
    try:
        while running["v"]:
            pkt = sniffer.get(timeout=0.2)
            if pkt is not None:
                agg.add(pkt)

            now = time.time()
            if now - last_tick < args.tick:
                continue
            last_tick = now
            agg.evict_stale(now)

            for feats in agg.snapshot():
                # Mute check — skip sources whose container we already stopped.
                if feats.src in muted_until:
                    if now < muted_until[feats.src]:
                        continue
                    del muted_until[feats.src]

                detections = []
                if th_det is not None:
                    d = th_det.check(feats)
                    if d is not None:
                        detections.append({
                            "engine": "threshold",
                            "rule": d.rule,
                            "score": d.score,
                            "detail": d.detail,
                        })
                if ml_det is not None:
                    m = ml_det.predict(feats)
                    if m is not None:
                        # Sanity gate: only honour an ML-only alert when the
                        # source actually shows *outbound* scan/brute signal.
                        # Without this, a victim's RST reply storm gets
                        # mis-classified as PortScan and the victim is stopped.
                        looks_initiating = (
                            feats.syn_count >= 3
                            or feats.unique_dst_ports >= 3
                            or feats.unique_udp_dst_ports >= 2
                            or feats.ssh_attempts >= 2
                        )
                        if not looks_initiating:
                            log.info(
                                "ML alert suppressed for %s — no outbound "
                                "scan signal (syn=%d ports=%d udp=%d ssh=%d)",
                                feats.src, feats.syn_count,
                                feats.unique_dst_ports,
                                feats.unique_udp_dst_ports,
                                feats.ssh_attempts,
                            )
                        else:
                            detections.append({
                                "engine": "ml",
                                "label": m.label,
                                "proba": m.proba,
                            })
                if not detections:
                    continue

                stopped = mit.mitigate(
                    feats.src,
                    reason=";".join(d.get("rule", d.get("label", "?")) for d in detections),
                )
                sink.emit({
                    "src_ip": feats.src,
                    "features": feats.to_dict(),
                    "detections": detections,
                    "mitigation": {"stopped_container": stopped, "dry_run": args.dry_run},
                })
                # If we actually stopped the container, mute this source so we
                # don't keep alerting on the same stale packets in the window.
                if stopped is not None:
                    muted_until[feats.src] = now + args.mute_after_stop
                    log.info("Muting alerts for %s until +%ds",
                             feats.src, int(args.mute_after_stop))
    finally:
        sniffer.stop()
        log.info("Shutdown complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

