"""
Multi-rule threshold detector — covers aggressive AND evasion variants.

Rules (any one triggers an alert):
  R1  AGGRESSIVE_SCAN   — short_unique_ports >= short_thr  (fast burst)
  R2  STEALTH_SCAN      — unique_dst_ports >= long_thr     (slow over 120 s)
  R3  UDP_SCAN          — unique_udp_dst_ports >= udp_thr
  R4  HIGH_NO_REPLY     — syn >= min_syn AND no_reply_ratio >= 0.75
                          (catches stealth/decoy: many SYNs, almost no replies)
  R5  SSH_BRUTE         — ssh_attempts >= ssh_thr
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional

from .features import FlowFeatures


@dataclass
class Detection:
    src: str
    rule: str
    score: float
    detail: str
    ts: float


class ThresholdDetector:
    def __init__(
        self,
        port_scan_threshold: int = 12,        # short window TCP unique ports
        long_port_scan_threshold: int = 25,   # long window TCP unique ports (stealth)
        udp_scan_threshold: int = 5,          # UDP unique ports
        no_reply_min_syn: int = 15,           # min SYNs before no-reply rule applies
        no_reply_ratio: float = 0.75,
        ssh_brute_threshold: int = 8,
        cooldown_sec: float = 180.0,
    ):
        self.short_thr = port_scan_threshold
        self.long_thr = long_port_scan_threshold
        self.udp_thr = udp_scan_threshold
        self.no_reply_min_syn = no_reply_min_syn
        self.no_reply_ratio = no_reply_ratio
        self.ssh_thr = ssh_brute_threshold
        self.cooldown_sec = cooldown_sec
        self._last: Dict[str, float] = {}

    def _ok(self, key: str) -> bool:
        last = self._last.get(key, 0.0)
        now = time.time()
        if now - last < self.cooldown_sec:
            return False
        self._last[key] = now
        return True

    def check(self, f: FlowFeatures) -> Optional[Detection]:
        # SSH brute first (most specific)
        if f.ssh_attempts >= self.ssh_thr and self._ok(f"{f.src}|SSH"):
            return Detection(f.src, "SSH_BRUTE", float(f.ssh_attempts),
                             f"{f.ssh_attempts} SSH SYNs", f.window_end)
        if f.unique_udp_dst_ports >= self.udp_thr and self._ok(f"{f.src}|UDP"):
            return Detection(f.src, "UDP_SCAN", float(f.unique_udp_dst_ports),
                             f"{f.unique_udp_dst_ports} unique UDP ports", f.window_end)
        if f.short_unique_ports >= self.short_thr and self._ok(f"{f.src}|FAST"):
            return Detection(f.src, "AGGRESSIVE_SCAN", float(f.short_unique_ports),
                             f"{f.short_unique_ports} TCP ports in 5 s", f.window_end)
        if f.unique_dst_ports >= self.long_thr and self._ok(f"{f.src}|SLOW"):
            return Detection(f.src, "STEALTH_SCAN", float(f.unique_dst_ports),
                             f"{f.unique_dst_ports} TCP ports in 120 s", f.window_end)
        if (f.syn_count >= self.no_reply_min_syn
                and f.no_reply_ratio >= self.no_reply_ratio
                and self._ok(f"{f.src}|NOREPLY")):
            return Detection(f.src, "HIGH_NO_REPLY", f.no_reply_ratio,
                             f"{int(f.no_reply_ratio*100)}% unanswered SYNs "
                             f"({f.syn_count} SYNs)", f.window_end)
        return None

    # Back-compat with older callers
    @property
    def port_scan_threshold(self) -> int:
        return self.short_thr

    @property
    def ssh_brute_threshold(self) -> int:
        return self.ssh_thr

