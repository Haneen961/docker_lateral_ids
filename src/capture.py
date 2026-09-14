"""
Live packet capture on a Docker bridge interface using Scapy's AsyncSniffer.

The sniffer pushes lightweight packet dicts onto a queue consumed by the
feature aggregator. Keeping the sniffer thread minimal (no parsing of higher
layers) is critical to avoid drops at high pps.
"""

from __future__ import annotations

import logging
import queue
import time
from dataclasses import dataclass
from typing import Optional

from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP

log = logging.getLogger(__name__)


@dataclass
class PacketRecord:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str  # "TCP" | "UDP" | "OTHER"
    flags: int  # TCP flags bitfield (0 for non-TCP)
    length: int  # IP total length


class BridgeSniffer:
    """AsyncSniffer wrapper that emits PacketRecord on a queue."""

    def __init__(self, iface: str, bpf: str = "ip", maxsize: int = 100_000):
        self.iface = iface
        self.bpf = bpf
        self.q: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=maxsize)
        self._sniffer: Optional[AsyncSniffer] = None
        self.dropped = 0

    def _on_pkt(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        sport = dport = 0
        proto = "OTHER"
        flags = 0
        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)

        rec = PacketRecord(
            ts=time.time(),
            src=ip.src,
            dst=ip.dst,
            sport=sport,
            dport=dport,
            proto=proto,
            flags=flags,
            length=int(ip.len),
        )
        try:
            self.q.put_nowait(rec)
        except queue.Full:
            self.dropped += 1

    def start(self):
        log.info("Starting sniffer on %s (bpf=%r)", self.iface, self.bpf)
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf,
            prn=self._on_pkt,
            store=False,
        )
        self._sniffer.start()

    def stop(self):
        if self._sniffer is not None:
            self._sniffer.stop()
            log.info("Sniffer stopped. Dropped=%d", self.dropped)

    def get(self, timeout: float = 0.5) -> Optional[PacketRecord]:
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None
