"""
Dual-window flow feature extraction with paper-aligned features.

Windows:
  * SHORT (default 5 s)  — catches aggressive / mass scans.
  * LONG  (default 120 s) — catches stealth / slow / decoy / version scans.

Per source IP we maintain a deque of recent PacketRecords and compute a rich
18-feature vector. Names align with the IGR paper (Table 2) where applicable
so the RF model can learn the same discriminative signals.

Feature schema (18 features):
   pkt_count            : packets in long window
   byte_count           : sum of IP lengths (long)
   avg_pkt_size         : mean packet size (paper #11)
   std_pkt_size         : stddev packet size
   pkt_len_max          : max packet size (paper #13)
   pkt_len_mean         : mean packet size (paper #10)
   bwd_pkt_len_mean     : mean response packet size to this src (paper #3)
   bwd_pkt_len_max      : max response packet size (paper #9)
   unique_dst_ips       : distinct destination IPs (long)
   unique_dst_ports     : distinct TCP destination ports (long)
   unique_udp_dst_ports : distinct UDP destination ports (long)
   short_unique_ports   : distinct TCP dst ports in SHORT window (fast scans)
   syn_count            : TCP SYN-only packets (long)
   syn_ack_count        : TCP SYN+ACK packets (long)
   fin_rst_count        : TCP FIN or RST packets (long)
   psh_flag_count       : TCP PSH packets (paper #1)
   no_reply_ratio       : (syn - syn_ack) / max(syn,1)  — scans get no reply
   ssh_attempts         : SYNs to dport 22 (long)
"""
from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, List, Optional

from .capture import PacketRecord

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

FEATURE_NAMES: List[str] = [
    "pkt_count", "byte_count", "avg_pkt_size", "std_pkt_size",
    "pkt_len_max", "pkt_len_mean", "bwd_pkt_len_mean", "bwd_pkt_len_max",
    "unique_dst_ips", "unique_dst_ports", "unique_udp_dst_ports",
    "short_unique_ports", "syn_count", "syn_ack_count", "fin_rst_count",
    "psh_flag_count", "no_reply_ratio", "ssh_attempts",
]


@dataclass
class FlowFeatures:
    src: str
    window_end: float
    pkt_count: int
    byte_count: int
    avg_pkt_size: float
    std_pkt_size: float
    pkt_len_max: float
    pkt_len_mean: float
    bwd_pkt_len_mean: float
    bwd_pkt_len_max: float
    unique_dst_ips: int
    unique_dst_ports: int
    unique_udp_dst_ports: int
    short_unique_ports: int
    syn_count: int
    syn_ack_count: int
    fin_rst_count: int
    psh_flag_count: int
    no_reply_ratio: float
    ssh_attempts: int

    def vector(self) -> List[float]:
        return [getattr(self, n) for n in FEATURE_NAMES]

    def to_dict(self) -> dict:
        return asdict(self)

    def as_dict(self) -> dict:    # back-compat alias
        return self.to_dict()


class SlidingWindowAggregator:
    """
    Dual-window per-source-IP aggregator.

    `long_window_sec`  — used for the feature vector (default 120 s)
    `short_window_sec` — used only to compute `short_unique_ports`
    """

    def __init__(self, window_sec: float = 120.0, short_window_sec: float = 5.0):
        self.long_window = window_sec
        self.short_window = short_window_sec
        # forward packets keyed by src
        self._fwd: Dict[str, Deque[PacketRecord]] = defaultdict(deque)
        # backward packets keyed by *src of the original direction* (i.e. responses sent to src)
        self._bwd: Dict[str, Deque[PacketRecord]] = defaultdict(deque)

    def add(self, pkt: PacketRecord) -> None:
        # Treat every packet twice: as forward from its src, and as backward to its dst.
        cutoff = pkt.ts - self.long_window
        dq_f = self._fwd[pkt.src]
        dq_f.append(pkt)
        while dq_f and dq_f[0].ts < cutoff:
            dq_f.popleft()
        dq_b = self._bwd[pkt.dst]
        dq_b.append(pkt)
        while dq_b and dq_b[0].ts < cutoff:
            dq_b.popleft()

    def evict_stale(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        cutoff = now - self.long_window
        for table in (self._fwd, self._bwd):
            drop = []
            for k, dq in table.items():
                while dq and dq[0].ts < cutoff:
                    dq.popleft()
                if not dq:
                    drop.append(k)
            for k in drop:
                del table[k]

    def compute(self, src: str) -> Optional[FlowFeatures]:
        fwd = self._fwd.get(src)
        if not fwd:
            return None
        fwd_pkts = list(fwd)
        bwd_pkts = list(self._bwd.get(src, []))

        sizes = [p.length for p in fwd_pkts]
        bwd_sizes = [p.length for p in bwd_pkts]

        dst_ips = {p.dst for p in fwd_pkts}
        tcp_dports = {p.dport for p in fwd_pkts if p.proto == "TCP" and p.dport}
        udp_dports = {p.dport for p in fwd_pkts if p.proto == "UDP" and p.dport}

        now = fwd_pkts[-1].ts
        short_cutoff = now - self.short_window
        short_ports = {p.dport for p in fwd_pkts
                       if p.proto == "TCP" and p.dport and p.ts >= short_cutoff}

        syn = sum(1 for p in fwd_pkts if p.proto == "TCP"
                  and (p.flags & TCP_SYN) and not (p.flags & TCP_ACK))
        syn_ack_recv = sum(1 for p in bwd_pkts if p.proto == "TCP"
                           and (p.flags & TCP_SYN) and (p.flags & TCP_ACK))
        fin_rst = sum(1 for p in fwd_pkts if p.proto == "TCP"
                      and (p.flags & (TCP_FIN | TCP_RST)))
        psh = sum(1 for p in fwd_pkts if p.proto == "TCP" and (p.flags & TCP_PSH))
        ssh = sum(1 for p in fwd_pkts if p.proto == "TCP" and p.dport == 22
                  and (p.flags & TCP_SYN))

        no_reply_ratio = max(0.0, (syn - syn_ack_recv)) / max(syn, 1)

        return FlowFeatures(
            src=src, window_end=now,
            pkt_count=len(fwd_pkts), byte_count=sum(sizes),
            avg_pkt_size=sum(sizes) / len(sizes),
            std_pkt_size=statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            pkt_len_max=float(max(sizes)),
            pkt_len_mean=sum(sizes) / len(sizes),
            bwd_pkt_len_mean=(sum(bwd_sizes) / len(bwd_sizes)) if bwd_sizes else 0.0,
            bwd_pkt_len_max=float(max(bwd_sizes)) if bwd_sizes else 0.0,
            unique_dst_ips=len(dst_ips),
            unique_dst_ports=len(tcp_dports),
            unique_udp_dst_ports=len(udp_dports),
            short_unique_ports=len(short_ports),
            syn_count=syn, syn_ack_count=syn_ack_recv, fin_rst_count=fin_rst,
            psh_flag_count=psh, no_reply_ratio=no_reply_ratio,
            ssh_attempts=ssh,
        )

    def all_sources(self) -> List[str]:
        return list(self._fwd.keys())

    def snapshot(self) -> List[FlowFeatures]:
        return [f for f in (self.compute(s) for s in self.all_sources()) if f]


# ---------------------------------------------------------------------------
# Incoming-direction aggregator
# ---------------------------------------------------------------------------

class IncomingAggregator:
    """
    Detection from the VICTIM's perspective.

    Aggregates packets by DESTINATION IP (the protected container).
    For each destination, finds the dominant incoming SOURCE (the attacker
    by construction), and computes the 18 features describing
        traffic_attacker -> traffic_destination
    The 'src' field of the resulting FlowFeatures is set to the attacker IP
    so the existing Mitigator (`mit.mitigate(feats.src, ...)`) stops the
    attacker, not the victim.

    This eliminates the false-positive case where a victim's RST reply
    storm gets misclassified, because the victim is no longer the
    "subject" of any feature vector — only attackers are.
    """

    def __init__(self, window_sec: float = 120.0, short_window_sec: float = 5.0,
                 min_packets: int = 3):
        self.long_window = window_sec
        self.short_window = short_window_sec
        self.min_packets = min_packets
        # All packets indexed by dst (this dst's INCOMING traffic)
        self._incoming: Dict[str, Deque[PacketRecord]] = defaultdict(deque)
        # All packets indexed by src (this src's OUTGOING traffic), used to
        # find reply packets when we look at a victim's outgoing replies.
        self._outgoing: Dict[str, Deque[PacketRecord]] = defaultdict(deque)

    def add(self, pkt: PacketRecord) -> None:
        cutoff = pkt.ts - self.long_window
        in_dq = self._incoming[pkt.dst]
        in_dq.append(pkt)
        while in_dq and in_dq[0].ts < cutoff:
            in_dq.popleft()
        out_dq = self._outgoing[pkt.src]
        out_dq.append(pkt)
        while out_dq and out_dq[0].ts < cutoff:
            out_dq.popleft()

    def evict_stale(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        cutoff = now - self.long_window
        for table in (self._incoming, self._outgoing):
            drop = []
            for k, dq in table.items():
                while dq and dq[0].ts < cutoff:
                    dq.popleft()
                if not dq:
                    drop.append(k)
            for k in drop:
                del table[k]

    def all_destinations(self) -> List[str]:
        return list(self._incoming.keys())

    def compute_for_dst(self, dst: str) -> Optional[FlowFeatures]:
        incoming = self._incoming.get(dst)
        if not incoming or len(incoming) < self.min_packets:
            return None

        # Find dominant attacker (most incoming packets to dst in window)
        from collections import Counter
        src_counts: Counter = Counter(p.src for p in incoming)
        # Don't blame ourselves: a host's own loopback / promiscuous capture
        # shouldn't make the host an "attacker of itself".
        if dst in src_counts:
            del src_counts[dst]
        if not src_counts:
            return None
        top_src, top_n = src_counts.most_common(1)[0]
        if top_n < self.min_packets:
            return None

        # Forward = top_src -> dst (the attack flow we're characterizing)
        fwd_pkts = [p for p in incoming if p.src == top_src]
        # Backward = dst -> top_src (any replies the victim sent)
        out_from_dst = self._outgoing.get(dst, [])
        bwd_pkts = [p for p in out_from_dst if p.dst == top_src]

        sizes = [p.length for p in fwd_pkts]
        bwd_sizes = [p.length for p in bwd_pkts]

        # Per-flow port / IP diversity (the destination is fixed)
        tcp_dports = {p.dport for p in fwd_pkts if p.proto == "TCP" and p.dport}
        udp_dports = {p.dport for p in fwd_pkts if p.proto == "UDP" and p.dport}

        now = fwd_pkts[-1].ts
        short_cutoff = now - self.short_window
        short_ports = {p.dport for p in fwd_pkts
                       if p.proto == "TCP" and p.dport and p.ts >= short_cutoff}

        syn = sum(1 for p in fwd_pkts if p.proto == "TCP"
                  and (p.flags & TCP_SYN) and not (p.flags & TCP_ACK))
        syn_ack_recv = sum(1 for p in bwd_pkts if p.proto == "TCP"
                           and (p.flags & TCP_SYN) and (p.flags & TCP_ACK))
        fin_rst = sum(1 for p in fwd_pkts if p.proto == "TCP"
                      and (p.flags & (TCP_FIN | TCP_RST)))
        psh = sum(1 for p in fwd_pkts if p.proto == "TCP" and (p.flags & TCP_PSH))
        ssh = sum(1 for p in fwd_pkts if p.proto == "TCP" and p.dport == 22
                  and (p.flags & TCP_SYN))
        no_reply = max(0.0, (syn - syn_ack_recv)) / max(syn, 1)

        # Skip pure-reply traffic: if the "attacker" never sent any SYN/PSH and
        # only emitted RST/FIN packets, it's the victim of a different scan
        # whose replies we happen to be capturing — not an attacker.
        if syn == 0 and psh == 0 and fin_rst > 0:
            return None

        return FlowFeatures(
            src=top_src,                          # attacker IP (for mitigation)
            window_end=now,
            pkt_count=len(fwd_pkts), byte_count=sum(sizes),
            avg_pkt_size=sum(sizes) / len(sizes),
            std_pkt_size=statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            pkt_len_max=float(max(sizes)),
            pkt_len_mean=sum(sizes) / len(sizes),
            bwd_pkt_len_mean=(sum(bwd_sizes) / len(bwd_sizes)) if bwd_sizes else 0.0,
            bwd_pkt_len_max=float(max(bwd_sizes)) if bwd_sizes else 0.0,
            unique_dst_ips=1,                     # one dst per evaluation
            unique_dst_ports=len(tcp_dports),
            unique_udp_dst_ports=len(udp_dports),
            short_unique_ports=len(short_ports),
            syn_count=syn, syn_ack_count=syn_ack_recv, fin_rst_count=fin_rst,
            psh_flag_count=psh, no_reply_ratio=no_reply,
            ssh_attempts=ssh,
        )

    def snapshot(self) -> List[FlowFeatures]:
        out = []
        for dst in self.all_destinations():
            f = self.compute_for_dst(dst)
            if f is not None:
                out.append(f)
        return out

