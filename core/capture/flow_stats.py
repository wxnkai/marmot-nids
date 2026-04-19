"""
core.capture.flow_stats
=======================
Per-flow statistical accumulator used by FlowAssembler.

Security relevance:
    Statistical features (packet lengths, inter-arrival times, flag ratios)
    are the primary inputs to both the signature engine and the LLM detection
    layer.  Accuracy here directly determines detection quality.  Raw packet
    payloads are deliberately NOT stored — only aggregate statistics — to
    limit the information-disclosure impact if the detection pipeline is
    compromised or the database is accessed by an unauthorised party.
"""

from __future__ import annotations

import math
from collections import deque


# ---------------------------------------------------------------------------
# TCP flag bitmasks (RFC 793 + RFC 3168)
# ---------------------------------------------------------------------------
_FLAG_FIN: int = 0x01
_FLAG_SYN: int = 0x02
_FLAG_RST: int = 0x04
_FLAG_PSH: int = 0x08
_FLAG_ACK: int = 0x10
_FLAG_URG: int = 0x20


class FlowStats:
    """Accumulates per-flow packet statistics using bounded ring buffers.

    Tracks two classes of data:

    * **Lifetime counters** — ``total_packets``, ``total_bytes``, and TCP flag
      counts.  These are unbounded integers that accurately reflect the entire
      flow, regardless of how long it has been active.

    * **Ring-buffer samples** — the most recent ``max_samples`` packet lengths
      and inter-arrival times (IATs).  Older values are silently dropped when
      the buffer is full.  These feed mean/std calculations for the detection
      engines.

    Args:
        max_samples: Maximum number of packet-length and IAT samples retained
            in memory per flow.  Older samples are evicted on overflow.
            Corresponds to ``FLOW_MAX_STAT_SAMPLES`` in the environment config.

    Security note:
        Only transport-layer payload *lengths* are stored — never the payload
        bytes themselves.  This prevents sensitive cleartext (HTTP credentials,
        DNS queries) from accumulating in long-lived flow records.
    """

    def __init__(self, max_samples: int = 1000) -> None:
        self.max_samples: int = max_samples

        # ------------------------------------------------------------------
        # Lifetime counters (unbounded, always accurate)
        # ------------------------------------------------------------------
        self.total_packets: int = 0
        self.total_bytes: int = 0

        # TCP control-flag counts
        self.syn_count: int = 0
        self.ack_count: int = 0
        self.fin_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.urg_count: int = 0

        # ------------------------------------------------------------------
        # Ring buffers (bounded, statistical only)
        # ------------------------------------------------------------------
        self._pkt_lengths: deque[int] = deque(maxlen=max_samples)
        self._iats: deque[float] = deque(maxlen=max_samples)
        self._last_pkt_time: float | None = None

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def update(
        self,
        pkt_len: int,
        timestamp: float,
        tcp_flags: int | None = None,
    ) -> None:
        """Record one packet's contribution to the flow statistics.

        Args:
            pkt_len: Transport-layer payload length in bytes.
            timestamp: Unix epoch time of the packet (seconds, floating-point).
            tcp_flags: TCP flags as a bitmask integer, or ``None`` for
                non-TCP protocols.  Bitmask values follow RFC 793:
                FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20.

        Security note:
            Flag counts (especially high ``syn_count`` with low ``ack_count``)
            are a primary indicator of SYN flood attacks.  Accurate tracking
            of these values is critical for the signature engine's
            ``tcp_flags`` match type.
        """
        self.total_packets += 1
        self.total_bytes += pkt_len
        self._pkt_lengths.append(pkt_len)

        if self._last_pkt_time is not None:
            iat = timestamp - self._last_pkt_time
            # Negative IAT can occur if packet timestamps are reordered;
            # clamp to zero to avoid corrupting mean/std calculations.
            self._iats.append(max(0.0, iat))
        self._last_pkt_time = timestamp

        if tcp_flags is not None:
            if tcp_flags & _FLAG_SYN:
                self.syn_count += 1
            if tcp_flags & _FLAG_ACK:
                self.ack_count += 1
            if tcp_flags & _FLAG_FIN:
                self.fin_count += 1
            if tcp_flags & _FLAG_RST:
                self.rst_count += 1
            if tcp_flags & _FLAG_PSH:
                self.psh_count += 1
            if tcp_flags & _FLAG_URG:
                self.urg_count += 1

    # ------------------------------------------------------------------
    # Statistical properties
    # ------------------------------------------------------------------

    @property
    def mean_pkt_len(self) -> float:
        """Mean payload length across the sampled packets (bytes).

        Returns:
            Mean payload length, or 0.0 if no samples have been recorded.
        """
        if not self._pkt_lengths:
            return 0.0
        return sum(self._pkt_lengths) / len(self._pkt_lengths)

    @property
    def std_pkt_len(self) -> float:
        """Population standard deviation of payload lengths (bytes).

        Returns:
            Standard deviation, or 0.0 if fewer than two samples exist.

        Security note:
            Low variance with very small packet sizes can indicate a
            crafted attack (e.g. SYN flood with minimal payloads) rather
            than organic application traffic.
        """
        n = len(self._pkt_lengths)
        if n < 2:
            return 0.0
        mean = self.mean_pkt_len
        return math.sqrt(sum((x - mean) ** 2 for x in self._pkt_lengths) / n)

    @property
    def mean_iat(self) -> float:
        """Mean inter-arrival time across sampled packets (seconds).

        Returns:
            Mean IAT, or 0.0 if fewer than two packets have been seen.

        Security note:
            Abnormally low mean IAT (near-zero) combined with a high
            packet count is a strong DoS/DDoS indicator.
        """
        if not self._iats:
            return 0.0
        return sum(self._iats) / len(self._iats)

    @property
    def syn_ratio(self) -> float:
        """Fraction of TCP packets that had the SYN flag set.

        Returns:
            A value in [0.0, 1.0], or 0.0 if no packets have been seen.

        Security note:
            A ratio near 1.0 (many SYNs, few ACKs) on a high-volume flow
            is the canonical signature of a SYN flood attack.
        """
        if self.total_packets == 0:
            return 0.0
        return self.syn_count / self.total_packets

    @property
    def rst_ratio(self) -> float:
        """Fraction of TCP packets that had the RST flag set.

        Returns:
            A value in [0.0, 1.0], or 0.0 if no packets have been seen.
        """
        if self.total_packets == 0:
            return 0.0
        return self.rst_count / self.total_packets

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"FlowStats("
            f"total_packets={self.total_packets}, "
            f"total_bytes={self.total_bytes}, "
            f"mean_pkt_len={self.mean_pkt_len:.1f}, "
            f"syn={self.syn_count}, ack={self.ack_count}, "
            f"fin={self.fin_count}, rst={self.rst_count})"
        )
