"""
core.capture.flow_assembler
============================
Bidirectional 5-tuple flow assembly.

Security relevance:
    Flow assembly is the foundation of every detection decision made
    downstream.  Two correctness properties are critical for security:

    1. **Bidirectional normalisation** — packets in both directions of a
       TCP/UDP exchange must merge into a single flow record.  Failure to
       normalise allows an attacker to split a single attack across two
       flow records, potentially falling below the detection threshold of
       each.

    2. **Bounded memory** — flows must expire and the active set must be
       capped.  An attacker can exhaust memory by opening many short-lived
       connections if neither limit is enforced.

    The ``CapturedPacket`` Protocol decouples the assembler from Scapy,
    enabling full unit-test coverage without root privileges or a live
    network interface.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from core.capture.flow_stats import FlowStats

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol: the packet abstraction consumed by FlowAssembler
# ---------------------------------------------------------------------------


@runtime_checkable
class CapturedPacket(Protocol):
    """Structural protocol for packet objects consumed by ``FlowAssembler``.

    Any object whose attributes satisfy this interface can be passed to
    ``FlowAssembler.process()`` without subclassing.  This enables:

    * ``ParsedPacket`` dataclasses (created by the Scapy adapter in
      ``sniffer.py``) to be used in production.
    * Plain ``ParsedPacket`` instances with controlled values to be used
      in unit tests — no live interface or root privileges required.

    The ``@runtime_checkable`` decorator allows ``isinstance(obj,
    CapturedPacket)`` checks, which can be useful for debugging but are
    not relied on by the assembler itself.

    Security note:
        This protocol intentionally does not expose raw payload bytes.
        Only metadata fields needed for flow keying and statistical analysis
        are surfaced.  Keeping payload data out of the interface minimises
        the risk that payload content is accidentally persisted.
    """

    @property
    def src_ip(self) -> str:
        """Source IP address (IPv4 dotted-decimal or compressed IPv6)."""
        ...

    @property
    def dst_ip(self) -> str:
        """Destination IP address."""
        ...

    @property
    def src_port(self) -> int | None:
        """Source port number, or ``None`` for protocols without ports (ICMP)."""
        ...

    @property
    def dst_port(self) -> int | None:
        """Destination port number, or ``None`` for protocols without ports."""
        ...

    @property
    def protocol(self) -> int:
        """IANA protocol number.  Common values: 1=ICMP, 6=TCP, 17=UDP."""
        ...

    @property
    def tcp_flags(self) -> int | None:
        """TCP control flags as a bitmask, or ``None`` for non-TCP.

        Bitmask values (RFC 793): FIN=0x01, SYN=0x02, RST=0x04,
        PSH=0x08, ACK=0x10, URG=0x20.
        """
        ...

    @property
    def payload_len(self) -> int:
        """Transport-layer payload length in bytes."""
        ...

    @property
    def timestamp(self) -> float:
        """Unix epoch timestamp of the packet (seconds, floating-point)."""
        ...

    @property
    def icmp_type(self) -> int | None:
        """ICMP message type (RFC 792), or ``None`` for non-ICMP protocols."""
        ...


# ---------------------------------------------------------------------------
# ParsedPacket: concrete Scapy-free implementation of CapturedPacket
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedPacket:
    """Immutable, Scapy-free representation of a captured packet.

    Satisfies ``CapturedPacket`` structurally.  Produced by
    ``sniffer.ScapyPacketAdapter`` in production and constructed directly
    in unit tests.

    All fields are extracted from the Scapy packet at construction time so
    that the Scapy object can be released without holding references to its
    internal memory.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        protocol: IANA protocol number.
        payload_len: Transport-layer payload length in bytes.
        timestamp: Unix epoch capture timestamp.
        src_port: Source port, or ``None`` for ICMP / unknown protocols.
        dst_port: Destination port, or ``None`` for ICMP / unknown protocols.
        tcp_flags: TCP flag bitmask, or ``None`` for non-TCP.
        icmp_type: ICMP type field value, or ``None`` for non-ICMP.
    """

    src_ip: str
    dst_ip: str
    protocol: int
    payload_len: int
    timestamp: float
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None


# ---------------------------------------------------------------------------
# FlowKey: normalised, hashable 5-tuple
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowKey:
    """Normalised 5-tuple flow identifier used as a ``dict`` key.

    Endpoints are stored in *canonical order* (lexicographically smaller
    ``(ip, port)`` pair first) so that packets in both directions of a
    connection produce the same key.  See ``FlowAssembler._make_key`` for
    the normalisation logic.

    Attributes:
        src_ip: Lexicographically smaller IP address of the two endpoints.
        dst_ip: Lexicographically larger IP address.
        src_port: Port corresponding to ``src_ip`` (0 for protocols without
            ports, e.g. ICMP).
        dst_port: Port corresponding to ``dst_ip``.
        protocol: IANA protocol number.

    Security note:
        The canonical ordering means that A→B and B→A map to the same key.
        This is essential for detecting attacks that use both directions of
        a TCP connection (e.g. brute force with ACK responses).
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int


# ---------------------------------------------------------------------------
# FlowRecord: mutable state for a single assembled flow
# ---------------------------------------------------------------------------


@dataclass
class FlowRecord:
    """Mutable state container for a single assembled network flow.

    Created by ``FlowAssembler`` on the first packet of a new flow and
    updated on every subsequent packet.  When the flow expires (either by
    timeout or capacity eviction), ``is_expired`` is set to ``True`` and
    the record is returned to the caller for detection analysis.

    Attributes:
        key: The normalised 5-tuple that identifies this flow.
        start_time: Timestamp of the first packet seen in this flow.
        last_seen: Timestamp of the most recent packet seen.
        packet_count: Total number of packets attributed to this flow in
            both directions.
        byte_count: Total payload bytes across all packets.
        stats: Detailed statistical accumulator; feeds both the signature
            engine and the LLM prompt builder.
        is_expired: Set to ``True`` when the flow is evicted.  Expired
            records should be forwarded to the detection pipeline.

    Security note:
        ``is_expired=True`` is the signal that a flow is ready for final
        analysis.  Detection engines should not act on intermediate updates
        (where the attack may not yet be fully observable) unless they are
        specifically designed for streaming evaluation.
    """

    key: FlowKey
    start_time: float
    last_seen: float
    packet_count: int
    byte_count: int
    stats: FlowStats
    is_expired: bool = field(default=False)

    @property
    def duration(self) -> float:
        """Elapsed time between the first and last observed packets (seconds)."""
        return self.last_seen - self.start_time


# ---------------------------------------------------------------------------
# FlowAssembler
# ---------------------------------------------------------------------------


class FlowAssembler:
    """Assembles captured packets into bidirectional 5-tuple flow records.

    Accepts objects implementing ``CapturedPacket`` (structurally), so it
    can be used with either Scapy-derived packets (via ``sniffer.py``) or
    plain ``ParsedPacket`` dataclasses in tests.

    **Normalisation:**
    The 5-tuple key is normalised by sorting the two ``(ip, port)`` endpoint
    pairs lexicographically.  This ensures A→B and B→A packets merge into
    the same ``FlowRecord``.

    **Memory bounds:**
    Two limits prevent unbounded growth:

    * ``flow_timeout`` — flows inactive for this many seconds are evicted by
      ``expire_flows()``, which the caller should invoke periodically.
    * ``max_flows`` — if the active set reaches this size, the least-recently-
      seen flow is evicted immediately to make room for the new one.

    Args:
        flow_timeout: Seconds of inactivity before a flow is considered
            complete.  Corresponds to ``FLOW_TIMEOUT`` in env config.
        max_flows: Maximum number of concurrent flows in memory.
            Corresponds to ``MAX_FLOWS`` in env config.
        max_stat_samples: Ring-buffer depth passed to ``FlowStats``.
            Corresponds to ``FLOW_MAX_STAT_SAMPLES`` in env config.

    Security note:
        Both ``flow_timeout`` and ``max_flows`` are attack surfaces:
        - Too short a timeout causes legitimate long-lived flows (e.g. SSH
          sessions) to be prematurely split and their statistics reset,
          potentially masking brute-force patterns.
        - Too large a ``max_flows`` value allows a connection-flood attack
          to exhaust memory.
        Operators should tune both values to their expected traffic volume.
    """

    def __init__(
        self,
        flow_timeout: float = 120.0,
        max_flows: int = 50_000,
        max_stat_samples: int = 1_000,
    ) -> None:
        self._flow_timeout: float = flow_timeout
        self._max_flows: int = max_flows
        self._max_stat_samples: int = max_stat_samples
        self._flows: dict[FlowKey, FlowRecord] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, packet: CapturedPacket) -> FlowRecord | None:
        """Attribute a captured packet to its flow, creating the flow if new.

        Args:
            packet: Any object satisfying the ``CapturedPacket`` protocol.

        Returns:
            The updated (or newly created) ``FlowRecord``, or ``None`` if
            the packet could not be keyed (e.g. no recognisable IP header).

        Security note:
            The caller should also pass TCP flag information to
            ``DoSTracker`` before calling this method, so that volumetric
            alerts fire even when the flow assembler's queue is saturated.
        """
        key = self._make_key(packet)
        if key is None:
            return None

        ts = packet.timestamp

        if key in self._flows:
            record = self._flows[key]
            record.last_seen = ts
            record.packet_count += 1
            record.byte_count += packet.payload_len
            record.stats.update(packet.payload_len, ts, packet.tcp_flags)
        else:
            if len(self._flows) >= self._max_flows:
                self._evict_lru()

            stats = FlowStats(max_samples=self._max_stat_samples)
            stats.update(packet.payload_len, ts, packet.tcp_flags)
            record = FlowRecord(
                key=key,
                start_time=ts,
                last_seen=ts,
                packet_count=1,
                byte_count=packet.payload_len,
                stats=stats,
            )
            self._flows[key] = record
            logger.debug("New flow: %s", key)

        return record

    def expire_flows(self, now: float | None = None) -> list[FlowRecord]:
        """Evict flows that have been inactive for longer than ``flow_timeout``.

        Should be called periodically by the main capture loop.  Expired
        records are returned so the caller can forward them to the detection
        pipeline for final analysis.

        Args:
            now: Reference time for the expiry cutoff.  Defaults to
                ``time.monotonic()``.  Pass an explicit value in tests for
                deterministic behaviour without mocking the clock.

        Returns:
            A list of ``FlowRecord`` objects that were evicted, each with
            ``is_expired=True``.  Returns an empty list if no flows expired.

        Security note:
            Returning expired flows (rather than silently discarding them)
            ensures that the detection pipeline gets to analyse every
            completed flow.  A flow that is just below a detection threshold
            during active recording may cross it when evaluated in full.
        """
        t = now if now is not None else time.monotonic()
        cutoff = t - self._flow_timeout

        expired: list[FlowRecord] = [
            record
            for record in self._flows.values()
            if record.last_seen < cutoff
        ]

        for record in expired:
            del self._flows[record.key]
            record.is_expired = True
            logger.debug(
                "Flow expired after %.1fs inactivity: %s",
                t - record.last_seen,
                record.key,
            )

        return expired

    def get_flow(self, key: FlowKey) -> FlowRecord | None:
        """Look up an active flow by its normalised key.

        Args:
            key: A ``FlowKey`` (must be pre-normalised; use ``_make_key``
                to derive from a packet).

        Returns:
            The ``FlowRecord`` if the flow is currently active, otherwise
            ``None``.
        """
        return self._flows.get(key)

    @property
    def active_flow_count(self) -> int:
        """Number of flows currently held in the active set."""
        return len(self._flows)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_key(self, packet: CapturedPacket) -> FlowKey | None:
        """Derive a normalised ``FlowKey`` from a packet.

        Sorts the two ``(ip, port)`` endpoint pairs so that A→B and B→A
        produce identical keys.

        Args:
            packet: The packet to key.

        Returns:
            A ``FlowKey``, or ``None`` if ``src_ip`` or ``dst_ip`` are
            empty strings (malformed packet).

        Security note:
            Normalisation is the critical correctness invariant of the whole
            detection pipeline.  Any bug here that causes bidirectional
            traffic to produce different keys will split attack flows across
            two records, halving the observable packet rate and potentially
            dropping them below detection thresholds.
        """
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        if not src_ip or not dst_ip:
            logger.warning("Discarding packet with empty IP address field")
            return None

        src_port = packet.src_port if packet.src_port is not None else 0
        dst_port = packet.dst_port if packet.dst_port is not None else 0

        pair_a = (src_ip, src_port)
        pair_b = (dst_ip, dst_port)

        if pair_a <= pair_b:
            lo_ip, lo_port = pair_a
            hi_ip, hi_port = pair_b
        else:
            lo_ip, lo_port = pair_b
            hi_ip, hi_port = pair_a

        return FlowKey(
            src_ip=lo_ip,
            dst_ip=hi_ip,
            src_port=lo_port,
            dst_port=hi_port,
            protocol=packet.protocol,
        )

    def _evict_lru(self) -> FlowRecord:
        """Evict the least-recently-seen flow to stay within ``max_flows``.

        Returns:
            The evicted ``FlowRecord`` (``is_expired=True``).

        Security note:
            LRU eviction ensures that long-lived attack flows (which have
            recently been seen) are *not* the ones evicted.  An attacker
            attempting to fill the flow table (connection flood) would cause
            their own oldest flows to be evicted first.
        """
        lru_key = min(self._flows, key=lambda k: self._flows[k].last_seen)
        record = self._flows.pop(lru_key)
        record.is_expired = True
        logger.warning(
            "Flow table at capacity (%d); evicted LRU flow: %s",
            self._max_flows,
            lru_key,
        )
        return record
