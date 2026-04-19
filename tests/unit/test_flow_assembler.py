"""
tests.unit.test_flow_assembler
==============================
Unit tests for FlowAssembler, FlowStats, and DoSTracker.

All tests use ``ParsedPacket`` objects constructed directly — no Scapy, no
live interface, no root privileges required.

The security properties under test are:

* **Bidirectional normalisation** — A→B and B→A must merge into a single
  flow so that attacks spanning both directions are not split.
* **Flow expiry** — flows must be released after inactivity so memory is
  bounded; expired flows are returned for detection analysis.
* **DoS sliding window** — threshold triggers must fire on the correct
  event count and not fire below threshold; old events must expire correctly.
* **Capacity eviction** — when the flow table is full, LRU eviction must
  not discard recently-active flows (which could be active attacks).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.capture.dos_tracker import DoSTrigger, DoSTracker
from core.capture.flow_assembler import (
    CapturedPacket,
    FlowAssembler,
    FlowKey,
    FlowRecord,
    ParsedPacket,
)
from core.capture.flow_stats import FlowStats

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def make_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int | None = 12345,
    dst_port: int | None = 80,
    protocol: int = 6,
    tcp_flags: int | None = 0x02,
    payload_len: int = 40,
    timestamp: float = 1000.0,
    icmp_type: int | None = None,
) -> ParsedPacket:
    """Factory for ``ParsedPacket`` test instances with sensible defaults."""
    return ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        timestamp=timestamp,
        icmp_type=icmp_type,
    )


def make_assembler(
    flow_timeout: float = 120.0,
    max_flows: int = 1000,
    max_stat_samples: int = 100,
) -> FlowAssembler:
    """Factory for ``FlowAssembler`` test instances."""
    return FlowAssembler(
        flow_timeout=flow_timeout,
        max_flows=max_flows,
        max_stat_samples=max_stat_samples,
    )


def make_tracker(
    window_size: float = 10.0,
    syn_threshold: int = 5,
    icmp_threshold: int = 5,
    rst_threshold: int = 5,
) -> DoSTracker:
    """Factory for ``DoSTracker`` test instances with low thresholds."""
    return DoSTracker(
        window_size=window_size,
        syn_threshold=syn_threshold,
        icmp_threshold=icmp_threshold,
        rst_threshold=rst_threshold,
    )


# ---------------------------------------------------------------------------
# CapturedPacket Protocol conformance
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCapturedPacketProtocol:
    """Verify that ParsedPacket satisfies the CapturedPacket Protocol."""

    def test_parsed_packet_satisfies_protocol(self) -> None:
        """ParsedPacket should pass runtime isinstance check for CapturedPacket."""
        pkt = make_packet()
        assert isinstance(pkt, CapturedPacket)

    def test_parsed_packet_fields_accessible(self) -> None:
        """All Protocol attributes must be accessible on ParsedPacket."""
        pkt = make_packet(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=55000,
            dst_port=443,
            protocol=6,
            tcp_flags=0x02,
            payload_len=128,
            timestamp=1234567890.0,
            icmp_type=None,
        )
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.src_port == 55000
        assert pkt.dst_port == 443
        assert pkt.protocol == 6
        assert pkt.tcp_flags == 0x02
        assert pkt.payload_len == 128
        assert pkt.timestamp == 1234567890.0
        assert pkt.icmp_type is None


# ---------------------------------------------------------------------------
# Flow creation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFlowCreation:
    """A single packet must create a new FlowRecord with correct initial state."""

    def test_first_packet_creates_flow(self) -> None:
        assembler = make_assembler()
        pkt = make_packet()
        record = assembler.process(pkt)

        assert record is not None
        assert assembler.active_flow_count == 1

    def test_first_packet_sets_packet_count_to_one(self) -> None:
        assembler = make_assembler()
        record = assembler.process(make_packet(payload_len=100))

        assert record is not None
        assert record.packet_count == 1

    def test_first_packet_sets_byte_count(self) -> None:
        assembler = make_assembler()
        record = assembler.process(make_packet(payload_len=256))

        assert record is not None
        assert record.byte_count == 256

    def test_first_packet_sets_start_and_last_seen(self) -> None:
        assembler = make_assembler()
        record = assembler.process(make_packet(timestamp=5000.0))

        assert record is not None
        assert record.start_time == 5000.0
        assert record.last_seen == 5000.0

    def test_new_flow_is_not_expired(self) -> None:
        assembler = make_assembler()
        record = assembler.process(make_packet())

        assert record is not None
        assert record.is_expired is False

    def test_malformed_packet_empty_src_ip_returns_none(self) -> None:
        """Packets with empty IP fields must be discarded without raising."""
        assembler = make_assembler()
        pkt = make_packet(src_ip="")
        record = assembler.process(pkt)

        assert record is None
        assert assembler.active_flow_count == 0

    def test_malformed_packet_empty_dst_ip_returns_none(self) -> None:
        assembler = make_assembler()
        pkt = make_packet(dst_ip="")
        record = assembler.process(pkt)

        assert record is None


# ---------------------------------------------------------------------------
# Flow update
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFlowUpdate:
    """Subsequent packets on the same 5-tuple must update the existing flow."""

    def test_second_packet_does_not_create_new_flow(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(timestamp=1000.0))
        assembler.process(make_packet(timestamp=1001.0))

        assert assembler.active_flow_count == 1

    def test_second_packet_increments_packet_count(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(timestamp=1000.0))
        record = assembler.process(make_packet(timestamp=1001.0))

        assert record is not None
        assert record.packet_count == 2

    def test_second_packet_accumulates_bytes(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(payload_len=100, timestamp=1000.0))
        record = assembler.process(make_packet(payload_len=200, timestamp=1001.0))

        assert record is not None
        assert record.byte_count == 300

    def test_second_packet_updates_last_seen(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(timestamp=1000.0))
        record = assembler.process(make_packet(timestamp=1005.0))

        assert record is not None
        assert record.last_seen == 1005.0

    def test_second_packet_preserves_start_time(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(timestamp=1000.0))
        record = assembler.process(make_packet(timestamp=1005.0))

        assert record is not None
        assert record.start_time == 1000.0

    def test_different_dst_port_creates_separate_flow(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(dst_port=80))
        assembler.process(make_packet(dst_port=443))

        assert assembler.active_flow_count == 2

    def test_different_protocol_creates_separate_flow(self) -> None:
        assembler = make_assembler()
        assembler.process(make_packet(protocol=6))   # TCP
        assembler.process(make_packet(protocol=17))  # UDP

        assert assembler.active_flow_count == 2


# ---------------------------------------------------------------------------
# Bidirectional flow merging  (the critical security invariant)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBidirectionalMerging:
    """A→B and B→A packets must resolve to the same FlowKey and FlowRecord."""

    def test_reverse_packet_merges_into_same_flow(self) -> None:
        assembler = make_assembler()
        pkt_fwd = make_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
            timestamp=1000.0,
        )
        pkt_rev = make_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345,
            timestamp=1001.0,
        )

        assembler.process(pkt_fwd)
        assembler.process(pkt_rev)

        assert assembler.active_flow_count == 1

    def test_reverse_packet_increments_shared_packet_count(self) -> None:
        assembler = make_assembler()
        pkt_fwd = make_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, timestamp=1000.0,
        )
        pkt_rev = make_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345, timestamp=1001.0,
        )

        assembler.process(pkt_fwd)
        record = assembler.process(pkt_rev)

        assert record is not None
        assert record.packet_count == 2

    def test_flow_keys_are_identical_regardless_of_direction(self) -> None:
        """_make_key must produce identical FlowKey for both directions."""
        assembler = make_assembler()
        pkt_fwd = make_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
        )
        pkt_rev = make_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345,
        )

        key_fwd = assembler._make_key(pkt_fwd)
        key_rev = assembler._make_key(pkt_rev)

        assert key_fwd == key_rev

    def test_fixture_bidirectional_ssh_merges_to_single_flow(self) -> None:
        """Load the bidirectional_ssh fixture and verify single-flow assembly."""
        data = json.loads((FIXTURES_DIR / "sample_flows.json").read_text())
        packets_raw = data["packet_sequences"]["bidirectional_ssh"]["packets"]

        assembler = make_assembler()
        for raw in packets_raw:
            pkt = ParsedPacket(**raw)
            assembler.process(pkt)

        assert assembler.active_flow_count == 1

    def test_icmp_flow_uses_zero_ports(self) -> None:
        """ICMP packets (no ports) must form a valid flow key with port=0."""
        assembler = make_assembler()
        pkt = make_packet(
            src_port=None, dst_port=None,
            protocol=1, tcp_flags=None, icmp_type=8,
        )
        record = assembler.process(pkt)

        assert record is not None
        key = record.key
        assert key.src_port == 0
        assert key.dst_port == 0


# ---------------------------------------------------------------------------
# Flow expiry
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFlowExpiry:
    """expire_flows() must evict timed-out flows and return them for analysis."""

    def test_expired_flow_is_returned(self) -> None:
        assembler = make_assembler(flow_timeout=10.0)
        assembler.process(make_packet(timestamp=1000.0))

        expired = assembler.expire_flows(now=1020.0)  # 20s > timeout

        assert len(expired) == 1

    def test_expired_flow_is_removed_from_active_set(self) -> None:
        assembler = make_assembler(flow_timeout=10.0)
        assembler.process(make_packet(timestamp=1000.0))

        assembler.expire_flows(now=1020.0)

        assert assembler.active_flow_count == 0

    def test_expired_flow_has_is_expired_flag_set(self) -> None:
        assembler = make_assembler(flow_timeout=10.0)
        assembler.process(make_packet(timestamp=1000.0))

        expired = assembler.expire_flows(now=1020.0)

        assert expired[0].is_expired is True

    def test_active_flow_is_not_expired(self) -> None:
        assembler = make_assembler(flow_timeout=10.0)
        assembler.process(make_packet(timestamp=1000.0))

        expired = assembler.expire_flows(now=1005.0)  # 5s < timeout

        assert len(expired) == 0
        assert assembler.active_flow_count == 1

    def test_only_stale_flows_are_expired(self) -> None:
        """A mix of fresh and stale flows — only stale ones must be returned."""
        assembler = make_assembler(flow_timeout=10.0)
        assembler.process(make_packet(src_port=1001, timestamp=1000.0))   # stale
        assembler.process(make_packet(src_port=1002, timestamp=1015.0))   # fresh

        expired = assembler.expire_flows(now=1025.0)

        assert len(expired) == 1
        assert assembler.active_flow_count == 1

    def test_expire_returns_empty_list_when_nothing_to_expire(self) -> None:
        assembler = make_assembler(flow_timeout=120.0)
        assembler.process(make_packet(timestamp=1000.0))

        expired = assembler.expire_flows(now=1001.0)

        assert expired == []

    def test_expire_on_empty_assembler_returns_empty_list(self) -> None:
        assembler = make_assembler()
        expired = assembler.expire_flows(now=9999.0)

        assert expired == []


# ---------------------------------------------------------------------------
# Capacity eviction
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCapacityEviction:
    """When max_flows is reached, the LRU flow must be evicted."""

    def test_eviction_occurs_at_capacity(self) -> None:
        assembler = make_assembler(max_flows=3)
        for i in range(3):
            assembler.process(make_packet(src_port=1000 + i, timestamp=float(i)))

        # Adding a 4th flow must evict the oldest (src_port=1000, timestamp=0.0)
        assembler.process(make_packet(src_port=9999, timestamp=100.0))

        assert assembler.active_flow_count == 3

    def test_lru_flow_is_evicted_not_most_recent(self) -> None:
        """The LRU (oldest last_seen) flow is evicted, not the newest."""
        assembler = make_assembler(max_flows=2)
        # Two flows: timestamps 0 and 1
        assembler.process(make_packet(src_port=100, timestamp=0.0))
        assembler.process(make_packet(src_port=200, timestamp=1.0))

        # Add a third — flow with src_port=100 (last_seen=0.0) must be evicted
        assembler.process(make_packet(src_port=300, timestamp=2.0))

        remaining_key = list(assembler._flows.keys())
        assert all(k.src_port != 100 for k in remaining_key)


# ---------------------------------------------------------------------------
# FlowStats
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFlowStats:
    """FlowStats must accumulate counters and statistics correctly."""

    def test_initial_state_has_zero_counts(self) -> None:
        stats = FlowStats()
        assert stats.total_packets == 0
        assert stats.total_bytes == 0
        assert stats.syn_count == 0

    def test_update_increments_total_packets(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=1.0, tcp_flags=None)
        stats.update(pkt_len=200, timestamp=2.0, tcp_flags=None)
        assert stats.total_packets == 2

    def test_update_accumulates_bytes(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=1.0)
        stats.update(pkt_len=300, timestamp=2.0)
        assert stats.total_bytes == 400

    def test_syn_flag_increments_syn_count(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=0, timestamp=1.0, tcp_flags=0x02)
        assert stats.syn_count == 1
        assert stats.ack_count == 0

    def test_syn_ack_increments_both_counters(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=0, timestamp=1.0, tcp_flags=0x12)  # SYN+ACK
        assert stats.syn_count == 1
        assert stats.ack_count == 1

    def test_mean_pkt_len_calculation(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=1.0)
        stats.update(pkt_len=300, timestamp=2.0)
        assert stats.mean_pkt_len == pytest.approx(200.0)

    def test_mean_pkt_len_zero_when_no_packets(self) -> None:
        assert FlowStats().mean_pkt_len == 0.0

    def test_mean_iat_calculation(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=1.0)
        stats.update(pkt_len=100, timestamp=3.0)  # IAT = 2.0
        stats.update(pkt_len=100, timestamp=6.0)  # IAT = 3.0
        assert stats.mean_iat == pytest.approx(2.5)

    def test_mean_iat_zero_with_single_packet(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=1.0)
        assert stats.mean_iat == 0.0

    def test_syn_ratio_with_mixed_flags(self) -> None:
        stats = FlowStats()
        stats.update(pkt_len=0, timestamp=1.0, tcp_flags=0x02)  # SYN
        stats.update(pkt_len=0, timestamp=2.0, tcp_flags=0x10)  # ACK
        stats.update(pkt_len=0, timestamp=3.0, tcp_flags=0x10)  # ACK
        assert stats.syn_ratio == pytest.approx(1 / 3)

    def test_ring_buffer_drops_oldest_samples(self) -> None:
        """With max_samples=3, the 4th update should evict the first."""
        stats = FlowStats(max_samples=3)
        for i in range(4):
            stats.update(pkt_len=10 * (i + 1), timestamp=float(i))
        # Ring buffer holds [20, 30, 40]; mean = 30
        assert stats.mean_pkt_len == pytest.approx(30.0)
        # But total_packets still counts all 4
        assert stats.total_packets == 4

    def test_negative_iat_clamped_to_zero(self) -> None:
        """Out-of-order timestamps must not produce negative IAT values."""
        stats = FlowStats()
        stats.update(pkt_len=100, timestamp=10.0)
        stats.update(pkt_len=100, timestamp=5.0)  # earlier timestamp
        assert stats.mean_iat == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# DoSTracker — threshold trigger
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDoSTrackerTrigger:
    """DoSTrigger must be returned exactly when the threshold is met."""

    def test_syn_flood_triggers_at_threshold(self) -> None:
        tracker = make_tracker(syn_threshold=5)
        triggers = []

        for i in range(5):
            result = tracker.record_syn(timestamp=1000.0 + i * 0.1)
            if result is not None:
                triggers.append(result)

        assert len(triggers) == 1
        assert triggers[0].threat_type == "syn_flood"

    def test_syn_flood_trigger_has_correct_rate(self) -> None:
        tracker = make_tracker(syn_threshold=5)
        result = None
        for i in range(5):
            result = tracker.record_syn(timestamp=1000.0 + i * 0.01)
        assert result is not None
        assert result.rate == 5

    def test_syn_flood_trigger_includes_threshold_value(self) -> None:
        tracker = make_tracker(syn_threshold=5)
        result = None
        for i in range(5):
            result = tracker.record_syn(timestamp=1000.0 + i * 0.01)
        assert result is not None
        assert result.threshold == 5

    def test_icmp_flood_triggers_at_threshold(self) -> None:
        tracker = make_tracker(icmp_threshold=3)
        triggers = [
            tracker.record_icmp(timestamp=1000.0 + i * 0.1)
            for i in range(3)
        ]
        last = triggers[-1]
        assert last is not None
        assert last.threat_type == "icmp_flood"

    def test_rst_flood_triggers_at_threshold(self) -> None:
        tracker = make_tracker(rst_threshold=4)
        results = [tracker.record_rst(1000.0 + i * 0.01) for i in range(4)]
        assert results[-1] is not None
        assert results[-1].threat_type == "rst_flood"


# ---------------------------------------------------------------------------
# DoSTracker — no trigger below threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDoSTrackerNoTrigger:
    """DoSTrigger must NOT be returned when below threshold."""

    def test_syn_below_threshold_returns_none(self) -> None:
        tracker = make_tracker(syn_threshold=10)

        for i in range(9):
            result = tracker.record_syn(timestamp=1000.0 + i * 0.1)
            assert result is None

    def test_icmp_below_threshold_returns_none(self) -> None:
        tracker = make_tracker(icmp_threshold=10)

        for i in range(9):
            result = tracker.record_icmp(timestamp=1000.0 + i * 0.1)
            assert result is None

    def test_rst_below_threshold_returns_none(self) -> None:
        tracker = make_tracker(rst_threshold=10)

        for i in range(9):
            result = tracker.record_rst(timestamp=1000.0 + i * 0.1)
            assert result is None


# ---------------------------------------------------------------------------
# DoSTracker — sliding window expiry
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDoSTrackerWindowExpiry:
    """Events older than window_size must no longer contribute to the count."""

    def test_expired_syn_events_not_counted(self) -> None:
        tracker = make_tracker(window_size=5.0, syn_threshold=3)

        # Record 2 events at t=1000
        tracker.record_syn(timestamp=1000.0)
        tracker.record_syn(timestamp=1001.0)

        # Query at t=1010 (both events are now older than window_size=5)
        rate = tracker.syn_rate(now=1010.0)
        assert rate == 0

    def test_events_within_window_are_counted(self) -> None:
        tracker = make_tracker(window_size=10.0, syn_threshold=100)

        tracker.record_syn(timestamp=1000.0)
        tracker.record_syn(timestamp=1005.0)
        tracker.record_syn(timestamp=1008.0)

        rate = tracker.syn_rate(now=1009.0)
        assert rate == 3

    def test_partial_window_expiry(self) -> None:
        """Events at the edge of the window must be handled correctly."""
        tracker = make_tracker(window_size=5.0, syn_threshold=100)

        tracker.record_syn(timestamp=1000.0)   # will expire at now=1006
        tracker.record_syn(timestamp=1003.0)   # still in window at now=1006
        tracker.record_syn(timestamp=1005.5)   # still in window at now=1006

        rate = tracker.syn_rate(now=1006.0)
        assert rate == 2  # t=1000 has expired (1000 < 1006-5=1001)

    def test_window_resets_allow_fresh_trigger(self) -> None:
        """After the window clears, the same number of events must re-trigger."""
        tracker = make_tracker(window_size=5.0, syn_threshold=3)

        # First burst — fills and clears
        for i in range(3):
            tracker.record_syn(timestamp=1000.0 + i * 0.1)

        # Advance past the window — all previous events have expired
        rate = tracker.syn_rate(now=1010.0)
        assert rate == 0

        # Second burst at t=2000 — must trigger again
        result = None
        for i in range(3):
            result = tracker.record_syn(timestamp=2000.0 + i * 0.1)
        assert result is not None
        assert result.threat_type == "syn_flood"

    def test_icmp_rate_query_prunes_window(self) -> None:
        tracker = make_tracker(window_size=5.0)

        tracker.record_icmp(timestamp=1000.0)
        tracker.record_icmp(timestamp=1001.0)

        rate = tracker.icmp_rate(now=1010.0)  # both expired
        assert rate == 0

    def test_rst_rate_query_prunes_window(self) -> None:
        # cutoff = now - window_size = 1005 - 5 = 1000.0
        # Events strictly < cutoff are pruned; t=999.9 < 1000.0 → pruned.
        tracker = make_tracker(window_size=5.0)

        tracker.record_rst(timestamp=999.9)   # outside window at now=1005
        tracker.record_rst(timestamp=1004.9)  # inside window at now=1005

        rate = tracker.rst_rate(now=1005.0)
        assert rate == 1


# ---------------------------------------------------------------------------
# Fixture-driven integration smoke test
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFixtureIntegration:
    """Load the JSON fixture file and run the assembler over each sequence."""

    def _load_sequence(self, name: str) -> list[ParsedPacket]:
        data = json.loads((FIXTURES_DIR / "sample_flows.json").read_text())
        raw_packets = data["packet_sequences"][name]["packets"]
        return [ParsedPacket(**p) for p in raw_packets]

    def test_syn_flood_fixture_produces_multiple_flows(self) -> None:
        """SYN flood packets each use a different src_port → many flows."""
        assembler = make_assembler()
        packets = self._load_sequence("syn_flood")
        for pkt in packets:
            assembler.process(pkt)
        # Each SYN uses a distinct ephemeral src_port — distinct flows
        assert assembler.active_flow_count == len(packets)

    def test_normal_http_fixture_produces_single_flow(self) -> None:
        """All HTTP packets share the same 5-tuple → single bidirectional flow."""
        assembler = make_assembler()
        packets = self._load_sequence("normal_http")
        for pkt in packets:
            assembler.process(pkt)
        assert assembler.active_flow_count == 1

    def test_icmp_flood_fixture_produces_single_flow(self) -> None:
        """ICMP flood packets from the same src → one flow (ports are 0)."""
        assembler = make_assembler()
        packets = self._load_sequence("icmp_flood")
        for pkt in packets:
            assembler.process(pkt)
        assert assembler.active_flow_count == 1

    def test_syn_flood_dos_tracker_triggers(self) -> None:
        """syn_flood fixture must trigger DoSTracker with threshold=5."""
        tracker = make_tracker(syn_threshold=5)
        packets = self._load_sequence("syn_flood")

        triggers: list[DoSTrigger] = []
        for pkt in packets:
            if pkt.tcp_flags is not None and pkt.tcp_flags & 0x02:
                result = tracker.record_syn(timestamp=pkt.timestamp)
                if result is not None:
                    triggers.append(result)

        assert len(triggers) >= 1
        assert triggers[0].threat_type == "syn_flood"
