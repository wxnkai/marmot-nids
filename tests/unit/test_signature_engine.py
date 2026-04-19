"""
Unit tests for Phase 3 — feat/signature-detection.

Coverage:
    * Alert dataclass
    * Pydantic schema validation (SignatureCondition, Signature, SignatureSet)
    * SignatureManager HMAC verification and JSON parsing
    * Namespace extraction from FlowRecord
    * Condition evaluation (all six operators + AND semantics)
    * Protocol-indexed pre-filtering
    * Detection of each major attack class
    * Benign flows producing no alerts

All tests are Scapy-free and do not require root privileges.  Flows are
built from ``ParsedPacket`` dataclasses via ``FlowAssembler``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.capture.flow_assembler import FlowAssembler, FlowRecord, ParsedPacket
from core.detection.base import Alert
from core.detection.signature.engine import (
    SignatureEngine,
    _evaluate_conditions,
    _extract_namespace,
    _threat_type_from_id,
)
from core.detection.signature.manager import SignatureLoadError, SignatureManager
from core.detection.signature.schema import (
    Signature,
    SignatureCondition,
    SignatureSet,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent.parent

#: Dev secret used to sign the repo's signatures.json.
_DEV_SECRET = "marmot-nids-dev-secret"

#: Minimal valid signatures.json payload for manager tests.
_MINIMAL_JSON = json.dumps(
    {
        "version": "1.0",
        "description": "Minimal test signatures.",
        "signatures": [
            {
                "id": "sig_001_test_rule",
                "name": "Test Rule",
                "description": "A minimal test signature for unit tests.",
                "severity": "low",
                "mitre_technique": None,
                "protocols": [6],
                "confidence": 1.0,
                "conditions": [
                    {"field": "packet_count", "op": ">=", "value": 1}
                ],
            }
        ],
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hmac_digest(content: bytes, secret: str) -> str:
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=content,
        digestmod=hashlib.sha256,
    ).hexdigest()


def _make_sig(
    *,
    sig_id: str = "sig_001_test_rule",
    name: str = "Test Rule",
    description: str = "A test signature.",
    severity: str = "low",
    protocols: list[int] | None = None,
    confidence: float = 0.9,
    conditions: list[dict] | None = None,
    mitre_technique: str | None = None,
) -> Signature:
    return Signature(
        id=sig_id,
        name=name,
        description=description,
        severity=severity,
        protocols=protocols or [6],
        confidence=confidence,
        conditions=[SignatureCondition(**c) for c in (conditions or [{"field": "packet_count", "op": ">=", "value": 1}])],
        mitre_technique=mitre_technique,
    )


def _tcp_pkt(
    ts: float,
    flags: int,
    dst_port: int = 80,
    src_port: int = 54321,
    payload_len: int = 0,
) -> ParsedPacket:
    return ParsedPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=6,
        payload_len=payload_len,
        timestamp=ts,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        icmp_type=None,
    )


def _icmp_pkt(ts: float, payload_len: int = 56) -> ParsedPacket:
    return ParsedPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=1,
        payload_len=payload_len,
        timestamp=ts,
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        icmp_type=8,
    )


def _udp_pkt(ts: float, src_port: int = 12345, dst_port: int = 53, payload_len: int = 512) -> ParsedPacket:
    return ParsedPacket(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol=17,
        payload_len=payload_len,
        timestamp=ts,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=None,
        icmp_type=None,
    )


def _build_flow(packets: list[ParsedPacket]) -> FlowRecord:
    """Assemble packets into a FlowRecord using FlowAssembler."""
    assembler = FlowAssembler()
    flow: FlowRecord | None = None
    for pkt in packets:
        flow = assembler.process(pkt)
    assert flow is not None, "No flow produced — empty packet list?"
    return flow


def _load_fixture(name: str) -> list[ParsedPacket]:
    """Load a named packet sequence from sample_flows.json."""
    fixture_path = _PROJECT_ROOT / "tests" / "fixtures" / "sample_flows.json"
    data = json.loads(fixture_path.read_text())
    raw_pkts = data["packet_sequences"][name]["packets"]
    return [ParsedPacket(**p) for p in raw_pkts]


# ---------------------------------------------------------------------------
# TestAlertModel (3 tests)
# ---------------------------------------------------------------------------


class TestAlertModel:
    def test_alert_creation_sets_all_fields(self):
        from core.capture.flow_assembler import FlowKey

        key = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1024, dst_port=22, protocol=6)
        alert = Alert(
            flow_key=key,
            signature_id="sig_007_ssh_brute_force",
            signature_name="SSH Brute Force",
            threat_type="ssh_brute_force",
            severity="high",
            confidence=0.85,
            description="Brute force detected.",
            timestamp=1700000000.0,
            mitre_technique="T1110.001",
        )
        assert alert.signature_id == "sig_007_ssh_brute_force"
        assert alert.severity == "high"
        assert alert.confidence == 0.85
        assert alert.mitre_technique == "T1110.001"

    def test_alert_mitre_technique_optional(self):
        from core.capture.flow_assembler import FlowKey

        key = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=0, dst_port=0, protocol=1)
        alert = Alert(
            flow_key=key,
            signature_id="sig_001_test_rule",
            signature_name="Test",
            threat_type="test_rule",
            severity="low",
            confidence=1.0,
            description="No MITRE mapping.",
            timestamp=0.0,
        )
        assert alert.mitre_technique is None

    def test_alert_is_frozen(self):
        from core.capture.flow_assembler import FlowKey

        key = FlowKey(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=0, dst_port=0, protocol=1)
        alert = Alert(
            flow_key=key,
            signature_id="sig_001_test_rule",
            signature_name="Test",
            threat_type="test_rule",
            severity="low",
            confidence=1.0,
            description="Frozen.",
            timestamp=0.0,
        )
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            alert.severity = "critical"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestSignatureConditionSchema (5 tests)
# ---------------------------------------------------------------------------


class TestSignatureConditionSchema:
    def test_valid_condition(self):
        cond = SignatureCondition(field="syn_ratio", op=">=", value=0.9)
        assert cond.field == "syn_ratio"
        assert cond.op == ">="
        assert cond.value == 0.9

    def test_invalid_field_raises_validation_error(self):
        with pytest.raises(ValidationError, match="Unknown condition field"):
            SignatureCondition(field="malicious_field", op=">=", value=1)

    def test_invalid_op_raises_validation_error(self):
        with pytest.raises(ValidationError):
            SignatureCondition(field="packet_count", op="~=", value=1)  # type: ignore[arg-type]

    def test_integer_value_coerced_to_float(self):
        cond = SignatureCondition(field="packet_count", op=">=", value=100)
        assert isinstance(cond.value, float)
        assert cond.value == 100.0

    def test_all_six_operators_accepted(self):
        for op in (">=", "<=", ">", "<", "==", "!="):
            cond = SignatureCondition(field="packet_count", op=op, value=1)  # type: ignore[arg-type]
            assert cond.op == op


# ---------------------------------------------------------------------------
# TestSignatureSchema (6 tests)
# ---------------------------------------------------------------------------


class TestSignatureSchema:
    def test_valid_signature_parses(self):
        sig = _make_sig(
            sig_id="sig_001_syn_flood",
            name="SYN Flood",
            description="High-volume SYN flood attack.",
            severity="critical",
            protocols=[6],
            confidence=0.95,
            conditions=[{"field": "syn_ratio", "op": ">=", "value": 0.9}],
            mitre_technique="T1498.001",
        )
        assert sig.id == "sig_001_syn_flood"
        assert sig.mitre_technique == "T1498.001"

    def test_invalid_id_format_raises(self):
        with pytest.raises(ValidationError):
            Signature(
                id="BAD_FORMAT",
                name="Bad",
                description="Should fail validation.",
                severity="low",
                protocols=[6],
                confidence=0.5,
                conditions=[SignatureCondition(field="packet_count", op=">=", value=1)],
            )

    def test_unknown_protocol_raises(self):
        with pytest.raises(ValidationError, match="Unsupported protocol"):
            Signature(
                id="sig_001_test_rule",
                name="Test",
                description="Unknown protocol 99.",
                severity="low",
                protocols=[99],
                confidence=0.5,
                conditions=[SignatureCondition(field="packet_count", op=">=", value=1)],
            )

    def test_empty_conditions_list_raises(self):
        with pytest.raises(ValidationError):
            Signature(
                id="sig_001_test_rule",
                name="Test",
                description="No conditions at all.",
                severity="low",
                protocols=[6],
                confidence=0.5,
                conditions=[],
            )

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValidationError):
            Signature(
                id="sig_001_test_rule",
                name="Test",
                description="Confidence out of range.",
                severity="low",
                protocols=[6],
                confidence=1.5,
                conditions=[SignatureCondition(field="packet_count", op=">=", value=1)],
            )

    def test_unknown_severity_raises(self):
        with pytest.raises(ValidationError):
            Signature(
                id="sig_001_test_rule",
                name="Test",
                description="Unknown severity level.",
                severity="extreme",  # type: ignore[arg-type]
                protocols=[6],
                confidence=0.5,
                conditions=[SignatureCondition(field="packet_count", op=">=", value=1)],
            )


# ---------------------------------------------------------------------------
# TestSignatureSetSchema (3 tests)
# ---------------------------------------------------------------------------


class TestSignatureSetSchema:
    def test_valid_set_parses(self):
        raw = json.loads(_MINIMAL_JSON)
        sig_set = SignatureSet.model_validate(raw)
        assert sig_set.version == "1.0"
        assert len(sig_set.signatures) == 1

    def test_empty_signatures_list_is_allowed(self):
        raw = {"version": "1.0", "description": "Empty set.", "signatures": []}
        sig_set = SignatureSet.model_validate(raw)
        assert sig_set.signatures == []

    def test_missing_version_raises(self):
        raw = {"description": "No version.", "signatures": []}
        with pytest.raises(ValidationError):
            SignatureSet.model_validate(raw)


# ---------------------------------------------------------------------------
# TestSignatureManagerHMAC (5 tests)
# ---------------------------------------------------------------------------


class TestSignatureManagerHMAC:
    def test_valid_hmac_passes(self, tmp_path):
        content = _MINIMAL_JSON.encode()
        (tmp_path / "signatures.json").write_bytes(content)
        (tmp_path / "signatures.json.hmac").write_text(_hmac_digest(content, "test-secret"))
        manager = SignatureManager(tmp_path / "signatures.json", secret="test-secret")
        sigs = manager.load()
        assert len(sigs) == 1

    def test_wrong_secret_raises(self, tmp_path):
        content = _MINIMAL_JSON.encode()
        (tmp_path / "signatures.json").write_bytes(content)
        (tmp_path / "signatures.json.hmac").write_text(_hmac_digest(content, "correct-secret"))
        manager = SignatureManager(tmp_path / "signatures.json", secret="wrong-secret")
        with pytest.raises(SignatureLoadError, match="HMAC verification failed"):
            manager.load()

    def test_tampered_content_raises(self, tmp_path):
        content = _MINIMAL_JSON.encode()
        (tmp_path / "signatures.json").write_bytes(content)
        (tmp_path / "signatures.json.hmac").write_text(_hmac_digest(content, "test-secret"))
        # Tamper with the file after signing
        (tmp_path / "signatures.json").write_bytes(content + b" ")
        manager = SignatureManager(tmp_path / "signatures.json", secret="test-secret")
        with pytest.raises(SignatureLoadError, match="HMAC verification failed"):
            manager.load()

    def test_missing_hmac_file_raises(self, tmp_path):
        content = _MINIMAL_JSON.encode()
        (tmp_path / "signatures.json").write_bytes(content)
        manager = SignatureManager(tmp_path / "signatures.json", secret="test-secret")
        with pytest.raises(SignatureLoadError, match="HMAC file not found"):
            manager.load()

    def test_missing_json_file_raises(self, tmp_path):
        manager = SignatureManager(tmp_path / "signatures.json", secret="test-secret")
        with pytest.raises(SignatureLoadError, match="not found"):
            manager.load()


# ---------------------------------------------------------------------------
# TestSignatureManagerParse (3 tests)
# ---------------------------------------------------------------------------


class TestSignatureManagerParse:
    def test_invalid_json_raises(self, tmp_path):
        content = b"{ this is not valid json }"
        (tmp_path / "signatures.json").write_bytes(content)
        (tmp_path / "signatures.json.hmac").write_text(_hmac_digest(content, "s"))
        manager = SignatureManager(tmp_path / "signatures.json", secret="s")
        with pytest.raises(SignatureLoadError, match="Malformed JSON"):
            manager.load()

    def test_schema_validation_error_raises(self, tmp_path):
        content = json.dumps({"version": "1.0", "description": "x", "signatures": [{"id": "bad"}]}).encode()
        (tmp_path / "signatures.json").write_bytes(content)
        (tmp_path / "signatures.json.hmac").write_text(_hmac_digest(content, "s"))
        manager = SignatureManager(tmp_path / "signatures.json", secret="s")
        with pytest.raises(SignatureLoadError, match="schema validation failed"):
            manager.load()

    def test_load_real_signatures_file(self):
        sigs_path = _PROJECT_ROOT / "signatures" / "signatures.json"
        manager = SignatureManager(sigs_path, secret=_DEV_SECRET)
        sigs = manager.load()
        assert len(sigs) == 17
        assert all(sig.id.startswith("sig_") for sig in sigs)


# ---------------------------------------------------------------------------
# TestNamespaceExtraction (3 tests)
# ---------------------------------------------------------------------------


class TestNamespaceExtraction:
    def test_all_expected_fields_present(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        ns = _extract_namespace(flow)
        expected = {
            "packet_count", "byte_count", "duration",
            "total_packets", "total_bytes",
            "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
            "syn_ratio", "rst_ratio", "mean_pkt_len", "std_pkt_len", "mean_iat",
            "src_port", "dst_port", "protocol",
            "min_port", "max_port",
        }
        assert expected.issubset(ns.keys())

    def test_flag_counts_and_ratios_correct(self):
        # 4 SYN packets
        pkts = [_tcp_pkt(float(i), 0x02) for i in range(4)]
        flow = _build_flow(pkts)
        ns = _extract_namespace(flow)
        assert ns["syn_count"] == 4.0
        assert ns["syn_ratio"] == 1.0
        assert ns["ack_count"] == 0.0

    def test_min_max_port_correct(self):
        pkt = _tcp_pkt(0.0, 0x02, dst_port=22, src_port=54321)
        flow = _build_flow([pkt])
        ns = _extract_namespace(flow)
        assert ns["min_port"] == 22.0
        assert ns["max_port"] == 54321.0


# ---------------------------------------------------------------------------
# TestConditionEvaluation (6 tests)
# ---------------------------------------------------------------------------


class TestConditionEvaluation:
    def _ns(self, **kwargs: float) -> dict[str, float]:
        base: dict[str, float] = {
            "packet_count": 10.0, "syn_ratio": 0.5, "syn_count": 5.0,
            "ack_count": 5.0, "fin_count": 0.0, "rst_count": 0.0,
            "psh_count": 0.0, "urg_count": 0.0, "byte_count": 1000.0,
            "duration": 1.0, "total_packets": 10.0, "total_bytes": 1000.0,
            "rst_ratio": 0.0, "mean_pkt_len": 100.0, "std_pkt_len": 0.0,
            "mean_iat": 0.1, "src_port": 54321.0, "dst_port": 80.0,
            "protocol": 6.0, "min_port": 80.0, "max_port": 54321.0,
        }
        base.update(kwargs)
        return base

    def test_gte_passes_when_equal(self):
        conds = [SignatureCondition(field="packet_count", op=">=", value=10)]
        assert _evaluate_conditions(conds, self._ns(packet_count=10.0)) is True

    def test_gte_fails_when_below(self):
        conds = [SignatureCondition(field="packet_count", op=">=", value=10)]
        assert _evaluate_conditions(conds, self._ns(packet_count=9.9)) is False

    def test_lt_strict_boundary(self):
        conds = [SignatureCondition(field="duration", op="<", value=5.0)]
        assert _evaluate_conditions(conds, self._ns(duration=4.9)) is True
        assert _evaluate_conditions(conds, self._ns(duration=5.0)) is False

    def test_equality_match(self):
        conds = [SignatureCondition(field="min_port", op="==", value=22)]
        assert _evaluate_conditions(conds, self._ns(min_port=22.0)) is True
        assert _evaluate_conditions(conds, self._ns(min_port=80.0)) is False

    def test_inequality_match(self):
        conds = [SignatureCondition(field="syn_count", op="!=", value=0)]
        assert _evaluate_conditions(conds, self._ns(syn_count=1.0)) is True
        assert _evaluate_conditions(conds, self._ns(syn_count=0.0)) is False

    def test_and_semantics_all_must_pass(self):
        conds = [
            SignatureCondition(field="packet_count", op=">=", value=10),
            SignatureCondition(field="syn_ratio", op=">=", value=0.9),
        ]
        # Both pass
        assert _evaluate_conditions(conds, self._ns(packet_count=100.0, syn_ratio=0.95)) is True
        # Second fails
        assert _evaluate_conditions(conds, self._ns(packet_count=100.0, syn_ratio=0.5)) is False
        # First fails
        assert _evaluate_conditions(conds, self._ns(packet_count=5.0, syn_ratio=0.95)) is False


# ---------------------------------------------------------------------------
# TestProtocolIndexing (4 tests)
# ---------------------------------------------------------------------------


class TestProtocolIndexing:
    def test_tcp_sig_only_in_protocol_6_index(self):
        sig = _make_sig(sig_id="sig_001_test_rule", protocols=[6])
        engine = SignatureEngine([sig])
        assert 6 in engine.protocol_index
        assert 1 not in engine.protocol_index

    def test_icmp_sig_only_in_protocol_1_index(self):
        sig = _make_sig(sig_id="sig_001_test_rule", protocols=[1])
        engine = SignatureEngine([sig])
        assert 1 in engine.protocol_index
        assert 6 not in engine.protocol_index

    def test_multi_protocol_sig_in_both_indexes(self):
        sig = _make_sig(sig_id="sig_001_test_rule", protocols=[1, 6])
        engine = SignatureEngine([sig])
        assert engine.protocol_index.get(1) == 1
        assert engine.protocol_index.get(6) == 1

    def test_protocol_index_counts_correct(self):
        tcp_sig = _make_sig(sig_id="sig_001_test_rule", protocols=[6])
        icmp_sig = _make_sig(sig_id="sig_002_test_rule2", name="Test2", protocols=[1])
        engine = SignatureEngine([tcp_sig, icmp_sig])
        assert engine.protocol_index[6] == 1
        assert engine.protocol_index[1] == 1
        assert engine.signature_count == 2


# ---------------------------------------------------------------------------
# TestSynFloodDetection (4 tests)
# ---------------------------------------------------------------------------


class TestSynFloodDetection:
    _SYN_FLOOD_SIG = _make_sig(
        sig_id="sig_001_syn_flood",
        name="SYN Flood",
        description="SYN flood signature.",
        severity="critical",
        protocols=[6],
        confidence=0.95,
        conditions=[
            {"field": "syn_ratio", "op": ">=", "value": 0.9},
            {"field": "packet_count", "op": ">=", "value": 100},
        ],
        mitre_technique="T1498.001",
    )

    def test_syn_flood_triggers_on_high_volume(self):
        pkts = [_tcp_pkt(float(i) * 0.001, 0x02) for i in range(100)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SYN_FLOOD_SIG])
        alerts = engine.analyse(flow)
        assert len(alerts) == 1
        assert alerts[0].signature_id == "sig_001_syn_flood"

    def test_below_packet_threshold_no_alert(self):
        pkts = [_tcp_pkt(float(i) * 0.001, 0x02) for i in range(10)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SYN_FLOOD_SIG])
        assert engine.analyse(flow) == []

    def test_low_syn_ratio_no_alert(self):
        # 50 SYN + 50 ACK = 100 packets, syn_ratio = 0.5
        pkts = []
        for i in range(50):
            pkts.append(_tcp_pkt(float(i) * 0.002, 0x02))
            pkts.append(_tcp_pkt(float(i) * 0.002 + 0.001, 0x10))
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SYN_FLOOD_SIG])
        assert engine.analyse(flow) == []

    def test_alert_fields_correct(self):
        pkts = [_tcp_pkt(float(i) * 0.001, 0x02) for i in range(100)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SYN_FLOOD_SIG])
        alerts = engine.analyse(flow)
        assert alerts[0].severity == "critical"
        assert alerts[0].threat_type == "syn_flood"
        assert alerts[0].confidence == 0.95
        assert alerts[0].mitre_technique == "T1498.001"


# ---------------------------------------------------------------------------
# TestRSTFloodDetection (2 tests)
# ---------------------------------------------------------------------------


class TestRSTFloodDetection:
    _RST_FLOOD_SIG = _make_sig(
        sig_id="sig_002_rst_flood",
        name="RST Flood",
        description="RST flood signature.",
        severity="high",
        protocols=[6],
        confidence=0.90,
        conditions=[
            {"field": "rst_ratio", "op": ">=", "value": 0.9},
            {"field": "packet_count", "op": ">=", "value": 50},
        ],
    )

    def test_rst_flood_triggers(self):
        pkts = [_tcp_pkt(float(i) * 0.001, 0x04) for i in range(50)]  # RST flag
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._RST_FLOOD_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_below_threshold_no_rst_alert(self):
        pkts = [_tcp_pkt(float(i) * 0.001, 0x04) for i in range(49)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._RST_FLOOD_SIG])
        assert engine.analyse(flow) == []


# ---------------------------------------------------------------------------
# TestICMPFloodDetection (2 tests)
# ---------------------------------------------------------------------------


class TestICMPFloodDetection:
    _ICMP_FLOOD_SIG = _make_sig(
        sig_id="sig_003_icmp_flood",
        name="ICMP Flood",
        description="ICMP flood signature.",
        severity="high",
        protocols=[1],
        confidence=0.90,
        conditions=[
            {"field": "packet_count", "op": ">=", "value": 100},
            {"field": "mean_iat", "op": "<=", "value": 0.01},
        ],
    )

    def test_icmp_flood_triggers_high_rate(self):
        pkts = [_icmp_pkt(float(i) * 0.005) for i in range(100)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._ICMP_FLOOD_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_slow_icmp_no_alert(self):
        pkts = [_icmp_pkt(float(i) * 1.0) for i in range(100)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._ICMP_FLOOD_SIG])
        assert engine.analyse(flow) == []


# ---------------------------------------------------------------------------
# TestNullScanDetection (3 tests)
# ---------------------------------------------------------------------------


class TestNullScanDetection:
    _NULL_SCAN_SIG = _make_sig(
        sig_id="sig_004_null_scan",
        name="TCP NULL Scan",
        description="TCP NULL scan signature.",
        severity="medium",
        protocols=[6],
        confidence=0.95,
        conditions=[
            {"field": "syn_count", "op": "==", "value": 0},
            {"field": "fin_count", "op": "==", "value": 0},
            {"field": "rst_count", "op": "==", "value": 0},
            {"field": "ack_count", "op": "==", "value": 0},
            {"field": "psh_count", "op": "==", "value": 0},
            {"field": "urg_count", "op": "==", "value": 0},
            {"field": "packet_count", "op": ">=", "value": 1},
        ],
    )

    def test_null_scan_triggers_on_zero_flag_packets(self):
        pkts = [_tcp_pkt(float(i) * 0.01, 0x00) for i in range(4)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._NULL_SCAN_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_flow_with_syn_does_not_trigger_null_scan(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        engine = SignatureEngine([self._NULL_SCAN_SIG])
        assert engine.analyse(flow) == []

    def test_single_null_packet_triggers(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x00)])
        engine = SignatureEngine([self._NULL_SCAN_SIG])
        assert len(engine.analyse(flow)) == 1


# ---------------------------------------------------------------------------
# TestFINScanDetection (2 tests)
# ---------------------------------------------------------------------------


class TestFINScanDetection:
    _FIN_SCAN_SIG = _make_sig(
        sig_id="sig_005_fin_scan",
        name="TCP FIN Scan",
        description="TCP FIN scan signature.",
        severity="medium",
        protocols=[6],
        confidence=0.90,
        conditions=[
            {"field": "fin_count", "op": ">=", "value": 1},
            {"field": "syn_count", "op": "==", "value": 0},
            {"field": "ack_count", "op": "==", "value": 0},
            {"field": "rst_count", "op": "==", "value": 0},
        ],
    )

    def test_fin_only_packets_trigger(self):
        pkts = [_tcp_pkt(float(i) * 0.01, 0x01) for i in range(4)]  # FIN=0x01
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._FIN_SCAN_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_fin_ack_does_not_trigger_fin_scan(self):
        # FIN+ACK = 0x11 — legitimate TCP teardown
        flow = _build_flow([_tcp_pkt(0.0, 0x11)])
        engine = SignatureEngine([self._FIN_SCAN_SIG])
        assert engine.analyse(flow) == []


# ---------------------------------------------------------------------------
# TestXMASScanDetection (2 tests)
# ---------------------------------------------------------------------------


class TestXMASScanDetection:
    _XMAS_SCAN_SIG = _make_sig(
        sig_id="sig_006_xmas_scan",
        name="TCP XMAS Scan",
        description="TCP XMAS scan signature.",
        severity="medium",
        protocols=[6],
        confidence=0.95,
        conditions=[
            {"field": "fin_count", "op": ">=", "value": 1},
            {"field": "psh_count", "op": ">=", "value": 1},
            {"field": "urg_count", "op": ">=", "value": 1},
            {"field": "syn_count", "op": "==", "value": 0},
            {"field": "ack_count", "op": "==", "value": 0},
        ],
    )

    def test_xmas_scan_triggers_on_fin_psh_urg(self):
        # 0x29 = FIN(0x01) + PSH(0x08) + URG(0x20)
        pkts = [_tcp_pkt(float(i) * 0.01, 0x29) for i in range(3)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._XMAS_SCAN_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_fin_only_does_not_trigger_xmas(self):
        # FIN only — psh_count and urg_count remain 0
        flow = _build_flow([_tcp_pkt(0.0, 0x01)])
        engine = SignatureEngine([self._XMAS_SCAN_SIG])
        assert engine.analyse(flow) == []


# ---------------------------------------------------------------------------
# TestBruteForceDetection (4 tests)
# ---------------------------------------------------------------------------


class TestBruteForceDetection:
    _SSH_SIG = _make_sig(
        sig_id="sig_007_ssh_brute_force",
        name="SSH Brute Force",
        description="SSH brute force signature.",
        severity="high",
        protocols=[6],
        confidence=0.85,
        conditions=[
            {"field": "min_port", "op": "==", "value": 22},
            {"field": "packet_count", "op": ">=", "value": 20},
            {"field": "duration", "op": "<=", "value": 60},
        ],
    )
    _HTTP_SIG = _make_sig(
        sig_id="sig_008_http_brute_force",
        name="HTTP Brute Force",
        description="HTTP brute force signature.",
        severity="high",
        protocols=[6],
        confidence=0.80,
        conditions=[
            {"field": "min_port", "op": "==", "value": 80},
            {"field": "packet_count", "op": ">=", "value": 50},
            {"field": "duration", "op": "<=", "value": 120},
        ],
    )

    def test_ssh_brute_force_triggers(self):
        # 20 packets to port 22, spread over 19s
        pkts = [_tcp_pkt(float(i), 0x18, dst_port=22) for i in range(20)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SSH_SIG])
        alerts = engine.analyse(flow)
        assert len(alerts) == 1
        assert alerts[0].threat_type == "ssh_brute_force"

    def test_http_brute_force_triggers(self):
        # 50 packets to port 80, spread over 5s
        pkts = [_tcp_pkt(float(i) * 0.1, 0x18, dst_port=80) for i in range(50)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._HTTP_SIG])
        assert len(engine.analyse(flow)) == 1

    def test_ssh_below_packet_threshold_no_alert(self):
        pkts = [_tcp_pkt(float(i), 0x18, dst_port=22) for i in range(5)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SSH_SIG])
        assert engine.analyse(flow) == []

    def test_non_service_port_no_brute_alert(self):
        # Port 8080 — doesn't match min_port==22 or min_port==80
        pkts = [_tcp_pkt(float(i) * 0.1, 0x18, dst_port=8080) for i in range(50)]
        flow = _build_flow(pkts)
        engine = SignatureEngine([self._SSH_SIG, self._HTTP_SIG])
        assert engine.analyse(flow) == []


# ---------------------------------------------------------------------------
# TestBenignFlowNoAlert (3 tests)
# ---------------------------------------------------------------------------


class TestBenignFlowNoAlert:
    """Verify that canonical benign flows produce no alerts from the full rule set."""

    @pytest.fixture(autouse=True)
    def engine(self):
        sigs_path = _PROJECT_ROOT / "signatures" / "signatures.json"
        manager = SignatureManager(sigs_path, secret=_DEV_SECRET)
        self._engine = SignatureEngine(manager.load())

    def test_normal_http_flow_no_alerts(self):
        pkts = _load_fixture("normal_http")
        flow = _build_flow(pkts)
        assert self._engine.analyse(flow) == []

    def test_normal_ssh_session_no_alerts(self):
        pkts = _load_fixture("bidirectional_ssh")
        flow = _build_flow(pkts)
        assert self._engine.analyse(flow) == []

    def test_small_icmp_normal_rate_no_alerts(self):
        pkts = _load_fixture("icmp_flood")  # only 5 packets — below threshold
        flow = _build_flow(pkts)
        assert self._engine.analyse(flow) == []
