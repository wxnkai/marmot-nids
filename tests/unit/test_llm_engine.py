"""
tests.unit.test_llm_engine
============================
Unit tests for Phase 4 — LLM + RAG engine.

Coverage:
    * LLM response parser (valid JSON, markdown fencing, malformed input)
    * Confidence threshold filtering
    * Pydantic schema validation for LLM responses
    * Prompt builder determinism and structure
    * RAG ingestor chunk splitting logic
    * Namespace extraction for LLM prompts
    * Benign flow classification

All tests are offline — no Ollama, no ChromaDB, no network calls.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from core.capture.flow_assembler import FlowAssembler, FlowKey, FlowRecord, ParsedPacket
from core.capture.flow_stats import FlowStats
from core.detection.llm.parser import (
    LLMAlert,
    LLMParser,
    LLMResponse,
    ParseResult,
)
from core.detection.llm.prompt_builder import PromptBuilder
from core.detection.llm.rag.ingestor import KnowledgeIngestor
from core.detection.llm.rag.retriever import RAGRetriever, RetrievedChunk

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent.parent


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


def _build_flow(packets: list[ParsedPacket]) -> FlowRecord:
    assembler = FlowAssembler()
    flow: FlowRecord | None = None
    for pkt in packets:
        flow = assembler.process(pkt)
    assert flow is not None
    return flow


def _valid_response_json(**overrides) -> str:
    """Build a valid LLM response JSON string."""
    data = {
        "alerts": [
            {
                "threat_type": "syn_flood",
                "severity": "critical",
                "confidence": 0.95,
                "reasoning": "High SYN ratio with 100+ packets.",
                "affected_flow": "10.0.0.1:54321 <-> 10.0.0.2:80 TCP",
                "mitre_technique": "T1498.001",
            }
        ],
        "benign_flows": [],
        "analysis_notes": "One suspicious flow detected.",
    }
    data.update(overrides)
    return json.dumps(data)


def _benign_response_json() -> str:
    return json.dumps({
        "alerts": [],
        "benign_flows": ["10.0.0.1:54321 <-> 10.0.0.2:80 TCP"],
        "analysis_notes": "All flows appear benign.",
    })


# ---------------------------------------------------------------------------
# TestLLMAlertSchema (5 tests)
# ---------------------------------------------------------------------------


class TestLLMAlertSchema:
    def test_valid_alert_parses(self):
        alert = LLMAlert(
            threat_type="syn_flood",
            severity="critical",
            confidence=0.95,
            reasoning="High SYN ratio.",
            affected_flow="10.0.0.1:1234 <-> 10.0.0.2:80 TCP",
            mitre_technique="T1498.001",
        )
        assert alert.threat_type == "syn_flood"
        assert alert.severity == "critical"

    def test_severity_normalized_to_lowercase(self):
        alert = LLMAlert(
            threat_type="test",
            severity="HIGH",
            confidence=0.5,
            reasoning="Test.",
            affected_flow="test",
        )
        assert alert.severity == "high"

    def test_invalid_severity_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="Invalid severity"):
            LLMAlert(
                threat_type="test",
                severity="extreme",
                confidence=0.5,
                reasoning="Test.",
                affected_flow="test",
            )

    def test_confidence_below_zero_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            LLMAlert(
                threat_type="test",
                severity="low",
                confidence=-0.1,
                reasoning="Test.",
                affected_flow="test",
            )

    def test_mitre_technique_optional(self):
        alert = LLMAlert(
            threat_type="test",
            severity="low",
            confidence=0.5,
            reasoning="Test.",
            affected_flow="test",
        )
        assert alert.mitre_technique is None


# ---------------------------------------------------------------------------
# TestLLMResponseSchema (3 tests)
# ---------------------------------------------------------------------------


class TestLLMResponseSchema:
    def test_full_response_parses(self):
        data = json.loads(_valid_response_json())
        resp = LLMResponse.model_validate(data)
        assert len(resp.alerts) == 1
        assert resp.analysis_notes is not None

    def test_empty_alerts_is_valid(self):
        data = json.loads(_benign_response_json())
        resp = LLMResponse.model_validate(data)
        assert resp.alerts == []
        assert len(resp.benign_flows) == 1

    def test_defaults_for_missing_fields(self):
        resp = LLMResponse.model_validate({})
        assert resp.alerts == []
        assert resp.benign_flows == []
        assert resp.analysis_notes is None


# ---------------------------------------------------------------------------
# TestLLMParser (10 tests)
# ---------------------------------------------------------------------------


class TestLLMParser:
    def test_valid_json_parsed_successfully(self):
        parser = LLMParser(confidence_threshold=0.0)
        result = parser.parse(_valid_response_json())
        assert result.success is True
        assert len(result.alerts) == 1
        assert result.alerts[0].threat_type == "syn_flood"

    def test_benign_response_has_no_alerts(self):
        parser = LLMParser()
        result = parser.parse(_benign_response_json())
        assert result.success is True
        assert len(result.alerts) == 0
        assert len(result.benign_flows) == 1

    def test_empty_string_returns_failure(self):
        parser = LLMParser()
        result = parser.parse("")
        assert result.success is False
        assert "Empty" in result.error

    def test_invalid_json_returns_failure(self):
        parser = LLMParser()
        result = parser.parse("This is not JSON at all!")
        assert result.success is False
        assert "Invalid JSON" in result.error

    def test_markdown_fenced_json_extracted(self):
        fenced = "```json\n" + _valid_response_json() + "\n```"
        parser = LLMParser(confidence_threshold=0.0)
        result = parser.parse(fenced)
        assert result.success is True
        assert len(result.alerts) == 1

    def test_json_with_preamble_text_extracted(self):
        text = "Here is my analysis:\n" + _valid_response_json()
        parser = LLMParser(confidence_threshold=0.0)
        result = parser.parse(text)
        assert result.success is True

    def test_confidence_threshold_filters_low_confidence(self):
        low_conf = json.dumps({
            "alerts": [{
                "threat_type": "maybe_scan",
                "severity": "low",
                "confidence": 0.3,
                "reasoning": "Uncertain.",
                "affected_flow": "test",
            }],
            "benign_flows": [],
        })
        parser = LLMParser(confidence_threshold=0.6)
        result = parser.parse(low_conf)
        assert result.success is True
        assert len(result.alerts) == 0  # filtered out

    def test_confidence_at_threshold_passes(self):
        exact_conf = json.dumps({
            "alerts": [{
                "threat_type": "test",
                "severity": "low",
                "confidence": 0.6,
                "reasoning": "Exactly at threshold.",
                "affected_flow": "test",
            }],
            "benign_flows": [],
        })
        parser = LLMParser(confidence_threshold=0.6)
        result = parser.parse(exact_conf)
        assert result.success is True
        assert len(result.alerts) == 1

    def test_raw_text_preserved_in_result(self):
        raw = _valid_response_json()
        parser = LLMParser(confidence_threshold=0.0)
        result = parser.parse(raw)
        assert result.raw_text == raw

    def test_schema_validation_failure_returns_error(self):
        # Valid JSON but invalid schema (confidence > 1.0)
        bad = json.dumps({
            "alerts": [{
                "threat_type": "test",
                "severity": "low",
                "confidence": 5.0,  # invalid
                "reasoning": "Bad.",
                "affected_flow": "test",
            }]
        })
        parser = LLMParser()
        result = parser.parse(bad)
        assert result.success is False
        assert "validation" in result.error.lower()


# ---------------------------------------------------------------------------
# TestPromptBuilder (5 tests)
# ---------------------------------------------------------------------------


class TestPromptBuilder:
    def test_prompt_contains_system_section(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        prompt = builder.build([flow])
        assert "=== SYSTEM ===" in prompt
        assert "intrusion detection analyst" in prompt

    def test_prompt_contains_flow_data_section(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        prompt = builder.build([flow])
        assert "=== FLOW DATA" in prompt
        assert "Packets:" in prompt

    def test_prompt_contains_output_instructions(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        prompt = builder.build([flow])
        assert "=== OUTPUT INSTRUCTIONS ===" in prompt
        assert "alerts" in prompt

    def test_prompt_without_rag_shows_no_context_message(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        prompt = builder.build([flow], rag_context=None)
        assert "No threat intelligence context" in prompt

    def test_prompt_with_rag_includes_context(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        prompt = builder.build([flow], rag_context="SYN floods target port 80.")
        assert "SYN floods target port 80." in prompt
        assert "THREAT INTELLIGENCE" in prompt

    def test_prompt_multiple_flows_numbered(self):
        flows = [
            _build_flow([_tcp_pkt(0.0, 0x02, dst_port=80)]),
            _build_flow([_tcp_pkt(1.0, 0x02, dst_port=443)]),
        ]
        builder = PromptBuilder()
        prompt = builder.build(flows)
        assert "Flow 1:" in prompt
        assert "Flow 2:" in prompt

    def test_prompt_tcp_includes_flag_breakdown(self):
        flow = _build_flow([
            _tcp_pkt(0.0, 0x02),
            _tcp_pkt(1.0, 0x10),
        ])
        builder = PromptBuilder()
        prompt = builder.build([flow])
        assert "SYN:" in prompt
        assert "ACK:" in prompt


# ---------------------------------------------------------------------------
# TestPromptDeterminism (2 tests)
# ---------------------------------------------------------------------------


class TestPromptDeterminism:
    def test_same_inputs_produce_same_prompt(self):
        flow = _build_flow([_tcp_pkt(0.0, 0x02)])
        builder = PromptBuilder()
        p1 = builder.build([flow])
        p2 = builder.build([flow])
        assert p1 == p2

    def test_different_flows_produce_different_prompts(self):
        f1 = _build_flow([_tcp_pkt(0.0, 0x02, dst_port=80)])
        f2 = _build_flow([_tcp_pkt(0.0, 0x02, dst_port=443)])
        builder = PromptBuilder()
        p1 = builder.build([f1])
        p2 = builder.build([f2])
        assert p1 != p2


# ---------------------------------------------------------------------------
# TestRAGRetriever (3 tests)
# ---------------------------------------------------------------------------


class TestRAGRetriever:
    def test_uninitialized_retriever_returns_empty(self):
        retriever = RAGRetriever()
        assert retriever.is_ready is False
        assert retriever.retrieve("syn flood") == []

    def test_format_context_empty_chunks_returns_empty(self):
        retriever = RAGRetriever()
        assert retriever.format_context([]) == ""

    def test_format_context_with_chunks(self):
        retriever = RAGRetriever()
        chunks = [
            RetrievedChunk(text="SYN flood info.", source="01_dos.md", score=0.9),
            RetrievedChunk(text="RST flood info.", source="01_dos.md", score=0.7),
        ]
        ctx = retriever.format_context(chunks)
        assert "SYN flood info." in ctx
        assert "RST flood info." in ctx
        assert "01_dos.md" in ctx
        assert "0.90" in ctx


# ---------------------------------------------------------------------------
# TestKnowledgeIngestor (3 tests)
# ---------------------------------------------------------------------------


class TestKnowledgeIngestor:
    def test_chunk_file_splits_on_h2_headings(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text(textwrap.dedent("""\
            # Title

            Intro paragraph.

            ## Section One

            Content for section one.

            ## Section Two

            Content for section two.
        """))
        ingestor = KnowledgeIngestor(knowledge_dir=tmp_path)
        chunks = ingestor._chunk_file(md)
        assert len(chunks) == 3  # title+intro, section one, section two

    def test_chunk_file_handles_single_section(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text("Just a single paragraph with no headings.")
        ingestor = KnowledgeIngestor(knowledge_dir=tmp_path)
        chunks = ingestor._chunk_file(md)
        assert len(chunks) == 1

    def test_chunk_file_empty_file_returns_empty(self, tmp_path):
        md = tmp_path / "empty.md"
        md.write_text("")
        ingestor = KnowledgeIngestor(knowledge_dir=tmp_path)
        chunks = ingestor._chunk_file(md)
        assert chunks == []

    def test_missing_knowledge_dir_raises(self):
        ingestor = KnowledgeIngestor(knowledge_dir=Path("/nonexistent/path"))
        with pytest.raises(FileNotFoundError):
            ingestor.ingest()


# ---------------------------------------------------------------------------
# TestKnowledgeFiles (2 tests)
# ---------------------------------------------------------------------------


class TestKnowledgeFiles:
    """Verify that the bundled knowledge files exist and are well-formed."""

    _KNOWLEDGE_DIR = (
        _PROJECT_ROOT / "core" / "detection" / "llm" / "rag" / "knowledge"
    )

    def test_knowledge_files_exist(self):
        md_files = list(self._KNOWLEDGE_DIR.glob("*.md"))
        assert len(md_files) >= 8, f"Expected 8+ knowledge files, found {len(md_files)}"

    def test_knowledge_files_have_h1_title(self):
        for md_file in self._KNOWLEDGE_DIR.glob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            assert content.startswith("# "), (
                f"{md_file.name} should start with an H1 heading"
            )


# ---------------------------------------------------------------------------
# TestParseResult (3 tests)
# ---------------------------------------------------------------------------


class TestParseResult:
    def test_successful_result_has_alerts(self):
        alert = LLMAlert(
            threat_type="test",
            severity="low",
            confidence=0.8,
            reasoning="Testing.",
            affected_flow="test",
        )
        result = ParseResult(success=True, alerts=[alert])
        assert result.success
        assert len(result.alerts) == 1

    def test_failed_result_has_error(self):
        result = ParseResult(success=False, error="Something broke")
        assert not result.success
        assert result.error == "Something broke"

    def test_parse_result_is_frozen(self):
        result = ParseResult(success=True)
        with pytest.raises(AttributeError):
            result.success = False  # type: ignore[misc]
