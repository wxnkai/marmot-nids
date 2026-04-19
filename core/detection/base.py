"""
core.detection.base
===================
Abstract base class and Alert dataclass shared by all detection engines.

Two concrete engines are planned:
* ``SignatureEngine`` (Phase 3) — rule-based matching against ``signatures.json``
* ``LLMEngine`` (Phase 4) — contextual analysis via Ollama/Gemma3 + ChromaDB RAG
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.capture.flow_assembler import FlowKey, FlowRecord


@dataclass(frozen=True)
class Alert:
    """Immutable alert raised by a detection engine against a completed flow.

    Attributes:
        flow_key: The normalised 5-tuple of the flow that triggered the alert.
        signature_id: Machine-readable identifier of the matching signature
            (e.g. ``"sig_001_syn_flood"``).
        signature_name: Human-readable name (e.g. ``"SYN Flood"``).
        threat_type: Threat category slug derived from the signature ID
            (e.g. ``"syn_flood"``).
        severity: Severity level: one of ``"low"``, ``"medium"``, ``"high"``,
            or ``"critical"``.
        confidence: Confidence score in [0.0, 1.0].  1.0 means near-certain
            match; lower values indicate heuristic or partial matches.
        description: Human-readable description of what was detected.
        timestamp: Unix epoch time at which the alert was raised.
        mitre_technique: MITRE ATT&CK technique identifier (e.g.
            ``"T1498.001"``), or ``None`` if no mapping exists.

    Security note:
        Alerts are immutable (``frozen=True``) to prevent downstream code
        from silently modifying threat metadata.  The blockchain logger and
        dashboard both receive the same frozen object.
    """

    flow_key: FlowKey
    signature_id: str
    signature_name: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    timestamp: float
    mitre_technique: str | None = None


class DetectionEngine(ABC):
    """Abstract interface implemented by all detection engines.

    All engines receive a completed ``FlowRecord`` (``is_expired=True``)
    from the flow assembler and return a (possibly empty) list of ``Alert``
    objects.

    Security note:
        Engines are designed to receive *completed* flows only.  Analysing
        partial flows risks generating alerts based on incomplete data,
        increasing both false positives (partially-observed benign connections)
        and false negatives (attack patterns that only emerge over the full
        flow lifetime).
    """

    @abstractmethod
    def analyse(self, flow: FlowRecord) -> list[Alert]:
        """Analyse a completed flow and return any matching alerts.

        Args:
            flow: A ``FlowRecord``, ideally with ``is_expired=True``.
                Callers should not pass active (in-progress) flows unless
                the engine explicitly supports streaming evaluation.

        Returns:
            A list of ``Alert`` objects for each threat detected.  An empty
            list means the flow matched no signatures.
        """
        ...
