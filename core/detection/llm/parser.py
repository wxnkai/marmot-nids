"""
core.detection.llm.parser
=========================
Strict JSON parser for LLM threat-analysis responses.

Security relevance:
    The LLM's output is **untrusted external input**.  A compromised,
    misconfigured, or hallucinating model can produce arbitrarily malformed
    JSON, partial output, prompt-injection-embedded strings, or complete
    nonsense.  ``LLMParser`` guarantees:

    1. **No raised exceptions** — ``parse()`` always returns a ``ParseResult``.
       If parsing fails, ``ParseResult.success`` is ``False`` and
       ``ParseResult.error`` describes the failure.

    2. **Pydantic validation** — every field in the response is validated
       against a strict schema.  Free-form strings from the LLM cannot inject
       types or structure that downstream code does not expect.

    3. **Confidence filtering** — alerts below ``confidence_threshold`` are
       silently discarded before they reach callers, providing a noise floor.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class LLMAlert(BaseModel):
    """A single alert produced by the LLM threat analysis.

    Attributes:
        threat_type: Slug label for the threat category
            (e.g. ``"syn_flood"``, ``"ssh_brute_force"``).
        severity: One of ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
        confidence: LLM's self-assessed confidence in [0.0, 1.0].
        reasoning: Free-text explanation of why the alert was raised.
        affected_flow: Flow key string identifying the flow
            (e.g. ``"10.0.0.1:1234 <-> 10.0.0.2:80 TCP"``).
        mitre_technique: MITRE ATT&CK technique ID, or ``None``.

    Security note:
        ``reasoning`` is free-form LLM output.  Never render it as HTML
        without escaping — it could contain crafted XSS payloads.
    """

    threat_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    affected_flow: str
    mitre_technique: str | None = None

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        v_lower = v.lower().strip()
        if v_lower not in allowed:
            raise ValueError(
                f"Invalid severity '{v}'. Must be one of: {sorted(allowed)}"
            )
        return v_lower


class LLMResponse(BaseModel):
    """Root schema for the JSON response expected from the LLM.

    Attributes:
        alerts: List of detected threats.  May be empty if the LLM
            considers all flows benign.
        benign_flows: List of flow key strings the LLM explicitly
            classified as benign.
        analysis_notes: Optional free-text notes from the LLM about
            the analysis (e.g. caveats, confidence rationale).

    Security note:
        The LLM is instructed to respond ONLY with this JSON schema.
        Any response that does not conform is treated as a parse failure.
    """

    alerts: list[LLMAlert] = Field(default_factory=list)
    benign_flows: list[str] = Field(default_factory=list)
    analysis_notes: str | None = None


# ---------------------------------------------------------------------------
# ParseResult wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParseResult:
    """Outcome of an LLM response parsing attempt.

    Attributes:
        success: ``True`` if the response was valid JSON matching the
            expected schema.
        alerts: Validated and confidence-filtered alert list (empty on
            failure).
        benign_flows: Flow keys classified as benign by the LLM.
        analysis_notes: Optional notes from the LLM.
        error: Human-readable error description if ``success=False``.
        raw_text: The original text received from the LLM (for debugging;
            never logged at INFO or above as it may contain sensitive data).

    Security note:
        ``raw_text`` may contain prompt-injection attempts, adversarial
        content, or sensitive flow data interpolated by the LLM.  It is
        retained only for DEBUG-level diagnostics and must never be displayed
        to untrusted users or stored in a user-facing database.
    """

    success: bool
    alerts: list[LLMAlert] = field(default_factory=list)
    benign_flows: list[str] = field(default_factory=list)
    analysis_notes: str | None = None
    error: str | None = None
    raw_text: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class LLMParser:
    """Parses and validates LLM threat-analysis JSON responses.

    Args:
        confidence_threshold: Minimum confidence score for an alert to be
            retained.  Alerts below this value are silently filtered out.
            Corresponds to ``LLM_CONFIDENCE_THRESHOLD`` in env config.

    Security note:
        The confidence threshold is a noise floor that trades recall for
        precision.  In high-security environments, lower the threshold to
        catch weaker signals; in noisy environments, raise it to reduce
        operator fatigue.
    """

    def __init__(self, confidence_threshold: float = 0.6) -> None:
        self._threshold: float = confidence_threshold

    def parse(self, raw_text: str) -> ParseResult:
        """Parse an LLM response string into a validated ``ParseResult``.

        This method **never raises**.  Any failure (JSON decode error,
        schema validation error, unexpected structure) is captured in a
        ``ParseResult`` with ``success=False``.

        Args:
            raw_text: The raw text response from the Ollama API.

        Returns:
            A ``ParseResult`` with ``success=True`` and validated alerts,
            or ``success=False`` with an error description.

        Security note:
            Called immediately after receiving an LLM response.  Nothing
            downstream sees the raw text unless it passes Pydantic
            validation first.
        """
        if not raw_text or not raw_text.strip():
            return ParseResult(
                success=False,
                error="Empty response from LLM",
                raw_text=raw_text,
            )

        # Step 1: extract JSON from possible markdown fencing or preamble
        json_str = self._extract_json(raw_text)

        # Step 2: parse raw JSON
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.debug("LLM JSON parse failed: %s", exc)
            return ParseResult(
                success=False,
                error=f"Invalid JSON: {exc}",
                raw_text=raw_text,
            )

        # Step 3: validate against Pydantic schema
        try:
            response = LLMResponse.model_validate(data)
        except Exception as exc:
            logger.debug("LLM schema validation failed: %s", exc)
            return ParseResult(
                success=False,
                error=f"Schema validation error: {exc}",
                raw_text=raw_text,
            )

        # Step 4: confidence threshold filtering
        filtered_alerts = [
            alert
            for alert in response.alerts
            if alert.confidence >= self._threshold
        ]

        discarded = len(response.alerts) - len(filtered_alerts)
        if discarded:
            logger.info(
                "Discarded %d LLM alert(s) below confidence threshold %.2f",
                discarded,
                self._threshold,
            )

        return ParseResult(
            success=True,
            alerts=filtered_alerts,
            benign_flows=response.benign_flows,
            analysis_notes=response.analysis_notes,
            raw_text=raw_text,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> str:
        """Extract JSON from an LLM response that may include markdown fencing.

        LLMs sometimes wrap their JSON output in ```json ... ``` blocks or
        include preamble text before the actual JSON payload.  This method
        strips common decorations to reach the raw JSON.

        Returns:
            The extracted JSON string, or the original text if no fencing
            is detected.
        """
        stripped = text.strip()

        # Handle ```json ... ``` fencing
        if stripped.startswith("```"):
            lines = stripped.split("\n")
            # Remove opening fence (```json or ```)
            lines = lines[1:]
            # Remove closing fence if present
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            return "\n".join(lines).strip()

        # Handle case where LLM starts with text before JSON
        brace_idx = stripped.find("{")
        if brace_idx > 0:
            # There's text before the first brace — try the brace-onward
            candidate = stripped[brace_idx:]
            bracket_idx = stripped.find("[")
            if bracket_idx >= 0 and bracket_idx < brace_idx:
                candidate = stripped[bracket_idx:]
            return candidate

        return stripped
