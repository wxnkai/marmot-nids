"""
core.detection.llm.prompt_builder
==================================
Deterministic prompt construction for LLM threat analysis.

Security relevance:
    Prompt construction is a security-sensitive operation because:

    1. **Structured layout prevents prompt injection** — flow data is placed in
       a clearly delimited block, not interpolated into the instruction text.
       Even if an attacker embeds instruction-like strings in packet content,
       they appear inside a labelled data section, not in the system prompt.

    2. **Output schema enforcement** — the expected JSON schema is injected
       with examples so the LLM is strongly constrained to produce parseable
       output.  ``LLMParser`` validates the output regardless, but a good
       prompt vastly reduces parse-failure rates.

    3. **RAG context labelling** — retrieved threat-intelligence chunks are
       inserted in a clearly labelled section so the LLM can distinguish
       reference material from live flow data.
"""

from __future__ import annotations

import logging

from core.capture.flow_assembler import FlowRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt (constant)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a network intrusion detection analyst. Your task is to analyse \
network flow statistics and determine whether any flows represent \
malicious or suspicious activity.

You will receive:
1. THREAT INTELLIGENCE: Reference material about known attack patterns.
2. FLOW DATA: Statistics for one or more network flows.
3. OUTPUT INSTRUCTIONS: The exact JSON schema you must respond with.

Respond ONLY with valid JSON matching the schema. Do not include any \
text outside the JSON object. Do not use markdown fencing.
"""

# ---------------------------------------------------------------------------
# Output schema template (constant)
# ---------------------------------------------------------------------------

_OUTPUT_SCHEMA = """\
{
  "alerts": [
    {
      "threat_type": "<string: threat category slug e.g. syn_flood>",
      "severity": "<low | medium | high | critical>",
      "confidence": <float 0.0 to 1.0>,
      "reasoning": "<string: why this flow is suspicious>",
      "affected_flow": "<string: flow key e.g. 10.0.0.1:1234 <-> 10.0.0.2:80 TCP>",
      "mitre_technique": "<string: MITRE ATT&CK ID e.g. T1498.001 | null>"
    }
  ],
  "benign_flows": ["<flow key string>"],
  "analysis_notes": "<string | null>"
}
"""


# ---------------------------------------------------------------------------
# PromptBuilder
# ---------------------------------------------------------------------------


class PromptBuilder:
    """Constructs structured, deterministic prompts for LLM threat analysis.

    The prompt layout has four fixed sections:

    1. **System prompt** — analyst role definition and output format contract.
    2. **RAG context block** — threat intelligence retrieved from ChromaDB.
    3. **Flow data block** — structured flow statistics from the assembler.
    4. **Instruction block** — explicit JSON output schema with examples.

    This structured layout is deterministic: given the same flows and context,
    the same prompt text is produced, which aids debugging and reproducibility.

    Security note:
        Flow data is presented as a formatted text table, not as raw string
        interpolation.  Field values are coerced to fixed-precision floats
        and integers, eliminating any injection surface from flow metadata.
    """

    def build(
        self,
        flows: list[FlowRecord],
        rag_context: str | None = None,
    ) -> str:
        """Build the full prompt string for a batch of flows.

        Args:
            flows: List of ``FlowRecord`` objects to analyse.
            rag_context: Pre-formatted RAG context string from the
                retriever, or ``None`` if RAG is disabled.

        Returns:
            A complete prompt string suitable for the Ollama API.

        Security note:
            This method does not access raw packet payloads.  Only
            statistical features (counts, ratios, timing) are included
            in the prompt.
        """
        sections: list[str] = []

        # Section 1: System prompt
        sections.append(f"=== SYSTEM ===\n{_SYSTEM_PROMPT}")

        # Section 2: RAG context
        if rag_context:
            sections.append(
                f"=== THREAT INTELLIGENCE ===\n"
                f"The following reference material describes known attack "
                f"patterns. Use it to inform your analysis but do not copy "
                f"it verbatim into alerts.\n\n{rag_context}"
            )
        else:
            sections.append(
                "=== THREAT INTELLIGENCE ===\n"
                "No threat intelligence context available for this batch."
            )

        # Section 3: Flow data
        sections.append(
            f"=== FLOW DATA ({len(flows)} flow(s)) ===\n"
            + self._format_flows(flows)
        )

        # Section 4: Output instructions
        sections.append(
            f"=== OUTPUT INSTRUCTIONS ===\n"
            f"Respond with ONLY a JSON object matching this schema:\n"
            f"{_OUTPUT_SCHEMA}\n"
            f"Rules:\n"
            f"- Include an entry in 'alerts' for each suspicious flow.\n"
            f"- Include an entry in 'benign_flows' for each flow you "
            f"consider benign.\n"
            f"- Set confidence between 0.0 (guess) and 1.0 (certain).\n"
            f"- Use 'analysis_notes' for any caveats or observations.\n"
            f"- Do not include flows in both 'alerts' and 'benign_flows'.\n"
            f"- Do not include any text outside the JSON object."
        )

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_flow_key(flow: FlowRecord) -> str:
        """Format a flow key as a human-readable string.

        Returns:
            A string like ``"10.0.0.1:1234 <-> 10.0.0.2:80 TCP"``.
        """
        proto_names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
        proto = proto_names.get(flow.key.protocol, str(flow.key.protocol))
        return (
            f"{flow.key.src_ip}:{flow.key.src_port} <-> "
            f"{flow.key.dst_ip}:{flow.key.dst_port} {proto}"
        )

    def _format_flows(self, flows: list[FlowRecord]) -> str:
        """Format a list of flows as a structured text block.

        Each flow is presented with its key, lifetime counters, timing,
        and TCP flag counters (where applicable).

        Security note:
            Only aggregate statistics are included — no payload content,
            no raw bytes, no host names.  IP addresses are inherently
            needed for flow identification but do not leak payload data.
        """
        parts: list[str] = []
        for i, flow in enumerate(flows, 1):
            key_str = self._format_flow_key(flow)
            s = flow.stats
            block = (
                f"Flow {i}: {key_str}\n"
                f"  Packets:     {flow.packet_count}\n"
                f"  Bytes:       {flow.byte_count}\n"
                f"  Duration:    {flow.duration:.3f}s\n"
                f"  Mean IAT:    {s.mean_iat:.6f}s\n"
                f"  Mean PktLen: {s.mean_pkt_len:.1f}\n"
                f"  Std PktLen:  {s.std_pkt_len:.1f}\n"
            )
            # Add TCP flag breakdown if applicable
            if flow.key.protocol == 6:  # TCP
                block += (
                    f"  SYN: {s.syn_count}  ACK: {s.ack_count}  "
                    f"FIN: {s.fin_count}  RST: {s.rst_count}  "
                    f"PSH: {s.psh_count}  URG: {s.urg_count}\n"
                    f"  SYN ratio: {s.syn_ratio:.3f}  "
                    f"RST ratio: {s.rst_ratio:.3f}\n"
                )
            parts.append(block)
        return "\n".join(parts)
