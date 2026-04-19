"""
core.detection.signature.engine
================================
Protocol-indexed signature evaluation engine.

Security relevance:
    Two correctness properties are critical:

    1. **Protocol pre-filtering** — signatures are indexed by protocol number
       at construction time.  ``analyse`` only evaluates signatures whose
       protocol matches the flow.  This prevents TCP-specific rules (e.g.
       SYN flood) from firing on UDP or ICMP flows, and vice versa.

    2. **AND-semantics for conditions** — every condition in a signature must
       evaluate to ``True`` for the signature to fire.  Single-condition
       signatures are intentionally broad; multi-condition signatures are
       precise.  Operators should prefer more conditions over higher thresholds
       to reduce false-positive rates.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from core.capture.flow_assembler import FlowRecord
from core.detection.base import Alert, DetectionEngine
from core.detection.signature.schema import Signature, SignatureCondition

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Operator dispatch table
# ---------------------------------------------------------------------------

_OPS: dict[str, Callable[[float, float], bool]] = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    "<":  lambda a, b: a < b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SignatureEngine(DetectionEngine):
    """Evaluates ``FlowRecord`` objects against a set of pre-compiled signatures.

    Signatures are indexed by their ``protocols`` list at construction time.
    ``analyse`` performs an O(1) protocol lookup followed by O(k) condition
    evaluation, where k is the number of signatures for that protocol — not
    the total rule count.

    Args:
        signatures: A list of validated ``Signature`` objects, typically
            produced by ``SignatureManager.load()``.

    Security note:
        Signatures are compiled into a read-only index at construction time.
        If the signature set changes (e.g. hot-reload after an update), create
        a new ``SignatureEngine`` instance.  Never mutate ``self._index`` after
        construction — the engine is designed to be immutable once built so
        that multiple workers can share the same instance safely.
    """

    def __init__(self, signatures: list[Signature]) -> None:
        # Build protocol → [Signature] index
        self._index: dict[int, list[Signature]] = {}
        for sig in signatures:
            for proto in sig.protocols:
                self._index.setdefault(proto, []).append(sig)

        logger.info(
            "SignatureEngine ready: %d rule(s) across protocols %s",
            self.signature_count,
            sorted(self._index.keys()),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, flow: FlowRecord) -> list[Alert]:
        """Evaluate all protocol-matching signatures against a flow.

        Args:
            flow: A completed ``FlowRecord``.  Should have
                ``is_expired=True``; the engine does not enforce this so
                that streaming evaluation remains possible.

        Returns:
            A (possibly empty) list of ``Alert`` objects for every signature
            that matched.

        Security note:
            All matching signatures fire independently.  A single flow can
            produce multiple alerts if it matches several signatures (e.g. a
            scan that also triggers a brute-force rule).
        """
        sigs = self._index.get(flow.key.protocol, [])
        if not sigs:
            return []

        ns = _extract_namespace(flow)
        alerts: list[Alert] = []

        for sig in sigs:
            if _evaluate_conditions(sig.conditions, ns):
                alert = Alert(
                    flow_key=flow.key,
                    signature_id=sig.id,
                    signature_name=sig.name,
                    threat_type=_threat_type_from_id(sig.id),
                    severity=sig.severity,
                    confidence=sig.confidence,
                    description=sig.description,
                    mitre_technique=sig.mitre_technique,
                    timestamp=time.time(),
                )
                alerts.append(alert)
                logger.warning(
                    "Alert [%s] %s on %s (confidence=%.2f)",
                    sig.severity.upper(),
                    sig.name,
                    flow.key,
                    sig.confidence,
                )

        return alerts

    @property
    def signature_count(self) -> int:
        """Total number of (protocol, signature) index entries."""
        return sum(len(v) for v in self._index.values())

    @property
    def protocol_index(self) -> dict[int, int]:
        """Mapping of ``{protocol_number: signature_count}``."""
        return {proto: len(sigs) for proto, sigs in self._index.items()}


# ---------------------------------------------------------------------------
# Namespace extraction
# ---------------------------------------------------------------------------


def _extract_namespace(flow: FlowRecord) -> dict[str, float]:
    """Build a flat numeric namespace from a ``FlowRecord``.

    Every key is a member of ``schema.VALID_FIELDS``.  All values are
    coerced to ``float`` so the condition evaluator uses uniform arithmetic.

    Security note:
        ``min_port`` / ``max_port`` are derived convenience fields.  They
        allow signatures to reference the smaller (service) port regardless
        of which direction the flow was normalised, avoiding coverage gaps
        that arise when the canonical ``src_port``/``dst_port`` ordering
        swaps depending on IP address values.
    """
    src_port = float(flow.key.src_port)
    dst_port = float(flow.key.dst_port)
    return {
        # FlowRecord direct
        "packet_count":  float(flow.packet_count),
        "byte_count":    float(flow.byte_count),
        "duration":      flow.duration,
        # FlowStats lifetime counters
        "total_packets": float(flow.stats.total_packets),
        "total_bytes":   float(flow.stats.total_bytes),
        "syn_count":     float(flow.stats.syn_count),
        "ack_count":     float(flow.stats.ack_count),
        "fin_count":     float(flow.stats.fin_count),
        "rst_count":     float(flow.stats.rst_count),
        "psh_count":     float(flow.stats.psh_count),
        "urg_count":     float(flow.stats.urg_count),
        # FlowStats statistical properties
        "syn_ratio":     flow.stats.syn_ratio,
        "rst_ratio":     flow.stats.rst_ratio,
        "mean_pkt_len":  flow.stats.mean_pkt_len,
        "std_pkt_len":   flow.stats.std_pkt_len,
        "mean_iat":      flow.stats.mean_iat,
        # FlowKey
        "src_port":      src_port,
        "dst_port":      dst_port,
        "protocol":      float(flow.key.protocol),
        # Derived convenience
        "min_port":      min(src_port, dst_port),
        "max_port":      max(src_port, dst_port),
    }


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------


def _evaluate_conditions(
    conditions: list[SignatureCondition],
    ns: dict[str, float],
) -> bool:
    """Return ``True`` only if every condition in ``conditions`` is satisfied.

    Args:
        conditions: Condition list to evaluate (AND semantics).
        ns: Flat namespace dict produced by ``_extract_namespace``.

    Returns:
        ``True`` if all conditions pass.  ``False`` if any condition fails
        or references an unknown field (logged as a warning).
    """
    for cond in conditions:
        actual = ns.get(cond.field)
        if actual is None:
            logger.warning(
                "Condition references unknown field '%s'; signature skipped",
                cond.field,
            )
            return False
        op_fn = _OPS.get(cond.op)
        if op_fn is None:
            logger.warning("Unknown operator '%s'; signature skipped", cond.op)
            return False
        if not op_fn(actual, cond.value):
            return False
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _threat_type_from_id(sig_id: str) -> str:
    """Extract the threat-type slug from a signature ID.

    For ``"sig_001_syn_flood"`` returns ``"syn_flood"``.
    Falls back to the full ID if the format is unexpected.
    """
    parts = sig_id.split("_", 2)
    return parts[2] if len(parts) == 3 else sig_id
