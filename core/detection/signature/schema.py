"""
core.detection.signature.schema
================================
Pydantic v2 models for the ``signatures.json`` file format.

Security relevance:
    Schema validation is the first line of defence against malformed or
    tampered signature files.  Every field in every signature is validated
    before any rule is compiled into the engine.  A single invalid signature
    causes the entire load to fail rather than silently loading a partial set,
    which would create undetected coverage gaps.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: IANA protocol numbers the engine currently supports.
_KNOWN_PROTOCOLS: frozenset[int] = frozenset({
    1,   # ICMP
    6,   # TCP
    17,  # UDP
    58,  # ICMPv6
})

#: Field names that may appear in a ``SignatureCondition``.
#: Must stay in sync with ``engine._extract_namespace``.
VALID_FIELDS: frozenset[str] = frozenset({
    # FlowRecord direct fields
    "packet_count",
    "byte_count",
    "duration",
    # FlowStats lifetime counters
    "total_packets",
    "total_bytes",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    # FlowStats statistical properties
    "syn_ratio",
    "rst_ratio",
    "mean_pkt_len",
    "std_pkt_len",
    "mean_iat",
    # FlowKey fields
    "dst_port",
    "src_port",
    "protocol",
    # Derived convenience fields
    "min_port",   # min(src_port, dst_port) — protocol-agnostic service detection
    "max_port",   # max(src_port, dst_port)
})


# ---------------------------------------------------------------------------
# Condition model
# ---------------------------------------------------------------------------


class SignatureCondition(BaseModel):
    """A single boolean condition evaluated against a flow's numeric namespace.

    All conditions in a signature are combined with AND semantics: every
    condition must evaluate to ``True`` for the signature to fire.

    Attributes:
        field: Name of the flow attribute to test.  Must be a member of
            ``VALID_FIELDS``.
        op: Comparison operator.  One of ``>=``, ``<=``, ``>``, ``<``,
            ``==``, ``!=``.
        value: Numeric value to compare against.  Integer inputs are
            automatically coerced to float for uniform arithmetic.

    Security note:
        Restricting ``field`` to a known enumeration prevents signatures from
        referencing internal attributes not intended for external evaluation,
        and catches typos in hand-authored signature files before they cause
        silent false negatives.
    """

    field: str
    op: Literal[">=", "<=", ">", "<", "==", "!="]
    value: float

    @field_validator("field")
    @classmethod
    def field_must_be_known(cls, v: str) -> str:
        if v not in VALID_FIELDS:
            raise ValueError(
                f"Unknown condition field '{v}'. "
                f"Valid fields: {sorted(VALID_FIELDS)}"
            )
        return v


# ---------------------------------------------------------------------------
# Signature model
# ---------------------------------------------------------------------------


class Signature(BaseModel):
    """A single threat signature rule.

    Attributes:
        id: Unique identifier in the format ``sig_NNN_slug`` (e.g.
            ``"sig_001_syn_flood"``).  The ``NNN`` portion is a zero-padded
            three-digit sequence number.
        name: Short human-readable label (3–80 characters).
        description: Detailed description of the threat (≥ 10 characters).
        severity: Severity level.
        mitre_technique: MITRE ATT&CK technique identifier, or ``None``.
        protocols: Non-empty list of IANA protocol numbers.  Only flows whose
            protocol matches one of these values will be evaluated against
            this signature.
        confidence: Base confidence score emitted in the ``Alert`` when this
            signature matches.  Must be in [0.0, 1.0].
        conditions: Non-empty list of conditions; all must be satisfied for
            the signature to fire (AND semantics).

    Security note:
        The ``protocols`` list is used for pre-filtering in the engine.  A
        signature with an incorrect protocol (e.g. TCP signature on protocol 1)
        would silently never fire.  Validation at load time prevents this class
        of authoring error.
    """

    id: str = Field(pattern=r"^sig_\d{3}_[a-z][a-z0-9_]*$")
    name: str = Field(min_length=3, max_length=80)
    description: str = Field(min_length=10)
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique: str | None = None
    protocols: list[int] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    conditions: list[SignatureCondition] = Field(min_length=1)

    @field_validator("protocols")
    @classmethod
    def protocols_must_be_known(cls, v: list[int]) -> list[int]:
        for p in v:
            if p not in _KNOWN_PROTOCOLS:
                raise ValueError(
                    f"Unsupported protocol number {p}. "
                    f"Known: {sorted(_KNOWN_PROTOCOLS)}"
                )
        return v


# ---------------------------------------------------------------------------
# Root envelope
# ---------------------------------------------------------------------------


class SignatureSet(BaseModel):
    """Root envelope model for the ``signatures.json`` file.

    Attributes:
        version: Schema version string (e.g. ``"1.0"``).
        description: Brief description of this signature collection.
        signatures: List of ``Signature`` objects.  May be empty (interpreted
            as "no rules loaded"; the engine will log a warning).

    Security note:
        An empty signature list is not a validation error because it allows
        a "monitor only" deployment mode where the engine is running but no
        alerting rules are active.  The application must log a conspicuous
        warning if it starts with zero signatures.
    """

    version: str
    description: str
    signatures: list[Signature]
