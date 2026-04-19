"""
core.blockchain.provider
=========================
Abstract ``BlockchainProvider`` interface and supporting types.

Security relevance:
    This is the typing boundary that decouples the detection pipeline from
    any specific blockchain implementation.  Application code only imports
    ``BlockchainProvider``, ``AlertRecord``, ``TxReceipt``, and
    ``ProviderStatus`` — never a concrete chain client.

    See ADR-001 (docs/adr/001-pluggable-blockchain.md) for the full design
    rationale, including private-key isolation and owner-only contract writes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


class ProviderStatus(Enum):
    """Health status returned by ``BlockchainProvider.health_check()``.

    Attributes:
        CONNECTED: The provider has a working connection to the chain.
        DISCONNECTED: The provider was configured but cannot reach the node.
        DISABLED: The provider is intentionally disabled (``NullProvider``).
    """

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    DISABLED = "disabled"


@dataclass(frozen=True)
class AlertRecord:
    """Immutable record of a detection alert destined for blockchain logging.

    Attributes:
        alert_id: Unique internal identifier (monotonic, from SQLite).
        signature_id: Signature or LLM rule ID that generated the alert.
        threat_type: Threat category slug (e.g. ``"syn_flood"``).
        severity: Severity level (``"low"``/``"medium"``/``"high"``/
            ``"critical"``).
        confidence: Detection confidence in [0.0, 1.0].
        src_ip: Source IP of the flow that triggered the alert.
        dst_ip: Destination IP of the flow.
        protocol: IANA protocol number.
        timestamp: Unix epoch time of alert creation.
        description: Human-readable explanation.

    Security note:
        ``AlertRecord`` is frozen to prevent mutation between creation and
        blockchain submission.  The blockchain logger receives the same
        object that was created by the detection engine.
    """

    alert_id: int
    signature_id: str
    threat_type: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: str
    protocol: int
    timestamp: float
    description: str


@dataclass(frozen=True)
class TxReceipt:
    """Lightweight receipt for a blockchain transaction.

    Attributes:
        tx_hash: Transaction hash as a hex string.
        block_number: Block number in which the transaction was included.
        gas_used: Gas consumed by the transaction.
        status: Transaction status (1 = success, 0 = reverted).
        provider_name: Name of the provider that submitted the transaction
            (for audit trail logging).
    """

    tx_hash: str
    block_number: int
    gas_used: int
    status: int
    provider_name: str = ""


# ---------------------------------------------------------------------------
# Abstract provider interface
# ---------------------------------------------------------------------------


class BlockchainProvider(ABC):
    """Abstract interface for blockchain audit logging.

    All concrete providers must implement these four methods.  Application
    code depends only on this interface — never on a specific chain client.

    Security note:
        ``log_alert()`` is the only write method.  It expects an
        ``AlertRecord`` whose fields have already been validated by the
        detection pipeline.  The provider must not modify the record.
    """

    @abstractmethod
    async def log_alert(self, alert: AlertRecord) -> TxReceipt | None:
        """Submit an alert to the blockchain audit log.

        Args:
            alert: The immutable alert record to log.

        Returns:
            A ``TxReceipt`` on success, or ``None`` if logging failed
            (e.g. node unreachable, transaction reverted).

        Security note:
            Implementations must not raise on transient failures — return
            ``None`` instead.  The background sync task will retry on the
            next cycle.
        """
        ...

    @abstractmethod
    async def get_alert(self, index: int) -> AlertRecord | None:
        """Retrieve an alert from the on-chain registry by index.

        Args:
            index: Zero-based index into the contract's alert array.

        Returns:
            The ``AlertRecord``, or ``None`` if the index is out of range
            or the provider is unavailable.
        """
        ...

    @abstractmethod
    async def get_alert_count(self) -> int:
        """Return the number of alerts currently stored on-chain.

        Returns:
            The count of alerts in the contract, or 0 if unavailable.
        """
        ...

    @abstractmethod
    async def health_check(self) -> ProviderStatus:
        """Check the provider's connection status.

        Returns:
            A ``ProviderStatus`` indicating the current state.
        """
        ...
