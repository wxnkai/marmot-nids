"""
core.blockchain.null_provider
==============================
No-op ``BlockchainProvider`` implementation.

Selected when ``BLOCKCHAIN_PROVIDER=none`` (the default).  All methods
succeed silently.  Alerts are still stored in SQLite — the only difference
is that no on-chain record is created.

Security note:
    Using ``NullProvider`` forfeits on-chain non-repudiation.  This is a
    deliberate deployment choice made explicit via environment configuration.
    The operator is informed of the active provider at startup via an
    INFO-level log message.

    See ADR-001 §Security Implications for the full analysis.
"""

from __future__ import annotations

import logging

from core.blockchain.provider import (
    AlertRecord,
    BlockchainProvider,
    ProviderStatus,
    TxReceipt,
)

logger = logging.getLogger(__name__)


class NullProvider(BlockchainProvider):
    """No-op blockchain provider — all operations are silent pass-throughs.

    This is the default provider for development, testing, and deployments
    that do not require blockchain audit logging.

    ``health_check()`` always returns ``ProviderStatus.DISABLED`` so the
    dashboard and status API can distinguish between "blockchain not
    configured" and "blockchain configured but unreachable".
    """

    def __init__(self) -> None:
        logger.info(
            "BlockchainProvider: NullProvider active — "
            "alerts will NOT be logged on-chain. "
            "Set BLOCKCHAIN_PROVIDER=ethereum to enable."
        )

    async def log_alert(self, alert: AlertRecord) -> TxReceipt | None:
        """No-op: returns ``None`` without submitting anything.

        Args:
            alert: The alert record (unused).

        Returns:
            ``None`` — no transaction was created.
        """
        logger.debug(
            "NullProvider: alert %s skipped (blockchain disabled)",
            alert.signature_id,
        )
        return None

    async def get_alert(self, index: int) -> AlertRecord | None:
        """No-op: always returns ``None``.

        Args:
            index: Alert index (unused).

        Returns:
            ``None`` — no on-chain storage to query.
        """
        return None

    async def get_alert_count(self) -> int:
        """No-op: returns 0.

        Returns:
            ``0`` — no alerts are stored on-chain when using NullProvider.
        """
        return 0

    async def health_check(self) -> ProviderStatus:
        """Returns ``ProviderStatus.DISABLED``.

        Returns:
            ``ProviderStatus.DISABLED`` — indicates the provider is
            intentionally inactive, not failed.
        """
        return ProviderStatus.DISABLED
