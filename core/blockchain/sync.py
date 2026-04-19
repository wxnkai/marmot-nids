"""
core.blockchain.sync
=====================
Background alert synchronisation task.

Reads unsynced alerts from the local SQLite store and submits them to the
active ``BlockchainProvider``.  Provider-agnostic: works identically with
``EthereumProvider`` or ``NullProvider``.

Security relevance:
    The sync task is the only component that writes to the blockchain.
    It uses monotonically increasing SQLite IDs for cursor tracking.
    Restarts after partial sync may produce duplicate on-chain entries
    (acceptable for an audit log — duplicates are visible and do not
    corrupt the record).

    See ADR-001 §Replay Attack Surface for the full analysis.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from core.blockchain.provider import AlertRecord, BlockchainProvider, TxReceipt

logger = logging.getLogger(__name__)


class AlertSyncTask:
    """Background task that syncs local alerts to the blockchain provider.

    Args:
        provider: The active ``BlockchainProvider`` instance.
        fetch_unsynced: Callable that returns the next batch of unsynced
            ``AlertRecord`` objects from SQLite.
        mark_synced: Callable that marks a given ``alert_id`` as synced
            in SQLite after successful blockchain submission.
        interval: Seconds between sync cycles.
            Corresponds to ``BLOCKCHAIN_SYNC_INTERVAL``.
        batch_size: Maximum alerts per sync cycle.
            Corresponds to ``BLOCKCHAIN_SYNC_BATCH_SIZE``.

    Security note:
        The sync task does not access private keys directly — all
        signing happens inside the provider.  The task's only
        responsibility is orchestrating the fetch-submit-mark cycle.
    """

    def __init__(
        self,
        provider: BlockchainProvider,
        fetch_unsynced: Callable[[int], list[AlertRecord]],
        mark_synced: Callable[[int, str], None],
        interval: float = 10.0,
        batch_size: int = 50,
    ) -> None:
        self._provider = provider
        self._fetch_unsynced = fetch_unsynced
        self._mark_synced = mark_synced
        self._interval = interval
        self._batch_size = batch_size
        self._task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._total_synced: int = 0
        self._total_failed: int = 0

    async def start(self) -> None:
        """Start the background sync loop.

        The first sync cycle runs immediately.  Subsequent cycles wait
        ``interval`` seconds.
        """
        self._running = True
        self._task = asyncio.create_task(
            self._sync_loop(), name="blockchain-sync"
        )
        logger.info(
            "Blockchain sync started: interval=%.1fs, batch_size=%d",
            self._interval,
            self._batch_size,
        )

    async def stop(self) -> None:
        """Signal the sync loop to stop and wait for cleanup."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "Blockchain sync stopped: synced=%d, failed=%d",
            self._total_synced,
            self._total_failed,
        )

    @property
    def is_running(self) -> bool:
        """Whether the sync loop is active."""
        return self._running

    @property
    def total_synced(self) -> int:
        """Total alerts successfully submitted to the blockchain."""
        return self._total_synced

    @property
    def total_failed(self) -> int:
        """Total alerts that failed to submit."""
        return self._total_failed

    async def _sync_loop(self) -> None:
        """Main sync loop — fetches unsynced alerts and submits them."""
        while self._running:
            try:
                await self._sync_batch()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Sync cycle error: %s", exc)

            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                raise

    async def _sync_batch(self) -> None:
        """Fetch and submit one batch of unsynced alerts."""
        try:
            unsynced = self._fetch_unsynced(self._batch_size)
        except Exception as exc:
            logger.warning("Failed to fetch unsynced alerts: %s", exc)
            return

        if not unsynced:
            return

        for alert in unsynced:
            try:
                receipt = await self._provider.log_alert(alert)
                if receipt is not None:
                    self._mark_synced(alert.alert_id, receipt.tx_hash)
                    self._total_synced += 1
                    logger.debug(
                        "Synced alert %d: tx=%s",
                        alert.alert_id,
                        receipt.tx_hash[:16] + "...",
                    )
                else:
                    self._total_failed += 1
                    logger.debug(
                        "Alert %d sync failed (provider returned None)",
                        alert.alert_id,
                    )
            except Exception as exc:
                self._total_failed += 1
                logger.warning(
                    "Alert %d sync error: %s", alert.alert_id, exc
                )
