"""
tests.unit.test_blockchain
============================
Unit tests for Phase 5 — Blockchain Provider.

Coverage:
    * AlertRecord / TxReceipt / ProviderStatus types
    * NullProvider — all methods succeed silently
    * Provider factory — env-based selection and fallback
    * AlertSyncTask — batch processing, error handling
    * BlockchainProvider ABC — interface contract

All tests are offline — no Ethereum node, no web3, no Hardhat required.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.blockchain.null_provider import NullProvider
from core.blockchain.provider import (
    AlertRecord,
    BlockchainProvider,
    ProviderStatus,
    TxReceipt,
)
from core.blockchain.sync import AlertSyncTask

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    alert_id: int = 1,
    signature_id: str = "sig_001_syn_flood",
    threat_type: str = "syn_flood",
    severity: str = "critical",
    confidence: float = 0.95,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    protocol: int = 6,
    timestamp: float = 1700000000.0,
    description: str = "SYN flood detected.",
) -> AlertRecord:
    return AlertRecord(
        alert_id=alert_id,
        signature_id=signature_id,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        timestamp=timestamp,
        description=description,
    )


def _make_receipt(
    tx_hash: str = "0xabc123",
    block_number: int = 42,
    gas_used: int = 100000,
    status: int = 1,
) -> TxReceipt:
    return TxReceipt(
        tx_hash=tx_hash,
        block_number=block_number,
        gas_used=gas_used,
        status=status,
        provider_name="test",
    )


# ---------------------------------------------------------------------------
# TestAlertRecord (4 tests)
# ---------------------------------------------------------------------------


class TestAlertRecord:
    def test_creation_with_all_fields(self):
        alert = _make_alert()
        assert alert.signature_id == "sig_001_syn_flood"
        assert alert.severity == "critical"
        assert alert.confidence == 0.95

    def test_alert_record_is_frozen(self):
        alert = _make_alert()
        with pytest.raises(AttributeError):
            alert.severity = "low"  # type: ignore[misc]

    def test_different_alert_ids_are_not_equal(self):
        a1 = _make_alert(alert_id=1)
        a2 = _make_alert(alert_id=2)
        assert a1 != a2

    def test_same_fields_are_equal(self):
        a1 = _make_alert(alert_id=1)
        a2 = _make_alert(alert_id=1)
        assert a1 == a2


# ---------------------------------------------------------------------------
# TestTxReceipt (3 tests)
# ---------------------------------------------------------------------------


class TestTxReceipt:
    def test_receipt_creation(self):
        r = _make_receipt()
        assert r.tx_hash == "0xabc123"
        assert r.block_number == 42
        assert r.status == 1

    def test_receipt_is_frozen(self):
        r = _make_receipt()
        with pytest.raises(AttributeError):
            r.tx_hash = "0x000"  # type: ignore[misc]

    def test_receipt_provider_name(self):
        r = _make_receipt()
        assert r.provider_name == "test"


# ---------------------------------------------------------------------------
# TestProviderStatus (3 tests)
# ---------------------------------------------------------------------------


class TestProviderStatus:
    def test_connected_value(self):
        assert ProviderStatus.CONNECTED.value == "connected"

    def test_disconnected_value(self):
        assert ProviderStatus.DISCONNECTED.value == "disconnected"

    def test_disabled_value(self):
        assert ProviderStatus.DISABLED.value == "disabled"


# ---------------------------------------------------------------------------
# TestNullProvider (5 tests)
# ---------------------------------------------------------------------------


class TestNullProvider:
    @pytest.fixture
    def provider(self):
        return NullProvider()

    @pytest.mark.asyncio
    async def test_log_alert_returns_none(self, provider):
        result = await provider.log_alert(_make_alert())
        assert result is None

    @pytest.mark.asyncio
    async def test_get_alert_returns_none(self, provider):
        result = await provider.get_alert(0)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_alert_count_returns_zero(self, provider):
        count = await provider.get_alert_count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_health_check_returns_disabled(self, provider):
        status = await provider.health_check()
        assert status == ProviderStatus.DISABLED

    def test_null_provider_is_blockchain_provider(self, provider):
        assert isinstance(provider, BlockchainProvider)


# ---------------------------------------------------------------------------
# TestProviderFactory (4 tests)
# ---------------------------------------------------------------------------


class TestProviderFactory:
    @patch.dict("os.environ", {"BLOCKCHAIN_PROVIDER": "none"}, clear=False)
    def test_none_creates_null_provider(self):
        from core.blockchain.factory import create_provider
        provider = create_provider()
        assert isinstance(provider, NullProvider)

    @patch.dict("os.environ", {"BLOCKCHAIN_PROVIDER": ""}, clear=False)
    def test_empty_creates_null_provider(self):
        from core.blockchain.factory import create_provider
        # Empty string should also result in NullProvider (fallback)
        provider = create_provider()
        assert isinstance(provider, (NullProvider,))

    @patch.dict("os.environ", {"BLOCKCHAIN_PROVIDER": "invalid_chain"}, clear=False)
    def test_unknown_provider_falls_back_to_null(self):
        from core.blockchain.factory import create_provider
        provider = create_provider()
        assert isinstance(provider, NullProvider)

    @patch.dict("os.environ", {
        "BLOCKCHAIN_PROVIDER": "ethereum",
        "ETHEREUM_RPC_URL": "http://localhost:8545",
    }, clear=False)
    def test_ethereum_without_key_falls_back_to_null(self):
        """Missing ETHEREUM_PRIVATE_KEY → fallback to NullProvider."""
        # Remove the key if it exists
        import os
        os.environ.pop("ETHEREUM_PRIVATE_KEY", None)
        os.environ.pop("CONTRACT_ADDRESS", None)
        from core.blockchain.factory import create_provider
        provider = create_provider()
        assert isinstance(provider, NullProvider)


# ---------------------------------------------------------------------------
# TestAlertSyncTask (6 tests)
# ---------------------------------------------------------------------------


class TestAlertSyncTask:
    def _mock_provider(self, receipt: TxReceipt | None = None):
        """Create a mock BlockchainProvider."""
        provider = AsyncMock(spec=BlockchainProvider)
        provider.log_alert.return_value = receipt
        return provider

    @pytest.mark.asyncio
    async def test_sync_calls_provider_with_alerts(self):
        alert = _make_alert()
        receipt = _make_receipt()
        provider = self._mock_provider(receipt)
        synced_ids: list[int] = []

        def mark_synced(alert_id: int, tx_hash: str) -> None:
            synced_ids.append(alert_id)

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=lambda n: [alert],
            mark_synced=mark_synced,
            interval=0.1,
        )

        # Run one sync cycle manually
        await task._sync_batch()

        provider.log_alert.assert_called_once_with(alert)
        assert synced_ids == [1]
        assert task.total_synced == 1

    @pytest.mark.asyncio
    async def test_sync_handles_provider_failure(self):
        alert = _make_alert()
        provider = self._mock_provider(None)  # log_alert returns None
        synced_ids: list[int] = []

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=lambda n: [alert],
            mark_synced=lambda a, t: synced_ids.append(a),
            interval=0.1,
        )

        await task._sync_batch()

        assert synced_ids == []
        assert task.total_failed == 1

    @pytest.mark.asyncio
    async def test_sync_handles_empty_batch(self):
        provider = self._mock_provider()

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=lambda n: [],
            mark_synced=lambda a, t: None,
            interval=0.1,
        )

        await task._sync_batch()

        provider.log_alert.assert_not_called()
        assert task.total_synced == 0

    @pytest.mark.asyncio
    async def test_sync_processes_multiple_alerts(self):
        alerts = [_make_alert(alert_id=i) for i in range(3)]
        receipt = _make_receipt()
        provider = self._mock_provider(receipt)
        synced_ids: list[int] = []

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=lambda n: alerts,
            mark_synced=lambda a, t: synced_ids.append(a),
            interval=0.1,
        )

        await task._sync_batch()

        assert len(synced_ids) == 3
        assert task.total_synced == 3

    @pytest.mark.asyncio
    async def test_start_and_stop_lifecycle(self):
        provider = self._mock_provider()

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=lambda n: [],
            mark_synced=lambda a, t: None,
            interval=0.05,
        )

        await task.start()
        assert task.is_running
        await asyncio.sleep(0.1)
        await task.stop()
        assert not task.is_running

    @pytest.mark.asyncio
    async def test_sync_handles_fetch_exception(self):
        provider = self._mock_provider()

        def bad_fetch(n: int) -> list[AlertRecord]:
            raise RuntimeError("DB connection lost")

        task = AlertSyncTask(
            provider=provider,
            fetch_unsynced=bad_fetch,
            mark_synced=lambda a, t: None,
            interval=0.1,
        )

        # Should not raise
        await task._sync_batch()
        assert task.total_synced == 0


# ---------------------------------------------------------------------------
# TestBlockchainProviderABC (2 tests)
# ---------------------------------------------------------------------------


class TestBlockchainProviderABC:
    def test_cannot_instantiate_abstract_provider(self):
        with pytest.raises(TypeError):
            BlockchainProvider()  # type: ignore[abstract]

    def test_null_provider_satisfies_interface(self):
        provider = NullProvider()
        assert hasattr(provider, "log_alert")
        assert hasattr(provider, "get_alert")
        assert hasattr(provider, "get_alert_count")
        assert hasattr(provider, "health_check")
