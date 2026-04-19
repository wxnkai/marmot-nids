"""
core.blockchain.ethereum
=========================
Ethereum-compatible ``BlockchainProvider`` using web3.py.

Security relevance:
    This module is the **only** place in the codebase that touches private
    keys or signs transactions.  Design invariants:

    1. **Key isolation** — ``ETHEREUM_PRIVATE_KEY`` is read once at
       construction time and stored in a private attribute.  It is never
       logged, serialised, or passed to any other component.

    2. **Owner-only writes** — The ``AlertRegistry`` contract uses
       OpenZeppelin ``Ownable``.  Only the deployer account (whose private
       key matches ``ETHEREUM_PRIVATE_KEY``) can call ``logAlert()``.

    3. **Non-blocking** — All web3 calls are delegated to a thread-pool
       executor via ``asyncio.to_thread`` so the asyncio event loop is
       never blocked by synchronous RPC calls.

    4. **Graceful degradation** — If the RPC node is unreachable, methods
       return ``None`` / ``0`` / ``ProviderStatus.DISCONNECTED`` rather
       than raising.  The detection pipeline continues unaffected.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from core.blockchain.provider import (
    AlertRecord,
    BlockchainProvider,
    ProviderStatus,
    TxReceipt,
)

logger = logging.getLogger(__name__)

#: Path to the compiled contract ABI, produced by Hardhat.
_DEFAULT_ABI_PATH = (
    Path(__file__).parent.parent.parent
    / "contracts"
    / "artifacts"
    / "AlertRegistry.json"
)


class EthereumProvider(BlockchainProvider):
    """Ethereum-compatible blockchain provider using web3.py.

    Args:
        rpc_url: Ethereum JSON-RPC endpoint URL.
            Corresponds to ``ETHEREUM_RPC_URL``.
        private_key: Hex-encoded private key for transaction signing.
            Corresponds to ``ETHEREUM_PRIVATE_KEY``.
        contract_address: Deployed ``AlertRegistry`` contract address.
            Corresponds to ``CONTRACT_ADDRESS``.
        abi_path: Path to the compiled contract ABI JSON file.
        chain_id: EIP-155 chain ID for replay protection.
            Corresponds to ``ETHEREUM_CHAIN_ID``.

    Raises:
        ImportError: If ``web3`` is not installed.
        ValueError: If ``private_key`` or ``contract_address`` are empty.

    Security note:
        The private key is **never** logged.  Even at DEBUG level, only
        the derived account address is logged (for operational verification
        that the correct key is loaded).
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        contract_address: str,
        abi_path: Path | None = None,
        chain_id: int = 31337,  # Hardhat default
    ) -> None:
        from web3 import Web3  # noqa: PLC0415

        if not private_key:
            raise ValueError("ETHEREUM_PRIVATE_KEY must not be empty")
        if not contract_address:
            raise ValueError("CONTRACT_ADDRESS must not be empty")

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._private_key = private_key
        self._chain_id = chain_id
        self._account = self._w3.eth.account.from_key(private_key)

        # Load contract ABI
        abi_file = abi_path or _DEFAULT_ABI_PATH
        if abi_file.exists():
            abi_data = json.loads(abi_file.read_text())
            # Handle both raw ABI arrays and Hardhat artifact format
            abi = abi_data if isinstance(abi_data, list) else abi_data.get("abi", [])
        else:
            logger.warning("Contract ABI not found at %s — using minimal ABI", abi_file)
            abi = self._minimal_abi()

        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi,
        )

        logger.info(
            "EthereumProvider ready: rpc=%s, account=%s, contract=%s",
            rpc_url,
            self._account.address,
            contract_address,
        )

    # ------------------------------------------------------------------
    # BlockchainProvider interface
    # ------------------------------------------------------------------

    async def log_alert(self, alert: AlertRecord) -> TxReceipt | None:
        """Submit an alert to the AlertRegistry contract.

        Builds and signs a ``logAlert()`` transaction, submits it to the
        chain, and waits for the receipt.

        Args:
            alert: The validated alert record.

        Returns:
            A ``TxReceipt`` on success, or ``None`` on failure.

        Security note:
            The transaction is signed locally with ``_private_key``.
            The private key never leaves this process — only the signed
            transaction bytes are sent to the RPC node.
        """
        try:
            receipt = await asyncio.to_thread(self._submit_alert, alert)
            if receipt is None:
                return None

            tx_receipt = TxReceipt(
                tx_hash=receipt["transactionHash"].hex(),
                block_number=receipt["blockNumber"],
                gas_used=receipt["gasUsed"],
                status=receipt["status"],
                provider_name="ethereum",
            )
            logger.info(
                "Alert logged on-chain: tx=%s block=%d gas=%d",
                tx_receipt.tx_hash[:16] + "...",
                tx_receipt.block_number,
                tx_receipt.gas_used,
            )
            return tx_receipt

        except Exception as exc:
            logger.warning("Failed to log alert on-chain: %s", exc)
            return None

    async def get_alert(self, index: int) -> AlertRecord | None:
        """Read an alert from the contract by index.

        Args:
            index: Zero-based index into the on-chain alert array.

        Returns:
            An ``AlertRecord``, or ``None`` if the index is out of range
            or the call fails.
        """
        try:
            result = await asyncio.to_thread(
                self._contract.functions.getAlert(index).call
            )
            return AlertRecord(
                alert_id=index,
                signature_id=result[0],
                threat_type=result[1],
                severity=result[2],
                confidence=result[3] / 100.0,  # Contract stores as uint (0-100)
                src_ip=result[4],
                dst_ip=result[5],
                protocol=result[6],
                timestamp=float(result[7]),
                description=result[8],
            )
        except Exception as exc:
            logger.debug("Failed to read alert at index %d: %s", index, exc)
            return None

    async def get_alert_count(self) -> int:
        """Return the number of alerts stored on-chain.

        Returns:
            The alert count, or ``0`` if the call fails.
        """
        try:
            count = await asyncio.to_thread(
                self._contract.functions.getAlertCount().call
            )
            return int(count)
        except Exception as exc:
            logger.debug("Failed to get alert count: %s", exc)
            return 0

    async def health_check(self) -> ProviderStatus:
        """Check connectivity to the Ethereum node.

        Returns:
            ``CONNECTED`` if the node responds to ``eth_blockNumber``,
            ``DISCONNECTED`` otherwise.
        """
        try:
            connected = await asyncio.to_thread(self._w3.is_connected)
            return ProviderStatus.CONNECTED if connected else ProviderStatus.DISCONNECTED
        except Exception:
            return ProviderStatus.DISCONNECTED

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _submit_alert(self, alert: AlertRecord) -> dict | None:
        """Build, sign, and submit a logAlert transaction (synchronous).

        Returns:
            The transaction receipt dict, or ``None`` on failure.
        """
        try:
            nonce = self._w3.eth.get_transaction_count(self._account.address)

            # Build transaction
            tx = self._contract.functions.logAlert(
                alert.signature_id,
                alert.threat_type,
                alert.severity,
                int(alert.confidence * 100),  # Store as uint 0-100
                alert.src_ip,
                alert.dst_ip,
                alert.protocol,
                int(alert.timestamp),
                alert.description,
            ).build_transaction({
                "chainId": self._chain_id,
                "from": self._account.address,
                "nonce": nonce,
                "gas": 500_000,
                "gasPrice": self._w3.eth.gas_price,
            })

            # Sign and send
            signed = self._w3.eth.account.sign_transaction(
                tx, private_key=self._private_key
            )
            tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
            return dict(receipt)

        except Exception as exc:
            logger.warning("Transaction submission failed: %s", exc)
            return None

    @staticmethod
    def _minimal_abi() -> list[dict]:
        """Return a minimal ABI for AlertRegistry with logAlert, getAlert, getAlertCount."""
        return [
            {
                "inputs": [
                    {"name": "_signatureId", "type": "string"},
                    {"name": "_threatType", "type": "string"},
                    {"name": "_severity", "type": "string"},
                    {"name": "_confidence", "type": "uint256"},
                    {"name": "_srcIp", "type": "string"},
                    {"name": "_dstIp", "type": "string"},
                    {"name": "_protocol", "type": "uint256"},
                    {"name": "_timestamp", "type": "uint256"},
                    {"name": "_description", "type": "string"},
                ],
                "name": "logAlert",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [{"name": "_index", "type": "uint256"}],
                "name": "getAlert",
                "outputs": [
                    {"name": "", "type": "string"},
                    {"name": "", "type": "string"},
                    {"name": "", "type": "string"},
                    {"name": "", "type": "uint256"},
                    {"name": "", "type": "string"},
                    {"name": "", "type": "string"},
                    {"name": "", "type": "uint256"},
                    {"name": "", "type": "uint256"},
                    {"name": "", "type": "string"},
                ],
                "name": "getAlert",
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [],
                "name": "getAlertCount",
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            },
        ]
