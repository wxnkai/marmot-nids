"""
core.blockchain.factory
========================
Provider factory — selects the active ``BlockchainProvider`` based on
environment configuration.

Security relevance:
    The factory is the single place where sensitive blockchain credentials
    (``ETHEREUM_PRIVATE_KEY``) are read from the environment.  If the
    configured provider is ``"none"`` (default), no credentials are accessed
    and ``NullProvider`` is returned.

    See ADR-001 for the full design rationale.
"""

from __future__ import annotations

import logging

from decouple import UndefinedValueError, config

from core.blockchain.null_provider import NullProvider
from core.blockchain.provider import BlockchainProvider

logger = logging.getLogger(__name__)


def create_provider() -> BlockchainProvider:
    """Create and return the configured ``BlockchainProvider``.

    Reads the ``BLOCKCHAIN_PROVIDER`` environment variable:

    * ``"none"`` (default) — returns ``NullProvider``.
    * ``"ethereum"`` — returns ``EthereumProvider``, reading
      ``ETHEREUM_RPC_URL``, ``ETHEREUM_PRIVATE_KEY``,
      ``CONTRACT_ADDRESS``, and ``ETHEREUM_CHAIN_ID``.

    Returns:
        A concrete ``BlockchainProvider`` instance.

    Security note:
        If ``BLOCKCHAIN_PROVIDER`` is set to an unrecognised value,
        ``NullProvider`` is used and a warning is logged.  The system
        never crashes on blockchain misconfiguration — detection
        continues unaffected.
    """
    try:
        provider_type = config("BLOCKCHAIN_PROVIDER", default="none").lower().strip()
    except UndefinedValueError:
        provider_type = "none"

    if provider_type == "none":
        return NullProvider()

    if provider_type == "ethereum":
        return _create_ethereum_provider()

    logger.warning(
        "Unknown BLOCKCHAIN_PROVIDER '%s' — falling back to NullProvider. "
        "Valid values: 'none', 'ethereum'.",
        provider_type,
    )
    return NullProvider()


def _create_ethereum_provider() -> BlockchainProvider:
    """Instantiate ``EthereumProvider`` from environment variables.

    Returns:
        An ``EthereumProvider`` instance, or ``NullProvider`` if
        required configuration is missing or web3 is not installed.
    """
    try:
        from core.blockchain.ethereum import EthereumProvider  # noqa: PLC0415

        rpc_url = config("ETHEREUM_RPC_URL", default="http://localhost:8545")
        private_key = config("ETHEREUM_PRIVATE_KEY")
        contract_address = config("CONTRACT_ADDRESS")
        chain_id = int(config("ETHEREUM_CHAIN_ID", default="31337"))

        return EthereumProvider(
            rpc_url=rpc_url,
            private_key=private_key,
            contract_address=contract_address,
            chain_id=chain_id,
        )

    except UndefinedValueError as exc:
        logger.warning(
            "Ethereum blockchain configuration incomplete: %s — "
            "falling back to NullProvider.",
            exc,
        )
        return NullProvider()

    except ImportError:
        logger.warning(
            "web3 is not installed — cannot use EthereumProvider. "
            "Install with: pip install web3. Falling back to NullProvider."
        )
        return NullProvider()

    except Exception as exc:
        logger.warning(
            "Failed to create EthereumProvider: %s — "
            "falling back to NullProvider.",
            exc,
        )
        return NullProvider()
