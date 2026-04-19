"""
core.blockchain
================
Pluggable blockchain audit logging provider.

Implements ADR-001: the ``BlockchainProvider`` abstract interface and two
concrete implementations:

* ``NullProvider`` — no-op stub; allows the system to run without a
  blockchain node.
* ``EthereumProvider`` — connects to an Ethereum-compatible chain via
  web3.py and submits alerts to the ``AlertRegistry`` contract.

The active provider is selected at startup based on the
``BLOCKCHAIN_PROVIDER`` environment variable.
"""
