# ADR-001: Pluggable Blockchain Provider

## Status

Accepted

---

## Context

The original FYP implementation hardcoded Ganache as the blockchain backend. This
created three problems:

1. **Fragility** — The detection pipeline crashed entirely if the Ganache node was
   unavailable, even during development or testing where blockchain logging is not
   relevant.

2. **Testability** — Unit and integration tests required a running Ganache instance,
   making the CI environment complex and slow to provision.

3. **Vendor lock-in** — All blockchain interaction was directly coupled to Ganache's
   specific RPC behaviour, making migration to any other provider (Hardhat, Sepolia,
   or a production chain) a significant refactor.

Additionally, Ganache has been deprecated by the Truffle Suite, removing it as a
viable long-term dependency.

The system needs a blockchain audit log that is: optional during development,
non-blocking when unavailable, and easy to swap for a different chain without
changing application code.

---

## Decision

We define an abstract `BlockchainProvider` interface (Python `ABC`) in
`core/blockchain/provider.py` with the following contract:

```python
class BlockchainProvider(ABC):
    async def log_alert(self, alert: AlertRecord) -> TxReceipt | None: ...
    async def get_alert(self, index: int) -> AlertRecord | None: ...
    async def get_alert_count(self) -> int: ...
    async def health_check(self) -> ProviderStatus: ...
```

Two concrete implementations are shipped:

| Implementation | Module | Behaviour |
|----------------|--------|-----------|
| `EthereumProvider` | `core/blockchain/ethereum.py` | Submits alerts to an Ethereum-compatible node via web3.py. Requires `ETHEREUM_RPC_URL`, `ETHEREUM_PRIVATE_KEY`, and `CONTRACT_ADDRESS`. |
| `NullProvider` | `core/blockchain/null_provider.py` | No-op. All methods succeed silently. `health_check()` returns `ProviderStatus.DISABLED`. Alerts are retained in SQLite. |

The active provider is selected at startup based on the `BLOCKCHAIN_PROVIDER`
environment variable (`"ethereum"` or `"none"`). Application code never imports
a concrete provider — it always depends on the abstract interface.

The background sync task (`core/blockchain/sync.py`) is provider-agnostic: it
queries SQLite for unsynced alerts and delegates to whatever provider is configured.

---

## Consequences

**Positive:**

- The detection pipeline never crashes due to blockchain unavailability.
- `NullProvider` allows all non-blockchain tests to run without any node.
- New chain integrations (e.g. Polygon, an enterprise chain) require only a new
  class implementing `BlockchainProvider` — zero changes to application logic.
- The Hardhat migration from Ganache is isolated to `EthereumProvider` and the
  `contracts/` directory.

**Negative:**

- Adds an abstraction layer that developers must understand before extending.
- Misconfiguration (wrong `BLOCKCHAIN_PROVIDER` value) silently uses `NullProvider`
  rather than failing loudly. Mitigated by a startup log message stating the
  active provider.

---

## Security Implications

- **Private key isolation:** `ETHEREUM_PRIVATE_KEY` is accessed only inside
  `EthereumProvider`. It is never passed to or stored by any other component.
  The key is never logged at any level.

- **Owner-only contract writes:** `AlertRegistry.sol` uses OpenZeppelin `Ownable`.
  Only the deployer account can call `logAlert()`. The provider pattern ensures
  that only the configured private key can initiate blockchain writes — there is
  no pathway for an unauthenticated caller to submit fabricated alerts on-chain.

- **NullProvider non-repudiation:** Using `NullProvider` means on-chain
  non-repudiation is not available. This is a deployment choice made explicit by
  the operator via environment configuration, not an invisible degradation.
  Alerts are still stored in SQLite with timestamps.

- **Replay attack surface:** The background sync task uses monotonically increasing
  SQLite IDs, not content-based deduplication. A restart after partial sync may
  produce duplicate blockchain transactions. This is acceptable for an audit log
  (duplicate entries are visible and do not corrupt the record).
