# Security

> [!CAUTION]
> **This is an educational portfolio project.** It is NOT intended for production
> deployment. The system has not been independently audited. Do not rely on it to
> protect real networks or infrastructure.

---

## Security Design Decisions

This section documents the intentional security controls in marmot-nids and their
rationale. These design patterns are the portfolio showcase — they demonstrate
security engineering thinking, not production-grade hardening.

### Signature File Integrity

`signatures.json` is HMAC-signed at build time by `sign_signatures.py`. On every
startup, `SignatureManager` recomputes the HMAC and compares it to
`signatures.json.hmac`. A mismatch raises `SignatureLoadError` and halts the
detection engine — it does not fall back to loading a potentially tampered file
silently.

**Threat addressed:** An attacker with write access to the filesystem could modify
signatures to suppress detections. The HMAC check ensures this would require
knowledge of `SIGNATURE_HMAC_SECRET` as well.

### Blockchain Access Control

The `AlertRegistry` smart contract uses OpenZeppelin `Ownable`. Only the account
that deployed the contract (stored in `ETHEREUM_PRIVATE_KEY`) can call `logAlert()`.

This fixes a vulnerability in the original FYP implementation where any connected
account could append arbitrary records to the audit log.

### Private Key Isolation

`ETHEREUM_PRIVATE_KEY` is accessed **only** inside `EthereumProvider`. It is never
logged, serialised, or passed to any other component. Even at DEBUG level, only the
derived account address is logged.

### LLM Response Validation

All LLM responses are parsed through a strict Pydantic schema before any field is
accessed. A `ParseResult` wrapper ensures that malformed or adversarial JSON from the
LLM layer never propagates as an exception into the detection pipeline.

**Threat addressed:** A compromised or misconfigured Ollama instance returning
malicious content cannot cause a parsing exception that halts the detection loop.

### Local LLM (No Cloud Dependency)

All LLM inference runs locally via Ollama. Network flow data — which may contain
sensitive host information — is never sent to a third-party API. This is documented
in [ADR-002](docs/adr/002-local-llm-ollama.md).

### Packet Capture Privileges

Raw packet capture requires elevated privileges:
- **Windows:** Npcap must be installed with WinPcap compatibility mode
- **Linux:** `CAP_NET_RAW` capability on the Python binary, or run via Docker with
  `cap_add: NET_RAW`

The application should never be run as Administrator/root for the entire process.

### Path Traversal Prevention

File operations that accept configurable paths (signatures, RAG knowledge) validate
that resolved paths are within the expected base directory before reading.

### Alert Immutability

`Alert` and `AlertRecord` dataclasses use `frozen=True` to prevent post-creation
mutation, ensuring the detection pipeline's output cannot be tampered with between
generation and consumption/logging.

---

## Known Limitations

| Area | Limitation |
|------|-----------|
| Packet capture | Requires elevated privileges (Npcap on Windows, CAP_NET_RAW on Linux) |
| SQLite storage | Single-file database, adequate for lab/educational use only |
| Local LLM | Detection quality depends on Gemma3 model capabilities |
| Blockchain | Hardhat local node is not a production chain |
| WebSocket | No authentication on WebSocket upgrade in current implementation |

---

## Threat Model

A STRIDE threat model covering all six system components is in
[docs/threat-model.md](docs/threat-model.md).
