# marmot-nids Threat Model

**Method:** STRIDE per component  
**Date:** 2026-04-18  
**Author:** Kai  
**Scope:** The marmot-nids application stack as deployed via Docker Compose on a single host,
monitoring a local network segment.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Trust Boundaries](#2-trust-boundaries)
3. [Component: Packet Capture](#3-component-packet-capture)
4. [Component: Detection Engines](#4-component-detection-engines)
5. [Component: Alert Storage (SQLite)](#5-component-alert-storage-sqlite)
6. [Component: Blockchain Layer](#6-component-blockchain-layer)
7. [Component: API Layer (FastAPI)](#7-component-api-layer-fastapi)
8. [Component: Frontend Dashboard](#8-component-frontend-dashboard)
9. [Summary Risk Table](#9-summary-risk-table)
10. [Mitigations Not Yet Implemented](#10-mitigations-not-yet-implemented)

---

## 1. System Overview

```
[Network Traffic] ──► [Packet Capture] ──► [Flow Assembler]
                                                  │
                              ┌───────────────────┴───────────────────┐
                              ▼                                       ▼
                    [Signature Engine]                      [LLM Engine + RAG]
                              │                                       │
                              └───────────────┬───────────────────────┘
                                              ▼
                                     [Alert Storage]
                                       (SQLite)
                                              │
                              ┌───────────────┴──────────────┐
                              ▼                              ▼
                    [Blockchain Provider]            [FastAPI Backend]
                    (Hardhat / NullProvider)               │
                                                    ┌──────┴──────┐
                                                    ▼             ▼
                                               [REST API]   [WebSocket]
                                                    │             │
                                                    └──────┬──────┘
                                                           ▼
                                                  [Frontend Dashboard]
```

**Actors:**

| Actor | Trust Level | Description |
|-------|-------------|-------------|
| Network attacker | Untrusted | Source of malicious traffic being monitored |
| API consumer | Semi-trusted | Holds a valid API key; may be compromised |
| System operator | Trusted | Configures and deploys the system |
| LLM (Ollama) | Semi-trusted | Local process; output validated through Pydantic |
| Blockchain node | Semi-trusted | Local Hardhat node or external RPC |

---

## 2. Trust Boundaries

| Boundary | Description |
|----------|-------------|
| B1 | Network interface → Scapy sniffer (raw packet ingestion) |
| B2 | Flow assembler → detection engines (structured flow data) |
| B3 | Detection engines → SQLite (alert persistence) |
| B4 | SQLite → blockchain sync task (read + status update) |
| B5 | FastAPI → external callers (HTTP/WebSocket) |
| B6 | FastAPI → LLM engine (internal async queue) |
| B7 | Frontend → FastAPI (API calls + WebSocket) |

---

## 3. Component: Packet Capture

**Function:** Sniffs raw packets from the network interface using Scapy and assembles
5-tuple flows.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | Attacker spoofs source IP addresses in captured packets, causing flows to be misattributed to legitimate hosts. | Medium | Inherent limitation of IP-based attribution. Detection relies on traffic pattern anomalies, not IP identity alone. |
| **Tampering** | Malformed or crafted packets designed to crash or corrupt the Scapy parser (e.g. oversized fields, malformed TCP options). | Medium | Scapy's parser is tolerant of malformed packets by design. `FlowAssembler` discards packets that fail field extraction without raising. Fuzzing with Scapy-crafted malformed packets is included in test fixtures. |
| **Repudiation** | No integrity guarantee on captured traffic. An attacker on the wire cannot be definitively identified. | Low | Out of scope for a NIDS. Attribution is a separate function. Flows are recorded with timestamps. |
| **Information Disclosure** | Captured payloads (plain-text protocols: HTTP, FTP, Telnet) may contain passwords, tokens, or personal data. Raw payloads are briefly held in memory during flow assembly. | High | Payloads are not persisted to SQLite or logged. Only statistical features (packet lengths, IAT, flag counts) are stored. Payload fragments used for signature matching are discarded after evaluation. |
| **Denial of Service** | High-volume traffic (legitimate or attack) floods the capture queue, exhausting memory or causing packet loss. | High | Configurable `CAPTURE_MAX_QUEUE_SIZE` with tail-drop. Warning logged on drop. `DoSTracker` uses a sliding window to detect flood conditions before they saturate the queue. |
| **Elevation of Privilege** | Capture requires `CAP_NET_RAW` (Linux) or administrator privileges (Windows). If the capture process is compromised, the attacker inherits raw socket access. | High | Capture runs with the minimum capability set required. Recommended: `setcap cap_net_raw=eip python3` so the capability is on the binary, not the user. Docker: `NET_RAW` + `NET_ADMIN` on the capture container only. FastAPI server runs as UID 1000 (non-root). |

---

## 4. Component: Detection Engines

**Function:** Evaluates assembled flows against HMAC-verified signatures and via
local LLM inference with RAG context.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | Attacker crafts traffic that statistically resembles benign patterns (slow-rate attacks, protocol mimicry) to evade both signature and LLM detection. | High | Inherent evasion risk in any NIDS. LLM contextual analysis provides a second opinion beyond rigid signatures. RAG knowledge base includes known evasion technique descriptions. |
| **Tampering** | `signatures.json` modified on disk to remove or weaken detection rules, suppressing alerts for specific attack types. | High | HMAC-SHA256 integrity check on every load. `SignatureManager` raises `SignatureIntegrityError` and halts if the file has been modified without re-signing. Requires knowledge of `SIGNATURE_HMAC_KEY` to forge. |
| **Repudiation** | An alert could be claimed never to have fired if log records are deleted. | Medium | Alerts are persisted to SQLite (append-only in practice) and optionally committed to the blockchain. Blockchain records are immutable once confirmed. |
| **Information Disclosure** | Flow data passed to the LLM includes IP addresses and port numbers. If Ollama is misconfigured to forward to a remote endpoint, this data could leak. | Medium | `LLMEngine` makes HTTP calls only to `OLLAMA_BASE_URL`. In Docker Compose, Ollama runs on the same internal network — no external egress. See [ADR-002](adr/002-local-llm-ollama.md). |
| **Denial of Service** | A flood of flows saturates the LLM batch queue, causing unbounded memory growth or indefinite queue delay. | Medium | `LLM_BATCH_SIZE` and `LLM_BATCH_TIMEOUT` bound the queue depth and processing interval. The LLM engine runs in a separate asyncio task — queue saturation does not block signature detection. |
| **Elevation of Privilege** | Prompt injection via crafted packet payload: attacker embeds LLM instruction strings in a packet payload hoping to alter the LLM's output schema. | Medium | Flow data sent to the LLM is structured statistics, not raw payload content. Payloads are not interpolated into prompts. All LLM output is validated through Pydantic regardless of content — prompt injection that bypasses the JSON schema is a no-op. |

---

## 5. Component: Alert Storage (SQLite)

**Function:** Persists all alerts, flow records, and blockchain sync state.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | N/A — SQLite is a local file; no network authentication surface. | N/A | — |
| **Tampering** | The SQLite file is modified directly on disk to alter or delete alert records. | High | SQLite WAL mode enables consistent reads. For forensic integrity, blockchain sync provides an independent, tamper-evident copy of alert records. Filesystem permissions should restrict the DB file to the application user only. |
| **Repudiation** | Alert records deleted from SQLite to deny that a detection occurred. | High | Same as above — blockchain sync is the non-repudiation mechanism. All records include a creation timestamp. |
| **Information Disclosure** | Alert records contain IP addresses, port numbers, and threat descriptions that reveal internal network topology. | Medium | Database file should be owner-readable only (`chmod 600`). SQLModel ORM prevents raw SQL injection. No database connection string is logged. |
| **Denial of Service** | Unbounded alert growth fills the host filesystem. | Medium | Alerts older than a configurable retention period should be archived or deleted. `DB_PATH` allows placing the database on a separate volume with a disk quota. |
| **Elevation of Privilege** | SQL injection via alert fields written by the detection engine. | Low | All database writes go through SQLModel (ORM). No raw SQL string interpolation. Alert fields are typed Pydantic models — free-form strings are not executed. |

---

## 6. Component: Blockchain Layer

**Function:** Provides pluggable, tamper-evident audit logging for alerts via an
Ethereum-compatible smart contract.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | An attacker impersonates the deployer account to call `logAlert()` and inject fabricated alerts into the audit log. | High | `AlertRegistry.sol` uses OpenZeppelin `Ownable`. Only the deployer's address can call `logAlert()`. Non-owner calls revert. See [ADR-001](adr/001-pluggable-blockchain.md). |
| **Tampering** | On-chain records are modified after submission. | Low | Blockchain immutability makes post-submission modification computationally infeasible on a proof-of-work or proof-of-stake chain. Hardhat local chain has no such guarantee — use a testnet or mainnet for production. |
| **Repudiation** | The deployer claims a specific alert was never submitted on-chain. | Low | `AlertLogged` events are emitted for every `logAlert()` call and are permanently part of the chain's event log. |
| **Information Disclosure** | Alert data on a public chain is visible to anyone. Alert descriptions may reveal internal IP ranges or vulnerability details. | Medium | Hardhat is a local private chain. Deployment to a public testnet or mainnet requires careful consideration of what data is included in the on-chain record (currently: name, category, severity, flow hash, timestamp). The `flowHash` is a hash of the flow key, not the full record. |
| **Denial of Service** | Blockchain node goes offline; the sync task retries indefinitely, consuming CPU. | Medium | Exponential backoff (`BC_RETRY_BACKOFF`) with a maximum retry count (`BC_RETRY_MAX`). After max retries, the batch is marked as `failed` in SQLite and skipped. Unsent alerts are not lost. |
| **Elevation of Privilege** | `ETHEREUM_PRIVATE_KEY` is compromised, allowing an attacker to submit arbitrary records as the owner. | Critical | Key is read from environment only — never logged, never stored in source. In production, use a hardware wallet or KMS-backed signer. Restrict key usage to the `logAlert()` function via a multi-sig or role-based contract if the audit log is high-value. |

---

## 7. Component: API Layer (FastAPI)

**Function:** Exposes REST endpoints and a WebSocket feed for external consumers
and the frontend dashboard.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | API key theft allows an attacker to impersonate a legitimate consumer. | High | HMAC-SHA256 comparison with `hmac.compare_digest` prevents timing attacks. API keys are never stored in plaintext. Key rotation requires generating a new hash via `generate_api_key.py`. |
| **Tampering** | Request body manipulation to inject malformed data into the detection pipeline or database. | Medium | All request bodies are validated by Pydantic before any handler logic runs. Invalid payloads return `422` before reaching business logic. |
| **Repudiation** | API calls are not logged with sufficient context to reconstruct an incident. | Medium | Structured logging records the API key hash (not plaintext), endpoint, method, status code, and timestamp for all mutating operations. |
| **Information Disclosure** | Alert data returned by GET endpoints reveals internal network topology and vulnerability information. | Medium | All endpoints require API key authentication. In production, TLS is required between the client and the server. The OpenAPI docs endpoint is disabled in production. |
| **Denial of Service** | Unauthenticated or authenticated flood of requests exhausts the asyncio event loop. | High | Sliding window rate limiter per API key. `401` is returned for unauthenticated requests before any rate-limit state is touched — prevents using rate-limit state as a side-channel. |
| **Elevation of Privilege** | Missing authentication on an admin endpoint allows an unauthenticated caller to stop packet capture or modify configuration. | High | All capture control endpoints (`POST /capture/start`, `POST /capture/stop`) require a valid API key. Dependency injection (`Depends(require_api_key)`) ensures the check cannot be bypassed at the route level. |

---

## 8. Component: Frontend Dashboard

**Function:** Browser-based UI that displays real-time alerts, flows, and blockchain
status via a WebSocket connection to the API.

### STRIDE Analysis

| Threat | Description | Risk | Mitigation |
|--------|-------------|------|------------|
| **Spoofing** | The API key stored in `sessionStorage` is exfiltrated via XSS, allowing an attacker to impersonate the operator's browser session. | High | `sessionStorage` is not accessible across origins. Content-Security-Policy headers (set by FastAPI middleware) should restrict script sources. For production, short-lived tokens derived from the API key should replace long-lived keys in the browser. |
| **Tampering** | CSRF: a malicious page tricks the operator's browser into making authenticated API calls. | Medium | All mutating API calls require the `X-API-Key` header. Browser CSRF attacks cannot set custom headers on cross-origin requests. WebSocket connections from untrusted origins are rejected by CORS configuration. |
| **Repudiation** | Client-side state (alert table, chart data) can be manipulated by browser extensions or devtools. | Low | The frontend is read-only for display purposes. All authoritative data lives server-side in SQLite. Refreshing the page re-fetches from the API. |
| **Information Disclosure** | Alert data is visible in browser devtools network tab and the DOM. | Low | Accepted: the frontend is only accessible to the operator on the local machine. TLS in production encrypts transit. |
| **Denial of Service** | A malicious script on a different tab floods the WebSocket endpoint. | Low | Rate limiter on the API key applies to WebSocket connections as well as REST endpoints. |
| **Elevation of Privilege** | N/A — the frontend has no elevated privileges; it only consumes the API. | N/A | — |

---

## 9. Summary Risk Table

| ID | Component | Threat | Severity | Status |
|----|-----------|--------|----------|--------|
| T01 | Capture | Payload data in memory | High | Mitigated (not persisted) |
| T02 | Capture | Privilege escalation via `CAP_NET_RAW` | High | Mitigated (capability isolation) |
| T03 | Detection | Signature file tampering | High | Mitigated (HMAC verification) |
| T04 | Detection | Evasion via traffic crafting | High | Accepted (inherent NIDS limitation) |
| T05 | Storage | Database file tampering | High | Partially mitigated (blockchain sync) |
| T06 | Blockchain | Private key compromise | Critical | Mitigated (env-only; KMS recommended for prod) |
| T07 | Blockchain | Non-owner `logAlert()` call | High | Mitigated (OpenZeppelin Ownable) |
| T08 | API | API key timing attack | High | Mitigated (constant-time compare) |
| T09 | API | Rate limit exhaustion | High | Mitigated (sliding window per key) |
| T10 | Frontend | XSS → API key exfiltration | High | Partially mitigated (CSP; session-only storage) |
| T11 | Detection | Prompt injection via payload | Medium | Mitigated (structured prompts; Pydantic output validation) |
| T12 | Capture | Source IP spoofing | Medium | Accepted (inherent IP limitation) |

---

## 10. Mitigations Not Yet Implemented

These known gaps are deferred to post-MVP phases or require operational controls:

| Gap | Recommendation |
|-----|----------------|
| No TLS on the API | Deploy behind a reverse proxy (nginx, Caddy) with TLS termination in production |
| Blockchain private key in env | Use a hardware wallet or cloud KMS signer for production deployments |
| Frontend API key in sessionStorage | Replace with short-lived tokens (HMAC-signed, time-bounded) for production |
| Alert retention policy | Implement configurable TTL-based archival or deletion for SQLite alerts |
| No anomaly baseline | Establishing a traffic baseline would reduce false positives from LLM detection |
| Web application firewall | Consider WAF rules in the reverse proxy for the API endpoints |
