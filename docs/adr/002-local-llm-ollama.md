# ADR-002: Local LLM Inference via Ollama

## Status

Accepted

---

## Context

The detection pipeline requires a language model capable of contextual threat
analysis — examining flow statistics, packet patterns, and protocol behaviour to
identify anomalies that rule-based signatures cannot express.

Several integration approaches were considered:

| Option | Description | Key Concerns |
|--------|-------------|--------------|
| Cloud API (OpenAI, Anthropic) | Send flow data to a hosted model | Privacy: raw network data sent to third party; Cost: per-token billing; Availability: requires internet connectivity |
| Fine-tuned local model (self-hosted) | Train or fine-tune a model on traffic datasets | Complexity: significant MLOps overhead outside project scope |
| Ollama + community model | Run a quantised open-weight model locally | Privacy: no data leaves the host; Cost: zero per-inference; Offline: works in air-gapped environments |

The primary blocker for cloud APIs is **data sensitivity**. Network flow records
may contain:

- Internal IP address ranges revealing network topology
- Port patterns that indicate internal service architecture
- Payload fragments (in plain-text protocols) that may include credentials,
  session tokens, or personal data

Sending this data to a third-party API conflicts with the security posture of any
IDS deployed in a production network and with reasonable data protection obligations.

---

## Decision

We use **Ollama** as the local LLM runtime with **Gemma3** as the default model.

- Ollama provides a simple REST API (`/api/generate`, `/api/chat`) that abstracts
  model loading, quantisation, and hardware acceleration.
- Gemma3 (Google DeepMind) is a capable small model with a strong instruction-following
  profile, available in 4-bit quantised form that runs on consumer hardware.
- The model is configurable via `LLM_MODEL` environment variable — operators can
  substitute any Ollama-compatible model (e.g. `llama3.2`, `mistral-nemo`) without
  code changes.

### Connectivity check

On startup, `LLMEngine` probes `OLLAMA_BASE_URL/api/tags`. If Ollama is unreachable:

- A `WARNING` is logged with the URL that was attempted.
- LLM detection is disabled for the session (`LLM_ENABLED` is set to `False` internally).
- Signature-based detection continues unaffected.
- The system does **not** crash — partial capability is better than no capability.

### Async batch processing

The LLM engine runs in a dedicated `asyncio` task. Flow records are queued and
batched (up to `LLM_BATCH_SIZE` or `LLM_BATCH_TIMEOUT` seconds, whichever fires
first) before a single prompt is constructed and submitted. This decouples LLM
inference latency from the real-time capture loop.

### Prompt determinism

Prompts are constructed by `PromptBuilder` using a fixed template structure:
`system role → RAG context → flow data → output schema`. The output schema is
injected into the prompt as an explicit JSON contract, and the LLM is instructed
to respond **only** with valid JSON matching that schema. The `LLMParser` validates
all responses through Pydantic before any field is accessed.

---

## Consequences

**Positive:**

- Zero data exfiltration risk: all inference is local and offline.
- No API key management or billing for LLM usage.
- Works in air-gapped environments and during internet outages.
- Model can be swapped without code changes.
- Startup graceful degradation means the system never fails completely because
  Ollama is slow to start or the model is still loading.

**Negative:**

- Inference speed depends on local hardware (CPU/GPU). On CPU-only hosts, latency
  per batch may be 5–30 seconds, which is acceptable for contextual analysis but
  not for real-time alerting.
- Model quality is below frontier models. Mitigated by RAG context injection and
  a confidence threshold that discards weak signals.
- Ollama must be running before marmot-nids starts. Docker Compose `depends_on`
  with a health check handles this for containerised deployments.

---

## Security Implications

- **No network egress for flow data.** This is the primary security motivation for
  this decision. Auditors can verify it by inspecting `LLMEngine` — the only
  external HTTP call is to `OLLAMA_BASE_URL`, which resolves to localhost or an
  internal host.

- **Prompt injection via crafted packets.** An attacker aware that payloads are
  included in LLM prompts could craft packets containing prompt injection strings
  (e.g. `"Ignore previous instructions..."`). Mitigations:
  1. Flow data is structured (statistics, not raw payload) — payloads are not
     inserted verbatim.
  2. The system prompt explicitly defines the output schema, making injection
     that bypasses the JSON parser effectively a no-op.
  3. All LLM output passes through Pydantic validation regardless of content.

- **Model output trust.** LLM alerts are treated as *advisory signals* with a
  confidence score, not ground truth. The confidence threshold (`LLM_CONFIDENCE_THRESHOLD`)
  acts as a noise floor. Human review is expected for all generated alerts in a
  production deployment.
