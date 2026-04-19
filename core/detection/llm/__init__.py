"""
core.detection.llm
==================
LLM-based contextual threat analysis engine.

This package implements the second detection pillar: submitting batched flow
records to a local Ollama instance (Gemma3 by default) with RAG-injected
threat intelligence context, then parsing and validating the structured JSON
response.

See ADR-002 (docs/adr/002-local-llm-ollama.md) for the privacy and
architectural rationale behind local-only inference.
"""
