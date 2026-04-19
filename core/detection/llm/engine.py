"""
core.detection.llm.engine
==========================
Async LLM-based contextual threat analysis engine.

Security relevance:
    This engine implements the second detection pillar — contextual analysis
    via local LLM inference.  Design invariants:

    1. **Non-blocking** — runs in a dedicated ``asyncio.Task``, never blocks
       the main capture loop or the FastAPI event loop.

    2. **Graceful degradation** — if Ollama is unreachable at startup, the
       engine disables itself and logs a warning.  Signature detection
       continues unaffected.  The system never crashes because the LLM is slow
       or unavailable.

    3. **Batch processing** — flows are collected up to ``batch_size`` or
       ``batch_timeout`` seconds (whichever comes first) before a single
       prompt is built and submitted.  This amortises inference cost.

    4. **Local only** — HTTP calls go only to ``OLLAMA_BASE_URL`` (localhost
       by default).  No flow data leaves the host.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

import httpx

from core.capture.flow_assembler import FlowRecord
from core.detection.base import Alert, DetectionEngine
from core.detection.llm.parser import LLMParser, ParseResult
from core.detection.llm.prompt_builder import PromptBuilder
from core.detection.llm.rag.retriever import RAGRetriever

logger = logging.getLogger(__name__)


class LLMEngine(DetectionEngine):
    """Async LLM detection engine backed by Ollama.

    Args:
        ollama_url: Base URL of the Ollama API.
            Corresponds to ``OLLAMA_BASE_URL``.
        model: Model name for inference.
            Corresponds to ``LLM_MODEL``.
        batch_size: Maximum flows per batch before submission.
            Corresponds to ``LLM_BATCH_SIZE``.
        batch_timeout: Maximum seconds to wait for a full batch.
            Corresponds to ``LLM_BATCH_TIMEOUT``.
        confidence_threshold: Minimum confidence for an alert.
            Corresponds to ``LLM_CONFIDENCE_THRESHOLD``.
        rag_retriever: Optional RAG retriever for context injection.
        on_alerts: Optional callback invoked with new alerts (for the
            alert handler / WebSocket broadcast).

    Security note:
        The engine's HTTP client uses a 120-second timeout.  A hung
        Ollama instance will not block the asyncio loop indefinitely.
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "gemma3",
        batch_size: int = 10,
        batch_timeout: float = 5.0,
        confidence_threshold: float = 0.6,
        rag_retriever: RAGRetriever | None = None,
        on_alerts: Callable[[list[Alert]], None] | None = None,
    ) -> None:
        self._ollama_url = ollama_url.rstrip("/")
        self._model = model
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout
        self._prompt_builder = PromptBuilder()
        self._parser = LLMParser(confidence_threshold=confidence_threshold)
        self._retriever = rag_retriever
        self._on_alerts = on_alerts

        self._queue: asyncio.Queue[FlowRecord] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._enabled: bool = True
        self._running: bool = False
        self._total_batches: int = 0
        self._total_alerts: int = 0
        self._total_errors: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background batch-processing task.

        Probes Ollama at startup.  If unreachable, disables the engine
        rather than crashing.

        Security note:
            The connectivity check makes a single GET to
            ``OLLAMA_BASE_URL/api/tags``.  This is a read-only metadata
            endpoint that reveals the loaded model list.
        """
        available = await self._check_ollama()
        if not available:
            logger.warning(
                "Ollama unreachable at %s — LLM detection disabled. "
                "Signature detection continues normally.",
                self._ollama_url,
            )
            self._enabled = False
            return

        self._running = True
        self._task = asyncio.create_task(
            self._batch_loop(), name="llm-engine-batch-loop"
        )
        logger.info(
            "LLM engine started: model=%s, batch_size=%d, timeout=%.1fs",
            self._model,
            self._batch_size,
            self._batch_timeout,
        )

    async def stop(self) -> None:
        """Signal the batch loop to stop and wait for it to finish.

        Drains any remaining flows in the queue before stopping.
        """
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            "LLM engine stopped: %d batches, %d alerts, %d errors",
            self._total_batches,
            self._total_alerts,
            self._total_errors,
        )

    @property
    def is_enabled(self) -> bool:
        """Whether the LLM engine is active (Ollama was reachable)."""
        return self._enabled

    @property
    def is_running(self) -> bool:
        """Whether the batch loop task is running."""
        return self._running

    # ------------------------------------------------------------------
    # DetectionEngine interface (synchronous — queues for async processing)
    # ------------------------------------------------------------------

    def analyse(self, flow: FlowRecord) -> list[Alert]:
        """Queue a flow for async LLM analysis.

        This method is synchronous to satisfy the ``DetectionEngine``
        interface.  Flows are placed on an internal asyncio queue and
        processed in batches by the background task.

        Args:
            flow: A completed ``FlowRecord``.

        Returns:
            Always returns an empty list.  Alerts are delivered
            asynchronously via the ``on_alerts`` callback.

        Security note:
            The method returns immediately.  Alert latency depends on
            batch fill time and LLM inference time.
        """
        if not self._enabled:
            return []

        try:
            self._queue.put_nowait(flow)
        except asyncio.QueueFull:
            logger.warning("LLM queue full — dropping flow %s", flow.key)

        return []

    async def submit_flow(self, flow: FlowRecord) -> None:
        """Async version of ``analyse`` for use from async contexts.

        Args:
            flow: A completed ``FlowRecord``.
        """
        if not self._enabled:
            return
        await self._queue.put(flow)

    # ------------------------------------------------------------------
    # Background batch loop
    # ------------------------------------------------------------------

    async def _batch_loop(self) -> None:
        """Main batch processing loop.  Runs as a background asyncio task.

        Collects flows until ``batch_size`` is reached or ``batch_timeout``
        elapses, then builds a prompt and submits to Ollama.

        Security note:
            Exceptions inside this loop are caught and logged — a single
            malformed LLM response or network hiccup does not kill the
            detection pipeline.
        """
        while self._running:
            batch: list[FlowRecord] = []
            deadline = time.monotonic() + self._batch_timeout

            try:
                # Collect batch
                while len(batch) < self._batch_size:
                    remaining = max(0.01, deadline - time.monotonic())
                    try:
                        flow = await asyncio.wait_for(
                            self._queue.get(), timeout=remaining
                        )
                        batch.append(flow)
                    except TimeoutError:
                        break

                if not batch:
                    continue

                # Process batch
                await self._process_batch(batch)

            except asyncio.CancelledError:
                # Drain remaining items
                while not self._queue.empty():
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if batch:
                    await self._process_batch(batch)
                raise

            except Exception as exc:
                self._total_errors += 1
                logger.error(
                    "LLM batch loop error (batch will be dropped): %s", exc
                )

    async def _process_batch(self, batch: list[FlowRecord]) -> None:
        """Build prompt, query Ollama, parse response, and deliver alerts.

        Args:
            batch: List of ``FlowRecord`` objects to analyse.
        """
        self._total_batches += 1

        # Build RAG context
        rag_context: str | None = None
        if self._retriever and self._retriever.is_ready:
            # Build a query from the flow characteristics
            query_parts: list[str] = []
            for flow in batch:
                proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
                proto = proto_names.get(flow.key.protocol, "unknown")
                query_parts.append(
                    f"{proto} traffic "
                    f"packets={flow.packet_count} "
                    f"bytes={flow.byte_count}"
                )
            query = " | ".join(query_parts)
            chunks = self._retriever.retrieve(query)
            rag_context = self._retriever.format_context(chunks)

        # Build prompt
        prompt = self._prompt_builder.build(batch, rag_context=rag_context)

        # Query Ollama
        raw_response = await self._query_ollama(prompt)
        if raw_response is None:
            self._total_errors += 1
            return

        # Parse response
        result: ParseResult = self._parser.parse(raw_response)

        if not result.success:
            logger.warning(
                "LLM parse failure (batch %d): %s",
                self._total_batches,
                result.error,
            )
            self._total_errors += 1
            return

        if not result.alerts:
            logger.debug(
                "LLM batch %d: no alerts (all flows benign)",
                self._total_batches,
            )
            return

        # Convert LLM alerts to detection Alert objects
        alerts: list[Alert] = []
        for llm_alert in result.alerts:
            from core.capture.flow_assembler import FlowKey  # noqa: PLC0415

            alert = Alert(
                flow_key=FlowKey(
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    src_port=0,
                    dst_port=0,
                    protocol=0,
                ),
                signature_id=f"llm_{llm_alert.threat_type}",
                signature_name=f"LLM: {llm_alert.threat_type}",
                threat_type=llm_alert.threat_type,
                severity=llm_alert.severity,
                confidence=llm_alert.confidence,
                description=llm_alert.reasoning,
                timestamp=time.time(),
                mitre_technique=llm_alert.mitre_technique,
            )
            alerts.append(alert)

        self._total_alerts += len(alerts)
        logger.info(
            "LLM batch %d: %d alert(s) generated",
            self._total_batches,
            len(alerts),
        )

        # Deliver alerts via callback
        if self._on_alerts and alerts:
            try:
                self._on_alerts(alerts)
            except Exception as exc:
                logger.error("Alert callback failed: %s", exc)

    # ------------------------------------------------------------------
    # Ollama HTTP client
    # ------------------------------------------------------------------

    async def _check_ollama(self) -> bool:
        """Probe Ollama's API to verify connectivity.

        Returns:
            ``True`` if Ollama responded to a health check.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._ollama_url}/api/tags")
                return resp.status_code == 200
        except Exception as exc:
            logger.debug("Ollama connectivity check failed: %s", exc)
            return False

    async def _query_ollama(self, prompt: str) -> str | None:
        """Send a prompt to Ollama and return the response text.

        Args:
            prompt: The full prompt string from ``PromptBuilder``.

        Returns:
            The response text, or ``None`` on failure.

        Security note:
            Uses a 120-second timeout.  The ``stream=False`` parameter
            ensures we receive the complete response atomically rather
            than streaming partial JSON that could fail mid-parse.
        """
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 2048,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self._ollama_url}/api/generate",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")
        except httpx.TimeoutException:
            logger.warning(
                "Ollama request timed out after 120s (model=%s)",
                self._model,
            )
            return None
        except Exception as exc:
            logger.warning("Ollama request failed: %s", exc)
            return None
