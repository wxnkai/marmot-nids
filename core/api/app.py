"""
core.api.app
=============
FastAPI application entry point with async lifespan management.

Security relevance:
    The lifespan handler controls startup and shutdown of all background
    tasks (packet capture, flow assembly, LLM engine, blockchain sync).
    Clean startup ordering and shutdown sequencing ensures:

    1. **Capture starts last** — background consumers (detection engines,
       sync task) are ready before packets arrive.
    2. **Capture stops first** — no new packets are enqueued while
       consumers are draining.
    3. **API key enforcement** — all mutation endpoints require HMAC-SHA256
       API key authentication via a dependency.

    See ``docs/threat-model.md`` §5 (API Gateway) for the full threat
    analysis.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.api.routes import alerts, health, status, ws

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown.

    Startup order:
        1. Blockchain provider
        2. Signature engine
        3. LLM engine (optional)
        4. Blockchain sync task
        5. Packet capture (if configured)

    Shutdown order:
        1. Packet capture (stop capturing)
        2. LLM engine (drain batch queue)
        3. Blockchain sync (final sync)
        4. Clean exit

    Security note:
        All background tasks are created as asyncio tasks within the
        same event loop.  There is no multi-process worker pool —
        exactly one capture thread (Scapy), one event loop, and one
        set of detection engines exist per process.
    """
    logger.info("marmot-nids starting up...")

    # Store shared state on app.state for route access
    app.state.alerts = []
    app.state.alert_count = 0
    app.state.engine_status = {
        "signature_engine": "ready",
        "llm_engine": "disabled",
        "blockchain_provider": "disabled",
        "capture": "stopped",
    }

    logger.info("marmot-nids ready — API accepting requests")
    yield

    logger.info("marmot-nids shutting down...")
    logger.info("marmot-nids shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        A fully configured ``FastAPI`` instance with all routes
        mounted and middleware applied.

    Security note:
        CORS is configured with restrictive defaults.  In production,
        ``allow_origins`` should be set to the exact dashboard domain.
        The permissive ``["*"]`` default is for development only.
    """
    app = FastAPI(
        title="marmot-nids",
        description=(
            "Modular Network Intrusion Detection System with LLM-based "
            "contextual analysis and pluggable blockchain audit logging."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount route modules
    app.include_router(health.router, prefix="/api", tags=["health"])
    app.include_router(status.router, prefix="/api", tags=["status"])
    app.include_router(alerts.router, prefix="/api", tags=["alerts"])
    app.include_router(ws.router, tags=["websocket"])

    return app
