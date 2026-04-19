"""
core.api.routes.health
=======================
Health check endpoint.

Security note:
    The ``/api/health`` endpoint is intentionally unauthenticated so that
    load balancers and monitoring probes can reach it without an API key.
    It returns only ``{\"status\": \"ok\"}`` — no sensitive information.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Health check")
async def health_check() -> dict[str, str]:
    """Return ``{\"status\": \"ok\"}`` if the API process is responsive.

    This endpoint does not verify downstream dependencies (database,
    blockchain, Ollama).  Use ``/api/status`` for a comprehensive
    component-level status report.
    """
    return {"status": "ok"}
