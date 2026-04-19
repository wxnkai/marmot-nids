"""
core.api.routes.status
=======================
System status endpoint — component-level health reporting.

Security note:
    ``/api/status`` reveals internal architecture details (engine names,
    provider types, flow counts).  In production, consider requiring
    authentication for this endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/status", summary="System status")
async def system_status(request: Request) -> dict:
    """Return detailed status of all system components.

    Includes: signature engine state, LLM engine state, blockchain
    provider status, capture state, alert counters, and active flow
    count.

    Security note:
        This endpoint exposes internal state.  In high-security
        environments, place it behind API key authentication.
    """
    state = request.app.state
    engine_status = getattr(state, "engine_status", {})
    alert_count = getattr(state, "alert_count", 0)

    return {
        "version": "0.1.0",
        "components": engine_status,
        "metrics": {
            "total_alerts": alert_count,
        },
    }
