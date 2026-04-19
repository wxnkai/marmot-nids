"""
core.api.routes.alerts
=======================
Alert retrieval and management endpoints.

Security relevance:
    Alert data contains IP addresses, threat types, and detection
    metadata.  While not PII in the traditional sense, IP addresses
    can be sensitive in some jurisdictions.  All alert endpoints
    should be behind authentication in production deployments.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AlertResponse(BaseModel):
    """Serialised alert for API responses.

    All fields are JSON-safe types.  ``timestamp`` is a float (Unix epoch)
    rather than a datetime to avoid timezone confusion.
    """

    signature_id: str
    signature_name: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    timestamp: float
    mitre_technique: str | None = None
    flow_key: str | None = None


class AlertListResponse(BaseModel):
    """Paginated alert list response."""

    total: int
    offset: int
    limit: int
    alerts: list[AlertResponse]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/alerts", summary="List alerts", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=200, description="Page size"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    threat_type: str | None = Query(default=None, description="Filter by threat type"),
) -> AlertListResponse:
    """Return a paginated list of detection alerts.

    Supports filtering by ``severity`` and ``threat_type``.  Results
    are ordered by timestamp (newest first).

    Security note:
        Pagination limits (max 200 per page) prevent memory exhaustion
        from overly broad queries.
    """
    all_alerts: list[dict] = getattr(request.app.state, "alerts", [])

    # Filter
    filtered = all_alerts
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity.lower()]
    if threat_type:
        filtered = [a for a in filtered if a.get("threat_type") == threat_type]

    # Sort by timestamp descending
    filtered.sort(key=lambda a: a.get("timestamp", 0), reverse=True)

    # Paginate
    total = len(filtered)
    page = filtered[offset : offset + limit]

    return AlertListResponse(
        total=total,
        offset=offset,
        limit=limit,
        alerts=[AlertResponse(**a) for a in page],
    )


@router.get(
    "/alerts/{alert_index}",
    summary="Get alert by index",
    response_model=AlertResponse,
)
async def get_alert(request: Request, alert_index: int) -> AlertResponse:
    """Retrieve a single alert by its index.

    Raises:
        HTTPException(404): If the index is out of range.
    """
    all_alerts: list[dict] = getattr(request.app.state, "alerts", [])

    if alert_index < 0 or alert_index >= len(all_alerts):
        raise HTTPException(status_code=404, detail="Alert not found")

    return AlertResponse(**all_alerts[alert_index])


@router.get("/alerts/stats/summary", summary="Alert statistics")
async def alert_stats(request: Request) -> dict:
    """Return summary statistics about alerts.

    Includes total count, breakdown by severity, and breakdown by
    threat type.
    """
    all_alerts: list[dict] = getattr(request.app.state, "alerts", [])

    by_severity: dict[str, int] = {}
    by_threat: dict[str, int] = {}

    for alert in all_alerts:
        sev = alert.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        threat = alert.get("threat_type", "unknown")
        by_threat[threat] = by_threat.get(threat, 0) + 1

    return {
        "total": len(all_alerts),
        "by_severity": by_severity,
        "by_threat_type": by_threat,
    }
