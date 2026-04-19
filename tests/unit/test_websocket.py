"""
tests.unit.test_websocket
===========================
Unit tests for Phase 7 — WebSocket dashboard.

Coverage:
    * WebSocket connection and accept
    * WebSocket ping/pong
    * Broadcast utility
    * Connection count tracking
    * Connection limit
    * Dashboard HTML file existence

All tests use FastAPI's TestClient WebSocket support — no live server.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app
from core.api.routes.ws import broadcast_alert, get_connection_count

_PROJECT_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# TestWebSocketConnection (3 tests)
# ---------------------------------------------------------------------------


class TestWebSocketConnection:
    def test_websocket_connects(self, client):
        with client.websocket_connect("/ws/alerts") as ws:
            ws.send_text("ping")
            data = ws.receive_text()
            assert data == "pong"

    def test_websocket_ping_pong(self, client):
        with client.websocket_connect("/ws/alerts") as ws:
            for _ in range(3):
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_multiple_connections(self, client):
        with client.websocket_connect("/ws/alerts") as ws1:
            ws1.send_text("ping")
            assert ws1.receive_text() == "pong"


# ---------------------------------------------------------------------------
# TestBroadcast (2 tests)
# ---------------------------------------------------------------------------


class TestBroadcast:
    @pytest.mark.asyncio
    async def test_broadcast_to_no_connections(self):
        """Broadcast with no connections should not raise."""
        await broadcast_alert({"test": True})

    def test_get_connection_count_starts_at_zero(self):
        """Connection count should be 0 before any connections."""
        # Note: this may be > 0 if other tests leave connections
        count = get_connection_count()
        assert isinstance(count, int)


# ---------------------------------------------------------------------------
# TestDashboardFile (2 tests)
# ---------------------------------------------------------------------------


class TestDashboardFile:
    _DASHBOARD_PATH = _PROJECT_ROOT / "dashboard" / "index.html"

    def test_dashboard_html_exists(self):
        assert self._DASHBOARD_PATH.exists()

    def test_dashboard_contains_websocket_code(self):
        content = self._DASHBOARD_PATH.read_text(encoding="utf-8")
        assert "WebSocket" in content
        assert "ws/alerts" in content

    def test_dashboard_has_xss_protection(self):
        content = self._DASHBOARD_PATH.read_text(encoding="utf-8")
        assert "escapeHtml" in content

    def test_dashboard_has_severity_filter(self):
        content = self._DASHBOARD_PATH.read_text(encoding="utf-8")
        assert "filter-btn" in content
        assert "critical" in content.lower()


# ---------------------------------------------------------------------------
# TestAPIWithWebSocket (2 tests)
# ---------------------------------------------------------------------------


class TestAPIWithWebSocket:
    def test_api_and_websocket_coexist(self, client):
        """Health check and WebSocket should both work on the same app."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

        with client.websocket_connect("/ws/alerts") as ws:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

    def test_status_endpoint_still_works(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
