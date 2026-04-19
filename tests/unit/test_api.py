"""
tests.unit.test_api
====================
Unit tests for Phase 6 — FastAPI backend.

Coverage:
    * Health check endpoint
    * System status endpoint
    * Alert list (pagination, filtering, sorting)
    * Alert detail (valid index, 404 for invalid)
    * Alert statistics
    * App factory and lifespan management

All tests use FastAPI's TestClient — no live server required.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Create a fresh app instance for each test."""
    return create_app()


@pytest.fixture
def client(app):
    """Test client with lifespan context."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def app_with_alerts(app):
    """Pre-populate the app with sample alerts."""
    sample_alerts = [
        {
            "signature_id": "sig_001_syn_flood",
            "signature_name": "SYN Flood",
            "threat_type": "syn_flood",
            "severity": "critical",
            "confidence": 0.95,
            "description": "SYN flood detected.",
            "timestamp": 1700000002.0,
            "mitre_technique": "T1498.001",
            "flow_key": "10.0.0.1:1234 <-> 10.0.0.2:80 TCP",
        },
        {
            "signature_id": "sig_004_null_scan",
            "signature_name": "TCP NULL Scan",
            "threat_type": "null_scan",
            "severity": "medium",
            "confidence": 0.90,
            "description": "NULL scan detected.",
            "timestamp": 1700000001.0,
            "mitre_technique": "T1046",
            "flow_key": "10.0.0.3:4444 <-> 10.0.0.4:22 TCP",
        },
        {
            "signature_id": "sig_007_ssh_brute_force",
            "signature_name": "SSH Brute Force",
            "threat_type": "ssh_brute_force",
            "severity": "high",
            "confidence": 0.85,
            "description": "SSH brute force detected.",
            "timestamp": 1700000003.0,
            "mitre_technique": "T1110.001",
            "flow_key": "10.0.0.5:55000 <-> 10.0.0.6:22 TCP",
        },
    ]
    with TestClient(app) as c:
        app.state.alerts = sample_alerts
        app.state.alert_count = len(sample_alerts)
        yield c


# ---------------------------------------------------------------------------
# TestHealthCheck (2 tests)
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_health_is_get_only(self, client):
        resp = client.post("/api/health")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# TestSystemStatus (3 tests)
# ---------------------------------------------------------------------------


class TestSystemStatus:
    def test_status_returns_version(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "0.1.0"

    def test_status_contains_components(self, client):
        resp = client.get("/api/status")
        data = resp.json()
        assert "components" in data
        assert "signature_engine" in data["components"]

    def test_status_contains_metrics(self, client):
        resp = client.get("/api/status")
        data = resp.json()
        assert "metrics" in data
        assert "total_alerts" in data["metrics"]


# ---------------------------------------------------------------------------
# TestAlertList (6 tests)
# ---------------------------------------------------------------------------


class TestAlertList:
    def test_empty_alert_list(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["alerts"] == []

    def test_alert_list_with_data(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts")
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 3

    def test_alert_list_pagination(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts?offset=0&limit=2")
        data = resp.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 2

    def test_alert_list_offset(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts?offset=2&limit=10")
        data = resp.json()
        assert len(data["alerts"]) == 1

    def test_alert_list_filter_by_severity(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts?severity=critical")
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["severity"] == "critical"

    def test_alert_list_filter_by_threat_type(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts?threat_type=null_scan")
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["threat_type"] == "null_scan"


# ---------------------------------------------------------------------------
# TestAlertDetail (3 tests)
# ---------------------------------------------------------------------------


class TestAlertDetail:
    def test_get_alert_by_index(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts/0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["signature_id"] is not None

    def test_get_alert_invalid_index_returns_404(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts/999")
        assert resp.status_code == 404

    def test_get_alert_negative_index_returns_404(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts/-1")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestAlertStats (3 tests)
# ---------------------------------------------------------------------------


class TestAlertStats:
    def test_stats_empty(self, client):
        resp = client.get("/api/alerts/stats/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_stats_with_data(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts/stats/summary")
        data = resp.json()
        assert data["total"] == 3
        assert "critical" in data["by_severity"]
        assert data["by_severity"]["critical"] == 1

    def test_stats_threat_breakdown(self, app_with_alerts):
        resp = app_with_alerts.get("/api/alerts/stats/summary")
        data = resp.json()
        assert "syn_flood" in data["by_threat_type"]
        assert "null_scan" in data["by_threat_type"]


# ---------------------------------------------------------------------------
# TestAppFactory (3 tests)
# ---------------------------------------------------------------------------


class TestAppFactory:
    def test_create_app_returns_fastapi(self):
        app = create_app()
        from fastapi import FastAPI
        assert isinstance(app, FastAPI)

    def test_app_has_docs_url(self):
        app = create_app()
        assert app.docs_url == "/api/docs"

    def test_app_title(self):
        app = create_app()
        assert app.title == "marmot-nids"
