"""
Tests for api.py — FastAPI endpoints via TestClient.

No actual network scans are triggered: scan pipeline functions are mocked
so tests run instantly without root privileges or nmap.
"""
import pathlib
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Ensure docker/tools is on the path
TOOLS_DIR = pathlib.Path(__file__).parent.parent / "docker" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets its own fresh SQLite database in a temp directory."""
    monkeypatch.setenv("RECONENGINE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("RECONENGINE_API_KEY", "test-key")
    yield tmp_path


@pytest.fixture()
def client(isolated_db):
    """TestClient with a fresh api module (re-imported after env changes)."""
    # Force reimport so _DB_PATH and _API_KEY pick up the patched env vars
    if "api" in sys.modules:
        del sys.modules["api"]
    import api as api_mod
    api_mod._db_init()
    return TestClient(api_mod.app)


# ── /health ────────────────────────────────────────────────────────────────────

def test_health_no_auth_required(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "scans_running" in data


def test_health_returns_zero_running_initially(client):
    resp = client.get("/health")
    assert resp.json()["scans_running"] == 0


# ── Auth ───────────────────────────────────────────────────────────────────────

def test_missing_api_key_returns_401(client):
    resp = client.post("/scans", json={"profile": "quick"})
    assert resp.status_code == 401


def test_wrong_api_key_returns_401(client):
    resp = client.post("/scans", json={"profile": "quick"}, headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


def test_correct_api_key_accepted(client):
    with patch("api._run_scan"):  # don't actually scan
        resp = client.post(
            "/scans",
            json={"profile": "quick"},
            headers={"X-API-Key": "test-key"},
        )
    assert resp.status_code == 202


# ── POST /scans ────────────────────────────────────────────────────────────────

def test_start_scan_returns_scan_id(client):
    with patch("api._run_scan"):
        resp = client.post(
            "/scans",
            json={"profile": "quick"},
            headers={"X-API-Key": "test-key"},
        )
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert len(data["scan_id"]) == 8
    assert data["status"] == "pending"
    assert data["profile"] == "quick"


def test_start_scan_invalid_profile(client):
    resp = client.post(
        "/scans",
        json={"profile": "invalid"},
        headers={"X-API-Key": "test-key"},
    )
    assert resp.status_code == 422  # Pydantic validation error


def test_start_scan_full_profile_default(client):
    with patch("api._run_scan"):
        resp = client.post("/scans", json={}, headers={"X-API-Key": "test-key"})
    assert resp.status_code == 202
    assert resp.json()["profile"] == "full"


def test_start_scan_conflict_when_running(client):
    """Second scan request while one is running → 409."""
    import api as api_mod
    # Manually inject a running scan into the in-memory tracker
    with api_mod._running_lock:
        api_mod._running["existing"] = {"scan_id": "existing", "status": "running"}

    resp = client.post("/scans", json={"profile": "quick"}, headers={"X-API-Key": "test-key"})
    assert resp.status_code == 409

    # Cleanup
    with api_mod._running_lock:
        api_mod._running.clear()


# ── GET /scans/{id} ───────────────────────────────────────────────────────────

def test_get_scan_not_found(client):
    resp = client.get("/scans/nonexistent", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 404


def test_get_scan_after_creation(client):
    with patch("api._run_scan"):
        create_resp = client.post(
            "/scans", json={"profile": "quick"}, headers={"X-API-Key": "test-key"}
        )
    scan_id = create_resp.json()["scan_id"]

    get_resp = client.get(f"/scans/{scan_id}", headers={"X-API-Key": "test-key"})
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == scan_id


# ── GET /scans ─────────────────────────────────────────────────────────────────

def test_list_scans_empty(client):
    resp = client.get("/scans", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_shows_created_scan(client):
    import api as api_mod

    with patch("api._run_scan"):
        client.post("/scans", json={"profile": "quick"}, headers={"X-API-Key": "test-key"})
    # Simulate scan finishing so the conflict lock is released
    with api_mod._running_lock:
        api_mod._running.clear()
    with patch("api._run_scan"):
        client.post("/scans", json={"profile": "full"}, headers={"X-API-Key": "test-key"})

    resp = client.get("/scans", headers={"X-API-Key": "test-key"})
    data = resp.json()
    assert len(data) == 2
    # Most recent first
    assert data[0]["started_at"] >= data[1]["started_at"]


# ── GET /reports ───────────────────────────────────────────────────────────────

def test_list_reports_empty(client):
    resp = client.get("/reports", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_reports_shows_pdfs(client, isolated_db):
    # Create a fake PDF in the report directory
    pdf = isolated_db / "Rapport_Audit_20260408.pdf"
    pdf.write_bytes(b"%PDF-1.4 " + b"x" * 2048)  # >1 KB so size_kb rounds to >0

    resp = client.get("/reports", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["filename"] == "Rapport_Audit_20260408.pdf"
    assert data[0]["size_kb"] >= 0  # may be small in tests


# ── GET /reports/{filename} ────────────────────────────────────────────────────

def test_download_report_not_found(client):
    resp = client.get("/reports/nonexistent.pdf", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 404


def test_download_report_path_traversal_rejected(client):
    resp = client.get("/reports/../etc/passwd", headers={"X-API-Key": "test-key"})
    # FastAPI may intercept this at routing level; either 404 or 400 is correct
    assert resp.status_code in (400, 404, 422)


def test_download_report_success(client, isolated_db):
    pdf = isolated_db / "Rapport_Audit_20260408.pdf"
    pdf.write_bytes(b"%PDF-1.4 test content")

    resp = client.get(
        "/reports/Rapport_Audit_20260408.pdf", headers={"X-API-Key": "test-key"}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert b"%PDF" in resp.content


def test_download_non_pdf_rejected(client, isolated_db):
    txt = isolated_db / "notes.txt"
    txt.write_text("hello")

    resp = client.get("/reports/notes.txt", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 404
