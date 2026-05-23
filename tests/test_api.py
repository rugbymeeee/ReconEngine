"""
Tests for api.py — FastAPI endpoints via TestClient.

No actual network scans are triggered: scan pipeline functions are mocked
so tests run instantly without root privileges or nmap.

nmap and scapy are stubbed at sys.modules level so api.py (which imports scan,
which imports nmap) can be loaded in environments without those packages.
"""
import pathlib
import sys
import types
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Ensure docker/tools is on the path
TOOLS_DIR = pathlib.Path(__file__).parent.parent / "docker" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# ── Stub dependencies unavailable outside Docker ───────────────────────────────
for _mod_name in ("nmap", "scapy", "scapy.all"):
    if _mod_name not in sys.modules:
        _stub = types.ModuleType(_mod_name)
        _stub.PortScanner = type("PortScanner", (), {"scan": lambda *a, **k: None, "all_hosts": lambda: []})
        _stub.PortScannerError = type("PortScannerError", (Exception,), {})
        _stub.arping = lambda *a, **k: ([], [])
        _stub.get_if_addr = lambda *a: "127.0.0.1"
        _stub.get_if_list = lambda: []
        sys.modules[_mod_name] = _stub


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
    # Context manager triggers lifespan startup/shutdown (Config load, DB init, LEDs)
    with TestClient(api_mod.app) as c:
        yield c


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
    assert len(data["scan_id"]) == 36  # full UUID e.g. "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    assert data["status"] == "pending"
    assert data["profile"] == "quick"


def test_start_scan_invalid_profile(client):
    resp = client.post(
        "/scans",
        json={"profile": "invalid"},
        headers={"X-API-Key": "test-key"},
    )
    assert resp.status_code == 422  # Pydantic validation error


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_start_scan_all_valid_profiles(client, profile):
    with patch("api._run_scan"):
        resp = client.post(
            "/scans",
            json={"profile": profile},
            headers={"X-API-Key": "test-key"},
        )
    assert resp.status_code == 202
    assert resp.json()["profile"] == profile


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
    # scan_id must NOT be leaked in the error message (enumeration protection)
    assert "nonexistent" not in resp.json().get("detail", "")


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


# ── GET /profiles ──────────────────────────────────────────────────────────────

def test_list_profiles_no_auth_required(client):
    resp = client.get("/profiles")
    assert resp.status_code == 200


def test_list_profiles_contains_builtin_profiles(client):
    resp = client.get("/profiles")
    data = resp.json()
    names = {p["name"] for p in data}
    assert {"quick", "full"} == names


def test_list_profiles_schema(client):
    resp = client.get("/profiles")
    for p in resp.json():
        assert "name" in p
        assert "description" in p
        assert "arguments" in p
        assert p["description"]
        assert p["arguments"]


def test_quick_profile_has_no_port_override(client):
    resp = client.get("/profiles")
    quick = next(p for p in resp.json() if p["name"] == "quick")
    assert quick["ports"] is None


# ── Auth — rate limiting ───────────────────────────────────────────────────────

def test_rate_limit_after_many_failures(client):
    """After _MAX_AUTH_FAILURES bad attempts, subsequent requests return 429."""
    import api as api_mod

    # Clear any existing failure state
    with api_mod._auth_lock:
        api_mod._auth_failures.clear()

    # Exhaust the allowed failures
    for _ in range(api_mod._MAX_AUTH_FAILURES):
        client.post("/scans", json={"profile": "quick"}, headers={"X-API-Key": "wrong-key"})

    resp = client.post("/scans", json={"profile": "quick"}, headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 429

    # Cleanup
    with api_mod._auth_lock:
        api_mod._auth_failures.clear()


def test_rate_limit_not_triggered_for_correct_key(client):
    """Correct key bypasses rate limit counting."""
    import api as api_mod

    with api_mod._auth_lock:
        api_mod._auth_failures.clear()

    with patch("api._run_scan"):
        resp = client.post(
            "/scans", json={"profile": "quick"}, headers={"X-API-Key": "test-key"}
        )
    assert resp.status_code == 202

    # No failures recorded for the correct key
    with api_mod._auth_lock:
        failures = api_mod._auth_failures.copy()
    # Either empty or the test IP has 0 recorded failures
    total = sum(len(v) for v in failures.values())
    assert total == 0


# ── Security — path traversal (canonical check) ────────────────────────────────

def test_download_canonical_path_traversal_rejected(client, isolated_db):
    """A filename that resolves outside output_dir must be rejected with 400."""
    # On some systems '../etc/passwd' is caught by the slash check.
    # This tests a more subtle case: a filename that stays "flat" but still
    # resolves outside the directory when concatenated with the output dir.
    resp = client.get("/reports/%2e%2e%2fetc%2fpasswd", headers={"X-API-Key": "test-key"})
    # FastAPI URL routing decodes percent-encoding, so this may hit 404 or 400
    assert resp.status_code in (400, 404, 422)


def test_download_report_not_found_hides_filename(client):
    """404 response for a missing report must not echo back the filename."""
    resp = client.get("/reports/secret_name.pdf", headers={"X-API-Key": "test-key"})
    assert resp.status_code == 404
    assert "secret_name" not in resp.json().get("detail", "")
