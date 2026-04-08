"""
Tests for config.py — Config.load(), validation helpers, env var overrides.
"""
import pytest


def test_default_config():
    from config import Config
    cfg = Config()
    assert cfg.scan.profile == "full"
    assert cfg.scan.max_workers == 8
    assert cfg.scan.discovery_timeout == 5
    assert cfg.output_dir == "rapports"
    assert cfg.scan.ports  # non-empty default port list


def test_env_profile_override(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PROFILE", "quick")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.profile == "quick"


def test_env_profile_case_insensitive(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PROFILE", "FULL")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.profile == "full"


def test_env_ports_override(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PORTS", "22,80,443")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.ports == "22,80,443"


def test_env_ports_range_valid(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PORTS", "1-1024")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.ports == "1-1024"


def test_env_ports_invalid_raises_systemexit(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PORTS", "not_a_port")
    from config import Config
    with pytest.raises(SystemExit):
        Config.load()


def test_env_profile_invalid_raises_systemexit(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PROFILE", "turbo")
    from config import Config
    with pytest.raises(SystemExit):
        Config.load()


def test_env_max_workers_override(monkeypatch):
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "4")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.max_workers == 4


def test_env_output_dir_override(monkeypatch):
    monkeypatch.setenv("RECONENGINE_OUTPUT_DIR", "/tmp/reports")
    from config import Config
    cfg = Config.load()
    assert cfg.output_dir == "/tmp/reports"


def test_env_invalid_max_workers_silently_ignored(monkeypatch):
    """Non-integer RECONENGINE_MAX_WORKERS should not crash — default unchanged."""
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "not_a_number")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.max_workers == 8


def test_default_ports_include_critical():
    from config import DEFAULT_PORTS
    ports = set(map(int, DEFAULT_PORTS.split(",")))
    for critical in (22, 80, 443, 445, 3389, 3306, 5432):
        assert critical in ports, f"Port {critical} missing from DEFAULT_PORTS"


def test_scan_profiles_have_required_keys():
    from config import SCAN_PROFILES
    for name, profile in SCAN_PROFILES.items():
        assert "description" in profile, f"{name} missing 'description'"
        assert "arguments" in profile, f"{name} missing 'arguments'"
        assert "-Pn" in profile["arguments"], f"{name} should include -Pn"


# ── Validation helpers ─────────────────────────────────────────────────────────

def test_validate_ports_single():
    from config import _validate_ports
    assert _validate_ports("80") == "80"


def test_validate_ports_list():
    from config import _validate_ports
    assert _validate_ports("22,80,443") == "22,80,443"


def test_validate_ports_range():
    from config import _validate_ports
    assert _validate_ports("1-1024") == "1-1024"


def test_validate_ports_empty_returns_default():
    from config import DEFAULT_PORTS, _validate_ports
    assert _validate_ports("") == DEFAULT_PORTS


def test_validate_ports_out_of_range_raises():
    from config import _validate_ports
    with pytest.raises(ValueError, match="hors de la plage"):
        _validate_ports("0")
    with pytest.raises(ValueError, match="hors de la plage"):
        _validate_ports("65536")


def test_validate_ports_invalid_format_raises():
    from config import _validate_ports
    with pytest.raises(ValueError):
        _validate_ports("http")


def test_validate_profile_valid():
    from config import _validate_profile
    assert _validate_profile("quick") == "quick"
    assert _validate_profile("full") == "full"
    assert _validate_profile("FULL") == "full"


def test_validate_profile_invalid_raises():
    from config import _validate_profile
    with pytest.raises(ValueError, match="Profil inconnu"):
        _validate_profile("turbo")


def test_validate_workers_bounds():
    from config import _validate_workers
    assert _validate_workers(1) == 1
    assert _validate_workers(64) == 64
    with pytest.raises(ValueError):
        _validate_workers(0)
    with pytest.raises(ValueError):
        _validate_workers(65)


def test_validate_timeout_bounds():
    from config import _validate_timeout
    assert _validate_timeout(1) == 1
    assert _validate_timeout(300) == 300
    with pytest.raises(ValueError):
        _validate_timeout(0)
    with pytest.raises(ValueError):
        _validate_timeout(301)
