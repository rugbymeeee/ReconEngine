"""
Tests for config.py — Config.load() with env var overrides.
"""
import os
import pytest


def test_default_config():
    from config import Config, ScanConfig
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


def test_env_ports_override(monkeypatch):
    monkeypatch.setenv("RECONENGINE_PORTS", "22,80,443")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.ports == "22,80,443"


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


def test_env_invalid_max_workers_ignored(monkeypatch):
    """Non-integer RECONENGINE_MAX_WORKERS should not crash — falls back to default."""
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "not_a_number")
    from config import Config
    cfg = Config.load()
    assert cfg.scan.max_workers == 8  # unchanged


def test_default_ports_include_critical():
    """Default port list must include well-known critical ports."""
    from config import DEFAULT_PORTS
    ports = set(map(int, DEFAULT_PORTS.split(",")))
    for critical in (22, 80, 443, 445, 3389, 3306, 5432):
        assert critical in ports, f"Port {critical} missing from DEFAULT_PORTS"


def test_scan_profiles_have_required_keys():
    from config import SCAN_PROFILES
    for name, profile in SCAN_PROFILES.items():
        assert "description" in profile, f"{name} missing 'description'"
        assert "arguments" in profile, f"{name} missing 'arguments'"
        assert "-Pn" in profile["arguments"], f"{name} should include -Pn (hosts pre-confirmed)"
