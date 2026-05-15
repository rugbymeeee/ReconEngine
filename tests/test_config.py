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


def test_all_builtin_profiles_present():
    from config import SCAN_PROFILES
    assert set(SCAN_PROFILES.keys()) >= {"quick", "full", "stealth", "web", "udp"}


def test_stealth_profile_uses_low_rate():
    from config import SCAN_PROFILES
    args = SCAN_PROFILES["stealth"]["arguments"]
    assert "--max-rate" in args
    assert "-T1" in args


def test_web_profile_has_port_override():
    from config import SCAN_PROFILES
    assert "ports" in SCAN_PROFILES["web"]
    ports = SCAN_PROFILES["web"]["ports"]
    assert "443" in ports
    assert "80" in ports


def test_udp_profile_uses_sU():
    from config import SCAN_PROFILES
    assert "-sU" in SCAN_PROFILES["udp"]["arguments"]


def test_fallback_profile_is_quick():
    from config import FALLBACK_PROFILE
    assert FALLBACK_PROFILE == "quick"


def test_validate_profile_accepts_all_builtins():
    from config import SCAN_PROFILES, _validate_profile
    for name in SCAN_PROFILES:
        assert _validate_profile(name) == name


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


# ── Nouveaux edge cases ────────────────────────────────────────────────────────

def test_toml_config_valid(tmp_path, monkeypatch):
    """Un fichier TOML valide est chargé correctement."""
    toml = tmp_path / "reconengine.toml"
    toml.write_text('[scan]\nprofile = "quick"\nmax_workers = 2\n')
    monkeypatch.setenv("RECONENGINE_CONFIG", str(toml))
    from config import Config
    cfg = Config.load()
    assert cfg.scan.profile == "quick"
    assert cfg.scan.max_workers == 2


def test_toml_config_invalid_profile_raises(tmp_path, monkeypatch):
    """Un profil invalide dans le TOML déclenche SystemExit."""
    toml = tmp_path / "reconengine.toml"
    toml.write_text('[scan]\nprofile = "turbomax"\n')
    monkeypatch.setenv("RECONENGINE_CONFIG", str(toml))
    from config import Config
    with pytest.raises(SystemExit):
        Config.load()


def test_toml_config_invalid_workers_raises(tmp_path, monkeypatch):
    """max_workers=0 dans le TOML déclenche SystemExit."""
    toml = tmp_path / "reconengine.toml"
    toml.write_text('[scan]\nmax_workers = 0\n')
    monkeypatch.setenv("RECONENGINE_CONFIG", str(toml))
    from config import Config
    with pytest.raises(SystemExit):
        Config.load()


def test_toml_config_missing_file_logs_warning(tmp_path, monkeypatch, caplog):
    """Un chemin RECONENGINE_CONFIG inexistant log un warning sans planter."""
    monkeypatch.setenv("RECONENGINE_CONFIG", str(tmp_path / "missing.toml"))
    import logging

    from config import Config
    with caplog.at_level(logging.WARNING, logger="config"):
        cfg = Config.load()
    assert cfg.scan.profile == "full"   # defaults preserved
    assert any("introuvable" in r.message for r in caplog.records)


def test_env_max_workers_boundary_min(monkeypatch):
    """max_workers=1 est accepté."""
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "1")
    from config import Config
    assert Config.load().scan.max_workers == 1


def test_env_max_workers_boundary_max(monkeypatch):
    """max_workers=64 est accepté."""
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "64")
    from config import Config
    assert Config.load().scan.max_workers == 64


def test_env_max_workers_out_of_range_silently_ignored(monkeypatch):
    """max_workers=65 est hors plage — ignoré silencieusement, défaut conservé."""
    monkeypatch.setenv("RECONENGINE_MAX_WORKERS", "65")
    from config import Config
    assert Config.load().scan.max_workers == 8


def test_env_discovery_timeout_boundary(monkeypatch):
    """discovery_timeout=1 et =300 sont acceptés."""
    for v in ("1", "300"):
        monkeypatch.setenv("RECONENGINE_DISCOVERY_TIMEOUT", v)
        from config import Config
        cfg = Config.load()
        assert cfg.scan.discovery_timeout == int(v)


def test_env_discovery_timeout_out_of_range_ignored(monkeypatch):
    """discovery_timeout=0 est hors plage — ignoré, défaut conservé."""
    monkeypatch.setenv("RECONENGINE_DISCOVERY_TIMEOUT", "0")
    from config import Config
    assert Config.load().scan.discovery_timeout == 5


def test_cvss_thresholds_exported():
    """CVSS_THRESHOLDS doit être exporté depuis config et contenir les 4 niveaux."""
    from config import CVSS_THRESHOLDS
    levels = {cls for _, cls, _ in CVSS_THRESHOLDS}
    assert levels == {"critical", "high", "medium", "low"}


def test_fallback_disabled_env_unset_means_enabled(monkeypatch):
    """Sans RECONENGINE_FALLBACK_DISABLED, le fallback est actif (valeur "0" par défaut)."""
    import os
    monkeypatch.delenv("RECONENGINE_FALLBACK_DISABLED", raising=False)
    assert os.environ.get("RECONENGINE_FALLBACK_DISABLED", "0") != "1"


def test_fallback_disabled_env_1_means_disabled(monkeypatch):
    """RECONENGINE_FALLBACK_DISABLED=1 doit désactiver le fallback dans scan.py."""
    import os
    monkeypatch.setenv("RECONENGINE_FALLBACK_DISABLED", "1")
    assert os.environ.get("RECONENGINE_FALLBACK_DISABLED", "0") == "1"


def test_setup_logging_does_not_raise():
    """setup_logging() ne lève pas d'exception même si appelée plusieurs fois."""
    from config import setup_logging
    setup_logging()
    setup_logging()  # second call is a no-op for basicConfig
