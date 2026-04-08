"""
Tests for rapport.py — classification, scoring, and host-type logic.
No network, no nmap, no WeasyPrint rendering.
"""


# ── _classify ──────────────────────────────────────────────────────────────────

def test_classify_critical_port_open():
    from rapport import CRITICAL_PORTS, _classify
    port = next(iter(CRITICAL_PORTS))  # pick any critical port
    pinfo = {"state": "open", "name": "ftp"}
    sev_class, sev_text = _classify(port, pinfo, [], None)
    assert sev_class == "high"
    assert sev_text == "ELEVE"


def test_classify_exploit_no_cvss_is_critical():
    """A service with a known exploit but no CVSS score → critical (exploitability proven)."""
    from rapport import _classify
    pinfo = {"state": "open", "name": "http"}
    fake_exploit = [{"Title": "Apache RCE", "Path": "/some/path"}]
    sev_class, sev_text = _classify(80, pinfo, fake_exploit, None)
    assert sev_class == "critical"
    assert sev_text == "CRITIQUE"


def test_classify_cvss_overrides_heuristic():
    """A CVSS score should override port-based heuristics."""
    from rapport import _classify
    pinfo = {"state": "open", "name": "ssh"}
    cve_data = {"max_cvss": 9.8, "severity_class": "critical", "severity_text": "CRITIQUE"}
    sev_class, _ = _classify(22, pinfo, [], cve_data)
    assert sev_class == "critical"


def test_classify_low_port_no_exploit_medium():
    """Privileged port (<1024), open, no exploit, no CVE → medium."""
    from rapport import _classify
    pinfo = {"state": "open", "name": "unknown-service"}
    sev_class, sev_text = _classify(999, pinfo, [], None)
    assert sev_class == "medium"
    assert sev_text == "MODERE"


def test_classify_high_port_no_data_low():
    """Non-privileged port (≥1024), no exploit, no CVE, not a critical port → low."""
    from rapport import _classify
    pinfo = {"state": "open", "name": "unknown"}
    sev_class, sev_text = _classify(50000, pinfo, [], None)
    assert sev_class == "low"
    assert sev_text == "FAIBLE"


def test_classify_closed_state_always_low():
    """Closed ports should be low regardless of port number."""
    from rapport import _classify
    pinfo = {"state": "closed", "name": "ms-wbt-server"}
    sev_class, _ = _classify(3389, pinfo, [], None)
    assert sev_class == "low"


def test_classify_filtered_critical_port_high():
    """Filtered critical port → high (still a risk)."""
    from rapport import _classify
    pinfo = {"state": "filtered", "name": "ftp"}
    sev_class, _ = _classify(21, pinfo, [], None)
    assert sev_class == "high"


def test_classify_exploit_with_medium_cvss_stays_high():
    """If CVSS is medium but there's an exploit, severity must be at least high."""
    from rapport import _classify
    pinfo = {"state": "open", "name": "http"}
    cve_data = {"max_cvss": 5.5, "severity_class": "medium", "severity_text": "MODERE"}
    fake_exploit = [{"Title": "Some exploit"}]
    sev_class, _ = _classify(80, pinfo, fake_exploit, cve_data)
    assert sev_class == "high"


# ── _risk_from_counts ──────────────────────────────────────────────────────────

def test_risk_no_vulns_is_faible():
    from rapport import _risk_from_counts
    score, level = _risk_from_counts({"critical": 0, "high": 0, "medium": 0, "low": 0})
    assert score == 0.0
    assert level == "FAIBLE"


def test_risk_all_critical_is_100():
    from rapport import _risk_from_counts
    score, level = _risk_from_counts({"critical": 5, "high": 0, "medium": 0, "low": 0})
    assert score == 100.0
    assert level == "CRITIQUE"


def test_risk_mixed_is_moderate():
    from rapport import _risk_from_counts
    score, level = _risk_from_counts({"critical": 0, "high": 0, "medium": 3, "low": 2})
    assert level in ("MODERE", "FAIBLE")


def test_risk_score_capped_at_100():
    from rapport import _risk_from_counts
    score, _ = _risk_from_counts({"critical": 100, "high": 100, "medium": 100, "low": 100})
    assert score <= 100.0


# ── _classify_host_type ────────────────────────────────────────────────────────

def test_host_type_linux_server():
    from rapport import _classify_host_type
    assert _classify_host_type("Ubuntu Server 22.04", set()) == "server"


def test_host_type_windows_workstation():
    from rapport import _classify_host_type
    assert _classify_host_type("Windows 10", set()) == "workstation"


def test_host_type_macos_workstation():
    from rapport import _classify_host_type
    result = _classify_host_type("Apple macOS 13 Ventura", set())
    assert result == "workstation"


def test_host_type_server_by_ports():
    """If OS is unknown but 2+ server-indicator ports are open → server."""
    from rapport import _classify_host_type
    # 80 (http) and 443 (https) are both in _SERVER_INDICATOR_PORTS
    assert _classify_host_type("Unknown OS", {80, 443}) == "server"


def test_host_type_unknown():
    from rapport import _classify_host_type
    # SSH only — not enough evidence to classify as server
    assert _classify_host_type("Unknown", {22}) == "unknown"


# ── _format_service ────────────────────────────────────────────────────────────

def test_format_service_product_and_version():
    from rapport import _format_service
    pinfo = {"product": "OpenSSH", "version": "8.2p1", "name": "ssh"}
    assert _format_service(pinfo) == "OpenSSH 8.2p1"


def test_format_service_name_fallback():
    from rapport import _format_service
    pinfo = {"product": "", "version": "", "name": "http"}
    assert _format_service(pinfo) == "http"


def test_format_service_empty_is_inconnu():
    from rapport import _format_service
    pinfo = {"product": "", "version": "", "name": ""}
    assert _format_service(pinfo) == "inconnu"


# ── _port_count (main.py) ──────────────────────────────────────────────────────

def test_port_count_single():
    from main import _port_count
    assert _port_count("80") == 1


def test_port_count_comma_separated():
    from main import _port_count
    assert _port_count("22,80,443") == 3


def test_port_count_range():
    from main import _port_count
    assert _port_count("1-1024") == 1024


def test_port_count_mixed():
    from main import _port_count
    assert _port_count("22,80,1000-1010") == 13  # 2 + 11


def test_port_count_empty_returns_one():
    from main import _port_count
    assert _port_count("") == 1
