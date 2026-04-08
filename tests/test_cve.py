"""
Tests for cve.py — pure logic, no network calls.
"""


# ── cvss_to_severity ───────────────────────────────────────────────────────────

def test_cvss_critical():
    from cve import cvss_to_severity
    assert cvss_to_severity(9.8) == ("critical", "CRITIQUE")
    assert cvss_to_severity(9.0) == ("critical", "CRITIQUE")
    assert cvss_to_severity(10.0) == ("critical", "CRITIQUE")


def test_cvss_high():
    from cve import cvss_to_severity
    assert cvss_to_severity(8.9) == ("high", "ELEVE")
    assert cvss_to_severity(7.0) == ("high", "ELEVE")


def test_cvss_medium():
    from cve import cvss_to_severity
    assert cvss_to_severity(6.9) == ("medium", "MODERE")
    assert cvss_to_severity(4.0) == ("medium", "MODERE")


def test_cvss_low():
    from cve import cvss_to_severity
    assert cvss_to_severity(3.9) == ("low", "FAIBLE")
    assert cvss_to_severity(0.1) == ("low", "FAIBLE")


def test_cvss_zero_is_low():
    from cve import cvss_to_severity
    # 0.0 is below the lowest threshold (0.1) — falls through to default
    assert cvss_to_severity(0.0) == ("low", "FAIBLE")


# ── parse_nmap_scripts ─────────────────────────────────────────────────────────

def test_parse_vulners_format():
    """Standard vulners output: CVE-XXXX-YYYY<tab>score<tab>url"""
    from cve import parse_nmap_scripts
    script_data = {
        "vulners": "CVE-2021-44228\t10.0\thttps://nvd.nist.gov/...\nCVE-2021-45046\t9.0\thttps://...",
    }
    results = parse_nmap_scripts(script_data)
    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2021-44228"
    assert results[0]["cvss"] == 10.0
    assert results[1]["cve_id"] == "CVE-2021-45046"
    assert results[1]["cvss"] == 9.0


def test_parse_deduplicates_same_cve():
    """Same CVE appearing in two scripts → keep the highest score."""
    from cve import parse_nmap_scripts
    script_data = {
        "vulners":  "CVE-2021-44228\t9.8\thttps://...",
        "vuln":     "CVE-2021-44228\t10.0\thttps://...",
    }
    results = parse_nmap_scripts(script_data)
    assert len(results) == 1
    assert results[0]["cvss"] == 10.0


def test_parse_cvss_generic_fallback():
    """Script output with 'CVSS: 7.5' but no CVE IDs."""
    from cve import parse_nmap_scripts
    script_data = {"http-vuln-cve2014-3704": "CVSS: 7.5\nRisk factor: High"}
    results = parse_nmap_scripts(script_data)
    assert len(results) == 1
    assert results[0]["cvss"] == 7.5


def test_parse_risk_factor_fallback():
    """Script output with only 'Risk factor: Critical' — maps to heuristic CVSS."""
    from cve import parse_nmap_scripts
    script_data = {"smb-vuln-ms17-010": "Risk factor: Critical\nSome details here"}
    results = parse_nmap_scripts(script_data)
    assert len(results) == 1
    assert results[0]["cvss"] == 9.5  # RISK_TO_CVSS["critical"]


def test_parse_empty_script_data():
    from cve import parse_nmap_scripts
    assert parse_nmap_scripts({}) == []


def test_parse_skips_empty_outputs():
    from cve import parse_nmap_scripts
    assert parse_nmap_scripts({"script": ""}) == []
    assert parse_nmap_scripts({"script": "   "}) == []


def test_parse_ignores_out_of_range_scores():
    from cve import parse_nmap_scripts
    # Score > 10 should be ignored
    script_data = {"vuln": "CVE-2021-1234\t99.9\thttps://..."}
    assert parse_nmap_scripts(script_data) == []


def test_parse_results_sorted_descending():
    """Results should be sorted by CVSS descending."""
    from cve import parse_nmap_scripts
    script_data = {
        "vulners": (
            "CVE-2020-0001\t4.0\thttps://...\n"
            "CVE-2020-0002\t9.8\thttps://...\n"
            "CVE-2020-0003\t7.5\thttps://..."
        )
    }
    results = parse_nmap_scripts(script_data)
    scores = [r["cvss"] for r in results]
    assert scores == sorted(scores, reverse=True)


# ── _extract_nvd_cvss ──────────────────────────────────────────────────────────

def test_extract_nvd_cvss_v31():
    from cve import _extract_nvd_cvss
    entry = {
        "cve": {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
            }
        }
    }
    assert _extract_nvd_cvss(entry) == 9.8


def test_extract_nvd_cvss_prefers_v31_over_v2():
    from cve import _extract_nvd_cvss
    entry = {
        "cve": {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
                "cvssMetricV2":  [{"cvssData": {"baseScore": 6.8}}],
            }
        }
    }
    assert _extract_nvd_cvss(entry) == 7.5


def test_extract_nvd_cvss_falls_back_to_v2():
    from cve import _extract_nvd_cvss
    entry = {
        "cve": {
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
            }
        }
    }
    assert _extract_nvd_cvss(entry) == 5.0


def test_extract_nvd_cvss_empty_metrics():
    from cve import _extract_nvd_cvss
    assert _extract_nvd_cvss({"cve": {"metrics": {}}}) == 0.0
    assert _extract_nvd_cvss({}) == 0.0
