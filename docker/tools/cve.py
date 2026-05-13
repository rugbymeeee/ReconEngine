"""
Enrichissement CVE/CVSS pour les services détectés.

Stratégies d'enrichissement (ordre de fiabilité décroissant) :
  1. Scripts nmap vuln/vulners — CVE IDs + scores CVSS extraits du scan lui-même
  2. API NVD (NIST) v2       — CVEs officiels par product+version (nécessite réseau)
  3. Heuristiques             — fallback si aucune source n'est disponible

Utilisation :
    cache: dict = {}
    result = get_cve_data("OpenSSH", "8.2p1", script_data, cache)
    # → {"cve_list": [...], "max_cvss": 9.8, "severity_class": "critical", ...}
"""
import contextlib
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

# ── Seuils CVSS — importés depuis config (source de vérité unique) ─────────────
from config import CVSS_THRESHOLDS  # noqa: E402

# ── NVD API ────────────────────────────────────────────────────────────────────
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
# Sans clé : 5 req/30s → 1 toutes les 6s. Avec clé : 50 req/30s → 0.6s.
_NVD_MIN_INTERVAL: float = 0.65 if _NVD_API_KEY else 6.2
_last_nvd_call: float = 0.0
_nvd_available: bool | None = None  # None = pas encore testé
# Locks protecting shared globals mutated from parallel scan threads
_nvd_available_lock = threading.Lock()
_nvd_throttle_lock  = threading.Lock()
# Lock protecting shared cache dict (read-check-write must be atomic)
_cache_lock = threading.Lock()
# In-flight registry: prevents duplicate NVD fetches for the same keyword
# when multiple threads scan identical services simultaneously.
# {cache_key → threading.Event} — waiting threads block on the event.
_inflight: dict[str, threading.Event] = {}
_inflight_lock = threading.Lock()

# ── Validation des mots-clés NVD ──────────────────────────────────────────────
# Un produit ou une version retourné par nmap peut contenir des caractères
# inattendus (parenthèses, slashes, etc.). On conserve uniquement les caractères
# sûrs pour éviter toute pollution des paramètres d'API ou des logs.
_SAFE_KEYWORD_RE = re.compile(r"[^\w\s.\-/+]")
_MAX_KEYWORD_LEN = 80


def _sanitize_nvd_keyword(s: str) -> str:
    """Nettoie un mot-clé NVD : conserve alphanumérique, espaces et ./-+."""
    return _SAFE_KEYWORD_RE.sub("", s)[:_MAX_KEYWORD_LEN].strip()

# ── Regex de parsing scripts nmap ─────────────────────────────────────────────
# Format vulners : "CVE-XXXX-YYYY<TAB>9.8<TAB>https://..."
_RE_CVE_SCORE = re.compile(
    r"(CVE-\d{4}-\d{4,})\s+([\d]+\.[\d]+)",
    re.IGNORECASE,
)
# Format générique : "CVSS: 7.5" / "CVSSv3: 9.8" / "CVSS Score: 6.5"
_RE_CVSS_GENERIC = re.compile(
    r"CVSS\s*(?:v\d(?:\.\d)?)?\s*(?:Score)?\s*:\s*([\d]+\.[\d]+)",
    re.IGNORECASE,
)
# "Risk factor: High"
_RE_RISK_FACTOR = re.compile(r"Risk\s+factor\s*:\s*(\w+)", re.IGNORECASE)
_RISK_TO_CVSS = {
    "critical": 9.5, "high": 7.5, "medium": 5.5,
    "moderate": 5.5, "low": 2.5, "none": 0.0,
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def cvss_to_severity(score: float) -> tuple[str, str]:
    """Convertit un score CVSS flottant en (class, texte) selon les seuils FIRST."""
    for threshold, cls, text in CVSS_THRESHOLDS:
        if score >= threshold:
            return cls, text
    return "low", "FAIBLE"


def _nvd_is_available() -> bool:
    """Sonde l'API NVD une seule fois et mémorise le résultat (thread-safe)."""
    global _nvd_available
    # Fast path: already determined (no lock needed for read of a bool)
    if _nvd_available is not None:
        return _nvd_available
    with _nvd_available_lock:
        # Double-check inside lock (another thread may have set it while we waited)
        if _nvd_available is not None:
            return _nvd_available
        try:
            req = urllib.request.Request(
                f"{_NVD_BASE}?resultsPerPage=1&keywordSearch=test",
                headers={"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {},
            )
            with urllib.request.urlopen(req, timeout=6):
                pass
            _nvd_available = True
            log.info(
                "NVD API disponible%s — enrichissement CVSS activé.",
                " (clé API fournie)" if _NVD_API_KEY else " (sans clé, débit limité)",
            )
        except Exception as e:
            _nvd_available = False
            log.info("NVD API inaccessible (%s) — CVSS depuis scripts nmap uniquement.", e)
    return _nvd_available


def _nvd_throttle() -> None:
    """Attend le minimum requis entre deux appels NVD (thread-safe)."""
    global _last_nvd_call
    with _nvd_throttle_lock:
        elapsed = time.monotonic() - _last_nvd_call
        if elapsed < _NVD_MIN_INTERVAL:
            time.sleep(_NVD_MIN_INTERVAL - elapsed)
        _last_nvd_call = time.monotonic()


# ── Parsing scripts nmap ───────────────────────────────────────────────────────

def parse_nmap_scripts(script_data: dict) -> list[dict]:
    """
    Extrait CVE IDs et scores CVSS depuis le dict de scripts nmap.

    Le dict ``script_data`` est ``pinfo.get('script', {})``, soit
    ``{script_name: output_string}`` tel que retourné par python-nmap.

    Retourne une liste de dicts triée par CVSS décroissant :
      {"cve_id": str, "cvss": float, "source": "nmap:<script>"}
    """
    findings: dict[str, float] = {}  # cve_id → CVSS max

    for script_name, output in script_data.items():
        if not isinstance(output, str) or not output.strip():
            continue

        # Format vulners / scripts structurés : CVE-XXXX-YYYY  9.8
        matched_cves = False
        for m in _RE_CVE_SCORE.finditer(output):
            cve_id = m.group(1).upper()
            try:
                score = float(m.group(2))
            except ValueError:
                continue
            if 0.1 <= score <= 10.0:
                findings[cve_id] = max(findings.get(cve_id, 0.0), score)
                matched_cves = True

        if matched_cves:
            continue  # Format précis trouvé, pas besoin des regex génériques

        # Fallback : CVSS Score générique ou Risk factor → synthétique
        score_found = 0.0
        m_cvss = _RE_CVSS_GENERIC.search(output)
        if m_cvss:
            with contextlib.suppress(ValueError):
                score_found = float(m_cvss.group(1))

        if not score_found:
            m_risk = _RE_RISK_FACTOR.search(output)
            if m_risk:
                score_found = _RISK_TO_CVSS.get(m_risk.group(1).lower(), 0.0)

        if 0.1 <= score_found <= 10.0:
            key = f"NMAP-{script_name.upper()}"  # synthetic key for non-CVE script findings
            findings[key] = max(findings.get(key, 0.0), score_found)

    return sorted(
        [{"cve_id": cid, "cvss": sc, "source": "nmap"} for cid, sc in findings.items()],
        key=lambda x: -x["cvss"],
    )


# ── NVD API v2 ─────────────────────────────────────────────────────────────────

def _extract_nvd_cvss(vuln_entry: dict) -> float:
    """Extrait le meilleur score CVSS d'une entrée NVD (v3.1 > v3.0 > v2)."""
    metrics = vuln_entry.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return 0.0


def _nvd_fetch(keyword: str) -> list[dict]:
    """Appelle l'API NVD et retourne la liste brute de vulnérabilités."""
    _nvd_throttle()
    params = urllib.parse.urlencode({
        "keywordSearch":  keyword,
        "resultsPerPage": 15,
        "noRejected":     "",
    })
    headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}
    req = urllib.request.Request(f"{_NVD_BASE}?{params}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode()).get("vulnerabilities", [])
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        log.debug("NVD fetch failed pour '%s' : %s", keyword, e)
        return []


def _process_nvd_raw(raw: list) -> list[dict]:
    """
    Convertit les entrées brutes de l'API NVD en dicts ``{cve_id, cvss, description, source}``.
    Filtre les entrées sans CVE ID ou avec CVSS nul. Trie par CVSS décroissant.
    """
    results: list[dict] = []
    for entry in raw:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        score = _extract_nvd_cvss(entry)
        if score < 0.1:
            continue
        desc_list = cve.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
        results.append({
            "cve_id":      cve_id,
            "cvss":        score,
            "description": desc[:220],
            "source":      "nvd",
        })
    results.sort(key=lambda x: -x["cvss"])
    return results


def query_nvd(product: str, version: str, cache: dict) -> list[dict]:
    """
    Interroge l'API NVD pour ``product version`` et retourne les CVEs pertinents.

    Deux passes :
      1. product + version (précise)
      2. product seul si la passe 1 retourne moins de 3 résultats

    Le cache stocke TOUJOURS des résultats traités (list[dict] avec clé ``cve_id``),
    jamais des données brutes NVD — évite les KeyError 'cve_id' lors de la fusion.

    Thread-safe : toutes les lectures/écritures du cache sont protégées par _cache_lock.
    Les mots-clés product/version sont sanitizés avant envoi à l'API NVD.

    Retourne une liste triée par CVSS décroissant :
      {"cve_id": str, "cvss": float, "description": str, "source": "nvd"}
    """
    if not product:
        return []

    # Sanitize pour éviter toute injection de paramètres ou pollution des logs
    product_clean  = _sanitize_nvd_keyword(product)
    version_clean  = _sanitize_nvd_keyword(version) if version else ""
    if not product_clean:
        return []

    keyword_full = f"{product_clean} {version_clean}".strip() if version_clean else product_clean
    cache_key = f"nvd:{keyword_full.lower()}"

    # Lecture atomique du cache (évite TOCTOU entre threads parallèles)
    with _cache_lock:
        if cache_key in cache:
            return cache[cache_key]

    if not _nvd_is_available():
        with _cache_lock:
            cache[cache_key] = []
        return []

    # Appel réseau hors du lock (opération lente — ne pas bloquer les autres threads)
    results = _process_nvd_raw(_nvd_fetch(keyword_full))

    # Si version précise mais peu de résultats, compléter avec product seul
    if version_clean and len(results) < 3:
        cache_key_base = f"nvd:{product_clean.lower()}"

        with _cache_lock:
            base_cached = cache.get(cache_key_base)

        if base_cached is None:
            # Appel réseau hors du lock
            base_results = _process_nvd_raw(_nvd_fetch(product_clean))
            with _cache_lock:
                # Double-check : un autre thread a peut-être écrit entre-temps
                if cache_key_base not in cache:
                    cache[cache_key_base] = base_results
                base_cached = cache[cache_key_base]

        # Fusionner en déduplicant par cve_id
        seen_ids = {e["cve_id"] for e in results}
        for item in base_cached:
            if item["cve_id"] not in seen_ids:
                results.append(item)
        results.sort(key=lambda x: -x["cvss"])

    with _cache_lock:
        cache[cache_key] = results

    if results:
        log.debug(
            "NVD '%s' → %d CVE(s), max CVSS %.1f (%s)",
            keyword_full, len(results), results[0]["cvss"], results[0]["cve_id"],
        )
    return results


# ── API publique ───────────────────────────────────────────────────────────────

def get_cve_data(
    product: str,
    version: str,
    script_data: dict,
    cache: dict,
) -> dict:
    """
    Retourne les CVEs et le score CVSS le plus élevé pour un service donné.

    Hiérarchie des sources :
      1. Scripts nmap (dans les données de scan, toujours gratuit/offline)
      2. API NVD (si réseau disponible et product connu)

    Args:
        product:     Nom du produit nmap (ex: "OpenSSH", "Apache httpd").
        version:     Version nmap (ex: "8.2p1", "2.4.51").
        script_data: Dict {script_name: output} issu de pinfo.get('script', {}).
        cache:       Cache partagé pour éviter les doublons d'appels NVD.

    Returns::

        {
          "cve_list":       list[dict],  # CVEs triés par CVSS, max 5
          "max_cvss":       float,       # score CVSS le plus élevé (0.0 si aucun)
          "severity_class": str,         # "critical" | "high" | "medium" | "low" | ""
          "severity_text":  str,         # "CRITIQUE" | "ELEVE" | ... | ""
          "source":         str,         # "nmap" | "nvd" | "mixed" | "none"
        }
    """
    # Phase 1 : scripts nmap (offline, instantané)
    nmap_cves = parse_nmap_scripts(script_data) if script_data else []
    nmap_max = nmap_cves[0]["cvss"] if nmap_cves else 0.0

    # Phase 2 : NVD — uniquement si on a un nom de produit et que nmap
    # n'a pas déjà trouvé un CVSS critique (≥ 9.0)
    nvd_cves: list = []
    if product and nmap_max < 9.0:
        nvd_cves = query_nvd(product, version, cache)

    # Fusion : NVD d'abord (officiel), nmap en complément
    seen: set = set()
    merged: list = []
    for entry in nvd_cves + nmap_cves:
        cid = entry["cve_id"]
        if cid not in seen:
            seen.add(cid)
            merged.append(entry)

    merged.sort(key=lambda x: -x["cvss"])
    top5 = merged[:5]
    max_cvss = top5[0]["cvss"] if top5 else 0.0

    if max_cvss == 0.0:
        return {
            "cve_list":       [],
            "max_cvss":       0.0,
            "severity_class": "",
            "severity_text":  "",
            "source":         "none",
        }

    sev_class, sev_text = cvss_to_severity(max_cvss)

    # Déterminer la source dominante
    sources = {e["source"] for e in top5}
    if len(sources) > 1:
        source = "mixed"
    elif sources == {"nvd"}:
        source = "nvd"
    else:
        source = "nmap"

    return {
        "cve_list":       top5,
        "max_cvss":       max_cvss,
        "severity_class": sev_class,
        "severity_text":  sev_text,
        "source":         source,
    }
