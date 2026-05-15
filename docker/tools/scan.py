"""
Scan de ports et détection de services via nmap (python-nmap).

Expose :
  scan_host()      — scan d'un hôte unique (utilisé en parallèle depuis main.py)
  get_os()         — extraction du meilleur match OS depuis les données nmap
  _get_portscanner() — instance nmap.PortScanner (utilisée aussi par discover.py)
"""
import logging
import os
import pathlib
import shutil
import time

import nmap
from config import FALLBACK_PROFILE, SCAN_PROFILES

log = logging.getLogger(__name__)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()

_NMAP_PATH = tuple(filter(None, [
    os.environ.get("NMAP_PATH"),
    shutil.which("nmap"),
    str(SCRIPT_DIR / "nmap" / "nmap"),
]))


def _get_portscanner() -> nmap.PortScanner:
    """Retourne un PortScanner configuré avec le chemin nmap résolu."""
    return nmap.PortScanner(nmap_search_path=_NMAP_PATH)


def _scan_args(profile: str, arguments: str | None) -> str:
    return arguments or SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["arguments"]


def scan_host(
    ip: str,
    ports: str,
    profile: str = "full",
    arguments: str | None = None,
) -> object | None:
    """
    Scanne un hôte et retourne son HostDict nmap, ou None si inaccessible.

    Stratégie :
      1. Scan principal avec le profil demandé.
      2. Si aucun résultat (hôte absent de all_hosts), retry avec le profil quick
         pour récupérer au moins les ports ouverts (évite de perdre des hôtes
         dont nmap timeout sur les scripts vuln mais qui ont des ports ouverts).

    Args:
        ip:        Adresse IP cible.
        ports:     Ports à scanner (format nmap : "22,80,443" ou "1-1024").
        profile:   Profil de scan ("quick" ou "full").
        arguments: Arguments nmap personnalisés (remplace le profil si fourni).
    """
    nm = _get_portscanner()
    args = _scan_args(profile, arguments)
    t0 = time.monotonic()
    try:
        nm.scan(ip, ports, arguments=args)
    except Exception as e:
        log.error("Scan échoué pour %s : %s", ip, e)
        return None
    elapsed = time.monotonic() - t0
    log.debug("Scan '%s' terminé pour %s en %.1fs", profile, ip, elapsed)
    if ip in nm.all_hosts():
        try:
            open_count = sum(
                1 for proto in nm[ip].all_protocols()
                for port in nm[ip][proto]
                if nm[ip][proto][port].get("state") == "open"
            )
        except Exception:
            open_count = 0
        log.info("%-16s  profil=%-8s  durée=%5.1fs  ports_ouverts=%d", ip, profile, elapsed, open_count)
        return nm[ip]

    # Retry avec le profil fallback (quick) si le scan principal n'a rien renvoyé.
    # Utile pour les profils lents (full, stealth, udp) où l'hôte peut être présent
    # mais timeout sur les scripts ou les sockets UDP.
    # Désactivable via RECONENGINE_FALLBACK_DISABLED=1.
    if os.environ.get("RECONENGINE_FALLBACK_DISABLED", "0") != "1" and profile != FALLBACK_PROFILE and not arguments:
        log.warning(
            "Scan '%s' sans résultat pour %s — retry profil '%s' (ports ouverts seulement)",
            profile, ip, FALLBACK_PROFILE,
        )
        nm2 = _get_portscanner()
        try:
            nm2.scan(ip, ports, arguments=SCAN_PROFILES[FALLBACK_PROFILE]["arguments"])
        except Exception as e:
            log.error("Retry scan échoué pour %s : %s", ip, e)
            return None
        return nm2[ip] if ip in nm2.all_hosts() else None

    return None


def get_os(data) -> str:
    """
    Extrait le meilleur match OS depuis les données nmap.
    Retourne une chaîne vide si la détection OS n'était pas activée ou a échoué.
    """
    try:
        matches = data.get("osmatch") or []
        if matches:
            best = matches[0]
            name = best.get("name", "")
            acc  = best.get("accuracy", "?")
            return f"{name} ({acc}%)" if name else ""
    except Exception:
        pass
    return ""
