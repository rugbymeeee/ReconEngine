"""
Scan de ports et détection de services via nmap (python-nmap).

Expose :
  scan_host()          — scan d'un hôte unique sur une liste de ports fixe (profil quick)
  scan_host_twophase() — Phase 1 : découverte TCP complète (-p-) puis Phase 2 : service/vuln
                         uniquement sur les ports ouverts détectés (profil full)
  get_os()             — extraction du meilleur match OS depuis les données nmap
  _get_portscanner()   — instance nmap.PortScanner (utilisée aussi par discover.py)
"""
import logging
import os
import pathlib
import shutil

import nmap

from config import SCAN_PROFILES

log = logging.getLogger(__name__)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()

_NMAP_PATH = tuple(filter(None, [
    os.environ.get("NMAP_PATH"),
    shutil.which("nmap"),
    str(SCRIPT_DIR / "nmap" / "nmap"),
]))

_PHASE1_ARGS = "-sS -T4 --min-rate 5000 -p- -Pn --max-retries 1 --open -n"


def _get_portscanner() -> nmap.PortScanner:
    """Retourne un PortScanner configuré avec le chemin nmap résolu."""
    return nmap.PortScanner(nmap_search_path=_NMAP_PATH)


def scan_host(
    ip: str,
    ports: str,
    profile: str = "full",
    arguments: str | None = None,
) -> object | None:
    """
    Scanne un hôte sur une liste de ports fixe et retourne son HostDict nmap.
    Utilisé pour le profil quick ou quand un port set explicite est fourni.
    """
    nm = _get_portscanner()
    args = arguments or SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["arguments"]
    try:
        nm.scan(ip, ports, arguments=args)
    except Exception as e:
        log.error("Scan échoué pour %s : %s", ip, e)
        return None
    return nm[ip] if ip in nm.all_hosts() else None


def scan_host_twophase(
    ip: str,
    profile: str = "full",
    save_dir: str | None = None,
) -> object | None:
    """
    Scan en deux phases pour maximiser la couverture et minimiser le temps de détection.

    Phase 1 — Découverte TCP rapide sur les 65 535 ports (-p-).
              Aucune détection de service : uniquement ouvert/fermé.
    Phase 2 — Détection de services et scripts de vulnérabilité sur les seuls
              ports ouverts trouvés en phase 1.

    Si save_dir est fourni, les résultats nmap sont sauvegardés au format -oA
    dans ce répertoire pour traçabilité (audit trail).

    Retourne le HostDict nmap de la phase 2, ou celui de la phase 1 si aucun
    port n'a été trouvé ouvert, ou None si l'hôte est inaccessible.
    """
    log.info("Phase 1 (découverte TCP complète) pour %s", ip)
    nm1 = _get_portscanner()

    p1_args = _PHASE1_ARGS
    if save_dir:
        pathlib.Path(save_dir).mkdir(parents=True, exist_ok=True)
        safe_ip = ip.replace(".", "_")
        p1_args = f"{p1_args} -oA {save_dir}/scan_{safe_ip}_p1"

    try:
        nm1.scan(ip, arguments=p1_args)
    except Exception as e:
        log.error("Phase 1 échouée pour %s : %s", ip, e)
        return None

    if ip not in nm1.all_hosts():
        log.warning("Hôte %s non trouvé en phase 1", ip)
        return None

    open_ports: list[str] = []
    for proto in nm1[ip].all_protocols():
        for port, pinfo in nm1[ip][proto].items():
            if pinfo.get("state") == "open":
                open_ports.append(str(port))

    if not open_ports:
        log.info("Aucun port ouvert sur %s — phase 2 ignorée", ip)
        return nm1[ip]

    log.info("Phase 2 (service + vuln) sur %d port(s) ouverts pour %s", len(open_ports), ip)
    nm2 = _get_portscanner()
    ports_str = ",".join(sorted(open_ports, key=int))
    p2_args = SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["arguments"]

    if save_dir:
        p2_args = f"{p2_args} -oA {save_dir}/scan_{safe_ip}_p2"

    try:
        nm2.scan(ip, ports_str, arguments=p2_args)
    except Exception as e:
        log.error("Phase 2 échouée pour %s : %s", ip, e)
        return nm1[ip]

    return nm2[ip] if ip in nm2.all_hosts() else nm1[ip]


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
