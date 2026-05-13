"""
Configuration centralisée de ReconEngine.
Chargée depuis un fichier TOML (RECONENGINE_CONFIG) et/ou des variables d'environnement.
Env vars ont toujours la priorité sur le fichier TOML.
"""
import contextlib
import logging
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


# ── Seuils CVSS (source de vérité unique — importés par cve.py et rapport.py) ─
# Norme FIRST/NVD : Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low ≥ 0.1
CVSS_THRESHOLDS: list[tuple[float, str, str]] = [
    (9.0, "critical", "CRITIQUE"),
    (7.0, "high",     "ELEVE"),
    (4.0, "medium",   "MODERE"),
    (0.1, "low",      "FAIBLE"),
]

# Noms canoniques des niveaux de sévérité (dans l'ordre décroissant)
SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")

# ── Liste de ports prioritaires ────────────────────────────────────────────────
# Couvre les services les plus exposés en environnement réseau typique.
# Plus ciblée que 1-3389 : moins de bruit, résultats plus rapides sur matériel embarqué.
DEFAULT_PORTS = ",".join(map(str, sorted([
    # Accès non sécurisés / protocoles en clair
    21, 22, 23, 25, 69, 79,
    # Web
    80, 443, 8080, 8443, 8888, 9090,
    # Mail
    110, 143, 465, 587, 993, 995,
    # DNS / SNMP
    53, 161, 162,
    # Windows / SMB / RPC
    111, 135, 137, 139, 445,
    # Anciens services Unix
    512, 513, 514, 873,
    # Annuaires
    389, 636,
    # Java RMI
    1098, 1099,
    # Bases de données
    1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 27018,
    # Accès distants
    2222, 3389, 5900, 5901, 5902,
    # Docker / conteneurs
    2375, 2376, 2377,
    # NFS
    2049,
    # Services divers à risque
    4444, 4848, 5000, 5601, 7001, 7002, 8009, 8161,
    9000, 9001, 9042, 9092, 15672, 16379, 28017,
])))

SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Scan rapide — détection des ports ouverts, sans scripts",
        # -Pn              : hôtes déjà confirmés actifs (discover.py)
        # --max-retries 1  : nmap défaut = 2 re-sondes ; 1 suffit sur LAN fiable
        # --host-timeout   : libère le thread si un hôte ne répond plus
        # --min-parallelism: force le parallélisme de sondage nmap
        "arguments": "-sS -T4 --min-rate 2000 -n --open -Pn --max-retries 1 --host-timeout 60s --min-parallelism 20",
    },
    "full": {
        "description": "Scan complet — services, OS et scripts de vulnérabilité (CVSSv2 ≥ 5.0)",
        # -Pn            : hôtes pré-confirmés, pas besoin de re-ping
        # --host-timeout : évite qu'un hôte bloque un thread indéfiniment
        # --max-retries  : retry sur perte de paquets (WiFi, réseaux bruyants)
        "arguments": "-sS -sV -O --script vuln,default --script-args mincvss=5.0 -T4 -Pn --host-timeout 300s --max-retries 3",
    },
    "stealth": {
        "description": "Scan furtif — rythme lent, randomisé, conçu pour éviter IDS/IPS et logs réseau",
        # -T1            : timing paranoïaque (délai ~15s entre sondes)
        # --max-rate 10  : max 10 paquets/s pour rester sous les seuils de détection courants
        # --randomize-hosts : ordre aléatoire pour éviter les patterns prévisibles
        # --data-length  : padding aléatoire pour contourner la signature nmap
        "arguments": "-sS -T1 -n --open -Pn --max-rate 10 --randomize-hosts --data-length 24",
    },
    "web": {
        "description": "Scan web — HTTP/HTTPS, énumération de chemins et scripts de vulnérabilité web",
        # Restreint aux ports web courants pour aller plus vite
        # Scripts : titres de pages, méthodes HTTP autorisées, découverte de répertoires
        "arguments": "-sS -sV --script http-headers,http-title,http-methods,http-enum,http-auth-finder,http-default-accounts -T4 -Pn",
        # ports override: uniquement les ports web — plus ciblé que DEFAULT_PORTS
        "ports": "80,443,3000,4443,5000,7001,7443,8000,8080,8443,8888,9000,9090,9200,9443",
    },
    "udp": {
        "description": "Scan UDP — services UDP exposés (DNS, SNMP, TFTP, NTP, SSDP, mDNS…)",
        # -sU            : mode UDP (nécessite root)
        # --top-ports 200: les 200 ports UDP les plus courants (compromis vitesse/couverture)
        # Pas de scripts : les scripts UDP sont très lents
        "arguments": "-sU --top-ports 200 -T4 -Pn",
    },
}

# Clé de profil de fallback utilisée par scan.py si un profil lent ne renvoie aucun résultat.
# Désactivable via RECONENGINE_FALLBACK_DISABLED=1 (utile sur matériel lent / WiFi instable).
FALLBACK_PROFILE = "quick"
FALLBACK_SCAN_ENABLED: bool = os.environ.get("RECONENGINE_FALLBACK_DISABLED", "0") != "1"

# ── Validation helpers ─────────────────────────────────────────────────────────
_PORT_SPEC_RE = re.compile(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$")


def _validate_ports(ports: str) -> str:
    """Valide une expression de ports nmap et retourne la valeur nettoyée."""
    ports = ports.strip()
    if not ports:
        return DEFAULT_PORTS
    if not _PORT_SPEC_RE.match(ports):
        raise ValueError(
            f"Expression de ports invalide : '{ports}'. "
            "Format attendu : '22,80,443' ou '1-1024' ou '22,80,1000-2000'."
        )
    # Check individual port numbers are in [1, 65535]
    for chunk in ports.split(","):
        parts = chunk.split("-")
        for p in parts:
            n = int(p)
            if not 1 <= n <= 65535:
                raise ValueError(f"Port {n} hors de la plage valide [1, 65535].")
    return ports


def _validate_profile(profile: str) -> str:
    profile = profile.strip().lower()
    if profile not in SCAN_PROFILES:
        valid = ", ".join(SCAN_PROFILES.keys())
        raise ValueError(f"Profil inconnu : '{profile}'. Valeurs valides : {valid}.")
    return profile


def _validate_workers(value: int) -> int:
    if value < 1 or value > 64:
        raise ValueError(f"max_workers doit être entre 1 et 64 (reçu : {value}).")
    return value


def _validate_timeout(value: int) -> int:
    if value < 1 or value > 300:
        raise ValueError(f"discovery_timeout doit être entre 1 et 300 secondes (reçu : {value}).")
    return value


@dataclass
class ScanConfig:
    ports: str = DEFAULT_PORTS
    profile: str = "full"
    discovery_timeout: int = 5
    max_workers: int = 8


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    output_dir: str = "rapports"

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()

        config_path = os.environ.get("RECONENGINE_CONFIG")
        if config_path:
            p = Path(config_path)
            if p.exists():
                try:
                    with open(p, "rb") as f:
                        data = tomllib.load(f)
                    s = data.get("scan", {})
                    if "ports" in s:
                        cfg.scan.ports = _validate_ports(str(s["ports"]))
                    if "profile" in s:
                        cfg.scan.profile = _validate_profile(str(s["profile"]))
                    if "max_workers" in s:
                        cfg.scan.max_workers = _validate_workers(int(s["max_workers"]))
                    if "discovery_timeout" in s:
                        cfg.scan.discovery_timeout = _validate_timeout(int(s["discovery_timeout"]))
                    if "output_dir" in data:
                        cfg.output_dir = str(data["output_dir"])
                except (ValueError, KeyError, TypeError) as e:
                    log.error("Erreur de configuration dans '%s' : %s", config_path, e)
                    raise SystemExit(1) from e
            else:
                log.warning("Fichier de configuration introuvable : %s", config_path)

        # ── Variables d'environnement (priorité absolue) ───────────────────────
        if v := os.environ.get("RECONENGINE_PORTS"):
            try:
                cfg.scan.ports = _validate_ports(v)
            except ValueError as e:
                log.error("RECONENGINE_PORTS invalide : %s", e)
                raise SystemExit(1) from e

        if v := os.environ.get("RECONENGINE_PROFILE"):
            try:
                cfg.scan.profile = _validate_profile(v)
            except ValueError as e:
                log.error("RECONENGINE_PROFILE invalide : %s", e)
                raise SystemExit(1) from e

        if v := os.environ.get("RECONENGINE_OUTPUT_DIR"):
            cfg.output_dir = v

        if v := os.environ.get("RECONENGINE_MAX_WORKERS"):
            with contextlib.suppress(ValueError):
                cfg.scan.max_workers = _validate_workers(int(v))

        if v := os.environ.get("RECONENGINE_DISCOVERY_TIMEOUT"):
            with contextlib.suppress(ValueError):
                cfg.scan.discovery_timeout = _validate_timeout(int(v))

        if cfg.scan.profile not in SCAN_PROFILES:
            raise ValueError(
                f"Profil invalide : '{cfg.scan.profile}'. "
                f"Profils disponibles : {', '.join(SCAN_PROFILES)}"
            )
        if cfg.scan.max_workers < 1:
            raise ValueError(f"max_workers doit être ≥ 1, reçu : {cfg.scan.max_workers}")

        return cfg


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure le logging centralisé pour tous les modules ReconEngine.

    À appeler une seule fois au démarrage (main.py, api.py).
    Les appels redondants à basicConfig() dans les sous-modules sont sans effet
    une fois que le root logger est déjà configuré.
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
