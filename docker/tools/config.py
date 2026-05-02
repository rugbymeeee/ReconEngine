"""
Configuration centralisée de ReconEngine.
Chargée depuis un fichier TOML (RECONENGINE_CONFIG) et/ou des variables d'environnement.
"""
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

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
        # -Pn              : hôtes pré-confirmés
        # --max-retries 1  : réduit le temps sur ports filtrés/closed
        # --host-timeout   : évite qu'un hôte bloque un thread indéfiniment
        "arguments": "-sS -sV -O --script vuln,default --script-args mincvss=5.0 -T4 -Pn --host-timeout 300s --max-retries 1",
    },
}


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
                with open(p, "rb") as f:
                    data = tomllib.load(f)
                s = data.get("scan", {})
                for attr in ("ports", "profile"):
                    if attr in s:
                        setattr(cfg.scan, attr, str(s[attr]))
                for attr in ("discovery_timeout", "max_workers"):
                    if attr in s:
                        setattr(cfg.scan, attr, int(s[attr]))
                if "output_dir" in data:
                    cfg.output_dir = str(data["output_dir"])

        # Variables d'environnement — priorité absolue
        if v := os.environ.get("RECONENGINE_PORTS"):
            cfg.scan.ports = v
        if v := os.environ.get("RECONENGINE_PROFILE"):
            cfg.scan.profile = v
        if v := os.environ.get("RECONENGINE_OUTPUT_DIR"):
            cfg.output_dir = v

        if cfg.scan.profile not in SCAN_PROFILES:
            raise ValueError(
                f"Profil invalide : '{cfg.scan.profile}'. "
                f"Profils disponibles : {', '.join(SCAN_PROFILES)}"
            )
        if cfg.scan.max_workers < 1:
            raise ValueError(f"max_workers doit être ≥ 1, reçu : {cfg.scan.max_workers}")

        return cfg
