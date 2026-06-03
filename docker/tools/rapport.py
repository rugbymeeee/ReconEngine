"""
Construction des données de rapport et génération du PDF.

Pipeline :
  build_report_data(scan_results, total_ports, cache, discovered_ips)  →  dict (contexte Jinja2)
  generate_report(scan_results, ...)                                     →  str (chemin du PDF)

Le cache d'exploits est partageable avec le rendu terminal (main.py)
pour éviter tout appel searchsploit dupliqué.
"""
import datetime
import logging
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from ipaddress import AddressValueError, ip_address

import cve as cve_mod
import exploits as exploit_mod
import mac_vendor
import scan as scan_mod
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML
from weasyprint.urls import URLFetchingError, default_url_fetcher

log = logging.getLogger(__name__)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
TEMPLATES_DIR = SCRIPT_DIR / "templates"

# ── Scoring ────────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {"critical": 30, "high": 18, "medium": 8, "low": 2}
LEVEL_THRESHOLDS = [
    (75, "CRITIQUE"),
    (50, "ELEVE"),
    (25, "MODERE"),
    (0,  "FAIBLE"),
]

# ── Classification ports ───────────────────────────────────────────────────────
CRITICAL_PORTS = {
    21, 23, 69, 512, 513, 514,          # protocoles en clair
    135, 137, 139, 445, 111, 873, 2049, # partages / RPC
    1433, 1521, 3306, 5432,             # bases de données SQL
    6379, 9200, 11211, 27017,           # bases NoSQL souvent sans auth
    3389, 5900, 5901,                   # accès distants graphiques
    1099, 2375, 2376,                   # Java RMI, Docker API
}

HIGH_RISK_SERVICES = {
    "smb", "microsoft-ds", "netbios-ssn", "rpcbind", "nfs", "rsync",
    "ftp", "telnet", "tftp", "rlogin", "rsh", "exec",
    "ms-sql", "ms-sql-s", "mysql", "postgresql",
    "oracle-tns", "redis", "mongodb", "elasticsearch", "memcached",
    "vnc", "ms-wbt-server", "x11",
    "snmp", "ldap", "ldaps", "java-rmi", "docker",
}


def has_critical_exposure(scan_results: dict) -> bool:
    """
    Détermine si au moins un hôte a un port critique ouvert ou un service à risque élevé.

    Utilisé par main.py / api.py pour piloter l'état final des LED (DONE_CRITICAL vs DONE_OK)
    sans dupliquer la logique de classification.

    Args:
        scan_results: dict ip → nmap.PortScannerHostDict (tel que produit par scan.scan_host)
    """
    for data in scan_results.values():
        try:
            protocols = data.all_protocols()
        except Exception:
            continue
        for proto in protocols:
            for port in data[proto]:
                pinfo = data[proto][port]
                if pinfo.get("state") != "open":
                    continue
                if port in CRITICAL_PORTS or (pinfo.get("name") or "").lower() in HIGH_RISK_SERVICES:
                    return True
    return False


# ── Classification hôtes ───────────────────────────────────────────────────────
_SERVER_OS_KW = (
    "server", "centos", "rhel", "debian", "freebsd", "esxi", "proxmox",
    "suse", "rocky", "almalinux", "openbsd", "netbsd", "solaris", "aix",
)
_WORKSTATION_OS_KW = (
    "windows 10", "windows 11", "macos", "os x", "fedora workstation",
    "ubuntu desktop", "mint", "manjaro", "elementary",
)
# Ports fortement associés à un rôle serveur (web, mail, DNS, DB…)
_SERVER_INDICATOR_PORTS = {
    25, 53, 80, 110, 143, 389, 443, 445, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 9200, 27017,
}

# ── Recommandations par niveau (langage accessible) ───────────────────────────
RECOMMENDATIONS = {
    "critical": (
        "Ce service doit être désactivé ou coupé du réseau immédiatement. "
        "Contactez votre responsable informatique aujourd'hui et vérifiez "
        "si des accès suspects ont eu lieu récemment."
    ),
    "high": (
        "Ce service doit être mis à jour et son accès limité aux seules personnes autorisées. "
        "Faites appel à votre informaticien pour effectuer les mises à jour et "
        "bloquer les connexions non nécessaires."
    ),
    "medium": (
        "Ce service mérite une vérification de configuration. "
        "S'il n'est pas indispensable, désactivez-le. "
        "Planifiez une revue avec votre équipe informatique dans les deux prochaines semaines."
    ),
    "low": (
        "Ce point ne nécessite pas d'action immédiate. "
        "Intégrez-le à votre prochaine maintenance informatique."
    ),
}

# Libellés de confiance (affichés dans le rapport)
CONFIDENCE_LABELS = {
    "confirmed":  ("Confirmée",  "NVD"),       # CVSS NVD avec version réelle
    "probable":   ("Probable",   "nmap"),       # scripts nmap / NVD sans version exacte
    "potential":  ("Potentielle", "searchsploit"),  # matching textuel approximatif
    "heuristic":  ("Heuristique", "port"),      # classification par port/service uniquement
}

ACTION_PLAN_MAX_ITEMS = 25

# ── Noms lisibles des services courants (par port) ────────────────────────────
_SERVICE_PLAIN_NAMES: dict[int, str] = {
    20:    "Transfert de fichiers FTP (données)",
    21:    "Transfert de fichiers non chiffré (FTP)",
    22:    "Administration à distance sécurisée (SSH)",
    23:    "Administration à distance non chiffrée (Telnet)",
    25:    "Serveur de messagerie sortante (SMTP)",
    53:    "Résolution de noms de domaine (DNS)",
    67:    "Attribution d'adresses réseau (DHCP)",
    69:    "Transfert de fichiers simplifié (TFTP)",
    80:    "Site web non chiffré (HTTP)",
    110:   "Réception de messagerie (POP3)",
    111:   "Services réseau à distance (RPC)",
    135:   "Services Windows à distance (RPC/DCOM)",
    137:   "Partage réseau Windows (NetBIOS)",
    139:   "Partage réseau Windows",
    143:   "Réception de messagerie (IMAP)",
    389:   "Annuaire d'entreprise (LDAP)",
    443:   "Site web chiffré (HTTPS)",
    445:   "Partage de fichiers et imprimantes Windows (SMB)",
    512:   "Exécution de commandes à distance (rexec)",
    513:   "Session à distance non chiffrée (rlogin)",
    514:   "Shell à distance non chiffré (RSH)",
    587:   "Envoi de messagerie (SMTP soumission)",
    873:   "Synchronisation de fichiers (rsync)",
    993:   "Réception de messagerie chiffrée (IMAP)",
    995:   "Réception de messagerie chiffrée (POP3)",
    1099:  "Services Java à distance (RMI)",
    1433:  "Base de données SQL Server (Microsoft)",
    1521:  "Base de données Oracle",
    2049:  "Partage de fichiers réseau (NFS)",
    2375:  "Gestion de conteneurs Docker (non chiffré)",
    2376:  "Gestion de conteneurs Docker",
    3306:  "Base de données MySQL / MariaDB",
    3389:  "Bureau à distance Windows (RDP)",
    5432:  "Base de données PostgreSQL",
    5900:  "Contrôle d'écran à distance (VNC)",
    5901:  "Contrôle d'écran à distance (VNC)",
    6379:  "Base de données en mémoire (Redis)",
    8080:  "Application web (port alternatif)",
    8443:  "Application web chiffrée (port alternatif)",
    9200:  "Moteur de recherche de données (Elasticsearch)",
    11211: "Cache mémoire applicatif (Memcached)",
    27017: "Base de données MongoDB",
}

# ── Impact métier par niveau de risque ────────────────────────────────────────
_BUSINESS_IMPACTS = {
    "critical": (
        "Un attaquant pourrait prendre le contrôle total de cette machine : "
        "voler toutes les données, bloquer vos activités ou vous demander une rançon."
    ),
    "high": (
        "Un accès non autorisé à des informations confidentielles est possible, "
        "ou le fonctionnement du service peut être perturbé."
    ),
    "medium": (
        "Ce point facilite la collecte d'informations sur votre réseau "
        "et peut ouvrir la voie à d'autres tentatives d'intrusion."
    ),
    "low": (
        "Risque limité dans les conditions actuelles. "
        "À surveiller lors des prochaines maintenances."
    ),
}

# ── Libellés d'urgence ─────────────────────────────────────────────────────────
_URGENCY_LABELS = {
    "critical": ("Aujourd'hui",        "#dc2626"),
    "high":     ("Sous 48 heures",     "#ea580c"),
    "medium":   ("Sous 2 semaines",    "#d97706"),
    "low":      ("Prochaine révision", "#059669"),
}

# ── Textes de synthèse non-technique ──────────────────────────────────────────
_PLAIN_INTROS = {
    "CRITIQUE": (
        "L'audit a révélé des problèmes graves sur votre réseau. "
        "Des portes d'entrée exploitables par des personnes malveillantes ont été trouvées : "
        "elles pourraient leur permettre de voler vos données, de prendre le contrôle de vos machines "
        "ou de bloquer complètement vos activités. Une intervention est nécessaire dès aujourd'hui."
    ),
    "ELEVE": (
        "L'audit a révélé des failles sérieuses qui exposent votre organisation à un risque réel. "
        "Ces points ne sont pas encore une urgence absolue, mais des personnes malveillantes "
        "pourraient en tirer profit rapidement si rien n'est fait. "
        "Nous recommandons d'agir dans les 48 heures."
    ),
    "MODERE": (
        "Votre réseau est globalement bien protégé, mais quelques points méritent attention. "
        "Les problèmes identifiés n'exposent pas vos données à un danger immédiat, "
        "mais ils pourraient faciliter une attaque si d'autres failles venaient s'y ajouter. "
        "Une correction planifiée dans les deux prochaines semaines est recommandée."
    ),
    "FAIBLE": (
        "Votre réseau présente un bon niveau de sécurité. "
        "L'audit n'a détecté que des points mineurs, sans risque immédiat pour vos données "
        "ou vos activités. Ces éléments peuvent être traités lors de votre prochaine maintenance."
    ),
}

_ACTION_LABELS = {
    "critical": "Désactiver ou couper du réseau immédiatement. Contacter votre informaticien aujourd'hui.",
    "high":     "Mettre à jour et limiter l'accès à ce service. À faire dans les 48 heures.",
    "medium":   "Vérifier la configuration et désactiver si le service est inutile. À planifier.",
}

# ── Guide de remédiation ───────────────────────────────────────────────────────
# Base de connaissances : instructions concrètes par port / service.
# Clés : int (port) en priorité, str (nom de service nmap) en fallback.
REMEDIATION_GUIDE: dict = {
    # ── Protocoles d'administration non chiffrés ───────────────────────────────
    21: {
        "titre":       "FTP — Transfert de fichiers sans chiffrement",
        "probleme":    "Ce service transmet les mots de passe et les fichiers en clair sur le réseau.",
        "danger":      "N'importe qui connecté au même réseau peut lire vos identifiants et vos fichiers sans effort.",
        "etapes": [
            "Désactiver le service FTP sur le serveur (Panneau de configuration → Outils d'administration → Services → arrêter 'FTP').",
            "Le remplacer par SFTP ou FTPS si des transferts de fichiers sont nécessaires — votre hébergeur ou prestataire peut configurer cela.",
            "Si FTP doit rester actif temporairement, le restreindre à certaines adresses IP uniquement via le pare-feu.",
        ],
        "complexite":  "Facile",
        "responsable": "Prestataire informatique / Administrateur système",
    },
    22: {
        "titre":       "SSH — Accès à distance (vérifier la configuration)",
        "probleme":    "L'accès à distance SSH est exposé sur le réseau avec une version potentiellement ancienne.",
        "danger":      "Une configuration par défaut ou une version obsolète peut permettre à un attaquant de se connecter à distance.",
        "etapes": [
            "Mettre à jour le système d'exploitation pour obtenir la dernière version de SSH.",
            "Interdire la connexion directe en tant qu'administrateur root : modifier la ligne 'PermitRootLogin yes' en 'PermitRootLogin no' dans /etc/ssh/sshd_config.",
            "Préférer les clés SSH aux mots de passe : activer 'PubkeyAuthentication yes' et 'PasswordAuthentication no'.",
            "Bloquer l'accès SSH aux seules adresses IP de confiance via le pare-feu.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système",
    },
    23: {
        "titre":       "Telnet — Administration à distance sans chiffrement (protocole obsolète)",
        "probleme":    "Telnet est un outil d'administration des années 1970 qui ne chiffre absolument rien.",
        "danger":      "Chaque mot de passe tapé circule en clair et peut être intercepté par n'importe qui sur le réseau.",
        "etapes": [
            "Désactiver immédiatement le service Telnet (Panneau de configuration → Fonctionnalités Windows → décocher Telnet, ou via systemctl disable telnet sous Linux).",
            "Utiliser SSH à la place pour toute administration à distance — c'est identique mais chiffré.",
        ],
        "complexite":  "Facile",
        "responsable": "Prestataire informatique / Administrateur système",
    },
    512: {
        "titre":       "Rexec / Rlogin / RSH — Services d'accès à distance Unix obsolètes",
        "probleme":    "Ces services permettent l'exécution de commandes à distance sans chiffrement.",
        "danger":      "Aucun chiffrement, souvent pas d'authentification robuste — risque de prise de contrôle totale.",
        "etapes": [
            "Désactiver ces services immédiatement (rexec, rlogin, rsh sont considérés dangereux depuis 1990).",
            "Utiliser SSH à la place.",
        ],
        "complexite":  "Facile",
        "responsable": "Administrateur système",
    },
    # ── Partage de fichiers et réseau interne ──────────────────────────────────
    445: {
        "titre":       "SMB — Partage de fichiers Windows",
        "probleme":    "Le partage de fichiers Windows est exposé sur le réseau.",
        "danger":      "Des ransomwares (WannaCry, NotPetya) ont paralysé des milliers d'entreprises via ce service. Un accès non autorisé donne accès à tous vos fichiers partagés.",
        "etapes": [
            "Appliquer immédiatement toutes les mises à jour Windows (Démarrer → Paramètres → Windows Update → Rechercher des mises à jour).",
            "Désactiver SMBv1 (version très vulnérable) : Panneau de configuration → Programmes → Activer ou désactiver des fonctionnalités Windows → décocher 'Prise en charge du partage de fichiers SMB 1.0/CIFS'.",
            "Bloquer le port 445 sur le pare-feu pour les connexions venant d'internet.",
            "Vérifier que seuls les utilisateurs autorisés ont accès aux partages réseau.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système",
    },
    139: {
        "titre":       "NetBIOS — Partage réseau Windows (protocole ancien)",
        "probleme":    "NetBIOS est l'ancien protocole de partage Windows, moins sécurisé que SMB.",
        "danger":      "Expose le nom de vos machines, vos groupes de travail et peut faciliter des attaques de type 'man-in-the-middle'.",
        "etapes": [
            "Désactiver NetBIOS si vous n'en avez pas besoin : Connexions réseau → Propriétés de la carte → TCP/IP → Avancé → WINS → Désactiver NetBIOS.",
            "Si nécessaire, bloquer les ports 137-139 sur le pare-feu.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système",
    },
    2049: {
        "titre":       "NFS — Partage de fichiers réseau Linux",
        "probleme":    "Le partage de fichiers NFS est exposé sur le réseau.",
        "danger":      "Sans contrôle strict, n'importe quelle machine sur le réseau peut monter et lire vos fichiers.",
        "etapes": [
            "Vérifier les exports NFS (/etc/exports) et restreindre l'accès aux seules machines autorisées.",
            "Activer l'authentification Kerberos si disponible.",
            "Bloquer NFS au pare-feu si seule une communication interne est nécessaire.",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur système",
    },
    # ── Services web ───────────────────────────────────────────────────────────
    80: {
        "titre":       "HTTP — Site web sans chiffrement",
        "probleme":    "Votre service web fonctionne sans chiffrement (HTTP au lieu de HTTPS).",
        "danger":      "Les données échangées — y compris les mots de passe et informations personnelles — sont lisibles par tous sur le réseau.",
        "etapes": [
            "Installer un certificat SSL/TLS sur votre serveur web — les certificats Let's Encrypt sont gratuits et largement supportés.",
            "Activer HTTPS (port 443) et configurer une redirection automatique de HTTP vers HTTPS.",
            "Mettre à jour votre serveur web (Apache, Nginx ou IIS) vers la dernière version stable.",
        ],
        "complexite":  "Moyen",
        "responsable": "Développeur web / Prestataire informatique",
    },
    443: {
        "titre":       "HTTPS — Vérification de la configuration SSL/TLS",
        "probleme":    "Le service HTTPS présente une version ou configuration SSL/TLS potentiellement vulnérable.",
        "danger":      "Une mauvaise configuration peut permettre le déchiffrement des communications.",
        "etapes": [
            "Mettre à jour le serveur web et les bibliothèques SSL/TLS.",
            "Désactiver les anciens protocoles obsolètes : SSL 3.0, TLS 1.0 et TLS 1.1.",
            "Tester votre configuration gratuitement sur ssllabs.com (SSL Server Test) et viser la note A ou A+.",
            "Renouveler le certificat si sa date d'expiration approche.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système / Développeur web",
    },
    8080: {
        "titre":       "Application web sur port alternatif",
        "probleme":    "Une application web est exposée sur un port alternatif, souvent sans chiffrement.",
        "danger":      "Ces interfaces sont souvent des outils d'administration ou des API — leur exposition représente un risque élevé.",
        "etapes": [
            "Vérifier à quoi correspond ce service et s'il doit être accessible depuis le réseau.",
            "Si c'est un outil d'administration, le restreindre aux seules adresses IP autorisées.",
            "Activer HTTPS si ce n'est pas encore fait.",
            "Protéger l'accès par un mot de passe fort ou une authentification à deux facteurs.",
        ],
        "complexite":  "Moyen",
        "responsable": "Développeur / Prestataire informatique",
    },
    # ── Bases de données ───────────────────────────────────────────────────────
    3306: {
        "titre":       "MySQL / MariaDB — Base de données exposée sur le réseau",
        "probleme":    "Le serveur de base de données est directement accessible depuis le réseau.",
        "danger":      "Une base de données exposée peut être vidée, modifiée ou chiffrée par un ransomware. Toutes vos données sont à risque.",
        "etapes": [
            "Configurer MySQL pour n'écouter que sur la machine locale : ajouter 'bind-address = 127.0.0.1' dans /etc/mysql/my.cnf, puis redémarrer MySQL.",
            "Si l'accès depuis une autre machine est indispensable, utiliser un tunnel SSH plutôt qu'exposer le port directement.",
            "Vérifier qu'aucun compte n'a un mot de passe vide : lancer 'SELECT User,Host,authentication_string FROM mysql.user;' dans MySQL.",
            "Mettre à jour MySQL/MariaDB vers la dernière version stable.",
        ],
        "complexite":  "Moyen",
        "responsable": "Développeur / Prestataire informatique",
    },
    5432: {
        "titre":       "PostgreSQL — Base de données exposée sur le réseau",
        "probleme":    "La base de données PostgreSQL est accessible depuis le réseau.",
        "danger":      "Un accès non autorisé peut exposer ou détruire l'intégralité de vos données.",
        "etapes": [
            "Configurer PostgreSQL pour n'écouter que localement : définir 'listen_addresses = localhost' dans postgresql.conf.",
            "Revoir le fichier pg_hba.conf pour n'autoriser que les connexions nécessaires.",
            "Mettre à jour PostgreSQL vers la dernière version stable.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur base de données",
    },
    1433: {
        "titre":       "Microsoft SQL Server — Base de données exposée",
        "probleme":    "SQL Server est accessible depuis le réseau.",
        "danger":      "Un accès non autorisé peut conduire à la lecture, modification ou destruction de toutes vos données métier.",
        "etapes": [
            "Désactiver ou changer le mot de passe du compte 'sa' (administrateur SQL) s'il est actif.",
            "Bloquer le port 1433 sur le pare-feu pour les connexions extérieures non nécessaires.",
            "Appliquer les correctifs Microsoft SQL Server via Windows Update.",
            "Auditer les comptes SQL Server et supprimer ceux qui sont inutilisés.",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur base de données",
    },
    1521: {
        "titre":       "Oracle Database — Base de données exposée",
        "probleme":    "Le serveur Oracle Database est accessible depuis le réseau.",
        "danger":      "Un accès non autorisé peut exposer l'intégralité de vos données.",
        "etapes": [
            "Restreindre l'accès au port 1521 via le pare-feu.",
            "Changer les mots de passe par défaut des comptes Oracle (SYS, SYSTEM).",
            "Appliquer le dernier Oracle Critical Patch Update (CPU).",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur base de données",
    },
    6379: {
        "titre":       "Redis — Base de données en mémoire sans authentification",
        "probleme":    "Redis est exposé sur le réseau, souvent sans aucune authentification par défaut.",
        "danger":      "Redis sans protection peut être vidé, utilisé pour exécuter des commandes ou même compromettre le serveur entier.",
        "etapes": [
            "Ajouter un mot de passe dans /etc/redis/redis.conf : décommenter et définir 'requirepass VotreMotDePasseFort'.",
            "Configurer Redis pour n'écouter que sur localhost : définir 'bind 127.0.0.1' dans redis.conf.",
            "Redémarrer Redis après ces modifications.",
            "Mettre à jour Redis vers la dernière version stable.",
        ],
        "complexite":  "Facile",
        "responsable": "Développeur / Administrateur système",
    },
    27017: {
        "titre":       "MongoDB — Base de données sans authentification",
        "probleme":    "MongoDB est installé sans authentification activée, ce qui est le comportement par défaut.",
        "danger":      "Des milliers de bases MongoDB ont été entièrement vidées par des attaquants automatisés. Vos données sont lisibles par tout le monde.",
        "etapes": [
            "Activer l'authentification dans /etc/mongod.conf : ajouter 'security: authorization: enabled'.",
            "Créer un utilisateur administrateur MongoDB avec un mot de passe fort.",
            "Configurer MongoDB pour n'écouter que sur localhost : définir 'net: bindIp: 127.0.0.1'.",
            "Mettre à jour MongoDB vers la dernière version stable.",
        ],
        "complexite":  "Moyen",
        "responsable": "Développeur / Administrateur base de données",
    },
    9200: {
        "titre":       "Elasticsearch — Moteur de recherche exposé sans authentification",
        "probleme":    "Elasticsearch est accessible sur le réseau, souvent sans authentification dans les anciennes versions.",
        "danger":      "Des données potentiellement sensibles indexées dans Elasticsearch peuvent être lues ou effacées par n'importe qui.",
        "etapes": [
            "Mettre à jour vers Elasticsearch 8.x qui active la sécurité par défaut.",
            "Activer le module de sécurité X-Pack : ajouter 'xpack.security.enabled: true' dans elasticsearch.yml.",
            "Configurer Elasticsearch pour n'écouter que sur localhost si l'accès externe n'est pas nécessaire.",
            "Placer Elasticsearch derrière un proxy avec authentification si un accès externe est requis.",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur système / Développeur",
    },
    11211: {
        "titre":       "Memcached — Cache applicatif exposé sans authentification",
        "probleme":    "Memcached est exposé sur le réseau sans authentification.",
        "danger":      "Peut être utilisé pour amplifier des attaques DDoS (facteur x50 000) et expose des données applicatives en cache.",
        "etapes": [
            "Configurer Memcached pour n'écouter que sur localhost : ajouter '-l 127.0.0.1' dans la configuration.",
            "Bloquer le port 11211 sur le pare-feu.",
        ],
        "complexite":  "Facile",
        "responsable": "Administrateur système",
    },
    # ── Accès à distance graphique ─────────────────────────────────────────────
    3389: {
        "titre":       "Bureau à distance Windows (RDP) — Exposition directe sur le réseau",
        "probleme":    "Le bureau à distance Windows est accessible directement depuis votre réseau.",
        "danger":      "RDP est la cible principale des ransomwares. Des milliers de tentatives d'intrusion automatisées ciblent ce service chaque jour. Une seule connexion réussie donne le contrôle total de la machine.",
        "etapes": [
            "Si RDP n'est pas indispensable : le désactiver (Paramètres → Système → Bureau à distance → Désactiver).",
            "Si RDP est nécessaire : l'utiliser UNIQUEMENT via un VPN — ne jamais l'exposer directement à internet.",
            "Activer l'authentification au niveau réseau (NLA) : Propriétés système → Accès à distance → cocher 'Autoriser uniquement les connexions avec NLA'.",
            "Appliquer toutes les mises à jour Windows immédiatement.",
            "Utiliser un mot de passe fort pour tous les comptes Windows (minimum 12 caractères, majuscules + chiffres + symboles).",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système / Prestataire informatique",
    },
    5900: {
        "titre":       "VNC — Contrôle à distance d'écran exposé",
        "probleme":    "VNC permet de prendre le contrôle visuel d'un ordinateur à distance et est exposé sur le réseau.",
        "danger":      "Sans protection forte, un attaquant peut voir et contrôler entièrement votre écran.",
        "etapes": [
            "Définir un mot de passe VNC fort si ce n'est pas déjà fait (minimum 8 caractères).",
            "Désactiver VNC si non utilisé régulièrement.",
            "Si VNC est nécessaire, l'utiliser uniquement via un tunnel SSH chiffré — ne jamais exposer le port 5900 directement.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système",
    },
    # ── Infrastructure réseau ──────────────────────────────────────────────────
    53: {
        "titre":       "DNS — Serveur de résolution de noms exposé",
        "probleme":    "Un serveur DNS tourne sur cette machine et est accessible depuis le réseau.",
        "danger":      "Un DNS mal configuré peut permettre des transferts de zone (révélant toute votre infrastructure) ou être utilisé pour des attaques d'amplification DDoS.",
        "etapes": [
            "Désactiver le service DNS si cette machine n'est pas censée être un serveur DNS.",
            "Si c'est un serveur DNS légitime, désactiver les transferts de zone vers des hôtes non autorisés.",
            "Restreindre les requêtes récursives aux seules machines internes.",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur réseau / Prestataire informatique",
    },
    161: {
        "titre":       "SNMP — Protocole de supervision réseau mal configuré",
        "probleme":    "SNMP expose des informations détaillées sur vos équipements réseau.",
        "danger":      "La communauté 'public' par défaut donne accès en lecture à la configuration de vos équipements. SNMPv1 et v2 ne chiffrent rien.",
        "etapes": [
            "Changer impérativement les noms de communauté par défaut ('public', 'private') par des chaînes aléatoires.",
            "Passer à SNMPv3 qui intègre chiffrement et authentification.",
            "Restreindre l'accès SNMP aux seules adresses IP de supervision.",
            "Désactiver SNMP complètement si vous ne faites pas de supervision réseau.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur réseau",
    },
    # ── Messagerie ─────────────────────────────────────────────────────────────
    25: {
        "titre":       "SMTP — Serveur de messagerie exposé",
        "probleme":    "Un serveur de messagerie est accessible sur le réseau.",
        "danger":      "Un serveur mail mal configuré peut être détourné pour envoyer du spam en votre nom (open relay) ou révéler des informations sur votre infrastructure.",
        "etapes": [
            "Vérifier que le serveur n'est pas un 'open relay' : tester via mxtoolbox.com → SuperTool → 'Test Email Server'.",
            "Activer l'authentification SMTP pour tous les envois.",
            "Mettre à jour le logiciel de messagerie.",
            "Restreindre le port 25 aux seuls flux légitimes via le pare-feu.",
        ],
        "complexite":  "Expert",
        "responsable": "Administrateur système",
    },
    # ── Infrastructure critique ────────────────────────────────────────────────
    2375: {
        "titre":       "API Docker exposée sans chiffrement — CRITIQUE",
        "probleme":    "L'API de gestion des conteneurs Docker est accessible sans authentification.",
        "danger":      "Accès complet à Docker = accès root à toute la machine. Un attaquant peut lancer des conteneurs, lire des fichiers système et prendre le contrôle total du serveur.",
        "etapes": [
            "Désactiver immédiatement l'API Docker non chiffrée : supprimer '-H tcp://0.0.0.0:2375' des options Docker.",
            "Si l'accès à distance à Docker est nécessaire, utiliser le port 2376 avec TLS mutualisé.",
            "Redémarrer le service Docker après modification.",
        ],
        "complexite":  "Moyen",
        "responsable": "Administrateur système / DevOps",
    },
    1099: {
        "titre":       "Java RMI — Services Java à distance exposés",
        "probleme":    "Des services Java accessibles à distance sont exposés sur le réseau.",
        "danger":      "Java RMI est souvent associé à des vulnérabilités de désérialisation permettant l'exécution de code à distance.",
        "etapes": [
            "Désactiver RMI si non indispensable.",
            "Restreindre l'accès au pare-feu.",
            "Mettre à jour le JDK/JRE vers la dernière version.",
        ],
        "complexite":  "Expert",
        "responsable": "Développeur Java / Administrateur système",
    },
    # ── Fallback par nom de service ────────────────────────────────────────────
    "ftp":        {"titre": "FTP", "probleme": "Transfert de fichiers sans chiffrement.", "danger": "Identifiants lisibles sur le réseau.", "etapes": ["Désactiver FTP et utiliser SFTP à la place."], "complexite": "Facile", "responsable": "Prestataire informatique"},
    "telnet":     {"titre": "Telnet", "probleme": "Administration sans chiffrement.", "danger": "Mots de passe lisibles en clair.", "etapes": ["Désactiver Telnet et utiliser SSH à la place."], "complexite": "Facile", "responsable": "Administrateur système"},
    "smb":        {"titre": "SMB", "probleme": "Partage de fichiers Windows exposé.", "danger": "Risque de ransomware et d'accès non autorisé aux fichiers.", "etapes": ["Appliquer les mises à jour Windows.", "Désactiver SMBv1.", "Auditer les partages."], "complexite": "Moyen", "responsable": "Administrateur système"},
    "rdp":        {"titre": "RDP", "probleme": "Bureau à distance exposé.", "danger": "Cible principale des ransomwares.", "etapes": ["Utiliser uniquement via VPN.", "Activer NLA.", "Mettre à jour Windows."], "complexite": "Moyen", "responsable": "Administrateur système"},
    "vnc":        {"titre": "VNC", "probleme": "Contrôle à distance d'écran exposé.", "danger": "Accès visuel et contrôle complet de la machine.", "etapes": ["Définir un mot de passe fort.", "Accès uniquement via tunnel SSH."], "complexite": "Moyen", "responsable": "Administrateur système"},
    "mysql":      {"titre": "MySQL", "probleme": "Base de données exposée.", "danger": "Toutes vos données sont accessibles.", "etapes": ["Restreindre MySQL à localhost.", "Changer les mots de passe.", "Mettre à jour."], "complexite": "Moyen", "responsable": "Développeur"},
    "redis":      {"titre": "Redis", "probleme": "Cache Redis sans authentification.", "danger": "Données exposées, risque de compromission serveur.", "etapes": ["Activer requirepass.", "Bind sur localhost.", "Mettre à jour."], "complexite": "Facile", "responsable": "Développeur"},
    "mongodb":    {"titre": "MongoDB", "probleme": "Base de données sans authentification.", "danger": "Données lisibles par tout le monde.", "etapes": ["Activer l'authentification.", "Bind sur localhost.", "Mettre à jour."], "complexite": "Moyen", "responsable": "Développeur"},
    "snmp":       {"titre": "SNMP", "probleme": "Protocole de supervision exposé.", "danger": "Révèle la configuration réseau.", "etapes": ["Changer les communautés.", "Passer à SNMPv3.", "Restreindre l'accès."], "complexite": "Moyen", "responsable": "Administrateur réseau"},
    "docker":     {"titre": "Docker API", "probleme": "API Docker exposée.", "danger": "Accès root au serveur.", "etapes": ["Désactiver l'API non chiffrée.", "Utiliser TLS sur le port 2376."], "complexite": "Moyen", "responsable": "DevOps"},
    "ms-wbt-server": {"titre": "Bureau à distance Windows (RDP)", "probleme": "RDP exposé.", "danger": "Cible principale des ransomwares.", "etapes": ["Accès uniquement via VPN.", "Activer NLA.", "Mettre à jour Windows."], "complexite": "Moyen", "responsable": "Administrateur système"},
}

def _build_remediation_guide(hosts: list) -> list:
    """
    Construit le guide de remédiation adapté aux vulnérabilités trouvées.

    Pour chaque port ouvert critique/élevé (dédupliqué par port), cherche les
    instructions dans REMEDIATION_GUIDE (port → nom de service → fallback générique).
    Retourne une liste ordonnée par sévérité puis port.
    """
    _sev_order = {"critical": 0, "high": 1, "medium": 2}
    seen: set = set()
    items: list = []

    for host in hosts:
        if host.get("unreachable"):
            continue
        for v in host.get("vulnerabilities", []):
            if v["state"] != "open":
                continue
            sev = v["severity_class"]
            if sev not in _sev_order:
                continue

            port = v["port"]
            service_key = (v.get("service") or "").lower().split()[0].strip()
            dedup_key = port  # un seul bloc par port (même si plusieurs hôtes)

            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Lookup : port numérique d'abord, nom de service ensuite
            rem = REMEDIATION_GUIDE.get(port) or REMEDIATION_GUIDE.get(service_key)
            if rem is None:
                continue  # pas de fiche connue pour ce port/service

            complexity = rem.get("complexite", "Moyen")

            items.append({
                "port":          port,
                "protocol":      v.get("protocol", "TCP"),
                "service":       v.get("service", f"Port {port}"),
                "severity_class": sev,
                "severity_text": v["severity_text"],
                "titre":         rem["titre"],
                "probleme":      rem["probleme"],
                "danger":        rem["danger"],
                "etapes":        rem["etapes"],
                "complexite":    complexity,
                "responsable":   rem.get("responsable", "Administrateur système"),
                "urgency_label": _URGENCY_LABELS.get(sev, ("À planifier", "#64748b"))[0],
            })

    items.sort(key=lambda x: (_sev_order.get(x["severity_class"], 3), x["port"]))
    return items[:18]  # max 18 fiches pour garder le rapport lisible


def _plain_service(port: int, pinfo: dict) -> str:
    """
    Retourne un nom de service lisible par un non-technicien.

    Priorité : table de noms connus par port → produit nmap → nom de service → "Service inconnu".
    """
    if port in _SERVICE_PLAIN_NAMES:
        return _SERVICE_PLAIN_NAMES[port]
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    name = (pinfo.get("name") or "").strip()
    label = " ".join(filter(None, [product, version])) or name
    return label or "Service inconnu"


def _plain_summary(
    global_risk: str,
    n_hosts: int,
    n_critical: int,
    n_vulns: int,
    risk_dist: dict,
) -> str:
    """Génère un texte d'explication en français simple pour un lecteur non-technique."""
    intro = _PLAIN_INTROS.get(global_risk, _PLAIN_INTROS["FAIBLE"])
    parts: list[str] = []

    # Formulation naturelle du nombre de machines
    if n_hosts == 1:
        parts.append("1 machine a été analysée sur ce réseau.")
    else:
        parts.append(f"{n_hosts} machines ont été analysées sur ce réseau.")

    # Critiques
    if n_critical == 1:
        parts.append("1 problème critique nécessite une intervention immédiate.")
    elif n_critical > 1:
        parts.append(f"{n_critical} problèmes critiques nécessitent une intervention immédiate.")

    # Autres niveaux
    n_high = risk_dist.get("ELEVE", 0)
    if n_high == 1:
        parts.append("1 machine présente un risque élevé.")
    elif n_high > 1:
        parts.append(f"{n_high} machines présentent un risque élevé.")

    other = n_vulns - n_critical
    if other > 0 and not n_high:
        parts.append(f"{other} autre(s) point(s) de vigilance ont été relevés.")

    return f"{intro} {' '.join(parts)}"


def _build_action_plan(hosts: list) -> list:
    """Construit le plan d'action priorisé (critiques et élevés d'abord) pour le rapport client."""
    _sev_order = {"critical": 0, "high": 1, "medium": 2}
    actions: list = []
    for host in hosts:
        if host.get("unreachable"):
            continue
        for v in host.get("vulnerabilities", []):
            if v["state"] != "open":
                continue
            sev = v["severity_class"]
            if sev not in _sev_order:
                continue
            cve_refs = [
                c["cve_id"] for c in v.get("cve_list", [])[:3]
                if isinstance(c, dict) and c.get("cve_id")
            ]
            urgency_label, urgency_color = _URGENCY_LABELS.get(sev, ("À planifier", "#64748b"))
            actions.append({
                "ip":              host["ip"],
                "port":            v["port"],
                "service":         v["service"] or f"Port {v['port']}",
                "service_label":   v.get("service_label") or v["service"] or f"Port {v['port']}",
                "severity_class":  sev,
                "severity_text":   v["severity_text"],
                "action":          _ACTION_LABELS[sev],
                "has_exploits":    v["exploit_count"] > 0,
                "cve_refs":        cve_refs,
                "max_cvss":        v.get("max_cvss", 0.0),
                "business_impact": _BUSINESS_IMPACTS.get(sev, ""),
                "urgency_label":   urgency_label,
                "urgency_color":   urgency_color,
            })
    actions.sort(key=lambda a: (_sev_order[a["severity_class"]], a["ip"], a["port"]))
    for i, a in enumerate(actions, 1):
        a["num"] = i
    return actions[:ACTION_PLAN_MAX_ITEMS]


def _build_top_open_ports(hosts: list, top_n: int = 10) -> list:
    """
    Retourne les N ports ouverts les plus fréquents (tous hôtes confondus).

    Chaque entrée : {"port": int, "service": str, "host_count": int, "severity": str}
    La sévérité retenue est la plus haute observée pour ce port.
    """
    from collections import Counter

    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    port_counter: Counter = Counter()
    port_service: dict[int, str] = {}
    port_severity: dict[int, str] = {}

    for host in hosts:
        if host.get("unreachable"):
            continue
        seen = set()
        for v in host.get("vulnerabilities", []):
            if v["state"] != "open":
                continue
            port = v["port"]
            if port not in seen:
                seen.add(port)
                port_counter[port] += 1
            if port not in port_service:
                port_service[port] = v.get("service") or str(port)
            # Retenir la sévérité la plus haute observée pour ce port
            cur = port_severity.get(port, "low")
            new = v.get("severity_class", "low")
            if _sev_order.get(new, 3) < _sev_order.get(cur, 3):
                port_severity[port] = new

    return [
        {
            "port":       port,
            "service":    port_service.get(port, str(port)),
            "host_count": count,
            "severity":   port_severity.get(port, "low"),
        }
        for port, count in port_counter.most_common(top_n)
    ]


# ── Fonctions internes ─────────────────────────────────────────────────────────

def _classify(
    port: int,
    pinfo: dict,
    found_exploits: list,
    cve_data: dict | None = None,
) -> tuple[str, str, str]:
    """
    Retourne (severity_class, severity_text, confidence) pour un port/service.

    confidence indique la fiabilité de la classification :
      - "confirmed"  → CVSS réel depuis NVD avec version vérifiée
      - "probable"   → CVSS issu de scripts nmap ou NVD sans version exacte
      - "potential"  → uniquement searchsploit (matching textuel, non vérifié)
      - "heuristic"  → heuristique port/service (aucune base CVE consultée)

    Hiérarchie de sévérité :
      1. Score CVSS réel (NVD / scripts nmap) — source la plus fiable
      2. Exploit public searchsploit → high max (pas critical : matching approximatif)
      3. Port critique ou service à risque élevé → high
      4. Port < 1024 (service privilégié) → medium
      5. Sinon → low
    """
    name = (pinfo.get("name") or "").lower()
    state = pinfo.get("state", "")

    if state not in ("open", "filtered"):
        return "low", "FAIBLE", "heuristic"

    # ── Priorité 1 : CVSS réel ───────────────────────────────────────────────
    if cve_data and cve_data.get("max_cvss", 0.0) > 0.0:
        source = cve_data.get("source", "nmap")
        confidence = "confirmed" if source == "nvd" else "probable"
        sev_class, sev_text = cve_data["severity_class"], cve_data["severity_text"]
        # Un exploit public connu ne peut pas abaisser la sévérité sous "high"
        if found_exploits and sev_class not in ("critical", "high"):
            return "high", "ELEVE", confidence
        return sev_class, sev_text, confidence

    # ── Priorité 2 : exploit searchsploit (matching textuel, non vérifié) ────
    # Ne pas classer "critical" sur la base de searchsploit seul : trop de faux
    # positifs par matching approximatif. → "high" + confidence "potential".
    if found_exploits:
        return "high", "ELEVE", "potential"

    # ── Priorité 3 : heuristiques port/service ───────────────────────────────
    if state == "filtered":
        if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
            return "high", "ELEVE", "heuristic"
        return "low", "FAIBLE", "heuristic"

    # state == "open"
    if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
        return "high", "ELEVE", "heuristic"
    if port < 1024:
        return "medium", "MODERE", "heuristic"
    return "low", "FAIBLE", "heuristic"


def _build_recommendation(
    sev_class: str,
    product: str,
    version: str,
    cve_list: list,
) -> str:
    """
    Génère une recommandation contextuelle en langage accessible.

    Si le logiciel est connu, précise qu'il faut le mettre à jour.
    Les CVE et scores techniques sont relégués à la note technique.
    """
    base = RECOMMENDATIONS[sev_class]
    extras: list[str] = []

    # Mentionner la mise à jour si le logiciel est identifié
    if product and version:
        extras.append(
            f"Le logiciel \"{product}\" (version {version}) doit être mis à jour "
            f"vers la dernière version disponible."
        )
    elif product:
        extras.append(
            f"Vérifiez que le logiciel \"{product}\" est à jour et correctement configuré."
        )

    # Nombre de failles référencées (sans les IDs techniques)
    n_cves = len([c for c in cve_list if isinstance(c, dict)])
    if n_cves == 1:
        extras.append("1 faille de sécurité officielle a été référencée sur ce service.")
    elif n_cves > 1:
        extras.append(f"{n_cves} failles de sécurité officielles ont été référencées sur ce service.")

    if extras:
        return f"{base} {' '.join(extras)}"
    return base


def _format_service(pinfo: dict) -> str:
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    name = (pinfo.get("name") or "").strip()
    return " ".join(filter(None, [product, version])) or name or "inconnu"


def software_query(pinfo: dict) -> str:
    """
    Construit la chaîne de recherche exploit la plus précise possible.

    Retourne une chaîne vide si nmap n'a pas identifié AU MOINS le produit ET
    la version :
      - "http"/"ssh"/"ftp" sans product → searchsploit matche des milliers
        d'exploits génériques sans rapport avec la version réelle.
      - "nginx"/"Apache" sans version → searchsploit retourne tout l'historique
        des CVE du produit, dont l'écrasante majorité sur des versions qui ne
        sont probablement pas la nôtre.
    Dans ces cas, on s'en remet à la classification par port (CRITICAL_PORTS)
    et aux scripts nmap (CVE via --script vuln) — plus fiables que des matches
    textuels approximatifs.
    """
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    if not product or not version:
        return ""
    return f"{product} {version}"


def _risk_from_counts(counts: dict) -> tuple[float, str]:
    """Score 0-100 et niveau textuel depuis les comptes par sévérité."""
    total = sum(counts.values())
    if not total:
        return 0.0, "FAIBLE"
    _weights = SEVERITY_WEIGHTS  # local ref — évite lookup global répété
    weighted = sum(_weights.get(sev, 0) * n for sev, n in counts.items())
    score = min(round(weighted / (total * _weights["critical"]) * 100, 1), 100.0)
    for threshold, label in LEVEL_THRESHOLDS:
        if score >= threshold:
            return score, label
    return score, "FAIBLE"


def _classify_host_type(os_str: str, open_ports: set) -> str:
    """Classifie l'hôte : 'server' | 'workstation' | 'unknown'."""
    os_lower = os_str.lower()
    if any(kw in os_lower for kw in _SERVER_OS_KW):
        return "server"
    if any(kw in os_lower for kw in _WORKSTATION_OS_KW):
        return "workstation"
    if len(open_ports & _SERVER_INDICATOR_PORTS) >= 2:
        return "server"
    return "unknown"


def _build_unreachable_host(ip: str, mac: str = "N/A") -> dict:
    """Construit un enregistrement vide pour un hôte découvert mais non scanné."""
    return {
        "ip":                    ip,
        "mac":                   mac,
        "vendor":                mac_vendor.label(mac),
        "os":                    "",
        "host_type":             "unknown",
        "risk":                  "FAIBLE",
        "risk_score":            0.0,
        "open_ports_count":      0,
        "filtered_ports_count":  0,
        "closed_ports_count":    0,
        "critical_count":        0,
        "severity_counts":       {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "vulnerability_density": 0.0,
        "exposure_rate":         0.0,
        "service_inventory":     {},
        "vulnerabilities":       [],
        "unreachable":           True,
    }


def _build_host(ip: str, data, total_ports: int, cache: dict) -> dict:
    """Construit le dict de données pour un hôte unique."""
    vulns: list = []
    open_count = filtered_count = 0
    open_ports_set: set = set()
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    services: dict = {}

    try:
        protocols = data.all_protocols()
    except Exception:
        log.exception("Impossible de lire les protocoles pour '%s'", ip)
        protocols = []

    for proto in protocols:
        for port in data[proto]:
            pinfo = data[proto][port]
            state = pinfo.get("state", "")
            if state not in ("open", "filtered"):
                continue

            if state == "open":
                open_count += 1
                open_ports_set.add(port)
            else:
                filtered_count += 1

            product = (pinfo.get("product") or "").strip()
            version = (pinfo.get("version") or "").strip()
            script_data = pinfo.get("script", {}) if isinstance(pinfo.get("script"), dict) else {}

            # Enrichissement CVE/CVSS (scripts nmap + NVD si disponible)
            cve_data = cve_mod.get_cve_data(product, version, script_data, cache)

            # Enrichissement exploit searchsploit (fallback / complément)
            query = software_query(pinfo)
            found = exploit_mod.find(query, cache=cache)

            sev_class, sev_text, confidence = _classify(port, pinfo, found, cve_data)
            sev_counts[sev_class] += 1

            if confidence == "potential":
                log.debug(
                    "%s:%d — searchsploit match '%s' (%d résultat(s)) — à vérifier manuellement",
                    ip, port, software_query(pinfo), len(found),
                )

            svc = _format_service(pinfo)
            svc_key = (pinfo.get("name") or svc or "inconnu").strip().lower()
            services[svc_key] = services.get(svc_key, 0) + 1

            conf_label, conf_source = CONFIDENCE_LABELS.get(confidence, ("?", "?"))
            recommendation = _build_recommendation(
                sev_class, product, version, cve_data["cve_list"]
            )
            svc_label = _plain_service(port, pinfo)
            urgency_label, urgency_color = _URGENCY_LABELS.get(sev_class, ("À planifier", "#64748b"))

            vulns.append({
                "port":             port,
                "protocol":         proto.upper(),
                "state":            state,
                "service":          svc,
                "service_label":    svc_label,
                "severity_class":   sev_class,
                "severity_text":    sev_text,
                "confidence":       confidence,
                "confidence_label": conf_label,
                "confidence_source": conf_source,
                "exploit_count":    len(found),
                "exploits":         [e.get("Title", "?") for e in found[:3]],
                "recommendation":   recommendation,
                "product":          product,
                "version":          version,
                "desc":             _format_service(pinfo),
                "business_impact":  _BUSINESS_IMPACTS.get(sev_class, ""),
                "urgency_label":    urgency_label,
                "urgency_color":    urgency_color,
                "max_cvss":         cve_data["max_cvss"],
                "cvss_source":      cve_data["source"],
                "cve_list":         cve_data["cve_list"],
            })

    # Tri : ports ouverts d'abord, puis sévérité décroissante
    _state_ord = {"open": 0, "filtered": 1}
    _sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns.sort(key=lambda v: (_state_ord.get(v["state"], 2), _sev_ord.get(v["severity_class"], 4)))

    score, risk = _risk_from_counts(sev_counts)
    closed = max(total_ports - open_count - filtered_count, 0)
    exposure = round((open_count + filtered_count) / total_ports * 100, 1) if total_ports else 0.0
    os_str = scan_mod.get_os(data)

    return {
        "ip":                    ip,
        "os":                    os_str,
        "host_type":             _classify_host_type(os_str, open_ports_set),
        "risk":                  risk,
        "risk_score":            score,
        "open_ports_count":      open_count,
        "filtered_ports_count":  filtered_count,
        "closed_ports_count":    closed,
        "critical_count":        sev_counts["critical"],
        "severity_counts":       sev_counts,
        "vulnerability_density": round(len(vulns) / open_count, 2) if open_count else 0.0,
        "exposure_rate":         exposure,
        "service_inventory":     dict(sorted(services.items())),
        "vulnerabilities":       vulns,
        "unreachable":           False,
    }


def _normalize_discovered(discovered_ips: list | None) -> list[dict]:
    """Normalise une liste str ou dict en list[{"ip": str, "mac": str}]."""
    if not discovered_ips:
        return []
    result = []
    for item in discovered_ips:
        if isinstance(item, str):
            result.append({"ip": item, "mac": "N/A"})
        elif isinstance(item, dict) and "ip" in item:
            result.append({"ip": item["ip"], "mac": item.get("mac", "N/A")})
    return result


def _build_topology(all_hosts: list[dict], hosts: list) -> list:
    """Groupe les hôtes par sous-réseau /24 pour la cartographie."""
    host_by_ip = {h["ip"]: h for h in hosts}
    subnets: dict = {}

    for host_info in all_hosts:
        ip_str = host_info["ip"]
        mac = host_info.get("mac", "N/A")
        try:
            ip_address(ip_str)
            subnet = ip_str.rsplit(".", 1)[0] + ".0/24"
        except (AddressValueError, ValueError):
            subnet = "inconnu"

        if subnet not in subnets:
            subnets[subnet] = []

        host = host_by_ip.get(ip_str, _build_unreachable_host(ip_str, mac))
        entry = dict(host)
        entry["mac"] = mac  # override with ARP-discovered MAC (plus fiable)
        entry["vendor"] = mac_vendor.label(mac)
        last_octet = ip_str.rsplit(".", 1)[-1] if "." in ip_str else ""
        entry["is_gateway"] = last_octet in ("1", "254")
        subnets[subnet].append(entry)

    _risk_order = {"CRITIQUE": 0, "ELEVE": 1, "MODERE": 2, "FAIBLE": 3}
    result = []
    for subnet, subnet_hosts in sorted(subnets.items()):
        subnet_hosts.sort(key=lambda h: (
            not h.get("is_gateway", False),
            [int(p) for p in h["ip"].split(".") if p.isdigit()],
        ))
        subnet_risk = min(
            (h["risk"] for h in subnet_hosts),
            key=lambda r: _risk_order.get(r, 4),
            default="FAIBLE",
        )
        result.append({
            "subnet":     subnet,
            "hosts":      subnet_hosts,
            "host_count": len(subnet_hosts),
            "risk":       subnet_risk,
        })

    return result


def _generate_network_map_image(topology: list) -> str:
    """
    Génère une image PNG (data URI base64) de la cartographie réseau via matplotlib.

    Layout hiérarchique :
      - Nœud racine "RÉSEAU LOCAL" au sommet
      - Rectangles arrondis par sous-réseau (niveau intermédiaire)
      - Cercles colorés par niveau de risque pour chaque hôte (niveau bas)
      - Connexions en traits pleins (LAN→sous-réseau) et pointillés (sous-réseau→hôte)

    Retourne "" si matplotlib n'est pas disponible ou si topology est vide.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.patches as mpatches
        import matplotlib.pyplot as plt
        from matplotlib.patches import Circle, FancyBboxPatch
    except ImportError:
        log.warning("matplotlib non disponible — cartographie image désactivée.")
        return ""

    import base64
    import math
    from io import BytesIO

    if not topology:
        return ""

    RISK_COL = {
        "CRITIQUE": "#dc2626",
        "ELEVE":    "#ea580c",
        "MODERE":   "#d97706",
        "FAIBLE":   "#059669",
    }

    # ── Paramètres de layout ────────────────────────────────────────────────────
    HOSTS_PER_ROW = 5
    H_STEP   = 1.6   # espacement horizontal entre hôtes
    V_STEP   = 1.6   # espacement vertical entre niveaux
    S_GAP    = 0.9   # marge supplémentaire entre blocs sous-réseau
    HOST_R   = 0.32  # rayon des cercles hôtes (unités data)
    ROOT_R   = 0.42  # rayon du nœud racine
    SUB_H    = 0.40  # hauteur du rectangle sous-réseau

    # ── Calcul des largeurs de chaque sous-réseau ───────────────────────────────
    sub_widths = []
    for net in topology:
        cols = min(len(net["hosts"]), HOSTS_PER_ROW) if net["hosts"] else 1
        sub_widths.append(max(cols * H_STEP, H_STEP + 0.6))

    total_w = sum(sub_widths) + (len(topology) - 1) * S_GAP

    # Centres X de chaque sous-réseau
    sub_xs: list[float] = []
    cx = 0.0
    for w in sub_widths:
        sub_xs.append(cx + w / 2)
        cx += w + S_GAP

    root_x = total_w / 2
    root_y = 0.0
    sub_y  = root_y - V_STEP
    host_y_base = sub_y - V_STEP

    max_rows = max(
        math.ceil(len(net["hosts"]) / HOSTS_PER_ROW) if net["hosts"] else 1
        for net in topology
    )

    # ── Taille de la figure ─────────────────────────────────────────────────────
    fig_w = max(total_w * 1.15, 9.0)
    fig_h = (2 + max_rows) * V_STEP + 1.8
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#f8fafc")
    ax.set_aspect("equal")
    ax.axis("off")

    # ── Helpers ─────────────────────────────────────────────────────────────────
    def draw_line(x1, y1, x2, y2, lw=1.2, ls="-", alpha=0.55, color="#94a3b8"):
        ax.plot([x1, x2], [y1, y2], color=color, lw=lw, ls=ls, alpha=alpha,
                solid_capstyle="round", zorder=1)

    def draw_circle(x, y, r, fc, ec="white", lw=1.5, alpha=1.0, zorder=4):
        ax.add_patch(Circle((x, y), r, facecolor=fc, edgecolor=ec,
                             linewidth=lw, alpha=alpha, zorder=zorder))

    # ── Nœud racine ─────────────────────────────────────────────────────────────
    draw_circle(root_x, root_y, ROOT_R, fc="#1a4a7a", ec="#0a2540", lw=2.5, zorder=5)
    ax.text(root_x, root_y + 0.06, "RÉSEAU", ha="center", va="center",
            fontsize=7.5, fontweight="bold", color="white", zorder=6)
    ax.text(root_x, root_y - 0.10, "LOCAL", ha="center", va="center",
            fontsize=7.5, fontweight="bold", color="white", zorder=6)

    # ── Sous-réseaux et hôtes ───────────────────────────────────────────────────
    for net, sx, sw in zip(topology, sub_xs, sub_widths, strict=False):
        net_risk_col = RISK_COL.get(net["risk"], "#64748b")

        # Ligne LAN → sous-réseau
        draw_line(root_x, root_y - ROOT_R, sx, sub_y + SUB_H / 2 + 0.02,
                  lw=1.8, color=net_risk_col, alpha=0.45)

        # Rectangle sous-réseau
        rect_w = max(sw * 0.92, 1.4)
        ax.add_patch(FancyBboxPatch(
            (sx - rect_w / 2, sub_y - SUB_H / 2),
            rect_w, SUB_H,
            boxstyle="round,pad=0.06",
            facecolor=net_risk_col,
            edgecolor="#0a2540",
            linewidth=1.8,
            zorder=4,
        ))
        ax.text(sx, sub_y + 0.06, net["subnet"],
                ha="center", va="center", fontsize=7, fontweight="bold",
                color="white", zorder=5)
        ax.text(sx, sub_y - 0.09, f"{net['host_count']} machine(s)",
                ha="center", va="center", fontsize=5.8, color="white",
                alpha=0.85, zorder=5)

        # Hôtes
        hosts = net["hosts"]
        for j, h in enumerate(hosts):
            col_j = j % HOSTS_PER_ROW
            row_j = j // HOSTS_PER_ROW

            cols_this_row = min(HOSTS_PER_ROW, len(hosts) - row_j * HOSTS_PER_ROW)
            hx = sx + (col_j - (cols_this_row - 1) / 2) * H_STEP
            hy = host_y_base - row_j * V_STEP

            # Ligne sous-réseau → hôte
            draw_line(sx, sub_y - SUB_H / 2, hx, hy + HOST_R + 0.02,
                      lw=0.9, ls=(0, (4, 3)), alpha=0.4)

            if h.get("unreachable"):
                fc, ec, tc, alpha = "#e2e8f0", "#94a3b8", "#64748b", 0.65
            else:
                fc = RISK_COL.get(h["risk"], "#64748b")
                ec, tc, alpha = "white", "white", 1.0

            # Halo passerelle
            if h.get("is_gateway"):
                draw_circle(hx, hy, HOST_R + 0.10, fc="#2d7dd2",
                            ec="none", lw=0, alpha=0.22, zorder=3)

            draw_circle(hx, hy, HOST_R, fc=fc, ec=ec, lw=1.5, alpha=alpha)

            # Lettre type dans le cercle
            type_char = {"server": "S", "workstation": "P"}.get(
                h.get("host_type", ""), "?"
            )
            ax.text(hx, hy + 0.04, type_char, ha="center", va="center",
                    fontsize=8, fontweight="bold", color=tc, zorder=6)

            # IP (2 derniers octets) sous le cercle
            parts = h["ip"].split(".")
            ip_s = ".".join(parts[-2:]) if len(parts) == 4 else h["ip"]
            ax.text(hx, hy - HOST_R - 0.13, ip_s, ha="center", va="top",
                    fontsize=6, color="#475569", zorder=6)

            # Label GW
            if h.get("is_gateway"):
                ax.text(hx, hy - HOST_R - 0.27, "GW", ha="center", va="top",
                        fontsize=5.5, fontweight="bold", color="#2d7dd2", zorder=6)

    # ── Légende ─────────────────────────────────────────────────────────────────
    legend_handles = [
        mpatches.Patch(facecolor="#dc2626", edgecolor="white", label="Critique"),
        mpatches.Patch(facecolor="#ea580c", edgecolor="white", label="Élevé"),
        mpatches.Patch(facecolor="#d97706", edgecolor="white", label="Modéré"),
        mpatches.Patch(facecolor="#059669", edgecolor="white", label="Faible"),
        mpatches.Patch(facecolor="#e2e8f0", edgecolor="#94a3b8", label="Hors ligne"),
        mpatches.Patch(facecolor="#f8fafc", edgecolor="none",
                       label="S = Serveur   P = Poste   ? = Inconnu   GW = Passerelle"),
    ]
    ax.legend(
        handles=legend_handles,
        loc="lower center",
        bbox_to_anchor=(0.5, -0.02),
        ncol=3,
        fontsize=6.5,
        framealpha=0.92,
        fancybox=True,
        edgecolor="#e2e8f0",
    )

    ax.autoscale_view()
    plt.tight_layout(pad=0.4)

    buf = BytesIO()
    try:
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="#f8fafc", edgecolor="none")
    except Exception:
        log.warning("Erreur lors du rendu matplotlib.", exc_info=True)
        plt.close(fig)
        return ""
    plt.close(fig)
    buf.seek(0)
    img_data = buf.read()
    if not img_data:
        log.warning("Image matplotlib vide générée.")
        return ""
    return "data:image/png;base64," + base64.b64encode(img_data).decode()


# ── API publique ───────────────────────────────────────────────────────────────

def build_report_data(
    scan_results: dict,
    total_ports: int = 100,
    cache: dict | None = None,
    discovered_ips: list | None = None,
) -> dict:
    """
    Construit le contexte Jinja2 complet à partir des résultats de scan.

    Args:
        scan_results:   dict ip → nmap.PortScannerHostDict
        total_ports:    Nombre de ports scannés par machine (pour les stats)
        cache:          Cache exploit partagé (optionnel)
        discovered_ips: Liste de toutes les IPs découvertes par ARP/nmap
                        (inclut les hôtes non scannés / inaccessibles)
    """
    if not isinstance(scan_results, dict):
        raise TypeError("scan_results doit être un dict ip → données nmap")
    if total_ports <= 0:
        raise ValueError("total_ports doit être > 0")

    if cache is None:
        cache = {}

    # Normalise discovered_ips : accepte list[str] ou list[dict]
    all_hosts: list[dict] = _normalize_discovered(discovered_ips)
    mac_by_ip: dict[str, str] = {h["ip"]: h["mac"] for h in all_hosts}

    hosts = []
    total_open = total_filtered = 0
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_dist = {"CRITIQUE": 0, "ELEVE": 0, "MODERE": 0, "FAIBLE": 0}
    services_global: dict = {}

    for ip, data in scan_results.items():
        if data is None:
            log.warning("Hôte '%s' : données de scan vides, ajouté comme inaccessible.", ip)
            hosts.append(_build_unreachable_host(ip, mac_by_ip.get(ip, "N/A")))
            risk_dist["FAIBLE"] += 1
            continue
        host = _build_host(ip, data, total_ports, cache)
        host["mac"] = mac_by_ip.get(ip, "N/A")
        host["vendor"] = mac_vendor.label(host["mac"])
        hosts.append(host)
        total_open += host["open_ports_count"]
        total_filtered += host["filtered_ports_count"]
        for sev, n in host["severity_counts"].items():
            sev_totals[sev] += n
        risk_dist[host["risk"]] = risk_dist.get(host["risk"], 0) + 1
        for svc, n in host["service_inventory"].items():
            services_global[svc] = services_global.get(svc, 0) + n

    # Ajouter les hôtes découverts mais non présents dans scan_results
    scanned_ips = set(scan_results.keys())
    for h_info in all_hosts:
        ip = h_info["ip"]
        if ip not in scanned_ips:
            log.info("Hôte '%s' découvert mais absent des résultats : ajouté comme inaccessible.", ip)
            hosts.append(_build_unreachable_host(ip, h_info["mac"]))
            risk_dist["FAIBLE"] += 1

    # Fallback si aucune découverte : on construit all_hosts depuis scan_results
    if not all_hosts:
        all_hosts = [{"ip": ip, "mac": "N/A"} for ip in scan_results]

    # Tri final : risque décroissant, puis IP
    _risk_order = {"CRITIQUE": 0, "ELEVE": 1, "MODERE": 2, "FAIBLE": 3}
    hosts.sort(key=lambda h: (
        _risk_order.get(h["risk"], 4),
        [int(p) for p in h["ip"].split(".") if p.isdigit()],
    ))

    n_hosts = len(hosts)
    n_discovered = len(all_hosts)
    total_possible = total_ports * n_hosts
    total_closed = max(total_possible - total_open - total_filtered, 0)
    global_score, global_risk = _risk_from_counts(sev_totals)
    n_critical = sev_totals["critical"]
    n_vulns = sum(sev_totals.values())
    exposure = round((total_open + total_filtered) / total_possible * 100, 1) if total_possible else 0.0
    stealth = round(total_closed / total_possible * 100, 1) if total_possible else 0.0

    total_v = sum(sev_totals.values()) or 1
    sev_pct = {k: round(v / total_v * 100, 1) for k, v in sev_totals.items()}

    top_services = sorted(services_global.items(), key=lambda x: x[1], reverse=True)[:6]
    topology = _build_topology(all_hosts, hosts)

    # Lance matplotlib en arrière-plan pendant que le reste du contexte est calculé
    _map_executor = ThreadPoolExecutor(max_workers=1)
    _map_future = _map_executor.submit(_generate_network_map_image, topology)

    # Compteurs par type — un seul passage sur hosts
    server_count = workstation_count = unreachable_count = 0
    for _h in hosts:
        _ht = _h.get("host_type")
        if _ht == "server":
            server_count += 1
        elif _ht == "workstation":
            workstation_count += 1
        if _h.get("unreachable"):
            unreachable_count += 1

    action_plan       = _build_action_plan(hosts)
    remediation_guide = _build_remediation_guide(hosts)
    summary_text      = _plain_summary(global_risk, n_hosts, n_critical, n_vulns, risk_dist)

    # Collecte le résultat matplotlib (prêt ou presque prêt à ce stade)
    try:
        network_map_img = _map_future.result(timeout=30)
    except Exception:
        log.warning("Génération de la carte réseau expirée ou échouée.", exc_info=True)
        network_map_img = ""
    finally:
        _map_executor.shutdown(wait=False)

    top_open_ports = _build_top_open_ports(hosts)

    # Résumé par urgence (pour la timeline)
    urgency_summary = {"today": 0, "48h": 0, "2weeks": 0}
    for a in action_plan:
        sev = a["severity_class"]
        if sev == "critical":
            urgency_summary["today"] += 1
        elif sev == "high":
            urgency_summary["48h"] += 1
        elif sev == "medium":
            urgency_summary["2weeks"] += 1

    # Prochaines étapes concrètes
    next_steps: list[str] = []
    if urgency_summary["today"]:
        next_steps.append(
            f"Contacter immédiatement votre responsable informatique "
            f"pour traiter les {urgency_summary['today']} point(s) critique(s) identifié(s)."
        )
    if urgency_summary["48h"]:
        next_steps.append(
            f"Dans les 48 heures, planifier la mise à jour et la sécurisation "
            f"des {urgency_summary['48h']} service(s) à risque élevé."
        )
    if urgency_summary["2weeks"]:
        next_steps.append(
            f"D'ici deux semaines, effectuer une revue de configuration "
            f"pour les {urgency_summary['2weeks']} point(s) modérés."
        )
    if not next_steps:
        next_steps.append(
            "Intégrer les points de vigilance identifiés à votre prochaine maintenance informatique."
        )
    next_steps.append(
        "Conserver ce rapport et le remettre à votre prestataire informatique "
        "pour mise en œuvre des corrections."
    )

    # Déduplication des CVE sur tous les hôtes
    all_cve_ids: set = set()
    for h in hosts:
        for v in h.get("vulnerabilities", []):
            for c in v.get("cve_list", []):
                if isinstance(c, dict) and c.get("cve_id"):
                    all_cve_ids.add(c["cve_id"])
    total_cves = len(all_cve_ids)

    target_ips = [h["ip"] for h in all_hosts]

    # Date affichée : heure locale (lisible par l'utilisateur)
    # Scan ID : UTC pour matcher le nom de fichier généré par generate_report
    _now_local = datetime.datetime.now()
    _now_utc   = datetime.datetime.now(datetime.UTC)
    return {
        "date_scan":              _now_local.strftime("%d/%m/%Y à %H:%M"),
        "scan_id":                f"RE-{_now_utc.strftime('%Y%m%d%H%M%S')}",
        "target_ips":             target_ips,
        "host_count":             n_hosts,
        "discovered_count":       n_discovered,
        "unreachable_count":      unreachable_count,
        "server_count":           server_count,
        "workstation_count":      workstation_count,
        "global_risk":            global_risk,
        "risk_score":             global_score,
        "total_ports":            total_ports,
        "total_possible_ports":   total_possible,
        "open_ports_count":       total_open,
        "filtered_ports_count":   total_filtered,
        "closed_ports_count":     total_closed,
        "critical_count":         n_critical,
        "total_vulnerabilities":  n_vulns,
        "severity_totals":        sev_totals,
        "severity_pct":           sev_pct,
        "host_risk_distribution": risk_dist,
        "critical_hosts_count":   risk_dist["CRITIQUE"],
        "exposure_rate":          exposure,
        "stealth_score":          stealth,
        "service_inventory":      dict(sorted(services_global.items(), key=lambda x: x[1], reverse=True)),
        "top_services":           top_services,
        "topology":               topology,
        "network_map_img":        network_map_img,
        "duration":               "",
        "hosts":                  hosts,
        "action_plan":            action_plan,
        "remediation_guide":      remediation_guide,
        "plain_summary":          summary_text,
        "top_open_ports":         top_open_ports,
        "total_cves":             total_cves,
        "scan_profile":           "",
        "urgency_summary":        urgency_summary,
        "next_steps":             next_steps,
    }


def generate_report(
    scan_results: dict,
    output_path: str | None = None,
    duration: str = "",
    total_ports: int = 100,
    cache: dict | None = None,
    discovered_ips: list | None = None,
    scan_profile: str = "",
) -> str:
    """
    Génère le rapport PDF et retourne son chemin.

    Args:
        scan_results:   dict ip → nmap.PortScannerHostDict
        output_path:    Chemin de sortie (auto-généré si None)
        duration:       Durée du scan lisible (ex: "3 min 42s")
        total_ports:    Nombre de ports scannés par machine
        cache:          Cache exploit partagé (optionnel)
        discovered_ips: Toutes les IPs découvertes (ARP + nmap ping)
    """
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        output_dir = os.environ.get("RECONENGINE_OUTPUT_DIR", "rapports")
        output_path = f"{output_dir}/Rapport_Audit_{ts}.pdf"

    out = pathlib.Path(output_path).resolve()
    # Bloquer les path traversal : le PDF doit rester dans le répertoire de sortie configuré.
    # On ancre sur RECONENGINE_OUTPUT_DIR (ou "rapports" par défaut) plutôt que sur cwd()
    # pour rester correct quelle que soit la working directory au moment de l'appel.
    output_root = pathlib.Path(
        os.environ.get("RECONENGINE_OUTPUT_DIR", "rapports")
    ).resolve()
    if not str(out).startswith(str(output_root) + os.sep):
        raise ValueError(
            f"Chemin de sortie non autorisé (doit être dans {output_root}) : {out}"
        )
    out.parent.mkdir(parents=True, exist_ok=True)

    data = build_report_data(
        scan_results,
        total_ports=total_ports,
        cache=cache,
        discovered_ips=discovered_ips,
    )
    if duration:
        data["duration"] = duration
    if scan_profile:
        data["scan_profile"] = scan_profile

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    html_content = template.render(data)

    def _local_url_fetcher(url: str) -> dict:
        # Autorise :
        #   - data: URIs (contenu inline binaire, ex: PNG base64 matplotlib → carto réseau)
        #   - file:// URIs résolues sous TEMPLATES_DIR (CSS/images du thème)
        # Bloque tout le reste pour éviter le SSRF si un banner nmap injecte du HTML.
        if url.startswith("data:"):
            return default_url_fetcher(url)
        if url.startswith("file://"):
            resolved = pathlib.Path(url.removeprefix("file://")).resolve()
            if str(resolved).startswith(str(TEMPLATES_DIR)):
                return default_url_fetcher(url)
        log.warning("Ressource externe bloquée par le sandbox PDF : %s", url[:120])
        raise URLFetchingError(f"Ressource externe bloquée : {url}")

    log.info("Rendu PDF en cours...")
    # url_fetcher se passe au constructeur HTML(), pas à write_pdf() — sinon
    # WeasyPrint l'ignore silencieusement avec "Unknown rendering option".
    HTML(
        string=html_content,
        base_url=str(TEMPLATES_DIR),
        url_fetcher=_local_url_fetcher,
    ).write_pdf(str(out))
    # 0o644 (et non 0o600) : l'outil tourne en root pour les raw sockets nmap,
    # mais l'utilisateur normal doit pouvoir ouvrir le PDF dans son navigateur.
    os.chmod(out, 0o644)
    log.info("Rapport généré : %s", out)
    return str(out)


if __name__ == "__main__":
    import logging as _log

    import scan as _scan
    _log.basicConfig(level=_log.INFO, format="%(levelname)s  %(message)s")
    print("Scan de test sur 127.0.0.1...")
    result = _scan.scan_host("127.0.0.1", ports="22,80,443,8080", profile="quick")
    if result:
        generate_report({"127.0.0.1": result}, total_ports=4, discovered_ips=["127.0.0.1"])
    else:
        print("Aucun résultat.")
