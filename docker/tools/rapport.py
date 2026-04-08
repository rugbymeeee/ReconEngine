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

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

import cve as cve_mod
import exploits as exploit_mod
import scan as scan_mod

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

# ── Recommandations par niveau ─────────────────────────────────────────────────
RECOMMENDATIONS = {
    "critical": (
        "Désactiver ou isoler immédiatement le service. "
        "Appliquer les correctifs CVE disponibles. "
        "Analyser les journaux pour toute trace de compromission."
    ),
    "high": (
        "Restreindre l'accès via liste d'autorisation pare-feu. "
        "Mettre à jour vers la dernière version stable. "
        "Activer l'authentification forte si possible."
    ),
    "medium": (
        "Audit de configuration recommandé. "
        "Surveiller les tentatives d'accès anormales. "
        "Désactiver si le service est non essentiel."
    ),
    "low": "Surveillance passive recommandée. Aucune action immédiate requise.",
}


ACTION_PLAN_MAX_ITEMS = 25

# ── Textes client (non-technique) ─────────────────────────────────────────────
_PLAIN_INTROS = {
    "CRITIQUE": (
        "L'audit révèle une situation préoccupante : des failles critiques ont été identifiées "
        "sur votre réseau. Ces vulnérabilités pourraient permettre à une personne malveillante "
        "d'accéder à vos systèmes, de voler des données sensibles ou de perturber vos activités."
    ),
    "ELEVE": (
        "L'audit révèle des failles importantes sur votre réseau. "
        "Plusieurs points nécessitent une attention rapide pour éviter tout incident de sécurité."
    ),
    "MODERE": (
        "Votre réseau présente un niveau de sécurité convenable, mais quelques points méritent "
        "attention. Les problèmes identifiés ne sont pas urgents mais doivent être traités "
        "dans un délai raisonnable."
    ),
    "FAIBLE": (
        "Votre réseau présente un bon niveau de sécurité. "
        "L'audit n'a identifié que des risques mineurs pouvant être traités progressivement."
    ),
}

_ACTION_LABELS = {
    "critical": "Désactiver ou isoler immédiatement ce service. Risque d'intrusion immédiat.",
    "high":     "Restreindre l'accès réseau à ce service et appliquer les mises à jour disponibles.",
    "medium":   "Vérifier la configuration du service et désactiver s'il n'est pas indispensable.",
}


def _plain_summary(
    global_risk: str,
    n_hosts: int,
    n_critical: int,
    n_vulns: int,
    risk_dist: dict,
) -> str:
    """Génère un texte d'explication en français simple pour un lecteur non-technique."""
    intro = _PLAIN_INTROS.get(global_risk, _PLAIN_INTROS["FAIBLE"])
    parts: list[str] = [f"{n_hosts} machine(s) ont été analysées sur ce réseau."]
    if n_critical:
        parts.append(
            f"{n_critical} vulnérabilité(s) critique(s) nécessitent une intervention immédiate."
        )
    other = n_vulns - n_critical
    if other > 0:
        parts.append(f"{other} autre(s) point(s) de sécurité ont également été répertoriés.")
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
            actions.append({
                "ip":             host["ip"],
                "port":           v["port"],
                "service":        v["service"] or f"Port {v['port']}",
                "severity_class": sev,
                "severity_text":  v["severity_text"],
                "action":         _ACTION_LABELS[sev],
                "has_exploits":   v["exploit_count"] > 0,
            })
    actions.sort(key=lambda a: (_sev_order[a["severity_class"]], a["ip"], a["port"]))
    for i, a in enumerate(actions, 1):
        a["num"] = i
    return actions[:ACTION_PLAN_MAX_ITEMS]


# ── Fonctions internes ─────────────────────────────────────────────────────────

def _classify(
    port: int,
    pinfo: dict,
    found_exploits: list,
    cve_data: dict | None = None,
) -> tuple[str, str]:
    """
    Retourne (severity_class, severity_text) pour un port/service.

    Hiérarchie de classification :
      1. Score CVSS réel (NVD / scripts nmap) — source la plus fiable
      2. Exploit public searchsploit sans score CVSS → critical (exploitabilité prouvée)
      3. Port critique ou service à risque élevé → high
      4. Port < 1024 (service privilégié) → medium
      5. Sinon → low
    """
    name = (pinfo.get("name") or "").lower()
    state = pinfo.get("state", "")

    if state not in ("open", "filtered"):
        return "low", "FAIBLE"

    # ── Priorité 1 : CVSS réel ───────────────────────────────────────────────
    if cve_data and cve_data.get("max_cvss", 0.0) > 0.0:
        sev_class, sev_text = cve_data["severity_class"], cve_data["severity_text"]
        # Un exploit public connu ne peut pas abaisser la sévérité sous "high"
        if found_exploits and sev_class not in ("critical", "high"):
            return "high", "ELEVE"
        return sev_class, sev_text

    # ── Priorité 2 : exploit searchsploit sans score CVSS ───────────────────
    if found_exploits:
        return "critical", "CRITIQUE"

    # ── Priorité 3 : heuristiques port/service ───────────────────────────────
    if state == "filtered":
        if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
            return "high", "ELEVE"
        return "low", "FAIBLE"

    # state == "open"
    if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
        return "high", "ELEVE"
    if port < 1024:
        return "medium", "MODERE"
    return "low", "FAIBLE"


def _format_service(pinfo: dict) -> str:
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    name = (pinfo.get("name") or "").strip()
    return " ".join(filter(None, [product, version])) or name or "inconnu"


def software_query(pinfo: dict) -> str:
    """Construit la chaîne de recherche exploit la plus précise possible."""
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    return " ".join(filter(None, [product, version])) or (pinfo.get("name") or "")


_software_query = software_query


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
        for port in data[proto].keys():
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
            query = _software_query(pinfo)
            found = exploit_mod.find(query, cache=cache)

            sev_class, sev_text = _classify(port, pinfo, found, cve_data)
            sev_counts[sev_class] += 1

            svc = _format_service(pinfo)
            svc_key = (pinfo.get("name") or svc or "inconnu").strip().lower()
            services[svc_key] = services.get(svc_key, 0) + 1

            vulns.append({
                "port":           port,
                "protocol":       proto.upper(),
                "state":          state,
                "service":        svc,
                "severity_class": sev_class,
                "severity_text":  sev_text,
                "exploit_count":  len(found),
                "exploits":       [e.get("Title", "?") for e in found[:3]],
                "recommendation": RECOMMENDATIONS[sev_class],
                "product":        product,
                "version":        version,
                "desc":           _format_service(pinfo),
                # CVE/CVSS
                "max_cvss":       cve_data["max_cvss"],
                "cvss_source":    cve_data["source"],
                "cve_list":       cve_data["cve_list"],
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
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.patches import FancyBboxPatch, Circle
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
    for i, (net, sx, sw) in enumerate(zip(topology, sub_xs, sub_widths)):
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

    action_plan = _build_action_plan(hosts)
    summary_text = _plain_summary(global_risk, n_hosts, n_critical, n_vulns, risk_dist)

    # Collecte le résultat matplotlib (prêt ou presque prêt à ce stade)
    try:
        network_map_img = _map_future.result(timeout=30)
    except Exception:
        log.warning("Génération de la carte réseau expirée ou échouée.", exc_info=True)
        network_map_img = ""
    finally:
        _map_executor.shutdown(wait=False)

    target_ips = [h["ip"] for h in all_hosts]

    return {
        "date_scan":              datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "scan_id":                f"RE-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
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
        "plain_summary":          summary_text,
    }


def generate_report(
    scan_results: dict,
    output_path: str | None = None,
    duration: str = "",
    total_ports: int = 100,
    cache: dict | None = None,
    discovered_ips: list | None = None,
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
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        output_path = f"rapports/Rapport_Audit_{ts}.pdf"

    out = pathlib.Path(output_path).resolve()
    # Bloquer les path traversal : le PDF doit rester dans le répertoire de travail courant
    try:
        out.relative_to(pathlib.Path.cwd())
    except ValueError:
        raise ValueError(
            f"Chemin de sortie non autorisé (hors du répertoire courant) : {out}"
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

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    template = env.get_template("report.html")
    html_content = template.render(data)

    log.info("Rendu PDF en cours...")
    HTML(string=html_content, base_url=str(TEMPLATES_DIR)).write_pdf(str(out))
    os.chmod(out, 0o600)
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
