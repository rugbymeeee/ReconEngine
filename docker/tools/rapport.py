from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
import datetime
import logging
import os
import scan as scan_module

SCRIPT_DIR = os.path.dirname(__file__)
log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}
SEVERITY_WEIGHTS = {"critical": 30, "high": 18, "medium": 8, "low": 2}
LEVEL_THRESHOLDS = [
    (75, "CRITIQUE"),
    (50, "ELEVE"),
    (25, "MODERE"),
    (0, "FAIBLE"),
]

# Ports critiques connus qui augmentent le niveau de risque
CRITICAL_PORTS = {
    # --- Protocoles en clair (Mots de passe non chiffrés) ---
    21,    # FTP
    23,    # Telnet
    69,    # TFTP (Aucune authentification requise)
    512, 513, 514, # Rexec, Rlogin, Rsh (Anciens protocoles Unix très vulnérables)
    
    # --- Partages de fichiers et RPC (Mouvements latéraux) ---
    135,   # MSRPC
    139,   # NetBIOS
    445,   # SMB / CIFS (Cible n°1 pour les ransomwares / EternalBlue)
    111,   # RPCBind (Souvent lié à NFS)
    873,   # Rsync (Souvent exposé sans mot de passe)
    2049,  # NFS (Partage de fichiers Linux)
    
    # --- Bases de données (Fuite d'informations critiques) ---
    1433,  # Microsoft SQL Server
    1521,  # Oracle DB
    3306,  # MySQL / MariaDB
    5432,  # PostgreSQL
    6379,  # Redis (Souvent sans authentification, mène à une exécution de code - RCE)
    9200,  # Elasticsearch (Fuite de données massive si exposé)
    11211, # Memcached (Utilisé pour des attaques DDoS ou fuites)
    27017, # MongoDB (Souvent exposé sans auth par défaut)
    
    # --- Prise de contrôle à distance ---
    3389,  # RDP (Bureau à distance Windows)
    5900, 5901, # VNC (Contrôle d'écran)
    
    # --- Infrastructures modernes mal configurées ---
    1099,  # Java RMI (Cible classique pour exécution de code RCE)
    2375, 2376  # API Docker (Si ouvert, donne un accès root immédiat à l'hôte)
}

HIGH_RISK_SERVICES = {
    # Partage et Réseau Windows/Linux
    "smb", "microsoft-ds", "netbios-ssn", 
    "rpcbind", "nfs", "rsync",
    
    # Protocoles en clair
    "ftp", "telnet", "tftp", "rlogin", "rsh", "exec",
    
    # Bases de données
    "ms-sql", "ms-sql-s", "mysql", "postgresql", 
    "oracle-tns", "redis", "mongodb", "elasticsearch", "memcached",
    
    # Accès distants
    "vnc", "ms-wbt-server", # ms-wbt-server est le nom Nmap pour RDP
    "x11", # Interface graphique Linux parfois exposée
    
    # Autres services critiques
    "snmp", # Si version 1 ou 2c, fuite énorme d'infos sur le réseau
    "ldap", "ldaps", # Active Directory (si requêtes anonymes autorisées)
    "java-rmi",
    "docker"
}

def _classify_port(port, pinfo, exploits):
    """Classify a port/service into a severity level based on exploits and known risks."""
    name = (pinfo.get("name") or "").lower()
    state = pinfo.get("state", "")

    if state == "filtered":
        # Filtered ports with exploits are still critical
        if exploits:
            return "critical", "CRITIQUE"
        if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
            return "high", "ELEVE"
        return "low", "FAIBLE"

    if state != "open":
        return "low", "FAIBLE"

    if exploits:
        return "critical", "CRITIQUE"
    if port in CRITICAL_PORTS or name in HIGH_RISK_SERVICES:
        return "high", "ELEVE"
    if port < 1024:
        return "medium", "MOYEN"
    return "low", "FAIBLE"


def _build_description(pinfo, exploits):
    """Build a human-readable description for a vulnerability entry."""
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    name = (pinfo.get("name") or "").strip()
    state = pinfo.get("state", "")
    service_label = " ".join(filter(None, [product, version])) or name or "Service inconnu"

    parts = []
    if state == "filtered":
        parts.append(f"Port filtré — service probable : {service_label}.")
    else:
        parts.append(f"Service détecté : {service_label}.")

    if exploits:
        titles = [e.get("Title", "?") for e in exploits[:3]]
        parts.append("Exploits connus : " + " | ".join(titles) + ".")

    return " ".join(parts)


def _format_service(pinfo):
    """Return a display name for the service."""
    product = (pinfo.get("product") or "").strip()
    version = (pinfo.get("version") or "").strip()
    name = (pinfo.get("name") or "").strip()
    return " ".join(filter(None, [product, version])) or name or "inconnu"


def _compute_global_risk(vulnerabilities):
    """Determine risk score/level from vulnerability entries."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = v.get("severity_class", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return _compute_risk_from_counts(severity_counts)


def _compute_risk_from_counts(severity_counts):
    """Return a normalized score (0-100) and textual level from severity counts."""
    total_items = sum(severity_counts.values())
    if total_items <= 0:
        return 0.0, "FAIBLE"

    weighted = 0
    for severity, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        weighted += weight * max(0, count)

    max_weighted = total_items * SEVERITY_WEIGHTS["critical"]
    score = round((weighted / max_weighted) * 100, 1) if max_weighted else 0.0

    for threshold, label in LEVEL_THRESHOLDS:
        if score >= threshold:
            return score, label
    return score, "FAIBLE"


def _safe_percent(numerator, denominator):
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def _normalize_total_ports(total_ports_scanned):
    try:
        total_ports = int(total_ports_scanned)
    except (TypeError, ValueError):
        raise ValueError("total_ports_scanned must be a positive integer")

    if total_ports <= 0:
        raise ValueError("total_ports_scanned must be greater than 0")
    return total_ports


def _lookup_exploits(software_query, exploit_cache):
    key = (software_query or "").strip().lower()
    if not key:
        return []

    if key in exploit_cache:
        return exploit_cache[key]

    try:
        exploit_cache[key] = scan_module.find_exploits(software_query)
    except Exception:
        log.exception("Exploit lookup failed for query='%s'", software_query)
        exploit_cache[key] = []
    return exploit_cache[key]


def _build_host_data(ip, data, total_ports_scanned, exploit_cache):
    """Build vulnerability list and stats for a single host."""
    vulns = []
    open_count = 0
    filtered_count = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    service_inventory = {}

    try:
        protocols = data.all_protocols()
    except Exception:
        log.exception("Unable to read protocols for host '%s'", ip)
        protocols = []

    for proto in protocols:
        ports = list(data[proto].keys())
        for port in ports:
            pinfo = data[proto][port]
            state = pinfo.get("state", "")

            if state not in ("open", "filtered"):
                continue

            if state == "open":
                open_count += 1
            else:
                filtered_count += 1

            software_query = " ".join(filter(None, [
                (pinfo.get("product") or "").strip(),
                (pinfo.get("version") or "").strip(),
            ])).strip() or (pinfo.get("name") or "")
            exploits = _lookup_exploits(software_query, exploit_cache)

            severity_class, severity_text = _classify_port(port, pinfo, exploits)
            severity_counts[severity_class] = severity_counts.get(severity_class, 0) + 1

            service_name = _format_service(pinfo)
            service_key = (pinfo.get("name") or service_name or "inconnu").strip().lower()
            if service_key:
                service_inventory[service_key] = service_inventory.get(service_key, 0) + 1

            vulns.append({
                "port": port,
                "protocol": proto.upper(),
                "state": state,
                "service": service_name,
                "severity_class": severity_class,
                "severity_text": severity_text,
                "desc": _build_description(pinfo, exploits),
                "exploit_count": len(exploits),
            })

    state_order = {"open": 0, "filtered": 1}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns.sort(key=lambda v: (state_order.get(v["state"], 2), severity_order.get(v["severity_class"], 4)))

    risk_score, risk_level = _compute_global_risk(vulns)
    critical_count = severity_counts["critical"]
    closed_count = max(total_ports_scanned - open_count - filtered_count, 0)
    vuln_density = round(len(vulns) / open_count, 2) if open_count else 0.0
    exposure_rate = _safe_percent(open_count + filtered_count, total_ports_scanned)

    return {
        "ip": ip,
        "risk": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "open_ports_count": open_count,
        "filtered_ports_count": filtered_count,
        "closed_ports_count": closed_count,
        "critical_count": critical_count,
        "severity_counts": severity_counts,
        "vulnerability_density": vuln_density,
        "exposure_rate": exposure_rate,
        "service_inventory": dict(sorted(service_inventory.items())),
        "vulnerabilities": vulns,
    }


def build_report_data(scan_results, total_ports_scanned=3389):
    """
    Build the template data dict from real scan results.

    Parameters
    ----------
    scan_results : dict
        Mapping of ip -> nmap host data (as returned by scan.scan_host or scan.scan_network).
    total_ports_scanned : int
        Number of ports that were scanned (for stats).

    Returns a dict ready to be passed to the Jinja2 template.
    """
    if not isinstance(scan_results, dict):
        raise ValueError("scan_results must be a dict mapping ip -> host data")

    total_ports_scanned = _normalize_total_ports(total_ports_scanned)
    hosts = []
    total_open = 0
    total_filtered = 0
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    host_risk_distribution = {"CRITIQUE": 0, "ELEVE": 0, "MODERE": 0, "FAIBLE": 0}
    service_inventory_global = {}
    exploit_cache = {}

    for ip, data in scan_results.items():
        if data is None:
            log.warning("Skipping host '%s': empty scan data", ip)
            continue

        host = _build_host_data(ip, data, total_ports_scanned, exploit_cache)
        hosts.append(host)
        total_open += host["open_ports_count"]
        total_filtered += host["filtered_ports_count"]
        for severity, count in host["severity_counts"].items():
            severity_totals[severity] = severity_totals.get(severity, 0) + count
        host_risk_distribution[host["risk_level"]] = host_risk_distribution.get(host["risk_level"], 0) + 1
        for svc, count in host["service_inventory"].items():
            service_inventory_global[svc] = service_inventory_global.get(svc, 0) + count

    total_hosts = len(hosts)
    total_possible_ports = total_ports_scanned * total_hosts
    total_closed = max(total_possible_ports - total_open - total_filtered, 0)

    global_score, global_risk = _compute_risk_from_counts(severity_totals)
    total_critical = severity_totals["critical"]
    total_vulnerabilities = sum(severity_totals.values())
    exposure_rate = _safe_percent(total_open + total_filtered, total_possible_ports)
    stealth_score = _safe_percent(total_closed, total_possible_ports)
    critical_hosts_count = host_risk_distribution["CRITIQUE"]

    summary_parts = []
    summary_parts.append(
        f"{total_open} port(s) ouvert(s), {total_filtered} port(s) filtré(s) et {total_closed} port(s) fermé(s) "
        f"sur {total_hosts} hôte(s)."
    )
    summary_parts.append(
        f"Exposition globale: {exposure_rate}% | Score de discrétion: {stealth_score}%."
    )
    if total_critical:
        summary_parts.append(
            f"{total_critical} vulnérabilité(s) critique(s) identifiée(s), "
            f"dont {critical_hosts_count} hôte(s) au niveau CRITIQUE."
        )
    else:
        summary_parts.append("Aucune vulnérabilité critique détectée.")

    return {
        "date_scan": datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "target_ips": [ip for ip in scan_results.keys()],
        "host_count": total_hosts,
        "scan_id": f"RE-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "global_risk": global_risk,
        "risk_score": global_score,
        "summary_text": " ".join(summary_parts),
        "total_ports": total_ports_scanned,
        "total_possible_ports": total_possible_ports,
        "open_ports_count": total_open,
        "filtered_ports_count": total_filtered,
        "closed_ports_count": total_closed,
        "critical_count": total_critical,
        "total_vulnerabilities": total_vulnerabilities,
        "severity_totals": severity_totals,
        "host_risk_distribution": host_risk_distribution,
        "critical_hosts_count": critical_hosts_count,
        "exposure_rate": exposure_rate,
        "stealth_score": stealth_score,
        "service_inventory": dict(sorted(service_inventory_global.items(), key=lambda item: item[1], reverse=True)),
        "top_services": sorted(service_inventory_global.items(), key=lambda item: item[1], reverse=True)[:6],
        "duration": "",
        "hosts": hosts,
    }


def generate_report(scan_results, output_path=None, duration=None, total_ports=3389):
    if output_path is None:
        output_path = f"rapports/Rapport_Audit_ReconEngine_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    # Create rapports directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    data = build_report_data(scan_results, total_ports_scanned=total_ports)
    if duration:
        data["duration"] = duration

    env = Environment(loader=FileSystemLoader(SCRIPT_DIR))
    template = env.get_template("report_template.html")
    html_out = template.render(data)

    print("Generation du PDF...")
    HTML(string=html_out, base_url=SCRIPT_DIR).write_pdf(output_path)
    print(f"Termine ! Fichier : {output_path}")
    return output_path


if __name__ == "__main__":
    # Quick test with a local scan on localhost
    print("Lancement d'un scan de test sur 127.0.0.1...")
    result = scan_module.scan_host("127.0.0.1", ports="1-1024")
    if result:
        generate_report({"127.0.0.1": result}, total_ports=1024)
    else:
        print("Aucun résultat de scan.")