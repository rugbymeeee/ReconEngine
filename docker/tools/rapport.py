from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
import datetime
import os
import time
import scan as scan_module

SCRIPT_DIR = os.path.dirname(__file__)

# Ports critiques connus qui augmentent le niveau de risque
CRITICAL_PORTS = {21, 23, 445, 135, 139, 3389, 1433, 3306, 5432}
HIGH_RISK_SERVICES = {"smb", "microsoft-ds", "telnet", "ftp", "ms-sql", "mysql", "vnc"}


def _classify_port(port, pinfo, exploits):
    """Classify a port/service into a severity level based on exploits and known risks."""
    name = (pinfo.get("name") or "").lower()
    state = pinfo.get("state", "")

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
    service_label = " ".join(filter(None, [product, version])) or name or "Service inconnu"

    parts = [f"Service détecté : {service_label}."]

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
    """Determine global risk from the list of vulnerability entries."""
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    max_level = 0
    for v in vulnerabilities:
        max_level = max(max_level, severity_order.get(v["severity_class"], 0))
    return {3: "Critique", 2: "Elevé", 1: "Modéré", 0: "Faible"}[max_level]


def _build_host_data(ip, data):
    """Build vulnerability list and stats for a single host."""
    vulns = []
    open_count = 0
    critical_count = 0

    try:
        protocols = data.all_protocols()
    except Exception:
        protocols = []

    for proto in protocols:
        ports = list(data[proto].keys())
        for port in ports:
            pinfo = data[proto][port]
            if pinfo.get("state") != "open":
                continue

            open_count += 1

            software_query = " ".join(filter(None, [
                (pinfo.get("product") or "").strip(),
                (pinfo.get("version") or "").strip(),
            ])).strip() or (pinfo.get("name") or "")
            try:
                exploits = scan_module.find_exploits(software_query)
            except Exception:
                exploits = []

            severity_class, severity_text = _classify_port(port, pinfo, exploits)
            if severity_class == "critical":
                critical_count += 1

            vulns.append({
                "port": port,
                "protocol": proto.upper(),
                "service": _format_service(pinfo),
                "severity_class": severity_class,
                "severity_text": severity_text,
                "desc": _build_description(pinfo, exploits),
            })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns.sort(key=lambda v: severity_order.get(v["severity_class"], 4))

    host_risk = _compute_global_risk(vulns) if vulns else "FAIBLE"

    return {
        "ip": ip,
        "risk": host_risk,
        "open_ports_count": open_count,
        "critical_count": critical_count,
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
    hosts = []
    total_open = 0
    total_critical = 0

    for ip, data in scan_results.items():
        host = _build_host_data(ip, data)
        hosts.append(host)
        total_open += host["open_ports_count"]
        total_critical += host["critical_count"]

    all_vulns = [v for h in hosts for v in h["vulnerabilities"]]
    global_risk = _compute_global_risk(all_vulns) if all_vulns else "FAIBLE"

    summary_parts = [f"{total_open} port(s) ouvert(s) détecté(s) sur {len(hosts)} hôte(s)."]
    if total_critical:
        summary_parts.append(f"{total_critical} vulnérabilité(s) critique(s) identifiée(s). Action immédiate recommandée.")
    else:
        summary_parts.append("Aucune vulnérabilité critique détectée.")

    return {
        "date_scan": datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "target_ips": [ip for ip in scan_results.keys()],
        "host_count": len(hosts),
        "scan_id": f"RE-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "global_risk": global_risk,
        "summary_text": " ".join(summary_parts),
        "total_ports": total_ports_scanned,
        "open_ports_count": total_open,
        "critical_count": total_critical,
        "duration": "",
        "hosts": hosts,
    }


def generate_report(scan_results, output_path=None, duration=None, total_ports=3389):
    """
    Generate a PDF report from scan results.

    Parameters
    ----------
    scan_results : dict
        ip -> nmap host data.
    output_path : str or None
        Where to write the PDF. Defaults to Rapport_Audit_ReconEngine.pdf in cwd.
    duration : str or None
        Human-readable scan duration.
    total_ports : int
        Number of ports scanned.
    """
    if output_path is None:
        output_path = "Rapport_Audit_ReconEngine.pdf"

    data = build_report_data(scan_results, total_ports_scanned=total_ports)
    if duration:
        data["duration"] = duration

    env = Environment(loader=FileSystemLoader(SCRIPT_DIR))
    template = env.get_template("report_template.html")
    html_out = template.render(data)

    print("Génération du PDF...")
    HTML(string=html_out, base_url=SCRIPT_DIR).write_pdf(output_path)
    print(f"Terminé ! Fichier : {output_path}")
    return output_path


if __name__ == "__main__":
    # Quick test with a local scan on localhost
    print("Lancement d'un scan de test sur 127.0.0.1...")
    result = scan_module.scan_host("127.0.0.1", ports="1-1024")
    if result:
        generate_report({"127.0.0.1": result}, total_ports=1024)
    else:
        print("Aucun résultat de scan.")