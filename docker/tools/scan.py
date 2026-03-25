import os
import pathlib
import shutil
import nmap
import sys
import logging
import subprocess
import json

log = logging.getLogger(__name__)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
_BUNDLED_NMAP = os.path.join(SCRIPT_DIR, 'nmap', 'nmap')
_ENV_NMAP = os.environ.get('NMAP_PATH')
_SYSTEM_NMAP = shutil.which('nmap')
NMAP_PATH = tuple(p for p in (_ENV_NMAP, _SYSTEM_NMAP, _BUNDLED_NMAP) if p)

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "description": "Scan rapide - Détection basique des ports ouverts",
        "arguments": "-sS -T4 --min-rate 1000"
    },
    "full": {
        "description": "Scan complet - Détection approfondie avec scripts de vulnérabilité",
        "arguments": "-Pn -sS -A --script vuln --script-args mincvss=5.0"
    }
}


def _get_portscanner():
    """Return a configured nmap.PortScanner or raise a helpful RuntimeError."""
    return nmap.PortScanner(nmap_search_path=NMAP_PATH)


def scan_host(ip, ports="1-3389", profile="full", arguments=None):
    """Scan a single host with the specified profile.

    Args:
        ip: IP address to scan
        ports: Port range to scan (default: "1-3389")
        profile: Scan profile to use - "quick" or "full" (default: "full")
        arguments: Custom nmap arguments (overrides profile if provided)
    """
    nm = _get_portscanner()
    if arguments is None:
        arguments = SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["arguments"]
    nm.scan(ip, ports, arguments=arguments)
    return nm[ip] if ip in nm.all_hosts() else None

def scan_network(network, ports="1-3389", profile="full", arguments=None):
    """Scan a network with the specified profile.

    Args:
        network: Network range to scan
        ports: Port range to scan (default: "1-3389")
        profile: Scan profile to use - "quick" or "full" (default: "full")
        arguments: Custom nmap arguments (overrides profile if provided)
    """
    nm = _get_portscanner()
    if arguments is None:
        arguments = SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])["arguments"]
    nm.scan(hosts=network, ports=ports, arguments=arguments)
    results = {}
    for host in nm.all_hosts():
        results[host] = nm[host]
    return results

def save_scan_results(scan_data, output_file):
    with open(output_file, 'w') as f:
        for host, data in scan_data.items():
            f.write(f"Host: {host}\n")
            f.write(f"State: {data.state()}\n")
            f.write("Ports:\n")
            for proto in data.all_protocols():
                lport = data[proto].keys()
                for port in lport:
                    f.write(f"  Port: {port}\tState: {data[proto][port]['state']}\tService: {data[proto][port]['name']}\n")
            f.write("\n")


def find_exploits(software: str, max_results: int = 5):
    """Query searchsploit for exploits matching `software` and return a list of results.

    Returns a list of exploit dicts (may be empty). If `searchsploit` is not available
    or output cannot be parsed, returns an empty list.
    """
    if not software:
        return []
    cmd = ["searchsploit", software, "--json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        log.warning("searchsploit binary not found; exploit enrichment disabled")
        return []

    if res.returncode != 0:
        log.warning("searchsploit returned non-zero status (%s) for query '%s'", res.returncode, software)
        return []

    if not res.stdout:
        return []

    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        log.warning("Invalid JSON from searchsploit for query '%s'", software)
        return []

    results = data.get("RESULTS_EXPLOIT") or []
    return results[:max_results]

