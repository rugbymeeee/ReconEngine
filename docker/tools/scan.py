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
# Prefer an explicit env var, then system `nmap`, then bundled path
_BUNDLED_NMAP = os.path.join(SCRIPT_DIR, 'nmap', 'nmap')
_ENV_NMAP = os.environ.get('NMAP_PATH')
_SYSTEM_NMAP = shutil.which('nmap')
# Build a tuple of candidate paths for python-nmap to search
NMAP_PATH = tuple(p for p in (_ENV_NMAP, _SYSTEM_NMAP, _BUNDLED_NMAP) if p)


def _get_portscanner():
    """Return a configured nmap.PortScanner or raise a helpful RuntimeError."""
    return nmap.PortScanner(nmap_search_path=NMAP_PATH)


def scan_host(ip, ports="1-3389", arguments="-Pn -sV -T4 --min-rate 1000"):
    nm = _get_portscanner()
    nm.scan(ip, ports, arguments=arguments)
    return nm[ip] if ip in nm.all_hosts() else None

def scan_network(network, ports="1-3389", arguments="-Pn -sV -T4 --min-rate 1000"):
    nm = _get_portscanner()
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
        # searchsploit not installed on host
        return []

    if not res.stdout:
        return []

    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []

    results = data.get("RESULTS_EXPLOIT") or []
    return results[:max_results]

