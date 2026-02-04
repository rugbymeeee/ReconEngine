import os
import pathlib
import nmap

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
NMAP_PATH = os.path.join(SCRIPT_DIR, 'nmap', 'nmap')


def scan_host(ip, ports="1-65535", arguments="-Pn -sS -sV -O --script vuln"):
    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    nm.scan(ip, ports, arguments=arguments)
    return nm[ip] if ip in nm.all_hosts() else None

def scan_network(network, ports="1-65535", arguments="-Pn -sS -sV -O --script vuln"):
    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
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

