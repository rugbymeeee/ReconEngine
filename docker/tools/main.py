import os
import sys
import pathlib
import time
import logging
import scan
import discover
import rapport
from rich.console import Console
from rich.table import Table

log = logging.getLogger(__name__)
SCAN_PORT_RANGE = os.environ.get("RECONENGINE_PORT_RANGE", "1-3389")


def _estimate_scanned_port_count(port_range: str) -> int:
    """Estimate scanned ports count from a simple nmap range expression."""
    if not port_range:
        return 3389

    total = 0
    for chunk in str(port_range).split(","):
        value = chunk.strip()
        if not value:
            continue
        if "-" in value:
            try:
                start_str, end_str = value.split("-", 1)
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                log.warning("Invalid port range chunk '%s', fallback to default", value)
                return 3389
            if end < start:
                start, end = end, start
            total += (end - start) + 1
        else:
            try:
                int(value)
            except ValueError:
                log.warning("Invalid port '%s', fallback to default", value)
                return 3389
            total += 1

    return total if total > 0 else 3389


def render_scan_result(console: Console, ip: str, data):
    console.rule(f"Scan results for {ip}")
    try:
        state = data.state()
    except Exception:
        state = "unknown"

    try:
        protocols = data.all_protocols()
    except Exception:
        protocols = []

    if not protocols:
        console.print("No open ports or protocols detected.")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Protocol", style="green")
    table.add_column("State", style="yellow")
    table.add_column("Service", style="white")
    table.add_column("Product/Version", style="dim")
    table.add_column("Exploit(s)", style="red")

    def _format_service_version(pinfo: dict) -> str:
        # Prefer explicit product+version, then extrainfo, then name
        product = pinfo.get("product") or ""
        version = pinfo.get("version") or ""
        extrainfo = pinfo.get("extrainfo") or ""
        # Combine product and version if available
        if product or version:
            s = " ".join(filter(None, [product.strip(), version.strip()])).strip()
            if extrainfo:
                # avoid duplication
                if extrainfo not in s:
                    s = f"{s} ({extrainfo})" if s else extrainfo
            return s
        if extrainfo:
            return extrainfo
        # Fallbacks
        name = pinfo.get("name") or ""
        servicefp = pinfo.get("servicefp") or ""
        return " ".join(filter(None, [name, servicefp])).strip()

    for proto in protocols:
        ports = list(data[proto].keys())
        for port in ports:
            pinfo = data[proto][port]
            st = pinfo.get("state", "")
            name = pinfo.get("name", "")
            prodver = _format_service_version(pinfo)
            # Build a concise software query for searchsploit: prefer product+version, fallback to name
            software_query = "".join(filter(None, [pinfo.get("product") or "", " ", pinfo.get("version") or ""]))
            software_query = software_query.strip() or name
            exploits = []
            try:
                exploits = scan.find_exploits(software_query)
            except Exception:
                exploits = []

            if exploits:
                exploit_summary = "| ".join(e.get("Title", "?") for e in exploits[:2])
            else:
                exploit_summary = ""

            table.add_row(str(port), proto, st, name, prodver, exploit_summary)

    console.print(table)


def main():
    console = Console()
    scan_results = {}
    start_time = time.time()
    try:
        discovered_ips = discover.main()
        if not discovered_ips:
            console.print("No hosts discovered to scan.")
            return
        for ip in discovered_ips:
            console.print(f"[bold blue]Scanning host:[/] {ip}")
            try:
                result = scan.scan_host(ip, ports=SCAN_PORT_RANGE)
            except KeyboardInterrupt:
                console.print(f"\n[yellow]Scan of {ip} interrupted, skipping.[/]")
                break
            if result:
                render_scan_result(console, ip, result)
                scan_results[ip] = result
            else:
                console.print(f"No results for {ip}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")

    elapsed = time.time() - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    duration = f"{minutes} min {seconds}s"

    if scan_results:
        console.print(f"\n[bold green]Generating PDF report...[/]")
        scanned_ports = _estimate_scanned_port_count(SCAN_PORT_RANGE)
        rapport.generate_report(scan_results, duration=duration, total_ports=scanned_ports)
    else:
        console.print("No scan results to report.")


if __name__ == "__main__":
    main()

    