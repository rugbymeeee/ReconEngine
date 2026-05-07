import os
import sys
import pathlib
import time
import scan
import discover
import rapport
from rich.console import Console
from rich.table import Table


def _safe_call(func, default):
    try:
        return func()
    except Exception:
        return default


def render_scan_result(console: Console, ip: str, data):
    console.rule(f"Scan results for {ip}")
    state = _safe_call(data.state, "unknown")
    protocols = _safe_call(data.all_protocols, [])

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
    try:
        console = Console()
        discovered_ips = discover.main()
        if not discovered_ips:
            console.print("No hosts discovered to scan.")
            return
        scan_results = {}
        start_time = time.time()
        for ip in discovered_ips:
            console.print(f"[bold blue]Scanning host:[/] {ip}")
            result = scan.scan_host(ip)
            if result:
                render_scan_result(console, ip, result)
                scan_results[ip] = result
            else:
                console.print(f"No results for {ip}")
        elapsed = time.time() - start_time
        minutes, seconds = divmod(int(elapsed), 60)
        duration = f"{minutes} min {seconds}s"

        if scan_results:
            console.print("\n[bold green]Generating PDF report...[/]")
            rapport.generate_report(scan_results, duration=duration)
        else:
            console.print("No scan results to report.")
    except KeyboardInterrupt:
        console.print("\nScan interrupted by user. Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()

    