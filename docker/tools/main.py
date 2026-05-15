"""
ReconEngine — point d'entrée principal.

Pipeline en 4 phases :
  1. Découverte des hôtes (ARP + nmap ping)
  2. Scan parallèle des ports (ThreadPoolExecutor)
  3. Affichage terminal des résultats (Rich)
  4. Génération du rapport PDF (WeasyPrint)

Usage :
  python main.py [quick|full] [-t CIDR] [-i IFACE] [-o OUTPUT] [--ports PORTS] [--workers N] [--timeout SEC]
"""
import argparse
import datetime
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import config as cfg_mod
import discover
import exploits
import nmap
import rapport
import scan
import status
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

cfg_mod.setup_logging()
log = logging.getLogger(__name__)

STATE_DISPLAY = {
    "open": "[green]ouvert[/]",
    "filtered": "[yellow]filtré[/]",
}


def _service_str(pinfo: dict) -> str:
    p = (pinfo.get("product") or "").strip()
    v = (pinfo.get("version") or "").strip()
    extra = (pinfo.get("extrainfo") or "").strip()
    s = " ".join(filter(None, [p, v]))
    if extra and extra not in s:
        s = f"{s} ({extra})" if s else extra
    return s or (pinfo.get("name") or "")


def _port_count(port_spec: str) -> int:
    """Compte le nombre de ports dans une expression nmap (ex: '22,80,1-1024')."""
    total = 0
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                total += abs(int(b) - int(a)) + 1
            except ValueError:
                log.warning("Plage de ports invalide : '%s'", chunk)
        else:
            try:
                int(chunk)
                total += 1
            except ValueError:
                log.warning("Port invalide : '%s'", chunk)
    return total or 1


def render_host(console: Console, ip: str, data, cache: dict, mac: str = "N/A") -> None:
    """Affiche les résultats d'un hôte dans le terminal."""
    mac_str = f"  [dim]MAC :[/] {mac}" if mac and mac != "N/A" else ""
    console.rule(f"[bold cyan]{ip}[/]{mac_str}")

    os_str = scan.get_os(data)
    if os_str:
        console.print(f"  [dim]OS détecté :[/] {os_str}")

    try:
        protocols = data.all_protocols()
    except Exception:
        protocols = []

    if not protocols:
        console.print("  [yellow]Aucun port détecté.[/]")
        return

    table = Table(show_header=True, header_style="bold blue", show_lines=False, expand=False)
    table.add_column("Port",    style="cyan",       justify="right", width=7)
    table.add_column("Proto",   style="dim",         width=6)
    table.add_column("État",                         width=9)
    table.add_column("Service",                      width=16)
    table.add_column("Produit / Version", style="dim")
    table.add_column("Exploits connus",  style="red", width=38)

    rows = 0
    for proto in protocols:
        for port in sorted(data[proto].keys()):
            pinfo = data[proto][port]
            state = pinfo.get("state", "")
            if state not in ("open", "filtered"):
                continue
            query = rapport.software_query(pinfo)
            found = exploits.find(query, cache=cache) if query else []
            exploit_str = " · ".join(e.get("Title", "?") for e in found[:2])
            table.add_row(
                str(port),
                proto,
                STATE_DISPLAY.get(state, state),
                pinfo.get("name", ""),
                _service_str(pinfo),
                exploit_str,
            )
            rows += 1

    if rows == 0:
        console.print("  [yellow]Aucun port ouvert ou filtré détecté.[/]")
        return

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="reconengine",
        description="ReconEngine — Reconnaissance réseau et audit de sécurité",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python main.py quick\n"
            "  python main.py full -t 192.168.1.0/24\n"
            "  python main.py -i eth0 --ports 22,80,443,8080\n"
        ),
    )
    parser.add_argument(
        "profile",
        nargs="?",
        choices=list(cfg_mod.SCAN_PROFILES.keys()),
        default=None,
        metavar="PROFILE",
        help=f"Profil : {', '.join(cfg_mod.SCAN_PROFILES.keys())} (défaut : config ou 'full')",
    )
    parser.add_argument("-t", "--target",  metavar="CIDR",  help="Réseau ou IP cible (ex: 192.168.1.0/24)")
    parser.add_argument("-i", "--iface",   metavar="IFACE", help="Interface réseau (ex: eth0)")
    parser.add_argument("-o", "--output",  metavar="PATH",  help="Chemin du rapport PDF de sortie")
    parser.add_argument("--ports",         metavar="PORTS", help="Ports à scanner (ex: 22,80,443 ou 1-1024)")
    parser.add_argument("--workers",       metavar="N",     type=int, help="Threads parallèles (défaut : 8)")
    parser.add_argument("--timeout",       metavar="SEC",   type=int, help="Délai découverte ARP en secondes (défaut : 5)")
    parser.add_argument("--no-pdf",        action="store_true", help="Affiche les résultats terminal uniquement, sans générer de PDF")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche les messages de débogage (logging DEBUG)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = cfg_mod.Config.load()
    if args.profile:
        cfg.scan.profile = args.profile
    if args.ports:
        cfg.scan.ports = args.ports
    if args.workers:
        cfg.scan.max_workers = args.workers
    if args.timeout:
        cfg.scan.discovery_timeout = args.timeout

    console = Console()
    profile_info = cfg_mod.SCAN_PROFILES.get(cfg.scan.profile, cfg_mod.SCAN_PROFILES["full"])

    ports_preview = cfg.scan.ports[:72] + ("…" if len(cfg.scan.ports) > 72 else "")
    console.print(Panel.fit(
        f"[bold]ReconEngine[/]  ·  Profil : [cyan]{cfg.scan.profile}[/]\n"
        f"[dim]{profile_info['description']}[/]\n"
        f"[yellow]Ports :[/] {ports_preview}",
        border_style="blue",
        padding=(0, 1),
    ))

    # ── Phase 1 : Découverte ───────────────────────────────────────────────────
    start = time.monotonic()
    status.set_state(status.State.DISCOVERING)
    console.print("\n[bold]Phase 1[/] — Découverte des hôtes")
    try:
        discovered_hosts = discover.discover(
            iface=args.iface or os.environ.get("RECONENGINE_IFACE") or None,
            network=args.target,
            timeout=cfg.scan.discovery_timeout,
        )
    except Exception:
        status.set_state(status.State.ERROR)
        status.shutdown()
        raise
    ips = [h["ip"] for h in discovered_hosts]

    if not ips:
        status.set_state(status.State.ERROR)
        console.print("[red]Aucun hôte découvert. Vérifiez les droits root et l'interface réseau.[/]")
        status.shutdown()
        sys.exit(0)

    console.print(f"[green]{len(ips)} hôte(s) découvert(s)[/] — lancement du scan...")

    # ── Phase 2 : Scan parallèle ───────────────────────────────────────────────
    exploit_cache: dict = {}
    scan_results: dict = {}

    status.set_state(status.State.SCANNING)
    console.print(
        f"\n[bold]Phase 2[/] — Scan des ports "
        f"([cyan]{cfg.scan.max_workers}[/] thread(s) parallèle(s))"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Scan en cours…", total=len(ips))

        with ThreadPoolExecutor(max_workers=cfg.scan.max_workers) as executor:
            futures = {
                executor.submit(scan.scan_host, ip, cfg.scan.ports, cfg.scan.profile): ip
                for ip in ips
            }
            for future in as_completed(futures):
                ip = futures[future]
                progress.advance(task_id)
                try:
                    result = future.result()
                except nmap.PortScannerError as e:
                    log.error("Erreur nmap pour %s (vérifier les droits root ou le chemin nmap) : %s", ip, e)
                    result = None
                except TimeoutError as e:
                    log.warning("Timeout scan pour %s : %s", ip, e)
                    result = None
                except OSError as e:
                    log.error("Erreur système lors du scan de %s : %s", ip, e)
                    result = None
                except Exception as e:
                    log.error("Erreur inattendue pour %s [%s] : %s", ip, type(e).__name__, e)
                    result = None
                if result is not None:
                    scan_results[ip] = result
                else:
                    log.info("Hôte %s : aucun port détecté ou inaccessible", ip)

    elapsed = time.monotonic() - start
    m, s = divmod(int(elapsed), 60)
    duration = f"{m} min {s}s"

    # ── Phase 3 : Affichage terminal ───────────────────────────────────────────
    mac_by_ip = {h["ip"]: h.get("mac", "N/A") for h in discovered_hosts}
    unreachable_ips = [h["ip"] for h in discovered_hosts if h["ip"] not in scan_results]
    console.print(
        f"\n[bold]Phase 3[/] — Résultats "
        f"([cyan]{len(scan_results)}[/] scanné(s), "
        f"[yellow]{len(unreachable_ips)}[/] inaccessible(s))"
    )
    for ip, data in scan_results.items():
        render_host(console, ip, data, exploit_cache, mac=mac_by_ip.get(ip, "N/A"))

    if unreachable_ips:
        console.rule("[dim]Hôtes inaccessibles (ARP découvert, scan échoué)[/]")
        for ip in unreachable_ips:
            console.print(f"  [dim]⊘ {ip}[/]  [red]aucune réponse au scan TCP[/]")

    if not scan_results:
        status.set_state(status.State.ERROR)
        console.print("[yellow]Aucun résultat à reporter.[/]")
        status.shutdown()
        sys.exit(0)

    console.print(f"[dim]Durée totale : {duration}[/]")

    # Indicateur final basé sur la sévérité max trouvée
    def _set_final_state() -> None:
        any_critical = False
        for data in scan_results.values():
            try:
                for proto in data.all_protocols():
                    for port in data[proto]:
                        pinfo = data[proto][port]
                        if pinfo.get("state") != "open":
                            continue
                        # Port critique ou service à risque élevé → flag critical
                        if (port in rapport.CRITICAL_PORTS
                                or (pinfo.get("name") or "").lower() in rapport.HIGH_RISK_SERVICES):
                            any_critical = True
                            break
                    if any_critical:
                        break
            except Exception:
                continue
            if any_critical:
                break
        status.set_state(status.State.DONE_CRITICAL if any_critical else status.State.DONE_OK)

    if args.no_pdf:
        _set_final_state()
        console.print("[dim]Option --no-pdf : génération du rapport PDF ignorée.[/]")
        # On laisse les LEDs allumées un instant pour que le statut soit visible
        time.sleep(2)
        status.shutdown()
        sys.exit(0)

    # ── Phase 4 : Rapport PDF ──────────────────────────────────────────────────
    status.set_state(status.State.REPORTING)
    console.print("\n[bold]Phase 4[/] — Génération du rapport PDF")
    n_ports = _port_count(cfg.scan.ports)
    output_path = args.output or (
        f"{cfg.output_dir}/Rapport_Audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    try:
        out = rapport.generate_report(
            scan_results,
            output_path=output_path,
            duration=duration,
            total_ports=n_ports,
            cache=exploit_cache,
            discovered_ips=discovered_hosts,
            scan_profile=cfg.scan.profile,
        )
    except Exception:
        status.set_state(status.State.ERROR)
        status.shutdown()
        raise
    _set_final_state()
    console.print(f"\n[bold green]✓ Rapport généré :[/] {out}")
    # Garder le statut final visible avant de rendre la main
    time.sleep(2)
    status.shutdown()


if __name__ == "__main__":
    main()
