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
import ipaddress
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
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

import mac_vendor
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
    mac_str = ""
    if mac and mac != "N/A":
        try:
            vendor_label = mac_vendor.label(mac)
        except Exception:
            vendor_label = ""
        vendor_str = f" [green]· {vendor_label}[/]" if vendor_label else ""
        mac_str = f"  [dim]MAC :[/] {mac}{vendor_str}"
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

    # Collecte d'abord : permet de masquer la colonne « Exploits » si aucun hôte
    # n'en a (cas le plus fréquent) → tableau plus compact et lisible.
    collected: list[tuple] = []
    for proto in protocols:
        for port in sorted(data[proto].keys()):
            pinfo = data[proto][port]
            state = pinfo.get("state", "")
            if state not in ("open", "filtered"):
                continue
            query = rapport.software_query(pinfo)
            found = exploits.find(query, cache=cache) if query else []
            exploit_str = " · ".join(e.get("Title", "?") for e in found[:2])
            collected.append((str(port), proto, state, pinfo, exploit_str))

    if not collected:
        console.print("  [yellow]Aucun port ouvert ou filtré détecté.[/]")
        return

    has_exploits = any(row[4] for row in collected)

    table = Table(show_header=True, header_style="bold blue", show_lines=False, expand=False)
    table.add_column("Port",    style="cyan",       justify="right", width=7)
    table.add_column("Proto",   style="dim",         width=6)
    table.add_column("État",                         width=9)
    table.add_column("Service",                      width=16)
    table.add_column("Produit / Version", style="dim")
    if has_exploits:
        table.add_column("Exploits connus", style="red", width=38)

    for port, proto, state, pinfo, exploit_str in collected:
        cells = [
            port,
            proto,
            STATE_DISPLAY.get(state, state),
            pinfo.get("name", "") or "[dim]—[/]",
            _service_str(pinfo) or "[dim]—[/]",
        ]
        if has_exploits:
            cells.append(exploit_str or "[dim]—[/]")
        table.add_row(*cells)

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
    parser.add_argument("--allow-large-nmap", action="store_true", help="Autorise nmap sur grands réseaux si ports limités")
    parser.add_argument("--large-nmap-max-ports", metavar="N", type=int, help="Seuil de ports pour nmap sur grands réseaux (défaut : 16)")
    parser.add_argument("--large-nmap-max-hosts", metavar="N", type=int, help="Limite d'hôtes scannés par nmap sur grands réseaux (défaut : 1024)")
    parser.add_argument("--localhost-first", action="store_true", help="Scanne 127.0.0.1 en premier")
    parser.add_argument("--scan-all", action="store_true", help="Scanne tout le réseau si la découverte est vide")
    parser.add_argument("--scan-all-max-hosts", metavar="N", type=int, help="Limite d'hôtes pour --scan-all (défaut : 1024)")
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
    if args.allow_large_nmap:
        cfg.scan.allow_large_nmap = True
    if args.large_nmap_max_ports:
        cfg.scan.large_nmap_max_ports = cfg_mod._validate_large_nmap_max_ports(args.large_nmap_max_ports)
    if args.large_nmap_max_hosts:
        cfg.scan.large_nmap_max_hosts = cfg_mod._validate_large_nmap_max_hosts(args.large_nmap_max_hosts)

    localhost_first = args.localhost_first
    if not localhost_first:
        env_localhost_first = os.environ.get("RECONENGINE_LOCALHOST_FIRST", "").strip().lower()
        if env_localhost_first in {"1", "true", "yes", "y", "on"}:
            localhost_first = True

    scan_all = args.scan_all
    if not scan_all:
        env_scan_all = os.environ.get("RECONENGINE_SCAN_ALL", "").strip().lower()
        if env_scan_all in {"1", "true", "yes", "y", "on"}:
            scan_all = True

    scan_all_max_hosts = None
    if args.scan_all_max_hosts is not None:
        scan_all_max_hosts = cfg_mod._validate_large_nmap_max_hosts(args.scan_all_max_hosts)
    else:
        env_scan_all_max_hosts = os.environ.get("RECONENGINE_SCAN_ALL_MAX_HOSTS")
        if env_scan_all_max_hosts is not None:
            try:
                scan_all_max_hosts = cfg_mod._validate_large_nmap_max_hosts(int(env_scan_all_max_hosts))
            except ValueError as e:
                log.error("RECONENGINE_SCAN_ALL_MAX_HOSTS invalide : %s", e)
                raise SystemExit(1) from e
        else:
            scan_all_max_hosts = cfg.scan.large_nmap_max_hosts

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
    port_count = _port_count(cfg.scan.ports)
    if cfg.scan.allow_large_nmap and port_count > cfg.scan.large_nmap_max_ports:
        log.warning(
            "allow-large-nmap actif mais ports=%d > seuil=%d — nmap sur grands réseaux sera ignoré.",
            port_count,
            cfg.scan.large_nmap_max_ports,
        )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30, pulse_style="cyan"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as discover_progress:
            discover_task = discover_progress.add_task(
                "Découverte ARP + nmap…", total=None,
            )
            found = [0]  # mutable holder pour closure

            def _on_host(ip: str, mac: str) -> None:
                found[0] += 1
                if mac and mac != "N/A":
                    try:
                        v = mac_vendor.label(mac)
                    except Exception:
                        v = ""
                    vendor_str = f"  [dim]·[/] [green]{v}[/]" if v else ""
                    mac_display = f"[dim]MAC :[/] {mac}{vendor_str}"
                else:
                    mac_display = "[dim]MAC : inconnue[/]"
                discover_progress.console.print(
                    f"  [green]✓[/] [cyan]{ip:<15}[/]  {mac_display}"
                )
                discover_progress.update(
                    discover_task,
                    description=f"Découverte… [bold green]{found[0]}[/] hôte(s) trouvé(s)",
                )

            discovered_hosts = discover.discover(
                iface=args.iface or os.environ.get("RECONENGINE_IFACE") or None,
                network=args.target,
                timeout=cfg.scan.discovery_timeout,
                allow_large_nmap=cfg.scan.allow_large_nmap,
                port_count=port_count,
                large_nmap_max_ports=cfg.scan.large_nmap_max_ports,
                large_nmap_max_hosts=cfg.scan.large_nmap_max_hosts,
                on_host_found=_on_host,
            )
            discover_progress.update(
                discover_task,
                description=f"Découverte terminée — [bold green]{found[0]}[/] hôte(s)",
            )
    except Exception:
        status.set_state(status.State.ERROR)
        status.shutdown()
        raise

    if not discovered_hosts and scan_all:
        networks = []
        local_ips: set[str] = set()
        if args.target:
            networks = [ipaddress.ip_network(args.target, strict=False)]
        else:
            detected, local_ips = discover._interface_networks()
            target_iface = args.iface or os.environ.get("RECONENGINE_IFACE")
            if target_iface:
                networks = [v["network"] for v in detected.values() if v["iface"] == target_iface]
            else:
                networks = [v["network"] for v in detected.values()]

        if networks:
            ips = []
            total_possible = 0
            for net in networks:
                total_possible += max(net.num_addresses - 2, 0)
                for ip in net.hosts():
                    ip_str = str(ip)
                    if ip_str in local_ips:
                        continue
                    ips.append(ip_str)
                    if scan_all_max_hosts and len(ips) >= scan_all_max_hosts:
                        break
                if scan_all_max_hosts and len(ips) >= scan_all_max_hosts:
                    break

            if scan_all_max_hosts and total_possible > scan_all_max_hosts:
                log.warning(
                    "scan-all actif : limite %d hôte(s) appliquée (sur %d possibles).",
                    scan_all_max_hosts,
                    total_possible,
                )
            if ips:
                discovered_hosts = [{"ip": ip, "mac": "N/A"} for ip in ips]
                log.info("scan-all actif : %d hôte(s) chargés pour le scan.", len(ips))
        else:
            log.warning("scan-all actif mais aucun réseau détecté.")

    if localhost_first:
        localhost_ip = "127.0.0.1"
        local_entry = next((h for h in discovered_hosts if h.get("ip") == localhost_ip), None)
        rest = [h for h in discovered_hosts if h.get("ip") != localhost_ip]
        if not local_entry:
            local_entry = {"ip": localhost_ip, "mac": "N/A"}
        discovered_hosts = [local_entry] + rest
        log.info("localhost-first actif : %s scanne en premier", localhost_ip)

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
    # two-phase uniquement si full ET aucun port set explicite par l'utilisateur
    twophase = cfg.scan.profile == "full" and not args.ports

    status.set_state(status.State.SCANNING)
    console.print(
        f"\n[bold]Phase 2[/] — Scan des ports "
        f"([cyan]{cfg.scan.max_workers}[/] thread(s) parallèle(s))"
        + (" · [dim]mode deux phases (TCP complet → services)[/]" if twophase else "")
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

        def _scan_ip(ip: str):
            try:
                if twophase:
                    return scan.scan_host_twophase(ip, cfg.scan.profile)
                return scan.scan_host(ip, cfg.scan.ports, cfg.scan.profile)
            except nmap.PortScannerError as e:
                log.error("Erreur nmap pour %s (vérifier les droits root ou le chemin nmap) : %s", ip, e)
                return None
            except TimeoutError as e:
                log.warning("Timeout scan pour %s : %s", ip, e)
                return None
            except OSError as e:
                log.error("Erreur système lors du scan de %s : %s", ip, e)
                return None
            except Exception as e:
                log.error("Erreur inattendue pour %s [%s] : %s", ip, type(e).__name__, e)
                return None

        remaining_ips = ips
        if localhost_first and ips:
            first_ip = ips[0]
            remaining_ips = ips[1:]
            result = _scan_ip(first_ip)
            progress.advance(task_id)
            if result is not None:
                scan_results[first_ip] = result
            else:
                log.info("Hôte %s : aucun port détecté ou inaccessible", first_ip)

        if remaining_ips:
            with ThreadPoolExecutor(max_workers=cfg.scan.max_workers) as executor:
                futures = {executor.submit(_scan_ip, ip): ip for ip in remaining_ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    progress.advance(task_id)
                    try:
                        result = future.result()
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

    def _set_final_state() -> None:
        critical = rapport.has_critical_exposure(scan_results)
        status.set_state(status.State.DONE_CRITICAL if critical else status.State.DONE_OK)

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
    n_ports = 65535 if twophase else _port_count(cfg.scan.ports)
    output_path = args.output or (
        f"{cfg.output_dir}/Rapport_Audit_"
        f"{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d_%H%M%S')}.pdf"
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
