"""
Découverte d'hôtes sur le réseau local.

Stratégie :
  1. ARP broadcast (Scapy) — rapide, fonctionne sur tout type de réseau, nécessite root.
  2. nmap ping sweep (-sn) — lancé en parallèle de l'ARP sur les petits réseaux,
     ou seul si root non disponible.

Point d'entrée public : discover(iface, network, timeout) → list[str]
"""
import ipaddress
import itertools
import logging
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False  # Windows — _get_netmask() retourne None, fallback /24

import nmap
import scan
from scapy.all import arping, get_if_addr, get_if_list

log = logging.getLogger(__name__)

_NMAP_MAX_PREFIX = 24  # nmap ping sweep uniquement sur réseaux ≤ /24


def _port_count(port_spec: str) -> int:
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


def _is_root() -> bool:
    return os.geteuid() == 0


def _get_netmask(ifname: str) -> str | None:
    """Netmask via ioctl SIOCGIFNETMASK (Linux uniquement). Retourne None sur Windows."""
    if not _HAS_FCNTL:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            result = fcntl.ioctl(
                s.fileno(), 0x891B,
                struct.pack("256s", ifname.encode()[:15]),
            )
        return socket.inet_ntoa(result[20:24])
    except Exception:
        return None


def _interface_networks() -> tuple[dict, set]:
    """Énumère toutes les interfaces et retourne (réseaux, IPs_locales)."""
    networks: dict = {}
    local_ips: set = set()

    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if not ip or ip.startswith("127.") or ip.startswith("169.254.") or ip == "0.0.0.0":
                continue
            local_ips.add(ip)
            netmask = _get_netmask(iface)
            mask = netmask if (netmask and netmask != "0.0.0.0") else "24"
            net = ipaddress.ip_network(
                f"{ip}/{mask}",
                strict=False,
            )
            if net.prefixlen < 8:  # ignore les réseaux absurdement larges
                continue
            net_str = str(net)
            if net_str not in networks:
                networks[net_str] = {"iface": iface, "network": net}
        except Exception:
            continue

    return networks, local_ips


def _arp_scan(network: ipaddress.IPv4Network, timeout: int = 5, retry: int = 2) -> dict:
    """
    ARP broadcast sur le réseau. Retourne {ip: {"ip": str, "mac": str}}.

    `retry` passes avec inter=0 (rafale de paquets) — sur Ethernet 1 suffit,
    mais 2 passes capturent les hôtes qui dormaient brièvement (ACPI, etc.).
    """
    if not _is_root():
        log.warning("[ARP] Ignoré — droits root requis.")
        return {}
    # Sur les grands réseaux, beaucoup d'hôtes à interroger → timeout plus long.
    if network.prefixlen <= 16:
        timeout = max(timeout, 30)   # /16 = 65536 hôtes
    elif network.prefixlen <= 20:
        timeout = max(timeout, 15)   # /17–/20

    hosts: dict = {}
    for _ in range(max(1, retry)):
        try:
            ans, _ = arping(str(network), timeout=timeout, verbose=False, inter=0)
            for _, rcv in ans:
                ip = rcv.psrc
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "mac": rcv.hwsrc}
        except PermissionError:
            log.error("[ARP] Permission refusée (nécessite root).")
            break  # unrecoverable — root required
        except Exception as e:
            msg = str(e)
            log.warning("[ARP] Erreur : %s", e)
            if "Failed to compile filter expression" in msg or "Cannot set filter" in msg:
                if network.prefixlen >= _NMAP_MAX_PREFIX:
                    log.warning("[ARP] Filtre libpcap invalide — fallback nmap -PR.")
                    return _nmap_arp_ping(network, timeout=timeout)
                log.warning("[ARP] Filtre libpcap invalide — fallback nmap -PR ignoré sur grand réseau.")
                return {}
            # transient error — continue remaining retries
    return hosts


def _nmap_ping(hosts: str | list[str], timeout: int = 30) -> dict:
    """
    Ping sweep nmap (-sn). Retourne {ip: {"ip": str, "mac": str}}.

    --max-retries 1   : nmap ne re-sonde qu'une fois (défaut = 2) → 2x plus rapide
    --min-parallelism : augmente le parallélisme de sondage
    """
    nm = scan._get_portscanner()
    try:
        target = " ".join(hosts) if isinstance(hosts, list) else hosts
        nm.scan(
            hosts=target,
            # -PE/-PP : sondes ICMP echo + timestamp (plus fiable que ping seul)
            # -PS/-PA : SYN/ACK sur ports communs pour hôtes filtrant l'ICMP
            arguments=(
                f"-sn -T4 -PE -PP -PS22,80,443,8080 -PA80,443 "
                f"--host-timeout {timeout}s --max-retries 1 --min-parallelism 50"
            ),
        )
    except nmap.PortScannerError as e:
        msg = str(e)
        if "Warning:" in msg and "not root" in msg:
            log.warning("[NMAP] %s", msg.strip())
        else:
            log.error("[NMAP] Ping sweep échoué : %s", msg)
            return {}
    except Exception as e:
        log.error("[NMAP] Ping sweep échoué : %s", e)
        return {}

    hosts: dict = {}
    for host in nm.all_hosts():
        try:
            state = nm[host].state()
        except Exception:
            state = "unknown"
        if state == "up":
            try:
                mac = nm[host].get("addresses", {}).get("mac", "N/A")
            except Exception:
                mac = "N/A"
            hosts[host] = {"ip": host, "mac": mac or "N/A"}
    return hosts


def _nmap_arp_ping(network: ipaddress.IPv4Network, timeout: int = 30) -> dict:
    """
    Découverte ARP via nmap (-PR). Retourne {ip: {"ip": str, "mac": str}}.
    """
    nm = scan._get_portscanner()
    try:
        nm.scan(
            hosts=str(network),
            arguments=(
                f"-sn -PR -n -T4 --host-timeout {timeout}s --max-retries 1 --min-parallelism 50"
            ),
        )
    except Exception as e:
        log.error("[NMAP] ARP ping échoué : %s", e)
        return {}

    hosts: dict = {}
    for host in nm.all_hosts():
        try:
            state = nm[host].state()
        except Exception:
            state = "unknown"
        if state == "up":
            try:
                mac = nm[host].get("addresses", {}).get("mac", "N/A")
            except Exception:
                mac = "N/A"
            hosts[host] = {"ip": host, "mac": mac or "N/A"}
    return hosts


def _discover_network(
    network: ipaddress.IPv4Network,
    timeout: int,
    allow_large_nmap: bool,
    port_count: int | None,
    large_nmap_max_ports: int,
    large_nmap_max_hosts: int,
) -> dict:
    """
    Lance ARP et nmap ping en parallèle sur les petits réseaux.

    Sur les grands réseaux (> /24) : ARP seul (nmap trop lent sans limite d'hôtes).
    Sans root : nmap ping seul.
    """
    small_network = network.prefixlen >= _NMAP_MAX_PREFIX
    allow_large = (
        allow_large_nmap
        and port_count is not None
        and port_count <= large_nmap_max_ports
    )

    nmap_hosts_target: str | list[str] = str(network)
    if allow_large and not small_network and large_nmap_max_hosts:
        limited = list(itertools.islice(network.hosts(), large_nmap_max_hosts))
        if limited:
            nmap_hosts_target = [str(ip) for ip in limited]
            log.info(
                "Nmap ping limité à %d hôte(s) (sur %d possibles).",
                len(nmap_hosts_target),
                network.num_addresses,
            )

    if _is_root():
        if small_network or allow_large:
            if allow_large and not small_network:
                log.info(
                    "Réseau %s > /%d — nmap ping autorisé (ports=%d <= %d).",
                    network,
                    _NMAP_MAX_PREFIX,
                    port_count,
                    large_nmap_max_ports,
                )
            # ARP + nmap ping en parallèle : on prend le meilleur des deux
            with ThreadPoolExecutor(max_workers=2) as ex:
                arp_fut  = ex.submit(_arp_scan, network, timeout, 2)
                nmap_fut = ex.submit(_nmap_ping, nmap_hosts_target, timeout)
            arp        = arp_fut.result()
            nmap_hosts = nmap_fut.result()
        else:
            arp        = _arp_scan(network, timeout=timeout, retry=2)
            nmap_hosts = {}
    else:
        arp = {}
        if small_network or allow_large:
            if allow_large and not small_network:
                log.info(
                    "Réseau %s > /%d — nmap ping autorisé (ports=%d <= %d).",
                    network,
                    _NMAP_MAX_PREFIX,
                    port_count,
                    large_nmap_max_ports,
                )
            nmap_hosts = _nmap_ping(nmap_hosts_target, timeout=timeout)
        else:
            log.warning(
                "Réseau %s trop grand pour nmap et ARP désactivé (pas root).",
                network,
            )
            nmap_hosts = {}

    # ARP écrase nmap si même IP trouvée (MAC plus fiable via ARP)
    return {**nmap_hosts, **arp}


def discover(
    iface: str | None = None,
    network: str | None = None,
    timeout: int = 5,
    allow_large_nmap: bool = False,
    port_count: int | None = None,
    large_nmap_max_ports: int = 16,
    large_nmap_max_hosts: int = 1024,
) -> list[dict]:
    """
    Découverte des hôtes actifs. Retourne une liste de dicts ``{"ip": str, "mac": str}``
    dédupliquée (les IPs propres à la machine sont exclues).

    Args:
        iface:   Limite la découverte à une interface (ex: "eth0").
        network: Force un réseau cible (CIDR, ex: "192.168.1.0/24").
        timeout: Délai d'attente ARP en secondes.
        allow_large_nmap: Autorise nmap ping sur grands réseaux si port_count est bas.
        port_count: Nombre de ports pour décider du seuil (optionnel).
        large_nmap_max_ports: Seuil de ports max pour activer nmap sur grands réseaux.
        large_nmap_max_hosts: Limite d'hôtes scannés par nmap sur grands réseaux.
    """
    if not _is_root():
        log.warning("Sans root — ARP désactivé, nmap limité aux réseaux ≤ /%d.", _NMAP_MAX_PREFIX)

    results: dict = {}

    if network:
        net = ipaddress.ip_network(network, strict=False)
        log.info("Réseau cible : %s (%d hôtes possibles)", net, net.num_addresses)
        results[str(net)] = list(
            _discover_network(
                net,
                timeout,
                allow_large_nmap,
                port_count,
                large_nmap_max_ports,
                large_nmap_max_hosts,
            ).values()
        )
        local_ips: set = set()
    else:
        networks, local_ips = _interface_networks()
        if not networks:
            log.warning("Aucune interface réseau utilisable détectée.")
            return []

        # Découverte simultanée sur toutes les interfaces
        def _scan_iface(net_str: str, info: dict) -> tuple[str, list]:
            net   = info["network"]
            label = f"{info['iface']} ({net_str})"
            log.info("Découverte sur %s — %d hôtes possibles", label, net.num_addresses)
            merged = _discover_network(
                net,
                timeout,
                allow_large_nmap,
                port_count,
                large_nmap_max_ports,
                large_nmap_max_hosts,
            )
            return label, list(merged.values())

        filtered = {
            k: v for k, v in networks.items()
            if not iface or v["iface"] == iface
        }
        if not filtered:
            log.warning("Interface '%s' introuvable ou sans IP.", iface)
            return []
        with ThreadPoolExecutor(max_workers=min(len(filtered), 4)) as ex:
            futures = {ex.submit(_scan_iface, k, v): k for k, v in filtered.items()}
            for fut in as_completed(futures):
                try:
                    label, hosts = fut.result()
                    results[label] = hosts
                except Exception as e:
                    log.warning("Découverte échouée : %s", e)

    seen: set = set()
    host_list: list[dict] = []

    for label, hosts in results.items():
        if not hosts:
            log.info("[%s] Aucun hôte actif détecté.", label)
            continue
        for h in hosts:
            ip = h["ip"]
            if ip in local_ips or ip in seen:
                continue
            seen.add(ip)
            mac = h.get("mac", "N/A")
            log.info("  ↳ %-16s  MAC: %s", ip, mac)
            host_list.append({"ip": ip, "mac": mac})

    return host_list


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    p = argparse.ArgumentParser(description="Découverte d'hôtes réseau")
    p.add_argument("-i", "--iface", help="Interface (ex: eth0)")
    p.add_argument("-n", "--network", help="Réseau CIDR (ex: 192.168.1.0/24)")
    p.add_argument("-t", "--timeout", type=int, default=500)
    p.add_argument("--allow-large-nmap", action="store_true", help="Autorise nmap sur grands réseaux")
    p.add_argument("--large-nmap-max-ports", type=int, default=16)
    p.add_argument("--large-nmap-max-hosts", type=int, default=1024)
    p.add_argument("--ports", help="Ports pour calculer le seuil (ex: 22,80,443)")
    a = p.parse_args()
    port_count = None
    if a.ports:
        port_count = _port_count(a.ports)
    hosts = discover(
        iface=a.iface,
        network=a.network,
        timeout=a.timeout,
        allow_large_nmap=a.allow_large_nmap,
        port_count=port_count,
        large_nmap_max_ports=a.large_nmap_max_ports,
        large_nmap_max_hosts=a.large_nmap_max_hosts,
    )
    print(f"\n{len(hosts)} hôte(s) découvert(s) :")
    for h in hosts:
        print(f"  {h['ip']}  MAC: {h['mac']}")
