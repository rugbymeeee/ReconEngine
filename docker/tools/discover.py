"""
Découverte d'hôtes sur le réseau local.

Stratégie :
  1. ARP broadcast (Scapy) — rapide, fonctionne sur tout type de réseau, nécessite root.
  2. nmap ping sweep (-sn) — utilisé en complément sur les petits réseaux (≤ /24)
     ou comme seul moyen si root non disponible.

Point d'entrée public : discover(iface, network, timeout) → list[str]
"""
import fcntl
import ipaddress
import logging
import os
import socket
import struct

from scapy.all import arping, get_if_addr, get_if_list

import scan

log = logging.getLogger(__name__)

_NMAP_MAX_PREFIX = 24  # nmap ping sweep uniquement sur réseaux ≤ /24


def _is_root() -> bool:
    return os.geteuid() == 0


def _get_netmask(ifname: str) -> str | None:
    """Netmask via ioctl SIOCGIFNETMASK (Linux uniquement)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result = fcntl.ioctl(
            s.fileno(), 0x891B,
            struct.pack("256s", ifname.encode()[:15]),
        )
        s.close()
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
            net = ipaddress.ip_network(
                f"{ip}/{netmask}" if (netmask and netmask != "0.0.0.0") else f"{ip}/24",
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
    """ARP broadcast sur le réseau. Retourne {ip: {"ip": str, "mac": str}}."""
    if not _is_root():
        log.warning("[ARP] Ignoré — droits root requis.")
        return {}
    if network.prefixlen <= 16:
        timeout = max(timeout, 10)  # plus de temps sur grands réseaux

    hosts: dict = {}
    for attempt in range(retry):
        try:
            ans, _ = arping(str(network), timeout=timeout, verbose=False)
            for _, rcv in ans:
                ip = rcv.psrc
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "mac": rcv.hwsrc}
        except PermissionError:
            log.error("[ARP] Permission refusée (nécessite root).")
            break
        except Exception as e:
            log.warning("[ARP] Tentative %d/%d : %s", attempt + 1, retry, e)
    return hosts


def _nmap_ping(network: ipaddress.IPv4Network, timeout: int = 30) -> dict:
    """Ping sweep nmap (-sn). Retourne {ip: {"ip": str, "mac": str}}."""
    try:
        nm = scan._get_portscanner()
        nm.scan(
            hosts=str(network),
            # -PE/-PP : sondes ICMP echo + timestamp (plus fiable que ping seul)
            # -PS/-PA : SYN/ACK sur ports communs pour hôtes filtrant l'ICMP
            arguments=f"-sn -T4 -PE -PP -PS22,80,443,8080 -PA80,443 --host-timeout {timeout}s",
        )
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
    except Exception as e:
        log.error("[NMAP] Ping sweep échoué : %s", e)
        return {}


def _discover_network(network: ipaddress.IPv4Network, timeout: int) -> dict:
    """Lance ARP + éventuellement nmap ping sur un réseau. ARP est prioritaire."""
    arp = _arp_scan(network, timeout=timeout)
    nmap_hosts = (
        _nmap_ping(network)
        if network.prefixlen >= _NMAP_MAX_PREFIX
        else {}
    )
    if not arp and not nmap_hosts and not _is_root():
        log.warning(
            "Réseau %s trop grand pour nmap et ARP désactivé (pas root).",
            network,
        )
    # ARP écrase nmap si même IP trouvée (MAC plus fiable via ARP)
    return {**nmap_hosts, **arp}


def discover(
    iface: str | None = None,
    network: str | None = None,
    timeout: int = 5,
) -> list[dict]:
    """
    Découverte des hôtes actifs. Retourne une liste de dicts ``{"ip": str, "mac": str}``
    dédupliquée (les IPs propres à la machine sont exclues).

    Args:
        iface:   Limite la découverte à une interface (ex: "eth0").
        network: Force un réseau cible (CIDR, ex: "192.168.1.0/24").
        timeout: Délai d'attente ARP en secondes.
    """
    if not _is_root():
        log.warning("Sans root — ARP désactivé, nmap limité aux réseaux ≤ /%d.", _NMAP_MAX_PREFIX)

    results: dict = {}

    if network:
        net = ipaddress.ip_network(network, strict=False)
        log.info("Réseau cible : %s (%d hôtes possibles)", net, net.num_addresses)
        results[str(net)] = list(_discover_network(net, timeout).values())
        local_ips: set = set()
    else:
        networks, local_ips = _interface_networks()
        if not networks:
            log.warning("Aucune interface réseau utilisable détectée.")
            return []
        for net_str, info in networks.items():
            if iface and info["iface"] != iface:
                continue
            net = info["network"]
            label = f"{info['iface']} ({net_str})"
            log.info("Découverte sur %s — %d hôtes possibles", label, net.num_addresses)
            merged = _discover_network(net, timeout)
            results[label] = list(merged.values())

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
    p.add_argument("-t", "--timeout", type=int, default=5)
    a = p.parse_args()
    hosts = discover(iface=a.iface, network=a.network, timeout=a.timeout)
    print(f"\n{len(hosts)} hôte(s) découvert(s) :")
    for h in hosts:
        print(f"  {h['ip']}  MAC: {h['mac']}")
