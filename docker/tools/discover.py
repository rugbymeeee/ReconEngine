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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False  # Windows — _get_netmask() retourne None, fallback /24

import nmap
import scan
from scapy.all import ARP, Ether, arping, get_if_addr, get_if_list, srp

# AsyncSniffer permet la remontée en temps réel des réponses ARP — fail-safe :
# si scapy ne l'expose pas (très vieille version, ou stub de test), on retombe
# sur les callbacks émis à la fin de chaque passe arping/srp.
try:
    from scapy.all import AsyncSniffer  # type: ignore
    _HAS_SNIFFER = True
except ImportError:
    AsyncSniffer = None  # type: ignore
    _HAS_SNIFFER = False

HostCallback = Callable[[str, str], None]

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


_INVALID_MACS = frozenset({"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def _normalize_mac(mac: str | None) -> str:
    """Normalise une MAC en minuscules `aa:bb:cc:dd:ee:ff`. Retourne '' si invalide."""
    if not mac:
        return ""
    mac = mac.strip().lower().replace("-", ":")
    if mac in _INVALID_MACS:
        return ""
    return mac


def _read_arp_cache(iface: str | None = None) -> dict[str, str]:
    """
    Lit le cache ARP du noyau (`/proc/net/arp`). Retourne `{ip: mac}`.

    Ne garde que les entrées avec flag 0x2 (REACHABLE/COMPLETE) — les autres
    sont des sondes du noyau encore sans réponse, donc non fiables.
    Filtre par interface si `iface` fourni.
    """
    cache: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)  # header
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip, _hwtype, flags, mac, _mask, dev = parts[:6]
                if flags != "0x2":
                    continue
                if iface and dev != iface:
                    continue
                mac_n = _normalize_mac(mac)
                if not mac_n:
                    continue
                cache[ip] = mac_n
    except (FileNotFoundError, PermissionError):
        return {}
    except Exception as e:  # noqa: BLE001
        log.debug("[ARP] Lecture /proc/net/arp échouée : %s", e)
    return cache


def _arp_scan(
    network: ipaddress.IPv4Network,
    timeout: int = 5,
    retry: int = 2,
    iface: str | None = None,
    on_host_found: HostCallback | None = None,
) -> dict:
    """
    ARP broadcast sur le réseau. Retourne `{ip: {"ip": str, "mac": str}}`.

    Précision :
      1. `inter` > 0 entre paquets — évite la perte sur switch/driver saturé (la
         rafale `inter=0` est la principale cause de faux négatifs).
      2. `iface=` explicite — force la bonne carte sur machine multi-homed.
      3. Retransmission ciblée sur l'ensemble `unans` plutôt qu'un broadcast
         identique au tour 2 → récupère les hôtes lents/endormis (ACPI).
      4. Recoupement avec `/proc/net/arp` (entrées REACHABLE du noyau).
      5. Filtre les réponses hors-réseau (paquets égarés / proxy ARP étranger).
      6. Détecte les MACs conflictuels (proxy ARP / spoofing) et journalise.

    Si `on_host_found` est fourni, l'`AsyncSniffer` scapy fait remonter chaque
    réponse ARP en temps réel — le callback est appelé dès qu'un hôte répond,
    pas en fin de passe. Il est invoqué une seule fois par IP (dédup interne).
    """
    if not _is_root():
        log.warning("[ARP] Ignoré — droits root requis.")
        return {}
    # Sur les grands réseaux, beaucoup d'hôtes à interroger → timeout plus long.
    if network.prefixlen <= 16:
        timeout = max(timeout, 30)   # /16 = 65536 hôtes
    elif network.prefixlen <= 20:
        timeout = max(timeout, 15)   # /17–/20

    # Espacement inter-paquets : la rafale (inter=0) sature pilotes et switchs
    # et provoque des pertes de réponses. 2 ms sur /24 = ~0.5 s d'émission,
    # impact négligeable face au gain de fiabilité.
    if network.num_addresses <= 256:
        inter = 0.003
    elif network.num_addresses <= 4096:
        inter = 0.002
    else:
        inter = 0.001

    base_kwargs: dict = {"timeout": timeout, "verbose": False, "inter": inter}
    if iface:
        base_kwargs["iface"] = iface

    # {ip: {mac: count}} — permet la détection de MACs multiples (spoof/proxy)
    seen: dict[str, dict[str, int]] = {}
    lock = threading.Lock()  # protège `seen` (sniffer + thread principal)

    def _record(ip: str, mac: str) -> None:
        mac_n = _normalize_mac(mac)
        if not mac_n:
            return
        try:
            if ipaddress.ip_address(ip) not in network:
                return  # réponse étrangère, on ignore
        except ValueError:
            return
        with lock:
            first_time = ip not in seen
            bucket = seen.setdefault(ip, {})
            bucket[mac_n] = bucket.get(mac_n, 0) + 1
        if first_time and on_host_found is not None:
            try:
                on_host_found(ip, mac_n)
            except Exception as e:  # noqa: BLE001
                log.debug("[ARP] on_host_found exception : %s", e)

    # ── Sniffer asynchrone : remontée temps réel des réponses ARP ───────────
    sniffer = None
    if _HAS_SNIFFER and on_host_found is not None:
        def _on_arp_pkt(pkt) -> None:
            try:
                if ARP in pkt and int(pkt[ARP].op) == 2:  # 2 = ARP reply (is-at)
                    _record(pkt[ARP].psrc, pkt[ARP].hwsrc)
            except Exception:
                pass
        sniffer_kwargs: dict = {"filter": "arp", "prn": _on_arp_pkt, "store": False}
        if iface:
            sniffer_kwargs["iface"] = iface
        try:
            sniffer = AsyncSniffer(**sniffer_kwargs)
            sniffer.start()
        except Exception as e:  # noqa: BLE001
            log.debug("[ARP] AsyncSniffer indisponible (%s) — fallback batch.", e)
            sniffer = None

    try:
        # ── Passe 1 : ARP broadcast complet ─────────────────────────────────
        unans_targets: list[str] = []
        try:
            ans, unans = arping(str(network), **base_kwargs)
            for _, rcv in ans:
                _record(rcv.psrc, rcv.hwsrc)
            # Extrait les IPs sans réponse pour la retransmission ciblée
            for pkt in unans or []:
                try:
                    unans_targets.append(pkt[ARP].pdst)
                except Exception:
                    continue
        except PermissionError:
            log.error("[ARP] Permission refusée (nécessite root).")
            return {}
        except Exception as e:
            msg = str(e)
            log.warning("[ARP] Erreur passe 1 : %s", e)
            if "Failed to compile filter expression" in msg or "Cannot set filter" in msg:
                if network.prefixlen >= _NMAP_MAX_PREFIX:
                    log.warning("[ARP] Filtre libpcap invalide — fallback nmap -PR.")
                    return _nmap_arp_ping(network, timeout=timeout, on_host_found=on_host_found)
                log.warning("[ARP] Filtre libpcap invalide — fallback nmap -PR ignoré sur grand réseau.")
                return {}

        # ── Passes 2+ : retransmission ciblée sur les hôtes sans réponse ────
        extra_passes = max(0, retry - 1)
        if extra_passes and unans_targets:
            if len(unans_targets) > 4096:
                log.debug("[ARP] Retry ciblé tronqué à 4096 hôtes (sur %d).", len(unans_targets))
                unans_targets = unans_targets[:4096]

            retry_kwargs: dict = {
                "timeout": max(2, timeout // 2),
                "verbose": False,
                "inter": 0.005,
                "retry": 0,
            }
            if iface:
                retry_kwargs["iface"] = iface

            targets = unans_targets
            for pass_no in range(extra_passes):
                if not targets:
                    break
                still_unans: list[str] = []
                for i in range(0, len(targets), 128):
                    chunk = targets[i:i + 128]
                    pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in chunk]
                    try:
                        ans, unans = srp(pkts, **retry_kwargs)
                    except Exception as e:  # noqa: BLE001
                        log.debug("[ARP] Retry passe %d échoué : %s", pass_no + 2, e)
                        continue
                    for _, rcv in ans:
                        _record(rcv.psrc, rcv.hwsrc)
                    for pkt in unans or []:
                        try:
                            still_unans.append(pkt[ARP].pdst)
                        except Exception:
                            continue
                targets = still_unans

        # ── Recoupement avec le cache ARP du noyau ──────────────────────────
        for ip, mac in _read_arp_cache(iface=iface).items():
            _record(ip, mac)

    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    # ── Consolidation et détection de conflit ───────────────────────────────
    hosts: dict = {}
    for ip, mac_counts in seen.items():
        if len(mac_counts) > 1:
            log.warning(
                "[ARP] MACs conflictuels pour %s : %s — proxy ARP ou spoofing possible.",
                ip, sorted(mac_counts.keys()),
            )
        # MAC majoritaire (réponses multiples = signal plus fort)
        best_mac = max(mac_counts.items(), key=lambda kv: kv[1])[0]
        hosts[ip] = {"ip": ip, "mac": best_mac}

    return hosts


def _fire_cb(cb: HostCallback | None, ip: str, mac: str) -> None:
    """Appelle `cb(ip, mac)` en avalant les exceptions."""
    if cb is None:
        return
    try:
        cb(ip, mac)
    except Exception as e:  # noqa: BLE001
        log.debug("on_host_found exception : %s", e)


def _nmap_ping(
    hosts: str | list[str],
    timeout: int = 30,
    on_host_found: HostCallback | None = None,
) -> dict:
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

    found: dict = {}
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
            mac = mac or "N/A"
            found[host] = {"ip": host, "mac": mac}
            _fire_cb(on_host_found, host, mac)
    return found


def _nmap_arp_ping(
    network: ipaddress.IPv4Network,
    timeout: int = 30,
    on_host_found: HostCallback | None = None,
) -> dict:
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

    found: dict = {}
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
            mac = mac or "N/A"
            found[host] = {"ip": host, "mac": mac}
            _fire_cb(on_host_found, host, mac)
    return found


def _discover_network(
    network: ipaddress.IPv4Network,
    timeout: int,
    allow_large_nmap: bool = False,
    port_count: int | None = None,
    large_nmap_max_ports: int = 16,
    large_nmap_max_hosts: int = 1024,
    iface: str | None = None,
    on_host_found: HostCallback | None = None,
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
                arp_fut  = ex.submit(
                    _arp_scan, network, timeout, 2, iface, on_host_found,
                )
                nmap_fut = ex.submit(
                    _nmap_ping, nmap_hosts_target, timeout, on_host_found,
                )
            arp        = arp_fut.result()
            nmap_hosts = nmap_fut.result()
        else:
            arp        = _arp_scan(
                network, timeout=timeout, retry=2, iface=iface,
                on_host_found=on_host_found,
            )
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
            nmap_hosts = _nmap_ping(
                nmap_hosts_target, timeout=timeout, on_host_found=on_host_found,
            )
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
    on_host_found: HostCallback | None = None,
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
        on_host_found: Callback ``(ip, mac)`` appelé en temps réel dès qu'un
            hôte est découvert, exactement une fois par IP. Idéal pour piloter
            une barre de progression. Peut être invoqué depuis n'importe quel
            thread — le callback doit être thread-safe côté appelant.
    """
    if not _is_root():
        log.warning("Sans root — ARP désactivé, nmap limité aux réseaux ≤ /%d.", _NMAP_MAX_PREFIX)

    results: dict = {}

    # local_ips détecté tôt (avant le wrapper) pour pouvoir filtrer la machine
    # locale dans les notifications, même quand l'utilisateur passe `network=`.
    if network:
        try:
            _, local_ips = _interface_networks()
        except Exception:
            local_ips = set()
    else:
        networks, local_ips = _interface_networks()
        if not networks:
            log.warning("Aucune interface réseau utilisable détectée.")
            return []

    # Wrapper de dédup global : le callback utilisateur est appelé au plus
    # une fois par IP unique, toutes sources confondues (ARP, nmap, sniffer,
    # cache noyau, interfaces multiples).
    notified: set[str] = set()
    notified_lock = threading.Lock()

    def _notify(ip: str, mac: str) -> None:
        if ip in local_ips:
            return
        with notified_lock:
            if ip in notified:
                return
            notified.add(ip)
        try:
            on_host_found(ip, mac)  # type: ignore[misc]
        except Exception as e:  # noqa: BLE001
            log.debug("on_host_found exception : %s", e)

    wrapped_cb: HostCallback | None = _notify if on_host_found is not None else None

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
                iface=iface,
                on_host_found=wrapped_cb,
            ).values()
        )
    else:
        # Découverte simultanée sur toutes les interfaces
        def _scan_iface(net_str: str, info: dict) -> tuple[str, list]:
            net   = info["network"]
            label = f"{info['iface']} ({net_str})"
            merged = _discover_network(
                net,
                timeout,
                allow_large_nmap,
                port_count,
                large_nmap_max_ports,
                large_nmap_max_hosts,
                iface=info["iface"],
                on_host_found=wrapped_cb,
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
