from scapy.all import get_if_list, get_if_addr, arping
import ipaddress
import os
import sys
import struct
import fcntl
import socket
import scan as scan_module

# Nmap ping scan is only used on networks <= this size (ARP handles the rest)
_NMAP_MAX_PREFIX = 24  # /24 = 256 hosts


def _is_root():
    return os.geteuid() == 0


def _get_netmask(ifname):
    """Get the netmask of an interface using ioctl (Linux)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result = fcntl.ioctl(
            s.fileno(),
            0x891B,  # SIOCGIFNETMASK
            struct.pack('256s', ifname.encode('utf-8')[:15])
        )
        s.close()
        return socket.inet_ntoa(result[20:24])
    except Exception:
        return None


def _get_interface_networks():
    """Detect all local interfaces and their CIDR networks.

    Returns (networks_dict, local_ips_set).
    """
    networks = {}
    local_ips = set()

    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue

            local_ips.add(ip)
            netmask = _get_netmask(iface)
            if netmask and netmask != "0.0.0.0":
                net = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)

            # Skip absurdly large networks (> /8)
            if net.prefixlen < 8:
                continue

            net_str = str(net)
            if net_str not in networks:
                networks[net_str] = {"iface": iface, "network": net}
        except Exception:
            continue

    return networks, local_ips


def _arp_scan(network, timeout=5, retry=2):
    """ARP scan with retry. Fast even on /16 since ARP is broadcast-based."""
    if not _is_root():
        print("  [ARP] Skipped — requires root.")
        return {}

    net = ipaddress.ip_network(str(network), strict=False)
    # Increase timeout for large networks
    if net.prefixlen <= 16:
        timeout = max(timeout, 10)

    hosts = {}
    for attempt in range(retry):
        try:
            ans, _ = arping(str(network), timeout=timeout, verbose=False)
            for snd, rcv in ans:
                ip = rcv.psrc
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "mac": rcv.hwsrc}
            if hosts:
                break  # Got results, no need to retry
        except PermissionError:
            print("  [ARP] Requires root privileges.")
            break
        except Exception as e:
            print(f"  [ARP] Error (attempt {attempt + 1}): {e}")
            continue

    return hosts


def _nmap_ping_scan(network, timeout=30):
    """Use nmap -sn (ping sweep) as fallback discovery.

    Uses nmap's native --host-timeout to prevent hanging.
    """
    try:
        nm = scan_module._get_portscanner()
        args = f"-sn -T4 --min-rate 500 --host-timeout {timeout}s"
        nm.scan(hosts=str(network), arguments=args)
        hosts = {}
        for host in nm.all_hosts():
            try:
                state = nm[host].state()
            except Exception:
                state = "unknown"
            if state == "up":
                mac = ""
                try:
                    addresses = nm[host].get("addresses", {})
                    mac = addresses.get("mac", "")
                except Exception:
                    pass
                hosts[host] = {"ip": host, "mac": mac or "N/A"}
        return hosts
    except Exception as e:
        print(f"  [NMAP] Error: {e}")
        return {}


def _should_use_nmap(network):
    """Only use nmap ping scan on small networks (<= /24) to avoid hanging."""
    net = ipaddress.ip_network(str(network), strict=False)
    return net.prefixlen >= _NMAP_MAX_PREFIX


def _do_discovery(network, timeout):
    """Run ARP + optional nmap on a single network. Returns hosts dict."""
    net = ipaddress.ip_network(str(network), strict=False)
    use_nmap = _should_use_nmap(net)

    arp_hosts = _arp_scan(net, timeout=timeout)

    # Only use nmap on small networks, or as fallback if ARP found nothing on small nets
    if use_nmap and not arp_hosts:
        nmap_hosts = _nmap_ping_scan(net)
    elif use_nmap:
        nmap_hosts = _nmap_ping_scan(net)
    else:
        if not arp_hosts and not _is_root():
            print(f"  [!] Network too large for nmap fallback. Run as root for ARP scan.")
        nmap_hosts = {}

    merged = {**nmap_hosts, **arp_hosts}
    return merged


def discover_hosts(iface=None, network=None, timeout=5):
    """
    Discover live hosts on local networks.

    Strategy:
    - ARP scan: always (fast broadcast, works on any size network)
    - Nmap ping sweep (-sn): only on small networks (<= /24)

    Returns (results_dict, local_ips_set).
    """
    if not _is_root():
        print("[!] Please run as root.")
        exit(1)

    results = {}

    if network:
        net = ipaddress.ip_network(network, strict=False)
        print(f"Scanning {net} ({net.num_addresses} hosts) ...")
        merged = _do_discovery(net, timeout)
        results[str(net)] = list(merged.values())
        return results, set()

    networks, local_ips = _get_interface_networks()
    if not networks:
        return results, local_ips

    for net_str, info in networks.items():
        if iface and info["iface"] != iface:
            continue
        net = info["network"]
        label = f"{info['iface']} ({net_str})"
        print(f"Scanning {label} ({net.num_addresses} hosts) ...")
        merged = _do_discovery(net, timeout)
        results[label] = list(merged.values())

    return results, local_ips


def main(iface=None, network=None, timeout=5):
    """
    Entry point: discover hosts and return a deduplicated IP list.
    Excludes the scanner's own IPs.
    """
    results, local_ips = discover_hosts(iface=iface, network=network, timeout=timeout)

    if not results:
        print("No networks found or no hosts discovered.")
        return []

    seen = set()
    iplist = []

    for net, hosts in results.items():
        print(f"\nNetwork: {net}")
        if not hosts:
            print("  No live hosts found.")
            continue
        for h in hosts:
            ip = h["ip"]
            if ip in local_ips:
                print(f"  IP: {ip}\tMAC: {h['mac']}\t(self - skipped)")
                continue
            if ip in seen:
                continue
            seen.add(ip)
            print(f"  IP: {ip}\tMAC: {h['mac']}")
            iplist.append(ip)

    return iplist


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Discover hosts on local network(s)")
    parser.add_argument("-i", "--iface", help="Interface to scan (e.g. eth0)")
    parser.add_argument("-n", "--network", help="Network to scan (CIDR, e.g. 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="ARP timeout seconds")
    args = parser.parse_args()
    main(iface=args.iface, network=args.network, timeout=args.timeout)
