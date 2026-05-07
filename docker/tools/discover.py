from scapy.all import get_if_list, get_if_addr, arping
import ipaddress
import os
import struct
import fcntl
import socket

BLOCKED_IPS, BLOCKED_MACS = set(), set()


def is_device_blocked(ip, mac):
    """Check si un appareil est bloqué (raisons de sécurité et de confidentialité + optimisation)."""
    return ip in BLOCKED_IPS or mac in BLOCKED_MACS


def _is_root():
    return os.geteuid() == 0


def detect_gateway_capability(ip):
    return False


def discover_remote_networks(gateway_ip):
    return []


def _get_netmask(ifname):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            result = fcntl.ioctl(s.fileno(), 0x891B, struct.pack('256s', ifname.encode('utf-8')[:15]))
        return socket.inet_ntoa(result[20:24])
    except Exception:
        return None


def _get_interface_networks():
    networks, local_ips = {}, set()

    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue

            local_ips.add(ip)
            netmask = _get_netmask(iface)
            mask = netmask if netmask and netmask != "0.0.0.0" else "24"
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)

            # ! à changer !
            if net.prefixlen < 8:
                continue

            net_str = str(net)
            if net_str not in networks:
                networks[net_str] = {"iface": iface, "network": net}
        except Exception:
            continue

    return networks, local_ips


def _arp_scan(network, timeout=5, retry=2):
    if not _is_root():
        print("  [ARP] Skipped — requires root.")
        return {}

    net = ipaddress.ip_network(str(network), strict=False)
    timeout = max(timeout, 10) if net.prefixlen <= 16 else timeout
    hosts = {}

    for attempt in range(retry):
        try:
            ans, _ = arping(str(network), timeout=timeout, verbose=False)
            for snd, rcv in ans:
                if rcv.psrc not in hosts:
                    hosts[rcv.psrc] = {"ip": rcv.psrc, "mac": rcv.hwsrc}
            if hosts:
                break
        except PermissionError:
            print("  [ARP] Requires root privileges.")
            break
        except Exception as e:
            print(f"  [ARP] Error (attempt {attempt + 1}): {e}")

    return hosts


def _do_discovery(network, timeout):
    arp_hosts = _arp_scan(ipaddress.ip_network(str(network), strict=False), timeout=timeout)

    if not arp_hosts and not _is_root():
        print("  [!] No hosts found. Run as root for ARP scan.")

    return arp_hosts


def _discover_base(iface=None, network=None, timeout=5):
    if not _is_root():
        print("[!] Please run as root.")
        exit(1)

    results = {}

    if network:
        net = ipaddress.ip_network(network, strict=False)
        print(f"Scanning {net} ({net.num_addresses} hosts) ...")
        results[str(net)] = list(_do_discovery(net, timeout).values())
        return results, set()

    networks, local_ips = _get_interface_networks()

    for net_str, info in networks.items():
        if iface and info["iface"] != iface:
            continue
        net = info["network"]
        print(f"Scanning {info['iface']} ({net_str}) ({net.num_addresses} hosts) ...")
        results[f"{info['iface']} ({net_str})"] = list(_do_discovery(net, timeout).values())

    return results, local_ips


def discover_hosts(iface=None, network=None, timeout=5, max_depth=3, visited_networks=None):
    if visited_networks is None:
        visited_networks = set()

    if max_depth <= 0:
        return {}, set()

    results, local_ips = _discover_base(iface, network, timeout)

    for net_label, hosts in results.items():
        for host in hosts:
            ip, mac = host["ip"], host.get("mac", "")

            if is_device_blocked(ip, mac):
                print(f"  [SKIP] {ip} is blocked")
                continue

            if ip in local_ips:
                continue

            if detect_gateway_capability(ip):
                print(f"  [GATEWAY] {ip} detected as potential gateway")

                for remote_net in discover_remote_networks(ip):
                    net_str = str(remote_net)

                    if net_str in visited_networks:
                        continue

                    visited_networks.add(net_str)
                    print(f"  [HOP] Scanning remote network {net_str} via {ip}")

                    remote_results, _ = discover_hosts(
                        network=net_str,
                        timeout=timeout,
                        max_depth=max_depth - 1,
                        visited_networks=visited_networks
                    )
                    results.update(remote_results)

    return results, local_ips


def main(iface=None, network=None, timeout=5):
    results, local_ips = discover_hosts(iface=iface, network=network, timeout=timeout)

    if not results:
        print("No networks found or no hosts discovered.")
        return []

    seen, iplist = set(), []

    for net, hosts in results.items():
        print(f"\nNetwork: {net}")

        if not hosts:
            print("  No live hosts found.")
            continue

        for h in hosts:
            ip = h["ip"]
            if ip in local_ips:
                print(f"  IP: {ip}\tMAC: {h['mac']}\t(self - skipped)")
            elif ip not in seen:
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
