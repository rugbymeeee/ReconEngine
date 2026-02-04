from scapy.all import get_if_list, get_if_addr, arping
import argparse
import ipaddress
import os
import sys


def discover_network():
    interfaces = get_if_list()
    ip_addresses = {}
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                ip_addresses[iface] = ip
        except Exception:
            continue
    return ip_addresses


def scan_network(network, timeout=2):
    try:
        ans, _ = arping(str(network), timeout=timeout, verbose=False)
    except PermissionError:
        print("ARP scan requires root privileges. Re-run with sudo/root.")
        return []
    hosts = []
    for snd, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        hosts.append({"ip": ip, "mac": mac})
    return hosts


def discover_hosts(iface=None, network=None, timeout=2):
    results = {}
    if network:
        net = ipaddress.ip_network(network, strict=False)
        hosts = scan_network(net, timeout=timeout)
        results[str(net)] = hosts
        return results

    interfaces = discover_network()
    for ifname, ip in interfaces.items():
        if iface and ifname != iface:
            continue
        # fallback to /16 if no netmask available
        try:
            net = ipaddress.ip_network(f"{ip}/16", strict=False)
        except Exception:
            continue
        hosts = scan_network(net, timeout=timeout)
        results[f"{ifname} ({net})"] = hosts
    return results


def main():
    iplist = []
    parser = argparse.ArgumentParser(description="Discover hosts on local network(s) via ARP scan")
    parser.add_argument("-i", "--iface", default='wlan0', help="Interface to scan (e.g. eth0)")
    parser.add_argument("-n", "--network", help="Network to scan (CIDR, e.g. 192.168.1.0/16)")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="ARP timeout seconds")
    args = parser.parse_args()

    results = discover_hosts(iface=args.iface, network=args.network, timeout=args.timeout)
    if not results:
        print("No networks found or no hosts discovered.")
        return
    for net, hosts in results.items():
        print(f"\nNetwork: {net}")
        if not hosts:
            print("  No live hosts found.")
            continue
        for h in hosts:
            print(f"  IP: {h['ip']}	MAC: {h['mac']}")
            iplist.append(h['ip'])
    return iplist

if __name__ == "__main__":
    main()
