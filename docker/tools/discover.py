from scapy.all import get_if_list, get_if_addr
import os
import sys

def discover_network():
    interfaces = get_if_list()
    ip_addresses = {}
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            if ip:
                ip_addresses[iface] = ip
        except Exception:
            continue
    return ip_addresses

if __name__ == "__main__":
    networks = discover_network()
    for iface, ip in networks.items():
        print(f"Interface: {iface}, IP Address: {ip}")
