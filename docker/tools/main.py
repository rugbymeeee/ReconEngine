import os
import sys
import pathlib
import nmap
import scan
import discover

def main():
    discovered_ips = discover.main()
    if not discovered_ips:
        print("No hosts discovered to scan.")
        return
    for ip in discovered_ips:
        print(f"Scanning host: {ip}")
        result = scan.scan_host(ip)
        if result:
            print(f"Scan results for {ip}:")
            print(result)
        else:
            print(f"No results for {ip}")


if __name__ == "__main__":
    main()