#!/usr/bin/env python3
"""
Network Toolkit (Linux)
-------------------------
A menu-driven tool to run different network scans.

How to run:
    sudo python3 network_toolkit.py

Use this ONLY on your own WiFi/LAN network.
Scanning someone else's network without permission may be illegal.
"""

import subprocess
import sys
import shutil
import socket
import ipaddress
import concurrent.futures


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def check_tool(name, install_hint):
    if shutil.which(name) is None:
        print(f"❌ '{name}' not found. Install it with: {install_hint}")
        return False
    return True


def get_local_subnet():
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "lo" in parts:
                continue
            for p in parts:
                if "/" in p and p.count(".") == 3:
                    return ipaddress.ip_interface(p).network, parts[1]
    except Exception:
        pass
    return None, None


def get_default_gateway():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                parts = line.split()
                return parts[2] if len(parts) > 2 else "-"
    except Exception:
        pass
    return "-"


def get_dns_servers():
    dns = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns.append(line.split()[1])
    except Exception:
        pass
    return dns


def ping(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False


def ping_sweep(network):
    hosts = list(network.hosts())
    active = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(ping, ip): ip for ip in hosts}
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                active.append(futures[f])
    return active


def get_arp_table():
    table = {}
    try:
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].count(".") == 3:
                ip = parts[0]
                mac = None
                for i, p in enumerate(parts):
                    if p == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1]
                if mac:
                    table[ip] = mac
    except Exception:
        pass
    return table


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "-"


def common_open_ports(ip, ports=(21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080)):
    """Just checking a few common ports, no exploit/attack involved"""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((str(ip), port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


# ---------------------------------------------------------------------------
# Menu options
# ---------------------------------------------------------------------------

def option_wifi_scan():
    if not check_tool("nmcli", "sudo apt install network-manager"):
        return

    try:
        subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True, timeout=15)
    except Exception:
        pass

    fields = "SSID,SIGNAL,CHAN,SECURITY,BSSID"
    result = subprocess.run(
        ["nmcli", "-t", "-f", fields, "device", "wifi", "list"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("⚠️  Scan failed. Try running with sudo.")
        return

    lines = [l for l in result.stdout.strip().split("\n") if l]
    if not lines:
        print("No WiFi networks found.")
        return

    networks = []
    for line in lines:
        parts = line.split(":")
        if len(parts) < 5:
            continue
        bssid = ":".join(parts[-5:])
        rest = parts[:-5]
        ssid = ":".join(rest[:-3]) if len(rest) > 3 else (rest[0] if rest else "")
        signal = rest[-3] if len(rest) >= 3 else ""
        chan = rest[-2] if len(rest) >= 2 else ""
        security = rest[-1] if len(rest) >= 1 else ""
        networks.append({"ssid": ssid or "(Hidden)", "signal": signal, "chan": chan,
                          "security": security or "Open", "bssid": bssid})

    networks.sort(key=lambda n: int(n["signal"]) if n["signal"].isdigit() else 0, reverse=True)

    print(f"\n📶 Found {len(networks)} WiFi network(s):\n")
    print(f"{'SSID':<25}{'Signal':<10}{'Channel':<10}{'Security':<20}{'BSSID'}")
    print("-" * 90)
    for n in networks:
        print(f"{n['ssid']:<25}{n['signal']+'%':<10}{n['chan']:<10}{n['security']:<20}{n['bssid']}")


def option_device_scan():
    if not check_tool("ip", "sudo apt install iproute2") or not check_tool("ping", "sudo apt install iputils-ping"):
        return

    network, iface = get_local_subnet()
    if network is None:
        print("❌ Could not detect local subnet.")
        return

    print(f"🔍 Scanning: {network} (interface: {iface}) ...\n")
    active_ips = ping_sweep(network)
    arp_table = get_arp_table()

    if not active_ips:
        print("No devices found.")
        return

    print(f"📡 Found {len(active_ips)} device(s):\n")
    print(f"{'IP Address':<18}{'MAC Address':<20}{'Hostname'}")
    print("-" * 70)
    for ip in sorted(active_ips):
        mac = arp_table.get(str(ip), "-")
        host = get_hostname(ip)
        print(f"{str(ip):<18}{mac:<20}{host}")


def option_device_info():
    ip = input("Enter the IP address of the device you want info on: ").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("❌ Invalid IP address.")
        return

    print(f"\n🔎 Gathering info for {ip} ...\n")
    host = get_hostname(ip)
    arp_table = get_arp_table()
    mac = arp_table.get(ip, "-")

    print(f"Hostname     : {host}")
    print(f"MAC Address  : {mac}")

    print("Open Ports   : scanning (this may take a few seconds)...")
    ports = common_open_ports(ip)
    if ports:
        print(f"               {', '.join(str(p) for p in ports)}")
    else:
        print("               No common ports found open.")


def option_network_info():
    network, iface = get_local_subnet()
    gateway = get_default_gateway()
    dns = get_dns_servers()

    print("\n🖥️  Your network info:\n")
    print(f"Interface      : {iface or '-'}")
    print(f"Subnet         : {network or '-'}")
    print(f"Default Gateway: {gateway}")
    print(f"DNS Servers    : {', '.join(dns) if dns else '-'}")


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

MENU = """
==============================
   🛰️  NETWORK TOOLKIT MENU
==============================
1. Scan nearby WiFi networks
2. Scan devices connected to network
3. Get info about a specific device (by IP)
4. Network info (Gateway, DNS, etc.)
5. Exit
==============================
"""


def main():
    while True:
        print(MENU)
        choice = input("Select an option (1-5): ").strip()

        if choice == "1":
            option_wifi_scan()
        elif choice == "2":
            option_device_scan()
        elif choice == "3":
            option_device_info()
        elif choice == "4":
            option_network_info()
        elif choice == "5":
            print("Bye! 👋")
            sys.exit(0)
        else:
            print("❌ Invalid option, try again.")

        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    main()
