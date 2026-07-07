# 🛰️ Network Toolkit (Linux)

A simple menu-driven Python toolkit for basic network discovery and information gathering on Linux systems.

> ⚠️ This tool is intended **only for your own network or networks where you have explicit permission to perform scans.**

## Features

- 📶 Scan nearby WiFi networks
- 🖥️ Discover devices connected to your local network
- 🔍 View information about a specific device by IP address
- 🌐 Display network information
  - Local subnet
  - Default gateway
  - DNS servers
- 🚪 Check a set of common open TCP ports
- 🏷️ Resolve hostnames and MAC addresses (when available)

## Requirements

- Python 3.8+
- Linux
- `iproute2`
- `iputils-ping`
- `network-manager` (for WiFi scanning)

Install the required packages on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install iproute2 iputils-ping network-manager
```

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/network-toolkit.git
cd network-toolkit
```

## Usage

Run the script:

```bash
sudo python3 network_toolkit.py
```

## Menu

```
1. Scan nearby WiFi networks
2. Scan devices connected to network
3. Get info about a specific device (by IP)
4. Network info (Gateway, DNS, etc.)
5. Exit
```

## Technologies Used

- Python 3
- subprocess
- socket
- ipaddress
- concurrent.futures
- shutil

## Notes

- WiFi scanning uses `nmcli`.
- Device discovery is performed using ICMP ping and the local ARP table.
- Port scanning checks only a small list of common TCP ports.
- Root privileges (`sudo`) may be required for some features.

## Disclaimer

This project is created for educational purposes and for network administration on systems you own or have permission to test. The author is not responsible for any misuse of this software.

## License

This project is licensed under the MIT License.
