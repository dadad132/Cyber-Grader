#!/usr/bin/env python3
"""On-site building network audit agent.

Run it on a laptop (Windows, Linux or macOS) or an Android phone (Termux) connected to the client's Wi-Fi or LAN.
It checks the router's management ports, UPnP, which devices expose file shares/RDP/cameras/printers to this
network segment, the Wi-Fi encryption and signal, and latency, then uploads the results to your account.

    python lan_agent.py --server https://check.easymikrotik.com --api-key cg_... --site "Client office"
    python lan_agent.py --output audit.json            # save locally instead of uploading

Only run it on networks you own or are authorised to audit: it connects to devices on the local network.
Needs Python 3.8+ and nothing else (it uses only the standard library).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "lan_agent.py 2.0"
GATEWAY_PORTS = [21, 22, 23, 80, 161, 8291, 8728, 8729]
LAN_PORTS = [445, 3389, 554, 9100]


def run(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=6, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway() -> str | None:
    system = platform.system().lower()
    patterns = {
        "linux": (["ip", "route", "show", "default"], r"default via (\d+\.\d+\.\d+\.\d+)"),
        "darwin": (["route", "-n", "get", "default"], r"gateway:\s*(\d+\.\d+\.\d+\.\d+)"),
        "windows": (["ipconfig"], r"Default Gateway[ .]*:\s*(?:[0-9a-f:%]+\s+)?(\d+\.\d+\.\d+\.\d+)"),
    }
    if system in patterns:
        command, pattern = patterns[system]
        match = re.search(pattern, run(command), re.I)
        if match:
            return match.group(1)
    return None


def local_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))  # no packet is sent; this just picks the outgoing interface
            return sock.getsockname()[0]
    except OSError:
        return None


def wifi_info() -> dict | None:
    """SSID, security and signal from the operating system, when this device is on Wi-Fi."""
    system = platform.system().lower()
    if system == "windows":
        text = run(["netsh", "wlan", "show", "interfaces"])
        fields = dict(re.findall(r"^\s*([^:\n]+?)\s*:\s*(.+?)\s*$", text, re.M))
        if fields.get("State", "").lower() != "connected":
            return None
        security = fields.get("Authentication", "")
        cipher = fields.get("Cipher", "")
        if "TKIP" in cipher.upper():
            security += "-TKIP"
        signal = fields.get("Signal", "").rstrip("%")
        return {"ssid": fields.get("SSID", ""), "security": security or None,
                "signal_dbm": round(int(signal) / 2 - 100) if signal.isdigit() else None, "source": "netsh"}
    if system == "linux" and shutil.which("nmcli"):
        for line in run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,SIGNAL", "dev", "wifi"]).splitlines():
            parts = re.split(r"(?<!\\):", line)
            if len(parts) >= 4 and parts[0] == "yes":
                security = parts[2] or "OPEN"
                return {"ssid": parts[1].replace("\\:", ":"), "security": security,
                        "signal_dbm": round(int(parts[3]) / 2 - 100) if parts[3].isdigit() else None, "source": "nmcli"}
    if shutil.which("termux-wifi-connectioninfo"):  # Android with Termux:API (no security info)
        try:
            data = json.loads(run(["termux-wifi-connectioninfo"]) or "{}")
        except ValueError:
            data = {}
        if data.get("ssid") and data.get("supplicant_state") == "COMPLETED":
            return {"ssid": data["ssid"].strip('"'), "security": None, "signal_dbm": data.get("rssi"), "source": "termux"}
    return None


def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def upnp_gateway(timeout: float = 2.0) -> bool:
    """Is a UPnP internet gateway answering SSDP discovery on this network?"""
    query = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
             "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data, _ = sock.recvfrom(4096)
                if b"InternetGatewayDevice" in data:
                    return True
        except OSError:
            pass
    return False


def latency_ms(ip: str, port: int) -> float | None:
    """TCP connect time, or None if it couldn't connect (never a made-up number)."""
    started = time.monotonic()
    if not port_open(ip, port, 2.0):
        return None
    return round((time.monotonic() - started) * 1000, 1)


def audit(site: str, domain: str, security_override: str | None, dns_filtering: bool | None,
          external_check: bool = True) -> dict:
    gateway = default_gateway()
    me = local_ip()
    if not gateway and me:
        gateway = str(ipaddress.ip_network(f"{me}/24", strict=False).network_address + 1)
        print(f"[!] Couldn't read the default gateway; assuming {gateway}")
    if not gateway:
        sys.exit("No network connection found. Connect to the building's Wi-Fi or LAN first.")
    print(f"[*] Gateway {gateway}, this device {me}")

    with ThreadPoolExecutor(max_workers=16) as pool:
        open_ports = [p for p, is_open in zip(GATEWAY_PORTS, pool.map(lambda p: port_open(gateway, p, 1.0), GATEWAY_PORTS)) if is_open]
    print(f"[*] Router ports reachable: {open_ports or 'none'}")

    network = ipaddress.ip_network(f"{gateway}/24", strict=False)
    hosts = [str(h) for h in network.hosts() if str(h) not in (gateway, me)]
    targets = [(ip, port) for ip in hosts for port in LAN_PORTS]
    with ThreadPoolExecutor(max_workers=128) as pool:
        found = [t for t, hit in zip(targets, pool.map(lambda t: port_open(t[0], t[1], 0.4), targets)) if hit]
    print(f"[*] Checked {len(hosts)} addresses on {network}: {len(found)} exposed service(s)")

    # iOS blocks multicast for apps without a special Apple entitlement, so silence there proves nothing.
    upnp = None if platform.machine().startswith(("iPhone", "iPad")) else upnp_gateway()
    print(f"[*] UPnP gateway answering: {'not checked on iPhone/iPad' if upnp is None else upnp}")
    wifi = wifi_info() or {}
    if security_override:
        wifi = {**wifi, "security": security_override, "source": "entered"}
    print(f"[*] Wi-Fi: {wifi or 'not on Wi-Fi (or not detectable on this device)'}")
    gw_latency = latency_ms(gateway, open_ports[0]) if open_ports else None
    return {
        "site_name": site,
        "domain": domain,
        "gateway_ip": gateway,
        "gateway_ports_checked": GATEWAY_PORTS,
        "open_gateway_ports": open_ports,
        "hosts_scanned": len(hosts),
        "lan_ports_checked": LAN_PORTS,
        "exposed_lan_services": [{"ip": ip, "port": port} for ip, port in found],
        "upnp_enabled": upnp,
        "wifi": wifi or None,
        "rogue_aps": None,                 # not measured by this agent
        "dns_filtering": dns_filtering,    # only if you tell us
        "gateway_latency_ms": gw_latency,
        "internet_latency_ms": latency_ms("1.1.1.1", 443) if gw_latency is not None else None,
        # Ask the server to check, from the internet, whether THIS network's router management ports are
        # exposed. The server only ever checks the public IP this upload comes from (the network you're on).
        "check_external": external_check,
        "agent": VERSION,
    }


def upload(server: str, api_key: str, payload: dict) -> dict:
    request = urllib.request.Request(f"{server.rstrip('/')}/api/lan-audit", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "X-API-Key": api_key}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            message = json.load(exc).get("error", "")
        except ValueError:
            message = ""
        sys.exit(f"Upload failed (HTTP {exc.code}): {message or exc.reason}")
    except urllib.error.URLError as exc:
        sys.exit(f"Couldn't reach {server}: {exc.reason}")


def main() -> None:
    parser = argparse.ArgumentParser(description="On-site building network audit agent.")
    parser.add_argument("--server", help="your grader's address, e.g. https://check.easymikrotik.com")
    parser.add_argument("--api-key", help="API key from Account > API access on the grader")
    parser.add_argument("--site", default="", help="a name for this site, e.g. 'Client office, 2nd floor'")
    parser.add_argument("--domain", default="", help="the client's domain (optional)")
    parser.add_argument("--wifi-security", help="override the detected Wi-Fi security, e.g. WPA2, WPA3, WEP, OPEN")
    parser.add_argument("--dns-filtering", choices=["yes", "no"], help="whether the network filters malicious domains, if you know")
    parser.add_argument("--no-external", action="store_true",
                        help="skip the internet-exposure check (the server checks this network's own public IP)")
    parser.add_argument("--output", help="save the measurements to this JSON file instead of uploading")
    args = parser.parse_args()
    if not args.output and not (args.server and args.api_key):
        parser.error("give --server and --api-key to upload, or --output FILE to save locally")
    payload = audit(args.site, args.domain, args.wifi_security,
                    None if args.dns_filtering is None else args.dns_filtering == "yes",
                    external_check=not args.no_external)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)
        print(f"[*] Saved to {args.output}")
        return
    result = upload(args.server, args.api_key, payload)
    print(f"\nGrade {result['grade']} ({result['score']}/100), {len(result['findings'])} thing(s) to fix")
    if result.get("public_ip"):
        print(f"Internet exposure checked on this network's public IP {result['public_ip']}")
    for finding in result["findings"]:
        print(f"  [{finding['severity'].upper()}] {finding['title']}")
    if result.get("not_checked"):
        print(f"Not checked: {', '.join(result['not_checked'])}")
    print(f"Full audit: {result['url']}")


if __name__ == "__main__":
    main()
