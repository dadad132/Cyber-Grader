"""External exposure check: is the office router's management interface open to the internet?

This runs on the grader server (which is on the internet) against the PUBLIC IP that an audit upload
came from, i.e. the network the technician is physically connected to. The target is always the request's
own source address and can never be chosen in the request body, so this only ever checks the exposure of
the network you are currently on (your own, or a client's office where you are present with their approval).
It connects to a fixed, small set of remote-management ports; it never changes anything and never logs in.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .target import is_public_ip

# Ports that a small-office router or server should never expose to the internet. Each: (severity, name, fix).
MANAGEMENT_PORTS: dict[int, tuple[str, str, str]] = {
    23: ("critical", "Telnet (23)", "Disable Telnet on the router (/ip service disable telnet); it sends the password in clear text."),
    21: ("critical", "FTP (21)", "Disable FTP on the router (/ip service disable ftp) or restrict it to the LAN."),
    8291: ("critical", "MikroTik Winbox (8291)", "Close Winbox to the internet: firewall it off and allow it only from the LAN or a VPN (the MikroTik attacks of recent years targeted exposed Winbox)."),
    8728: ("critical", "MikroTik RouterOS API (8728)", "Close the RouterOS API to the internet (/ip service set api address=<LAN>) and use the LAN or a VPN."),
    3389: ("critical", "Remote Desktop (3389)", "Never expose RDP to the internet; put it behind a VPN. Exposed RDP is a leading ransomware entry point."),
    5900: ("high", "VNC remote desktop (5900)", "Close VNC to the internet and reach it over a VPN."),
    8729: ("high", "MikroTik API-SSL (8729)", "Restrict the RouterOS API-SSL service to the LAN or a VPN."),
    22: ("high", "SSH (22)", "If SSH must be reachable, restrict it to known IPs and use keys, not passwords; otherwise close it to the internet."),
    8080: ("high", "HTTP admin (8080)", "Close the router/device web admin to the internet and manage it from the LAN or a VPN."),
}
PORTS = tuple(MANAGEMENT_PORTS)


def _reachable(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_exposure(public_ip: str, *, timeout: float = 2.0) -> dict:
    """Which management ports on public_ip answer from the internet. Refuses non-public addresses.

    Returns {"checked": bool, "ip": str, "open_ports": [...], "reason": str}. The caller passes the request's
    own source IP; callers never choose an arbitrary target.
    """
    try:
        public = is_public_ip(public_ip)
    except ValueError:
        return {"checked": False, "ip": public_ip, "open_ports": [], "reason": "not a usable address"}
    if not public:
        return {"checked": False, "ip": public_ip, "open_ports": [],
                "reason": "the upload didn't come from a public internet address (e.g. a local test), so there's nothing external to check"}
    with ThreadPoolExecutor(max_workers=len(PORTS)) as pool:
        open_ports = [p for p, ok in zip(PORTS, pool.map(lambda p: _reachable(public_ip, p, timeout), PORTS)) if ok]
    return {"checked": True, "ip": public_ip, "open_ports": open_ports, "reason": ""}


def findings(exposure: dict) -> list[dict]:
    out = []
    for port in exposure.get("open_ports", []):
        severity, name, fix = MANAGEMENT_PORTS[port]
        out.append({"check": "external", "severity": severity,
                    "title": f"{name} is reachable from the internet",
                    "issue": f"Anyone on the internet can reach {name} on this network's public address ({exposure['ip']}). "
                             "Management services exposed like this are scanned and attacked constantly.",
                    "fix": fix})
    return out
