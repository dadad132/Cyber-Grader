"""Building / LAN network audit: grades what the on-site agent or mobile app measured.

Only measured things are scored. Anything the agent couldn't measure (e.g. Wi-Fi security on a laptop
on a cable) is listed as "not checked" and left out of the score, so the grade never rests on guesses.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

GATEWAY_PORTS = {
    23: ("critical", "Telnet is open on the router", "Telnet sends the router password in clear text.",
         "Disable Telnet (/ip service disable telnet) and manage the router over SSH or a VPN."),
    21: ("critical", "FTP is open on the router", "FTP sends passwords in clear text and is rarely needed on a router.",
         "Disable FTP (/ip service disable ftp)."),
    8728: ("high", "RouterOS API (unencrypted) is open", "The plain API on port 8728 exposes router control without encryption.",
           "Disable it (/ip service disable api), or use API-SSL restricted to management addresses."),
    80: ("medium", "Router web admin over plain HTTP", "WebFig on port 80 sends the admin login unencrypted to anyone on the LAN.",
         "Disable www (/ip service disable www) or allow it only from a management VLAN; use www-ssl instead."),
    161: ("medium", "SNMP is reachable", "SNMP can leak the router's configuration if a default community string is in use.",
          "Disable SNMP if unused, or restrict it to your monitoring server with a strong community."),
    8291: ("medium", "Winbox is reachable from this network", "Anyone on this Wi-Fi/LAN can attempt to log in to the router.",
           "Restrict Winbox (/ip service set winbox address=…) to a management VLAN or VPN."),
    22: ("low", "SSH is reachable from this network", "Router SSH is open to every device on this network.",
         "Restrict SSH (/ip service set ssh address=…) to management addresses."),
    8729: ("low", "RouterOS API-SSL is reachable", "Encrypted, but still open to every device on this network.",
           "Restrict API-SSL to the addresses that need it."),
}
LAN_PORTS = {
    445: ("high", "Windows file sharing (SMB)", "File shares are reachable from this network segment, the classic path for ransomware to spread.",
          "Separate staff, guest and server networks with VLANs and firewall rules; only allow SMB where it's needed."),
    3389: ("high", "Remote Desktop (RDP)", "Remote Desktop is reachable from this network segment.",
           "Put servers/workstations on their own VLAN and require a VPN (e.g. WireGuard) for RDP."),
    554: ("medium", "CCTV camera streams (RTSP)", "Camera streams are reachable from this network segment.",
          "Move cameras and the NVR to an isolated security VLAN."),
    9100: ("low", "Raw network printing", "Printers accept jobs from any device on this segment.",
           "Put printers on an office-services VLAN with controlled access."),
}
PENALTY = {"critical": 1.0, "high": 0.6, "medium": 0.35, "low": 0.15}
CHECKS = (  # (key, title, max points)
    ("external", "Exposed to the internet", 30), ("gateway", "Router management ports", 30),
    ("segmentation", "Network segmentation", 20), ("wifi_security", "Wi-Fi encryption", 20),
    ("upnp", "UPnP port forwarding", 10), ("wifi_signal", "Wi-Fi signal", 5),
    ("rogue_aps", "Rogue access points", 5), ("dns_filtering", "DNS filtering", 5), ("latency", "Latency", 5),
)


class AuditError(ValueError):
    pass


def _ports(values, label: str) -> list[int]:
    try:
        ports = sorted({int(v) for v in values or []})
    except (TypeError, ValueError):
        raise AuditError(f"{label} must be a list of port numbers.") from None
    if any(not 0 < p < 65536 for p in ports):
        raise AuditError(f"{label} contains an invalid port.")
    return ports


def evaluate(data: dict) -> dict:
    """Grade an audit payload. Raises AuditError for malformed input."""
    if not isinstance(data, dict):
        raise AuditError("Send a JSON object.")
    gateway_ip = str(data.get("gateway_ip") or "")
    if gateway_ip:
        try:
            ipaddress.ip_address(gateway_ip)
        except ValueError:
            raise AuditError("gateway_ip isn't an IP address.") from None
    checked_gw = _ports(data.get("gateway_ports_checked"), "gateway_ports_checked")
    open_gw = [p for p in _ports(data.get("open_gateway_ports"), "open_gateway_ports") if not checked_gw or p in checked_gw]
    exposed = []
    for item in data.get("exposed_lan_services") or []:
        try:
            exposed.append({"ip": str(ipaddress.ip_address(item["ip"])), "port": int(item["port"])})
        except (KeyError, TypeError, ValueError):
            raise AuditError("exposed_lan_services entries need an ip and a port.") from None
    hosts_scanned = int(data.get("hosts_scanned") or 0)
    wifi = data.get("wifi") if isinstance(data.get("wifi"), dict) else {}
    findings, passed, not_checked = [], [], []
    scores: dict[str, float] = {}

    def finding(check, severity, title, issue, fix):
        findings.append({"check": check, "severity": severity, "title": title, "issue": issue, "fix": fix})

    # Router management ports
    if checked_gw:
        penalty = 0.0
        for port in open_gw:
            if port in GATEWAY_PORTS:
                severity, title, issue, fix = GATEWAY_PORTS[port]
                finding("gateway", severity, f"{title} (port {port} on {gateway_ip or 'the gateway'})", issue, fix)
                penalty += PENALTY[severity]
        scores["gateway"] = max(0.0, 1 - penalty)
        if not penalty:
            passed.append(f"The router ({gateway_ip}) doesn't expose risky management ports to this network.")
    else:
        not_checked.append("Router management ports")

    # Segmentation (flat network)
    if hosts_scanned:
        penalty, seen = 0.0, {}
        for item in exposed:
            seen.setdefault(item["port"], []).append(item["ip"])
        for port, ips in sorted(seen.items()):
            if port in LAN_PORTS:
                severity, name, issue, fix = LAN_PORTS[port]
                where = ", ".join(ips[:4]) + (f" and {len(ips) - 4} more" if len(ips) > 4 else "")
                finding("segmentation", severity, f"{name} reachable on {len(ips)} device(s): {where}", issue, fix)
                penalty += PENALTY[severity] * 0.7
        scores["segmentation"] = max(0.0, 1 - penalty)
        if not penalty:
            passed.append(f"None of the {hosts_scanned} addresses checked expose file shares, RDP, cameras or printers to this network.")
    else:
        not_checked.append("Network segmentation")

    # Wi-Fi
    security = str(wifi.get("security") or "").upper()
    ssid = str(wifi.get("ssid") or "")
    if security:
        label = f"'{ssid}'" if ssid else "this Wi-Fi"
        if "OPEN" in security or security == "NONE":
            finding("wifi_security", "critical", f"{label} has no password or encryption",
                    "Anyone nearby can join the network and see unencrypted traffic.",
                    "Use WPA2 (AES/CCMP) or WPA3, and give visitors a separate guest network.")
            scores["wifi_security"] = 0.0
        elif "WEP" in security or "TKIP" in security or security in ("WPA", "WPA-PERSONAL", "WPA1"):
            finding("wifi_security", "high", f"{label} uses outdated encryption ({security})",
                    "WEP and WPA-TKIP can be cracked with freely available tools.",
                    "Switch the access points to WPA2-AES (CCMP) or WPA3.")
            scores["wifi_security"] = 0.25
        else:
            scores["wifi_security"] = 1.0
            passed.append(f"Wi-Fi {label} uses {security} encryption.")
    else:
        not_checked.append("Wi-Fi encryption")
    signal = wifi.get("signal_dbm")
    if isinstance(signal, (int, float)) and -110 <= signal <= 0:
        if signal < -75:
            finding("wifi_signal", "low", f"Weak Wi-Fi signal here ({signal:.0f} dBm)",
                    "Weak signal causes slow speeds, retries and dropped calls in this part of the building.",
                    "Add or move an access point (e.g. with CAPsMAN for seamless roaming).")
            scores["wifi_signal"] = 0.3
        else:
            scores["wifi_signal"] = 1.0
            passed.append(f"Wi-Fi signal is healthy here ({signal:.0f} dBm).")
    else:
        not_checked.append("Wi-Fi signal")

    # UPnP, rogue APs, DNS filtering, latency: only when measured
    if isinstance(data.get("upnp_enabled"), bool):
        if data["upnp_enabled"]:
            finding("upnp", "high", "UPnP automatic port forwarding is on",
                    "Any device or malware inside can open holes in the router's firewall without asking.",
                    "Disable UPnP (/ip upnp set enabled=no) and create port forwards by hand.")
            scores["upnp"] = 0.0
        else:
            scores["upnp"] = 1.0
            passed.append("No UPnP internet gateway answered on this network.")
    else:
        not_checked.append("UPnP")
    rogues = data.get("rogue_aps")
    if isinstance(rogues, list):
        if rogues:
            finding("rogue_aps", "high", f"{len(rogues)} unknown access point(s) using the same network name",
                    f"Possible 'evil twin' access points: {', '.join(map(str, rogues[:3]))}.",
                    "Identify and remove unauthorised access points; enable rogue-AP detection.")
            scores["rogue_aps"] = 0.0
        else:
            scores["rogue_aps"] = 1.0
            passed.append("No unknown access points broadcast this network name.")
    else:
        not_checked.append("Rogue access points")
    if isinstance(data.get("dns_filtering"), bool):
        if data["dns_filtering"]:
            scores["dns_filtering"] = 1.0
            passed.append("DNS lookups are filtered for malware and phishing.")
        else:
            finding("dns_filtering", "medium", "DNS isn't filtered",
                    "Devices can reach known malware and phishing domains.",
                    "Use a filtering resolver (e.g. NextDNS, Cloudflare for Families or Quad9) on the router and redirect port 53.")
            scores["dns_filtering"] = 0.0
    else:
        not_checked.append("DNS filtering")
    gw_ms, wan_ms = data.get("gateway_latency_ms"), data.get("internet_latency_ms")
    if isinstance(gw_ms, (int, float)) and isinstance(wan_ms, (int, float)):
        if gw_ms > 20 or wan_ms > 150:
            finding("latency", "low", f"High latency (router {gw_ms:.0f} ms, internet {wan_ms:.0f} ms)",
                    "Usually Wi-Fi congestion or an overloaded internet link (bufferbloat).",
                    "Enable queues (fq_codel/CAKE) on the router and check access point placement.")
            scores["latency"] = 0.5
        else:
            scores["latency"] = 1.0
            passed.append(f"Latency is healthy (router {gw_ms:.0f} ms, internet {wan_ms:.0f} ms).")
    else:
        not_checked.append("Latency")

    # External internet exposure: the SERVER fills in data["_external"] from the request's own public IP
    # (see external.py); the client can't set it, so this reflects a real check from the internet or nothing.
    external = data.get("_external") if isinstance(data.get("_external"), dict) else None
    public_ip = ""
    if external and external.get("checked"):
        public_ip = str(external.get("ip") or "")
        for item in external.get("findings", []):
            finding("external", item["severity"], item["title"], item["issue"], item["fix"])
        scores["external"] = 0.0 if external.get("findings") else 1.0
        if not external.get("findings"):
            passed.append(f"No router-management ports are open to the internet on this network's public address ({public_ip}).")
    else:
        not_checked.append("Internet exposure" + (f" ({external['reason']})" if external and external.get("reason") else ""))

    weights = {key: points for key, _, points in CHECKS}
    possible = sum(weights[key] for key in scores)
    score = round(100 * sum(weights[k] * v for k, v in scores.items()) / possible) if possible else 0
    grade = next(letter for floor, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")) if score >= floor) if possible else "N/A"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order[f["severity"]])
    if any(f["severity"] == "critical" for f in findings) and grade in ("A", "B"):
        grade = "C"
    elif any(f["severity"] == "high" for f in findings) and grade == "A":
        grade = "B"
    return {
        "site_name": str(data.get("site_name") or "")[:80],
        "domain": str(data.get("domain") or "")[:253],
        "gateway_ip": gateway_ip,
        "public_ip": public_ip,
        "ssid": ssid,
        "hosts_scanned": hosts_scanned,
        "score": score,
        "grade": grade,
        "findings": findings,
        "passed": passed,
        "not_checked": not_checked,
        "agent": str(data.get("agent") or "")[:60],
        "audited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
