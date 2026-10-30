"""Turning user input into a valid domain, and refusing to scan private networks."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class BlockedTarget(Exception):
    """The host resolves to a private, loopback or otherwise non-public address."""


def normalize_domain(raw: str) -> str:
    """Accepts 'example.com', 'https://Example.com/path', 'bücher.de', ... and returns the ASCII domain."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Please enter a domain name.")
    if "://" not in text:
        text = "//" + text
    try:
        host = urlsplit(text).hostname
    except ValueError:
        host = None
    if not host:
        raise ValueError(f"Couldn't find a domain name in {raw!r}.")
    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name rather than an IP address.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError(f"{raw!r} is not a valid domain name.") from None
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or labels[-1].isdigit() or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"{raw!r} is not a valid domain name.")
    return host


def display_name(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_public_host(host: str, port: int) -> None:
    """Raise BlockedTarget unless every address the host resolves to is public (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return  # the connection attempt will fail on its own
    for info in infos:
        ip = info[4][0]
        if not is_public_ip(ip):
            raise BlockedTarget(f"{host} resolves to a private or reserved address ({ip}), which is not scanned.")
