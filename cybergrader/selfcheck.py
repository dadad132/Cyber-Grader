"""Environment checks for the admin portal: can this machine grade domains correctly?"""
from __future__ import annotations

import importlib.metadata
import platform
import re
import socket
import ssl
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from .context import DEFAULT_USER_AGENT
from .dnsbl import DOMAIN_LISTS, IP_LISTS, DnsblClient
from .dnsutil import DNSClient, Inconclusive
from .settings import Settings

PUBLIC_DNS_TIP = "In Settings > Website & scanning, set DNS servers to 1.1.1.1, 8.8.8.8 (or clear them if they're already set)."
REQUIRED_PACKAGES = (("dnspython", "2.4"), ("requests", "2.31"), ("cryptography", "42"), ("certifi", None), ("Flask", "3.0"))


@dataclass
class SystemCheck:
    name: str
    status: str  # "ok", "warn", "fail" or "info"
    detail: str
    fix: str = ""


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:3])


def _python() -> SystemCheck:
    version = platform.python_version()
    if sys.version_info >= (3, 10):
        return SystemCheck("Python", "ok", f"Python {version}.")
    return SystemCheck("Python", "fail", f"Python {version} is too old.", "Install Python 3.10 or newer from python.org.")


def _packages() -> SystemCheck:
    found, problems = [], []
    for name, minimum in REQUIRED_PACKAGES:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{name} is missing")
            continue
        found.append(f"{name} {version}")
        if minimum and _version_tuple(version) < _version_tuple(minimum):
            problems.append(f"{name} {version} is older than {minimum}")
    if problems:
        return SystemCheck("Python packages", "fail", "; ".join(problems) + ".",
                           "In the project folder run: python -m pip install -r requirements.txt")
    return SystemCheck("Python packages", "ok", ", ".join(found) + ".")


def _resolver(settings: Settings) -> tuple[DNSClient, str]:
    client = DNSClient(settings.nameservers or None, timeout=3.0)
    source = "your DNS settings" if settings.nameservers else "this computer's DNS"
    return client, f"{', '.join(client.resolver.nameservers) or 'no servers'} ({source})"


def _dns(settings: Settings) -> SystemCheck:
    client, described = _resolver(settings)
    started = time.monotonic()
    try:
        answered = bool(client.addresses("example.com")) and bool(client.txt("google.com"))
    except Inconclusive as exc:
        return SystemCheck("DNS lookups", "fail", f"Lookups through {described} failed: {exc}.", PUBLIC_DNS_TIP)
    if not answered:
        return SystemCheck("DNS lookups", "fail", f"{described} returned no records for example.com or google.com.", PUBLIC_DNS_TIP)
    elapsed = round((time.monotonic() - started) * 1000)
    return SystemCheck("DNS lookups", "ok", f"Resolving through {described}; answered in {elapsed} ms.")


def _blacklists(settings: Settings) -> SystemCheck:
    """Do the spam blacklists answer their test entries through the configured resolver?"""
    client = DnsblClient(settings.dnsbl_nameservers or settings.nameservers or None, timeout=3.0,
                         spamhaus_key=settings.spamhaus_dqs_key)
    lists = IP_LISTS + DOMAIN_LISTS
    with ThreadPoolExecutor(max_workers=len(lists)) as pool:
        problems = dict(zip((bl.name for bl in lists), pool.map(client.health, lists)))
    broken = {name: problem for name, problem in problems.items() if problem}
    via = ", ".join(str(server) for server in client.resolver.nameservers)
    if not broken:
        return SystemCheck("Blacklist lookups", "ok", f"All {len(lists)} blacklists answer correctly through {via}.")
    detail = f"{len(lists) - len(broken)} of {len(lists)} blacklists answer through {via}. Not answering: " +         "; ".join(f"{name} ({problem})" for name, problem in broken.items()) + "."
    fix = ("Reports show these lists as 'couldn't check'. Spamhaus and URIBL refuse lookups through public DNS services: "
           "on the server, the installer's local resolver (Settings > Website & scanning > Blacklist checks: 127.0.0.1) "
           "fixes that; for Spamhaus at commercial volumes add a DQS key.")
    major = any(name.startswith("Spamhaus") for name in broken)
    return SystemCheck("Blacklist lookups", "warn" if major else "info", detail, fix)


def _dns_record_types(settings: Settings) -> SystemCheck:
    client, described = _resolver(settings)
    try:
        missing = [kind for kind, present in (("CAA", bool(client.caa("google.com"))),
                                              ("DS", client.has_ds("cloudflare.com"))) if not present]
        # github.com publishes ~24 TXT records; some resolvers (e.g. WSL's DNS proxy) silently drop part of
        # such large answers, which would make the scanner report "no SPF record" for domains that have one.
        large_txt_complete = any(t.lower().startswith("v=spf1") for t in client.txt("github.com"))
    except Inconclusive as exc:
        return SystemCheck("DNS record types", "warn", f"CAA/DNSSEC lookups through {described} failed: {exc}.", PUBLIC_DNS_TIP)
    if not large_txt_complete:
        return SystemCheck(
            "DNS record types", "fail",
            f"{described} returned an incomplete answer for a domain with many TXT records, so domains like that "
            "would wrongly be reported as having no SPF record.",
            PUBLIC_DNS_TIP,
        )
    if missing:
        return SystemCheck(
            "DNS record types", "warn",
            f"{described} returned no {' or '.join(missing)} records for domains that have them, so the CAA and DNSSEC results would be wrong.",
            PUBLIC_DNS_TIP,
        )
    return SystemCheck("DNS record types", "ok", "CAA and DNSSEC (DS) lookups return correct answers.")


def _certificate_trust() -> SystemCheck:
    from .checks.tls import _STRICT

    host = "www.google.com"
    try:
        with socket.create_connection((host, 443), timeout=6) as sock, _STRICT.wrap_socket(sock, server_hostname=host) as tls:
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return SystemCheck(
            "HTTPS certificate checks", "fail",
            f"Verifying {host} failed ({exc.verify_message}). Something on this computer or network (antivirus HTTPS scanning, "
            "a corporate proxy or firewall) is intercepting HTTPS, so every website would wrongly be reported as untrusted.",
            "Turn off HTTPS/SSL scanning for Python in your antivirus, or run the grader on a machine whose traffic isn't intercepted.",
        )
    except OSError as exc:
        return SystemCheck("HTTPS certificate checks", "fail", f"Couldn't connect to {host}:443 ({exc}).",
                           "Check the internet connection and that outbound port 443 isn't blocked by a firewall.")
    return SystemCheck("HTTPS certificate checks", "ok",
                       f"Verified {host} against the Mozilla CA list over {version}; HTTPS isn't being intercepted.")


def _web_requests(settings: Settings) -> list[SystemCheck]:
    headers = {"User-Agent": settings.user_agent or DEFAULT_USER_AGENT}
    proxy = requests.utils.get_environ_proxies("https://example.com/").get("https")
    via = f" through proxy {proxy}" if proxy else ""
    results = []
    try:
        response = requests.get("https://example.com/", timeout=settings.timeout, headers=headers)
        results.append(SystemCheck("Outbound HTTPS", "ok", f"Web requests work{via} (example.com answered HTTP {response.status_code})."))
    except requests.RequestException as exc:
        results.append(SystemCheck("Outbound HTTPS", "fail", f"Fetching https://example.com/ failed{via}: {type(exc).__name__}.",
                                   "Check the internet connection, firewall and any HTTPS_PROXY setting."))
    try:
        requests.get("http://example.com/", timeout=settings.timeout, headers=headers, allow_redirects=False)
        results.append(SystemCheck("Outbound HTTP (port 80)", "ok", "Plain-HTTP requests work, so HTTP-to-HTTPS redirects can be tested."))
    except requests.RequestException:
        results.append(SystemCheck(
            "Outbound HTTP (port 80)", "warn",
            "Outbound port 80 seems blocked, so every site would wrongly pass the 'HTTP redirects to HTTPS' check.",
            "Allow outbound TCP port 80 for Python in the firewall.",
        ))
    return results


def _legacy_tls() -> SystemCheck:
    from .checks.tls import _LEGACY_ONLY

    if _LEGACY_ONLY is None:
        return SystemCheck("Legacy TLS testing", "warn",
                           f"{ssl.OPENSSL_VERSION} can't offer TLS 1.0/1.1, so the 'Legacy TLS disabled' check will show as undetermined.",
                           "Use the python.org build of Python, whose OpenSSL can still offer old protocols for testing.")
    return SystemCheck("Legacy TLS testing", "ok", f"{ssl.OPENSSL_VERSION} can test whether sites still accept TLS 1.0/1.1.")


def _storage(folder: Path) -> SystemCheck:
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / f".write-test-{uuid.uuid4().hex}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return SystemCheck("Settings storage", "fail", f"Can't write to {folder} ({exc}), so settings can't be saved.",
                           "Make the folder writable, or set the GRADER_DATA_DIR environment variable to a writable folder.")
    return SystemCheck("Settings storage", "ok", f"Settings and scan history are saved in {folder}.")


def run_selfcheck(settings: Settings, folder: Path) -> list[SystemCheck]:
    jobs = [_python, _packages, lambda: _dns(settings), lambda: _dns_record_types(settings), _certificate_trust,
            lambda: _web_requests(settings), _legacy_tls, lambda: _storage(folder), lambda: _blacklists(settings)]

    def run(job):
        try:
            return job()
        except Exception as exc:  # a broken probe should show up, not crash the dashboard
            return SystemCheck("System check", "fail", f"A check crashed: {type(exc).__name__}: {exc}")

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        outcomes = list(pool.map(run, jobs))
    flat: list[SystemCheck] = []
    for outcome in outcomes:
        flat.extend(outcome if isinstance(outcome, list) else [outcome])
    return flat
