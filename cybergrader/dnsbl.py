"""DNS blacklist lookups (DNSBL for IP addresses, RHSBL for domains) that never mistake an error for a listing.

Blacklists signal problems with answers that look like listings: Spamhaus answers 127.255.255.254 when a query
comes through a big public resolver, SURBL and URIBL answer 127.0.0.1 when they refuse a query, and lists that
shut down have answered "listed" for everything. So each answer is checked against the codes the list
documents, and each list is first asked about its RFC 5782 test entries (one that must be listed, one that
must not be). A list that gets those wrong is reported as "couldn't check", never as a listing.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

import dns.exception
import dns.nameserver
import dns.resolver

from .models import Severity

CRITICAL, HIGH, MEDIUM, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_SPAMHAUS_ZEN = {
    "127.0.0.2": (HIGH, "Spamhaus SBL: a known spam source"),
    "127.0.0.3": (HIGH, "Spamhaus CSS: sending low-reputation bulk spam"),
    "127.0.0.9": (HIGH, "Spamhaus DROP: a hijacked or criminal network"),
    **{f"127.0.0.{n}": (HIGH, "Spamhaus XBL: infected with malware or used to relay abuse") for n in (4, 5, 6, 7)},
    **{f"127.0.0.{n}": (MEDIUM, "Spamhaus PBL: a home or office connection that isn't meant to send email directly")
       for n in (10, 11)},
}
_SPAMHAUS_DBL = {
    "127.0.1.2": (HIGH, "Spamhaus DBL: a domain seen in spam"),
    "127.0.1.4": (CRITICAL, "Spamhaus DBL: a phishing domain"),
    "127.0.1.5": (CRITICAL, "Spamhaus DBL: a domain serving malware"),
    "127.0.1.6": (CRITICAL, "Spamhaus DBL: a botnet command-and-control domain"),
    "127.0.1.102": (HIGH, "Spamhaus DBL: a legitimate domain abused to send spam"),
    "127.0.1.103": (HIGH, "Spamhaus DBL: a legitimate domain abused as a spam redirector"),
    "127.0.1.104": (CRITICAL, "Spamhaus DBL: a legitimate domain abused for phishing"),
    "127.0.1.105": (CRITICAL, "Spamhaus DBL: a legitimate domain abused to serve malware"),
    "127.0.1.106": (CRITICAL, "Spamhaus DBL: a legitimate domain abused for botnet control"),
}


@dataclass(frozen=True)
class Blacklist:
    name: str
    zone: str
    kind: str  # "ip" or "domain"
    codes: dict  # answer (or, for bitmask lists, bit value) -> (severity, meaning)
    test: str  # an entry the list must report as listed (RFC 5782)
    url: str  # where to look up a listing and request removal
    ignore: frozenset = frozenset()  # answers (or bits) that are known but aren't listings
    bitmask: bool = False  # the last octet of the answer is a set of flags (SURBL, URIBL)
    dqs: str = ""  # Spamhaus Data Query Service zone, used when a DQS key is set

    @property
    def negative(self) -> str:
        return "127.0.0.1" if self.kind == "ip" else "invalid"  # RFC 5782: must never be listed


IP_LISTS = (
    Blacklist("Spamhaus ZEN", "zen.spamhaus.org", "ip", _SPAMHAUS_ZEN, "127.0.0.2", "https://check.spamhaus.org/", dqs="zen"),
    Blacklist("Barracuda", "b.barracudacentral.org", "ip", {"127.0.0.2": (HIGH, "Barracuda Reputation Block List")},
              "127.0.0.2", "https://www.barracudacentral.org/lookups"),
    Blacklist("SpamCop", "bl.spamcop.net", "ip", {"127.0.0.2": (HIGH, "SpamCop: reported for sending spam")},
              "127.0.0.2", "https://www.spamcop.net/bl.shtml"),
    Blacklist("UCEPROTECT level 1", "dnsbl-1.uceprotect.net", "ip", {"127.0.0.2": (MEDIUM, "UCEPROTECT level 1: sent spam to its traps")},
              "127.0.0.2", "https://www.uceprotect.net/en/rblcheck.php"),
    Blacklist("PSBL", "psbl.surriel.com", "ip", {"127.0.0.2": (MEDIUM, "PSBL: sent spam to its traps")},
              "127.0.0.2", "https://psbl.org/"),
    Blacklist("Mailspike", "bl.mailspike.net", "ip", {"127.0.0.2": (MEDIUM, "Mailspike: poor sending reputation")},
              "127.0.0.2", "https://mailspike.org/", ignore=frozenset(f"127.0.0.{n}" for n in range(10, 21))),
    Blacklist("blocklist.de", "bl.blocklist.de", "ip",
              {"127.0.0.2": (MEDIUM, "blocklist.de: reported for attacks such as password guessing (often a hacked server)")},
              "127.0.0.2", "https://www.blocklist.de/en/search.html"),
    Blacklist("0spam", "bl.0spam.org", "ip", {"127.0.0.2": (LOW, "0spam: sent spam to its traps")}, "127.0.0.2", "https://0spam.org/"),
    Blacklist("GBUdb Truncate", "truncate.gbudb.net", "ip", {"127.0.0.2": (LOW, "GBUdb Truncate: mostly sends spam")},
              "127.0.0.2", "https://www.gbudb.com/"),
)

DOMAIN_LISTS = (
    Blacklist("Spamhaus DBL", "dbl.spamhaus.org", "domain", _SPAMHAUS_DBL, "dbltest.com", "https://check.spamhaus.org/", dqs="dbl"),
    Blacklist("SURBL", "multi.surbl.org", "domain",
              {8: (CRITICAL, "SURBL: a phishing domain"), 16: (CRITICAL, "SURBL: a domain serving malware"),
               128: (HIGH, "SURBL: a hacked website"), 64: (HIGH, "SURBL: a domain seen in spam"),
               2: (HIGH, "SURBL: a domain seen in spam"), 4: (HIGH, "SURBL: a domain seen in spam"),
               32: (HIGH, "SURBL: a domain seen in spam")},
              "test.surbl.org", "https://www.surbl.org/", bitmask=True),
    Blacklist("URIBL", "multi.uribl.com", "domain",
              {2: (HIGH, "URIBL black: a domain seen in spam"), 8: (MEDIUM, "URIBL red: newly seen in spam")},
              "test.uribl.com", "https://www.uribl.com/", ignore=frozenset({4}), bitmask=True),  # 4 = grey: bulk mail, not a block
)

HEALTH_TTL, BROKEN_TTL = 3600, 600  # seconds to trust a list's test-entry result
_health: dict[tuple, tuple[float, str]] = {}  # (resolver, zone) -> (expiry, "" if working else why not)
_health_lock = threading.Lock()


class ListError(Exception):
    """The list couldn't give a usable answer (timeout, refusal or an undocumented code)."""


@dataclass
class Listing:
    target: str
    blacklist: Blacklist
    severity: Severity
    meaning: str
    detail: str = ""  # the list's own explanation (its TXT record), usually with a link to the listing


@dataclass
class Sweep:
    listings: list[Listing] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)  # names of the lists that answered properly
    unavailable: dict[str, str] = field(default_factory=dict)  # list name -> why it couldn't be checked

    @property
    def worst(self) -> Severity | None:
        return max((item.severity for item in self.listings), key=lambda s: s.rank, default=None)


def _parse_nameserver(value: str):
    host, sep, port = value.rpartition(":")
    if sep and "." in host and port.isdigit():  # IPv4 with a port, e.g. 127.0.0.1:5335
        return dns.nameserver.Do53Nameserver(host, int(port))
    return value


class DnsblClient:
    """Queries blacklists through its own resolver (ideally a local one: Spamhaus and URIBL refuse queries that
    come through big public resolvers). spamhaus_key switches Spamhaus to its Data Query Service."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 3.0, spamhaus_key: str = "",
                 lookup: Callable[[str], list[str]] | None = None) -> None:
        self.spamhaus_key = spamhaus_key.strip()
        self._lookup = lookup
        self.resolver = None
        if lookup is None:
            if nameservers:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [_parse_nameserver(server) for server in nameservers]
            else:
                resolver = dns.resolver.Resolver()
            resolver.timeout, resolver.lifetime = timeout, timeout * 2
            self.resolver = resolver
        self.key = (tuple(str(server) for server in self.resolver.nameservers) if self.resolver else id(lookup), self.spamhaus_key)

    def zone(self, blacklist: Blacklist) -> str:
        if blacklist.dqs and self.spamhaus_key:
            return f"{self.spamhaus_key}.{blacklist.dqs}.dq.spamhaus.net"
        return blacklist.zone

    def answers(self, name: str) -> list[str]:
        """A records for name; [] if it doesn't exist. Raises ListError if the lookup fails."""
        if self._lookup is not None:
            return self._lookup(name)
        try:
            return [record.address for record in self.resolver.resolve(name, "A")]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout as exc:
            raise ListError("timed out") from exc
        except dns.exception.DNSException as exc:
            raise ListError(f"lookup failed ({type(exc).__name__})") from exc

    def query_name(self, blacklist: Blacklist, target: str) -> str:
        if blacklist.kind == "ip":
            return ".".join(reversed(target.split("."))) + "." + self.zone(blacklist)
        return f"{target}.{self.zone(blacklist)}"

    def explanation(self, blacklist: Blacklist, target: str) -> str:
        """The list's TXT record for a listing (e.g. 'Listed by SBL, see https://...'), or '' if it has none."""
        if self._lookup is not None:
            return ""
        try:
            texts = [b"".join(record.strings).decode("utf-8", "replace") for record in
                     self.resolver.resolve(self.query_name(blacklist, target), "TXT")]
        except dns.exception.DNSException:
            return ""
        if self.spamhaus_key:  # never show the DQS key in a report
            texts = [text.replace(self.spamhaus_key, "...") for text in texts]
        return " | ".join(dict.fromkeys(texts))[:400]

    def lookup(self, blacklist: Blacklist, target: str) -> list[tuple[Severity, str]]:
        """What the list says about target: [] if it isn't listed. Raises ListError for anything unexpected."""
        reasons = []
        for answer in self.answers(self.query_name(blacklist, target)):
            if blacklist.bitmask:
                parts = answer.split(".")
                if answer == "127.0.0.1" or parts[:3] != ["127", "0", "0"]:
                    raise ListError(f"refused the query (answered {answer})")
                flags = int(parts[3])
                reasons += [blacklist.codes[bit] for bit in sorted(blacklist.codes) if flags & bit and bit not in blacklist.ignore]
            elif answer in blacklist.codes:
                reasons.append(blacklist.codes[answer])
            elif answer not in blacklist.ignore:
                raise ListError(f"gave an undocumented answer ({answer}), so it may be refusing queries from this server")
        return list(dict.fromkeys(reasons))

    def health(self, blacklist: Blacklist) -> str:
        """'' if the list answers its test entries correctly, else why it can't be trusted right now."""
        key = (self.key, blacklist.zone)
        now = time.monotonic()
        with _health_lock:
            cached = _health.get(key)
        if cached and cached[0] > now:
            return cached[1]
        try:
            if not self.lookup(blacklist, blacklist.test):
                problem = "didn't list its own test entry, so it isn't answering properly from this server"
            elif self.lookup(blacklist, blacklist.negative):
                problem = "listed an entry that must never be listed, so its answers can't be trusted"
            else:
                problem = ""
        except ListError as exc:
            problem = str(exc)
        with _health_lock:
            _health[key] = (now + (BROKEN_TTL if problem else HEALTH_TTL), problem)
        return problem

    def sweep(self, blacklists: tuple[Blacklist, ...], targets: list[str]) -> Sweep:
        """Look every target up on every list that passes its health check."""
        result = Sweep()
        with ThreadPoolExecutor(max_workers=12) as pool:
            problems = dict(zip((bl.name for bl in blacklists), pool.map(self.health, blacklists)))
            working = [bl for bl in blacklists if not problems[bl.name]]
            result.unavailable = {name: problem for name, problem in problems.items() if problem}
            pairs = [(bl, target) for bl in working for target in targets]

            def one(pair):
                try:
                    reasons = self.lookup(*pair)
                except ListError as exc:
                    return pair, [], "", str(exc)
                return pair, reasons, self.explanation(*pair) if reasons else "", ""

            for (blacklist, target), reasons, detail, error in pool.map(one, pairs):
                if error:
                    result.unavailable.setdefault(blacklist.name, error)
                for severity, meaning in reasons:
                    result.listings.append(Listing(target, blacklist, severity, meaning, detail))
        result.checked = [bl.name for bl in working if bl.name not in result.unavailable]
        return result


def valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False
