"""DNS lookups that tell "this record doesn't exist" apart from "the lookup failed"."""
from __future__ import annotations

import dns.exception
import dns.resolver
import dns.reversename

from .memo import Memo

FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]


class Inconclusive(Exception):
    """A lookup failed for reasons that say nothing about the domain's configuration."""


def _describe(exc: Exception) -> str:
    if isinstance(exc, dns.exception.Timeout):
        return "timed out"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "no nameserver gave a usable answer (SERVFAIL)"
    return type(exc).__name__


class DNSClient:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 4.0) -> None:
        if nameservers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(nameservers)
        else:
            try:
                resolver = dns.resolver.Resolver()
            except dns.resolver.NoResolverConfiguration:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = FALLBACK_NAMESERVERS
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2
        self.resolver = resolver
        self._memo = Memo()

    def query(self, name: str, rdtype: str) -> list:
        """Records of the given type; [] if the name or type doesn't exist. Raises Inconclusive."""
        return self._memo.get((name.lower(), rdtype), lambda: self._query(name, rdtype))

    def _query(self, name: str, rdtype: str) -> list:
        try:
            answer = self.resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.DNSException as exc:
            raise Inconclusive(f"{rdtype} lookup for {name} {_describe(exc)}") from exc
        return list(answer)

    def exists(self, name: str) -> bool:
        try:
            self.resolver.resolve(name, "SOA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.DNSException as exc:
            raise Inconclusive(f"Lookup for {name} {_describe(exc)}") from exc
        return True

    def txt(self, name: str) -> list[str]:
        # Long TXT records are split into 255-byte strings that must be joined without spaces.
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self.query(name, "TXT")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        """(preference, host) pairs; a null MX (RFC 7505) has host ''."""
        records = []
        for r in self.query(name, "MX"):
            host = r.exchange.to_text(omit_final_dot=True).lower()
            records.append((r.preference, "" if host == "." else host))
        return records

    def caa(self, name: str) -> list[tuple[int, str, str]]:
        return [(r.flags, r.tag.decode(), r.value.decode("utf-8", "replace")) for r in self.query(name, "CAA")]

    def addresses(self, name: str) -> list[str]:
        found: list[str] = []
        failures: list[Inconclusive] = []
        for rdtype in ("A", "AAAA"):
            try:
                found += [r.address for r in self.query(name, rdtype)]
            except Inconclusive as exc:
                failures.append(exc)
        if not found and failures:
            raise failures[0]
        return found

    def ipv4(self, name: str) -> list[str]:
        return [r.address for r in self.query(name, "A")]

    def ptr(self, ip: str) -> list[str]:
        """Reverse DNS names for an address."""
        return [r.target.to_text(omit_final_dot=True).lower()
                for r in self.query(dns.reversename.from_address(ip).to_text(), "PTR")]

    def zone_apex(self, name: str) -> str:
        """The zone that contains name, e.g. 'example.co.za' for 'shop.example.co.za'."""
        try:
            zone = dns.resolver.zone_for_name(name, resolver=self.resolver)
        except dns.exception.DNSException as exc:
            raise Inconclusive(f"Finding the DNS zone for {name} {_describe(exc)}") from exc
        return zone.to_text(omit_final_dot=True)

    def has_ds(self, zone: str) -> bool:
        return bool(self.query(zone, "DS"))
