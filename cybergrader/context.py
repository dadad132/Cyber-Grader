from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ._version import __version__
from .dnsutil import DNSClient
from .memo import Memo
from .target import assert_public_host

DEFAULT_USER_AGENT = f"Mozilla/5.0 (compatible; CyberHygieneGrader/{__version__})"


@dataclass
class ScanContext:
    """Everything a check needs: the domain, a DNS client, network settings and a shared cache."""

    domain: str
    dns: DNSClient
    timeout: float = 6.0
    allow_private: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    memo: Memo = field(default_factory=Memo)
    dnsbl: Any = None  # a dnsbl.DnsblClient; None = one using the system resolver

    def guard(self, host: str, port: int) -> None:
        if not self.allow_private:
            assert_public_host(host, port)
