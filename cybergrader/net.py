"""HTTP fetching with manual redirect handling (so every hop can be SSRF-checked) and shared page loads."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from .models import NotApplicable, NotTested

if TYPE_CHECKING:
    from .context import ScanContext

# Header checks still run against sites with broken certificates (the certificate problem is
# reported by its own check), so silence urllib3's warning for those unverified requests.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NO_WEBSITE = "No website found: neither the domain nor its www host has an address record, so web checks don't apply."


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict[str, str]  # lower-cased names
    cookies: list[str] = field(default_factory=list)  # raw Set-Cookie values from every hop
    chain: list[tuple[int, str]] = field(default_factory=list)
    insecure: bool = False  # certificate verification had to be turned off
    body: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def fetch(ctx: ScanContext, url: str, *, follow: bool = True, verify: bool = True,
          max_body: int = 0, max_hops: int = 8) -> HttpResult:
    chain: list[tuple[int, str]] = []
    cookies: list[str] = []
    with requests.Session() as session:
        session.headers["User-Agent"] = ctx.user_agent
        for _ in range(max_hops + 1):
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise requests.exceptions.InvalidURL(f"Unsupported redirect target: {url}")
            ctx.guard(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
            resp = session.get(url, allow_redirects=False, timeout=ctx.timeout, verify=verify, stream=True)
            with resp:
                cookies.extend(resp.raw.headers.getlist("Set-Cookie"))
                chain.append((resp.status_code, url))
                location = resp.headers.get("Location")
                if follow and resp.is_redirect and location:
                    url = urljoin(url, location)
                    continue
                body = _read_body(resp, max_body) if max_body else ""
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResult(url, resp.status_code, headers, cookies, chain, not verify, body)
    raise requests.exceptions.TooManyRedirects(f"More than {max_hops} redirects starting at {chain[0][1]}")


def _read_body(resp: requests.Response, limit: int) -> str:
    data = resp.raw.read(limit, decode_content=True) or b""
    try:
        return data.decode(resp.encoding or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def fetch_lenient(ctx: ScanContext, url: str, **kwargs) -> HttpResult:
    """fetch(), retrying without certificate verification if the certificate is bad."""
    try:
        return fetch(ctx, url, **kwargs)
    except requests.exceptions.SSLError:
        return fetch(ctx, url, verify=False, **kwargs)


def describe_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS error"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connection timed out"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "server didn't respond in time"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection refused or reset"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "too many redirects"
    return str(exc) or type(exc).__name__


def web_host(ctx: ScanContext) -> str:
    """The host serving the website: the domain itself, else www.<domain>."""

    def find() -> str | None:
        candidates = [ctx.domain] if ctx.domain.startswith("www.") else [ctx.domain, f"www.{ctx.domain}"]
        for host in candidates:
            if ctx.dns.addresses(host):
                return host
        return None

    host = ctx.memo.get("web_host", find)
    if host is None:
        raise NotApplicable(NO_WEBSITE)
    return host


def homepage(ctx: ScanContext) -> HttpResult:
    """The HTTPS homepage after redirects, loaded once and shared by every header check."""
    host = web_host(ctx)

    def load() -> HttpResult:
        try:
            return fetch_lenient(ctx, f"https://{host}/")
        except requests.RequestException as exc:
            raise NotTested(f"Not tested: couldn't load https://{host}/ ({describe_error(exc)}).") from exc

    return ctx.memo.get("homepage", load)
