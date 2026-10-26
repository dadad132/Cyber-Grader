"""Security headers, cookie flags and version banners on the site's HTTPS homepage."""
from __future__ import annotations

import re

from ..models import Deductions, NotApplicable, Outcome, Severity
from ..net import homepage
from . import HEADERS, check

HIGH, MEDIUM, LOW = Severity.HIGH, Severity.MEDIUM, Severity.LOW

HSTS_MIN_AGE = 15_552_000  # 180 days
_LEAKY_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
_VERSION = re.compile(r"\d+\.\d+|/\s*v?\d")
_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|login|jwt|remember", re.I)


def _show(name: str, value: str) -> str:
    return f"{'-'.join(part.capitalize() for part in name.split('-'))}: {value}" if value else ""


def _duration(seconds: int) -> str:
    days = seconds // 86400
    if days < 1:
        return f"{seconds} seconds"
    if days < 365:
        return f"{days} days"
    years = days // 365
    return f"{years} year{'s' if years > 1 else ''}"


def parse_directives(value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in value.split(";"):
        name, _, argument = part.strip().partition("=")
        if name:
            directives.setdefault(name.strip().lower(), argument.strip().strip('"'))
    return directives


@check("homepage", HEADERS, "Homepage response")
def check_homepage(ctx) -> Outcome:
    page = homepage(ctx)
    redirects = len(page.chain) - 1
    after = f" after {redirects} redirect{'s' if redirects > 1 else ''}" if redirects else ""
    evidence = "\n".join(f"{status} {url}" for status, url in page.chain)
    if page.status >= 400:
        return Outcome.info(
            f"{page.url} answered HTTP {page.status}{after}. That's usually bot protection or an error page, so the header "
            "results may not match what visitors see. If the site blocks the scanner, set a browser-like user agent in the admin settings.",
            evidence,
        )
    insecure = " The certificate is invalid, so this page was loaded without verifying it." if page.insecure else ""
    return Outcome.info(f"Headers were read from {page.url} (HTTP {page.status}{after}).{insecure}", evidence)


@check("hsts", HEADERS, "Strict-Transport-Security (HSTS)", 7)
def check_hsts(ctx) -> Outcome:
    value = homepage(ctx).header("strict-transport-security")
    fix = "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on every HTTPS response."
    if not value:
        return Outcome.fail(
            MEDIUM,
            "No HSTS header, so browsers keep trying plain HTTP first. That leaves room for SSL-stripping attacks on public Wi-Fi.",
            fix,
        )
    evidence = _show("strict-transport-security", value)
    directives = parse_directives(value)
    age = directives.get("max-age", "")
    if not age.isdigit():
        return Outcome.fail(MEDIUM, "The HSTS header has no valid max-age, so browsers ignore it.", fix, evidence)
    seconds = int(age)
    if seconds == 0:
        return Outcome.fail(MEDIUM, "HSTS max-age=0 switches HSTS off.", fix, evidence)
    if seconds < HSTS_MIN_AGE:
        return Outcome.warn(0.5, LOW, f"HSTS max-age is only {_duration(seconds)}; at least 6 months is recommended.",
                            fix, evidence)
    extras = [text for text, key in (("including subdomains", "includesubdomains"), ("preload-ready", "preload"))
              if key in directives]
    suffix = f", {' and '.join(extras)}" if extras else ""
    return Outcome.ok(f"HSTS tells browsers to use HTTPS only, for {_duration(seconds)}{suffix}.", evidence)


def evaluate_csp(policy: str) -> list[tuple[float, Severity, str]]:
    """Weaknesses in a Content-Security-Policy, as (penalty, severity, problem) tuples."""
    directives: dict[str, list[str]] = {}
    for part in re.split(r"[;,]", policy):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return [(0.5, MEDIUM, "The CSP doesn't restrict where scripts load from (no script-src or default-src), so it gives little XSS protection.")]
    issues = []
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in scripts)
    if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
        issues.append((0.35, LOW, "The CSP allows 'unsafe-inline' scripts, which cancels most of its XSS protection."))
    if "'strict-dynamic'" not in scripts and any(t in ("*", "http:", "https:", "data:") for t in scripts):
        issues.append((0.25, LOW, "The CSP lets scripts load from any host ('*', 'https:' or 'data:')."))
    if "'unsafe-eval'" in scripts:
        issues.append((0.1, LOW, "The CSP allows 'unsafe-eval'."))
    return issues


@check("csp", HEADERS, "Content-Security-Policy", 7)
def check_csp(ctx) -> Outcome:
    page = homepage(ctx)
    policy = page.header("content-security-policy")
    if not policy:
        report_only = page.header("content-security-policy-report-only")
        if report_only:
            return Outcome.warn(
                0.25, LOW, "A CSP is deployed in report-only mode, so it isn't enforced yet.",
                "Once the violation reports are clean, send the same policy as Content-Security-Policy.",
                _show("content-security-policy-report-only", report_only),
            )
        return Outcome.fail(
            MEDIUM,
            "No Content-Security-Policy header. CSP is the main browser defence against cross-site scripting (XSS) and injected scripts.",
            "Add a Content-Security-Policy, starting from \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\" "
            "and allow-listing the third-party sources the site needs. Trial it with Content-Security-Policy-Report-Only first.",
        )
    d = Deductions()
    for penalty, severity, problem in evaluate_csp(policy):
        d.add(penalty, severity, problem,
              "Tighten script-src: use nonces or hashes instead of 'unsafe-inline', and name specific hosts instead of wildcards.")
    return d.outcome("An enforced Content-Security-Policy restricts where scripts can load from.",
                     _show("content-security-policy", policy))


@check("clickjacking", HEADERS, "Clickjacking protection", 4)
def check_clickjacking(ctx) -> Outcome:
    page = homepage(ctx)
    xfo = page.header("x-frame-options").strip()
    csp = page.header("content-security-policy")
    if re.search(r"(^|[;,])\s*frame-ancestors\b", csp, re.I):
        return Outcome.ok("CSP frame-ancestors controls which sites may embed this page.")
    if xfo.upper() in ("DENY", "SAMEORIGIN"):
        return Outcome.ok(f"X-Frame-Options: {xfo.upper()} stops other sites framing this page.")
    fix = "Add 'X-Frame-Options: SAMEORIGIN' (or the CSP directive \"frame-ancestors 'self'\")."
    if xfo:
        return Outcome.warn(0.25, LOW, f"X-Frame-Options value '{xfo}' is obsolete or invalid, so browsers ignore it.",
                            fix, _show("x-frame-options", xfo))
    return Outcome.fail(
        LOW, "Nothing stops other sites embedding this page in a hidden frame to trick visitors into clicking (clickjacking).", fix,
    )


@check("nosniff", HEADERS, "X-Content-Type-Options", 3)
def check_nosniff(ctx) -> Outcome:
    value = homepage(ctx).header("x-content-type-options")
    if value.strip().lower() == "nosniff":
        return Outcome.ok("X-Content-Type-Options: nosniff stops browsers guessing (MIME-sniffing) file types.")
    return Outcome.fail(
        LOW, "Missing 'X-Content-Type-Options: nosniff', so browsers may run mislabelled or uploaded files as scripts.",
        "Add 'X-Content-Type-Options: nosniff'.", _show("x-content-type-options", value),
    )


@check("referrer_policy", HEADERS, "Referrer-Policy", 2)
def check_referrer_policy(ctx) -> Outcome:
    value = homepage(ctx).header("referrer-policy")
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""
    fix = "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    if not effective:
        return Outcome.fail(
            LOW, "No Referrer-Policy header. Modern browsers default to a safe policy, but older ones send full page URLs "
                 "(which can contain tokens or personal data) to other sites.", fix,
        )
    evidence = _show("referrer-policy", value)
    if effective in ("unsafe-url", "no-referrer-when-downgrade"):
        return Outcome.warn(0.5, LOW, f"Referrer-Policy '{effective}' sends full page URLs to other sites.", fix, evidence)
    return Outcome.ok(f"Referrer-Policy '{effective}' limits what leaks to other sites.", evidence)


@check("permissions_policy", HEADERS, "Permissions-Policy", 1)
def check_permissions_policy(ctx) -> Outcome:
    page = homepage(ctx)
    value = page.header("permissions-policy") or page.header("feature-policy")
    if value:
        return Outcome.ok("Permissions-Policy restricts powerful browser features.", _show("permissions-policy", value))
    return Outcome.fail(
        LOW, "No Permissions-Policy header to switch off browser features (camera, microphone, location) the site doesn't use.",
        "Add e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
    )


@check("banner", HEADERS, "Software version disclosure", 3)
def check_banner(ctx) -> Outcome:
    page = homepage(ctx)
    server = page.header("server")
    leaks = [_show("server", server)] if _VERSION.search(server) else []
    leaks += [_show(name, page.header(name)) for name in _LEAKY_HEADERS if page.header(name)]
    if leaks:
        return Outcome.fail(
            LOW,
            "Response headers reveal the server software and version, which helps attackers match the site to known exploits.",
            "Hide version banners: 'server_tokens off;' (nginx), 'ServerTokens Prod' and 'ServerSignature Off' (Apache), "
            "'expose_php = Off' (PHP), and remove X-Powered-By / X-AspNet-Version headers.",
            "\n".join(leaks),
        )
    return Outcome.ok("Response headers don't reveal software versions.", _show("server", server))


def parse_set_cookie(raw: str) -> tuple[str, dict[str, str]]:
    first, *attributes = raw.split(";")
    name = first.split("=", 1)[0].strip()
    flags = {}
    for attribute in attributes:
        key, _, value = attribute.strip().partition("=")
        if key:
            flags[key.lower()] = value.strip()
    return name, flags


def _names(names: list[str]) -> str:
    unique = list(dict.fromkeys(names))
    return ", ".join(unique[:6]) + (" …" if len(unique) > 6 else "")


@check("cookies", HEADERS, "Cookie security flags", 3)
def check_cookies(ctx) -> Outcome:
    page = homepage(ctx)
    cookies = [parse_set_cookie(raw) for raw in page.cookies]
    if not cookies:
        raise NotApplicable("The homepage sets no cookies.")
    not_secure = [name for name, flags in cookies if "secure" not in flags]
    readable = [name for name, flags in cookies if "httponly" not in flags and _SESSION_COOKIE.search(name)]
    no_samesite = [name for name, flags in cookies if "samesite" not in flags]
    d = Deductions()
    if not_secure:
        d.add(0.5, MEDIUM, f"Cookies without the Secure flag can leak over plain HTTP: {_names(not_secure)}.",
              "Set Secure on every cookie.")
    if readable:
        d.add(0.35, MEDIUM, f"Session-like cookies are readable by JavaScript (no HttpOnly), so an XSS bug could steal them: {_names(readable)}.",
              "Set HttpOnly on session and authentication cookies.")
    if no_samesite:
        d.add(0.15, LOW, f"Cookies without a SameSite attribute: {_names(no_samesite)}.",
              "Set SameSite=Lax (or Strict) explicitly.")
    # Cookie values may be session identifiers, so keep them out of the report.
    evidence = "\n".join(re.sub(r"^([^=;]*)=[^;]*", r"\1=…", raw) for raw in page.cookies)
    return d.outcome(f"All {len(cookies)} cookie(s) set by the homepage have Secure, SameSite and (where it matters) HttpOnly.", evidence)
