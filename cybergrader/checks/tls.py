"""HTTPS certificate, protocol-version and HTTP-to-HTTPS redirect checks."""
from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlsplit

import certifi
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from ..models import NotTested, Outcome, Severity
from ..net import describe_error, fetch, web_host
from . import TLS, check

CRITICAL, HIGH, MEDIUM, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


def _permissive_context(max_version: ssl.TLSVersion | None = None) -> ssl.SSLContext | None:
    """A context that accepts anything (no verification, TLS 1.0+, every cipher) to describe broken servers."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
            if max_version:
                context.maximum_version = max_version
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)  # old servers lack secure renegotiation
    except (ValueError, ssl.SSLError):
        return None  # this Python/OpenSSL build can't speak legacy TLS
    return context


# Built once at import: the legacy-version setters warn, and warning filters aren't thread-safe.
_STRICT = ssl.create_default_context(cafile=certifi.where())
_PERMISSIVE = _permissive_context() or ssl.create_default_context(cafile=certifi.where())
_LEGACY_ONLY = _permissive_context(ssl.TLSVersion.TLSv1_1)
if _PERMISSIVE.verify_mode != ssl.CERT_NONE:
    _PERMISSIVE.check_hostname = False
    _PERMISSIVE.verify_mode = ssl.CERT_NONE


@dataclass
class TlsProbe:
    host: str
    reachable: bool
    error: str = ""         # why the TLS connection failed outright
    verified: bool = False
    verify_error: str = ""  # why a modern, verifying client rejected the connection
    version: str = ""
    cert: x509.Certificate | None = None


def _handshake(ctx, host: str, context: ssl.SSLContext) -> tuple[str, bytes | None]:
    ctx.guard(host, 443)
    with socket.create_connection((host, 443), timeout=ctx.timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version() or "", tls.getpeercert(binary_form=True)


def probe(ctx) -> TlsProbe:
    host = web_host(ctx)
    return ctx.memo.get("tls", lambda: _probe(ctx, host))


def _probe(ctx, host: str) -> TlsProbe:
    result = TlsProbe(host, reachable=True)
    try:
        version, der = _handshake(ctx, host, _STRICT)
        result.verified = True
    except ssl.SSLCertVerificationError as exc:
        result.verify_error = exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        result.verify_error = f"handshake failed: {exc.reason or exc}"
    except OSError as exc:
        return TlsProbe(host, reachable=False, error=_describe_os_error(exc))
    if not result.verified:
        try:
            version, der = _handshake(ctx, host, _PERMISSIVE)
        except OSError as exc:  # includes ssl.SSLError
            return TlsProbe(host, reachable=False, error=f"TLS handshake failed ({getattr(exc, 'reason', None) or exc})")
    result.version = version
    result.cert = x509.load_der_x509_certificate(der) if der else None
    return result


def require_tls(ctx) -> TlsProbe:
    result = probe(ctx)
    if not result.reachable:
        raise NotTested(f"Not tested: HTTPS on {result.host} is unavailable.")
    return result


def _describe_os_error(exc: OSError) -> str:
    if isinstance(exc, TimeoutError):
        return "connection timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    return exc.strerror or type(exc).__name__


def _name_attr(name: x509.Name, oid) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else ""


def cert_hostnames(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.DNSName)


def cert_issuer(cert: x509.Certificate) -> str:
    return _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or _name_attr(cert.issuer, NameOID.COMMON_NAME)


def describe_cert(cert: x509.Certificate | None) -> str:
    if cert is None:
        return ""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_text = f"RSA {key.key_size}-bit"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_text = f"ECDSA {key.curve.name}"
    else:
        key_text = type(key).__name__
    names = cert_hostnames(cert)
    shown = ", ".join(names[:6]) + (f" (+{len(names) - 6} more)" if len(names) > 6 else "")
    return "\n".join([
        f"Subject: {_name_attr(cert.subject, NameOID.COMMON_NAME) or '(none)'}",
        f"Issuer: {cert_issuer(cert)}",
        f"Valid: {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}",
        f"Key: {key_text}",
        f"Covers: {shown or '(no subject alternative names)'}",
    ])


def _explain_verify_error(result: TlsProbe) -> tuple[str, str]:
    error = result.verify_error.lower()
    if "expired" in error:
        return ("The certificate has expired, so browsers show a full-page security warning.",
                "Renew the certificate now and make sure automatic renewal (e.g. certbot or acme.sh) is running.")
    if "hostname mismatch" in error or "not valid for" in error:
        covers = ", ".join(cert_hostnames(result.cert)[:5]) if result.cert else "other names"
        return (f"The certificate isn't valid for {result.host} (it covers {covers}), so browsers show a security warning.",
                f"Issue a certificate that includes {result.host}, plus www if you use it.")
    if "self-signed" in error or "self signed" in error:
        return ("The certificate is self-signed, so no browser or app trusts it.",
                "Replace it with a certificate from a public CA such as Let's Encrypt (free).")
    if "local issuer" in error:
        return ("The server doesn't send a complete certificate chain, or the CA isn't publicly trusted. Some browsers cope, "
                "but many phones, apps and API clients will refuse to connect.",
                "Install the full chain (your certificate plus intermediates), e.g. fullchain.pem instead of cert.pem.")
    if error.startswith("handshake failed"):
        return (f"A modern client can't complete a TLS handshake ({result.verify_error}). The server probably only offers "
                "obsolete protocols or ciphers.",
                "Enable TLS 1.2 and TLS 1.3 with modern cipher suites.")
    return (f"The certificate was rejected: {result.verify_error}.",
            "Install a valid certificate from a public CA that covers this hostname.")


@check("https_cert", TLS, "Trusted HTTPS certificate", 10)
def check_certificate(ctx) -> Outcome:
    result = probe(ctx)
    if not result.reachable:
        return Outcome.fail(
            CRITICAL,
            f"HTTPS isn't available on {result.host} ({result.error}). Visitors' data travels unencrypted and browsers mark the site 'Not secure'.",
            "Serve the site over HTTPS with a certificate from a trusted CA (Let's Encrypt is free) and redirect HTTP to HTTPS.",
        )
    evidence = describe_cert(result.cert)
    if result.verified:
        return Outcome.ok(f"The certificate for {result.host} is from a trusted CA and matches the hostname.", evidence)
    problem, fix = _explain_verify_error(result)
    return Outcome.fail(CRITICAL, problem, fix, evidence)


@check("cert_expiry", TLS, "Certificate renewal runway", 4)
def check_expiry(ctx) -> Outcome:
    result = require_tls(ctx)
    cert = result.cert
    if cert is None:
        raise NotTested("Not tested: the server sent no certificate.")
    now = datetime.now(timezone.utc)
    remaining = cert.not_valid_after_utc - now
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    days = remaining.days
    expires = f"{cert.not_valid_after_utc:%d %b %Y}"
    if remaining.total_seconds() < 0:
        return Outcome.fail(CRITICAL, f"The certificate expired on {expires}.",
                            "Renew it immediately and fix automatic renewal.")
    # Thresholds scale with lifetime so short-lived certificates (e.g. 6-day ones) aren't flagged.
    if remaining < min(lifetime / 6, timedelta(days=7)):
        return Outcome.warn(0.25, HIGH, f"The certificate expires in {days} day(s), on {expires}.",
                            "Renew now and find out why automatic renewal hasn't run.")
    if remaining < min(lifetime / 3, timedelta(days=30)):
        return Outcome.warn(0.75, LOW,
                            f"The certificate expires in {days} days ({expires}); automated renewal normally happens before this point.",
                            "Confirm that automatic renewal is working.")
    return Outcome.ok(f"The certificate is valid for another {days} days (until {expires}).")


@check("tls_version", TLS, "Modern TLS version", 4)
def check_tls_version(ctx) -> Outcome:
    version = require_tls(ctx).version
    if version == "TLSv1.3":
        return Outcome.ok("Negotiates TLS 1.3, the current protocol version.")
    if version == "TLSv1.2":
        return Outcome.warn(0.75, LOW, "The server supports TLS 1.2 but not TLS 1.3.",
                            "Enable TLS 1.3 on the web server or CDN for faster, more secure connections.")
    return Outcome.fail(HIGH, f"The best protocol the server offers is {version or 'unknown'}, which is obsolete and blocked by modern browsers.",
                        "Enable TLS 1.2 and TLS 1.3.")


# Errors raised before anything is sent: this machine can't speak TLS 1.0/1.1 at all.
_CLIENT_CANNOT_OFFER = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"}
# Errors that can only happen after the server agreed to TLS 1.0/1.1 and carried on with the handshake,
# e.g. RHEL/AlmaLinux crypto policies reject the SHA-1 signatures those versions use. The server accepts them.
_SERVER_AGREED_TO_LEGACY = {"LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED", "DH_KEY_TOO_SMALL",
                            "UNSAFE_LEGACY_RENEGOTIATION_DISABLED"}


@check("legacy_tls", TLS, "Legacy TLS 1.0/1.1 disabled", 4)
def check_legacy_tls(ctx) -> Outcome:
    result = require_tls(ctx)
    if _LEGACY_ONLY is None:
        return Outcome.error("This machine's OpenSSL can't offer TLS 1.0/1.1, so legacy support wasn't tested.")
    try:
        version, _ = _handshake(ctx, result.host, _LEGACY_ONLY)
    except ssl.SSLError as exc:
        if exc.reason in _CLIENT_CANNOT_OFFER:
            return Outcome.error("This machine's OpenSSL can't offer TLS 1.0/1.1, so legacy support wasn't tested.")
        if exc.reason not in _SERVER_AGREED_TO_LEGACY:
            return Outcome.ok("TLS 1.0 and 1.1 are refused.")
        version = "TLS 1.0/1.1"
    except ConnectionResetError:
        return Outcome.ok("TLS 1.0 and 1.1 are refused.")
    except OSError as exc:
        return Outcome.error(f"Legacy TLS test failed: {_describe_os_error(exc)}.")
    pretty = version.replace("TLSv", "TLS ")
    return Outcome.fail(
        MEDIUM,
        f"The server still accepts {pretty}, which has been deprecated since 2021 (RFC 8996) and fails PCI DSS.",
        "Set the minimum TLS version to 1.2 on the web server, load balancer or CDN (on Cloudflare: SSL/TLS > Edge Certificates > Minimum TLS Version).",
    )


@check("http_redirect", TLS, "HTTP redirects to HTTPS", 3)
def check_http_redirect(ctx) -> Outcome:
    host = web_host(ctx)
    url = f"http://{host}/"
    hops: list[str] = []
    for _ in range(6):
        try:
            response = fetch(ctx, url, follow=False)
        except (requests.ConnectionError, requests.Timeout) as exc:
            if not hops:
                return Outcome.ok(f"Port 80 on {host} doesn't serve plain HTTP at all.")
            raise NotTested(f"Not tested: the redirect chain broke at {url} ({describe_error(exc)}).") from exc
        except requests.RequestException as exc:
            raise NotTested(f"Not tested: {describe_error(exc)}.") from exc
        location = response.header("location")
        if response.status in (301, 302, 303, 307, 308) and location:
            target = urljoin(url, location)
            hops.append(f"{response.status} {url} -> {target}")
            if target.startswith("https://"):
                break
            url = target
            continue
        return Outcome.fail(
            MEDIUM,
            f"{url} serves the page over plain HTTP (status {response.status}) instead of redirecting to HTTPS.",
            "Add a permanent (301) redirect from HTTP to HTTPS for every URL.",
            "\n".join(hops + [f"{response.status} {url}"]),
        )
    else:
        return Outcome.fail(MEDIUM, "HTTP redirects loop without ever reaching HTTPS.",
                            "Redirect HTTP straight to the HTTPS version of the same URL.", "\n".join(hops))
    evidence = "\n".join(hops)
    if len(hops) > 1:
        return Outcome.warn(
            0.7, LOW,
            "Plain HTTP passes through another unencrypted redirect before reaching HTTPS.",
            f"Redirect http://{host}/ straight to https://{host}/ first (this is also required for HSTS preloading).",
            evidence,
        )
    final_host = urlsplit(target).hostname
    where = "" if final_host == host else f" (on {final_host})"
    return Outcome.ok(f"Plain HTTP redirects straight to HTTPS{where}.", evidence)
