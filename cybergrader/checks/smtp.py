"""Inbound mail encryption: do the domain's mail servers offer STARTTLS on port 25 (MXToolbox's SMTP test)?

The grader connects, reads the greeting, says EHLO, starts TLS and says QUIT. It never sends mail. Many hosting
networks block outgoing port 25, so a reference mail server is tried too: if that can't be reached either, the
check reports that it couldn't test rather than blaming the domain.
"""
from __future__ import annotations

import smtplib
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from ..models import NotTested, Outcome, Severity
from ..target import BlockedTarget
from . import EMAIL, check
from .mail import _require_mail

HIGH, MEDIUM, LOW = Severity.HIGH, Severity.MEDIUM, Severity.LOW
SMTP_PORT = 25
MAX_HOSTS = 2
REFERENCE_MX = "gmail-smtp-in.l.google.com"  # always up; only used to tell "port 25 is blocked here" apart
_reference: dict[str, float | bool] = {"until": 0.0, "open": False}
_reference_lock = threading.Lock()


def port25_open(timeout: float = 5.0) -> bool:
    """Can the grader reach mail servers on port 25 at all? Cached for 10 minutes."""
    with _reference_lock:
        if _reference["until"] > time.monotonic():
            return bool(_reference["open"])
        try:
            with socket.create_connection((REFERENCE_MX, SMTP_PORT), timeout=timeout):
                is_open = True
        except OSError:
            is_open = False
        _reference.update(until=time.monotonic() + 600, open=is_open)
        return is_open


def probe(ctx, host: str) -> dict:
    """What one mail server offers. 'error' means the test didn't complete (refused, dropped, unreachable);
    'starttls' is True only when an encrypted session was actually set up."""
    result = {"host": host, "reached": False, "refused": False, "banner": "", "offered": False, "starttls": False,
              "trusted": False, "tls": "", "cert_error": "", "error": ""}
    timeout = max(ctx.timeout, 10.0)  # some servers wait a few seconds before greeting, to deter spammers
    try:
        ctx.guard(host, SMTP_PORT)
        smtp = smtplib.SMTP(timeout=timeout)
        smtp._host = host  # the name STARTTLS verifies the certificate against (only set when passed to SMTP())
        try:
            code, banner = smtp.connect(host, SMTP_PORT)
            result.update(reached=True, banner=banner.decode("utf-8", "replace")[:200])
            if code != 220:
                result.update(refused=True, error=f"refused the grader's connection ({code} {result['banner']})")
                return result
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                return result
            result["offered"] = True
            try:
                smtp.starttls(context=ssl.create_default_context())
                result.update(starttls=True, trusted=True, tls=smtp.sock.version() or "")
            except ssl.SSLCertVerificationError as exc:  # the handshake got as far as the certificate: TLS works
                result.update(starttls=True, cert_error=exc.verify_message or "certificate not trusted")
            except ssl.SSLError as exc:
                result["cert_error"] = f"the TLS handshake failed ({exc.reason or exc})"  # offered, but unusable
            else:
                try:
                    smtp.quit()
                except (smtplib.SMTPException, OSError):
                    pass
        finally:
            smtp.close()
    except BlockedTarget as exc:
        result["error"] = str(exc)
    except (OSError, smtplib.SMTPException) as exc:
        result["error"] = f"connection dropped ({exc})" if result["reached"] else f"couldn't connect ({type(exc).__name__})"
    return result


def _describe(r: dict) -> str:
    if r["error"]:
        line = r["error"]
    elif r["starttls"]:
        line = f"STARTTLS {r['tls'] or 'works'}" + (", certificate trusted" if r["trusted"] else f", {r['cert_error']}")
    elif r["offered"]:
        line = f"STARTTLS offered but {r['cert_error']}"
    else:
        line = "no STARTTLS offered"
    return f"{r['host']}: {line}" + (f"\n  {r['banner']}" if r["banner"] else "")


@check("smtp_starttls", EMAIL, "Mail server encryption (STARTTLS)", 4)
def check_smtp_starttls(ctx) -> Outcome:
    setup = _require_mail(ctx)
    if not port25_open():  # checked first (and cached) so a blocked network doesn't make every scan wait
        raise NotTested("Not tested: the grader's network blocks outgoing connections to mail servers (port 25).")
    hosts = setup.hosts[:MAX_HOSTS]
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        results = list(pool.map(lambda host: probe(ctx, host), hosts))
    evidence = "\n".join(_describe(r) for r in results)
    tested = [r for r in results if not r["error"]]
    if not tested:
        incomplete = [r for r in results if r["reached"]]
        if incomplete:
            raise NotTested(f"Not tested: {incomplete[0]['host']} {incomplete[0]['error']}.")
        return Outcome.fail(MEDIUM, f"Couldn't connect to your mail server{'s' if len(hosts) > 1 else ''} on port 25, so email "
                                    "sent to you may be delayed or bounce.",
                            "Check that the mail server is running and that its firewall accepts connections on port 25 "
                            "from the internet (or from your email filtering service, if you use one).", evidence)
    plain = [r for r in tested if not r["starttls"]]
    if plain:
        names = ", ".join(r["host"] for r in plain)
        broken = all(r["offered"] for r in plain)
        one = len(plain) == 1
        problem = (f"{'offers' if one else 'offer'} encryption (STARTTLS) that fails to start" if broken
                   else f"{'doesn' if one else 'don'}'t offer encryption (STARTTLS)")
        return Outcome.fail(HIGH, f"{names} {problem}, so email sent to you crosses the internet unencrypted, readable by "
                                  "anyone on the path.",
                            "Switch on STARTTLS on the mail server with a certificate for its name and TLS 1.2 or newer "
                            "(most mail servers and hosting control panels have a TLS/SSL setting for SMTP); a free "
                            "Let's Encrypt certificate works.", evidence)
    untrusted = [r for r in tested if not r["trusted"]]
    if untrusted:
        return Outcome.warn(0.75, LOW, f"{', '.join(r['host'] for r in untrusted)} encrypt{'s' if len(untrusted) == 1 else ''} "
                                       f"mail but the certificate isn't trusted ({untrusted[0]['cert_error']}), so senders "
                                       "can't be sure they're talking to your real server, and MTA-STS can't be enforced.",
                            "Install a certificate from a trusted authority whose name matches the MX host name "
                            "(e.g. a free Let's Encrypt certificate).", evidence)
    versions = sorted({r["tls"] for r in tested if r["tls"]})
    return Outcome.ok(f"Your mail server{'s' if len(tested) > 1 else ''} accept{'' if len(tested) > 1 else 's'} encrypted "
                      f"connections with a trusted certificate ({', '.join(versions) or 'TLS'}).", evidence)
