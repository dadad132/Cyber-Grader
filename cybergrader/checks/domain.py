"""Domain-level checks: CAA, DNSSEC and a security.txt vulnerability-disclosure contact."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

from ..models import NotTested, Outcome, Severity
from ..net import describe_error, fetch_lenient, web_host
from . import DOMAIN, check

LOW = Severity.LOW

# Certificate issuer organisation (lower-case fragment) -> CAA issuer domain
CAA_IDENTIFIERS = (
    ("let's encrypt", "letsencrypt.org"),
    ("google trust services", "pki.goog"),
    ("digicert", "digicert.com"),
    ("sectigo", "sectigo.com"),
    ("zerossl", "sectigo.com"),
    ("comodo", "sectigo.com"),
    ("globalsign", "globalsign.com"),
    ("amazon", "amazon.com"),
    ("godaddy", "godaddy.com"),
    ("starfield", "starfieldtech.com"),
    ("entrust", "entrust.net"),
    ("ssl corporation", "ssl.com"),
    ("buypass", "buypass.com"),
    ("certum", "certum.pl"),
    ("actalis", "actalis.it"),
)


def _caa_fix(ctx) -> str:
    example = "letsencrypt.org"
    hint = ""
    try:
        from .tls import cert_issuer, probe

        cert = probe(ctx).cert
        issuer = cert_issuer(cert) if cert else ""
        for fragment, identifier in CAA_IDENTIFIERS:
            if fragment in issuer.lower():
                example, hint = identifier, f" Your current certificate comes from {issuer}."
                break
    except Exception:
        pass  # the suggestion is a nicety; the certificate check reports TLS problems
    return (f"Add CAA records naming every CA you use, e.g. '{ctx.domain}. CAA 0 issue \"{example}\"' and "
            f"'{ctx.domain}. CAA 0 iodef \"mailto:security@{ctx.domain}\"'.{hint} Include your CDN's CAs if it issues certificates for you.")


@check("caa", DOMAIN, "CAA certificate-authority lock", 4)
def check_caa(ctx) -> Outcome:
    # RFC 8659: the relevant CAA set is the first one found climbing from the name towards the root.
    labels = ctx.domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        records = ctx.dns.caa(name)
        if not records:
            continue
        evidence = "\n".join(f'{name}. CAA {flags} {tag} "{value}"' for flags, tag, value in records)
        where = "" if name == ctx.domain else f" (inherited from {name})"
        issue_values = [value.split(";")[0].strip() for _, tag, value in records if tag.lower() in ("issue", "issuewild")]
        if not issue_values:
            return Outcome.warn(0.5, LOW, f"CAA records exist{where} but have no 'issue' tag, so they don't restrict which CAs can issue.",
                                _caa_fix(ctx), evidence)
        issuers = sorted({value for value in issue_values if value})
        if not issuers:
            return Outcome.ok(f"CAA forbids every CA from issuing certificates{where}.", evidence)
        return Outcome.ok(f"CAA limits certificate issuance to {', '.join(issuers)}{where}.", evidence)
    return Outcome.fail(LOW, "No CAA record, so any certificate authority in the world may issue HTTPS certificates for this domain.",
                        _caa_fix(ctx))


@check("dnssec", DOMAIN, "DNSSEC", 4)
def check_dnssec(ctx) -> Outcome:
    zone = ctx.dns.zone_apex(ctx.domain)
    if ctx.dns.has_ds(zone):
        return Outcome.ok(f"DNSSEC is enabled: {zone} has a DS record at its registry, so resolvers can detect forged answers.")
    return Outcome.fail(
        LOW, f"DNSSEC isn't enabled for {zone}, so resolvers can't detect forged DNS answers (cache poisoning).",
        "Turn on DNSSEC at your DNS host, then add the DS record it gives you at your domain registrar.",
    )


@check("security_txt", DOMAIN, "security.txt contact (RFC 9116)", 2)
def check_security_txt(ctx) -> Outcome:
    host = web_host(ctx)
    url = f"https://{host}/.well-known/security.txt"
    try:
        response = fetch_lenient(ctx, url, max_body=32768)
    except requests.RequestException as exc:
        raise NotTested(f"Not tested: couldn't fetch {url} ({describe_error(exc)}).") from exc
    body = response.body
    contact = re.search(r"^\s*contact\s*:\s*(\S+)", body, re.I | re.M)
    if response.status != 200 or not contact or body.lstrip().startswith("<"):
        return Outcome.fail(
            LOW, "No security.txt file, so someone who finds a vulnerability has no published way to report it to you.",
            f"Publish {url} with at least 'Contact: mailto:security@{ctx.domain}' and an 'Expires:' date (generator at securitytxt.org).",
        )
    evidence = f"{response.url}\nContact: {contact.group(1)}"
    expires = re.search(r"^\s*expires\s*:\s*(\S+)", body, re.I | re.M)
    if expires:
        try:
            when = datetime.fromisoformat(expires.group(1).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
        except ValueError:
            when = None
        if when and when < datetime.now(timezone.utc):
            return Outcome.warn(0.5, LOW, f"security.txt expired on {when:%d %b %Y}, so reporters may treat it as stale.",
                                "Update the 'Expires:' field (and review the contacts).", evidence)
    return Outcome.ok(f"security.txt publishes a vulnerability-report contact ({contact.group(1)}).", evidence)
