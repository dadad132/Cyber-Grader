"""Email anti-spoofing and transport-security checks: SPF, DMARC, DKIM, MTA-STS and TLS-RPT."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from ..dnsutil import Inconclusive
from ..models import Deductions, NotApplicable, Outcome, Severity
from ..net import describe_error, fetch
from . import EMAIL, check

CRITICAL, HIGH, MEDIUM, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

# (MX host suffix, provider, SPF include that authorises the provider's outbound servers)
MAIL_PROVIDERS = (
    ("google.com", "Google Workspace", "include:_spf.google.com"),
    ("googlemail.com", "Google Workspace", "include:_spf.google.com"),
    ("protection.outlook.com", "Microsoft 365", "include:spf.protection.outlook.com"),
    ("zoho.com", "Zoho Mail", "include:zoho.com"),
    ("zoho.eu", "Zoho Mail", "include:zoho.eu"),
    ("messagingengine.com", "Fastmail", "include:spf.messagingengine.com"),
    ("protonmail.ch", "Proton Mail", "include:_spf.protonmail.ch"),
    ("icloud.com", "iCloud Mail", "include:icloud.com"),
    ("secureserver.net", "GoDaddy", "include:secureserver.net"),
    ("mimecast.com", "Mimecast", None),
    ("pphosted.com", "Proofpoint", None),
)

DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "dkim", "mail",
    "smtp", "mx", "email", "key1", "key2", "sig1", "fm1", "fm2", "fm3", "protonmail", "protonmail2",
    "protonmail3", "zoho", "zmail", "mandrill", "mxvault", "everlytickey1", "everlytickey2",
    "hs1", "hs2", "cm", "pm", "mailjet", "brevo",
)

NO_MAIL = "The domain has no mail servers (MX), so inbound-mail checks don't apply."


@dataclass
class MailSetup:
    kind: str  # "mail", "null" (RFC 7505 null MX) or "none"
    hosts: list[str] = field(default_factory=list)
    provider: str | None = None
    spf_include: str | None = None

    @property
    def receives_mail(self) -> bool:
        return self.kind == "mail"


def mail_setup(ctx) -> MailSetup:
    return ctx.memo.get("mx", lambda: _detect_mail_setup(ctx))


def _detect_mail_setup(ctx) -> MailSetup:
    hosts = [host for _, host in sorted(ctx.dns.mx(ctx.domain))]
    if not hosts:
        return MailSetup("none")
    if hosts == [""]:
        return MailSetup("null")
    hosts = [h for h in hosts if h]
    for suffix, provider, include in MAIL_PROVIDERS:
        if any(h == suffix or h.endswith("." + suffix) for h in hosts):
            return MailSetup("mail", hosts, provider, include)
    return MailSetup("mail", hosts)


def _require_mail(ctx) -> MailSetup:
    setup = mail_setup(ctx)
    if not setup.receives_mail:
        raise NotApplicable(NO_MAIL)
    return setup


# --- SPF ---------------------------------------------------------------------------------------

SPF_LOOKUP_LIMIT = 10
_SPF_START = re.compile(r"^v=spf1(\s|$)", re.I)
_MODIFIER = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.I)
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}


def spf_records(dns, name: str) -> list[str]:
    return [t.strip() for t in dns.txt(name) if _SPF_START.match(t.strip())]


@dataclass
class SpfAnalysis:
    all_qualifier: str | None = None  # '+', '-', '~' or '?' of the effective 'all'; None if absent
    lookups: int = 0
    problems: list[tuple[Severity, str]] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


def analyze_spf(dns, domain: str, record: str) -> SpfAnalysis:
    """Walks includes and redirects the way a receiver would, counting DNS lookups (RFC 7208 §4.6.4)."""
    analysis = SpfAnalysis()
    analysis.all_qualifier = _SpfWalker(dns, analysis).walk(record, frozenset({domain.lower()}), 0)
    return analysis


class _SpfWalker:
    MAX_DEPTH = 10

    def __init__(self, dns, analysis: SpfAnalysis) -> None:
        self.dns = dns
        self.analysis = analysis

    def walk(self, record: str, seen: frozenset[str], depth: int) -> str | None:
        all_qualifier = None
        redirect = None
        for term in record.split()[1:]:
            modifier = _MODIFIER.match(term)
            if modifier:
                if modifier.group(1).lower() == "redirect":
                    redirect = modifier.group(2)
                continue
            qualifier = term[0] if term[0] in "+-~?" else "+"
            mechanism, _, argument = term.lstrip("+-~?").partition(":")
            mechanism = mechanism.split("/")[0].lower()
            if mechanism in _LOOKUP_MECHANISMS:
                self.analysis.lookups += 1
            if mechanism == "ptr":
                self.analysis.problems.append((LOW, "SPF uses the deprecated 'ptr' mechanism, which is slow and unreliable."))
            elif mechanism == "include":
                self._follow(argument, seen, depth, "include")
            elif mechanism == "all":
                all_qualifier = qualifier
                break  # receivers stop evaluating at 'all'
        if redirect and all_qualifier is None:
            self.analysis.lookups += 1
            all_qualifier = self._follow(redirect, seen, depth, "redirect")
        return all_qualifier

    def _follow(self, target: str, seen: frozenset[str], depth: int, how: str) -> str | None:
        target = target.strip().lower().rstrip(".")
        if not target or "%" in target:
            return None  # macros can only be expanded per message
        if target in seen or depth >= self.MAX_DEPTH:
            self.analysis.problems.append((MEDIUM, f"SPF {how} of '{target}' loops back on itself."))
            return None
        try:
            records = spf_records(self.dns, target)
        except Inconclusive:
            self.analysis.unresolved.append(target)
            return None
        if len(records) != 1:
            count = "no" if not records else "more than one"
            self.analysis.problems.append(
                (MEDIUM, f"'{how}:{target}' points to a domain with {count} SPF record, which makes receivers return a permanent error.")
            )
            return None
        return self.walk(records[0], seen | {target}, depth + 1)


def _suggested_spf(setup: MailSetup) -> str:
    if not setup.receives_mail:
        return "v=spf1 -all"
    return f"v=spf1 {setup.spf_include or 'mx'} ~all"


@check("spf", EMAIL, "SPF sender policy", 10)
def check_spf(ctx) -> Outcome:
    records = spf_records(ctx.dns, ctx.domain)
    if not records:
        suggested = _suggested_spf(mail_setup(ctx))
        return Outcome.fail(
            CRITICAL,
            "No SPF record, so receiving mail servers can't tell which servers may send email as this domain. That makes it easy to spoof.",
            f"Publish one TXT record on {ctx.domain}: \"{suggested}\" (list every service that sends mail for you).",
        )
    if len(records) > 1:
        return Outcome.fail(
            HIGH,
            f"{len(records)} separate SPF records are published. Receivers treat that as a permanent error, so SPF fails for all mail.",
            "Merge them into a single TXT record starting with 'v=spf1'.",
            "\n".join(records),
        )
    record = records[0]
    spf = analyze_spf(ctx.dns, ctx.domain, record)
    evidence = record + (f"\nCouldn't resolve: {', '.join(spf.unresolved)}" if spf.unresolved else "")
    if spf.all_qualifier == "+":
        return Outcome.fail(
            CRITICAL,
            "SPF ends in '+all', which authorises every server on the internet to send as this domain.",
            "Replace '+all' with '-all' (or '~all').",
            evidence,
        )
    if spf.lookups > SPF_LOOKUP_LIMIT:
        return Outcome.warn(
            0.2, HIGH,
            f"SPF needs {spf.lookups} DNS lookups but the limit is {SPF_LOOKUP_LIMIT}. Receivers return a permanent error, so SPF fails even for your legitimate mail.",
            "Remove unused include: entries, or replace some with the ip4:/ip6: ranges they cover (SPF flattening).",
            evidence,
        )
    d = Deductions()
    if spf.all_qualifier in (None, "?"):
        d.add(0.6, HIGH,
              "SPF doesn't end in '-all' or '~all', so mail from unlisted servers is treated as neutral instead of failing.",
              "End the record with '-all' (or '~all').")
    for severity, problem in dict.fromkeys(spf.problems):
        d.add(0.3 if severity is MEDIUM else 0.1, severity, problem, "Correct or remove that SPF entry.")
    action = {"-": "rejects ('-all')", "~": "soft-fails ('~all')"}.get(spf.all_qualifier or "", "covers")
    return d.outcome(
        f"One valid SPF record that {action} unlisted senders, using {spf.lookups} of {SPF_LOOKUP_LIMIT} allowed DNS lookups.",
        evidence,
    )


# --- DMARC -------------------------------------------------------------------------------------

_DMARC_START = re.compile(r"^v\s*=\s*DMARC1\s*(;|$)", re.I)
_POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}


def find_dmarc(dns, domain: str) -> tuple[list[str], str | None]:
    """DMARC records for domain, falling back up the DNS tree (DMARCbis tree walk, max 8 labels)."""
    labels = domain.split(".")
    for i in range(min(len(labels) - 1, 8)):
        name = ".".join(labels[i:])
        records = [t.strip() for t in dns.txt(f"_dmarc.{name}") if _DMARC_START.match(t.strip())]
        if records:
            return records, name
    return [], None


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags.setdefault(key.strip().lower(), value.strip())
    return tags


@check("dmarc", EMAIL, "DMARC enforcement", 15)
def check_dmarc(ctx) -> Outcome:
    domain = ctx.domain
    records, found_at = find_dmarc(ctx.dns, domain)
    if not records:
        if mail_setup(ctx).receives_mail:
            fix = (f"Publish a TXT record at _dmarc.{domain}: \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}\". "
                   "Check the reports for a few weeks to confirm your real senders pass SPF or DKIM, then change p=none "
                   "to p=quarantine and finally to p=reject.")
        else:
            fix = (f"Publish a TXT record at _dmarc.{domain}: \"v=DMARC1; p=reject\". This domain receives no email, so it "
                   "most likely sends none either and can reject spoofed mail straight away. If something does send email "
                   "as this domain (a website form or newsletter service), start with \"v=DMARC1; p=none; "
                   "rua=mailto:an-address-you-read\" instead, then move to p=reject once the reports show those senders pass.")
        return Outcome.fail(
            HIGH,
            "No DMARC record, so nothing tells receiving servers to reject email that fails SPF/DKIM. Spoofed mail from this domain gets delivered.",
            fix,
        )
    if len(records) > 1:
        return Outcome.fail(
            HIGH,
            f"{len(records)} DMARC records are published at _dmarc.{found_at}. Receivers ignore DMARC entirely when there is more than one.",
            "Delete all but one DMARC record.",
            "\n".join(records),
        )
    record = records[0]
    tags = parse_tags(record)
    inherited = found_at != domain
    raw_policy = (tags.get("sp") or tags.get("p")) if inherited else tags.get("p")
    policy = (raw_policy or "none").lower()
    evidence = f"_dmarc.{found_at}: {record}"

    d = Deductions()
    if policy not in _POLICY_RANK:
        d.add(0.75, HIGH, f"DMARC policy '{raw_policy}' is invalid, so receivers apply no enforcement.",
              "Set p=quarantine or p=reject.")
    elif policy == "none":
        d.add(0.75, HIGH, "DMARC is in monitoring-only mode (p=none): spoofed email is still delivered.",
              "Once the reports show your legitimate senders pass, change to p=quarantine and then p=reject.")
    elif policy == "quarantine":
        d.add(0.1, LOW, "DMARC sends spoofed mail to spam (p=quarantine) rather than rejecting it outright.",
              "Move to p=reject when you're confident all legitimate senders pass.")
    pct = tags.get("pct", "100")
    if policy in ("quarantine", "reject") and pct.isdigit() and int(pct) < 100:
        d.add(0.2, MEDIUM, f"pct={pct} applies the policy to only {pct}% of failing mail; the rest is delivered.",
              "Remove pct= (or set pct=100).")
    if not inherited:
        sp = tags.get("sp", "").lower()
        if sp in _POLICY_RANK and policy in _POLICY_RANK and _POLICY_RANK[sp] < _POLICY_RANK[policy]:
            d.add(0.15, MEDIUM, f"Subdomain policy sp={sp} is weaker than p={policy}, so attackers can spoof made-up subdomains.",
                  f"Set sp={policy} or remove sp=.")
    if "rua" not in tags:
        d.add(0.05, LOW, "No rua= reporting address, so you get no visibility of who sends email as your domain.",
              f"Add rua=mailto:dmarc-reports@{found_at} (or use a DMARC reporting service).")
    where = f"inherited from {found_at}" if inherited else "published"
    effect = "rejected" if policy == "reject" else "quarantined"
    return d.outcome(f"DMARC {where} with p={policy}: email that fails authentication is {effect}.", evidence)


# --- DKIM, MTA-STS, TLS-RPT ----------------------------------------------------------------------

_DKIM_KEY = re.compile(r"(?:^|;)\s*p=([^;]*)", re.I)


@check("dkim", EMAIL, "DKIM signing key", 4)
def check_dkim(ctx) -> Outcome:
    _require_mail(ctx)

    def lookup(selector: str) -> tuple[str, list[str] | None]:
        try:
            return selector, ctx.dns.txt(f"{selector}._domainkey.{ctx.domain}")
        except Inconclusive:
            return selector, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(lookup, DKIM_SELECTORS))
    if all(records is None for _, records in answers):
        raise Inconclusive("Every DKIM lookup failed.")
    found, revoked, evidence = [], [], []
    for selector, records in answers:
        for txt in records or []:
            key = _DKIM_KEY.search(txt)
            if key:
                (found if key.group(1).strip() else revoked).append(selector)
                evidence.append(f"{selector}._domainkey.{ctx.domain}: {txt[:120]}{'…' if len(txt) > 120 else ''}")
                break
    if found:
        return Outcome.ok(f"DKIM public key published for selector(s): {', '.join(found)}.", "\n".join(evidence))
    note = f" Revoked keys found for: {', '.join(revoked)}." if revoked else ""
    return Outcome.info(
        f"No DKIM key at {len(DKIM_SELECTORS)} common selectors. DKIM may still be set up under a custom selector: "
        f"check the 's=' tag in the DKIM-Signature header of an email you sent.{note}"
    )


@check("mta_sts", EMAIL, "MTA-STS inbound TLS policy", 4)
def check_mta_sts(ctx) -> Outcome:
    _require_mail(ctx)
    domain = ctx.domain
    policy_id = datetime.now(timezone.utc).strftime("%Y%m%d")
    fix = (f"Publish a TXT record at _mta-sts.{domain} (\"v=STSv1; id={policy_id}\") and serve a policy file at "
           f"https://mta-sts.{domain}/.well-known/mta-sts.txt with 'mode: enforce' and your MX hosts.")
    records = [t for t in ctx.dns.txt(f"_mta-sts.{domain}") if t.strip().lower().startswith("v=stsv1")]
    if not records:
        return Outcome.fail(
            LOW,
            "No MTA-STS policy, so an attacker on the network path can silently downgrade email sent to you to unencrypted delivery.",
            fix,
        )
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        policy = fetch(ctx, url, follow=False, max_body=65536)  # RFC 8461: no redirects, valid certificate
    except requests.RequestException as exc:
        return Outcome.warn(
            0.25, LOW,
            f"An MTA-STS record exists but its policy file can't be fetched ({describe_error(exc)}), so sending servers ignore it.",
            fix, records[0],
        )
    match = re.search(r"^\s*mode\s*:\s*(\w+)", policy.body, re.I | re.M) if policy.status == 200 else None
    mode = match.group(1).lower() if match else None
    evidence = f"{records[0]}\n{url}:\n{policy.body.strip()[:500]}"
    if mode == "enforce":
        return Outcome.ok("MTA-STS is enforced: other servers must use verified TLS to deliver mail here.", evidence)
    if mode == "testing":
        return Outcome.warn(
            0.5, LOW,
            "MTA-STS is in testing mode: failures are reported but mail is still delivered without TLS.",
            "Switch the policy to 'mode: enforce' once TLS-RPT reports are clean.", evidence,
        )
    detail = f"mode: {mode}" if mode else f"HTTP {policy.status}"
    return Outcome.warn(0.25, LOW, f"The MTA-STS policy file is missing or not enforcing ({detail}).", fix, evidence)


@check("tls_rpt", EMAIL, "SMTP TLS reporting (TLS-RPT)", 2)
def check_tls_rpt(ctx) -> Outcome:
    _require_mail(ctx)
    records = [t for t in ctx.dns.txt(f"_smtp._tls.{ctx.domain}") if t.strip().lower().startswith("v=tlsrptv1")]
    if records:
        return Outcome.ok("TLS-RPT is set up, so you'll hear when other servers can't deliver mail to you securely.", records[0])
    return Outcome.fail(
        LOW,
        "No TLS-RPT record, so you won't be told when other servers fail to deliver mail to you securely.",
        f"Publish a TXT record at _smtp._tls.{ctx.domain}: \"v=TLSRPTv1; rua=mailto:tls-reports@{ctx.domain}\".",
    )


@check("mx", EMAIL, "Mail servers")
def check_mx(ctx) -> Outcome:
    setup = mail_setup(ctx)
    if setup.kind == "null":
        return Outcome.info("Null MX published (RFC 7505): this domain explicitly accepts no email.")
    if setup.kind == "none":
        return Outcome.info(
            "No MX records, so this domain doesn't receive email. It can still be spoofed, so SPF '-all' and DMARC 'p=reject' still matter."
        )
    provider = f", hosted by {setup.provider}" if setup.provider else ""
    return Outcome.info(f"{len(setup.hosts)} mail server(s){provider}.", "\n".join(setup.hosts))
