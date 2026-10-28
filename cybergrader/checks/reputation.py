"""Blacklists and sender reputation (what MXToolbox's blacklist check covers): are the domain's own mail servers or
the domain itself on the spam, phishing and malware blocklists that mail filters consult, and do its mail servers
have the reverse DNS that big receivers insist on?"""
from __future__ import annotations

import re

from ..dnsbl import DOMAIN_LISTS, IP_LISTS, DnsblClient, Sweep, valid_ipv4
from ..dnsutil import Inconclusive
from ..models import Deductions, NotApplicable, Outcome, Severity
from ..target import is_public_ip
from . import REPUTATION, check
from .mail import mail_setup, spf_records

HIGH, MEDIUM, LOW = Severity.HIGH, Severity.MEDIUM, Severity.LOW
MAX_MAIL_IPS = 8


def dnsbl_client(ctx) -> DnsblClient:
    return ctx.dnsbl or ctx.memo.get("dnsbl", lambda: DnsblClient(timeout=min(ctx.timeout, 4.0)))


def own_mail_ips(ctx) -> tuple[list[str], list[str]]:
    return ctx.memo.get("mail_ips", lambda: _own_mail_ips(ctx))


def _own_mail_ips(ctx) -> tuple[list[str], list[str]]:
    """IPv4 addresses of the domain's own mail servers, and notes on what was left out. Its MX hosts count unless
    a big provider runs them (their reputation is the provider's job), plus the servers its SPF record names
    directly: single ip4 addresses and the 'a' and 'mx' mechanisms. Includes (Google, Mailchimp, ...) and
    address ranges are left out."""
    notes: list[str] = []
    hosts: list[str] = []
    setup = mail_setup(ctx)
    if setup.receives_mail:
        if setup.provider:
            notes.append(f"Mail servers run by {setup.provider} aren't checked: their reputation is managed by {setup.provider}.")
        else:
            hosts += setup.hosts[:3]
    ips: list[str] = []
    records = spf_records(ctx.dns, ctx.domain)
    if len(records) == 1:
        for term in records[0].split()[1:]:
            if term[:1] in "-~?":
                continue  # not (or only doubtfully) allowed to send
            mechanism, _, argument = term.lstrip("+").partition(":")
            mechanism, _, length = mechanism.partition("/")
            argument, _, arg_length = argument.partition("/")
            mechanism, length = mechanism.lower(), length or arg_length
            if length and length != "32":
                if mechanism in ("ip4", "a", "mx"):
                    notes.append(f"The SPF range '{term}' isn't checked (only single addresses are).")
            elif mechanism == "ip4" and valid_ipv4(argument):
                ips.append(argument)
            elif mechanism == "a":
                hosts.append(argument or ctx.domain)
            elif mechanism == "mx" and argument and argument.lower() != ctx.domain:
                hosts += [host for _, host in sorted(ctx.dns.mx(argument)) if host][:3]
    for host in dict.fromkeys(hosts):
        ips += ctx.dns.ipv4(host)
    public = [ip for ip in dict.fromkeys(ips) if is_public_ip(ip)]
    if len(public) > MAX_MAIL_IPS:
        notes.append(f"Only the first {MAX_MAIL_IPS} of {len(public)} mail server addresses were checked.")
    return public[:MAX_MAIL_IPS], notes


def _sweep_evidence(sweep: Sweep, targets: list[str], notes: list[str]) -> str:
    lines = [f"Checked: {', '.join(targets)}", f"Blacklists that answered: {', '.join(sweep.checked) or 'none'}"]
    grouped: dict[tuple[str, str], list] = {}
    for item in sweep.listings:  # one line per address and list (Spamhaus ZEN can give several reasons at once)
        grouped.setdefault((item.target, item.blacklist.name), []).append(item)
    for (target, name), items in grouped.items():
        detail = items[0].detail
        lines.append(f"LISTED: {target} on {name} ({'; '.join(item.meaning for item in items)}). "
                     + (f"The list says: {detail}" if detail else f"Look up and request removal: {items[0].blacklist.url}"))
    for name, reason in sweep.unavailable.items():
        lines.append(f"Couldn't check {name}: {reason}.")
    return "\n".join(lines + notes)


def _not_checked_note(sweep: Sweep) -> str:
    missed = [name for name in sweep.unavailable if name.startswith("Spamhaus")]
    return f" ({', '.join(missed)} couldn't be checked from here)" if missed else ""


def _listing_score(severity: Severity) -> float:
    return 0.0 if severity.rank >= HIGH.rank else 0.5 if severity is MEDIUM else 0.8


@check("ip_blacklists", REPUTATION, "Mail servers on spam blacklists", 8)
def check_ip_blacklists(ctx) -> Outcome:
    ips, notes = own_mail_ips(ctx)
    if not ips:
        raise NotApplicable(" ".join(notes) or "No mail servers of your own were found (no self-hosted MX and no "
                                                "addresses in SPF), so there are no mail server addresses to check.")
    sweep = dnsbl_client(ctx).sweep(IP_LISTS, ips)
    if not sweep.checked:
        raise Inconclusive("None of the blacklists could be queried from the grader right now.")
    evidence = _sweep_evidence(sweep, ips, notes)
    if not sweep.listings:
        return Outcome.ok(f"None of your {len(ips)} mail server address{'es' if len(ips) != 1 else ''} is on the "
                          f"{len(sweep.checked)} spam blacklists checked{_not_checked_note(sweep)}.", evidence)
    listed = sorted({item.target for item in sweep.listings})
    lists = sorted({item.blacklist.name for item in sweep.listings})
    pbl_only = all("PBL" in item.meaning for item in sweep.listings)
    summary = (f"{', '.join(listed)} {'is' if len(listed) == 1 else 'are'} on {len(lists)} blacklist{'s' if len(lists) != 1 else ''} "
               f"({', '.join(lists)}), so email you send from {'it' if len(listed) == 1 else 'them'} may be rejected or land in spam.")
    if pbl_only:
        fix = ("The Spamhaus PBL lists home and office internet connections that shouldn't deliver email directly. If this server "
               "sends your email, send it through your email provider's or ISP's mail server instead, or ask your ISP for a "
               "business address and remove it from the PBL at check.spamhaus.org.")
    else:
        fix = ("First find and stop what sent the spam: usually a mailbox with a stolen password, a website contact form or "
               "plugin being abused, or an infected computer on the network. Then request removal from each list (links "
               "below); most lists also drop an address by themselves a few days after the spam stops. If a listing covers "
               "your hosting company's whole network (Spamhaus SBL listings often do), only the host can fix it: ask them, "
               "or move to a better host.")
    severity = sweep.worst
    score = _listing_score(severity)
    if score == 0:
        return Outcome.fail(severity, summary, fix, evidence)
    return Outcome.warn(score, severity, summary, fix, evidence)


@check("domain_blacklists", REPUTATION, "Domain on spam & phishing blocklists", 8)
def check_domain_blacklists(ctx) -> Outcome:
    try:
        apex = ctx.dns.zone_apex(ctx.domain)
    except Inconclusive:
        apex = ctx.domain
    targets = list(dict.fromkeys([apex, ctx.domain]))
    sweep = dnsbl_client(ctx).sweep(DOMAIN_LISTS, targets)
    if not sweep.checked:
        raise Inconclusive("None of the domain blocklists could be queried from the grader right now.")
    evidence = _sweep_evidence(sweep, targets, [])
    if not sweep.listings:
        return Outcome.ok(f"{apex} isn't on the {len(sweep.checked)} spam and phishing domain blocklists checked"
                          f"{_not_checked_note(sweep)}.", evidence)
    reasons = sorted({item.meaning for item in sweep.listings})
    severity = sweep.worst
    summary = (f"{' and '.join(sorted({item.target for item in sweep.listings}))} is listed: {'; '.join(reasons)}. Mail filters "
               "block emails that mention or link to listed domains, and browsers and security tools may warn people away.")
    fix = ("Check the website and mailboxes for compromise first: hacked pages, unknown files or redirects (an outdated "
           "WordPress site or plugin is the usual cause), and mailboxes sending spam. Clean them up, change passwords, "
           "then request delisting from each list (the links below explain why it's listed and how to request removal).")
    score = _listing_score(severity)
    if score == 0:
        return Outcome.fail(severity, summary, fix, evidence)
    return Outcome.warn(score, severity, summary, fix, evidence)


def _generic_name(ip: str, name: str) -> bool:
    """ISP-style names that embed the address, e.g. 41-0-0-9.dsl.example.net or host9.0.0.41.example.net."""
    octets = ip.split(".")
    digits = re.findall(r"\d+", name)
    return all(octet in digits for octet in octets)


@check("mail_ptr", REPUTATION, "Mail server reverse DNS (PTR)", 4)
def check_mail_ptr(ctx) -> Outcome:
    ips, notes = own_mail_ips(ctx)
    if not ips:
        raise NotApplicable(" ".join(notes) or "No mail servers of your own were found, so there's no reverse DNS to check.")
    deductions = Deductions()
    share = 1.0 / len(ips)
    lines = []
    fix = (f"Reverse DNS is set by whoever provides the server's IP address (your hosting company or ISP), not in your own "
           f"DNS. Ask them to set it to your mail server's name, e.g. mail.{ctx.domain}, and make sure that name has an A "
           "record pointing back to the same address.")
    for ip in ips:
        names = ctx.dns.ptr(ip)
        if not names:
            lines.append(f"{ip}: no PTR record")
            deductions.add(share, MEDIUM, f"{ip} has no reverse DNS (PTR) record, so Gmail, Microsoft and many other "
                                          "receivers may reject or junk email sent from it.", fix)
            continue
        confirmed = next((name for name in names if ip in ctx.dns.ipv4(name)), None)
        lines.append(f"{ip}: PTR {', '.join(names)}{'' if confirmed else ' (does not point back to ' + ip + ')'}")
        if not confirmed:
            deductions.add(share * 0.5, LOW, f"{ip}'s reverse DNS name ({names[0]}) doesn't point back to {ip}, which some "
                                             "receivers treat as a sign of a spam source.", fix)
        elif _generic_name(ip, confirmed):
            deductions.add(share * 0.25, LOW, f"{ip}'s reverse DNS name ({confirmed}) looks like a generic ISP name, which "
                                              "spam filters score as a home connection.", fix)
    return deductions.outcome(f"Every mail server address ({len(ips)}) has matching reverse DNS.", "\n".join(lines + notes))
