"""Command-line interface: python -m cybergrader example.com [--json] [--html report.html]"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ._version import __version__
from .context import DEFAULT_USER_AGENT
from .dnsutil import Inconclusive
from .grader import GRADES, grade_domain
from .models import Report
from .report import render_html, render_text
from .settings import Settings, SettingsError, load_settings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybergrader",
        description="Passive cyber-hygiene grader: email spoofing protection, HTTPS/TLS, web security headers and DNS.",
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN", help="domain or URL to grade")
    parser.add_argument("-f", "--file", help="read domains from a file, one per line ('#' starts a comment)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    parser.add_argument("--html", metavar="PATH", help="write an HTML report (a directory when grading several domains)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the evidence behind each result")
    parser.add_argument("--timeout", type=float, help="network timeout in seconds (default: admin settings, else 6)")
    parser.add_argument("--nameserver", action="append", metavar="IP",
                        help="DNS resolver to use, repeatable (default: admin settings, else this computer's DNS)")
    parser.add_argument("--brand", help="business name on HTML reports (default: the one in the admin portal)")
    parser.add_argument("--brand-url", help="link for the business name on HTML reports")
    parser.add_argument("--fail-under", metavar="GRADE", choices=GRADES,
                        help="exit with status 2 if any domain grades below this (for monitoring/CI)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _read_domains(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    domains = list(args.domains)
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                domains.append(entry)
    if not domains:
        parser.error("give at least one domain (or --file)")
    return domains


def _supports_unicode(stream) -> bool:
    try:
        "█░✓·".encode(stream.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _below(grade: str, threshold: str) -> bool:
    return grade not in GRADES or GRADES.index(grade) > GRADES.index(threshold)


def _html_path(target: str, report: Report, multiple: bool) -> Path:
    path = Path(target)
    if multiple or path.is_dir() or not path.suffix:
        path.mkdir(parents=True, exist_ok=True)
        return path / f"{report.domain}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    domains = _read_domains(args, parser)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # never crash on characters the console code page lacks
            stream.reconfigure(errors="replace")
    color = not args.no_color and not args.json and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        os.system("")  # switches the Windows console into ANSI escape-code mode
    unicode = _supports_unicode(sys.stdout)
    try:
        settings = load_settings()  # details entered in the admin portal
    except SettingsError as exc:
        print(f"Warning: {exc}; using default settings.", file=sys.stderr)
        settings = Settings()
    branding = settings.branding()
    if args.brand is not None:
        branding.name = args.brand
    if args.brand_url is not None:
        branding.url = args.brand_url

    reports: list[Report] = []
    exit_code = 0
    for domain in domains:
        if sys.stderr.isatty():
            print(f"Grading {domain}…" if unicode else f"Grading {domain}...", file=sys.stderr, flush=True)
        try:
            report = grade_domain(domain, timeout=args.timeout or settings.timeout,
                                  nameservers=args.nameserver or settings.nameservers or None,
                                  user_agent=settings.user_agent or DEFAULT_USER_AGENT,
                                  dnsbl_nameservers=settings.dnsbl_nameservers or None,
                                  spamhaus_key=settings.spamhaus_dqs_key)
        except (ValueError, Inconclusive) as exc:
            print(f"{domain}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        reports.append(report)
        if not args.json:
            print(render_text(report, color=color, unicode=unicode, verbose=args.verbose))
            print()
        if args.html:
            path = _html_path(args.html, report, multiple=len(domains) > 1)
            path.write_text(render_html(report, branding=branding), encoding="utf-8")
            print(f"HTML report written to {path}", file=sys.stderr)

    if args.json:
        payload = [r.to_dict() for r in reports] if len(domains) > 1 else (reports[0].to_dict() if reports else None)
        print(json.dumps(payload, indent=2))
    if args.fail_under and any(_below(r.grade, args.fail_under) for r in reports):
        exit_code = exit_code or 2
    return exit_code
