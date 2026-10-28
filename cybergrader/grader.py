"""Runs every registered check against a domain and turns the results into a graded Report."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ._version import __version__
from .checks import CATEGORIES, CheckSpec, all_checks
from .context import DEFAULT_USER_AGENT, ScanContext
from .dnsbl import DnsblClient
from .dnsutil import DNSClient, Inconclusive
from .models import CategoryScore, CheckResult, NotApplicable, NotTested, Outcome, Report, Severity, Status
from .target import BlockedTarget, display_name, is_public_ip, normalize_domain

log = logging.getLogger(__name__)

GRADE_BANDS = ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F"))
GRADES = ("A+", "A", "B", "C", "D", "F")
# The best grade a domain can get while it has an unresolved issue of this severity.
GRADE_CAPS = ((Severity.CRITICAL, "C"), (Severity.HIGH, "B"))
A_PLUS_SCORE = 97
MIN_COVERAGE = 0.8


def grade_domain(domain: str, *, timeout: float = 6.0, nameservers: list[str] | None = None,
                 allow_private: bool = True, user_agent: str = DEFAULT_USER_AGENT, workers: int = 12,
                 dnsbl_nameservers: list[str] | None = None, spamhaus_key: str = "") -> Report:
    """Grade a domain. Raises ValueError for bad/non-existent domains, BlockedTarget, or Inconclusive.
    Blacklists are queried through dnsbl_nameservers (default: the same as nameservers)."""
    name = normalize_domain(domain)
    dnsbl = DnsblClient(dnsbl_nameservers or nameservers, timeout=min(timeout, 4.0), spamhaus_key=spamhaus_key)
    ctx = ScanContext(name, DNSClient(nameservers, timeout=min(timeout, 5.0)), timeout=timeout,
                      allow_private=allow_private, user_agent=user_agent, dnsbl=dnsbl)
    started_at = datetime.now(timezone.utc)
    clock = time.monotonic()
    _preflight(ctx)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda spec: run_check(ctx, spec), all_checks()))
    return build_report(ctx, results, started_at, time.monotonic() - clock)


def _preflight(ctx: ScanContext) -> None:
    if not ctx.dns.exists(ctx.domain):
        raise ValueError(f"{ctx.domain} doesn't exist in DNS. Check the spelling.")
    if not ctx.allow_private:
        for ip in ctx.dns.addresses(ctx.domain):
            if not is_public_ip(ip):
                raise BlockedTarget(f"{ctx.domain} resolves to a private or reserved address ({ip}); only public domains can be graded.")


def run_check(ctx: ScanContext, spec: CheckSpec) -> CheckResult:
    try:
        outcome = spec.func(ctx)
    except NotApplicable as exc:
        outcome = Outcome.info(str(exc))
    except NotTested as exc:
        outcome = Outcome.skip(str(exc))
    except (Inconclusive, BlockedTarget) as exc:
        outcome = Outcome.error(str(exc))
    except Exception as exc:  # one broken check must not sink the whole report
        log.exception("Check %s crashed", spec.id)
        outcome = Outcome.error(f"The check failed unexpectedly ({type(exc).__name__}: {exc}).")
    if outcome.score is not None:
        fraction = outcome.score
    else:
        fraction = 1.0 if outcome.status is Status.PASS else 0.0
    return CheckResult(
        id=spec.id, category=spec.category, title=spec.title, status=outcome.status, severity=outcome.severity,
        points=round(spec.max_points * fraction, 2), max_points=spec.max_points,
        summary=outcome.summary, fix=outcome.fix, evidence=outcome.evidence,
    )


def letter_grade(score: int, results: list[CheckResult]) -> tuple[str, str]:
    """Grade from the score, then capped by the worst open finding. Returns (grade, explanation)."""
    grade = next(letter for floor, letter in GRADE_BANDS if score >= floor)
    findings = [r for r in results if r.is_finding]
    if grade == "A" and score >= A_PLUS_SCORE and all(r.severity.rank < Severity.MEDIUM.rank for r in findings):
        grade = "A+"
    for severity, cap in GRADE_CAPS:
        culprits = [r.title for r in findings if r.severity is severity]
        if culprits and GRADES.index(grade) < GRADES.index(cap):
            return cap, f"Capped at {cap} because of {severity.value}-severity issues: {', '.join(culprits)}."
    return grade, ""


def build_report(ctx: ScanContext, results: list[CheckResult], started_at: datetime, duration: float) -> Report:
    scored = [r for r in results if r.scored]
    possible = sum(r.max_points for r in scored)
    earned = sum(r.points for r in scored)
    undetermined = sum(r.max_points for r in results if r.status is Status.ERROR)
    coverage = possible / (possible + undetermined) if possible + undetermined else 0.0
    score = round(100 * earned / possible) if possible else 0
    if possible:
        grade, note = letter_grade(score, results)
        if coverage < MIN_COVERAGE:
            note = f"{note} Only {coverage:.0%} of the checks could be completed, so treat this grade as provisional.".strip()
    else:
        grade, note = "N/A", "No checks could be completed."
    categories = []
    for name in CATEGORIES:
        in_category = [r for r in scored if r.category == name]
        categories.append(CategoryScore(name, round(sum(r.points for r in in_category), 2),
                                        sum(r.max_points for r in in_category)))
    page = ctx.memo.peek("homepage")
    return Report(
        domain=ctx.domain, display_domain=display_name(ctx.domain), scanned_at=started_at, duration=duration,
        score=score, grade=grade, grade_note=note, coverage=coverage, web_host=ctx.memo.peek("web_host"),
        homepage_url=page.url if page else None, categories=categories, results=results, version=__version__,
    )
