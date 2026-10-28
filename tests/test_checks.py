import pytest

from cybergrader.checks import domain, mail, web
from cybergrader.grader import letter_grade
from cybergrader.models import CheckResult, Severity, Status
from cybergrader.target import is_public_ip, normalize_domain

GOOGLE_MX = {"example.com": [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]}


# --- input handling -----------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("example.com", "example.com"),
    ("https://Example.COM/some/path?q=1", "example.com"),
    ("http://example.com:8443", "example.com"),
    ("  www.example.co.za. ", "www.example.co.za"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "192.168.1.1", "http://[::1]/", "exa mple.com", "-bad.com", "a..com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


@pytest.mark.parametrize("ip, public", [
    ("8.8.8.8", True), ("2606:4700:4700::1111", True), ("10.0.0.1", False), ("127.0.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("::ffff:127.0.0.1", False), ("fe80::1", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


# --- SPF ----------------------------------------------------------------------------------------

def test_spf_strict_record_passes(make_ctx):
    ctx = make_ctx(mx=GOOGLE_MX, txt={
        "example.com": ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
        "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
        "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
    })
    outcome = mail.check_spf(ctx)
    assert outcome.status is Status.PASS
    assert "2 of 10" in outcome.summary


def test_spf_missing_is_critical_and_suggests_provider(make_ctx):
    outcome = mail.check_spf(make_ctx(mx=GOOGLE_MX))
    assert outcome.status is Status.FAIL and outcome.severity is Severity.CRITICAL
    assert "include:_spf.google.com" in outcome.fix


def test_spf_plus_all_is_critical(make_ctx):
    outcome = mail.check_spf(make_ctx(txt={"example.com": ["v=spf1 +all"]}))
    assert outcome.severity is Severity.CRITICAL


def test_spf_multiple_records_is_permerror(make_ctx):
    outcome = mail.check_spf(make_ctx(txt={"example.com": ["v=spf1 -all", "v=spf1 mx -all"]}))
    assert outcome.status is Status.FAIL and outcome.severity is Severity.HIGH


def test_spf_lookup_limit(make_ctx):
    txt = {"example.com": ["v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"]}
    txt.update({f"s{i}.example.net": ["v=spf1 ip4:192.0.2.1 -all"] for i in range(11)})
    outcome = mail.check_spf(make_ctx(txt=txt))
    assert outcome.severity is Severity.HIGH and "11 DNS lookups" in outcome.summary


def test_spf_redirect_supplies_all(make_ctx):
    outcome = mail.check_spf(make_ctx(txt={
        "example.com": ["v=spf1 redirect=_spf.example.com"],
        "_spf.example.com": ["v=spf1 ip4:192.0.2.0/24 -all"],
    }))
    assert outcome.status is Status.PASS and "'-all'" in outcome.summary


def test_spf_include_without_record_is_flagged(make_ctx):
    outcome = mail.check_spf(make_ctx(txt={"example.com": ["v=spf1 include:gone.example.net -all"]}))
    assert outcome.status is Status.WARN and outcome.severity is Severity.MEDIUM


def test_spf_neutral_all_is_high(make_ctx):
    outcome = mail.check_spf(make_ctx(txt={"example.com": ["v=spf1 mx ?all"]}))
    assert outcome.status is Status.WARN and outcome.severity is Severity.HIGH


# --- DMARC --------------------------------------------------------------------------------------

def test_dmarc_reject_passes(make_ctx):
    outcome = mail.check_dmarc(make_ctx(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]}))
    assert outcome.status is Status.PASS


def test_dmarc_sp_reject_does_not_mask_p_none(make_ctx):
    # v1 used substring matching, so 'sp=reject' counted as 'p=reject'.
    outcome = mail.check_dmarc(make_ctx(txt={"_dmarc.example.com": ["v=DMARC1; p=none; sp=reject; rua=mailto:d@example.com"]}))
    assert outcome.status is Status.WARN and outcome.severity is Severity.HIGH
    assert "p=none" in outcome.summary


def test_dmarc_missing(make_ctx):
    outcome = mail.check_dmarc(make_ctx(mx=GOOGLE_MX))
    assert outcome.status is Status.FAIL and outcome.severity is Severity.HIGH
    # Mail domains start in monitoring mode with reports, then step up; never "start at reject, then move to reject".
    assert '"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"' in outcome.fix
    assert outcome.fix.index("p=quarantine") < outcome.fix.index("finally to p=reject")
    no_mail = mail.check_dmarc(make_ctx()).fix
    assert '"v=DMARC1; p=reject"' in no_mail and "then move to p=reject" in no_mail and "p=none" in no_mail


def test_dmarc_subdomain_inherits_sp(make_ctx):
    ctx = make_ctx("shop.example.com", txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"]})
    outcome = mail.check_dmarc(ctx)
    assert outcome.status is Status.WARN and outcome.severity is Severity.HIGH
    assert "p=none" in outcome.summary


def test_dmarc_partial_pct(make_ctx):
    outcome = mail.check_dmarc(make_ctx(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; pct=25; rua=mailto:d@example.com"]}))
    assert outcome.status is Status.WARN and outcome.severity is Severity.MEDIUM


def test_null_mx_makes_inbound_checks_not_applicable(make_ctx):
    from cybergrader.models import NotApplicable

    ctx = make_ctx(mx={"example.com": [(0, "")]})
    assert mail.mail_setup(ctx).kind == "null"
    with pytest.raises(NotApplicable):
        mail.check_mta_sts(ctx)


# --- headers ------------------------------------------------------------------------------------

def test_hsts_levels(make_ctx):
    assert web.check_hsts(make_ctx(headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})).status is Status.PASS
    assert web.check_hsts(make_ctx(headers={"Strict-Transport-Security": "max-age=300"})).status is Status.WARN
    assert web.check_hsts(make_ctx(headers={})).status is Status.FAIL


@pytest.mark.parametrize("policy, problems", [
    ("default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'", 0),
    ("script-src 'self' 'unsafe-inline'", 1),
    ("default-src *; script-src https: 'unsafe-inline' 'unsafe-eval'", 3),
    ("upgrade-insecure-requests; frame-ancestors 'self'", 1),
])
def test_csp_evaluation(policy, problems):
    assert len(web.evaluate_csp(policy)) == problems


def test_clickjacking_accepts_frame_ancestors(make_ctx):
    ctx = make_ctx(headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    assert web.check_clickjacking(ctx).status is Status.PASS


def test_banner_detects_versions(make_ctx):
    assert web.check_banner(make_ctx(headers={"Server": "nginx/1.18.0 (Ubuntu)"})).status is Status.FAIL
    assert web.check_banner(make_ctx(headers={"Server": "cloudflare"})).status is Status.PASS
    assert web.check_banner(make_ctx(headers={"X-Powered-By": "PHP/8.1"})).status is Status.FAIL


def test_cookie_flags(make_ctx):
    ctx = make_ctx(headers={}, cookies=["PHPSESSID=abc123; path=/; SameSite=Lax", "theme=dark; Secure; SameSite=Lax"])
    outcome = web.check_cookies(ctx)
    assert outcome.status is Status.WARN and outcome.severity is Severity.MEDIUM
    assert "abc123" not in outcome.evidence


# --- DNS ----------------------------------------------------------------------------------------

def test_caa_inherited_from_parent(make_ctx):
    ctx = make_ctx("shop.example.com", caa={"example.com": [(0, "issue", "letsencrypt.org")]})
    outcome = domain.check_caa(ctx)
    assert outcome.status is Status.PASS and "inherited from example.com" in outcome.summary


def test_dnssec(make_ctx):
    assert domain.check_dnssec(make_ctx(ds={"example.com"})).status is Status.PASS
    assert domain.check_dnssec(make_ctx()).status is Status.FAIL


# --- grading ------------------------------------------------------------------------------------

def _result(severity, status=Status.FAIL):
    return CheckResult("x", "Email Security", "X", status, severity, 0, 10, "summary")


def test_critical_finding_caps_grade():
    grade, note = letter_grade(95, [_result(Severity.CRITICAL)])
    assert grade == "C" and "Capped" in note


def test_high_finding_caps_grade():
    assert letter_grade(92, [_result(Severity.HIGH)])[0] == "B"


def test_a_plus_requires_no_medium_findings():
    assert letter_grade(98, [_result(Severity.LOW)])[0] == "A+"
    assert letter_grade(98, [_result(Severity.MEDIUM)])[0] == "A"


def test_low_score_not_raised_by_caps():
    assert letter_grade(40, [_result(Severity.CRITICAL)])[0] == "F"


# --- grader plumbing ----------------------------------------------------------------------------

def _spec(check_id):
    from cybergrader.checks import all_checks

    return next(spec for spec in all_checks() if spec.id == check_id)


def test_domain_without_website_skips_web_checks(make_ctx):
    from cybergrader.grader import run_check

    ctx = make_ctx(addresses={"example.com": [], "www.example.com": []})
    for check_id in ("https_cert", "hsts", "security_txt"):
        result = run_check(ctx, _spec(check_id))
        assert result.status is Status.INFO and not result.scored


def test_unexpected_crash_becomes_error_not_failure(make_ctx):
    from cybergrader.checks import CheckSpec
    from cybergrader.grader import run_check

    def broken(ctx):
        raise RuntimeError("boom")

    result = run_check(make_ctx(), CheckSpec("broken", "Email Security", "Broken", 10, broken))
    assert result.status is Status.ERROR and not result.scored and "boom" in result.summary


def test_report_flags_low_coverage(make_ctx):
    from datetime import datetime, timezone

    from cybergrader.grader import build_report

    results = [
        CheckResult("a", "Email Security", "A", Status.PASS, Severity.INFO, 10, 10, "ok"),
        CheckResult("b", "HTTPS & TLS", "B", Status.ERROR, Severity.INFO, 0, 25, "timed out"),
    ]
    report = build_report(make_ctx(), results, datetime.now(timezone.utc), 1.0)
    assert report.score == 100 and "provisional" in report.grade_note
    assert report.to_dict()["vulnerabilities_and_fixes"] == []


# --- legacy TLS classification -------------------------------------------------------------------

@pytest.mark.parametrize("reason, expected", [
    ("TLSV1_ALERT_PROTOCOL_VERSION", Status.PASS),             # server refused the old protocol
    ("WRONG_VERSION_NUMBER", Status.PASS),
    ("LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED", Status.FAIL),  # server agreed; our crypto policy balked (RHEL)
    ("NO_PROTOCOLS_AVAILABLE", Status.ERROR),                  # this machine can't offer TLS 1.0/1.1 at all
])
def test_legacy_tls_error_classification(make_ctx, monkeypatch, reason, expected):
    import ssl

    from cybergrader.checks import tls

    def handshake(ctx, host, context):
        error = ssl.SSLError(1, reason)
        error.reason = reason
        raise error

    monkeypatch.setattr(tls, "_handshake", handshake)
    ctx = make_ctx()
    ctx.memo.seed("web_host", "example.com")
    ctx.memo.seed("tls", tls.TlsProbe("example.com", reachable=True, verified=True, version="TLSv1.3"))
    assert tls.check_legacy_tls(ctx).status is expected
