"""Blacklist (DNSBL/RHSBL), reverse DNS and SMTP STARTTLS checks, with fake blacklists and mail servers."""
import pytest

from cybergrader import dnsbl
from cybergrader.checks import reputation, smtp
from cybergrader.dnsbl import DOMAIN_LISTS, IP_LISTS, DnsblClient
from cybergrader.grader import letter_grade, run_check
from cybergrader.models import Severity, Status
from cybergrader.settings import Settings, general_from_form

TEST_ANSWERS = {"zen.spamhaus.org": "127.0.0.2", "dbl.spamhaus.org": "127.0.1.2", "multi.surbl.org": "127.0.0.254",
                "multi.uribl.com": "127.0.0.14"}
SELF_HOSTED = {"mx": {"example.com": [(10, "mail.example.com")]}, "a": {"mail.example.com": ["41.1.2.5"]},
               "txt": {"example.com": ["v=spf1 mx -all"]}}


@pytest.fixture(autouse=True)
def _fresh_health_cache():
    dnsbl._health.clear()


def fake_lists(listed=None, refuse=(), broken_negative=()):
    """A lookup that answers every list's RFC 5782 test entries correctly, plus the given listings
    (query name -> answers). Lists in refuse answer like Spamhaus/URIBL do when they refuse a query."""
    listed = listed or {}

    def lookup(name):
        for bl in IP_LISTS + DOMAIN_LISTS:
            if name.endswith("." + bl.zone):
                if bl.zone in refuse:
                    return ["127.0.0.1"] if bl.bitmask else ["127.255.255.254"]
                target = name[: -len(bl.zone) - 1]
                if target in ("2.0.0.127", bl.test) or (bl.zone in broken_negative and target in ("1.0.0.127", "invalid")):
                    return [TEST_ANSWERS.get(bl.zone, "127.0.0.2")]
                return listed.get(name, [])
        raise AssertionError(f"unexpected query {name}")

    return DnsblClient(lookup=lookup)


def _spec(check_id):
    from cybergrader.checks import all_checks
    return next(spec for spec in all_checks() if spec.id == check_id)


def check(ctx, check_id):
    return run_check(ctx, _spec(check_id))


# --- the blacklist client ------------------------------------------------------------------------------

def test_a_refusing_list_is_never_reported_as_a_listing():
    client = fake_lists(listed={"5.2.1.41.bl.spamcop.net": ["127.0.0.2"]}, refuse={"zen.spamhaus.org", "multi.uribl.com"})
    sweep = client.sweep(IP_LISTS, ["41.1.2.5"])
    assert [(item.blacklist.name, item.target) for item in sweep.listings] == [("SpamCop", "41.1.2.5")]
    assert "127.255.255.254" in sweep.unavailable["Spamhaus ZEN"] and "Spamhaus ZEN" not in sweep.checked
    domain_sweep = client.sweep(DOMAIN_LISTS, ["example.com"])
    assert domain_sweep.listings == [] and "refused" in domain_sweep.unavailable["URIBL"]


def test_a_list_that_lists_everything_is_ignored():
    client = fake_lists(listed={"5.2.1.41.psbl.surriel.com": ["127.0.0.2"]}, broken_negative={"psbl.surriel.com"})
    sweep = client.sweep(IP_LISTS, ["41.1.2.5"])
    assert sweep.listings == [] and "never be listed" in sweep.unavailable["PSBL"]


def test_answer_codes_are_decoded():
    client = fake_lists(listed={
        "5.2.1.41.zen.spamhaus.org": ["127.0.0.4", "127.0.0.10"],  # XBL + PBL
        "5.2.1.41.bl.mailspike.net": ["127.0.0.13"],  # a reputation score, not a listing
        "example.com.multi.uribl.com": ["127.0.0.4"],  # grey: bulk mail, not a block
        "example.com.multi.surbl.org": ["127.0.0.24"],  # phishing (8) + malware (16)
    })
    zen = DnsblClient.lookup(client, IP_LISTS[0], "41.1.2.5")
    assert [severity for severity, _ in zen] == [Severity.HIGH, Severity.MEDIUM]
    assert client.lookup(next(bl for bl in IP_LISTS if bl.name == "Mailspike"), "41.1.2.5") == []
    assert client.lookup(next(bl for bl in DOMAIN_LISTS if bl.name == "URIBL"), "example.com") == []
    surbl = client.lookup(next(bl for bl in DOMAIN_LISTS if bl.name == "SURBL"), "example.com")
    assert [meaning for _, meaning in surbl] == ["SURBL: a phishing domain", "SURBL: a domain serving malware"]


def test_spamhaus_key_switches_to_the_data_query_service():
    assert DnsblClient(lookup=lambda name: [], spamhaus_key="abc123").zone(IP_LISTS[0]) == "abc123.zen.dq.spamhaus.net"
    assert DnsblClient(lookup=lambda name: []).zone(IP_LISTS[0]) == "zen.spamhaus.org"


# --- which addresses are checked -------------------------------------------------------------------

def test_own_mail_servers_come_from_mx_and_spf_but_not_big_providers(make_ctx):
    ctx = make_ctx(mx={"example.com": [(1, "aspmx.l.google.com")]},
                   txt={"example.com": ["v=spf1 include:_spf.google.com ip4:41.1.3.7 ip4:41.1.3.0/24 a ~ip4:41.1.4.9 -all"]},
                   a={"example.com": ["41.1.3.20"], "aspmx.l.google.com": ["142.250.1.26"]})
    ips, notes = reputation.own_mail_ips(ctx)
    assert ips == ["41.1.3.7", "41.1.3.20"]
    assert any("Google Workspace" in note for note in notes) and any("41.1.3.0/24" in note for note in notes)


def test_hosted_mail_only_is_not_applicable(make_ctx):
    ctx = make_ctx(mx={"example.com": [(1, "example-com.mail.protection.outlook.com")]},
                   txt={"example.com": ["v=spf1 include:spf.protection.outlook.com -all"]})
    ctx.dnsbl = fake_lists()
    result = check(ctx, "ip_blacklists")
    assert result.status is Status.INFO and not result.scored and "Microsoft 365" in result.summary


# --- the checks ----------------------------------------------------------------------------------------

def test_spamhaus_listing_fails_with_removal_advice(make_ctx):
    ctx = make_ctx(**SELF_HOSTED)
    ctx.dnsbl = fake_lists(listed={"5.2.1.41.zen.spamhaus.org": ["127.0.0.2"]})
    result = check(ctx, "ip_blacklists")
    assert result.status is Status.FAIL and result.severity is Severity.HIGH and result.points == 0
    assert "41.1.2.5 is on 1 blacklist (Spamhaus ZEN)" in result.summary
    assert "LISTED: 41.1.2.5 on Spamhaus ZEN" in result.evidence and "check.spamhaus.org" in result.evidence


def test_pbl_only_is_a_medium_warning_about_sending_directly(make_ctx):
    ctx = make_ctx(**SELF_HOSTED)
    ctx.dnsbl = fake_lists(listed={"5.2.1.41.zen.spamhaus.org": ["127.0.0.10"]})
    result = check(ctx, "ip_blacklists")
    assert result.status is Status.WARN and result.severity is Severity.MEDIUM and result.points == 4.0
    assert "home and office internet connections" in result.fix


def test_clean_servers_pass_and_say_what_couldnt_be_checked(make_ctx):
    ctx = make_ctx(**SELF_HOSTED)
    ctx.dnsbl = fake_lists(refuse={"zen.spamhaus.org"})
    result = check(ctx, "ip_blacklists")
    assert result.status is Status.PASS and "Spamhaus ZEN couldn't be checked" in result.summary
    assert "8 spam blacklists" in result.summary


def test_no_working_lists_is_inconclusive_not_clean(make_ctx):
    ctx = make_ctx(**SELF_HOSTED)
    ctx.dnsbl = fake_lists(refuse={bl.zone for bl in IP_LISTS})
    result = check(ctx, "ip_blacklists")
    assert result.status is Status.ERROR and not result.scored


def test_phishing_domain_is_critical_and_caps_the_grade(make_ctx):
    ctx = make_ctx(zone="example.com")
    ctx.dnsbl = fake_lists(listed={"example.com.dbl.spamhaus.org": ["127.0.1.4"]})
    result = check(ctx, "domain_blacklists")
    assert result.status is Status.FAIL and result.severity is Severity.CRITICAL
    assert "Spamhaus DBL: a phishing domain" in result.summary
    assert letter_grade(95, [result])[0] == "C"


def test_subdomain_and_its_parent_are_both_looked_up(make_ctx):
    ctx = make_ctx(domain="shop.example.com", zone="example.com")
    ctx.dnsbl = fake_lists(listed={"shop.example.com.multi.uribl.com": ["127.0.0.2"]})
    result = check(ctx, "domain_blacklists")
    assert result.status is Status.FAIL and "shop.example.com is listed: URIBL black" in result.summary


def test_reverse_dns(make_ctx):
    ctx = make_ctx(**SELF_HOSTED, ptr={"41.1.2.5": ["mail.example.com"]})
    assert check(ctx, "mail_ptr").status is Status.PASS
    missing = check(make_ctx(**SELF_HOSTED), "mail_ptr")
    assert missing.status is Status.FAIL and missing.severity is Severity.MEDIUM and "no reverse DNS" in missing.summary
    mismatch = check(make_ctx(**SELF_HOSTED, ptr={"41.1.2.5": ["other.example.net"]}), "mail_ptr")
    assert mismatch.status is Status.WARN and "doesn't point back" in mismatch.summary
    generic_dns = {**SELF_HOSTED, "a": {"mail.example.com": ["41.1.2.5"], "41-1-2-5.dsl.isp.example": ["41.1.2.5"]}}
    generic = check(make_ctx(**generic_dns, ptr={"41.1.2.5": ["41-1-2-5.dsl.isp.example"]}), "mail_ptr")
    assert generic.status is Status.WARN and "generic ISP name" in generic.summary


# --- SMTP STARTTLS -------------------------------------------------------------------------------------

def smtp_result(host="mail.example.com", **overrides):
    result = {"host": host, "reached": True, "refused": False, "banner": "220 mail.example.com ESMTP", "offered": True,
              "starttls": True, "trusted": True, "tls": "TLSv1.3", "cert_error": "", "error": ""}
    return {**result, **overrides}


@pytest.mark.parametrize("probe, status, severity", [
    (smtp_result(), Status.PASS, Severity.INFO),
    (smtp_result(offered=False, starttls=False, trusted=False, tls=""), Status.FAIL, Severity.HIGH),
    (smtp_result(trusted=False, tls="", cert_error="hostname mismatch"), Status.WARN, Severity.LOW),
    (smtp_result(starttls=False, trusted=False, tls="", cert_error="the TLS handshake failed (x)"), Status.FAIL, Severity.HIGH),
    (smtp_result(refused=True, error="refused the grader's connection (554 blocked)"), Status.ERROR, Severity.INFO),
    (smtp_result(reached=False, banner="", error="couldn't connect (TimeoutError)"), Status.FAIL, Severity.MEDIUM),
])
def test_starttls_outcomes(make_ctx, monkeypatch, probe, status, severity):
    monkeypatch.setattr(smtp, "port25_open", lambda timeout=5.0: True)
    monkeypatch.setattr(smtp, "probe", lambda ctx, host: {**probe, "host": host})
    result = check(make_ctx(mx={"example.com": [(10, "mail.example.com")]}), "smtp_starttls")
    assert (result.status, result.severity) == (status, severity)


def test_blocked_port_25_is_not_tested_and_not_blamed_on_the_domain(make_ctx, monkeypatch):
    monkeypatch.setattr(smtp, "port25_open", lambda timeout=5.0: False)
    monkeypatch.setattr(smtp, "probe", lambda ctx, host: pytest.fail("shouldn't try to connect"))
    result = check(make_ctx(mx={"example.com": [(10, "mail.example.com")]}), "smtp_starttls")
    assert result.status is Status.ERROR and "port 25" in result.summary
    assert not result.scored  # the grader's own network mustn't cost the domain points


# --- settings ------------------------------------------------------------------------------------------

def test_blacklist_settings_validation():
    base = {"site_url": "", "timeout": "6", "rate_limit": "10", "max_concurrent": "4"}
    updated, errors = general_from_form(Settings(), {**base, "dnsbl_nameservers": "127.0.0.1:5335, 9.9.9.9",
                                                     "spamhaus_dqs_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"})
    assert errors == [] and updated.dnsbl_nameservers == ["127.0.0.1:5335", "9.9.9.9"]
    assert updated.spamhaus_dqs_key == "abcdefghijklmnopqrstuvwxyz"
    _, errors = general_from_form(Settings(), {**base, "dnsbl_nameservers": "localhost", "spamhaus_dqs_key": "short!"})
    assert len(errors) == 2
