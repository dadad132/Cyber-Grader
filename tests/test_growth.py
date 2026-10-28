"""Free checks, owner verification, leads, SEO pages, PDFs and building network audits."""
import json
import re

import pytest
from conftest import csrf_from, signup

from cybergrader import accounts, lan
from cybergrader.db import connect
from cybergrader.seo import TOOLS, jsonld
from markupsafe import escape


def _db(app):
    return connect(app.config["DB_PATH"])


def free_check(client, domain="example.com"):
    return client.post("/check", data={"csrf": csrf_from(client, "/"), "domain": domain})


def json_ld(html):
    return [json.loads(block) for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)]


# --- search engines ---------------------------------------------------------------------------------

def test_landing_targets_domain_health_searches(app):
    response = app.test_client().get("/")
    html = response.get_data(as_text=True)
    assert "<title>Free Domain Health Check" in html and "<h1>Free domain health check" in html
    assert 'name="description" content="Free domain health check' in html and 'rel="canonical"' in html
    assert 'action="/check"' in html  # the free check is the first thing people see
    types = [item["@type"] for item in json_ld(html)[0]["@graph"]]
    assert types == ["Organization", "WebSite", "WebApplication", "FAQPage"]


@pytest.mark.parametrize("slug", sorted(TOOLS))
def test_tool_pages(app, slug):
    html = app.test_client().get(f"/{slug}").get_data(as_text=True)
    assert f"<h1>{TOOLS[slug]['h1']}</h1>" in html and str(escape(TOOLS[slug]["description"])) in html
    assert 'action="/check"' in html and 'rel="canonical"' in html
    assert {"FAQPage", "BreadcrumbList"} <= {item["@type"] for item in json_ld(html)[0]["@graph"]}


def test_robots_and_sitemap(app):
    client = app.test_client()
    robots = client.get("/robots.txt").get_data(as_text=True)
    assert "Disallow: /app" in robots and "Disallow: /admin" in robots and "Sitemap: http://localhost/sitemap.xml" in robots
    sitemap = client.get("/sitemap.xml").get_data(as_text=True)
    for slug in TOOLS:
        assert f"http://localhost/{slug}</loc>" in sitemap
    assert "/app" not in sitemap and "/check/" not in sitemap


def test_private_pages_are_noindex(app):
    for path in ("/login", "/signup", "/forgot"):
        assert '<meta name="robots" content="noindex">' in app.test_client().get(path).get_data(as_text=True)


def test_json_ld_cannot_break_out_of_its_script_tag():
    assert "</script><script>" not in str(jsonld({"name": "</script><script>alert(1)</script>"}))


# --- free checks ------------------------------------------------------------------------------------

def test_free_check_shows_summary_but_hides_details(app):
    client = app.test_client()
    response = free_check(client, "https://Example.com/page")
    assert response.status_code == 302 and "/check/" in response.location
    page = client.get(response.location)
    html = page.get_data(as_text=True)
    assert page.headers["X-Robots-Tag"] == "noindex"
    assert "example.com" in html and "1 thing to fix" in html and "Email Security" in html
    assert "No DMARC." not in html and "Add DMARC." not in html  # the actual finding and fix stay locked
    assert "Sign up free to unlock" in html


def test_free_checks_are_rate_limited_but_repeats_are_free(app):
    app.extensions["grader"].store.update(free_checks_per_hour=2)
    client = app.test_client()
    free_check(client, "a.example.com")
    free_check(client, "a.example.com")  # same domain within the hour: reused, not counted
    free_check(client, "b.example.com")
    assert free_check(client, "c.example.com").location.endswith("/signup")
    assert app.scanned == ["a.example.com", "b.example.com"]


def test_unlocking_with_a_credit_reuses_the_check(app):
    client = app.test_client()
    signup(client)
    token_url = free_check(client).location
    response = client.post(token_url + "/unlock", data={"csrf": csrf_from(client, token_url)})
    assert "/app/scans/" in response.location
    assert accounts.get_user_by_email(_db(app), "ann@example.com")["credits"] == 1
    assert app.scanned == ["example.com"]  # not scanned twice
    assert "No DMARC." in client.get(response.location).get_data(as_text=True)


def test_with_charging_off_free_checks_show_everything(app):
    app.extensions["grader"].store.update(charge_for_checks=False)
    client = app.test_client()
    token_url = free_check(client).location
    html = client.get(token_url).get_data(as_text=True)
    assert "No DMARC." in html and "Add DMARC." in html and "Sign up free to unlock" not in html
    pdf = client.get(token_url + "/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")


def test_anonymous_unlock_goes_to_sign_up(app):
    client = app.test_client()
    token_url = free_check(client).location
    response = client.post(token_url + "/unlock", data={"csrf": csrf_from(client, token_url)})
    assert "/signup" in response.location and "next=" in response.location


def test_owner_verification(app, monkeypatch):
    app.extensions["grader"].store.update(smtp_host="smtp.example.com", mail_from="noreply@example.com")
    sent = []
    monkeypatch.setattr("cybergrader.preview.send_mail", lambda settings, to, subject, text, *a: sent.append((to, text)))
    client = app.test_client()
    token_url = free_check(client).location

    def post(path, **data):
        return client.post(token_url + path, data={"csrf": csrf_from(client, token_url), **data}, follow_redirects=True)

    assert "only be sent to an address ending in @example.com" in post("/owner", email="me@gmail.com").get_data(as_text=True)
    post("/owner", email="info")
    assert sent[0][0] == "info@example.com"
    code = re.search(r"\b(\d{6})\b", sent[0][1]).group(1)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        post("/owner/verify", code=wrong)
    locked = post("/owner/verify", code=code).get_data(as_text=True)
    assert "expired or had too many attempts" in locked  # brute force is capped at 5 tries per code
    post("/owner", email="info@example.com")
    code = re.search(r"\b(\d{6})\b", sent[-1][1]).group(1)
    html = post("/owner/verify", code=code).get_data(as_text=True)
    assert "No DMARC." in html and "you're verified" in html.replace("&#39;", "'")
    lead = _db(app).execute("SELECT * FROM leads").fetchone()
    assert (lead["source"], lead["email"], lead["domain"]) == ("owner", "info@example.com", "example.com")


def test_owner_codes_are_rate_limited(app, monkeypatch):
    app.extensions["grader"].store.update(smtp_host="smtp.example.com", mail_from="noreply@example.com")
    sent = []
    monkeypatch.setattr("cybergrader.preview.send_mail", lambda settings, to, subject, text, *a: sent.append(to))
    client = app.test_client()
    token_url = free_check(client).location
    for _ in range(5):
        client.post(token_url + "/owner", data={"csrf": csrf_from(client, token_url), "email": "info"})
    assert len(sent) == 3


# --- leads ------------------------------------------------------------------------------------------

def test_fix_requests_become_leads(app):
    client = app.test_client()
    token_url = free_check(client).location
    client.post(token_url + "/help", data={"csrf": csrf_from(client, token_url), "name": "Bob", "email": "bob@example.com",
                                           "phone": "+27 82 000 0000", "message": "Please help"})
    signup(client, email="carol@example.com", name="Carol")
    report_url = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "example.org"}).location
    client.post(report_url + "/help", data={"csrf": csrf_from(client, report_url), "message": "Fix it"})
    rows = _db(app).execute("SELECT source, name, email, tier FROM leads ORDER BY id").fetchall()
    assert [(r["source"], r["name"]) for r in rows] == [("preview", "Bob"), ("report", "Carol")]
    assert rows[0]["tier"] == "Urgent security overhaul"


def test_admin_sees_and_updates_leads(app):
    from test_admin import admin_client

    client = app.test_client()
    token_url = free_check(client).location
    client.post(token_url + "/help", data={"csrf": csrf_from(client, token_url), "name": "Bob", "email": "bob@example.com"})
    admin = admin_client(app)
    assert "bob@example.com" in admin.get("/admin/leads").get_data(as_text=True)
    lead_id = _db(app).execute("SELECT id FROM leads").fetchone()[0]
    admin.post(f"/admin/leads/{lead_id}/status", data={"csrf": csrf_from(admin, "/admin/leads"), "status": "won"})
    assert _db(app).execute("SELECT status FROM leads").fetchone()[0] == "won"
    assert "Recent free checks" in admin.get("/admin/").get_data(as_text=True)


# --- PDF ----------------------------------------------------------------------------------------------

def test_report_pdf_download(app):
    pytest.importorskip("reportlab")
    client = app.test_client()
    signup(client)
    report_url = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "example.com"}).location
    response = client.get(report_url + "/pdf")
    assert response.mimetype == "application/pdf" and response.data.startswith(b"%PDF")


def test_pdf_prepared_for_can_be_changed_or_hidden(app, monkeypatch):
    from cybergrader import site

    client = app.test_client()
    signup(client)
    report_url = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "example.com"}).location
    assert 'name="prepared_for" value="Example Ltd"' in client.get(report_url).get_data(as_text=True)
    seen = []
    monkeypatch.setattr(site, "report_pdf", lambda report, branding, **kw: seen.append(kw["recipient"]) or b"%PDF-fake")
    client.get(report_url + "/pdf")  # plain link (e.g. from the Clients page): the default
    client.get(report_url + "/pdf?prepared_for=  Multi   IT ")
    client.get(report_url + "/pdf?prepared_for=")  # blank: no "Prepared for" line at all
    assert seen == ["Example Ltd", "Multi IT", ""]


# --- building network audits -------------------------------------------------------------------------

def test_lan_scores_only_what_was_measured():
    audit = lan.evaluate({"gateway_ip": "192.168.88.1", "gateway_ports_checked": [23, 8291], "open_gateway_ports": [23],
                          "hosts_scanned": 0, "wifi": None})
    assert audit["grade"] == "F" and audit["findings"][0]["severity"] == "critical"
    assert set(audit["not_checked"]) >= {"Wi-Fi encryption", "UPnP", "Latency", "Network segmentation"}
    clean = lan.evaluate({"gateway_ports_checked": [23], "open_gateway_ports": [], "hosts_scanned": 253,
                          "upnp_enabled": False, "wifi": {"ssid": "Office", "security": "WPA2-Personal", "signal_dbm": -60}})
    assert clean["grade"] == "A" and clean["score"] == 100 and not clean["findings"]
    with pytest.raises(lan.AuditError):
        lan.evaluate({"gateway_ip": "not-an-ip"})


def test_lan_audit_upload_requires_api_key(app):
    client = app.test_client()
    signup(client)
    page = client.post("/app/account/api-key", data={"csrf": csrf_from(client, "/app/account")}).get_data(as_text=True)
    key = "cg_" + page.split("<code>cg_")[1].split("</code>")[0]
    payload = {"site_name": "HQ", "gateway_ip": "192.168.88.1", "gateway_ports_checked": [80, 8291],
               "open_gateway_ports": [80], "hosts_scanned": 253, "exposed_lan_services": [{"ip": "192.168.88.20", "port": 445}],
               "upnp_enabled": True, "wifi": {"ssid": "HQ", "security": "OPEN"}}
    api = app.test_client()
    assert api.post("/api/lan-audit", json=payload).status_code == 401
    assert api.post("/api/lan-audit", json={"gateway_ip": "x"}, headers={"X-API-Key": key}).status_code == 400
    response = api.post("/api/lan-audit", json=payload, headers={"X-API-Key": key})
    assert response.status_code == 201
    result = response.get_json()
    assert result["grade"] in ("D", "F") and len(result["findings"]) == 4
    html = client.get(f"/app/lan/{result['id']}").get_data(as_text=True)
    assert "has no password or encryption" in html and "Not checked" in html
    assert "Building network audits" in client.get("/app").get_data(as_text=True)
    other = app.test_client()
    signup(other, email="eve@example.com")
    assert other.get(f"/app/lan/{result['id']}").status_code == 404


def test_agent_download_and_guide(app, monkeypatch, tmp_path):
    response = app.test_client().get("/downloads/lan_agent.py")
    assert response.status_code == 200 and b"def audit(" in response.data  # no secrets inside, so no sign-in needed
    guide = app.test_client().get("/network-audit").get_data(as_text=True)
    assert "How to run a building network audit" in guide and "Create API key" in guide
    assert "isn't available for download" in guide or "Download the app" in guide
    fake_apk = tmp_path / "app.apk"
    fake_apk.write_bytes(b"PK fake apk")
    monkeypatch.setattr("cybergrader.site.APP_PATH", fake_apk)
    response = app.test_client().get("/downloads/building-network-audit.apk")
    assert response.mimetype == "application/vnd.android.package-archive" and response.data == b"PK fake apk"
    assert "Download the app (.apk)" in app.test_client().get("/network-audit").get_data(as_text=True)


# --- external internet-exposure check ---------------------------------------------------------------

def test_external_exposure_only_targets_the_callers_own_ip(app, monkeypatch):
    from cybergrader import external

    checked = []

    def fake_check(public_ip, *, timeout=2.0):
        checked.append(public_ip)
        # Pretend Winbox (8291) is open to the internet on the caller's own address.
        return {"checked": True, "ip": public_ip, "open_ports": [8291], "reason": ""}

    monkeypatch.setattr(external, "check_exposure", fake_check)
    client = app.test_client()
    signup(client)
    key = "cg_" + client.post("/app/account/api-key", data={"csrf": csrf_from(client, "/app/account")}
                             ).get_data(as_text=True).split("<code>cg_")[1].split("</code>")[0]
    api = app.test_client()
    # A payload that tries to name a different target is ignored; only the request source IP is used.
    payload = {"site_name": "HQ", "gateway_ports_checked": [23], "open_gateway_ports": [], "hosts_scanned": 253,
               "check_external": True, "_external": {"checked": True, "ip": "8.8.8.8", "findings": []}}
    resp = api.post("/api/lan-audit", json=payload, headers={"X-API-Key": key}, environ_base={"REMOTE_ADDR": "41.0.0.9"})
    assert resp.status_code == 201
    audit = resp.get_json()
    assert checked == ["41.0.0.9"] and audit["public_ip"] == "41.0.0.9"  # only the real source IP, never 8.8.8.8
    assert any("Winbox" in f["title"] and f["severity"] == "critical" for f in audit["findings"])
    assert audit["grade"] in ("D", "F")


def test_external_check_refuses_private_source_ips():
    from cybergrader import external

    result = external.check_exposure("127.0.0.1")
    assert result["checked"] is False and "local test" in result["reason"]
    result = external.check_exposure("192.168.1.10")
    assert result["checked"] is False and not result["open_ports"]


def test_external_findings_map_ports_to_fixes():
    from cybergrader import external

    out = external.findings({"ip": "41.0.0.9", "open_ports": [8291, 3389]})
    assert {f["severity"] for f in out} == {"critical"}
    assert any("Winbox" in f["title"] for f in out) and any("Remote Desktop" in f["title"] for f in out)
    assert external.findings({"ip": "41.0.0.9", "open_ports": []}) == []
