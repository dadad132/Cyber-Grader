import json

from conftest import csrf_from, signup

from cybergrader import accounts
from cybergrader.db import connect, transaction
from cybergrader.service import GraderService, ScanRefused


def _db(app):
    return connect(app.config["DB_PATH"])


def _user(app, email="ann@example.com"):
    return accounts.get_user_by_email(_db(app), email)


def _scan(client, domain, **extra):
    return client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": domain, **extra})


def test_landing_explains_the_service_and_offers_sign_up(app):
    html = app.test_client().get("/").get_data(as_text=True)
    for text in ("How it works", "Who it", "IT providers", "Simple pricing", "How accurate is it?",
                 'href="/signup"', 'href="/login"', "R49.00"):
        assert text in html


def test_signup_gives_free_credits_and_signs_in(app):
    client = app.test_client()
    response = signup(client)
    assert response.status_code == 302 and response.location.endswith("/app")
    assert _user(app)["credits"] == 2
    assert "2 credits" in client.get("/app").get_data(as_text=True)


def test_signup_rejects_duplicates_and_requires_terms(app):
    signup(app.test_client())
    duplicate = signup(app.test_client(), email="ANN@example.com")
    assert duplicate.status_code == 400 and "already exists" in duplicate.get_data(as_text=True)
    client = app.test_client()
    response = client.post("/signup", data={"csrf": csrf_from(client, "/signup"), "name": "Bob", "email": "bob@example.com",
                                            "password": "correct horse battery"})
    assert response.status_code == 400 and "accept the terms" in response.get_data(as_text=True)


def test_login_logout_and_bad_password(app):
    signup(app.test_client())
    client = app.test_client()
    bad = client.post("/login", data={"csrf": csrf_from(client, "/login"), "email": "ann@example.com", "password": "nope"})
    assert bad.status_code == 400
    good = client.post("/login", data={"csrf": csrf_from(client, "/login"), "email": "ann@example.com",
                                       "password": "correct horse battery", "next": "/app/account"})
    assert good.location.endswith("/app/account")
    client.post("/logout", data={"csrf": csrf_from(client, "/app")})
    assert client.get("/app").status_code == 302


def test_login_redirect_cannot_leave_the_site(app):
    signup(app.test_client())
    client = app.test_client()
    response = client.post("/login", data={"csrf": csrf_from(client, "/login"), "email": "ann@example.com",
                                           "password": "correct horse battery", "next": "//evil.example/steal"})
    assert response.location.endswith("/app")


def test_scan_uses_a_credit_and_shows_the_report(app):
    client = app.test_client()
    signup(client)
    response = _scan(client, "https://Example.com/page")
    assert response.status_code == 302 and "/app/scans/" in response.location
    assert _user(app)["credits"] == 1 and app.scanned == ["example.com"]
    page = client.get(response.location).get_data(as_text=True)
    assert "example.com" in page and "DMARC enforcement" in page and "Check again" in page


def test_repeat_scan_shows_recent_report_for_free(app):
    client = app.test_client()
    signup(client)
    first = _scan(client, "example.com")
    second = _scan(client, "example.com")
    assert second.location == first.location and _user(app)["credits"] == 1
    _scan(client, "example.com", again="1")
    assert _user(app)["credits"] == 0 and len(app.scanned) == 2


def test_no_credits_sends_customer_to_buy(app):
    client = app.test_client()
    signup(client)
    accounts.adjust_credits(_db(app), _user(app)["id"], -2, "test")
    response = _scan(client, "example.com")
    assert response.location.endswith("/app/buy") and app.scanned == []


def test_with_charging_off_checks_and_pdfs_are_free(app):
    app.extensions["grader"].store.update(charge_for_checks=False)
    client = app.test_client()
    signup(client)
    accounts.adjust_credits(_db(app), _user(app)["id"], -2, "test")  # no credits left
    assert "Free checks" in client.get("/app").get_data(as_text=True)
    response = _scan(client, "example.com")
    assert "/app/scans/" in response.location and _user(app)["credits"] == 0
    assert "No DMARC." in client.get(response.location).get_data(as_text=True)
    pdf = client.get(response.location + "/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    assert _db(app).execute("SELECT paid_with FROM scans").fetchone()["paid_with"] == "free"


def test_failed_scan_is_refunded(app, monkeypatch):
    client = app.test_client()
    signup(client)

    def refuse(self, domain, *, client=None):
        raise ScanRefused("Lookups failed.", 502)

    monkeypatch.setattr(GraderService, "scan", refuse)
    response = _scan(client, "example.com")
    assert "/app" in response.location and _user(app)["credits"] == 2


def test_plan_checks_are_used_before_credits(app):
    client = app.test_client()
    signup(client)
    conn = _db(app)
    user_id = _user(app)["id"]
    with transaction(conn):
        accounts.apply_plan(conn, user_id, plan_id="plan-1", plan_name="Monthly", days=30, scans=1)
    _scan(client, "a.example.com")
    assert _user(app)["credits"] == 2 and _user(app)["plan_scans_left"] == 0
    _scan(client, "b.example.com")
    assert _user(app)["credits"] == 1


def test_reports_are_private(app):
    owner = app.test_client()
    signup(owner)
    report_url = _scan(owner, "example.com").location
    other = app.test_client()
    signup(other, email="eve@example.com")
    assert other.get(report_url).status_code == 404


def test_forms_need_a_csrf_token(app):
    client = app.test_client()
    signup(client)
    assert client.post("/app/scan", data={"domain": "example.com"}).status_code == 400


def test_api_key_checks_charge_credits(app):
    client = app.test_client()
    signup(client)
    page = client.post("/app/account/api-key", data={"csrf": csrf_from(client, "/app/account")}).get_data(as_text=True)
    key = page.split("<code>cg_")[1].split("</code>")[0]
    api = app.test_client()
    assert api.get("/api/grade?domain=example.com").status_code == 401
    assert api.get("/api/grade?domain=example.com", headers={"X-API-Key": "cg_wrong"}).status_code == 401
    response = api.get("/api/grade?domain=example.com", headers={"X-API-Key": "cg_" + key})
    assert response.status_code == 200 and response.get_json()["credits_left"] == 1
    api.get("/api/grade?domain=example.org", headers={"X-API-Key": "cg_" + key})
    assert api.get("/api/grade?domain=example.net", headers={"X-API-Key": "cg_" + key}).status_code == 402


def test_password_reset_flow(app, monkeypatch):
    signup(app.test_client())
    store = app.extensions["grader"].store
    store.update(smtp_host="smtp.example.com", mail_from="noreply@example.com")
    sent = []
    monkeypatch.setattr("cybergrader.site.send_later", lambda settings, to, subject, text: sent.append(text))
    client = app.test_client()
    client.post("/forgot", data={"csrf": csrf_from(client, "/forgot"), "email": "ann@example.com"})
    client.post("/forgot", data={"csrf": csrf_from(client, "/forgot"), "email": "nobody@example.com"})
    assert len(sent) == 1
    link = next(line for line in sent[0].splitlines() if "/reset/" in line)
    path = link[link.index("/reset/"):]
    response = client.post(path, data={"csrf": csrf_from(client, path), "password": "brand new password", "confirm": "brand new password"})
    assert response.location.endswith("/app")
    assert "expired" in client.get(path).get_data(as_text=True)  # single use
    assert accounts.authenticate(_db(app), "ann@example.com", "brand new password") is not None


def test_changing_password_signs_out_other_sessions(app):
    first, second = app.test_client(), app.test_client()
    signup(first)
    second.post("/login", data={"csrf": csrf_from(second, "/login"), "email": "ann@example.com", "password": "correct horse battery"})
    first.post("/app/account/password", data={"csrf": csrf_from(first, "/app/account"), "current": "correct horse battery",
                                              "password": "another long password", "confirm": "another long password"})
    assert first.get("/app").status_code == 200
    assert second.get("/app").status_code == 302


def test_download_report_is_a_standalone_file(app):
    client = app.test_client()
    signup(client)
    report_url = _scan(client, "example.com").location
    response = client.get(report_url + "/download")
    assert "attachment" in response.headers["Content-Disposition"] and b"<!doctype html>" in response.data


def test_stored_report_round_trips(app):
    client = app.test_client()
    signup(client)
    _scan(client, "example.com")
    row = _db(app).execute("SELECT * FROM scans").fetchone()
    report = accounts.load_report(row)
    assert report.domain == "example.com" and report.to_dict()["checks"] == json.loads(row["report_json"])["checks"]
