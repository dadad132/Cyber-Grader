import json

from conftest import csrf_from, signup

from cybergrader import accounts, billing
from cybergrader.db import connect
from cybergrader.settings import Settings, payments_from_form, invoices_from_form

PASSWORD = "correct horse battery"


def admin_client(app):
    client = app.test_client()
    client.post("/admin/setup", data={"csrf": csrf_from(client, "/admin/setup"), "password": PASSWORD, "confirm": PASSWORD})
    return client


def test_first_visit_on_this_computer_creates_the_password(app):
    client = app.test_client()
    assert client.get("/admin/").location.endswith("/admin/setup")
    page = client.post("/admin/setup", data={"csrf": csrf_from(client, "/admin/setup"), "password": "short", "confirm": "short"})
    assert "at least 10 characters" in page.get_data(as_text=True)
    response = client.post("/admin/setup", data={"csrf": csrf_from(client, "/admin/setup"), "password": PASSWORD, "confirm": PASSWORD})
    assert response.location.endswith("/admin/")
    dashboard = client.get("/admin/").get_data(as_text=True)
    assert "Go-live checklist" in dashboard and "Yoco webhook" in dashboard
    assert app.test_client().get("/admin/").location.endswith("/admin/login")


def test_admin_is_hidden_from_the_internet_unless_enabled(app, monkeypatch):
    remote = {"REMOTE_ADDR": "203.0.113.9"}
    assert app.test_client().get("/admin/", environ_base=remote).status_code == 404
    monkeypatch.setenv("GRADER_ADMIN_REMOTE", "1")
    client = app.test_client()
    assert client.get("/admin/", environ_base=remote).location.endswith("/admin/setup")
    # Nobody on the internet can claim the portal before the password is set on the server.
    page = client.get("/admin/setup", environ_base=remote)
    assert page.status_code == 403 and "cybergrader-manage set-admin-password" in page.get_data(as_text=True)


def test_admin_login_lockout(app):
    admin_client(app)
    client = app.test_client()
    token = csrf_from(client, "/admin/login")
    for _ in range(5):
        client.post("/admin/login", data={"csrf": token, "password": "wrong"})
    locked = client.post("/admin/login", data={"csrf": token, "password": PASSWORD}).get_data(as_text=True)
    assert "Too many failed attempts" in locked


def test_settings_sections_save_and_validate(app):
    client = admin_client(app)
    store = app.extensions["grader"].store
    for section in ("general", "payments", "invoices", "email", "legal", "password"):
        assert client.get(f"/admin/settings/{section}").status_code == 200
    form = {"csrf": csrf_from(client, "/admin/settings/general"), "site_url": "https://grader.example.co.za/",
            "brand_name": "EasyMikroTik", "brand_url": "https://easymikrotik.com", "contact_email": "hi@easymikrotik.com",
            "contact_phone": "", "cta_text": "", "timeout": "6", "nameservers": "", "user_agent": "", "rate_limit": "10",
            "max_concurrent": "4", "trust_proxy": "on"}
    assert client.post("/admin/settings/general", data=form).status_code == 302
    assert store.current.site_url == "https://grader.example.co.za" and store.current.trust_proxy
    assert "EasyMikroTik" in app.test_client().get("/").get_data(as_text=True)
    bad = client.post("/admin/settings/general", data={**form, "brand_url": "javascript:alert(1)"})
    assert bad.status_code == 400 and store.current.brand_url == "https://easymikrotik.com"


def test_pricing_and_vat_validation():
    base = {"signup_credits": "1", "yoco_secret_key": "pk_live_wrong", "pack_0_name": "Cheap", "pack_0_credits": "1",
            "pack_0_price": "1.50", "plan_0_name": "Monthly", "plan_0_price": "R 499.00", "plan_0_scans": "0", "plan_0_days": "30"}
    updated, errors = payments_from_form(Settings(), base)
    assert len(errors) == 2  # wrong key prefix, price under R2
    assert updated.plans[0]["price_cents"] == 49900 and updated.plans[0]["scans"] == 0
    _, errors = invoices_from_form(Settings(), {"vat_registered": "on", "vat_number": "12345", "vat_rate": "15",
                                                "invoice_prefix": "INV"})
    assert errors == ["A South African VAT number has 10 digits and starts with 4."]


def test_secrets_are_kept_when_left_blank(app):
    client = admin_client(app)
    store = app.extensions["grader"].store
    store.update(yoco_secret_key="sk_test_keepme", smtp_password="keep-this")
    form = {"csrf": csrf_from(client, "/admin/settings/payments"), "signup_credits": "1", "yoco_secret_key": "",
            "yoco_webhook_secret": "", "pack_0_name": "One", "pack_0_credits": "1", "pack_0_price": "49"}
    assert client.post("/admin/settings/payments", data=form).status_code == 302
    assert store.current.yoco_secret_key == "sk_test_keepme"
    page = client.get("/admin/settings/payments").get_data(as_text=True)
    assert "sk_test_keepme" not in page and "sk_test_…" in page


def test_support_tools_for_users_and_payments(app):
    client = admin_client(app)
    signup(app.test_client())
    conn = connect(app.config["DB_PATH"])
    user = accounts.get_user_by_email(conn, "ann@example.com")
    token = csrf_from(client, f"/admin/users/{user['id']}")
    client.post(f"/admin/users/{user['id']}/credits", data={"csrf": token, "change": "5", "reason": "Promo"})
    assert accounts.get_user(conn, user["id"])["credits"] == 7
    client.post(f"/admin/users/{user['id']}/plan", data={"csrf": token, "plan_id": "plan-1", "action": "grant"})
    assert accounts.plan_status(accounts.get_user(conn, user["id"]))["active"]
    client.post(f"/admin/users/{user['id']}/status", data={"csrf": token})
    assert accounts.get_user(conn, user["id"])["disabled"] == 1
    order = billing.create_order(conn, user["id"], app.extensions["grader"].store.current.product("pack-1"))
    client.post(f"/admin/orders/{order['id']}/mark-paid", data={"csrf": csrf_from(client, "/admin/payments"), "reference": "EFT-42"})
    invoice = conn.execute("SELECT * FROM invoices").fetchone()
    assert json.loads(invoice["data_json"])["payment_ref"] == "EFT-42"
    assert "INVOICE" in client.get(f"/admin/invoices/{invoice['number']}").get_data(as_text=True)
    assert "ann@example.com" in client.get("/admin/users?q=ann").get_data(as_text=True)
