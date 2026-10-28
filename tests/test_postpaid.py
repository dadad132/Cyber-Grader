"""Monthly accounts (pay after use), plan renewal reminders and the plan settings."""
import json
from datetime import datetime, timedelta, timezone

from conftest import csrf_from, signup
from markupsafe import escape
from test_admin import admin_client
from test_billing import event, post_webhook, setup_paid_site

from cybergrader import accounts, billing, manage, postpaid
from cybergrader.db import connect, iso, parse_iso, transaction, utcnow
from cybergrader.settings import Settings, SettingsStore, payments_from_form

MAIL = {"smtp_host": "smtp.example.com", "mail_from": "billing@example.com", "site_url": "https://grader.example.com"}


def _db(app):
    return connect(app.config["DB_PATH"])


def _user(app):
    return accounts.get_user_by_email(_db(app), "ann@example.com")


def scan(client, domain):
    return client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": domain})


def account_site(app, **settings):
    """A paid site offering monthly accounts (R99 a month + R39 a check, 3 checks a month, 3 days to pay) and a
    signed-in customer with no credits, so checks go on the account once it's open."""
    store = setup_paid_site(app, account_enabled=True, account_fee_cents=9900, account_check_cents=3900,
                            account_max_checks=3, account_grace_days=3, **settings)
    client = app.test_client()
    signup(client)
    conn = _db(app)
    accounts.adjust_credits(conn, _user(app)["id"], -_user(app)["credits"], "test")
    return store, client, conn


def open_now(conn, user_id):
    with transaction(conn):
        accounts.open_account(conn, user_id)


def with_checkout(conn, order, checkout_id):
    conn.execute("UPDATE orders SET checkout_id = ? WHERE id = ?", (checkout_id, order["id"]))
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order["id"],)).fetchone()


def test_billing_day_is_the_same_day_next_month_and_never_drifts():
    def day(*parts):
        return datetime(*parts, tzinfo=timezone.utc)
    assert accounts.next_bill_date(day(2026, 10, 15, 9)) == day(2026, 11, 15, 9)
    assert accounts.next_bill_date(day(2026, 12, 20)) == day(2027, 1, 20)
    assert accounts.next_bill_date(day(2027, 1, 31)) == day(2027, 2, 28)
    assert accounts.next_bill_date(day(2027, 2, 28)) == day(2027, 3, 28)


def test_paying_the_fee_opens_the_account_with_an_invoice(app):
    store, client, conn = account_site(app)
    assert "Open account" in client.get("/app/buy").get_data(as_text=True)
    order = with_checkout(conn, billing.create_order(conn, _user(app)["id"], store.current.product("account")), "ch_acc")
    assert order["amount_cents"] == 9900
    assert post_webhook(app, event(order)).status_code == 200
    user = _user(app)
    assert user["account_status"] == "active"
    assert parse_iso(user["account_period_end"]) == accounts.next_bill_date(parse_iso(user["account_period_start"]))
    invoice = json.loads(conn.execute("SELECT data_json FROM invoices WHERE order_id = ?", (order["id"],)).fetchone()[0])
    assert invoice["lines"][0]["description"] == "Monthly account: first month's fee"
    assert "Your account is open" in client.get("/app/buy").get_data(as_text=True)


def test_checks_use_credits_first_then_the_account_up_to_the_monthly_limit(app):
    _, client, conn = account_site(app)
    open_now(conn, _user(app)["id"])
    accounts.adjust_credits(conn, _user(app)["id"], 1, "test")
    for domain in ("a.example.com", "b.example.com", "c.example.com", "d.example.com"):
        assert "/app/scans/" in scan(client, domain).location
    rows = conn.execute("SELECT paid_with, charge_cents FROM scans ORDER BY id").fetchall()
    assert [tuple(row) for row in rows] == [("credit", None), ("account", 3900), ("account", 3900), ("account", 3900)]
    assert "3 / 3" in client.get("/app").get_data(as_text=True)
    assert scan(client, "e.example.com").location.endswith("/app/buy")
    assert str(escape("used this month's 3 checks")) in client.get("/app/buy").get_data(as_text=True)


def test_month_end_bill_lists_the_checks_and_next_months_fee_once(app):
    store, client, conn = account_site(app)
    uid = _user(app)["id"]
    open_now(conn, uid)
    scan(client, "a.example.com")
    scan(client, "b.example.com")
    start, end = utcnow() - timedelta(days=30), utcnow() - timedelta(minutes=1)
    conn.execute("UPDATE users SET account_period_start = ?, account_period_end = ? WHERE id = ?", (iso(start), iso(end), uid))
    conn.execute("UPDATE scans SET created_at = ?", (iso(end - timedelta(days=1)),))
    (bill,) = postpaid.issue_bills(conn, store.current)
    lines = json.loads(bill["lines_json"])
    assert [(line["quantity"], line["amount_cents"]) for line in lines] == [(2, 7800), (1, 9900)]
    assert lines[1]["description"].startswith("Monthly account fee")
    assert bill["amount_cents"] == 17700 and bill["status"] == "pending"
    assert parse_iso(bill["due_at"]) - parse_iso(bill["created_at"]) == timedelta(days=3)
    user = _user(app)
    assert user["account_period_start"] == iso(end)
    assert parse_iso(user["account_period_end"]) == accounts.next_bill_date(end)
    assert postpaid.issue_bills(conn, store.current) == []  # never billed twice
    assert postpaid.unbilled(conn, uid) == (0, 0)
    assert "R177.00" in client.get("/app/invoices").get_data(as_text=True)


def test_unpaid_bill_puts_the_account_on_hold_until_it_is_paid(app):
    store, client, conn = account_site(app)
    uid = _user(app)["id"]
    open_now(conn, uid)
    bill = postpaid.bill_now(conn, store.current, uid)  # nothing used yet: just next month's fee
    assert [line["amount_cents"] for line in json.loads(bill["lines_json"])] == [9900]
    assert "/app/scans/" in scan(client, "a.example.com").location  # still works while the bill isn't due
    conn.execute("UPDATE orders SET due_at = ? WHERE id = ?", (iso(utcnow() - timedelta(minutes=1)), bill["id"]))
    response = scan(client, "b.example.com")
    assert response.location.endswith(f"/app/bills/{bill['ref']}")
    page = client.get(response.location).get_data(as_text=True)
    assert "on hold" in page and "Pay R99.00" in page
    bill = with_checkout(conn, bill, "ch_bill")
    post_webhook(app, event(bill, event_id="evt_declined", kind="payment.failed"))
    assert conn.execute("SELECT status FROM orders WHERE id = ?", (bill["id"],)).fetchone()[0] == "pending"  # still owed
    assert post_webhook(app, event(bill, event_id="evt_paid")).status_code == 200
    assert "/app/scans/" in scan(client, "b.example.com").location
    invoice = json.loads(conn.execute("SELECT data_json FROM invoices WHERE order_id = ?", (bill["id"],)).fetchone()[0])
    assert invoice["lines"] == json.loads(bill["lines_json"])


def test_closing_ends_with_a_final_bill_and_no_new_fee(app):
    store, client, conn = account_site(app)
    uid = _user(app)["id"]
    open_now(conn, uid)
    scan(client, "a.example.com")
    client.post("/app/account/monthly", data={"csrf": csrf_from(client, "/app/account"), "action": "close"})
    assert _user(app)["account_status"] == "closing"
    bill = postpaid.bill_now(conn, store.current, uid)
    assert [line["amount_cents"] for line in json.loads(bill["lines_json"])] == [3900]
    assert _user(app)["account_status"] == "closed"
    assert scan(client, "b.example.com").location.endswith("/app/buy")


def test_bill_email_then_reminder_then_on_hold_notice(app, monkeypatch):
    store, _, conn = account_site(app, **MAIL)
    sent = []
    monkeypatch.setattr(manage, "send_mail", lambda settings, to, subject, text: sent.append((subject, text)))
    uid = _user(app)["id"]
    open_now(conn, uid)
    conn.execute("UPDATE users SET account_period_end = ? WHERE id = ?", (iso(utcnow() - timedelta(minutes=1)), uid))
    assert manage.bill_accounts(store, None) == 0
    assert len(sent) == 1 and sent[0][0].startswith("Your monthly account bill: R99.00")
    assert "https://grader.example.com/app/bills/" in sent[0][1]
    manage.bill_accounts(store, None)
    assert len(sent) == 1  # nothing new to say
    bill_id = conn.execute("SELECT id FROM orders WHERE product_kind = 'bill'").fetchone()[0]
    conn.execute("UPDATE orders SET due_at = ? WHERE id = ?", (iso(utcnow() + timedelta(hours=12)), bill_id))
    manage.bill_accounts(store, None)
    assert sent[1][0].startswith("Reminder")
    conn.execute("UPDATE orders SET due_at = ? WHERE id = ?", (iso(utcnow() - timedelta(hours=1)), bill_id))
    manage.bill_accounts(store, None)
    assert "on hold" in sent[2][0] and len(sent) == 3
    manage.bill_accounts(store, None)
    assert len(sent) == 3


def test_admin_opens_bills_settles_and_closes_an_account(app):
    store, client, conn = account_site(app)
    uid = _user(app)["id"]
    admin = admin_client(app)
    page = f"/admin/users/{uid}"
    admin.post(f"/admin/users/{uid}/account", data={"csrf": csrf_from(admin, page), "action": "open"})
    assert _user(app)["account_status"] == "active"
    scan(client, "a.example.com")
    admin.post(f"/admin/users/{uid}/account", data={"csrf": csrf_from(admin, page), "action": "bill"})
    bill = conn.execute("SELECT * FROM orders WHERE product_kind = 'bill'").fetchone()
    assert bill["amount_cents"] == 3900 + 9900
    admin.post(f"/admin/orders/{bill['id']}/mark-paid", data={"csrf": csrf_from(admin, "/admin/payments"), "reference": "EFT-7"})
    assert conn.execute("SELECT status FROM orders WHERE id = ?", (bill["id"],)).fetchone()[0] == "paid"
    admin.post(f"/admin/users/{uid}/account", data={"csrf": csrf_from(admin, page), "action": "close"})
    assert _user(app)["account_status"] == "closing"
    assert "closing" in admin.get(page).get_data(as_text=True)


# --- plan renewal reminders ------------------------------------------------------------------------

def test_reminder_stages():
    expires = datetime(2026, 11, 30, 7, tzinfo=timezone.utc)

    def stage(days_before, sent=None, ended_email=True):
        return manage.reminder_stage(expires, expires - timedelta(days=days_before), [7, 3, 1], ended_email, sent)

    assert stage(10) is None
    assert stage(6.5) == "7"
    assert stage(6.5, f"{iso(expires)}|7") is None
    assert stage(2.5, f"{iso(expires)}|7") == "3"
    assert stage(0.5, f"{iso(expires)}|3") == "1"
    assert stage(-1, f"{iso(expires)}|1") == "ended"
    assert stage(-1, f"{iso(expires)}|ended") is None
    assert stage(-10) is None  # ended too long ago to mention
    assert stage(-1, ended_email=False) is None
    assert stage(2.5, iso(expires)) is None  # the older single 3-day reminder counts as sent
    assert stage(0.5, iso(expires)) == "1"
    assert stage(6.5, f"{iso(expires - timedelta(days=30))}|ended") == "7"  # renewed: a new period starts over


def test_plan_reminder_links_to_renewing_that_plan(app, monkeypatch):
    store = app.extensions["grader"].store
    store.update(**MAIL)
    sent = []
    monkeypatch.setattr(manage, "send_mail", lambda settings, to, subject, text: sent.append((subject, text)))
    client = app.test_client()
    signup(client)
    conn, uid = _db(app), _user(app)["id"]
    conn.execute("UPDATE users SET plan_id = 'plan-1', plan_name = 'Monthly', plan_expires_at = ?, plan_scans_left = 5 "
                 "WHERE id = ?", (iso(utcnow() + timedelta(days=2)), uid))
    assert manage.send_reminders(store, None) == 0
    assert len(sent) == 1 and sent[0][0].startswith("Your Monthly plan ends on")
    assert "https://grader.example.com/app/buy?renew=plan-1" in sent[0][1] and "5 checks left" in sent[0][1]
    manage.send_reminders(store, None)
    assert len(sent) == 1
    assert "Renew your Monthly plan" in client.get("/app/buy?renew=plan-1").get_data(as_text=True)
    accounts.end_plan(conn, uid)  # ended by the admin: no "your plan has ended" email
    manage.send_reminders(store, None)
    assert len(sent) == 1


# --- settings --------------------------------------------------------------------------------------

def test_settings_for_reminders_and_monthly_accounts(tmp_path):
    base = {"signup_credits": "1", "pack_0_name": "One", "pack_0_credits": "1", "pack_0_price": "49",
            "plan_reminder_days": "1, 7 3", "plan_ended_email": "on", "account_enabled": "on", "account_name": "Pay monthly",
            "account_fee": "99", "account_check": "R 25.00", "account_max_checks": "50", "account_grace_days": "3"}
    updated, errors = payments_from_form(Settings(), base)
    assert errors == []
    assert updated.plan_reminder_days == [7, 3, 1] and updated.plan_ended_email
    assert (updated.account_fee_cents, updated.account_check_cents, updated.account_max_checks) == (9900, 2500, 50)
    assert updated.product("account") == {"id": "account", "kind": "account", "name": "Pay monthly", "price_cents": 9900}
    _, errors = payments_from_form(Settings(), {**base, "plan_reminder_days": "7, soon", "account_fee": ""})
    assert len(errors) == 2
    off, errors = payments_from_form(Settings(), {**base, "account_enabled": "", "account_fee": "", "account_check": ""})
    assert errors == [] and off.account_fee_cents == Settings().account_fee_cents and off.product("account") is None
    store = SettingsStore(tmp_path / "settings.json")
    store.update(plan_reminder_days=[5, 2])
    assert SettingsStore(tmp_path / "settings.json").current.plan_reminder_days == [5, 2]
