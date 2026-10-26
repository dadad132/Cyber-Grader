import base64
import hashlib
import hmac
import json
import time

from conftest import csrf_from, signup

from cybergrader import accounts, billing
from cybergrader.db import connect
from cybergrader.settings import Settings

SECRET = "whsec_" + base64.b64encode(b"super-secret-webhook-key").decode()


def sign(body: bytes, event_id="evt_1", timestamp=None, secret=SECRET) -> dict:
    timestamp = str(int(timestamp if timestamp is not None else time.time()))
    key = base64.b64decode(secret.split("_", 1)[1])
    signature = base64.b64encode(hmac.new(key, f"{event_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()).decode()
    return {"webhook-id": event_id, "webhook-timestamp": timestamp, "webhook-signature": f"v1,{signature}"}


def event(order, event_id="evt_1", amount=None, mode="live", kind="payment.succeeded") -> dict:
    return {"id": event_id, "type": kind, "createdDate": "2026-10-21T08:00:00Z",
            "payload": {"id": "pay_123", "type": "payment", "status": "succeeded", "currency": "ZAR", "mode": mode,
                        "amount": order["amount_cents"] if amount is None else amount,
                        "metadata": {"checkoutId": order["checkout_id"], "orderRef": order["ref"]}}}


def setup_paid_site(app, **settings):
    store = app.extensions["grader"].store
    store.update(yoco_secret_key="sk_live_abc123", yoco_webhook_secret=SECRET, legal_name="EasyMikroTik (Pty) Ltd",
                 business_address="1 Main Road\nCape Town", **settings)
    return store


def make_order(app, product_id="pack-2", checkout_id="ch_1"):
    conn = connect(app.config["DB_PATH"])
    client = app.test_client()
    signup(client)
    user = accounts.get_user_by_email(conn, "ann@example.com")
    order = billing.create_order(conn, user["id"], app.extensions["grader"].store.current.product(product_id))
    conn.execute("UPDATE orders SET checkout_id = ? WHERE id = ?", (checkout_id, order["id"]))
    return conn, client, conn.execute("SELECT * FROM orders WHERE id = ?", (order["id"],)).fetchone()


def post_webhook(app, payload: dict, **sign_kwargs):
    body = json.dumps(payload).encode()
    return app.test_client().post("/billing/yoco/webhook", data=body, headers=sign(body, payload["id"], **sign_kwargs),
                                  content_type="application/json")


# --- signatures and money --------------------------------------------------------------------------

def test_webhook_signature_verification():
    body = b'{"id":"evt_1"}'
    headers = sign(body)
    assert billing.verify_webhook(SECRET, headers, body)
    assert not billing.verify_webhook(SECRET, headers, body + b" ")
    assert not billing.verify_webhook(SECRET, sign(body, timestamp=time.time() - 3600), body)
    assert not billing.verify_webhook("whsec_" + base64.b64encode(b"other").decode(), headers, body)
    assert not billing.verify_webhook("", headers, body)
    rotated = dict(headers, **{"webhook-signature": "v1,bm90LWl0 " + headers["webhook-signature"]})
    assert billing.verify_webhook(SECRET, rotated, body)


def test_vat_is_extracted_from_inclusive_prices():
    registered = Settings(vat_registered=True, vat_rate=15.0)
    assert billing.vat_split(11500, registered) == (10000, 1500)
    assert billing.vat_split(4900, registered) == (4261, 639)
    assert billing.vat_split(4900, Settings()) == (4900, 0)
    assert billing.money(123456) == "R1,234.56"


# --- fulfilment ------------------------------------------------------------------------------------

def test_paid_webhook_adds_credits_and_issues_one_invoice(app):
    setup_paid_site(app)
    conn, client, order = make_order(app)
    assert post_webhook(app, event(order)).status_code == 200
    assert post_webhook(app, event(order)).status_code == 200            # Yoco retry of the same event
    assert post_webhook(app, event(order, event_id="evt_2")).status_code == 200  # a different duplicate
    user = accounts.get_user_by_email(conn, "ann@example.com")
    assert user["credits"] == 2 + 5
    invoices = conn.execute("SELECT * FROM invoices").fetchall()
    assert [i["number"] for i in invoices] == ["INV-00001"]
    data = json.loads(invoices[0]["data_json"])
    assert data["seller"]["name"] == "EasyMikroTik (Pty) Ltd" and data["title"] == "Invoice" and data["vat_cents"] == 0
    page = client.get("/app/invoices/INV-00001").get_data(as_text=True)
    assert "INVOICE" in page and "R199.00" in page and "PAID" in page


def test_bad_signature_and_wrong_amount_are_rejected(app):
    setup_paid_site(app)
    conn, _, order = make_order(app)
    body = json.dumps(event(order)).encode()
    forged = app.test_client().post("/billing/yoco/webhook", data=body, content_type="application/json",
                                    headers=sign(body, secret="whsec_" + base64.b64encode(b"guess").decode()))
    assert forged.status_code == 403
    assert post_webhook(app, event(order, amount=200)).status_code == 200
    assert conn.execute("SELECT status FROM orders").fetchone()[0] == "pending"
    assert accounts.get_user_by_email(conn, "ann@example.com")["credits"] == 2


def test_failed_payment_marks_order_failed(app):
    setup_paid_site(app)
    conn, _, order = make_order(app)
    post_webhook(app, event(order, kind="payment.failed"))
    assert conn.execute("SELECT status FROM orders").fetchone()[0] == "failed"


def test_plan_purchase_and_renewal(app):
    setup_paid_site(app)
    conn, _, order = make_order(app, product_id="plan-1")
    post_webhook(app, event(order))
    user = accounts.get_user_by_email(conn, "ann@example.com")
    status = accounts.plan_status(user)
    assert status["active"] and status["scans_left"] == 50 and status["days_left"] in (29, 30)
    renewal = billing.create_order(conn, user["id"], app.extensions["grader"].store.current.product("plan-1"))
    billing.fulfil_order(conn, app.extensions["grader"].store.current, renewal["id"], payment_id="pay_2")
    status = accounts.plan_status(accounts.get_user(conn, user["id"]))
    assert status["scans_left"] == 100 and status["days_left"] in (59, 60)


def test_vat_invoice_and_test_mode_numbering(app):
    setup_paid_site(app, vat_registered=True, vat_number="4123456789")
    conn, client, order = make_order(app)
    post_webhook(app, event(order, mode="test"))
    invoice = conn.execute("SELECT * FROM invoices").fetchone()
    data = json.loads(invoice["data_json"])
    assert invoice["number"] == "TEST-INV-00001" and data["title"] == "Tax invoice" and data["vat_cents"] == 2596
    page = client.get(f"/app/invoices/{invoice['number']}").get_data(as_text=True)
    assert "TAX INVOICE" in page and "4123456789" in page and "Test payment" in page


def test_checkout_redirects_to_yoco_and_webhook_completes_it(app, monkeypatch):
    setup_paid_site(app)
    calls = []

    def fake_yoco(method, path, secret_key, payload=None, idempotency_key=""):
        calls.append((method, path, payload, idempotency_key))
        return {"id": "ch_live_9", "redirectUrl": "https://c.yoco.com/checkout/ch_live_9", "processingMode": "live"}

    monkeypatch.setattr(billing, "_yoco", fake_yoco)
    client = app.test_client()
    signup(client)
    response = client.post("/app/buy/pack-3", data={"csrf": csrf_from(client, "/app/buy")})
    assert response.location == "https://c.yoco.com/checkout/ch_live_9"
    method, path, payload, key = calls[0]
    assert (method, path, payload["amount"], payload["currency"]) == ("POST", "/checkouts", 59900, "ZAR")
    assert payload["successUrl"].startswith("http://localhost/app/payment/") and key.startswith("order-")
    conn = connect(app.config["DB_PATH"])
    order = conn.execute("SELECT * FROM orders").fetchone()
    assert order["checkout_id"] == "ch_live_9"
    pending = client.get(f"/app/payment/{order['ref']}?result=success").get_data(as_text=True)
    assert "Confirming your payment" in pending and 'http-equiv="refresh"' in pending
    post_webhook(app, event(order))
    done = client.get(f"/app/payment/{order['ref']}?result=success").get_data(as_text=True)
    assert "Payment received" in done and "INV-00001" in done


def test_buying_without_yoco_configured_explains(app):
    client = app.test_client()
    signup(client)
    response = client.post("/app/buy/pack-1", data={"csrf": csrf_from(client, "/app/buy")}, follow_redirects=True)
    assert "switched on yet" in response.get_data(as_text=True)


def test_customers_cannot_see_each_others_invoices(app):
    setup_paid_site(app)
    _, _, order = make_order(app)
    post_webhook(app, event(order))
    other = app.test_client()
    signup(other, email="eve@example.com")
    assert other.get("/app/invoices/INV-00001").status_code == 404
