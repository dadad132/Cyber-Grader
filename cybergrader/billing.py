"""Payments through the Yoco Checkout API, order fulfilment and invoices.

Flow: create an order -> create a Yoco checkout -> send the customer to Yoco's payment page ->
Yoco calls our webhook (payment.succeeded) -> we add credits or a plan and issue an invoice.
Only the signed webhook (or a super admin) marks an order paid; the return URL is never trusted.
Yoco has no recurring billing, so plans are bought (and renewed) like any other product, and monthly accounts
get a bill each month that the customer pays the same way (see postpaid.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from decimal import ROUND_HALF_UP, Decimal

import requests

from .accounts import _change_credits, apply_plan, open_account
from .db import iso, next_number, transaction, utcnow
from .settings import Settings

log = logging.getLogger(__name__)

YOCO_API = os.environ.get("GRADER_YOCO_API", "https://payments.yoco.com/api")
WEBHOOK_TOLERANCE = 300  # seconds; Yoco suggests a few minutes to block replays


class BillingError(Exception):
    pass


def money(cents: int) -> str:
    return f"R{Decimal(cents) / 100:,.2f}"


def vat_split(total_cents: int, settings: Settings) -> tuple[int, int]:
    """(excl. VAT, VAT) for a VAT-inclusive total; VAT is 0 when the business isn't VAT registered."""
    if not settings.vat_registered or settings.vat_rate <= 0:
        return total_cents, 0
    rate = Decimal(str(settings.vat_rate))
    vat = int((Decimal(total_cents) * rate / (100 + rate)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    return total_cents - vat, vat


# --- Yoco API --------------------------------------------------------------------------------------

def _yoco(method: str, path: str, secret_key: str, payload: dict | None = None, idempotency_key: str = "") -> dict:
    headers = {"Authorization": f"Bearer {secret_key}", "Content-Type": "application/json"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    try:
        response = requests.request(method, f"{YOCO_API}{path}", json=payload, headers=headers, timeout=20)
    except requests.RequestException as exc:
        raise BillingError(f"Couldn't reach Yoco ({type(exc).__name__}). Please try again.") from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("message") or response.text[:200]
        except ValueError:
            detail = response.text[:200]
        raise BillingError(f"Yoco returned HTTP {response.status_code}: {detail}")
    return response.json() if response.content else {}


def register_webhook(settings: Settings, url: str) -> dict:
    """Registers url with Yoco and returns {'id', 'secret', 'mode', ...}. The secret is only shown once."""
    if not settings.yoco_secret_key:
        raise BillingError("Enter your Yoco secret key first.")
    return _yoco("POST", "/webhooks", settings.yoco_secret_key, {"name": "cyber-hygiene-grader", "url": url})


def delete_webhook(settings: Settings, webhook_id: str) -> None:
    _yoco("DELETE", f"/webhooks/{webhook_id}", settings.yoco_secret_key)


def verify_webhook(secret: str, headers, body: bytes, now: float | None = None) -> bool:
    """Standard Webhooks signature check, as documented by Yoco."""
    webhook_id = headers.get("webhook-id", "")
    timestamp = headers.get("webhook-timestamp", "")
    signatures = headers.get("webhook-signature", "")
    if not (secret and webhook_id and timestamp and signatures):
        return False
    try:
        sent = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - sent) > WEBHOOK_TOLERANCE:
        return False
    encoded = secret.split("_", 1)[1] if secret.startswith("whsec_") else secret
    try:
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError:
        return False
    signed = f"{webhook_id}.{timestamp}.".encode() + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
    for entry in signatures.split():
        _, _, signature = entry.partition(",")
        if signature and hmac.compare_digest(signature.encode(), expected):
            return True
    return False


# --- orders ----------------------------------------------------------------------------------------

def create_order(conn: sqlite3.Connection, user_id: int, product: dict) -> sqlite3.Row:
    if product["kind"] == "credits":
        description = f"{product['name']}: {product['credits']} domain check credit{'s' if product['credits'] != 1 else ''}"
        values = (product["credits"], None, 0)
    elif product["kind"] == "account":
        description = f"{product['name']}: first month's fee"
        values = (0, None, 0)
    else:
        scans = product["scans"] or None  # 0 means unlimited
        allowance = "unlimited checks" if scans is None else f"{scans} checks"
        description = f"{product['name']} plan: {allowance} for {product['days']} days"
        values = (0, scans, product["days"])
    ref = secrets.token_hex(8)
    conn.execute(
        "INSERT INTO orders (ref, user_id, product_kind, product_id, description, credits, plan_scans, plan_days, "
        "amount_cents, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ref, user_id, product["kind"], product["id"], description, *values, product["price_cents"], iso(utcnow())),
    )
    return conn.execute("SELECT * FROM orders WHERE ref = ?", (ref,)).fetchone()


def start_checkout(conn: sqlite3.Connection, settings: Settings, order: sqlite3.Row, base_url: str) -> str:
    """Create the Yoco checkout for an order and return the URL to send the customer to."""
    if not settings.yoco_secret_key:
        raise BillingError("Online payments aren't set up yet.")
    return_url = f"{base_url}/app/payment/{order['ref']}"
    _, vat = vat_split(order["amount_cents"], settings)
    pricing = {"price": order["amount_cents"]}
    payload = {
        "amount": order["amount_cents"],
        "currency": "ZAR",
        "successUrl": f"{return_url}?result=success",
        "cancelUrl": f"{return_url}?result=cancelled",
        "failureUrl": f"{return_url}?result=failed",
        "externalId": order["ref"],
        "clientReferenceId": str(order["user_id"]),
        "metadata": {"orderRef": order["ref"]},
        "lineItems": [{"displayName": order["description"][:100], "quantity": 1, "pricingDetails": pricing}],
    }
    if vat:  # display only; the amount already includes it
        payload["totalTaxAmount"] = pricing["taxAmount"] = vat
    checkout = _yoco("POST", "/checkouts", settings.yoco_secret_key, payload, idempotency_key=f"order-{order['ref']}")
    if not checkout.get("redirectUrl") or not checkout.get("id"):
        raise BillingError("Yoco didn't return a payment page.")
    conn.execute("UPDATE orders SET checkout_id = ?, mode = ? WHERE id = ?",
                 (checkout["id"], checkout.get("processingMode"), order["id"]))
    return checkout["redirectUrl"]


def fulfil_order(conn: sqlite3.Connection, settings: Settings, order_id: int, *, payment_id: str = "",
                 mode: str | None = None, paid_by: str = "yoco") -> str | None:
    """Mark an order paid, deliver what was bought and issue the invoice. Returns the invoice number,
    or None if the order was already paid (webhooks can arrive more than once)."""
    with transaction(conn):
        updated = conn.execute(
            "UPDATE orders SET status = 'paid', paid_at = ?, payment_id = ?, mode = COALESCE(?, mode), paid_by = ? "
            "WHERE id = ? AND status != 'paid'", (iso(utcnow()), payment_id or None, mode, paid_by, order_id)).rowcount
        if not updated:
            return None
        order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order["product_kind"] == "credits":
            _change_credits(conn, order["user_id"], order["credits"], f"Bought {order['description']} (order {order['ref']})")
        elif order["product_kind"] == "account":
            open_account(conn, order["user_id"])
        elif order["product_kind"] == "plan":
            plan_name = order["description"].rsplit(" plan: ", 1)[0]
            apply_plan(conn, order["user_id"], plan_id=order["product_id"], plan_name=plan_name,
                       days=order["plan_days"], scans=order["plan_scans"])
        return _create_invoice(conn, settings, order)


def _create_invoice(conn: sqlite3.Connection, settings: Settings, order: sqlite3.Row) -> str:
    user = conn.execute("SELECT * FROM users WHERE id = ?", (order["user_id"],)).fetchone()
    test = order["mode"] == "test"
    prefix = f"TEST-{settings.invoice_prefix}" if test else settings.invoice_prefix
    number = f"{prefix}-{next_number(conn, prefix):05d}"
    excl, vat = vat_split(order["amount_cents"], settings)
    data = {
        "title": "Tax invoice" if settings.vat_registered else "Invoice",
        "test": test,
        "seller": {
            "name": settings.legal_name or settings.business_name,
            "trading_as": settings.brand_name if settings.legal_name and settings.brand_name != settings.legal_name else "",
            "address": settings.business_address,
            "registration_number": settings.registration_number,
            "vat_number": settings.vat_number if settings.vat_registered else "",
            "email": settings.contact_email,
            "phone": settings.contact_phone,
            "website": settings.brand_url or settings.site_url,
        },
        "buyer": {"name": user["name"], "company": user["company"], "email": user["email"],
                  "address": user["address"], "vat_number": user["vat_number"]},
        "lines": (json.loads(order["lines_json"]) if order["lines_json"]
                  else [{"description": order["description"], "quantity": 1, "amount_cents": order["amount_cents"]}]),
        "excl_cents": excl,
        "vat_cents": vat,
        "vat_rate": settings.vat_rate if settings.vat_registered else 0,
        "total_cents": order["amount_cents"],
        "currency": order["currency"],
        "order_ref": order["ref"],
        "payment_ref": order["payment_id"] or "",
        "paid_by": order["paid_by"],
        "paid_at": order["paid_at"],
        "notes": settings.invoice_notes,
    }
    conn.execute("INSERT INTO invoices (number, order_id, user_id, issued_at, total_cents, data_json) VALUES (?, ?, ?, ?, ?, ?)",
                 (number, order["id"], order["user_id"], iso(utcnow()), order["amount_cents"], json.dumps(data)))
    return number


def handle_event(conn: sqlite3.Connection, settings: Settings, event: dict) -> str | None:
    """Process one verified Yoco webhook event. Returns an invoice number when an order was fulfilled."""
    event_id = str(event.get("id") or "")
    if event_id and conn.execute("SELECT 1 FROM webhook_events WHERE event_id = ?", (event_id,)).fetchone():
        return None  # a retry of an event we've already handled
    invoice = _process_event(conn, settings, event)
    if event_id:  # recorded only after success, so a failed attempt is processed again on Yoco's retry
        conn.execute("INSERT OR IGNORE INTO webhook_events (event_id, received_at) VALUES (?, ?)", (event_id, iso(utcnow())))
    return invoice


def _process_event(conn: sqlite3.Connection, settings: Settings, event: dict) -> str | None:
    event_id = event.get("id")
    payload = event.get("payload") or {}
    metadata = payload.get("metadata") or {}
    order = None
    if metadata.get("checkoutId"):
        order = conn.execute("SELECT * FROM orders WHERE checkout_id = ?", (metadata["checkoutId"],)).fetchone()
    if order is None and metadata.get("orderRef"):
        order = conn.execute("SELECT * FROM orders WHERE ref = ?", (metadata["orderRef"],)).fetchone()
    if order is None:
        log.warning("Yoco event %s doesn't match any order (metadata %s)", event_id, metadata)
        return None
    if event.get("type") == "payment.failed":
        # A declined card doesn't settle a monthly bill: it stays owed (and payable).
        conn.execute("UPDATE orders SET status = 'failed' WHERE id = ? AND status = 'pending' AND product_kind != 'bill'",
                     (order["id"],))
        return None
    if event.get("type") != "payment.succeeded":
        return None
    if payload.get("amount") != order["amount_cents"] or (payload.get("currency") or "ZAR") != order["currency"]:
        log.error("Yoco payment %s amount %s %s doesn't match order %s (%s)", payload.get("id"), payload.get("amount"),
                  payload.get("currency"), order["ref"], order["amount_cents"])
        return None
    return fulfil_order(conn, settings, order["id"], payment_id=str(payload.get("id") or ""), mode=payload.get("mode"))
