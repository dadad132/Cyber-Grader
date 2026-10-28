"""Monthly accounts ("pay after use"): a fixed monthly fee paid up front, checks billed at the end of each month.

The first month's fee is paid through Yoco before the account opens, which shows the customer is real. Each check
run on the account is recorded with its price. On the billing day the month's checks and next month's fee go on
one bill. If a bill isn't paid within the grace period the account is on hold: checks on it are refused until the
bill is paid (credits and plans still work). A monthly limit caps what anyone can run up before paying.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timedelta

from flask import render_template

from .accounts import next_bill_date, open_account  # noqa: F401 (open_account is part of this module's API)
from .billing import money
from .db import iso, parse_iso, transaction, utcnow
from .settings import Settings

MAX_CATCH_UP = 12  # months billed in one go if the daily job hasn't run for a while


def span(start: datetime | None, end: datetime | None) -> str:
    if not start or not end:
        return ""
    return f"{start:%d %b} - {end:%d %b %Y}" if start.year == end.year else f"{start:%d %b %Y} - {end:%d %b %Y}"


def set_closing(conn: sqlite3.Connection, user_id: int, closing: bool) -> bool:
    """Close the account on its next billing day (after a final bill), or undo that. Returns whether it changed."""
    old, new = ("active", "closing") if closing else ("closing", "active")
    return bool(conn.execute("UPDATE users SET account_status = ? WHERE id = ? AND account_status = ?",
                             (new, user_id, old)).rowcount)


def unbilled(conn: sqlite3.Connection, user_id: int) -> tuple[int, int]:
    """(checks, cents) used on the account and not billed yet."""
    row = conn.execute("SELECT COUNT(*), COALESCE(SUM(charge_cents), 0) FROM scans "
                       "WHERE user_id = ? AND paid_with = 'account' AND bill_order_id IS NULL", (user_id,)).fetchone()
    return row[0], row[1]


def unpaid_bills(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM orders WHERE user_id = ? AND product_kind = 'bill' AND status != 'paid' "
                        "ORDER BY id", (user_id,)).fetchall()


def summary(conn: sqlite3.Connection, settings: Settings, user: sqlite3.Row, now: datetime | None = None) -> dict:
    """Everything the pages need to show about a customer's monthly account."""
    now = now or utcnow()
    checks, owed = unbilled(conn, user["id"])
    bills = unpaid_bills(conn, user["id"])
    overdue = next((bill for bill in bills if parse_iso(bill["due_at"]) <= now), None)
    is_open = user["account_status"] in ("active", "closing")
    limit = settings.account_max_checks
    limit_reached = bool(limit) and checks >= limit
    return {
        "status": user["account_status"],
        "open": is_open,
        "closing": user["account_status"] == "closing",
        "period_start": parse_iso(user["account_period_start"]),
        "period_end": parse_iso(user["account_period_end"]),
        "checks": checks,
        "owed_cents": owed,
        "limit": limit,
        "limit_reached": limit_reached,
        "bills": bills,
        "overdue": overdue,
        "on_hold": overdue is not None,
        "usable": is_open and overdue is None and not limit_reached,
    }


def issue_bills(conn: sqlite3.Connection, settings: Settings, now: datetime | None = None,
                user_id: int | None = None) -> list[sqlite3.Row]:
    """Bill every monthly account whose billing day has come (or just one). Returns the new bills."""
    now = now or utcnow()
    sql = "SELECT id FROM users WHERE account_status IN ('active', 'closing') AND account_period_end <= ?"
    params: tuple = (iso(now),)
    if user_id is not None:
        sql, params = sql + " AND id = ?", (*params, user_id)
    bills = []
    for (uid,) in conn.execute(sql, params).fetchall():
        for _ in range(MAX_CATCH_UP):
            with transaction(conn):
                # Read again inside the write lock, so two runs can't bill the same month twice.
                user = conn.execute("SELECT * FROM users WHERE id = ? AND account_status IN ('active', 'closing') "
                                    "AND account_period_end <= ?", (uid, iso(now))).fetchone()
                if user is None:
                    break
                bill = _bill_month(conn, settings, user, now)
            if bill is not None:
                bills.append(bill)
    return bills


def _bill_month(conn: sqlite3.Connection, settings: Settings, user: sqlite3.Row, now: datetime) -> sqlite3.Row | None:
    start, end = parse_iso(user["account_period_start"]), parse_iso(user["account_period_end"])
    closing = user["account_status"] == "closing"
    lines = []
    for price, count in conn.execute(
            "SELECT charge_cents, COUNT(*) FROM scans WHERE user_id = ? AND paid_with = 'account' AND bill_order_id IS NULL "
            "AND created_at <= ? GROUP BY charge_cents ORDER BY charge_cents", (user["id"], iso(end))).fetchall():
        lines.append({"description": f"Domain checks, {span(start, end)} ({money(price)} each)", "quantity": count,
                      "amount_cents": price * count})
    next_end = next_bill_date(end)
    if closing:
        conn.execute("UPDATE users SET account_status = 'closed' WHERE id = ?", (user["id"],))
    else:
        lines.append({"description": f"{settings.account_name} fee, {span(end, next_end)}", "quantity": 1,
                      "amount_cents": settings.account_fee_cents})
        conn.execute("UPDATE users SET account_period_start = ?, account_period_end = ? WHERE id = ?",
                     (iso(end), iso(next_end), user["id"]))
    total = sum(line["amount_cents"] for line in lines)
    if not total:
        return None  # a closing account that wasn't used
    ref = secrets.token_hex(8)
    conn.execute(
        "INSERT INTO orders (ref, user_id, product_kind, product_id, description, amount_cents, lines_json, due_at, created_at) "
        "VALUES (?, ?, 'bill', 'account', ?, ?, ?, ?, ?)",
        (ref, user["id"], f"{settings.account_name} bill, {span(start, end)}", total, json.dumps(lines),
         iso(now + timedelta(days=settings.account_grace_days)), iso(now)))
    bill = conn.execute("SELECT * FROM orders WHERE ref = ?", (ref,)).fetchone()
    conn.execute("UPDATE scans SET bill_order_id = ? WHERE user_id = ? AND paid_with = 'account' AND bill_order_id IS NULL "
                 "AND created_at <= ?", (bill["id"], user["id"], iso(end)))
    return bill


def bill_now(conn: sqlite3.Connection, settings: Settings, user_id: int) -> sqlite3.Row | None:
    """End the account's month now and bill it (super admin, e.g. to try the flow or settle up early)."""
    now = utcnow()
    conn.execute("UPDATE users SET account_period_end = ? WHERE id = ? AND account_status IN ('active', 'closing')",
                 (iso(now), user_id))
    bills = issue_bills(conn, settings, now, user_id)
    return bills[-1] if bills else None


def notices_due(conn: sqlite3.Connection, now: datetime | None = None) -> list[tuple[sqlite3.Row, str]]:
    """Unpaid bills that need an email now: 'issued' (the bill), 'reminder' (due within a day) or 'on-hold'."""
    now = now or utcnow()
    due = []
    for bill in conn.execute("SELECT o.*, u.email, u.name FROM orders o JOIN users u ON u.id = o.user_id "
                             "WHERE o.product_kind = 'bill' AND o.status != 'paid' AND u.disabled = 0 ORDER BY o.id").fetchall():
        due_at = parse_iso(bill["due_at"])
        if bill["notice"] is None:
            due.append((bill, "issued"))
        elif due_at <= now and bill["notice"] != "on-hold":
            due.append((bill, "on-hold"))
        elif due_at - now <= timedelta(days=1) and bill["notice"] == "issued":
            due.append((bill, "reminder"))
    return due


def bill_email(settings: Settings, bill: sqlite3.Row, stage: str, link: str) -> tuple[str, str]:
    """Subject and text of a bill email. Needs a Flask app context (for the template)."""
    due = parse_iso(bill["due_at"])
    subjects = {
        "issued": f"Your {settings.account_name.lower()} bill: {money(bill['amount_cents'])}, due {due:%d %b}",
        "reminder": f"Reminder: your bill of {money(bill['amount_cents'])} is due {due:%d %b}",
        "on-hold": f"Your {settings.account_name.lower()} is on hold: bill of {money(bill['amount_cents'])} unpaid",
    }
    text = render_template("email/bill.txt", bill=bill, lines=json.loads(bill["lines_json"]), stage=stage, due=due,
                           settings=settings, money=money, link=link)
    return subjects[stage], text
