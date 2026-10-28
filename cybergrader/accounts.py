"""Customer accounts: sign-up, sign-in, credits, monthly plans, scan history, password resets and API keys."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from .db import iso, parse_iso, transaction, utcnow
from .models import Report

MIN_PASSWORD_LENGTH = 10
RESET_TOKEN_HOURS = 1
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Checked against when an email isn't registered, so sign-in takes the same time either way.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class AccountError(ValueError):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def password_problem(password: str, confirm: str | None = None) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use a password of at least {MIN_PASSWORD_LENGTH} characters."
    if confirm is not None and password != confirm:
        return "The two passwords don't match."
    return ""


def create_user(conn: sqlite3.Connection, *, email: str, name: str, password: str, company: str = "",
                signup_credits: int = 0) -> int:
    email, name, company = email.strip().lower(), name.strip(), company.strip()
    if not _EMAIL.match(email) or len(email) > 160:
        raise AccountError("Enter a valid email address.")
    if not name or len(name) > 100:
        raise AccountError("Enter your name.")
    if len(company) > 120:
        raise AccountError("Company name is too long.")
    problem = password_problem(password)
    if problem:
        raise AccountError(problem)
    with transaction(conn):
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise AccountError("An account with that email already exists. Sign in instead.")
        user_id = conn.execute(
            "INSERT INTO users (email, name, company, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, name, company, generate_password_hash(password), iso(utcnow())),
        ).lastrowid
        if signup_credits:
            _change_credits(conn, user_id, signup_credits, "Welcome credits")
    return user_id


def get_user(conn: sqlite3.Connection, user_id: int | None) -> sqlite3.Row | None:
    if not user_id:
        return None
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> sqlite3.Row | None:
    user = get_user_by_email(conn, email)
    if not check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password) or not user:
        return None
    if user["disabled"]:
        raise AccountError("This account has been disabled. Please contact us.")
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (iso(utcnow()), user["id"]))
    return user


def set_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    problem = password_problem(password)
    if problem:
        raise AccountError(problem)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), user_id))


def update_profile(conn: sqlite3.Connection, user_id: int, *, name: str, company: str, vat_number: str, address: str) -> None:
    name, company, vat_number, address = name.strip(), company.strip(), vat_number.strip(), address.strip()
    if not name or len(name) > 100:
        raise AccountError("Enter your name.")
    if len(company) > 120 or len(vat_number) > 20 or len(address) > 400:
        raise AccountError("One of the fields is too long.")
    conn.execute("UPDATE users SET name = ?, company = ?, vat_number = ?, address = ? WHERE id = ?",
                 (name, company, vat_number, address, user_id))


def update_firm_branding(conn: sqlite3.Connection, user_id: int, *, name: str, email: str, phone: str, url: str) -> None:
    """The business details an IT firm puts on reports it sends to its clients."""
    name, email, phone, url = name.strip(), email.strip().lower(), phone.strip(), url.strip()
    if len(name) > 100:
        raise AccountError("Business name is too long.")
    if email and not _EMAIL.match(email):
        raise AccountError("Enter a valid email address for your clients to reply to.")
    if phone and not re.fullmatch(r"[+0-9 ().-]{5,40}", phone):
        raise AccountError("Phone numbers may only contain digits, spaces, +, -, ( and ).")
    if url and not re.fullmatch(r"https?://[^\s/?#]+\.[^\s]*", url, re.I):
        raise AccountError("Website must start with https:// (or http://).")
    conn.execute("UPDATE users SET firm_name = ?, firm_email = ?, firm_phone = ?, firm_url = ? WHERE id = ?",
                 (name, email, phone, url, user_id))


def firm_branding(user: sqlite3.Row):
    """Branding for reports this customer sends to their clients (their own name, not ours)."""
    from .report import Branding

    return Branding(user["firm_name"] or user["company"] or user["name"], user["firm_url"],
                    user["firm_email"] or user["email"], user["firm_phone"], "Questions about this report? Get in touch.")


# --- credits and plans -----------------------------------------------------------------------------

def _change_credits(conn: sqlite3.Connection, user_id: int, change: int, reason: str) -> int:
    """Adjust the balance and log it. Call inside transaction()."""
    row = conn.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise AccountError("No such account.")
    balance = row["credits"] + change
    if balance < 0:
        raise AccountError(f"That would leave a negative balance ({balance}).")
    conn.execute("UPDATE users SET credits = ? WHERE id = ?", (balance, user_id))
    conn.execute("INSERT INTO ledger (user_id, change, balance, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                 (user_id, change, balance, reason, iso(utcnow())))
    return balance


def adjust_credits(conn: sqlite3.Connection, user_id: int, change: int, reason: str) -> int:
    with transaction(conn):
        return _change_credits(conn, user_id, change, reason)


def plan_status(user: sqlite3.Row) -> dict:
    expires = parse_iso(user["plan_expires_at"])
    active = bool(expires and expires > utcnow() and (user["plan_scans_left"] is None or user["plan_scans_left"] > 0))
    return {
        "active": active,
        "name": user["plan_name"],
        "expires_at": expires,
        "expired": bool(expires and expires <= utcnow()),
        "scans_left": user["plan_scans_left"],
        "unlimited": user["plan_scans_left"] is None,
        "days_left": max(0, (expires - utcnow()).days) if expires else 0,
    }


def apply_plan(conn: sqlite3.Connection, user_id: int, *, plan_id: str, plan_name: str, days: int,
               scans: int | None) -> None:
    """Start or extend a plan. Buying the same plan while it's active adds days and checks. Call inside transaction()."""
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    now = utcnow()
    expires = parse_iso(user["plan_expires_at"])
    if user["plan_id"] == plan_id and expires and expires > now:
        new_expiry = expires + timedelta(days=days)
        left = None if scans is None or user["plan_scans_left"] is None else user["plan_scans_left"] + scans
    else:
        new_expiry, left = now + timedelta(days=days), scans
    conn.execute("UPDATE users SET plan_id = ?, plan_name = ?, plan_expires_at = ?, plan_scans_left = ? WHERE id = ?",
                 (plan_id, plan_name, iso(new_expiry), left, user_id))


def end_plan(conn: sqlite3.Connection, user_id: int) -> None:
    now = iso(utcnow())  # ended on purpose, so no "your plan has ended" email
    conn.execute("UPDATE users SET plan_expires_at = ?, reminder_sent_for = ? WHERE id = ?", (now, f"{now}|ended", user_id))


BILL_DAY_MAX = 28  # every month has a 28th, so a monthly account's billing day never drifts


def next_bill_date(moment: datetime) -> datetime:
    """The same day next month (the 28th at the latest), e.g. 15 Oct -> 15 Nov, 31 Jan -> 28 Feb."""
    year, month = (moment.year + 1, 1) if moment.month == 12 else (moment.year, moment.month + 1)
    return moment.replace(year=year, month=month, day=min(moment.day, BILL_DAY_MAX))


def open_account(conn: sqlite3.Connection, user_id: int, now: datetime | None = None) -> None:
    """Open a monthly account (see postpaid.py) whose first month is paid for. Call inside transaction()."""
    now = now or utcnow()
    user = conn.execute("SELECT account_status FROM users WHERE id = ?", (user_id,)).fetchone()
    if user["account_status"] == "closing":  # paid again before it closed: just keep it open
        conn.execute("UPDATE users SET account_status = 'active' WHERE id = ?", (user_id,))
    elif user["account_status"] != "active":
        conn.execute("UPDATE users SET account_status = 'active', account_period_start = ?, account_period_end = ? "
                     "WHERE id = ?", (iso(now), iso(next_bill_date(now)), user_id))


def charge_for_scan(conn: sqlite3.Connection, user_id: int, domain: str, *, free: bool = False) -> str | None:
    """Take payment for one check: plan allowance first, then a credit. Returns 'plan', 'credit' or None.

    free=True (charging switched off under Settings > Payments) takes nothing and returns 'free'."""
    if free:
        return "free"
    now = iso(utcnow())
    with transaction(conn):
        unlimited = conn.execute(
            "SELECT 1 FROM users WHERE id = ? AND plan_expires_at > ? AND plan_scans_left IS NULL",
            (user_id, now)).fetchone()
        if unlimited:
            return "plan"
        used = conn.execute(
            "UPDATE users SET plan_scans_left = plan_scans_left - 1 "
            "WHERE id = ? AND plan_expires_at > ? AND plan_scans_left > 0", (user_id, now)).rowcount
        if used:
            return "plan"
        balance = conn.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()["credits"]
        if balance > 0:
            _change_credits(conn, user_id, -1, f"Check of {domain}")
            return "credit"
    return None


def refund_scan(conn: sqlite3.Connection, user_id: int, method: str, domain: str) -> None:
    with transaction(conn):
        if method == "credit":
            _change_credits(conn, user_id, 1, f"Refund: check of {domain} couldn't run")
        elif method == "plan":
            conn.execute("UPDATE users SET plan_scans_left = plan_scans_left + 1 "
                         "WHERE id = ? AND plan_scans_left IS NOT NULL", (user_id,))


def record_scan(conn: sqlite3.Connection, user_id: int | None, report: Report, paid_with: str,
                charge_cents: int | None = None) -> int:
    """Save a check. charge_cents is its price when it goes on a monthly account's bill."""
    return conn.execute(
        "INSERT INTO scans (user_id, domain, grade, score, paid_with, report_json, created_at, charge_cents) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, report.domain, report.grade, report.score, paid_with, json.dumps(report.to_dict()), iso(utcnow()),
         charge_cents),
    ).lastrowid


def recent_scan(conn: sqlite3.Connection, user_id: int, domain: str, minutes: int = 10) -> sqlite3.Row | None:
    since = iso(utcnow() - timedelta(minutes=minutes))
    return conn.execute("SELECT id, created_at FROM scans WHERE user_id = ? AND domain = ? AND created_at >= ? "
                        "ORDER BY id DESC LIMIT 1", (user_id, domain, since)).fetchone()


def load_report(row: sqlite3.Row) -> Report:
    return Report.from_dict(json.loads(row["report_json"]))


# --- password resets and API keys ------------------------------------------------------------------

def create_reset_token(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = iso(utcnow() + timedelta(hours=RESET_TOKEN_HOURS))
    conn.execute("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                 (_hash_token(token), user_id, expires))
    return token


def reset_token_user(conn: sqlite3.Connection, token: str) -> int | None:
    row = conn.execute("SELECT user_id FROM password_resets WHERE token_hash = ? AND used = 0 AND expires_at > ?",
                       (_hash_token(token), iso(utcnow()))).fetchone()
    return row["user_id"] if row else None


def use_reset_token(conn: sqlite3.Connection, token: str, password: str) -> int:
    with transaction(conn):
        user_id = reset_token_user(conn, token)
        if user_id is None:
            raise AccountError("That reset link has expired or was already used. Ask for a new one.")
        set_password(conn, user_id, password)
        conn.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (user_id,))
    return user_id


def new_api_key(conn: sqlite3.Connection, user_id: int) -> str:
    key = "cg_" + secrets.token_urlsafe(30)
    conn.execute("UPDATE users SET api_key_hash = ?, api_key_hint = ? WHERE id = ?",
                 (_hash_token(key), key[:7] + "…" + key[-4:], user_id))
    return key


def revoke_api_key(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET api_key_hash = NULL, api_key_hint = NULL WHERE id = ?", (user_id,))


def user_for_api_key(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    if not key.startswith("cg_"):
        return None
    user = conn.execute("SELECT * FROM users WHERE api_key_hash = ?", (_hash_token(key),)).fetchone()
    return user if user and not user["disabled"] else None
