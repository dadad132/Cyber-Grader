"""Sales leads: "have us fix it" requests and verified domain owners, with an email to your inbox."""
from __future__ import annotations

import re
import sqlite3

from flask import render_template

from .db import iso, utcnow
from .mailer import send_later
from .settings import Settings

STATUSES = ("new", "contacted", "won", "lost")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE = re.compile(r"^[+0-9 ().-]{5,40}$")


class LeadError(ValueError):
    pass


def clean_lead(form) -> dict:
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    phone = (form.get("phone") or "").strip()
    message = (form.get("message") or "").strip().replace("\r\n", "\n")
    if not name or len(name) > 100:
        raise LeadError("Please tell us your name.")
    if not _EMAIL.match(email) or len(email) > 160:
        raise LeadError("Please enter a valid email address so we can reply.")
    if phone and not _PHONE.match(phone):
        raise LeadError("Phone numbers may only contain digits, spaces, +, -, ( and ).")
    if len(message) > 2000:
        raise LeadError("Please keep the message under 2000 characters.")
    return {"name": name, "email": email, "phone": phone, "message": message}


def record_lead(conn: sqlite3.Connection, settings: Settings, *, domain: str, source: str, name: str, email: str,
                phone: str = "", message: str = "", grade: str = "", score: int | None = None, tier: str = "",
                user_id: int | None = None) -> int:
    lead_id = conn.execute(
        "INSERT INTO leads (user_id, domain, name, email, phone, message, grade, score, tier, source, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, domain, name, email, phone, message, grade, score, tier, source, iso(utcnow())),
    ).lastrowid
    if settings.lead_inbox:
        send_later(settings, settings.lead_inbox, f"New lead: {domain} ({source})", render_template(
            "email/lead.txt", domain=domain, source=source, name=name, email=email, phone=phone, message=message,
            grade=grade, score=score, tier=tier, settings=settings))
    return lead_id
