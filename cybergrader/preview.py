"""Free checks: anyone can check a domain and see its grade and score; the details unlock with a credit,
by proving they own the domain (a code sent to an @thatdomain mailbox), or for the super admin.

Hiding the details from anonymous visitors stops the site being used to scout other companies' weak spots,
and turns free checks into sign-ups and leads.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import timedelta

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup

from . import accounts
from .billing import money
from .db import iso, parse_iso, request_db, utcnow
from .leads import LeadError, clean_lead, record_lead
from .mailer import MailError, send_later, send_mail
from .models import Report
from .pdf import PdfUnavailable, report_pdf
from .report import VERDICTS, report_body
from .security import csrf_ok
from .service import GraderService, RateLimiter, ScanRefused, check_domain_input
from .site import NoCredits, run_paid_scan

REUSE_MINUTES = 60        # a recent check of the same domain is reused instead of re-scanning
UNLOCK_HOURS = 24         # older previews are re-checked when unlocked with a credit
CODE_MINUTES = 15
CODE_ATTEMPTS = 5
CODES_PER_PREVIEW_HOUR = 3
_MAILBOX = re.compile(r"^[a-z0-9._%+-]{1,64}$")


def owner_email(raw: str, domain: str) -> str:
    """An address at the checked domain (or its parent, for subdomains). Accepts 'info' or 'info@domain'."""
    text = (raw or "").strip().lower()
    local, at, host = text.rpartition("@")
    if not at:
        local, host = text, domain
    if not _MAILBOX.match(local):
        raise ValueError(f"Enter a mailbox at {domain}, e.g. info@{domain}.")
    if host != domain and not (domain.endswith("." + host) and "." in host):
        raise ValueError(f"For security, the code can only be sent to an address ending in @{domain}.")
    return f"{local}@{host}"


def _code_hash(token: str, code: str) -> str:
    return hashlib.sha256(f"{token}:{code}".encode()).hexdigest()


def summarise(data: dict) -> dict:
    """What an anonymous visitor may see: grade, score, areas and issue counts, but not which checks failed."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_area: dict[str, dict] = {}
    passed = 0
    for check in data["checks"]:
        if check["status"] in ("warn", "fail") and check["severity"] != "info":
            counts[check["severity"]] += 1
            area = by_area.setdefault(check["category"], {"count": 0, "worst": "low"})
            area["count"] += 1
            if list(counts).index(check["severity"]) < list(counts).index(area["worst"]):
                area["worst"] = check["severity"]
        elif check["status"] == "pass" and check["max_points"] > 0:
            passed += 1
    return {"counts": counts, "issues": sum(counts.values()), "by_area": by_area, "passed": passed}


def create_preview_blueprint(service: GraderService) -> Blueprint:
    bp = Blueprint("preview", __name__)
    store = service.store
    free_limiter = RateLimiter(store.current.free_checks_per_hour, 3600)
    code_limiter = RateLimiter(5, 3600)
    lead_limiter = RateLimiter(5, 3600)

    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def base_url() -> str:
        return store.current.site_url.rstrip("/") or request.host_url.rstrip("/")

    @bp.before_request
    def check_csrf():
        if request.method == "POST" and not csrf_ok(request.form):
            abort(400, description="Your session expired. Go back, reload the page and try again.")

    def load(token: str) -> sqlite3.Row:
        row = request_db().execute("SELECT * FROM previews WHERE token = ?", (token,)).fetchone()
        if row is None:
            abort(404)
        return row

    def can_see_all(row: sqlite3.Row) -> bool:
        return bool(row["unlocked_by"]) or bool(session.get("admin")) or not store.current.charge_for_checks

    @bp.post("/check")
    def check():
        settings = store.current
        raw = request.form.get("domain", "")
        back = request.form.get("back") or url_for("site.landing")
        if not settings.free_checks_enabled:
            return redirect(url_for("site.signup", next=url_for("site.dashboard", domain=raw)))
        try:
            domain = check_domain_input(raw)
        except ScanRefused as exc:
            flash(str(exc), "err")
            return redirect(back)
        conn = request_db()
        since = iso(utcnow() - timedelta(minutes=REUSE_MINUTES))
        recent = conn.execute("SELECT report_json FROM previews WHERE domain = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
                              (domain, since)).fetchone()
        if recent:
            data = json.loads(recent["report_json"])
        else:
            free_limiter.limit = settings.free_checks_per_hour
            if not free_limiter.allow(client_ip()):
                flash("You've used your free checks for now. Create a free account to keep going, or try again in an hour.", "err")
                return redirect(url_for("site.signup"))
            try:
                data = service.scan(domain).to_dict()
            except ScanRefused as exc:
                flash(f"{domain}: {exc}", "err")
                return redirect(back)
        token = secrets.token_urlsafe(16)
        conn.execute("INSERT INTO previews (token, domain, grade, score, report_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (token, domain, data["grade"], data["score"], json.dumps(data), iso(utcnow())))
        return redirect(url_for("preview.show", token=token))

    @bp.get("/check/<token>")
    def show(token):
        row = load(token)
        settings = store.current
        data = json.loads(row["report_json"])
        report = Report.from_dict(data)
        unlocked = can_see_all(row)
        body = Markup(report_body(report, settings.branding(), cta=False)) if unlocked else None
        latest_code = request_db().execute("SELECT email, expires_at FROM owner_codes WHERE token = ? ORDER BY id DESC LIMIT 1",
                                           (token,)).fetchone()
        code_pending = bool(latest_code and parse_iso(latest_code["expires_at"]) > utcnow())
        response = Response(render_template(
            "site/preview.html", row=row, report=report, summary=summarise(data), unlocked=unlocked, body=body,
            verdict=VERDICTS.get(report.grade, ""),
            tier=settings.fix_tier(report.grade, report.score), code_pending=code_pending,
            code_email=latest_code["email"] if code_pending else "", plan=accounts.plan_status(g.user) if g.user else None))
        response.headers["X-Robots-Tag"] = "noindex"  # results about other people's domains stay out of Google
        return response

    @bp.post("/check/<token>/unlock")
    def unlock(token):
        row = load(token)
        if g.user is None:
            return redirect(url_for("site.signup", next=url_for("preview.show", token=token)))
        conn = request_db()
        try:
            if parse_iso(row["created_at"]) < utcnow() - timedelta(hours=UNLOCK_HOURS):
                scan_id = run_paid_scan(conn, service, g.user, row["domain"])  # too old: check again
            else:
                method = accounts.charge_for_scan(conn, g.user["id"], row["domain"],
                                                  free=not store.current.charge_for_checks)
                if method is None:
                    raise NoCredits()
                scan_id = accounts.record_scan(conn, g.user["id"], Report.from_dict(json.loads(row["report_json"])), method)
        except NoCredits:
            flash("You're out of checks. Buy credits or a monthly plan to unlock full reports.", "err")
            return redirect(url_for("site.buy"))
        except ScanRefused as exc:
            flash(f"{row['domain']}: {exc} You haven't been charged.", "err")
            return redirect(url_for("preview.show", token=token))
        return redirect(url_for("site.scan_report", scan_id=scan_id))

    @bp.post("/check/<token>/owner")
    def send_code(token):
        row = load(token)
        settings = store.current
        target = url_for("preview.show", token=token) + "#owner"
        if not settings.owner_unlock_free:
            abort(404)
        try:
            email = owner_email(request.form.get("email", ""), row["domain"])
        except ValueError as exc:
            flash(str(exc), "err")
            return redirect(target)
        conn = request_db()
        sent_recently = conn.execute("SELECT COUNT(*) FROM owner_codes WHERE token = ? AND created_at >= ?",
                                     (token, iso(utcnow() - timedelta(hours=1)))).fetchone()[0]
        if sent_recently >= CODES_PER_PREVIEW_HOUR or not code_limiter.allow(client_ip()):
            flash("Too many codes requested. Please wait a while, or contact us.", "err")
            return redirect(target)
        if not settings.email_ready:
            flash("Email verification isn't available yet. Create a free account to unlock the report instead.", "err")
            return redirect(target)
        code = f"{secrets.randbelow(1_000_000):06d}"
        try:
            send_mail(settings, email, f"Your verification code for {row['domain']}", render_template(
                "email/owner_code.txt", code=code, domain=row["domain"], minutes=CODE_MINUTES, settings=settings))
        except MailError:
            flash(f"We couldn't send an email to {email}. Check the address and try again.", "err")
            return redirect(target)
        conn.execute("INSERT INTO owner_codes (token, email, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                     (token, email, _code_hash(token, code), iso(utcnow() + timedelta(minutes=CODE_MINUTES)), iso(utcnow())))
        flash(f"We've emailed a 6-digit code to {email}. It works for {CODE_MINUTES} minutes.", "ok")
        return redirect(target)

    @bp.post("/check/<token>/owner/verify")
    def verify_code(token):
        row = load(token)
        settings = store.current
        target = url_for("preview.show", token=token) + "#owner"
        conn = request_db()
        code_row = conn.execute("SELECT * FROM owner_codes WHERE token = ? ORDER BY id DESC LIMIT 1", (token,)).fetchone()
        if code_row is None or parse_iso(code_row["expires_at"]) <= utcnow() or code_row["attempts"] >= CODE_ATTEMPTS:
            flash("That code has expired or had too many attempts. Ask for a new one.", "err")
            return redirect(target)
        conn.execute("UPDATE owner_codes SET attempts = attempts + 1 WHERE id = ?", (code_row["id"],))
        supplied = re.sub(r"\D", "", request.form.get("code", ""))
        if not hmac.compare_digest(_code_hash(token, supplied), code_row["code_hash"]):
            left = CODE_ATTEMPTS - code_row["attempts"] - 1
            flash(f"That code isn't right. {left} attempt{'s' if left != 1 else ''} left.", "err")
            return redirect(target)
        conn.execute("UPDATE owner_codes SET expires_at = ? WHERE id = ?", (iso(utcnow()), code_row["id"]))
        conn.execute("UPDATE previews SET unlocked_by = ? WHERE token = ?", (code_row["email"], token))
        report = Report.from_dict(json.loads(row["report_json"]))
        record_lead(conn, settings, domain=row["domain"], source="owner", name=code_row["email"].split("@")[0],
                    email=code_row["email"], grade=report.grade, score=report.score,
                    tier=settings.fix_tier(report.grade, report.score)["name"])
        attachments = []
        try:
            attachments.append((f"{row['domain']}-domain-health.pdf", report_pdf(report, settings.branding(),
                                                                                  recipient=code_row["email"]), "application/pdf"))
        except PdfUnavailable:
            pass
        send_later(settings, code_row["email"], f"Your domain health report for {row['domain']}", render_template(
            "email/owner_report.txt", report=report, link=base_url() + url_for("preview.show", token=token), settings=settings),
            attachments)
        flash("Thanks, you're verified. Here's your full report; we've emailed you a copy too.", "ok")
        return redirect(url_for("preview.show", token=token))

    @bp.post("/check/<token>/help")
    def request_help(token):
        row = load(token)
        settings = store.current
        try:
            lead = clean_lead(request.form)
        except LeadError as exc:
            flash(str(exc), "err")
            return redirect(url_for("preview.show", token=token) + "#help")
        if not lead_limiter.allow(client_ip()):
            flash("We've already received your request. We'll be in touch soon.", "info")
            return redirect(url_for("preview.show", token=token))
        tier = settings.fix_tier(row["grade"], row["score"])
        record_lead(request_db(), settings, domain=row["domain"], source="preview", grade=row["grade"], score=row["score"],
                    tier=tier["name"], user_id=g.user["id"] if g.user else None, **lead)
        flash(f"Thanks {lead['name']}! We'll contact you about fixing {row['domain']} shortly.", "ok")
        return redirect(url_for("preview.show", token=token))

    @bp.get("/check/<token>/pdf")
    def pdf(token):
        row = load(token)
        if not can_see_all(row):
            abort(403)
        report = Report.from_dict(json.loads(row["report_json"]))
        try:
            data = report_pdf(report, store.current.branding(), recipient=row["unlocked_by"] or "")
        except PdfUnavailable as exc:
            flash(str(exc), "err")
            return redirect(url_for("preview.show", token=token))
        return Response(data, mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{row["domain"]}-domain-health.pdf"'})

    @bp.app_template_global()
    def fix_price(tier: dict) -> str:
        return money(tier["price_cents"])

    return bp
