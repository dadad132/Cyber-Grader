"""IT firms managing their clients' domains.

A firm keeps a client list. Each client approves the firm by clicking a link emailed to an address at their
own domain (which proves they control it). Approved clients' reports say who authorised them, and the firm
can email them the PDF report with a message and a quote, under the firm's own name. Clients can revoke
access at any time with the same link.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from . import accounts
from .billing import money
from .db import iso, parse_iso, request_db, utcnow
from .mailer import MailError, send_later, send_mail
from .pdf import PdfUnavailable, report_pdf
from .preview import owner_email
from .security import csrf_ok
from .service import GraderService, RateLimiter
from .target import normalize_domain

APPROVAL_DAYS = 14
SENDS_PER_CLIENT_PER_DAY = 5


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def firm_name(row) -> str:
    return row["firm_name"] or row["company"] or row["name"]


def client_for_domain(conn: sqlite3.Connection, user_id: int, domain: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM clients WHERE user_id = ? AND domain = ?", (user_id, domain)).fetchone()


def create_clients_blueprint(service: GraderService) -> Blueprint:
    bp = Blueprint("clients", __name__)
    store = service.store
    approval_limiter = RateLimiter(3, 86400)  # approval emails per client per day
    send_limiter = RateLimiter(30, 86400)     # client emails per firm per day

    def base_url() -> str:
        return store.current.site_url.rstrip("/") or request.host_url.rstrip("/")

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("site.login", next=request.path if request.method == "GET" else None))
            return view(*args, **kwargs)
        return wrapped

    @bp.before_request
    def check_csrf():
        if request.method == "POST" and not csrf_ok(request.form):
            abort(400, description="Your session expired. Go back, reload the page and try again.")

    def own_client(client_id: int) -> sqlite3.Row:
        row = request_db().execute("SELECT * FROM clients WHERE id = ? AND user_id = ?", (client_id, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        return row

    def send_approval(client: sqlite3.Row) -> bool:
        settings = store.current
        if not settings.email_ready:
            flash("Email isn't set up on this site yet, so approval requests can't be sent. Please contact us.", "err")
            return False
        if not approval_limiter.allow(f"client:{client['id']}"):
            flash("Approval was requested several times today already. Please wait until tomorrow.", "err")
            return False
        token = secrets.token_urlsafe(24)
        firm = firm_name(g.user)
        branding = accounts.firm_branding(g.user)
        try:
            send_mail(settings, client["contact_email"], f"{firm} would like to manage security checks for {client['domain']}",
                      render_template("email/client_approval.txt", client=client, firm=firm, branding=branding,
                                      link=f"{base_url()}{url_for('clients.approve', token=token)}", days=APPROVAL_DAYS,
                                      settings=settings),
                      from_name=f"{firm} via {settings.business_name}", reply_to=branding.email)
        except MailError:
            flash(f"We couldn't email {client['contact_email']}. Check the address and try again.", "err")
            return False
        request_db().execute("UPDATE clients SET approval_status = 'pending', approval_token_hash = ?, approval_sent_at = ? "
                             "WHERE id = ?", (_hash(token), iso(utcnow()), client["id"]))
        flash(f"Approval request emailed to {client['contact_email']}. You'll get an email when they respond.", "ok")
        return True

    # --- the firm's side -------------------------------------------------------------------------

    @bp.get("/app/clients")
    @login_required
    def index():
        rows = request_db().execute(
            "SELECT c.*, s.id AS scan_id, s.grade, s.score, s.created_at AS checked_at FROM clients c "
            "LEFT JOIN scans s ON s.id = (SELECT MAX(id) FROM scans WHERE user_id = c.user_id AND domain = c.domain) "
            "WHERE c.user_id = ? ORDER BY c.name COLLATE NOCASE", (g.user["id"],)).fetchall()
        return render_template("site/clients.html", clients=rows, active="clients")

    @bp.post("/app/clients")
    @login_required
    def add():
        form = request.form
        name = form.get("name", "").strip()
        try:
            domain = normalize_domain(form.get("domain", ""))
            contact = owner_email(form.get("contact_email", ""), domain)
        except ValueError as exc:
            flash(str(exc), "err")
            return redirect(url_for("clients.index"))
        if not name or len(name) > 100:
            flash("Enter the client's company name.", "err")
            return redirect(url_for("clients.index"))
        conn = request_db()
        try:
            client_id = conn.execute("INSERT INTO clients (user_id, domain, name, contact_email, created_at) VALUES (?, ?, ?, ?, ?)",
                                     (g.user["id"], domain, name, contact, iso(utcnow()))).lastrowid
        except sqlite3.IntegrityError:
            flash(f"{domain} is already in your client list.", "err")
            return redirect(url_for("clients.index"))
        if form.get("request_approval"):
            send_approval(conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone())
        else:
            flash(f"{name} added.", "ok")
        return redirect(url_for("clients.detail", client_id=client_id))

    @bp.get("/app/clients/<int:client_id>")
    @login_required
    def detail(client_id):
        client = own_client(client_id)
        conn = request_db()
        scans = conn.execute("SELECT id, grade, score, paid_with, created_at FROM scans WHERE user_id = ? AND domain = ? "
                             "ORDER BY id DESC LIMIT 50", (g.user["id"], client["domain"])).fetchall()
        messages = conn.execute("SELECT * FROM client_messages WHERE client_id = ? ORDER BY id DESC LIMIT 25",
                                (client_id,)).fetchall()
        latest = accounts.load_report(conn.execute("SELECT * FROM scans WHERE id = ?", (scans[0]["id"],)).fetchone()) if scans else None
        branding = accounts.firm_branding(g.user)
        default_message = ""
        if latest:
            top = ", ".join(r.title for r in latest.findings[:3])
            default_message = (f"Hi {client['name']},\n\nWe ran a security check on {client['domain']}. It scored {latest.score}/100 "
                               f"(grade {latest.grade}) with {len(latest.findings)} issue{'s' if len(latest.findings) != 1 else ''} to fix"
                               + (f", including {top}" if top else "") + ".\n\nThe full report is attached. We recommend fixing these "
                               f"soon; our quote is below. Reply to this email and we'll get started.\n\nKind regards,\n{branding.name}")
        pending_expired = (client["approval_status"] == "pending" and client["approval_sent_at"]
                           and parse_iso(client["approval_sent_at"]) < utcnow() - timedelta(days=APPROVAL_DAYS))
        return render_template("site/client.html", client=client, scans=scans, messages=messages, latest=latest,
                               default_message=default_message, branding=branding, pending_expired=pending_expired,
                               active="clients")

    @bp.post("/app/clients/<int:client_id>/edit")
    @login_required
    def edit(client_id):
        client = own_client(client_id)
        name = request.form.get("name", "").strip()
        notes = request.form.get("notes", "").strip()
        try:
            contact = owner_email(request.form.get("contact_email", ""), client["domain"])
        except ValueError as exc:
            flash(str(exc), "err")
            return redirect(url_for("clients.detail", client_id=client_id))
        if not name or len(name) > 100 or len(notes) > 2000:
            flash("Enter the client's name (and keep notes under 2000 characters).", "err")
            return redirect(url_for("clients.detail", client_id=client_id))
        request_db().execute("UPDATE clients SET name = ?, contact_email = ?, notes = ? WHERE id = ?",
                             (name, contact, notes, client_id))
        flash("Client details saved.", "ok")
        return redirect(url_for("clients.detail", client_id=client_id))

    @bp.post("/app/clients/<int:client_id>/delete")
    @login_required
    def delete(client_id):
        client = own_client(client_id)
        conn = request_db()
        conn.execute("DELETE FROM client_messages WHERE client_id = ?", (client_id,))
        conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        flash(f"{client['name']} removed from your clients. Their reports stay in your history.", "ok")
        return redirect(url_for("clients.index"))

    @bp.post("/app/clients/<int:client_id>/request-approval")
    @login_required
    def request_approval(client_id):
        client = own_client(client_id)
        if client["approval_status"] == "approved":
            flash("This client has already approved you.", "info")
        else:
            send_approval(client)
        return redirect(url_for("clients.detail", client_id=client_id))

    @bp.post("/app/clients/<int:client_id>/send")
    @login_required
    def send(client_id):
        client = own_client(client_id)
        settings = store.current
        form = request.form
        back = redirect(url_for("clients.detail", client_id=client_id) + "#send")
        if client["approval_status"] != "approved":
            flash(f"{client['name']} needs to approve you before you can email them reports.", "err")
            return back
        conn = request_db()
        scan = conn.execute("SELECT * FROM scans WHERE id = ? AND user_id = ? AND domain = ?",
                            (form.get("scan_id", type=int), g.user["id"], client["domain"])).fetchone()
        subject = form.get("subject", "").strip()
        message = form.get("message", "").strip().replace("\r\n", "\n")
        quote_text = form.get("quote_text", "").strip().replace("\r\n", "\n")
        raw_quote = form.get("quote_amount", "").replace("R", "").replace(" ", "").replace(",", "")
        try:
            quote_cents = int((Decimal(raw_quote) * 100).quantize(Decimal("1"))) if raw_quote else None
        except InvalidOperation:
            quote_cents = -1
        problem = ""
        if scan is None:
            problem = "Choose a report to send (run a check first if there isn't one)."
        elif not subject or len(subject) > 150:
            problem = "Enter a subject (up to 150 characters)."
        elif not message or len(message) > 4000:
            problem = "Write a message to your client (up to 4000 characters)."
        elif quote_cents is not None and not 0 < quote_cents <= 1_000_000_000:
            problem = "The quote must be an amount in rand, e.g. 4500.00."
        elif len(quote_text) > 2000:
            problem = "Keep the quote description under 2000 characters."
        elif not settings.email_ready:
            problem = "Email isn't set up on this site yet. Please contact us."
        if problem:
            flash(problem, "err")
            return back
        sent_today = conn.execute("SELECT COUNT(*) FROM client_messages WHERE client_id = ? AND sent_at >= ?",
                                  (client_id, iso(utcnow() - timedelta(days=1)))).fetchone()[0]
        if sent_today >= SENDS_PER_CLIENT_PER_DAY or not send_limiter.allow(f"user:{g.user['id']}"):
            flash("You've sent a lot of emails today. Please try again tomorrow.", "err")
            return back
        report = accounts.load_report(scan)
        branding = accounts.firm_branding(g.user)
        try:
            pdf = report_pdf(report, branding, recipient=client["name"], powered_by=settings.business_name,
                             authorised_by=client["approved_by"] or "")
        except PdfUnavailable as exc:
            flash(str(exc), "err")
            return back
        text = render_template("email/client_report.txt", client=client, report=report, message=message, branding=branding,
                               quote=money(quote_cents) if quote_cents else "", quote_text=quote_text, settings=settings)
        try:
            send_mail(settings, client["contact_email"], subject, text,
                      [(f"{client['domain']}-security-report.pdf", pdf, "application/pdf")],
                      from_name=f"{branding.name} via {settings.business_name}", reply_to=branding.email)
        except MailError:
            flash(f"We couldn't email {client['contact_email']}. Please try again later.", "err")
            return back
        conn.execute("INSERT INTO client_messages (client_id, scan_id, to_email, subject, message, quote_cents, quote_text, sent_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (client_id, scan["id"], client["contact_email"], subject, message, quote_cents, quote_text, iso(utcnow())))
        flash(f"Report{' and quote' if quote_cents else ''} sent to {client['contact_email']}. Replies come to {branding.email}.", "ok")
        return redirect(url_for("clients.detail", client_id=client_id))

    # --- the client's side (no account needed) ------------------------------------------------------

    @bp.route("/approve/<token>", methods=["GET", "POST"])
    def approve(token):
        conn = request_db()
        client = conn.execute(
            "SELECT c.*, u.name AS firm_user, u.company, u.firm_name, u.firm_email, u.email AS firm_login "
            "FROM clients c JOIN users u ON u.id = c.user_id WHERE c.approval_token_hash = ?", (_hash(token),)).fetchone()
        if client is None:
            return render_template("site/approve.html", client=None), 404
        firm = client["firm_name"] or client["company"] or client["firm_user"]
        expired = (client["approval_status"] == "pending"
                   and parse_iso(client["approval_sent_at"]) < utcnow() - timedelta(days=APPROVAL_DAYS))
        if request.method == "POST":
            action = request.form.get("action")
            status = client["approval_status"]
            new_status = None
            if action == "approve" and status in ("pending", "declined", "revoked") and not expired:
                new_status = "approved"
                conn.execute("UPDATE clients SET approval_status = 'approved', approved_by = ?, approved_at = ? WHERE id = ?",
                             (client["contact_email"], iso(utcnow()), client["id"]))
            elif action == "decline" and status == "pending":
                new_status = "declined"
            elif action == "revoke" and status == "approved":
                new_status = "revoked"
            if new_status in ("declined", "revoked"):
                conn.execute("UPDATE clients SET approval_status = ? WHERE id = ?", (new_status, client["id"]))
            if new_status:
                settings = store.current
                send_later(settings, client["firm_email"] or client["firm_login"],
                           f"{client['name']} has {new_status} your access to {client['domain']}",
                           render_template("email/client_decision.txt", client=client, status=new_status, settings=settings,
                                           link=f"{base_url()}{url_for('clients.detail', client_id=client['id'])}"))
                flash({"approved": f"Thank you. {firm} can now run checks for {client['domain']} and send you reports.",
                       "declined": f"Thank you. {firm} hasn't been given access.",
                       "revoked": f"Done. {firm} can no longer send you reports for {client['domain']}."}[new_status], "ok")
            return redirect(url_for("clients.approve", token=token))
        response = render_template("site/approve.html", client=client, firm=firm, expired=expired)
        return response, 200, {"X-Robots-Tag": "noindex"}

    return bp
