"""Super-admin portal at /admin: go-live checklist, users, payments and invoices, Yoco, email, pricing, invoice
details, legal pages and the scanner's own settings.

On a server (GRADER_ADMIN_REMOTE=1) it's reachable over HTTPS and protected by the admin password, which is
set on the server with `python -m cybergrader.manage set-admin-password`. On a PC it only answers this computer,
and the first visit asks you to create the password.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from datetime import timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import accounts, billing, postpaid
from .accounts import AccountError
from .billing import BillingError
from .context import DEFAULT_USER_AGENT
from .db import iso, parse_iso, request_db, transaction, utcnow
from .mailer import MailError, send_later, send_mail
from .report import render_html
from .selfcheck import SystemCheck, run_selfcheck
from .service import GraderService, ScanRefused, check_domain_input
from .leads import STATUSES as LEAD_STATUSES
from .settings import (MAX_PACKS, MAX_PLANS, email_from_form, general_from_form, growth_from_form, invoices_from_form,
                       legal_from_form, payments_from_form)
from .security import csrf_ok

SELFCHECK_TTL = 300
ADMIN_SESSION_HOURS = 12
SECTIONS = (("general", "Website & scanning"), ("payments", "Payments & pricing"), ("growth", "Free checks, leads & SEO"),
            ("invoices", "Invoices & tax"), ("email", "Email"), ("legal", "Legal pages"), ("password", "Admin password"))
FORM_PARSERS = {"general": general_from_form, "payments": payments_from_form, "growth": growth_from_form,
                "invoices": invoices_from_form, "email": email_from_form, "legal": legal_from_form}


def _is_loopback(address: str | None) -> bool:
    try:
        return ipaddress.ip_address((address or "").split("%")[0]).is_loopback
    except ValueError:
        return False


def _remote_allowed() -> bool:
    return bool(os.environ.get("GRADER_ADMIN_REMOTE"))


def go_live_checklist(settings) -> list[SystemCheck]:
    """What still needs doing before customers can sign up and pay."""
    items = []
    if settings.site_url.startswith("https://"):
        items.append(SystemCheck("Website address", "ok", f"{settings.site_url}"))
    else:
        items.append(SystemCheck("Website address", "warn" if settings.site_url else "fail",
                                 f"Set to '{settings.site_url}'." if settings.site_url else "Not set.",
                                 "Enter the public https:// address under Website & scanning (the installer does this for you)."))
    items.append(SystemCheck("Business details", "ok" if settings.brand_name and settings.contact_email else "fail",
                             f"{settings.brand_name or 'No business name'} · {settings.contact_email or 'no contact email'}",
                             "" if settings.brand_name and settings.contact_email else "Add your business name and contact email under Website & scanning."))
    invoice_ok = settings.legal_name and settings.business_address
    items.append(SystemCheck(
        "Invoice details", "ok" if invoice_ok else "fail",
        (f"{settings.legal_name}, {'VAT registered (' + settings.vat_number + ')' if settings.vat_registered else 'not VAT registered'}"
         if invoice_ok else "Registered name or address missing."),
        "" if invoice_ok else "Fill in Invoices & tax so invoices show your legal details."))
    if not settings.charge_for_checks:
        items.append(SystemCheck("Charging", "warn", "Switched off: every check, full report and PDF is free.",
                                 "Tick Charge for checks under Payments & pricing when you're ready to take payments."))
    mode = settings.yoco_mode
    if not settings.yoco_secret_key:
        items.append(SystemCheck("Yoco payments", "fail", "No Yoco secret key yet.",
                                 "Copy the secret key from the Yoco app (Sales > Payment gateway) into Payments & pricing."))
    elif mode == "test":
        items.append(SystemCheck("Yoco payments", "warn", "Using a TEST key: payments are simulated and invoices are marked as tests.",
                                 "Switch to your live key once your domain is verified in the Yoco app, then register the webhook again."))
    else:
        items.append(SystemCheck("Yoco payments", "ok", f"Live key {settings.yoco_secret_key[:8]}…{settings.yoco_secret_key[-4:]}."))
    if not settings.yoco_webhook_secret:
        items.append(SystemCheck("Yoco webhook", "fail", "Not registered, so payments can't be confirmed automatically.",
                                 "Click 'Register webhook with Yoco' under Payments & pricing."))
    elif mode and settings.yoco_webhook_mode and settings.yoco_webhook_mode != mode:
        items.append(SystemCheck("Yoco webhook", "fail", f"Registered for {settings.yoco_webhook_mode} mode but the key is {mode}.",
                                 "Register the webhook again under Payments & pricing."))
    else:
        items.append(SystemCheck("Yoco webhook", "ok", f"Payments are confirmed at {settings.yoco_webhook_url or 'your webhook URL'}."))
    items.append(SystemCheck("Email", "ok" if settings.email_ready else "fail",
                             f"Sending as {settings.mail_from} via {settings.smtp_host}." if settings.email_ready else "Not set up.",
                             "" if settings.email_ready else "Add your SMTP details under Email so invoices and password resets go out."))
    if settings.google_site_verification:
        items.append(SystemCheck("Google Search Console", "ok", "Verification tag is on every page."))
    else:
        items.append(SystemCheck("Google Search Console", "warn", "Not verified yet, so you can't see searches or submit the sitemap.",
                                 "Add the site in Google Search Console (HTML tag method), paste the code under Free checks, leads & SEO, "
                                 "then submit /sitemap.xml there."))
    template_left = "[Template:" in settings.terms_text or "[Template:" in settings.privacy_text
    items.append(SystemCheck("Terms & privacy", "warn" if template_left else "ok",
                             "Still the starter templates." if template_left else "Customised.",
                             "Review both under Legal pages (ideally with your legal adviser) and remove the template notes." if template_left else ""))
    return items


def create_admin_blueprint(service: GraderService) -> Blueprint:
    bp = Blueprint("admin", __name__, url_prefix="/admin")
    store = service.store
    selfcheck_cache: dict = {"at": 0.0, "checks": []}

    def base_url() -> str:
        return store.current.site_url.rstrip("/") or request.host_url.rstrip("/")

    @bp.before_request
    def guard():
        if not (_remote_allowed() or _is_loopback(request.remote_addr)):
            abort(404)
        if request.method == "POST" and not csrf_ok(request.form):
            abort(400, description="Your session expired. Go back, reload the page and try again.")
        endpoint = request.endpoint or ""
        if not store.current.admin_password_hash:
            return None if endpoint == "admin.setup" else redirect(url_for("admin.setup"))
        if endpoint == "admin.setup":
            return redirect(url_for("admin.login"))
        signed_in_at = session.get("admin_at", 0)
        if session.get("admin") and time.time() - signed_in_at > ADMIN_SESSION_HOURS * 3600:
            session.pop("admin", None)
            flash("For safety, please sign in again.", "info")
        if endpoint != "admin.login" and not session.get("admin"):
            return redirect(url_for("admin.login"))
        return None

    def sign_in() -> None:
        session.pop("csrf", None)
        session["admin"] = True
        session["admin_at"] = time.time()
        session.permanent = True

    # --- sign-in -------------------------------------------------------------------------------

    @bp.route("/setup", methods=["GET", "POST"])
    def setup():
        if not _is_loopback(request.remote_addr):
            # On a server the password is set from the command line, so nobody can claim the portal first.
            return render_template("admin/auth.html", mode="remote-setup", path=str(store.path)), 403
        error = ""
        if request.method == "POST":
            password, confirm = request.form.get("password", ""), request.form.get("confirm", "")
            error = accounts.password_problem(password, confirm)
            if not error:
                store.update(admin_password_hash=generate_password_hash(password))
                sign_in()
                flash("Admin password created. Next, work through the go-live checklist.", "ok")
                return redirect(url_for("admin.dashboard"))
        return render_template("admin/auth.html", mode="setup", error=error, path=str(store.path))

    @bp.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            client = request.remote_addr or "unknown"
            if service.login_limiter.blocked(client):
                error = "Too many failed attempts. Wait 15 minutes and try again."
            elif check_password_hash(store.current.admin_password_hash, request.form.get("password", "")):
                sign_in()
                return redirect(url_for("admin.dashboard"))
            else:
                service.login_limiter.allow(client)
                error = "That password isn't right."
        return render_template("admin/auth.html", mode="login", error=error), (400 if error else 200)

    @bp.post("/logout")
    def logout():
        session.pop("admin", None)
        session.pop("admin_at", None)
        return redirect(url_for("admin.login"))

    # --- dashboard -----------------------------------------------------------------------------

    def runtime_checks() -> list[SystemCheck]:
        checks = []
        if _remote_allowed():
            secure = request.is_secure
            checks.append(SystemCheck("Admin access", "ok" if secure else "warn",
                                      "Reachable from anywhere over HTTPS, protected by your admin password." if secure
                                      else "Reachable from other computers WITHOUT HTTPS.",
                                      "" if secure else "Get a certificate (the installer runs certbot) before using the portal remotely."))
        else:
            checks.append(SystemCheck("Admin access", "ok", "The admin portal only accepts connections from this computer."))
        if request.environ.get("SERVER_SOFTWARE", "").startswith("Werkzeug"):
            checks.append(SystemCheck("Web server", "info", "Running on Flask's built-in server: fine for trying it out on this "
                                      "computer. Use install.sh on AlmaLinux for the real site."))
        return checks

    def system_checks(force: bool = False) -> list[SystemCheck]:
        if force or not selfcheck_cache["checks"] or time.monotonic() - selfcheck_cache["at"] > SELFCHECK_TTL:
            selfcheck_cache["checks"] = run_selfcheck(store.current, store.path.parent)
            selfcheck_cache["at"] = time.monotonic()
        return selfcheck_cache["checks"] + runtime_checks()

    @bp.get("/")
    def dashboard():
        conn = request_db()
        week, month = iso(utcnow() - timedelta(days=7)), iso(utcnow() - timedelta(days=30))
        stats = {
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "new_users": conn.execute("SELECT COUNT(*) FROM users WHERE created_at >= ?", (week,)).fetchone()[0],
            "scans": conn.execute("SELECT COUNT(*) FROM scans WHERE created_at >= ? AND user_id IS NOT NULL", (week,)).fetchone()[0],
            "revenue": conn.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM orders WHERE status = 'paid' "
                                    "AND COALESCE(mode, 'live') != 'test' AND paid_at >= ?", (month,)).fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM orders WHERE status = 'pending'").fetchone()[0],
            "free_checks": conn.execute("SELECT COUNT(*) FROM previews WHERE created_at >= ?", (week,)).fetchone()[0],
            "new_leads": conn.execute("SELECT COUNT(*) FROM leads WHERE status = 'new'").fetchone()[0],
            "overdue_bills": conn.execute("SELECT COUNT(*) FROM orders WHERE product_kind = 'bill' AND status != 'paid' "
                                          "AND due_at <= ?", (iso(utcnow()),)).fetchone()[0],
        }
        previews = conn.execute("SELECT token, domain, grade, score, unlocked_by, created_at FROM previews "
                                "ORDER BY created_at DESC LIMIT 10").fetchall()
        orders = conn.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id = o.user_id "
                              "ORDER BY o.id DESC LIMIT 8").fetchall()
        scans = conn.execute("SELECT s.id, s.domain, s.grade, s.score, s.paid_with, s.created_at, u.email FROM scans s "
                             "LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id DESC LIMIT 10").fetchall()
        return render_template("admin/dashboard.html", checklist=go_live_checklist(store.current), checks=system_checks(),
                               stats=stats, orders=orders, scans=scans, previews=previews, active="dashboard")

    @bp.post("/system-check")
    def refresh_checks():
        system_checks(force=True)
        flash("System check finished.", "ok")
        return redirect(url_for("admin.dashboard"))

    @bp.get("/test")
    def test():
        raw = request.args.get("domain", "").strip()
        if not raw:
            return redirect(url_for("admin.dashboard"))
        try:
            domain = check_domain_input(raw)
            report = service.scan(domain)
        except ScanRefused as exc:
            flash(f"{raw}: {exc}", "err")
            return redirect(url_for("admin.dashboard"))
        accounts.record_scan(request_db(), None, report, "admin")
        nav = f'<a href="{url_for("admin.dashboard")}">← Admin</a>'
        return render_html(report, branding=store.current.branding(), form_action=url_for("admin.test"), nav_html=nav)

    # --- users ---------------------------------------------------------------------------------

    @bp.get("/users")
    def users():
        query = request.args.get("q", "").strip()
        sql = ("SELECT u.*, (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scan_count, "
               "(SELECT COALESCE(SUM(amount_cents), 0) FROM orders o WHERE o.user_id = u.id AND o.status = 'paid') AS spent "
               "FROM users u")
        params: tuple = ()
        if query:
            sql += " WHERE u.email LIKE ? OR u.name LIKE ? OR u.company LIKE ?"
            params = (f"%{query}%",) * 3
        rows = request_db().execute(sql + " ORDER BY u.id DESC LIMIT 200", params).fetchall()
        return render_template("admin/users.html", users=rows, query=query, active="users")

    def load_user(user_id: int):
        user = accounts.get_user(request_db(), user_id)
        if user is None:
            abort(404)
        return user

    @bp.get("/users/<int:user_id>")
    def user_detail(user_id):
        user, conn = load_user(user_id), request_db()
        return render_template(
            "admin/user.html", user=user, plan=accounts.plan_status(user), active="users",
            scans=conn.execute("SELECT id, domain, grade, score, paid_with, created_at FROM scans WHERE user_id = ? "
                               "ORDER BY id DESC LIMIT 25", (user_id,)).fetchall(),
            orders=conn.execute("SELECT o.*, i.number AS invoice FROM orders o LEFT JOIN invoices i ON i.order_id = o.id "
                                "WHERE o.user_id = ? ORDER BY o.id DESC LIMIT 25", (user_id,)).fetchall(),
            ledger=conn.execute("SELECT * FROM ledger WHERE user_id = ? ORDER BY id DESC LIMIT 25", (user_id,)).fetchall(),
            audits=conn.execute("SELECT id, site_name, domain, grade, score, report_json, created_at FROM lan_audits "
                                "WHERE user_id = ? ORDER BY id DESC LIMIT 25", (user_id,)).fetchall(),
            clients=conn.execute("SELECT * FROM clients WHERE user_id = ? ORDER BY name COLLATE NOCASE", (user_id,)).fetchall(),
            plans=store.current.plans, account_info=postpaid.summary(conn, store.current, user))

    @bp.post("/users/<int:user_id>/credits")
    def user_credits(user_id):
        load_user(user_id)
        try:
            change = int(request.form.get("change", ""))
        except ValueError:
            flash("Enter a whole number of credits, e.g. 5 or -2.", "err")
        else:
            reason = request.form.get("reason", "").strip() or "Adjusted by support"
            try:
                balance = accounts.adjust_credits(request_db(), user_id, change, reason[:200])
            except AccountError as exc:
                flash(str(exc), "err")
            else:
                flash(f"Credits adjusted by {change:+d}; balance is now {balance}.", "ok")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    @bp.post("/users/<int:user_id>/plan")
    def user_plan(user_id):
        load_user(user_id)
        conn = request_db()
        if request.form.get("action") == "end":
            accounts.end_plan(conn, user_id)
            flash("Plan ended.", "ok")
        else:
            plan = store.current.product(request.form.get("plan_id", ""))
            if not plan or plan["kind"] != "plan":
                flash("Choose a plan.", "err")
            else:
                with transaction(conn):
                    accounts.apply_plan(conn, user_id, plan_id=plan["id"], plan_name=plan["name"], days=plan["days"],
                                        scans=plan["scans"] or None)
                flash(f"{plan['name']} plan granted for {plan['days']} days (no payment or invoice).", "ok")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    @bp.post("/users/<int:user_id>/account")
    def user_account(user_id):
        load_user(user_id)
        conn, settings, action = request_db(), store.current, request.form.get("action")
        name = settings.account_name
        if action == "open":
            with transaction(conn):
                accounts.open_account(conn, user_id)
            flash(f"{name} opened without payment (no invoice). It's billed monthly from today.", "ok")
        elif action in ("close", "keep"):
            with transaction(conn):
                changed = postpaid.set_closing(conn, user_id, action == "close")
            if changed:
                flash(f"{name} will close on its next billing day, after a final bill." if action == "close"
                      else f"{name} stays open.", "ok")
        elif action == "bill":
            bill = postpaid.bill_now(conn, settings, user_id)
            if bill is None:
                flash("Nothing to bill.", "info")
            else:
                if settings.email_ready:
                    owner = load_user(user_id)
                    subject, text = postpaid.bill_email(settings, bill, "issued", base_url() + url_for("site.bill", ref=bill["ref"]))
                    send_later(settings, owner["email"], subject, text)
                    conn.execute("UPDATE orders SET notice = 'issued' WHERE id = ?", (bill["id"],))
                flash(f"Bill of {billing.money(bill['amount_cents'])} issued{' and emailed' if settings.email_ready else ''}. "
                      f"It's due {parse_iso(bill['due_at']):%d %b %Y}.", "ok")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    @bp.post("/users/<int:user_id>/status")
    def user_status(user_id):
        user = load_user(user_id)
        request_db().execute("UPDATE users SET disabled = ? WHERE id = ?", (0 if user["disabled"] else 1, user_id))
        flash("Account enabled." if user["disabled"] else "Account disabled; they can no longer sign in.", "ok")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    @bp.post("/users/<int:user_id>/password")
    def user_password(user_id):
        load_user(user_id)
        try:
            accounts.set_password(request_db(), user_id, request.form.get("password", ""))
        except AccountError as exc:
            flash(str(exc), "err")
        else:
            flash("Password set. Give it to the customer securely and ask them to change it under Account.", "ok")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    # --- leads ---------------------------------------------------------------------------------

    @bp.get("/leads")
    def leads():
        status = request.args.get("status", "")
        sql, params = "SELECT * FROM leads", ()
        if status in LEAD_STATUSES:
            sql, params = sql + " WHERE status = ?", (status,)
        rows = request_db().execute(sql + " ORDER BY id DESC LIMIT 300", params).fetchall()
        return render_template("admin/leads.html", leads=rows, status=status, statuses=LEAD_STATUSES, active="leads")

    @bp.post("/leads/<int:lead_id>/status")
    def lead_status(lead_id):
        status = request.form.get("status", "")
        if status in LEAD_STATUSES:
            request_db().execute("UPDATE leads SET status = ? WHERE id = ?", (status, lead_id))
        return redirect(url_for("admin.leads", status=request.form.get("filter") or None))

    # --- payments ------------------------------------------------------------------------------

    @bp.get("/payments")
    def payments():
        status = request.args.get("status", "")
        sql = ("SELECT o.*, u.email, i.number AS invoice FROM orders o JOIN users u ON u.id = o.user_id "
               "LEFT JOIN invoices i ON i.order_id = o.id")
        params: tuple = ()
        if status in ("paid", "pending", "failed"):
            sql += " WHERE o.status = ?"
            params = (status,)
        rows = request_db().execute(sql + " ORDER BY o.id DESC LIMIT 300", params).fetchall()
        return render_template("admin/payments.html", orders=rows, status=status, active="payments")

    @bp.post("/orders/<int:order_id>/mark-paid")
    def mark_paid(order_id):
        conn = request_db()
        order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order is None:
            abort(404)
        reference = request.form.get("reference", "").strip()[:80]
        number = billing.fulfil_order(conn, store.current, order_id, payment_id=reference, paid_by="admin")
        if number:
            flash(f"Order {order['ref']} marked as paid and invoice {number} issued.", "ok")
        else:
            flash("That order was already paid.", "info")
        return redirect(url_for("admin.payments"))

    @bp.get("/invoices/<number>")
    def invoice(number):
        row = request_db().execute("SELECT * FROM invoices WHERE number = ?", (number,)).fetchone()
        if row is None:
            abort(404)
        return render_template("invoice.html", invoice=row, data=json.loads(row["data_json"]),
                               back=url_for("admin.payments"), layout="admin/base.html")

    # --- settings ------------------------------------------------------------------------------

    def render_settings(section: str, values, status: int = 200):
        webhook_url = (values.site_url.rstrip("/") + url_for("site.yoco_webhook")) if values.site_url else ""
        return render_template("admin/settings.html", section=section, sections=SECTIONS, values=values,
                               webhook_url=webhook_url, default_user_agent=DEFAULT_USER_AGENT,
                               max_packs=MAX_PACKS, max_plans=MAX_PLANS, active="settings"), status

    @bp.get("/settings")
    def settings_home():
        return redirect(url_for("admin.settings_page", section="general"))

    @bp.route("/settings/<section>", methods=["GET", "POST"])
    def settings_page(section):
        if section not in dict(SECTIONS):
            abort(404)
        if request.method == "GET" or section == "password":
            return render_settings(section, store.current)
        updated, errors = FORM_PARSERS[section](store.current, request.form)
        if errors:
            for error in errors:
                flash(error, "err")
            return render_settings(section, updated, 400)
        store.save(updated)
        selfcheck_cache["at"] = 0.0
        flash("Settings saved.", "ok")
        return redirect(url_for("admin.settings_page", section=section))

    @bp.post("/yoco/register-webhook")
    def register_webhook():
        settings = store.current
        if not settings.site_url.startswith("https://"):
            flash("Set the website address (https://…) under Website & scanning first; Yoco needs a public HTTPS URL.", "err")
            return redirect(url_for("admin.settings_page", section="payments"))
        url = settings.site_url.rstrip("/") + url_for("site.yoco_webhook")
        if settings.yoco_webhook_id:
            try:
                billing.delete_webhook(settings, settings.yoco_webhook_id)
            except BillingError:
                pass  # it may already be gone, or belong to the other key mode
        try:
            webhook = billing.register_webhook(settings, url)
        except BillingError as exc:
            flash(f"Yoco didn't accept the webhook: {exc}", "err")
        else:
            store.update(yoco_webhook_id=webhook.get("id", ""), yoco_webhook_secret=webhook.get("secret", ""),
                         yoco_webhook_url=url, yoco_webhook_mode=webhook.get("mode", settings.yoco_mode))
            flash(f"Webhook registered with Yoco ({webhook.get('mode', 'unknown')} mode). Payments will now be confirmed automatically.", "ok")
        return redirect(url_for("admin.settings_page", section="payments"))

    @bp.post("/email/test")
    def test_email():
        to = request.form.get("to", "").strip() or store.current.contact_email
        settings = store.current
        try:
            send_mail(settings, to, f"Test email from {settings.business_name}",
                      "This is a test from your Cyber Hygiene Grader admin portal. Email is working.")
        except MailError as exc:
            flash(str(exc), "err")
        else:
            flash(f"Test email sent to {to}. Check the inbox (and spam folder).", "ok")
        return redirect(url_for("admin.settings_page", section="email"))

    @bp.post("/password")
    def change_password():
        form = request.form
        if not check_password_hash(store.current.admin_password_hash, form.get("current", "")):
            flash("The current password isn't right.", "err")
        elif problem := accounts.password_problem(form.get("password", ""), form.get("confirm", "")):
            flash(problem, "err")
        else:
            store.update(admin_password_hash=generate_password_hash(form["password"]))
            flash("Admin password changed.", "ok")
        return redirect(url_for("admin.settings_page", section="password"))

    @bp.app_template_filter("ago")
    def ago(value):
        moment = parse_iso(value)
        if not moment:
            return ""
        seconds = (utcnow() - moment).total_seconds()
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if seconds >= size:
                return f"{int(seconds // size)}{unit} ago"
        return "just now"

    return bp
