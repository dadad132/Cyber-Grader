"""Customer website: landing page, sign-up/sign-in, paid domain checks, buying credits/plans, invoices,
building network audits and the API."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Blueprint, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from markupsafe import Markup

from . import accounts, billing, external, lan, postpaid
from .accounts import AccountError, password_problem
from .billing import BillingError, money
from .db import iso, parse_iso, request_db, transaction, utcnow
from .leads import LeadError, clean_lead, record_lead
from .mailer import send_later
from .pdf import PdfUnavailable, report_pdf
from .report import render_html, report_body
from .security import csrf_ok, safe_next
from .service import GraderService, ScanRefused, check_domain_input
from .settings import Settings

log = logging.getLogger(__name__)
DUPLICATE_MINUTES = 10
NO_CSRF = {"site.yoco_webhook", "site.api_lan_audit"}  # called by Yoco / the on-site agent, not a browser form
AGENT_PATH = Path(__file__).resolve().parents[1] / "tools" / "lan_agent.py"
APP_PATH = Path(__file__).resolve().parents[1] / "tools" / "building-network-audit.apk"  # built from mobile_app/


class NoCredits(Exception):
    def __init__(self, message: str = "", bill_ref: str = "") -> None:
        super().__init__(message or "You're out of checks. Buy credits or a monthly plan to keep going.")
        self.bill_ref = bill_ref  # set when an unpaid monthly bill is what's in the way


def _password_marker(user: sqlite3.Row) -> str:
    # Changes whenever the password does, which signs out every other session.
    return hashlib.sha256(user["password_hash"].encode()).hexdigest()[:16]


def sign_in_customer(user: sqlite3.Row) -> None:
    session.pop("csrf", None)
    session["user_id"] = user["id"]
    session["user_pw"] = _password_marker(user)
    session.permanent = True


def product_cards(settings: Settings) -> dict:
    packs = []
    for pack in settings.credit_packs:
        each = money(round(pack["price_cents"] / pack["credits"])) if pack["credits"] > 1 else ""
        packs.append({**pack, "price": money(pack["price_cents"]), "each": each})
    plans = []
    for plan in settings.plans:
        allowance = "Unlimited checks" if not plan["scans"] else f"{plan['scans']} checks"
        plans.append({**plan, "price": money(plan["price_cents"]), "allowance": allowance})
    account = None
    if settings.account_enabled:
        account = {**settings.product("account"), "price": money(settings.account_fee_cents),
                   "per_check": money(settings.account_check_cents), "limit": settings.account_max_checks,
                   "grace_days": settings.account_grace_days}
    return {"packs": packs, "plans": plans, "account": account}


def charge_check(conn: sqlite3.Connection, settings: Settings, user: sqlite3.Row, domain: str) -> tuple[str, int | None]:
    """Pay for one check: plan allowance, then a credit, then the monthly account (billed later).
    Returns (how it was paid, price on the monthly bill) or raises NoCredits saying why it can't be paid."""
    method = accounts.charge_for_scan(conn, user["id"], domain, free=not settings.charge_for_checks)
    if method:
        return method, None
    account = postpaid.summary(conn, settings, user)
    if account["usable"]:
        return "account", settings.account_check_cents
    name = settings.account_name.lower()
    if account["open"] and account["on_hold"]:
        bill = account["overdue"]
        raise NoCredits(f"Your {name} is on hold because the bill of {money(bill['amount_cents'])} due on "
                        f"{parse_iso(bill['due_at']):%d %b} hasn't been paid. Pay it to carry on checking.", bill["ref"])
    if account["open"] and account["limit_reached"]:
        raise NoCredits(f"You've used this month's {account['limit']} checks on your {name}. The limit resets on "
                        f"{account['period_end']:%d %b}; buy credits if you need more checks before then.")
    raise NoCredits()


def run_paid_scan(conn: sqlite3.Connection, service: GraderService, user: sqlite3.Row, domain: str) -> int:
    """Charge one check (see charge_check), run it, and refund if it can't run."""
    method, price = charge_check(conn, service.store.current, user, domain)
    try:
        report = service.scan(domain, client=f"user:{user['id']}")
    except BaseException:
        accounts.refund_scan(conn, user["id"], method, domain)  # nothing to undo for a monthly account
        raise
    return accounts.record_scan(conn, user["id"], report, method, price)


def create_site_blueprint(service: GraderService) -> Blueprint:
    bp = Blueprint("site", __name__)
    store = service.store

    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def base_url() -> str:
        return store.current.site_url.rstrip("/") or request.host_url.rstrip("/")

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                target = request.path + (f"?{request.query_string.decode()}" if request.query_string else "")
                return redirect(url_for("site.login", next=target if request.method == "GET" else None))
            return view(*args, **kwargs)
        return wrapped

    @bp.before_app_request
    def load_user():
        g.user = None
        user_id = session.get("user_id")
        if user_id:
            user = accounts.get_user(request_db(), user_id)
            if user is None or user["disabled"] or session.get("user_pw") != _password_marker(user):
                session.pop("user_id", None)
                session.pop("user_pw", None)
            else:
                g.user = user

    @bp.before_request
    def check_csrf():
        if request.method == "POST" and request.endpoint not in NO_CSRF and not csrf_ok(request.form):
            abort(400, description="Your session expired. Go back, reload the page and try again.")

    # --- public pages --------------------------------------------------------------------------

    @bp.get("/")
    def landing():
        if request.args.get("domain"):  # old shareable links: checks now need an account
            return redirect(url_for("site.dashboard", domain=request.args["domain"]))
        return render_template("site/landing.html", products=product_cards(store.current), active="home")

    @bp.get("/pricing")
    def pricing():
        return render_template("site/pricing.html", products=product_cards(store.current), active="pricing")

    @bp.get("/terms")
    def terms():
        return render_template("site/legal.html", title="Terms of service", text=store.current.terms_text)

    @bp.get("/privacy")
    def privacy():
        return render_template("site/legal.html", title="Privacy policy", text=store.current.privacy_text)

    # --- sign-up and sign-in -------------------------------------------------------------------

    @bp.route("/signup", methods=["GET", "POST"])
    def signup():
        if g.user is not None:
            return redirect(url_for("site.dashboard"))
        form, error = request.form, ""
        settings = store.current
        if request.method == "POST":
            if form.get("website"):  # honeypot field that people never see
                abort(400)
            if not form.get("terms"):
                error = "Please accept the terms of service to continue."
            elif not service.signup_limiter.allow(client_ip()):
                error = "Too many sign-ups from your network. Please try again later."
            else:
                conn = request_db()
                try:
                    user_id = accounts.create_user(conn, email=form.get("email", ""), name=form.get("name", ""),
                                                   password=form.get("password", ""), company=form.get("company", ""),
                                                   signup_credits=settings.signup_credits)
                except AccountError as exc:
                    error = str(exc)
                else:
                    user = accounts.get_user(conn, user_id)
                    sign_in_customer(user)
                    send_later(settings, user["email"], f"Welcome to {settings.business_name}", render_template(
                        "email/welcome.txt", user=user, settings=settings, link=base_url() + url_for("site.dashboard")))
                    if settings.signup_credits:
                        flash(f"Welcome, {user['name']}! You have {settings.signup_credits} free "
                              f"check{'s' if settings.signup_credits != 1 else ''} to start with.", "ok")
                    return redirect(safe_next(form.get("next"), url_for("site.dashboard")))
        return render_template("site/signup.html", error=error, form=form, next=request.values.get("next", "")), \
            (400 if error else 200)

    @bp.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("site.dashboard"))
        form, error = request.form, ""
        if request.method == "POST":
            ip = client_ip()
            if service.customer_login_limiter.blocked(ip):
                error = "Too many failed attempts. Please wait 15 minutes, or reset your password."
            else:
                try:
                    user = accounts.authenticate(request_db(), form.get("email", ""), form.get("password", ""))
                except AccountError as exc:
                    user, error = None, str(exc)
                if user is not None:
                    sign_in_customer(user)
                    return redirect(safe_next(form.get("next"), url_for("site.dashboard")))
                if not error:
                    service.customer_login_limiter.allow(ip)
                    error = "That email and password don't match an account."
        return render_template("site/login.html", error=error, form=form, next=request.values.get("next", "")), \
            (400 if error else 200)

    @bp.post("/logout")
    def logout():
        session.pop("user_id", None)
        session.pop("user_pw", None)
        return redirect(url_for("site.landing"))

    @bp.route("/forgot", methods=["GET", "POST"])
    def forgot():
        settings, sent, error = store.current, False, ""
        if request.method == "POST":
            if not service.reset_limiter.allow(client_ip()):
                error = "Too many requests. Please try again later."
            else:
                conn = request_db()
                user = accounts.get_user_by_email(conn, request.form.get("email", ""))
                if user and not user["disabled"] and settings.email_ready:
                    token = accounts.create_reset_token(conn, user["id"])
                    send_later(settings, user["email"], "Reset your password", render_template(
                        "email/reset.txt", user=user, settings=settings,
                        link=base_url() + url_for("site.reset", token=token)))
                sent = True  # same answer whether or not the email exists
        return render_template("site/forgot.html", sent=sent, error=error)

    @bp.route("/reset/<token>", methods=["GET", "POST"])
    def reset(token):
        conn, error = request_db(), ""
        if request.method == "POST":
            error = password_problem(request.form.get("password", ""), request.form.get("confirm", ""))
            if not error:
                try:
                    user_id = accounts.use_reset_token(conn, token, request.form["password"])
                except AccountError as exc:
                    error = str(exc)
                else:
                    sign_in_customer(accounts.get_user(conn, user_id))
                    flash("Your password has been changed.", "ok")
                    return redirect(url_for("site.dashboard"))
        valid = accounts.reset_token_user(conn, token) is not None
        return render_template("site/reset.html", valid=valid, error=error)

    # --- checks ----------------------------------------------------------------------------------

    def account_summary() -> dict:
        return postpaid.summary(request_db(), store.current, g.user)

    @bp.get("/app")
    @login_required
    def dashboard():
        scans = request_db().execute(
            "SELECT id, domain, grade, score, paid_with, created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 100",
            (g.user["id"],)).fetchall()
        audits = request_db().execute(
            "SELECT id, site_name, domain, grade, score, created_at FROM lan_audits WHERE user_id = ? ORDER BY id DESC LIMIT 20",
            (g.user["id"],)).fetchall()
        return render_template("site/dashboard.html", scans=scans, audits=audits, plan=accounts.plan_status(g.user),
                               account_info=account_summary(), prefill=request.args.get("domain", ""), active="dashboard")

    @bp.post("/app/scan")
    @login_required
    def scan():
        raw = request.form.get("domain", "")
        try:
            domain = check_domain_input(raw)
        except ScanRefused as exc:
            flash(str(exc), "err")
            return redirect(url_for("site.dashboard", domain=raw))
        conn = request_db()
        if not request.form.get("again"):
            recent = accounts.recent_scan(conn, g.user["id"], domain, DUPLICATE_MINUTES)
            if recent:
                flash(f"You checked {domain} a few minutes ago, so here's that report (no credit used). "
                      "Use “Check again” for a fresh check.", "info")
                return redirect(url_for("site.scan_report", scan_id=recent["id"]))
        try:
            scan_id = run_paid_scan(conn, service, g.user, domain)
        except NoCredits as exc:
            flash(str(exc), "err")
            return redirect(url_for("site.bill", ref=exc.bill_ref) if exc.bill_ref else url_for("site.buy"))
        except ScanRefused as exc:
            flash(f"{domain}: {exc} You haven't been charged.", "err")
            return redirect(url_for("site.dashboard", domain=raw))
        return redirect(url_for("site.scan_report", scan_id=scan_id))

    def own_scan(scan_id: int) -> sqlite3.Row:
        row = request_db().execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        return row

    @bp.get("/app/scans/<int:scan_id>")
    @login_required
    def scan_report(scan_id):
        row = own_scan(scan_id)
        report = accounts.load_report(row)
        body = Markup(report_body(report, store.current.branding(), cta=False))
        return render_template("site/report.html", report=report, body=body, scan=row, active="dashboard",
                               tier=store.current.fix_tier(report.grade, report.score), client=client_of(report.domain),
                               prepared_for=default_recipient(report.domain))

    def client_of(domain: str) -> sqlite3.Row | None:
        """The signed-in IT firm's client record for a domain, if they manage it."""
        return request_db().execute("SELECT * FROM clients WHERE user_id = ? AND domain = ?", (g.user["id"], domain)).fetchone()

    def default_recipient(domain: str) -> str:
        """Who a report's PDF says it's "Prepared for" unless the customer types something else."""
        client = client_of(domain)
        if g.user["firm_name"]:
            return client["name"] if client else ""
        return g.user["company"] or g.user["name"]

    @bp.get("/app/scans/<int:scan_id>/pdf")
    @login_required
    def report_pdf_download(scan_id):
        report = accounts.load_report(own_scan(scan_id))
        client = client_of(report.domain)
        settings = store.current
        if "prepared_for" in request.args:  # typed on the report page; blank leaves the line out (e.g. cold outreach)
            recipient = " ".join(request.args["prepared_for"].split())[:80]
        else:
            recipient = default_recipient(report.domain)
        try:
            if g.user["firm_name"]:  # IT firms get reports under their own name
                data = report_pdf(report, accounts.firm_branding(g.user), recipient=recipient,
                                  powered_by=settings.business_name,
                                  authorised_by=client["approved_by"] if client and client["approval_status"] == "approved" else "")
            else:
                data = report_pdf(report, settings.branding(), recipient=recipient)
        except PdfUnavailable as exc:
            flash(str(exc), "err")
            return redirect(url_for("site.scan_report", scan_id=scan_id))
        name = f"{report.domain}-domain-health-{report.scanned_at:%Y-%m-%d}.pdf"
        return Response(data, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @bp.post("/app/scans/<int:scan_id>/help")
    @login_required
    def request_fix(scan_id):
        report = accounts.load_report(own_scan(scan_id))
        form = {"name": g.user["name"], "email": g.user["email"], "phone": request.form.get("phone", ""),
                "message": request.form.get("message", "")}
        try:
            lead = clean_lead(form)
        except LeadError as exc:
            flash(str(exc), "err")
        else:
            settings = store.current
            record_lead(request_db(), settings, domain=report.domain, source="report", grade=report.grade,
                        score=report.score, tier=settings.fix_tier(report.grade, report.score)["name"],
                        user_id=g.user["id"], **lead)
            flash(f"Thanks! We'll contact you at {g.user['email']} about fixing {report.domain}.", "ok")
        return redirect(url_for("site.scan_report", scan_id=scan_id))

    @bp.get("/app/scans/<int:scan_id>/download")
    @login_required
    def download_report(scan_id):
        row = own_scan(scan_id)
        report = accounts.load_report(row)
        name = f"{report.domain}-{report.scanned_at:%Y-%m-%d}.html"
        return Response(render_html(report, branding=store.current.branding()), mimetype="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # --- buying ----------------------------------------------------------------------------------

    @bp.get("/app/buy")
    @login_required
    def buy():
        settings = store.current
        renew = settings.product(request.args.get("renew", ""))  # the link in plan reminder emails
        if renew and renew["kind"] == "plan":
            allowance = "unlimited checks" if not renew["scans"] else f"{renew['scans']} checks"
            renew = {**renew, "price": money(renew["price_cents"]), "allowance": allowance}
        else:
            renew = None
        return render_template("site/buy.html", products=product_cards(settings), plan=accounts.plan_status(g.user),
                               account_info=account_summary(), renew=renew, active="buy")

    @bp.post("/app/buy/<product_id>")
    @login_required
    def checkout(product_id):
        settings = store.current
        product = settings.product(product_id)
        if product is None:
            abort(404)
        if not settings.payments_ready:
            flash("Online payments aren't switched on yet. Please contact us to buy credits.", "err")
            return redirect(url_for("site.buy"))
        if product["kind"] == "account" and g.user["account_status"] == "active":
            flash(f"Your {settings.account_name.lower()} is already open.", "info")
            return redirect(url_for("site.account") + "#monthly")
        conn = request_db()
        order = billing.create_order(conn, g.user["id"], product)
        try:
            payment_page = billing.start_checkout(conn, settings, order, base_url())
        except BillingError as exc:
            log.error("Checkout for order %s failed: %s", order["ref"], exc)
            conn.execute("UPDATE orders SET status = 'failed' WHERE id = ?", (order["id"],))
            flash("We couldn't open the payment page just now. Please try again in a moment.", "err")
            return redirect(url_for("site.buy"))
        return redirect(payment_page)

    def own_bill(ref: str) -> sqlite3.Row:
        bill = request_db().execute("SELECT * FROM orders WHERE ref = ? AND user_id = ? AND product_kind = 'bill'",
                                    (ref, g.user["id"])).fetchone()
        if bill is None:
            abort(404)
        return bill

    @bp.get("/app/bills/<ref>")
    @login_required
    def bill(ref):
        row = own_bill(ref)
        invoice = request_db().execute("SELECT number FROM invoices WHERE order_id = ?", (row["id"],)).fetchone()
        return render_template("site/bill.html", bill=row, lines=json.loads(row["lines_json"]), invoice=invoice,
                               overdue=row["status"] != "paid" and parse_iso(row["due_at"]) <= utcnow(), active="invoices")

    @bp.post("/app/bills/<ref>/pay")
    @login_required
    def pay_bill(ref):
        row, settings = own_bill(ref), store.current
        if row["status"] == "paid":
            return redirect(url_for("site.bill", ref=ref))
        if not settings.payments_ready:
            flash("Online payments aren't switched on yet. Please contact us to pay this bill.", "err")
            return redirect(url_for("site.bill", ref=ref))
        try:
            payment_page = billing.start_checkout(request_db(), settings, row, base_url())
        except BillingError as exc:  # the bill stays owed; nothing to mark failed
            log.error("Checkout for bill %s failed: %s", ref, exc)
            flash("We couldn't open the payment page just now. Please try again in a moment.", "err")
            return redirect(url_for("site.bill", ref=ref))
        return redirect(payment_page)

    @bp.post("/app/account/monthly")
    @login_required
    def monthly_account():
        settings, closing = store.current, request.form.get("action") == "close"
        with transaction(request_db()) as conn:
            changed = postpaid.set_closing(conn, g.user["id"], closing)
        if changed and closing:
            flash(f"Your {settings.account_name.lower()} will close on "
                  f"{parse_iso(g.user['account_period_end']):%d %b %Y}, after a final bill for the checks you've used.", "ok")
        elif changed:
            flash(f"Your {settings.account_name.lower()} stays open.", "ok")
        return redirect(url_for("site.account") + "#monthly")

    @bp.get("/app/payment/<ref>")
    @login_required
    def payment(ref):
        conn = request_db()
        order = conn.execute("SELECT * FROM orders WHERE ref = ? AND user_id = ?", (ref, g.user["id"])).fetchone()
        if order is None:
            abort(404)
        invoice = conn.execute("SELECT number FROM invoices WHERE order_id = ?", (order["id"],)).fetchone()
        return render_template("site/payment.html", order=order, invoice=invoice, result=request.args.get("result", ""),
                               plan=accounts.plan_status(g.user), active="buy")

    @bp.post("/billing/yoco/webhook")
    def yoco_webhook():
        settings = store.current
        body = request.get_data()
        if not billing.verify_webhook(settings.yoco_webhook_secret, request.headers, body):
            log.warning("Rejected a Yoco webhook with a bad or missing signature from %s", client_ip())
            return "invalid signature", 403
        try:
            event = json.loads(body)
        except ValueError:
            return "invalid JSON", 400
        conn = request_db()
        try:
            number = billing.handle_event(conn, settings, event)
        except Exception:
            log.exception("Processing Yoco event %s failed", event.get("id"))
            return "error", 500  # Yoco retries later
        if number:
            email_invoice(conn, settings, number)
        return "ok", 200

    def email_invoice(conn: sqlite3.Connection, settings: Settings, number: str) -> None:
        row = conn.execute("SELECT i.*, u.email, u.name FROM invoices i JOIN users u ON u.id = i.user_id "
                           "WHERE i.number = ?", (number,)).fetchone()
        data = json.loads(row["data_json"])
        send_later(settings, row["email"], f"Your invoice {number} from {settings.business_name}", render_template(
            "email/invoice.txt", name=row["name"], number=number, data=data, settings=settings, money=money,
            link=base_url() + url_for("site.invoice", number=number)))

    # --- invoices and account --------------------------------------------------------------------

    @bp.get("/app/invoices")
    @login_required
    def invoices():
        conn = request_db()
        rows = conn.execute("SELECT number, issued_at, total_cents FROM invoices WHERE user_id = ? ORDER BY id DESC",
                            (g.user["id"],)).fetchall()
        pending = conn.execute("SELECT ref, description, amount_cents, created_at, status FROM orders WHERE user_id = ? "
                               "AND status != 'paid' AND product_kind != 'bill' ORDER BY id DESC LIMIT 10",
                               (g.user["id"],)).fetchall()
        return render_template("site/invoices.html", invoices=rows, orders=pending,
                               bills=postpaid.unpaid_bills(conn, g.user["id"]), now=utcnow(), active="invoices")

    @bp.get("/app/invoices/<number>")
    @login_required
    def invoice(number):
        row = request_db().execute("SELECT * FROM invoices WHERE number = ? AND user_id = ?",
                                   (number, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        return render_template("invoice.html", invoice=row, data=json.loads(row["data_json"]), back=url_for("site.invoices"))

    def account_page(new_key: str = "", status: int = 200):
        ledger = request_db().execute("SELECT change, balance, reason, created_at FROM ledger WHERE user_id = ? "
                                      "ORDER BY id DESC LIMIT 25", (g.user["id"],)).fetchall()
        return render_template("site/account.html", ledger=ledger, new_key=new_key, plan=accounts.plan_status(g.user),
                               account_info=account_summary(), api_example=f"{base_url()}{url_for('site.api_grade')}?domain=example.com",
                               active="account"), status

    @bp.get("/app/account")
    @login_required
    def account():
        return account_page()

    @bp.post("/app/account/profile")
    @login_required
    def update_profile():
        form = request.form
        try:
            accounts.update_profile(request_db(), g.user["id"], name=form.get("name", ""), company=form.get("company", ""),
                                    vat_number=form.get("vat_number", ""), address=form.get("address", ""))
        except AccountError as exc:
            flash(str(exc), "err")
        else:
            flash("Details saved. They'll appear on your next invoice.", "ok")
        return redirect(url_for("site.account"))

    @bp.post("/app/account/branding")
    @login_required
    def update_branding():
        form = request.form
        try:
            accounts.update_firm_branding(request_db(), g.user["id"], name=form.get("firm_name", ""), email=form.get("firm_email", ""),
                                          phone=form.get("firm_phone", ""), url=form.get("firm_url", ""))
        except AccountError as exc:
            flash(str(exc), "err")
        else:
            flash("Saved. Reports you download or send to clients now carry these details.", "ok")
        return redirect(url_for("site.account") + "#branding")

    @bp.post("/app/account/password")
    @login_required
    def change_password():
        form, conn = request.form, request_db()
        if not accounts.authenticate(conn, g.user["email"], form.get("current", "")):
            flash("Your current password isn't right.", "err")
        elif problem := password_problem(form.get("password", ""), form.get("confirm", "")):
            flash(problem, "err")
        else:
            accounts.set_password(conn, g.user["id"], form["password"])
            sign_in_customer(accounts.get_user(conn, g.user["id"]))  # keep this session, end the others
            flash("Password changed. Other devices have been signed out.", "ok")
        return redirect(url_for("site.account"))

    @bp.post("/app/account/api-key")
    @login_required
    def create_api_key():
        key = accounts.new_api_key(request_db(), g.user["id"])
        g.user = accounts.get_user(request_db(), g.user["id"])
        return account_page(new_key=key)

    @bp.post("/app/account/api-key/revoke")
    @login_required
    def revoke_api_key():
        accounts.revoke_api_key(request_db(), g.user["id"])
        flash("API key revoked.", "ok")
        return redirect(url_for("site.account"))

    # --- API -------------------------------------------------------------------------------------

    def api_user():
        key = request.headers.get("X-API-Key") or request.args.get("key") or ""
        return accounts.user_for_api_key(request_db(), key) if key else None

    @bp.get("/api/grade")
    def api_grade():
        conn = request_db()
        user = api_user()
        if user is None:
            return jsonify(error="Send a valid API key in the X-API-Key header (create one under Account)."), 401
        try:
            domain = check_domain_input(request.args.get("domain", ""))
            scan_id = run_paid_scan(conn, service, user, domain)
        except NoCredits as exc:
            return jsonify(error=str(exc)), 402
        except ScanRefused as exc:
            return jsonify(error=str(exc)), exc.status
        row = conn.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        balance = accounts.get_user(conn, user["id"])
        return jsonify({**json.loads(row["report_json"]), "scan_id": scan_id, "credits_left": balance["credits"]})

    # --- building network audits (uploaded by tools/lan_agent.py or the mobile app) ---------------

    @bp.post("/api/lan-audit")
    def api_lan_audit():
        user = api_user()
        if user is None:
            return jsonify(error="Send a valid API key in the X-API-Key header (create one under Account)."), 401
        if not service.scan_limiter.allow(f"user:{user['id']}"):
            return jsonify(error="Too many uploads in a short time. Please wait a few minutes."), 429
        payload = request.get_json(silent=True)
        # Optionally check what the network exposes to the internet, but only its OWN public IP: the address
        # this request came from (where the technician is connected), never a target chosen in the payload.
        if isinstance(payload, dict) and payload.pop("check_external", False):
            exposure = external.check_exposure(request.remote_addr or "")
            exposure["findings"] = external.findings(exposure)
            payload["_external"] = exposure
        try:
            audit = lan.evaluate(payload)
        except lan.AuditError as exc:
            return jsonify(error=str(exc)), 400
        audit_id = request_db().execute(
            "INSERT INTO lan_audits (user_id, site_name, domain, grade, score, report_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user["id"], audit["site_name"], audit["domain"], audit["grade"], audit["score"], json.dumps(audit), iso(utcnow())),
        ).lastrowid
        return jsonify({**audit, "id": audit_id, "url": f"{base_url()}{url_for('site.lan_audit', audit_id=audit_id)}"}), 201

    # The agent and the phone app hold no secrets (uploads need the customer's API key), so they're public downloads.
    @bp.get("/downloads/lan_agent.py")
    def download_agent():
        if not AGENT_PATH.exists():
            abort(404)
        return Response(AGENT_PATH.read_bytes(), mimetype="text/x-python",
                        headers={"Content-Disposition": 'attachment; filename="lan_agent.py"'})

    @bp.get("/downloads/building-network-audit.apk")
    def download_app():
        if not APP_PATH.exists():
            abort(404)
        return Response(APP_PATH.read_bytes(), mimetype="application/vnd.android.package-archive",
                        headers={"Content-Disposition": 'attachment; filename="building-network-audit.apk"'})

    @bp.get("/network-audit")
    def network_audit_guide():
        return render_template("site/network_audit.html", app_available=APP_PATH.exists(), server=base_url(),
                               active="dashboard" if g.user else "")

    @bp.get("/app/lan/<int:audit_id>")
    @login_required
    def lan_audit(audit_id):
        row = request_db().execute("SELECT * FROM lan_audits WHERE id = ? AND user_id = ?", (audit_id, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        return render_template("site/lan.html", audit=json.loads(row["report_json"]), row=row, active="dashboard")

    @bp.post("/app/lan/<int:audit_id>/help")
    @login_required
    def lan_help(audit_id):
        row = request_db().execute("SELECT * FROM lan_audits WHERE id = ? AND user_id = ?", (audit_id, g.user["id"])).fetchone()
        if row is None:
            abort(404)
        try:
            lead = clean_lead({"name": g.user["name"], "email": g.user["email"], "phone": request.form.get("phone", ""),
                               "message": request.form.get("message", "")})
        except LeadError as exc:
            flash(str(exc), "err")
        else:
            record_lead(request_db(), store.current, domain=row["domain"] or row["site_name"] or "building network",
                        source="lan", grade=row["grade"], score=row["score"], user_id=g.user["id"], **lead)
            flash("Thanks! We'll be in touch about fixing the network.", "ok")
        return redirect(url_for("site.lan_audit", audit_id=audit_id))

    return bp


def format_date(value, with_time: bool = False) -> str:
    moment = parse_iso(value) if isinstance(value, str) else value
    if moment is None:
        return ""
    return moment.strftime("%d %b %Y, %H:%M UTC" if with_time else "%d %b %Y")
