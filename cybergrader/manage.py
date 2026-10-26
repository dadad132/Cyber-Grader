"""Server-side maintenance commands.

    python -m cybergrader.manage set-admin-password          # prompt for the super-admin password
    python -m cybergrader.manage configure --site-url https://grader.example.co.za --trust-proxy
    python -m cybergrader.manage send-reminders              # email customers whose plan ends within 3 days
    python -m cybergrader.manage add-credits someone@example.com 10 --reason "Promo"
    python -m cybergrader.manage status                      # the go-live checklist
    python -m cybergrader.manage backup /root/grader-backup.db
    python -m cybergrader.manage daily                       # reminders + rotating backups (run by a systemd timer)

Set GRADER_DATA_DIR to the data folder (the installer uses /var/lib/cybergrader).
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template
from werkzeug.security import generate_password_hash

from . import accounts
from .admin import go_live_checklist
from .billing import money
from .db import connect, iso, migrate, parse_iso, utcnow
from .mailer import MailError, send_mail
from .settings import SettingsStore

REMINDER_DAYS = 3


def _db(store: SettingsStore) -> sqlite3.Connection:
    path = store.path.parent / "grader.db"
    migrate(path)
    return connect(path)


def set_admin_password(store: SettingsStore, args) -> int:
    if args.generate:
        password = secrets.token_urlsafe(14)
        print(f"Generated super-admin password: {password}\nStore it in your password manager now.")
    elif args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("New super-admin password (at least 10 characters): ")
        if getpass.getpass("Type it again: ") != password:
            print("The passwords didn't match; nothing changed.", file=sys.stderr)
            return 1
    problem = accounts.password_problem(password)
    if problem:
        print(problem, file=sys.stderr)
        return 1
    store.ensure_secret_key()
    store.update(admin_password_hash=generate_password_hash(password))
    print("Super-admin password saved.")
    return 0


def configure(store: SettingsStore, args) -> int:
    changes = {}
    if args.site_url:
        if not args.site_url.startswith(("https://", "http://")):
            print("--site-url must start with https://", file=sys.stderr)
            return 1
        changes["site_url"] = args.site_url.rstrip("/")
    if args.trust_proxy:
        changes["trust_proxy"] = True
    if args.brand:
        changes["brand_name"] = args.brand
    if args.contact_email:
        changes["contact_email"] = args.contact_email
    store.ensure_secret_key()
    if changes:
        store.update(**changes)
    print("Settings saved: " + (", ".join(f"{k}={v}" for k, v in changes.items()) or "nothing to change"))
    return 0


def send_reminders(store: SettingsStore, _args) -> int:
    settings = store.current
    conn = _db(store)
    now = utcnow()
    soon = iso(now + timedelta(days=REMINDER_DAYS))
    rows = conn.execute(
        "SELECT * FROM users WHERE disabled = 0 AND plan_expires_at > ? AND plan_expires_at <= ? "
        "AND (reminder_sent_for IS NULL OR reminder_sent_for != plan_expires_at)", (iso(now), soon)).fetchall()
    if not rows:
        print("No plans ending soon.")
        return 0
    if not settings.email_ready:
        print(f"{len(rows)} plan(s) end soon, but email isn't set up, so no reminders were sent.", file=sys.stderr)
        return 1
    app = Flask(__name__.rsplit(".", 1)[0])  # just for rendering the email template
    base = settings.site_url.rstrip("/")
    sent = 0
    for user in rows:
        with app.app_context():
            text = render_template("email/reminder.txt", user=user, settings=settings,
                                   expires=parse_iso(user["plan_expires_at"]).strftime("%d %b %Y"), link=f"{base}/app/buy")
        try:
            send_mail(settings, user["email"], f"Your {user['plan_name']} plan ends soon", text)
        except MailError as exc:
            print(exc, file=sys.stderr)
            continue
        conn.execute("UPDATE users SET reminder_sent_for = plan_expires_at WHERE id = ?", (user["id"],))
        sent += 1
    print(f"Sent {sent} reminder(s).")
    return 0 if sent == len(rows) else 1


def add_credits(store: SettingsStore, args) -> int:
    conn = _db(store)
    user = accounts.get_user_by_email(conn, args.email)
    if user is None:
        print(f"No account for {args.email}.", file=sys.stderr)
        return 1
    balance = accounts.adjust_credits(conn, user["id"], args.count, args.reason)
    print(f"{args.email} now has {balance} credit(s).")
    return 0


def status(store: SettingsStore, _args) -> int:
    conn = _db(store)
    users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    revenue = conn.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM orders WHERE status = 'paid' "
                           "AND COALESCE(mode, 'live') != 'test'").fetchone()[0]
    print(f"Data folder: {store.path.parent}\nCustomers: {users} · live revenue to date: {money(revenue)}\n")
    marks = {"ok": "[ok]  ", "warn": "[warn]", "fail": "[todo]", "info": "[info]"}
    for item in go_live_checklist(store.current):
        print(f"{marks[item.status]} {item.name}: {item.detail}" + (f"\n        -> {item.fix}" if item.fix else ""))
    if not store.current.admin_password_hash:
        print("[todo] Super-admin password: not set. Run: python -m cybergrader.manage set-admin-password")
    return 0


def backup(store: SettingsStore, args) -> int:
    source = _db(store)
    target = sqlite3.connect(args.destination)
    with target:
        source.backup(target)  # consistent copy even while the site is running
    target.close()
    print(f"Database backed up to {args.destination}. Also keep a copy of {store.path} (settings and secrets).")
    return 0


def daily(store: SettingsStore, args) -> int:
    """Daily housekeeping: plan reminders, clearing out old free checks, then a dated database backup (keeping 14)."""
    reminders_ok = send_reminders(store, args) == 0 or not store.current.email_ready
    conn = _db(store)
    old_previews = iso(utcnow() - timedelta(days=30))
    conn.execute("DELETE FROM owner_codes WHERE created_at < ? OR token IN (SELECT token FROM previews WHERE created_at < ?)",
                 (iso(utcnow() - timedelta(days=2)), old_previews))
    conn.execute("DELETE FROM previews WHERE created_at < ?", (old_previews,))
    folder = store.path.parent / "backups"
    folder.mkdir(exist_ok=True)
    backup(store, argparse.Namespace(destination=str(folder / f"grader-{utcnow():%Y-%m-%d}.db")))
    for old in sorted(folder.glob("grader-*.db"))[:-14]:
        old.unlink()
    return 0 if reminders_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cybergrader.manage", description="Grader maintenance commands.")
    commands = parser.add_subparsers(dest="command", required=True)
    pw = commands.add_parser("set-admin-password", help="set the super-admin password")
    pw.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    pw.add_argument("--generate", action="store_true", help="generate a random password and print it")
    pw.set_defaults(func=set_admin_password)
    cfg = commands.add_parser("configure", help="set basic settings from the command line")
    cfg.add_argument("--site-url")
    cfg.add_argument("--trust-proxy", action="store_true")
    cfg.add_argument("--brand")
    cfg.add_argument("--contact-email")
    cfg.set_defaults(func=configure)
    commands.add_parser("send-reminders", help="email customers whose plan ends soon").set_defaults(func=send_reminders)
    credits = commands.add_parser("add-credits", help="give (or with a negative number, take) credits")
    credits.add_argument("email")
    credits.add_argument("count", type=int)
    credits.add_argument("--reason", default="Added by support")
    credits.set_defaults(func=add_credits)
    commands.add_parser("status", help="show the go-live checklist").set_defaults(func=status)
    bk = commands.add_parser("backup", help="make a safe copy of the database")
    bk.add_argument("destination")
    bk.set_defaults(func=backup)
    commands.add_parser("daily", help="send reminders and make a rotating backup").set_defaults(func=daily)
    args = parser.parse_args(argv)
    return args.func(SettingsStore(), args)


if __name__ == "__main__":
    sys.exit(main())
