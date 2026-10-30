"""Server-side maintenance commands.

    python -m cybergrader.manage set-admin-password          # prompt for the super-admin password
    python -m cybergrader.manage configure --site-url https://grader.example.co.za --trust-proxy
    python -m cybergrader.manage send-reminders              # plan renewal reminders (days set under Payments & pricing)
    python -m cybergrader.manage bill-accounts               # monthly account bills, reminders and on-hold notices
    python -m cybergrader.manage add-credits someone@example.com 10 --reason "Promo"
    python -m cybergrader.manage status                      # the go-live checklist
    python -m cybergrader.manage backup /root/grader-backup.db
    python -m cybergrader.manage daily                       # bills, reminders + rotating backups (run by a systemd timer)

Set GRADER_DATA_DIR to the data folder (the installer uses /var/lib/cybergrader).
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta

from flask import Flask, render_template
from werkzeug.security import generate_password_hash

from . import accounts, postpaid
from .admin import go_live_checklist
from .billing import money
from .db import connect, iso, migrate, parse_iso, utcnow
from .mailer import MailError, send_mail
from .settings import SettingsStore

ENDED_NOTICE_DAYS = 7  # "your plan has ended" only goes out for plans that ended this recently


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
    if args.dnsbl_resolver is not None:
        changes["dnsbl_nameservers"] = [args.dnsbl_resolver] if args.dnsbl_resolver else []
    store.ensure_secret_key()
    if changes:
        store.update(**changes)
    print("Settings saved: " + (", ".join(f"{k}={v}" for k, v in changes.items()) or "nothing to change"))
    return 0


def _templates() -> Flask:
    return Flask(__name__.rsplit(".", 1)[0])  # just for rendering email templates outside the website


def _stage_rank(stage: str) -> int:
    return 0 if stage == "ended" else int(stage)  # lower = more urgent


def reminder_stage(expires: datetime, now: datetime, days: list[int], ended_email: bool, sent_for: str | None) -> str | None:
    """Which renewal email a plan ending at `expires` needs now: a number of days before ('7', '3', '1'), 'ended',
    or None. sent_for records the last one sent as '<expiry>|<stage>' (or just '<expiry>' from older versions)."""
    if expires <= now:
        stage = "ended" if ended_email and now - expires <= timedelta(days=ENDED_NOTICE_DAYS) else None
    else:
        stage = next((str(d) for d in sorted(days) if expires - now <= timedelta(days=d)), None)
    if stage is None:
        return None
    sent_expiry, _, sent_stage = (sent_for or "").partition("|")
    if sent_expiry == iso(expires) and _stage_rank(sent_stage or "3") <= _stage_rank(stage):
        return None  # this one (or a more urgent one) already went out for this plan period
    return stage


def send_reminders(store: SettingsStore, _args) -> int:
    """Plan renewal emails: on each of the configured days before a plan ends, and once after it has ended."""
    settings = store.current
    conn = _db(store)
    now = utcnow()
    since = now - timedelta(days=ENDED_NOTICE_DAYS) if settings.plan_ended_email else now
    until = now + timedelta(days=max(settings.plan_reminder_days, default=0))
    due = []
    for user in conn.execute("SELECT * FROM users WHERE disabled = 0 AND plan_expires_at > ? AND plan_expires_at <= ?",
                             (iso(since), iso(until))).fetchall():
        stage = reminder_stage(parse_iso(user["plan_expires_at"]), now, settings.plan_reminder_days,
                               settings.plan_ended_email, user["reminder_sent_for"])
        if stage:
            due.append((user, stage))
    if not due:
        print("No plan reminders due.")
        return 0
    if not settings.email_ready:
        print(f"{len(due)} plan reminder(s) due, but email isn't set up, so none were sent.", file=sys.stderr)
        return 1
    base = settings.site_url.rstrip("/")
    sent = 0
    for user, stage in due:
        expires = parse_iso(user["plan_expires_at"])
        with _templates().app_context():
            text = render_template("email/reminder.txt", user=user, settings=settings, expires=expires.strftime("%d %b %Y"),
                                   ended=stage == "ended", days_left=max(1, round((expires - now) / timedelta(days=1))),
                                   link=f"{base}/app/buy?renew={user['plan_id']}")
        subject = (f"Your {user['plan_name']} plan has ended" if stage == "ended"
                   else f"Your {user['plan_name']} plan ends on {expires:%d %b}")
        try:
            send_mail(settings, user["email"], subject, text)
        except MailError as exc:
            print(exc, file=sys.stderr)
            continue
        conn.execute("UPDATE users SET reminder_sent_for = ? WHERE id = ?", (f"{user['plan_expires_at']}|{stage}", user["id"]))
        sent += 1
    print(f"Sent {sent} plan reminder(s).")
    return 0 if sent == len(due) else 1


def bill_accounts(store: SettingsStore, _args) -> int:
    """Monthly accounts: issue the bills whose billing day has come, then email bills, reminders and on-hold notices."""
    settings = store.current
    conn = _db(store)
    bills = postpaid.issue_bills(conn, settings)
    print(f"Issued {len(bills)} monthly bill(s).")
    due = postpaid.notices_due(conn)
    if not due:
        return 0
    if not settings.email_ready:
        print(f"{len(due)} bill email(s) due, but email isn't set up, so none were sent.", file=sys.stderr)
        return 1
    base = settings.site_url.rstrip("/")
    sent = 0
    for bill, stage in due:
        with _templates().app_context():
            subject, text = postpaid.bill_email(settings, bill, stage, f"{base}/app/bills/{bill['ref']}")
        try:
            send_mail(settings, bill["email"], subject, text)
        except MailError as exc:
            print(exc, file=sys.stderr)
            continue
        conn.execute("UPDATE orders SET notice = ? WHERE id = ?", (stage, bill["id"]))
        sent += 1
    print(f"Sent {sent} bill email(s).")
    return 0 if sent == len(due) else 1


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
    """Daily housekeeping: monthly bills, plan reminders, clearing out old free checks, then a dated database backup
    (keeping 14)."""
    bills_ok = bill_accounts(store, args) == 0 or not store.current.email_ready
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
    return 0 if reminders_ok and bills_ok else 1


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
    cfg.add_argument("--dnsbl-resolver", help="DNS server for blacklist lookups, e.g. 127.0.0.1:5335 ('' = same as scans)")
    cfg.set_defaults(func=configure)
    commands.add_parser("send-reminders", help="email customers whose plan ends soon").set_defaults(func=send_reminders)
    commands.add_parser("bill-accounts", help="issue monthly account bills and send bill emails").set_defaults(func=bill_accounts)
    credits = commands.add_parser("add-credits", help="give (or with a negative number, take) credits")
    credits.add_argument("email")
    credits.add_argument("count", type=int)
    credits.add_argument("--reason", default="Added by support")
    credits.set_defaults(func=add_credits)
    commands.add_parser("status", help="show the go-live checklist").set_defaults(func=status)
    bk = commands.add_parser("backup", help="make a safe copy of the database")
    bk.add_argument("destination")
    bk.set_defaults(func=backup)
    commands.add_parser("daily", help="bills, reminders and a rotating backup").set_defaults(func=daily)
    args = parser.parse_args(argv)
    return args.func(SettingsStore(), args)


if __name__ == "__main__":
    sys.exit(main())
