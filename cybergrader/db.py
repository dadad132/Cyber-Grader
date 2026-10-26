"""SQLite storage for accounts, credits, scans, orders and invoices.

Kept compatible with SQLite 3.26 (AlmaLinux 8): no RETURNING, STRICT tables or DROP COLUMN.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

MIGRATIONS = [
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        name TEXT NOT NULL,
        company TEXT NOT NULL DEFAULT '',
        vat_number TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0 CHECK (credits >= 0),
        plan_id TEXT,
        plan_name TEXT,
        plan_expires_at TEXT,
        plan_scans_left INTEGER,              -- NULL means unlimited while the plan is active
        reminder_sent_for TEXT,               -- the plan_expires_at we already sent a reminder for
        api_key_hash TEXT UNIQUE,
        api_key_hint TEXT,
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login_at TEXT
    );
    CREATE TABLE ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        change INTEGER NOT NULL,
        balance INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX ledger_user ON ledger(user_id, id);
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),  -- NULL for super-admin test scans
        domain TEXT NOT NULL,
        grade TEXT NOT NULL,
        score INTEGER NOT NULL,
        paid_with TEXT NOT NULL,               -- credit, plan, free, api or admin
        report_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX scans_user ON scans(user_id, id);
    CREATE TABLE orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL REFERENCES users(id),
        product_kind TEXT NOT NULL,            -- credits or plan
        product_id TEXT NOT NULL,
        description TEXT NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        plan_scans INTEGER,                    -- NULL means unlimited
        plan_days INTEGER NOT NULL DEFAULT 0,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL DEFAULT 'ZAR',
        status TEXT NOT NULL DEFAULT 'pending', -- pending, paid or failed
        checkout_id TEXT UNIQUE,
        payment_id TEXT,
        mode TEXT,                             -- live or test
        paid_by TEXT,                          -- yoco or admin
        created_at TEXT NOT NULL,
        paid_at TEXT
    );
    CREATE INDEX orders_user ON orders(user_id, id);
    CREATE TABLE invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT NOT NULL UNIQUE,
        order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        issued_at TEXT NOT NULL,
        total_cents INTEGER NOT NULL,
        data_json TEXT NOT NULL                -- frozen copy of seller, buyer, lines and totals
    );
    CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
    CREATE TABLE password_resets (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE webhook_events (event_id TEXT PRIMARY KEY, received_at TEXT NOT NULL);
    """,
    """
    CREATE TABLE previews (                    -- free checks: summary public, details locked
        token TEXT PRIMARY KEY,                -- unguessable link id
        domain TEXT NOT NULL,
        grade TEXT NOT NULL,
        score INTEGER NOT NULL,
        report_json TEXT NOT NULL,
        unlocked_by TEXT,                      -- verified owner's email once unlocked
        created_at TEXT NOT NULL
    );
    CREATE INDEX previews_domain ON previews(domain, created_at);
    CREATE TABLE owner_codes (                 -- one-time codes proving someone owns a domain's mailbox
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL REFERENCES previews(token),
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX owner_codes_token ON owner_codes(token, id);
    CREATE TABLE leads (                       -- "have us fix it" requests and verified domain owners
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        domain TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL DEFAULT '',
        grade TEXT NOT NULL DEFAULT '',
        score INTEGER,
        tier TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL,                  -- report, preview, owner or lan
        status TEXT NOT NULL DEFAULT 'new',    -- new, contacted, won or lost
        created_at TEXT NOT NULL
    );
    CREATE TABLE lan_audits (                  -- on-site building network audits uploaded by the agent/app
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        site_name TEXT NOT NULL DEFAULT '',
        domain TEXT NOT NULL DEFAULT '',
        grade TEXT NOT NULL,
        score INTEGER NOT NULL,
        report_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX lan_audits_user ON lan_audits(user_id, id);
    """,
    """
    CREATE TABLE clients (                     -- domains an IT firm manages for its clients
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),   -- the IT firm's account
        domain TEXT NOT NULL,
        name TEXT NOT NULL,
        contact_email TEXT NOT NULL,           -- an address at the client's domain
        notes TEXT NOT NULL DEFAULT '',
        approval_status TEXT NOT NULL DEFAULT 'none',    -- none, pending, approved, declined, revoked
        approval_token_hash TEXT UNIQUE,
        approval_sent_at TEXT,
        approved_by TEXT,
        approved_at TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (user_id, domain)
    );
    CREATE INDEX clients_user ON clients(user_id, id);
    CREATE TABLE client_messages (             -- reports and quotes sent to clients
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL REFERENCES clients(id),
        scan_id INTEGER REFERENCES scans(id),
        to_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        quote_cents INTEGER,
        quote_text TEXT NOT NULL DEFAULT '',
        sent_at TEXT NOT NULL
    );
    CREATE INDEX client_messages_client ON client_messages(client_id, id);
    ALTER TABLE users ADD COLUMN firm_name TEXT NOT NULL DEFAULT '';   -- shown on reports the firm sends
    ALTER TABLE users ADD COLUMN firm_email TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN firm_phone TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN firm_url TEXT NOT NULL DEFAULT '';
    """,
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def connect(path: Path | str) -> sqlite3.Connection:
    # Autocommit mode; writes that must be atomic use transaction() below.
    conn = sqlite3.connect(str(path), timeout=15, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def migrate(path: Path | str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
            conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")
    finally:
        conn.close()


def request_db() -> sqlite3.Connection:
    """The database connection for the current web request (closed by the app's teardown handler)."""
    from flask import current_app, g

    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE takes the write lock up front, so concurrent writers queue instead of deadlocking."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def next_number(conn: sqlite3.Connection, name: str) -> int:
    """Next value of a gap-free counter; call inside transaction()."""
    conn.execute("INSERT INTO counters (name, value) VALUES (?, 1) "
                 "ON CONFLICT(name) DO UPDATE SET value = value + 1", (name,))
    return conn.execute("SELECT value FROM counters WHERE name = ?", (name,)).fetchone()[0]
