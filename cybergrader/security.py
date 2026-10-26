"""CSRF tokens and small request-safety helpers shared by the customer site and the super-admin portal."""
from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

from flask import session
from markupsafe import Markup


def same(supplied: str, expected: str) -> bool:
    return bool(supplied) and bool(expected) and hmac.compare_digest(supplied.encode(), expected.encode())


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_field() -> Markup:
    return Markup(f'<input type="hidden" name="csrf" value="{csrf_token()}">')


def csrf_ok(form) -> bool:
    return same(form.get("csrf", ""), session.get("csrf", ""))


def safe_next(target: str | None, default: str) -> str:
    """Only allow redirects back to a path on this site (no open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return default
    parts = urlsplit(target)
    return target if not parts.scheme and not parts.netloc else default
