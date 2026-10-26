"""Settings for the website, super-admin portal and CLI, stored as JSON in the data folder.

The super-admin portal edits them; the CLI reads them for its defaults. The v2.0 environment variables
(GRADER_BRAND, GRADER_RATE_LIMIT, ...) still work as defaults until settings are first saved.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import threading
from dataclasses import asdict, dataclass, field, fields, replace
from decimal import Decimal, InvalidOperation
from email.utils import parseaddr
from pathlib import Path
from typing import Mapping

from .report import Branding

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "instance"
MIN_PRICE_CENTS = 200  # Yoco doesn't accept payments under R2.00
MAX_PACKS, MAX_PLANS = 5, 3


class SettingsError(ValueError):
    pass


def data_dir() -> Path:
    return Path(os.environ.get("GRADER_DATA_DIR") or DEFAULT_DATA_DIR)


def _default_packs() -> list[dict]:
    return [
        {"id": "pack-1", "name": "Single check", "credits": 1, "price_cents": 4900},
        {"id": "pack-2", "name": "5 checks", "credits": 5, "price_cents": 19900},
        {"id": "pack-3", "name": "20 checks", "credits": 20, "price_cents": 59900},
    ]


def _default_plans() -> list[dict]:
    return [{"id": "plan-1", "name": "Monthly", "price_cents": 49900, "scans": 50, "days": 30}]


DEFAULT_TERMS = """These terms apply to your use of this website and its domain security checks.

1. The service. We check publicly available information about a domain (DNS records, its website's HTTPS setup and response headers). Checks are passive: we don't scan ports, try passwords or attempt to break in. Results describe the moment of the check and are guidance, not a guarantee of security.

2. Acceptable use. Only check domains you own, manage or have a legitimate reason to assess. Don't use the service to harass anyone or to break the law.

3. Credits and plans. One credit pays for one check of one domain. Credits don't expire. A monthly plan gives the listed number of checks for 30 days from payment and doesn't renew automatically. Unused plan checks lapse when the plan ends.

4. Payments and refunds. Payments are processed by Yoco. A credit that has been used can't be refunded. If a payment went wrong or you bought something by mistake, contact us within 14 days and we'll make it right.

5. Liability. To the extent the law allows, we aren't liable for losses arising from reliance on the results.

6. Changes. We may update these terms; the version on this page applies.

[Template: review these terms with your legal adviser before going live.]"""

DEFAULT_PRIVACY = """This policy explains what personal information we collect and how we use it, in line with the Protection of Personal Information Act (POPIA).

What we collect: your name, email address and company details when you create an account; the domains you check and their results; and payment records (card details are handled by Yoco and never reach us).

Why: to provide the service, keep your results in your account, issue invoices and contact you about your account.

Sharing: we share payment information with Yoco to process payments. We don't sell your information.

Keeping it: account data is kept while your account is open; invoices are kept for as long as tax law requires.

Your rights: you may ask to see, correct or delete your personal information, or object to how we process it, by contacting us. You may also complain to the Information Regulator.

[Template: review this policy with your legal adviser before going live.]"""


@dataclass
class Settings:
    # Website and business details shown on pages and reports
    site_url: str = ""  # e.g. https://grader.example.com (used in emails and payment links)
    brand_name: str = ""
    brand_url: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    cta_text: str = ""
    # Scanning
    timeout: float = 6.0
    nameservers: list[str] = field(default_factory=list)
    user_agent: str = ""
    # Abuse protection
    rate_limit: int = 10  # scans per account per 10 minutes
    max_concurrent: int = 4
    trust_proxy: bool = False
    # Accounts and pricing (amounts in cents, ZAR)
    signup_credits: int = 1
    charge_for_checks: bool = True  # off = every check, full report and PDF is free (no credits used)
    credit_packs: list[dict] = field(default_factory=_default_packs)
    plans: list[dict] = field(default_factory=_default_plans)
    # Yoco
    yoco_secret_key: str = ""
    yoco_webhook_id: str = ""
    yoco_webhook_secret: str = ""
    yoco_webhook_url: str = ""
    yoco_webhook_mode: str = ""  # Yoco webhooks belong to the key mode (test/live) they were registered with
    # Invoices and tax
    legal_name: str = ""
    business_address: str = ""
    registration_number: str = ""
    vat_registered: bool = False
    vat_number: str = ""
    vat_rate: float = 15.0
    invoice_prefix: str = "INV"
    invoice_notes: str = ""
    # Outgoing email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # starttls, ssl or none
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    # Free checks, domain-owner unlocks and "have us fix it" requests (lead generation)
    free_checks_enabled: bool = True
    free_checks_per_hour: int = 5  # per visitor
    owner_unlock_free: bool = True  # verified owners (code sent to an @theirdomain mailbox) see their full report free
    dfy_enabled: bool = True
    dfy_minor_cents: int = 79900
    dfy_moderate_cents: int = 149900
    dfy_critical_cents: int = 249900
    lead_notify_email: str = ""  # blank = contact email
    # Search engines
    google_site_verification: str = ""
    # Legal pages
    terms_text: str = DEFAULT_TERMS
    privacy_text: str = DEFAULT_PRIVACY
    # Managed by the portal itself, never by a settings form
    admin_password_hash: str = ""
    secret_key: str = ""

    def branding(self) -> Branding:
        return Branding(self.brand_name, self.brand_url, self.contact_email, self.contact_phone, self.cta_text)

    @property
    def business_name(self) -> str:
        return self.brand_name or self.legal_name or "Cyber Hygiene Grader"

    @property
    def payments_ready(self) -> bool:
        return bool(self.yoco_secret_key and self.yoco_webhook_secret)

    @property
    def yoco_mode(self) -> str:
        key = self.yoco_secret_key.replace("_", "")
        return "live" if key.startswith("sklive") else "test" if key.startswith("sktest") else ""

    @property
    def email_ready(self) -> bool:
        return bool(self.smtp_host and self.mail_from)

    @property
    def lead_inbox(self) -> str:
        return self.lead_notify_email or self.contact_email

    def fix_tier(self, grade: str, score: int) -> dict:
        """The 'have us fix it' price band for a report, from how much work it's likely to need."""
        if score >= 80 and grade in ("A+", "A", "B"):
            return {"code": "minor", "name": "Minor tune-up", "price_cents": self.dfy_minor_cents}
        if score >= 60:
            return {"code": "moderate", "name": "Moderate fixes", "price_cents": self.dfy_moderate_cents}
        return {"code": "critical", "name": "Urgent security overhaul", "price_cents": self.dfy_critical_cents}

    def product(self, product_id: str) -> dict | None:
        for pack in self.credit_packs:
            if pack.get("id") == product_id:
                return {**pack, "kind": "credits"}
        for plan in self.plans:
            if plan.get("id") == product_id:
                return {**plan, "kind": "plan"}
        return None


def _env_defaults() -> dict:
    env = os.environ
    values: dict = {}
    if env.get("GRADER_BRAND"):
        values["brand_name"] = env["GRADER_BRAND"]
    if env.get("GRADER_BRAND_URL"):
        values["brand_url"] = env["GRADER_BRAND_URL"]
    for key, name in (("rate_limit", "GRADER_RATE_LIMIT"), ("max_concurrent", "GRADER_MAX_CONCURRENT")):
        if env.get(name, "").isdigit():
            values[key] = int(env[name])
    if env.get("GRADER_TRUST_PROXY"):
        values["trust_proxy"] = True
    return values


class SettingsStore:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else data_dir() / "settings.json"
        self._lock = threading.Lock()
        self.current = self._load()

    def _load(self) -> Settings:
        settings = Settings(**_env_defaults())
        if not self.path.exists():
            return settings
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SettingsError(f"Can't read {self.path}: {exc}") from exc
        defaults = Settings()
        for f in fields(Settings):
            if f.name not in data:
                continue
            value, default = data[f.name], getattr(defaults, f.name)
            expected = type(default)
            if expected is float and isinstance(value, int) and not isinstance(value, bool):
                value = float(value)
            if expected is list and isinstance(value, list):
                item_type = dict if f.name in ("credit_packs", "plans") else str
                value = [item for item in value if isinstance(item, item_type)]
            # Ignore hand-edited values of the wrong type rather than crashing later.
            if isinstance(value, expected) and not (expected is not bool and isinstance(value, bool)):
                setattr(settings, f.name, value)
        return settings

    def save(self, settings: Settings) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_name(self.path.name + ".tmp")
            temp.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
            if os.name != "nt":
                os.chmod(temp, 0o600)  # holds password hash, session key and API secrets
            os.replace(temp, self.path)
            self.current = settings

    def update(self, **changes) -> Settings:
        settings = replace(self.current, **changes)
        self.save(settings)
        return settings

    def ensure_secret_key(self) -> None:
        if not self.current.secret_key:
            self.update(secret_key=secrets.token_hex(32))


def load_settings() -> Settings:
    """Current settings for read-only use (the CLI); defaults if the file is missing."""
    return SettingsStore().current


# --- form validation -------------------------------------------------------------------------------

_URL = re.compile(r"^https?://[^\s/?#]+\.[^\s]*$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE = re.compile(r"^[+0-9 ().-]{5,40}$")


class _Form:
    """Reads and validates one settings form, collecting every problem instead of stopping at the first."""

    def __init__(self, data: Mapping[str, str], current: Settings) -> None:
        self.data, self.current = data, current
        self.errors: list[str] = []

    def raw(self, name: str) -> str:
        return (self.data.get(name) or "").strip()

    def text(self, name: str, label: str, limit: int, *, multiline: bool = False) -> str:
        value = self.raw(name).replace("\r\n", "\n")
        if len(value) > limit:
            self.errors.append(f"{label} must be {limit} characters or fewer.")
        elif not all(ch.isprintable() or (multiline and ch == "\n") for ch in value):
            self.errors.append(f"{label} contains characters that aren't allowed.")
        return value[:limit]

    def url(self, name: str, label: str, *, strip_slash: bool = False) -> str:
        value = self.text(name, label, 200)
        if strip_slash:
            value = value.rstrip("/")
        if value and not _URL.match(value):
            self.errors.append(f"{label} must be a full address starting with https:// (or http://).")
        return value

    def email(self, name: str, label: str) -> str:
        value = self.text(name, label, 120)
        if value and not _EMAIL.match(value):
            self.errors.append(f"{label} doesn't look like an email address.")
        return value

    def number(self, name: str, label: str, cast, low, high):
        raw = self.raw(name)
        try:
            value = cast(raw)
        except ValueError:
            self.errors.append(f"{label} must be a number.")
            return getattr(self.current, name, low)
        if not low <= value <= high:
            self.errors.append(f"{label} must be between {low} and {high}.")
            return getattr(self.current, name, low)
        return value

    def rands(self, name: str, label: str) -> int:
        raw = self.raw(name).replace("R", "").replace(" ", "").replace(",", "")
        try:
            cents = int((Decimal(raw) * 100).quantize(Decimal("1")))
        except (InvalidOperation, ValueError):
            self.errors.append(f"{label} must be an amount in rand, e.g. 199.00.")
            return 0
        if cents < MIN_PRICE_CENTS:
            self.errors.append(f"{label} must be at least R2.00 (Yoco's minimum).")
        return cents

    def flag(self, name: str) -> bool:
        return self.data.get(name) == "on"

    def secret(self, name: str, label: str) -> str:
        """Blank keeps the stored value, so secrets never have to be shown again."""
        value = self.text(name, label, 300)
        return value or getattr(self.current, name)


def general_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    phone = form.text("contact_phone", "Contact phone", 40)
    if phone and not _PHONE.match(phone):
        form.errors.append("Contact phone may only contain digits, spaces, +, -, ( and ).")
    nameservers = [part for part in re.split(r"[,;\s]+", data.get("nameservers") or "") if part]
    for server in nameservers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            form.errors.append(f"DNS server '{server}' must be an IP address, e.g. 1.1.1.1.")
    user_agent = form.text("user_agent", "Scanner user agent", 200)
    if user_agent and not user_agent.isascii():
        form.errors.append("Scanner user agent may only contain plain ASCII characters.")
    updated = replace(
        current,
        site_url=form.url("site_url", "Website address of this grader", strip_slash=True),
        brand_name=form.text("brand_name", "Business name", 80),
        brand_url=form.url("brand_url", "Business website"),
        contact_email=form.email("contact_email", "Contact email"),
        contact_phone=phone,
        cta_text=form.text("cta_text", "Call-to-action text", 160),
        timeout=form.number("timeout", "Network timeout", float, 2, 30),
        nameservers=nameservers[:4],
        user_agent=user_agent,
        rate_limit=form.number("rate_limit", "Scans per account", int, 1, 1000),
        max_concurrent=form.number("max_concurrent", "Simultaneous scans", int, 1, 32),
        trust_proxy=form.flag("trust_proxy"),
    )
    return updated, form.errors


def payments_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    secret_key = form.secret("yoco_secret_key", "Yoco secret key")
    if secret_key and not secret_key.replace("_", "").startswith(("sktest", "sklive")):
        form.errors.append("The Yoco secret key should start with sk_test_ or sk_live_ (copy it from the Yoco app).")
    packs = []
    for i in range(MAX_PACKS):
        name = form.text(f"pack_{i}_name", f"Credit pack {i + 1} name", 60)
        if not name:
            continue
        packs.append({"id": f"pack-{i + 1}", "name": name,
                      "credits": form.number(f"pack_{i}_credits", f"Credit pack {i + 1} credits", int, 1, 10000),
                      "price_cents": form.rands(f"pack_{i}_price", f"Credit pack {i + 1} price")})
    plans = []
    for i in range(MAX_PLANS):
        name = form.text(f"plan_{i}_name", f"Plan {i + 1} name", 60)
        if not name:
            continue
        plans.append({"id": f"plan-{i + 1}", "name": name,
                      "price_cents": form.rands(f"plan_{i}_price", f"Plan {i + 1} price"),
                      "scans": form.number(f"plan_{i}_scans", f"Plan {i + 1} checks", int, 0, 100000),
                      "days": form.number(f"plan_{i}_days", f"Plan {i + 1} length", int, 1, 366)})
    if not packs and not plans:
        form.errors.append("Offer at least one credit pack or plan.")
    updated = replace(
        current,
        yoco_secret_key=secret_key,
        yoco_webhook_secret=form.secret("yoco_webhook_secret", "Yoco webhook secret"),
        signup_credits=form.number("signup_credits", "Free credits on sign-up", int, 0, 100),
        charge_for_checks=form.flag("charge_for_checks"),
        credit_packs=packs,
        plans=plans,
    )
    return updated, form.errors


def invoices_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    vat_registered = form.flag("vat_registered")
    vat_number = form.text("vat_number", "VAT number", 20)
    if vat_registered and not re.fullmatch(r"4\d{9}", vat_number.replace(" ", "")):
        form.errors.append("A South African VAT number has 10 digits and starts with 4.")
    prefix = form.text("invoice_prefix", "Invoice number prefix", 12).upper()
    if not re.fullmatch(r"[A-Z0-9-]{1,12}", prefix):
        form.errors.append("Invoice number prefix may only use letters, digits and dashes.")
    updated = replace(
        current,
        legal_name=form.text("legal_name", "Registered business name", 120),
        business_address=form.text("business_address", "Business address", 400, multiline=True),
        registration_number=form.text("registration_number", "Company registration number", 40),
        vat_registered=vat_registered,
        vat_number=vat_number.replace(" ", ""),
        vat_rate=form.number("vat_rate", "VAT rate", float, 0, 30),
        invoice_prefix=prefix or "INV",
        invoice_notes=form.text("invoice_notes", "Invoice notes", 600, multiline=True),
    )
    return updated, form.errors


def email_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    mail_from = form.text("mail_from", "From address", 160)
    if mail_from and not _EMAIL.match(parseaddr(mail_from)[1]):
        form.errors.append("From address must be an email address, optionally with a name: Name <noreply@example.com>.")
    security = form.raw("smtp_security")
    if security not in ("starttls", "ssl", "none"):
        form.errors.append("Choose a connection security option.")
        security = current.smtp_security
    updated = replace(
        current,
        smtp_host=form.text("smtp_host", "SMTP server", 120),
        smtp_port=form.number("smtp_port", "SMTP port", int, 1, 65535),
        smtp_security=security,
        smtp_username=form.text("smtp_username", "SMTP username", 160),
        smtp_password=form.secret("smtp_password", "SMTP password"),
        mail_from=mail_from,
    )
    return updated, form.errors


def growth_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    verification = form.text("google_site_verification", "Google verification code", 400)
    tag_value = re.search(r'content\s*=\s*["\']([^"\']+)', verification)  # accept the whole <meta> tag too
    verification = tag_value.group(1) if tag_value else verification
    if verification and not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", verification):
        form.errors.append("The Google verification code should look like 'AbC123…' (copy the content value of the meta tag).")
    updated = replace(
        current,
        free_checks_enabled=form.flag("free_checks_enabled"),
        free_checks_per_hour=form.number("free_checks_per_hour", "Free checks per visitor per hour", int, 1, 100),
        owner_unlock_free=form.flag("owner_unlock_free"),
        dfy_enabled=form.flag("dfy_enabled"),
        dfy_minor_cents=form.rands("dfy_minor", "Minor tune-up price"),
        dfy_moderate_cents=form.rands("dfy_moderate", "Moderate fixes price"),
        dfy_critical_cents=form.rands("dfy_critical", "Urgent overhaul price"),
        lead_notify_email=form.email("lead_notify_email", "Send fix requests to"),
        google_site_verification=verification,
    )
    return updated, form.errors


def legal_from_form(current: Settings, data: Mapping[str, str]) -> tuple[Settings, list[str]]:
    form = _Form(data, current)
    updated = replace(
        current,
        terms_text=form.text("terms_text", "Terms", 20000, multiline=True),
        privacy_text=form.text("privacy_text", "Privacy policy", 20000, multiline=True),
    )
    return updated, form.errors
