"""Outgoing email over SMTP: password resets, invoices, plan reminders and welcome messages."""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr

from .settings import Settings

log = logging.getLogger(__name__)


class MailError(Exception):
    pass


def send_mail(settings: Settings, to: str, subject: str, text: str,
              attachments: list[tuple[str, bytes, str]] | None = None, *, from_name: str = "", reply_to: str = "") -> None:
    """Send a plain-text email; attachments are (filename, data, mime type) tuples.
    from_name/reply_to send it on someone's behalf (e.g. an IT firm) from our own address."""
    if not settings.email_ready:
        raise MailError("Email isn't set up yet (Super admin > Settings > Email).")
    message = EmailMessage()
    message["From"] = formataddr((from_name, parseaddr(settings.mail_from)[1])) if from_name else settings.mail_from
    if reply_to:
        message["Reply-To"] = reply_to
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    sender_domain = parseaddr(settings.mail_from)[1].rpartition("@")[2] or None
    message["Message-ID"] = make_msgid(domain=sender_domain)
    message.set_content(text)
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    context = ssl.create_default_context()
    try:
        if settings.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        with server:
            if settings.smtp_security == "starttls":
                server.starttls(context=context)
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"Sending to {to} failed: {exc}") from exc


def send_later(settings: Settings, to: str, subject: str, text: str,
               attachments: list[tuple[str, bytes, str]] | None = None) -> None:
    """Send in the background so a slow mail server never holds up a page; failures are logged."""
    if not settings.email_ready:
        log.info("Email not configured; skipped %r to %s", subject, to)
        return

    def run() -> None:
        try:
            send_mail(settings, to, subject, text, attachments)
        except MailError as exc:
            log.error("%s", exc)

    threading.Thread(target=run, daemon=True).start()
