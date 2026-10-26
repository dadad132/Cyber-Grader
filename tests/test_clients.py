"""IT firms managing client domains: approval by email, white-label reports and quotes."""
import re

import pytest
from conftest import csrf_from, signup

from cybergrader.db import connect


@pytest.fixture
def mail(app, monkeypatch):
    app.extensions["grader"].store.update(smtp_host="smtp.example.com", mail_from="EasyMikroTik <noreply@easymikrotik.com>",
                                          brand_name="EasyMikroTik")
    sent = []

    def fake_send(settings, to, subject, text, attachments=None, *, from_name="", reply_to=""):
        sent.append({"to": to, "subject": subject, "text": text, "attachments": attachments or [],
                     "from_name": from_name, "reply_to": reply_to})

    monkeypatch.setattr("cybergrader.clients.send_mail", fake_send)
    return sent


def _db(app):
    return connect(app.config["DB_PATH"])


def firm(app):
    client = app.test_client()
    signup(client, email="managing@itfirm.co.za", name="Mandla")
    client.post("/app/account/branding", data={"csrf": csrf_from(client, "/app/account"), "firm_name": "IT Firm (Pty) Ltd",
                                               "firm_email": "help@itfirm.co.za", "firm_phone": "+27 21 555 0000",
                                               "firm_url": "https://itfirm.co.za"})
    return client


def add_client(client, **overrides):
    data = {"csrf": csrf_from(client, "/app/clients"), "name": "Company A", "domain": "a.co.za",
            "contact_email": "compony@a.co.za", "request_approval": "on", **overrides}
    return client.post("/app/clients", data=data, follow_redirects=True)


def approval_link(mail):
    return re.search(r"https?://\S+/approve/\S+", mail[-1]["text"]).group(0).split("localhost", 1)[1]


def test_contact_must_be_at_the_clients_domain(app, mail):
    client = firm(app)
    page = add_client(client, contact_email="owner@gmail.com").get_data(as_text=True)
    assert "ending in @a.co.za" in page and not mail
    add_client(client)
    assert mail[0]["to"] == "compony@a.co.za" and "IT Firm (Pty) Ltd" in mail[0]["subject"]
    assert mail[0]["from_name"] == "IT Firm (Pty) Ltd via EasyMikroTik" and mail[0]["reply_to"] == "help@itfirm.co.za"
    assert "already in your client list" in add_client(client).get_data(as_text=True)


def test_client_approves_declines_and_revokes(app, mail):
    client = firm(app)
    add_client(client)
    link = approval_link(mail)
    visitor = app.test_client()
    page = visitor.get(link)
    assert page.status_code == 200 and "Allow IT Firm (Pty) Ltd to manage security checks for a.co.za?" in page.get_data(as_text=True)
    assert _db(app).execute("SELECT approval_status FROM clients").fetchone()[0] == "pending"  # opening the link isn't approval
    visitor.post(link, data={"csrf": csrf_from(visitor, link), "action": "approve"})
    row = _db(app).execute("SELECT * FROM clients").fetchone()
    assert (row["approval_status"], row["approved_by"]) == ("approved", "compony@a.co.za")
    visitor.post(link, data={"csrf": csrf_from(visitor, link), "action": "revoke"})
    assert _db(app).execute("SELECT approval_status FROM clients").fetchone()[0] == "revoked"
    assert app.test_client().get("/approve/not-a-real-token").status_code == 404


def test_reports_only_go_to_approved_clients(app, mail):
    client = firm(app)
    add_client(client)
    client_id = _db(app).execute("SELECT id FROM clients").fetchone()[0]
    client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "a.co.za"})
    scan_id = _db(app).execute("SELECT id FROM scans").fetchone()[0]
    detail = f"/app/clients/{client_id}"
    form = {"scan_id": scan_id, "subject": "Security check for a.co.za", "message": "Hi, see attached.",
            "quote_amount": "4500", "quote_text": "Fix SPF, DMARC and DKIM."}
    blocked = client.post(detail + "/send", data={"csrf": csrf_from(client, detail), **form}, follow_redirects=True)
    assert "needs to approve you" in blocked.get_data(as_text=True) and len(mail) == 1
    link = approval_link(mail)
    visitor = app.test_client()
    visitor.post(link, data={"csrf": csrf_from(visitor, link), "action": "approve"})
    client.post(detail + "/send", data={"csrf": csrf_from(client, detail), **form})
    email = mail[-1]
    assert email["to"] == "compony@a.co.za" and email["reply_to"] == "help@itfirm.co.za"
    assert email["from_name"] == "IT Firm (Pty) Ltd via EasyMikroTik"
    assert "R4,500.00" in email["text"] and "Fix SPF, DMARC and DKIM." in email["text"]
    assert email["attachments"][0][0] == "a.co.za-security-report.pdf" and email["attachments"][0][1].startswith(b"%PDF")
    assert _db(app).execute("SELECT quote_cents FROM client_messages").fetchone()[0] == 450000


def test_client_reports_hide_our_fix_offer(app, mail):
    client = firm(app)
    add_client(client)
    client_report = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "a.co.za"}).location
    own_report = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "itfirm.co.za"}).location
    client_page = client.get(client_report).get_data(as_text=True)
    assert "Client: <strong>Company A</strong>" in client_page and "Want us to fix it" not in client_page
    assert "Want us to fix it" in client.get(own_report).get_data(as_text=True)


def test_firm_pdfs_carry_the_firms_name(app, mail, monkeypatch):
    captured = {}

    def fake_pdf(report, branding, **kwargs):
        captured.update(branding=branding, **kwargs)
        return b"%PDF-fake"

    monkeypatch.setattr("cybergrader.site.report_pdf", fake_pdf)
    client = firm(app)
    add_client(client)
    report_url = client.post("/app/scan", data={"csrf": csrf_from(client, "/app"), "domain": "a.co.za"}).location
    client.get(report_url + "/pdf")
    assert captured["branding"].name == "IT Firm (Pty) Ltd" and captured["powered_by"] == "EasyMikroTik"
    assert captured["recipient"] == "Company A" and captured["authorised_by"] == ""


def test_clients_are_private_to_each_firm(app, mail):
    client = firm(app)
    add_client(client)
    client_id = _db(app).execute("SELECT id FROM clients").fetchone()[0]
    other = app.test_client()
    signup(other, email="eve@example.com")
    assert other.get(f"/app/clients/{client_id}").status_code == 404
    assert "<strong>Company A</strong>" not in other.get("/app/clients").get_data(as_text=True)


def test_branding_validation(app):
    client = app.test_client()
    signup(client)
    page = client.post("/app/account/branding", data={"csrf": csrf_from(client, "/app/account"), "firm_name": "X",
                                                      "firm_email": "not-an-email", "firm_phone": "", "firm_url": ""},
                       follow_redirects=True).get_data(as_text=True)
    assert "valid email address" in page
