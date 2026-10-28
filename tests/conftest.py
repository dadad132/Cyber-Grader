import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cybergrader.context import ScanContext  # noqa: E402
from cybergrader.net import HttpResult  # noqa: E402


class FakeDNS:
    """In-memory stand-in for DNSClient."""

    def __init__(self, txt=None, mx=None, caa=None, ds=(), zone=None, addresses=None, a=None, ptr=None):
        self.txt_records = txt or {}
        self.mx_records = mx or {}
        self.caa_records = caa or {}
        self.ds_zones = set(ds)
        self.zone = zone
        self.address_records = addresses or {}
        self.a_records = a or {}
        self.ptr_records = ptr or {}

    def ipv4(self, name):
        return list(self.a_records.get(name, []))

    def ptr(self, ip):
        return list(self.ptr_records.get(ip, []))

    def txt(self, name):
        return list(self.txt_records.get(name, []))

    def mx(self, name):
        return list(self.mx_records.get(name, []))

    def caa(self, name):
        return list(self.caa_records.get(name, []))

    def has_ds(self, zone):
        return zone in self.ds_zones

    def zone_apex(self, name):
        return self.zone or name

    def addresses(self, name):
        return list(self.address_records.get(name, ["93.184.215.14"]))

    def exists(self, name):
        return True


@pytest.fixture
def make_ctx():
    def factory(domain="example.com", headers=None, cookies=None, **dns):
        ctx = ScanContext(domain, FakeDNS(**dns))
        if headers is not None or cookies is not None:
            ctx.memo.seed("web_host", domain)
            ctx.memo.seed("homepage", HttpResult(f"https://{domain}/", 200,
                                                 {k.lower(): v for k, v in (headers or {}).items()}, cookies or []))
        return ctx

    return factory


# --- web app fixtures ------------------------------------------------------------------------------

def fake_report(domain="example.com", grade_points=8.0):
    """A small but real Report, as if the scanner had run."""
    from datetime import datetime, timezone

    from cybergrader.grader import build_report
    from cybergrader.models import CheckResult, Severity, Status

    results = [
        CheckResult("spf", "Email Security", "SPF sender policy", Status.PASS, Severity.INFO, 10, 10, "SPF is fine."),
        CheckResult("dmarc", "Email Security", "DMARC enforcement", Status.FAIL, Severity.HIGH, 0, 15, "No DMARC.", "Add DMARC."),
        CheckResult("hsts", "Web Security Headers", "HSTS", Status.PASS, Severity.INFO, grade_points, 7, "HSTS on."),
    ]
    return build_report(ScanContext(domain, FakeDNS()), results, datetime.now(timezone.utc), 1.2)


@pytest.fixture
def app(tmp_path, monkeypatch):
    from cybergrader import admin as admin_module
    from cybergrader.selfcheck import SystemCheck
    from cybergrader.service import GraderService
    from cybergrader.settings import SettingsStore
    from cybergrader.webapp import create_app

    monkeypatch.setattr(admin_module, "run_selfcheck", lambda settings, folder: [SystemCheck("Python", "ok", "fine")])
    scanned = []

    def scan(self, domain, *, client=None):
        scanned.append(domain)
        return fake_report(domain)

    monkeypatch.setattr(GraderService, "scan", scan)
    monkeypatch.setattr("cybergrader.site.send_later", lambda *args, **kwargs: None)
    store = SettingsStore(tmp_path / "settings.json")
    store.update(site_url="", signup_credits=2)
    application = create_app(store)
    application.config["TESTING"] = True
    application.scanned = scanned
    return application


def csrf_from(client, path):
    import re

    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def signup(client, email="ann@example.com", password="correct horse battery", name="Ann Example"):
    token = csrf_from(client, "/signup")
    return client.post("/signup", data={"csrf": token, "name": name, "email": email, "password": password,
                                        "company": "Example Ltd", "terms": "on"})


@pytest.fixture(autouse=True)
def _no_real_email(monkeypatch):
    """No test ever talks to an SMTP server."""
    monkeypatch.setattr("cybergrader.leads.send_later", lambda *args, **kwargs: None)
    monkeypatch.setattr("cybergrader.preview.send_later", lambda *args, **kwargs: None)
    monkeypatch.setattr("cybergrader.clients.send_later", lambda *args, **kwargs: None)
    monkeypatch.setattr("cybergrader.admin.send_later", lambda *args, **kwargs: None)
