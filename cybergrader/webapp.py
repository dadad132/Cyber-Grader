"""The website: landing page, customer accounts with paid checks (Yoco), invoices, JSON API and super-admin portal.

On a PC:   python -m cybergrader.webapp --open          (or double-click "Start Grader.bat")
On a server: sudo bash install.sh grader.yourdomain.co.za you@yourdomain.co.za   (AlmaLinux; see README)

All settings live in the data folder (settings.json + grader.db) and are edited in the super-admin portal.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import webbrowser
from datetime import timedelta

from flask import Flask, g, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .admin import create_admin_blueprint
from .checks import all_checks
from .clients import create_clients_blueprint
from .billing import money
from .db import iso, migrate, utcnow
from .preview import create_preview_blueprint
from .report import BASE_CSS, SUBMIT_SCRIPT, SUBMIT_SCRIPT_CSP, _tone
from .security import csrf_field
from .seo import TOOLS, create_seo_blueprint
from .service import GraderService
from .settings import SettingsError, SettingsStore
from .site import create_site_blueprint, format_date

# Pages search engines may index; everything else (accounts, reports, admin) is marked noindex.
INDEXABLE = {"site.landing", "site.pricing", "site.terms", "site.privacy"} | {
    f"seo.tool_{slug.replace('-', '_')}" for slug in TOOLS}

ERRORS = {
    400: ("Something went wrong", "That request didn't work. Go back, reload the page and try again."),
    403: ("Not allowed", "You don't have access to that page."),
    404: ("Page not found", "That page doesn't exist or isn't yours to see."),
    500: ("Something went wrong", "An unexpected error occurred. Please try again in a moment."),
}


class _ProxySwitch:
    """Trusts X-Forwarded-* headers only while the 'behind a reverse proxy' setting is on."""

    def __init__(self, app, store: SettingsStore) -> None:
        self.app, self.store = app, store
        self.proxied = ProxyFix(app, x_for=1, x_proto=1, x_host=1)

    def __call__(self, environ, start_response):
        target = self.proxied if self.store.current.trust_proxy else self.app
        return target(environ, start_response)


def create_app(store: SettingsStore | None = None) -> Flask:
    store = store or SettingsStore()
    store.ensure_secret_key()
    service = GraderService(store)
    migrate(service.db_path)

    app = Flask(__name__)
    app.secret_key = store.current.secret_key
    app.config.update(
        DB_PATH=str(service.db_path),
        SESSION_COOKIE_NAME="grader_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=store.current.site_url.startswith("https://"),
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    app.wsgi_app = _ProxySwitch(app.wsgi_app, store)
    app.extensions["grader"] = service
    app.register_blueprint(create_site_blueprint(service))
    app.register_blueprint(create_preview_blueprint(service))
    app.register_blueprint(create_clients_blueprint(service))
    app.register_blueprint(create_seo_blueprint(service))
    app.register_blueprint(create_admin_blueprint(service))

    app.add_template_filter(format_date, "date")
    app.add_template_filter(_tone, "tone")
    app.add_template_filter(lambda value: f"{value:g}", "num")
    app.add_template_filter(json.loads, "fromjson")

    @app.context_processor
    def template_globals():
        base = store.current.site_url.rstrip("/") or request.host_url.rstrip("/")
        return {"site": store.current, "current_user": g.get("user"), "csrf_field": csrf_field, "money": money,
                "check_count": sum(1 for spec in all_checks() if spec.max_points),  # scored checks
                "base_css": BASE_CSS, "page_script": SUBMIT_SCRIPT, "now_iso": iso(utcnow()),
                "canonical_url": base + request.path, "indexable": request.endpoint in INDEXABLE}

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        if exc.code not in ERRORS or exc.code == 405:
            return exc
        heading, message = ERRORS[exc.code]
        if exc.code == 400 and exc.description and "session" in exc.description:
            message = exc.description
        return render_template("error.html", code=exc.code, heading=heading, message=message), exc.code

    @app.errorhandler(500)
    def server_error(_exc):
        heading, message = ERRORS[500]
        return render_template("error.html", code=500, heading=heading, message=message), 500

    @app.after_request
    def security_headers(response):
        # The grader's own pages should pass its own header checks. form-action allows Yoco because the
        # "Buy" form redirects there, and browsers apply form-action to redirects too.
        response.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'none'; style-src 'unsafe-inline'; script-src {SUBMIT_SCRIPT_CSP}; img-src 'self' data:; "
            "form-action 'self' https://*.yoco.com; frame-ancestors 'none'; base-uri 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if store.current.site_url.startswith("https://"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if response.mimetype == "text/html" and not response.headers.get("Cache-Control"):
            response.headers["Cache-Control"] = "no-store"  # pages show account data
        return response

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the grader website and super-admin portal on this computer.")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default: this computer only)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--open", action="store_true", help="open the super-admin portal in your browser")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        store = SettingsStore()
        app = create_app(store)
    except SettingsError as exc:
        sys.exit(f"{exc}\nFix or delete that file and start again.")
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    base = f"http://{shown_host}:{args.port}"
    first_run = "" if store.current.admin_password_hash else "   (first visit: create your admin password)"
    print(f"\n  Website:       {base}/\n  Super admin:   {base}/admin/{first_run}\n  Data folder:   {store.path.parent}\n"
          "  Press Ctrl+C to stop.\n", flush=True)
    if args.open:
        threading.Timer(1.5, webbrowser.open, [f"{base}/admin/"]).start()
    try:
        app.run(host=args.host, port=args.port, threaded=True)
    except OSError as exc:
        sys.exit(f"Couldn't start on port {args.port} ({exc}). Is it already running? Try --port 8080.")


if __name__ == "__main__":
    main()
