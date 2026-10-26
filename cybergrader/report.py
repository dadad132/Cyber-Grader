"""Renders a Report as terminal text or as a self-contained HTML page."""
from __future__ import annotations

import base64
import hashlib
import re
import textwrap
from dataclasses import dataclass
from html import escape

from .models import CheckResult, Report, Severity

VERDICTS = {
    "A+": "Excellent. This domain follows current best practice across the board.",
    "A": "Strong. Only minor improvements remain.",
    "B": "Good, with some gaps worth closing.",
    "C": "Fair. Several important protections are missing.",
    "D": "Weak. Attackers have easy openings here.",
    "F": "Failing. Urgent fixes are needed.",
    "N/A": "The scan couldn't complete enough checks to grade this domain.",
}

METHODOLOGY = (
    "This grade comes from passive, non-intrusive checks of public information: DNS records, one HTTPS page load, "
    "a few TLS handshakes and two well-known files. No ports were scanned and nothing was logged into. "
    "Results reflect the moment of the scan."
)


def _tone(grade_or_percent: str | int | None) -> str:
    if isinstance(grade_or_percent, int):
        return next(t for floor, t in ((90, "a"), (80, "b"), (65, "c"), (50, "d"), (0, "f")) if grade_or_percent >= floor)
    return {"A+": "a", "A": "a", "B": "b", "C": "c", "D": "d", "F": "f"}.get(grade_or_percent or "", "na")


def _pts(value: float) -> str:
    return f"{value:g}"


# --- Terminal ------------------------------------------------------------------------------------

_ANSI = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "red": "\033[31m", "green": "\033[32m",
         "yellow": "\033[33m", "cyan": "\033[36m"}
_TONE_ANSI = {"a": "green", "b": "green", "c": "yellow", "d": "red", "f": "red", "na": "dim"}
_SEVERITY_ANSI = {Severity.CRITICAL: ("red", "bold"), Severity.HIGH: ("red",), Severity.MEDIUM: ("yellow",),
                  Severity.LOW: ("cyan",), Severity.INFO: ("dim",)}


def render_text(report: Report, *, color: bool = False, unicode: bool = True, verbose: bool = False,
                width: int = 100) -> str:
    def paint(text: str, *styles: str) -> str:
        if not color or not styles:
            return text
        return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]

    def wrap(text: str, indent: str, first: str | None = None) -> list[str]:
        return textwrap.wrap(text, width, initial_indent=first if first is not None else indent,
                             subsequent_indent=indent) or [first or indent]

    full, empty, tick, sep = ("█", "░", "✓", "·") if unicode else ("#", "-", "+", "-")
    out = [paint(f"Cyber hygiene report: {report.display_domain}", "bold")]
    meta = f"Scanned {report.scanned_at:%Y-%m-%d %H:%M} UTC in {report.duration:.1f}s"
    if report.homepage_url:
        meta += f" {sep} website {report.homepage_url}"
    out += [paint(meta, "dim"), ""]
    out.append(f"  Grade {paint(f' {report.grade} ', 'bold', _TONE_ANSI[_tone(report.grade)])}   Score {report.score}/100")
    out.append("  " + VERDICTS.get(report.grade, ""))
    if report.grade_note:
        out += [paint(line, "dim") for line in wrap(report.grade_note, "  ")]
    out.append("")
    for cat in report.categories:
        if cat.percent is None:
            out.append(f"  {cat.name:<22} {'not applicable':>16}")
            continue
        filled = round(cat.percent / 10)
        bar = paint(full * filled + empty * (10 - filled), _TONE_ANSI[_tone(cat.percent)])
        out.append(f"  {cat.name:<22} {bar} {cat.percent:>4}%   {_pts(cat.points)}/{_pts(cat.max_points)}")

    def evidence(result: CheckResult, indent: str) -> list[str]:
        if not (verbose and result.evidence):
            return []
        return [paint(indent + line, "dim") for line in result.evidence.splitlines()]

    findings = report.findings
    out += ["", paint(f"What to fix ({len(findings)})", "bold")]
    if not findings:
        out.append("  Nothing! Every scored check passed.")
    for r in findings:
        label = paint(f"{r.severity.value.upper():<9}", *_SEVERITY_ANSI[r.severity])
        out.append(f"  {label} {paint(r.title, 'bold')} {paint(f'({r.category})', 'dim')}")
        out += wrap(r.summary, " " * 12)
        if r.fix:
            out += wrap(r.fix, " " * 17, first=" " * 12 + "Fix: ")
        out += evidence(r, " " * 12)
    sections = (
        (f"Passing ({len(report.passed)})", report.passed, paint(tick, "green")),
        (f"Not tested ({len(report.skipped)})", report.skipped, "-"),
        (f"Couldn't determine ({len(report.errors)})", report.errors, paint("?", "yellow")),
        ("Notes", report.notes, "i"),
    )
    for heading, results, icon in sections:
        if not results:
            continue
        out += ["", paint(heading, "bold")]
        for r in results:
            out += wrap(f"{r.title}: {r.summary}", "    ", first=f"  {icon} ")
            out += evidence(r, "    ")
    return "\n".join(out)


# --- HTML ----------------------------------------------------------------------------------------

SUBMIT_SCRIPT = (
    'document.querySelectorAll("form.scan,form[data-busy]").forEach(function(f){f.addEventListener("submit",function(){'
    'var b=f.querySelector("button[type=submit]");if(b){b.disabled=true;'
    'b.textContent=f.getAttribute("data-busy")||"Scanning\\u2026";}});});'
    'document.querySelectorAll("[data-print]").forEach(function(b){b.addEventListener("click",function(){window.print();});});'
)
# CSP source that allows exactly SUBMIT_SCRIPT and no other inline script.
SUBMIT_SCRIPT_CSP = "'sha256-" + base64.b64encode(hashlib.sha256(SUBMIT_SCRIPT.encode()).digest()).decode() + "'"

BASE_CSS = """
:root{--bg:#f5f6f8;--surface:#fff;--surface-2:#eff1f4;--text:#16191d;--muted:#5d6672;--border:#e1e4e9;
--accent:#1f5bd6;--accent-text:#fff;--grade-text:#fff;
--a:#16803c;--b:#4a8a12;--c:#b07600;--d:#c9560a;--f:#c22a1f;--na:#6b7280;
--crit:#c22a1f;--crit-bg:#fdeceb;--high:#c4480a;--high-bg:#fff0e5;--med:#996200;--med-bg:#fff5db;--low:#1f5bd6;--low-bg:#e9f0fd;
--ok:#16803c;--ok-bg:#e4f4e9;--radius:14px;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--surface:#171a20;--surface-2:#1f232b;--text:#e8eaee;--muted:#9aa3ae;--border:#2a2f38;
--accent:#6d9bff;--accent-text:#0f1115;--grade-text:#0f1115;
--a:#45c26f;--b:#93c947;--c:#e2ab33;--d:#f2843b;--f:#f25c50;--na:#9aa3ae;
--crit:#ff7266;--crit-bg:#3a1714;--high:#ff9d5c;--high-bg:#3a2112;--med:#f0c04d;--med-bg:#352a10;--low:#86adff;--low-bg:#16233d;
--ok:#4fca7d;--ok-bg:#12301d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:0 16px}
.topbar{background:var(--surface);border-bottom:1px solid var(--border)}
.topbar-inner{display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding-top:12px;padding-bottom:12px}
.brand{font-weight:700;color:var(--text);text-decoration:none;letter-spacing:-.01em}
.scan{display:flex;gap:8px;flex:1;max-width:420px}
.scan input{flex:1;min-width:0;padding:9px 12px;border:1px solid var(--border);border-radius:10px;background:var(--bg);color:var(--text);font:inherit}
.scan input:focus{outline:2px solid var(--accent);outline-offset:1px}
.scan button{padding:9px 16px;border:0;border-radius:10px;background:var(--accent);color:var(--accent-text);font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}
.scan button:disabled{opacity:.7;cursor:progress}
.hero{display:flex;gap:24px;align-items:center;padding:32px 0 8px}
.grade{flex:none;width:112px;height:112px;border-radius:24px;display:grid;place-items:center;font-size:54px;font-weight:800;color:var(--grade-text);letter-spacing:-.04em}
.tone-a{background:var(--a)}.tone-b{background:var(--b)}.tone-c{background:var(--c)}.tone-d{background:var(--d)}.tone-f{background:var(--f)}.tone-na{background:var(--na)}
.eyebrow{margin:0;color:var(--muted);font-size:12.5px;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
h1{margin:2px 0 4px;font-size:30px;line-height:1.2;letter-spacing:-.02em;overflow-wrap:anywhere}
.verdict{margin:0 0 6px;font-size:17px}
.meta{margin:0;color:var(--muted);font-size:13.5px;overflow-wrap:anywhere}
.cap{margin:10px 0 0;padding:8px 12px;border-radius:10px;background:var(--surface-2);font-size:14px}
.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:24px 0 8px}
.cat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
.cat-name{display:block;font-size:13.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cat-row{display:flex;justify-content:space-between;align-items:baseline;gap:8px;margin-top:2px}
.cat-row strong{font-size:24px;letter-spacing:-.02em}
.cat-row span{font-size:12.5px;color:var(--muted)}
.bar{height:8px;border-radius:99px;background:var(--surface-2);overflow:hidden;margin-top:8px}
.bar span{display:block;height:100%;border-radius:99px}
h2{font-size:19px;margin:36px 0 12px;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
.count{font-size:13px;font-weight:600;color:var(--muted);background:var(--surface-2);border-radius:99px;padding:1px 9px}
.sev-critical{--sev:var(--crit);--sev-bg:var(--crit-bg)}.sev-high{--sev:var(--high);--sev-bg:var(--high-bg)}
.sev-medium{--sev:var(--med);--sev-bg:var(--med-bg)}.sev-low{--sev:var(--low);--sev-bg:var(--low-bg)}
.finding{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--sev);border-radius:var(--radius);padding:14px 18px;margin-bottom:12px}
.finding-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.finding h3{margin:0;font-size:16px}
.finding-cat{margin-left:auto;color:var(--muted);font-size:13px}
.pill{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:99px;color:var(--sev);background:var(--sev-bg)}
.finding>p{margin:8px 0 0}
.fix{margin-top:10px;padding:10px 12px;background:var(--surface-2);border-radius:10px}
.fix-label{display:block;font-size:11.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.fix p{margin:2px 0 0;overflow-wrap:anywhere}
details{margin-top:8px;font-size:13.5px}
summary{cursor:pointer;color:var(--muted)}
pre{margin:6px 0 0;padding:10px 12px;background:var(--surface-2);border-radius:8px;font:12.5px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.checklist{list-style:none;margin:0;padding:0;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
.checklist li{display:flex;gap:12px;padding:12px 16px;border-top:1px solid var(--border)}
.checklist li:first-child{border-top:0}
.icon{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:12px;font-weight:700;margin-top:1px;background:var(--surface-2);color:var(--muted)}
.icon-ok{background:var(--ok-bg);color:var(--ok)}
.item{min-width:0;flex:1}
.item strong{display:block;font-size:14.5px}
.item p{margin:2px 0 0;color:var(--muted);font-size:14px}
.foot{padding-top:32px;padding-bottom:48px;color:var(--muted);font-size:13px}
.foot p{margin:6px 0}
.cta{margin:0 0 20px;padding:16px 18px;border-radius:var(--radius);background:var(--surface);border:1px solid var(--border);color:var(--text);font-size:15px}
.cta p{margin:0}.cta .cta-lead{font-weight:600}.cta .cta-contact{margin-top:4px;color:var(--muted);overflow-wrap:anywhere}
.cta a{color:var(--accent);font-weight:600}
.topnav{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.topnav a,.topnav button{color:var(--muted);text-decoration:none;padding:6px 10px;border-radius:8px;font:inherit;font-size:14px;background:none;border:0;cursor:pointer}
.topnav a:hover,.topnav button:hover{color:var(--text);background:var(--surface-2)}
.topnav a[aria-current]{color:var(--text);background:var(--surface-2);font-weight:600}
.landing{padding-top:56px;padding-bottom:24px;text-align:center}
.landing h1{font-size:36px}
.lede{color:var(--muted);font-size:17px;max-width:560px;margin:8px auto 24px}
.scan-lg{max-width:520px;margin:0 auto}
.scan-lg input,.scan-lg button{padding:13px 16px;font-size:16px}
.alert{max-width:520px;margin:0 auto 16px;padding:10px 14px;border-radius:10px;background:var(--crit-bg);color:var(--crit);text-align:left}
.features{list-style:none;padding:0;margin:40px auto 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;text-align:left}
.features li{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;color:var(--muted);font-size:14px}
.features strong{display:block;color:var(--text);margin-bottom:2px}
.fineprint{color:var(--muted);font-size:13px;margin-top:28px}
@media (max-width:560px){.hero{flex-direction:column;align-items:flex-start;gap:16px}
.grade{width:88px;height:88px;font-size:42px;border-radius:20px}h1,.landing h1{font-size:25px}
.finding-cat{margin-left:0;width:100%}.scan{max-width:none;flex-basis:100%}}
@media print{.topbar .scan{display:none}body{background:#fff}.finding,.cat,.checklist li{break-inside:avoid}}
"""


@dataclass
class Branding:
    """Business details shown on pages and reports (set in the admin portal or with CLI flags)."""

    name: str = ""
    url: str = ""
    email: str = ""
    phone: str = ""
    cta: str = ""


def _form(action: str, value: str = "", large: bool = False) -> str:
    return (
        f'<form class="scan{" scan-lg" if large else ""}" action="{escape(action)}" method="get" role="search">'
        f'<input name="domain" type="text" inputmode="url" autocomplete="url" spellcheck="false" required '
        f'placeholder="yourdomain.com" aria-label="Domain to grade" value="{escape(value)}">'
        f"<button type=\"submit\">Grade it</button></form>"
    )


def page_shell(title: str, topbar: str, body: str, *, script: bool = False, extra_css: str = "") -> str:
    """A complete HTML document: the shared stylesheet, a top bar and the page body."""
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{escape(title)}</title>\n<style>{BASE_CSS}{extra_css}</style>\n</head>\n<body>\n"
        f'<header class="topbar"><div class="wrap topbar-inner">{topbar}</div></header>\n'
        f"{body}\n"
        + (f"<script>{SUBMIT_SCRIPT}</script>\n" if script else "")
        + "</body>\n</html>\n"
    )


def _topbar(branding: Branding, *, home: str, form_action: str | None = None, form_value: str = "",
            nav_html: str = "") -> str:
    brand = f'<a class="brand" href="{escape(home)}">{escape(branding.name or "Cyber Hygiene Grader")}</a>'
    nav = f'<nav class="topnav">{nav_html}</nav>' if nav_html else ""
    form = _form(form_action, form_value) if form_action else ""
    return brand + nav + form


def _cta_html(branding: Branding) -> str:
    contacts = []
    if branding.name:
        contacts.append(f'<a href="{escape(branding.url)}">{escape(branding.name)}</a>' if branding.url
                        else f"<strong>{escape(branding.name)}</strong>")
    if branding.email:
        contacts.append(f'<a href="mailto:{escape(branding.email)}">{escape(branding.email)}</a>')
    if branding.phone:
        contacts.append(f'<a href="tel:{re.sub(r"[^0-9+]", "", branding.phone)}">{escape(branding.phone)}</a>')
    if not contacts:
        return ""
    lead = escape(branding.cta or "Want help closing these gaps?")
    return f'<div class="cta"><p class="cta-lead">{lead}</p><p class="cta-contact">{" · ".join(contacts)}</p></div>'


def _evidence_html(result: CheckResult) -> str:
    if not result.evidence:
        return ""
    return f"<details><summary>Evidence</summary><pre>{escape(result.evidence)}</pre></details>"


def _finding_html(r: CheckResult) -> str:
    fix = f'<div class="fix"><span class="fix-label">How to fix</span><p>{escape(r.fix)}</p></div>' if r.fix else ""
    return (
        f'<article class="finding sev-{r.severity.value}"><div class="finding-head">'
        f'<span class="pill">{r.severity.value}</span><h3>{escape(r.title)}</h3>'
        f'<span class="finding-cat">{escape(r.category)}</span></div>'
        f"<p>{escape(r.summary)}</p>{fix}{_evidence_html(r)}</article>"
    )


def _checklist_html(results: list[CheckResult], icon: str, icon_class: str = "") -> str:
    items = "".join(
        f'<li><span class="icon {icon_class}" aria-hidden="true">{icon}</span><div class="item">'
        f"<strong>{escape(r.title)}</strong><p>{escape(r.summary)}</p>{_evidence_html(r)}</div></li>"
        for r in results
    )
    return f'<ul class="checklist">{items}</ul>'


def _section(title: str, count: int | None, content: str) -> str:
    badge = f' <span class="count">{count}</span>' if count is not None else ""
    return f"<section><h2>{escape(title)}{badge}</h2>{content}</section>"


def report_body(report: Report, branding: Branding | None = None, *, cta: bool = True) -> str:
    """The report itself (main content and footer), for embedding in a page."""
    branding = branding or Branding()
    tone = _tone(report.grade)
    meta = [f"Score {report.score}/100", f"{report.scanned_at:%d %b %Y, %H:%M} UTC"]
    if report.homepage_url:
        meta.append(f"website {report.homepage_url}")
    cap = f'<p class="cap">{escape(report.grade_note)}</p>' if report.grade_note else ""
    hero = (
        f'<section class="hero"><div class="grade tone-{tone}" role="img" aria-label="Grade {escape(report.grade)}">'
        f"{escape(report.grade)}</div><div>"
        f'<p class="eyebrow">Cyber hygiene report</p><h1>{escape(report.display_domain)}</h1>'
        f'<p class="verdict">{escape(VERDICTS.get(report.grade, ""))}</p>'
        f'<p class="meta">{escape(" · ".join(meta))}</p>{cap}</div></section>'
    )
    cards = []
    for cat in report.categories:
        if cat.percent is None:
            value, bar, pts = "n/a", "", "not applicable"
        else:
            value = f"{cat.percent}%"
            bar = f'<span class="tone-{_tone(cat.percent)}" style="width:{cat.percent}%"></span>'
            pts = f"{_pts(cat.points)} of {_pts(cat.max_points)} pts"
        cards.append(
            f'<div class="cat"><span class="cat-name" title="{escape(cat.name)}">{escape(cat.name)}</span>'
            f'<div class="cat-row"><strong>{value}</strong><span>{pts}</span></div><div class="bar">{bar}</div></div>'
        )
    findings = report.findings
    sections = [
        hero,
        f'<section class="cats">{"".join(cards)}</section>',
        _section("What to fix", len(findings),
                 "".join(_finding_html(r) for r in findings) or '<p class="meta">Nothing. Every scored check passed.</p>'),
    ]
    if report.passed:
        sections.append(_section("Passing", len(report.passed), _checklist_html(report.passed, "✓", "icon-ok")))
    if report.skipped:
        sections.append(_section("Not tested", len(report.skipped), _checklist_html(report.skipped, "–")))
    if report.errors:
        sections.append(_section("Couldn't determine", len(report.errors), _checklist_html(report.errors, "?")))
    if report.notes:
        sections.append(_section("Notes", None, _checklist_html(report.notes, "i")))
    footer = (
        f'<footer class="wrap foot">{_cta_html(branding) if cta else ""}<p>{escape(METHODOLOGY)}</p>'
        f"<p>Cyber Hygiene Grader v{escape(report.version)} · scan took {report.duration:.1f}s</p></footer>"
    )
    return f'<main class="wrap">{"".join(sections)}</main>\n{footer}'


def render_html(report: Report, *, branding: Branding | None = None, form_action: str | None = None,
                nav_html: str = "") -> str:
    """A complete, self-contained HTML report. form_action adds a 'grade another domain' form (web mode)."""
    branding = branding or Branding()
    body = report_body(report, branding)
    topbar = _topbar(branding, home=branding.url or form_action or "#", form_action=form_action,
                     form_value=report.display_domain, nav_html=nav_html)
    return page_shell(f"{report.display_domain}: grade {report.grade}", topbar, body, script=bool(form_action))


def render_landing(*, action: str = "/", branding: Branding | None = None, error: str | None = None,
                   domain: str = "") -> str:
    branding = branding or Branding()
    alert = f'<p class="alert" role="alert">{escape(error)}</p>' if error else ""
    body = (
        '<main class="wrap landing"><h1>How well protected is your domain?</h1>'
        '<p class="lede">A free, passive check of email spoofing protection, HTTPS, browser security headers and DNS. '
        "Results in about ten seconds.</p>"
        f"{alert}{_form(action, domain, large=True)}"
        '<ul class="features">'
        "<li><strong>Email security</strong>SPF, DMARC, DKIM and MTA-STS: can someone send email pretending to be you?</li>"
        "<li><strong>HTTPS &amp; TLS</strong>Certificate trust and expiry, protocol versions and HTTPS redirects.</li>"
        "<li><strong>Security headers</strong>HSTS, Content-Security-Policy, clickjacking and cookie protection.</li>"
        "<li><strong>Domain &amp; DNS</strong>CAA, DNSSEC and a published security contact.</li></ul>"
        f'<p class="fineprint">{escape(METHODOLOGY)}</p></main>'
    )
    topbar = _topbar(branding, home=branding.url or action)
    return page_shell(branding.name or "Cyber Hygiene Grader", topbar, body, script=True)
