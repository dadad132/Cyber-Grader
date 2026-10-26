"""PDF version of a report (A4), for downloads and email attachments. Needs the reportlab package."""
from __future__ import annotations

import io
from html import escape

from .models import Report, Status
from .report import METHODOLOGY, VERDICTS, Branding

SEVERITY_COLOURS = {"critical": "#c22a1f", "high": "#c4480a", "medium": "#996200", "low": "#1f5bd6"}
GRADE_COLOURS = {"A+": "#16803c", "A": "#16803c", "B": "#4a8a12", "C": "#b07600", "D": "#c9560a", "F": "#c22a1f"}


class PdfUnavailable(RuntimeError):
    pass


def report_pdf(report: Report, branding: Branding | None = None, *, recipient: str = "", powered_by: str = "",
               authorised_by: str = "") -> bytes:
    """powered_by adds a small credit line (white-label reports); authorised_by notes who approved the checks."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise PdfUnavailable("PDF reports need the reportlab package: pip install -r requirements.txt") from exc

    branding = branding or Branding()
    business = branding.name or "Cyber Hygiene Grader"
    styles = getSampleStyleSheet()
    title = ParagraphStyle("T", parent=styles["Heading1"], fontSize=17, textColor=colors.HexColor("#16191d"), spaceAfter=2)
    sub = ParagraphStyle("S", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#5d6672"), spaceAfter=10)
    section = ParagraphStyle("H", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#16191d"),
                             spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("B", parent=styles["Normal"], fontSize=8.5, leading=12, textColor=colors.HexColor("#1e293b"))
    grid = colors.HexColor("#d5d9e0")
    header_bg = colors.HexColor("#1e293b")

    def table(rows, widths, header_colour=header_bg):
        t = Table(rows, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), header_colour), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.5, grid),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    story = [
        Paragraph(f"{escape(business)}: domain health report for {escape(report.display_domain)}", title),
        Paragraph(f"Checked {report.scanned_at:%d %b %Y, %H:%M} UTC" + (f" · Prepared for {escape(recipient)}" if recipient else "")
                  + (f" · Website {escape(report.homepage_url)}" if report.homepage_url else "")
                  + (f" · Checks authorised by {escape(authorised_by)}" if authorised_by else ""), sub),
    ]
    grade_colour = colors.HexColor(GRADE_COLOURS.get(report.grade, "#6b7280"))
    summary = table([["Grade", "Score", "Verdict"],
                     [report.grade, f"{report.score} / 100", Paragraph(escape(VERDICTS.get(report.grade, "")), body)]],
                    [60, 70, 390])
    summary.setStyle(TableStyle([("TEXTCOLOR", (0, 1), (0, 1), grade_colour), ("FONTNAME", (0, 1), (1, 1), "Helvetica-Bold"),
                                 ("FONTSIZE", (0, 1), (0, 1), 16)]))
    story.append(summary)
    if report.grade_note:
        story += [Spacer(1, 5), Paragraph(f"<b>Note:</b> {escape(report.grade_note)}", body)]

    story.append(Paragraph("Scores by area", section))
    rows = [["Area", "Points", "Score"]]
    for cat in report.categories:
        rows.append([cat.name, f"{cat.points:g} / {cat.max_points:g}" if cat.max_points else "not applicable",
                     f"{cat.percent}%" if cat.percent is not None else "n/a"])
    story.append(table(rows, [260, 130, 130]))

    story.append(Paragraph(f"What to fix ({len(report.findings)})", section))
    if report.findings:
        rows = [["Severity", "Check", "Problem and how to fix it"]]
        for r in report.findings:
            colour = SEVERITY_COLOURS.get(r.severity.value, "#5d6672")
            detail = f"{escape(r.summary)}"
            if r.fix:
                detail += f"<br/><font color='#16803c'><b>Fix:</b> {escape(r.fix)}</font>"
            if r.evidence:
                detail += f"<br/><font face='Courier' size='7' color='#5d6672'>{escape(r.evidence[:400]).replace(chr(10), '<br/>')}</font>"
            rows.append([Paragraph(f"<font color='{colour}'><b>{r.severity.value.upper()}</b></font>", body),
                         Paragraph(f"<b>{escape(r.title)}</b><br/><font size='7.5' color='#5d6672'>{escape(r.category)}</font>", body),
                         Paragraph(detail, body)])
        story.append(table(rows, [62, 118, 340]))
    else:
        story.append(Paragraph("Nothing to fix: every scored check passed.", body))

    passed = [r for r in report.results if r.status is Status.PASS and r.max_points > 0]
    if passed:
        story.append(Paragraph(f"Passing ({len(passed)})", section))
        for r in passed:
            story.append(Paragraph(f"&#10003; <b>{escape(r.title)}:</b> {escape(r.summary)}", body))
            story.append(Spacer(1, 2))

    contact = " · ".join(part for part in (branding.email, branding.phone, branding.url) if part)
    story += [Spacer(1, 14), Paragraph(f"{escape(branding.cta or 'Want help closing these gaps?')} "
                                       f"<b>{escape(business)}</b>{' · ' + escape(contact) if contact else ''}", sub),
              Paragraph(escape(METHODOLOGY), sub)]
    if powered_by:
        story.append(Paragraph(f"Powered by {escape(powered_by)}", sub))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=34, bottomMargin=34,
                            title=f"{report.display_domain} domain health report", author=business)
    doc.build(story)
    return buffer.getvalue()
