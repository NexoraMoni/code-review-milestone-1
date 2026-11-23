"""Milestone 4 - Code Review Report Generation: exportable PDF."""
import io
import textwrap
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak
from .models import SEVERITIES, SEV_RANK

SEV_COLOR = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825", "Low": "#1565c0", "Info": "#607d8b"}


def _code(text: str, width: int = 90) -> Preformatted:
    wrapped = "\n".join("\n".join(textwrap.wrap(l, width, subsequent_indent="    ")) or "" for l in text.splitlines())
    st = ParagraphStyle("code", fontName="Courier", fontSize=7.5, leading=9.5, backColor=colors.HexColor("#f4f4f4"),
                        leftIndent=4, borderPadding=3)
    return Preformatted(wrapped, st)


def build_pdf(review) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title="Code Review Report")
    ss = getSampleStyleSheet()
    h1, h2, h3, body = ss["Title"], ss["Heading2"], ss["Heading4"], ss["BodyText"]
    sub, findings, summ = review.submission, review.findings, review.summary
    P = lambda t, s=body: Paragraph(escape(t), s)
    el = [P("AI Code Review & Security Analysis Report", h1),
          P(f"File: {sub.filename}   |   Language: {sub.language.title()}   |   Lines: {len(sub.lines)}   |   "
            f"Generated: {datetime.now():%Y-%m-%d %H:%M}"), Spacer(1, 8)]

    el += [P("1. Executive Summary", h2), P(summ["overview"]), Spacer(1, 6)]
    score_tbl = Table([["Code Health Score", "Grade", "Verdict"],
                       [f"{review.health_score} / 100", review.grade, Paragraph(escape(summ["verdict"]), body)]],
                      colWidths=[45 * mm, 25 * mm, 100 * mm])
    score_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .5, colors.grey),
                                   ("FONTSIZE", (0, 1), (1, 1), 14), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    el += [score_tbl, Spacer(1, 10), P("2. Severity Breakdown", h2)]
    rows = [["Severity", "Count"]] + [[s, str(summ["counts"][s])] for s in SEVERITIES]
    t = Table(rows, colWidths=[50 * mm, 25 * mm])
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("GRID", (0, 0), (-1, -1), .5, colors.grey)]
    for i, s in enumerate(SEVERITIES, 1):
        style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEV_COLOR[s])))
    t.setStyle(TableStyle(style))
    el += [t, Spacer(1, 10), P("3. Prioritized Fix List", h2)]
    for p in summ["priority"]:
        el.append(P(f"{p['rank']}. [{p['severity']}] {p['title']} - line {p['line']}"))
    if not summ["priority"]:
        el.append(P("No issues found."))

    el += [PageBreak(), P("4. Detailed Findings", h2)]
    for f in sorted(findings, key=lambda x: (SEV_RANK[x.severity], x.line)):
        head = ParagraphStyle("fh", parent=h3, textColor=colors.HexColor(SEV_COLOR[f.severity]))
        el += [P(f"{f.id}  [{f.severity}]  {f.title}", head),
               P(f"Line {f.line} | Agent: {f.agent.replace('_', ' ')}" + (f" | {f.cwe}" if f.cwe else "") +
                 (f" | {f.owasp}" if f.owasp else ""), ss["Italic"]),
               _code(f.snippet or "(n/a)"), P(f.description), P("Remediation: " + f.remediation)]
        if f.fixed_code:
            el += [P("Suggested fix:"), _code(f.fixed_code)]
        el.append(Spacer(1, 8))

    el += [P("5. Remediation Roadmap", h2)]
    phases = [("Immediate (this sprint)", ("Critical", "High")), ("Short term (next 2 sprints)", ("Medium",)),
              ("Backlog / hygiene", ("Low", "Info"))]
    for name, sevs in phases:
        items = [f for f in findings if f.severity in sevs]
        el.append(P(f"{name} - {len(items)} item(s)", h3))
        for f in items[:15]:
            el.append(P(f"- {f.id} {f.title} (line {f.line})"))
        if len(items) > 15:
            el.append(P(f"... and {len(items) - 15} more"))

    c = summ["counts"]
    assess = (f"Overall quality is rated {review.grade} ({review.health_score}/100). "
              f"{c['Critical']} critical and {c['High']} high-severity issues "
              f"{'require immediate remediation before release.' if c['Critical'] + c['High'] else 'were not found.'} "
              "Re-run the review after applying fixes to confirm the score improves.")
    el += [P("6. Overall Code Quality Assessment", h2), P(assess)]
    doc.build(el)
    return buf.getvalue()
