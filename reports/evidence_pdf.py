"""
Court-ready APK evidence bundle generator (ReportLab).

Produces a PDF with: case details, file identity (SHA-256), manifest
permissions, suspicious strings, matched IOCs, 0-100 risk score, and the
AI executive briefing.

BRANDING: the header text and colours below are PLACEHOLDERS. Replace them
with the official Bihar Police wording, logo and colour specification
before any real use. Pass logo_path to embed the official logo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---- Branding placeholders (confirm with the department) -------------------
BRANDING = {
    "org_line": "BIHAR POLICE",  # PLACEHOLDER: confirm official wording
    "unit_line": "Cyber Crime Investigation - Digital Forensics Evidence Bundle",  # PLACEHOLDER
    "primary": colors.HexColor("#1F3A5F"),  # PLACEHOLDER colour
    "accent": colors.HexColor("#B22222"),  # PLACEHOLDER colour
}

CLASSIFICATION = "CONFIDENTIAL - FOR OFFICIAL USE ONLY"


@dataclass
class IOCHit:
    ioc_type: str  # domain / ip / hash
    value: str
    observed: str
    source: str


@dataclass
class CaseReport:
    case_number: str
    fir_number: str
    police_station: str
    investigating_officer: str
    apk_filename: str
    apk_sha256: str
    apk_size_bytes: int
    risk_score: int  # 0-100
    ai_briefing: str  # 2 sentences from the local LLM
    permissions: Sequence[str] = field(default_factory=list)
    suspicious_strings: Sequence[str] = field(default_factory=list)
    ioc_hits: Sequence[IOCHit] = field(default_factory=list)
    analysis_time: Optional[datetime] = None
    analyst_notes: str = ""

    def validate(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if len(self.apk_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.apk_sha256.lower()):
            raise ValueError("apk_sha256 must be a 64-character hex SHA-256")
        if not self.case_number.strip():
            raise ValueError("case_number is required")
        if self.apk_size_bytes < 0:
            raise ValueError("apk_size_bytes cannot be negative")


def _risk_band(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], textColor=BRANDING["primary"], fontSize=16, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], textColor=BRANDING["primary"], fontSize=12, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5, leading=13, alignment=TA_LEFT),
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier", fontSize=8, leading=10),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=7.5, leading=9, textColor=colors.grey),
    }


def _kv_table(rows: list[tuple[str, str]], st) -> Table:
    data = [[Paragraph(k, st["body"]), Paragraph(v, st["body"])] for k, v in rows]
    t = Table(data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F4F7")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _list_table(header: list[str], rows: list[list[str]], st) -> Table:
    data = [[Paragraph(h, st["body"]) for h in header]]
    data += [[Paragraph(str(c), st["mono"]) for c in r] for r in rows]
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E4E9F2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _on_page(canvas, doc, logo_path: Optional[str], generated: str):
    canvas.saveState()
    w, h = A4
    if logo_path and Path(logo_path).exists():
        canvas.drawImage(logo_path, 15 * mm, h - 25 * mm, width=18 * mm, height=18 * mm,
                         preserveAspectRatio=True, mask="auto")
    canvas.setFillColor(BRANDING["primary"])
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(37 * mm, h - 14 * mm, BRANDING["org_line"])
    canvas.setFont("Helvetica", 8.5)
    canvas.drawString(37 * mm, h - 19 * mm, BRANDING["unit_line"])
    canvas.setStrokeColor(BRANDING["accent"])
    canvas.setLineWidth(1)
    canvas.line(15 * mm, h - 27 * mm, w - 15 * mm, h - 27 * mm)

    canvas.setFillColor(colors.grey)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(15 * mm, 12 * mm, f"{CLASSIFICATION}  |  Generated {generated}")
    canvas.drawRightString(w - 15 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_evidence_pdf(report: CaseReport, output_path: str | Path, logo_path: Optional[str] = None) -> Path:
    report.validate()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    analysis_time = report.analysis_time or datetime.now()
    generated = analysis_time.strftime("%d-%m-%Y %H:%M:%S")
    st = _styles()

    doc = SimpleDocTemplate(
        str(out), pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=34 * mm, bottomMargin=20 * mm,
        title=f"Evidence Bundle - Case {report.case_number}",
        author="Digital Forensics Unit",  # PLACEHOLDER: confirm
        subject="APK analysis evidence bundle",
    )

    story = []
    story.append(Paragraph("APK Analysis - Evidence Bundle", st["title"]))
    story.append(Paragraph(f"Case No. <b>{report.case_number}</b>", st["body"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("1. Case details", st["h2"]))
    story.append(_kv_table([
        ("Case number", report.case_number),
        ("FIR number", report.fir_number or "-"),
        ("Police station", report.police_station or "-"),
        ("Investigating officer", report.investigating_officer or "-"),
        ("Analysis date/time", generated),
    ], st))

    story.append(Paragraph("2. File identity", st["h2"]))
    story.append(_kv_table([
        ("File name", report.apk_filename),
        ("Size (bytes)", f"{report.apk_size_bytes:,}"),
        ("SHA-256", f"<font face='Courier'>{report.apk_sha256.lower()}</font>"),
    ], st))

    band = _risk_band(report.risk_score)
    story.append(Paragraph("3. Risk assessment", st["h2"]))
    story.append(_kv_table([
        ("Risk score (0-100)", f"<b>{report.risk_score}</b>"),
        ("Risk band", f"<font color='{BRANDING['accent'].hexval().replace('0x', '#')}'><b>{band}</b></font>"),
    ], st))
    story.append(Spacer(1, 4))
    story.append(Paragraph("AI executive briefing", st["h2"]))
    story.append(Paragraph(report.ai_briefing or "Not generated.", st["body"]))

    story.append(Paragraph("4. Requested permissions (AndroidManifest.xml)", st["h2"]))
    if report.permissions:
        rows = [[str(i + 1), p] for i, p in enumerate(report.permissions)]
        story.append(_list_table(["#", "Permission"], rows, st))
    else:
        story.append(Paragraph("No permissions extracted.", st["body"]))

    story.append(Paragraph("5. Suspicious strings", st["h2"]))
    if report.suspicious_strings:
        rows = [[str(i + 1), s] for i, s in enumerate(report.suspicious_strings)]
        story.append(_list_table(["#", "String"], rows, st))
    else:
        story.append(Paragraph("None flagged.", st["body"]))

    story.append(Paragraph("6. IOC cross-reference matches", st["h2"]))
    if report.ioc_hits:
        rows = [[h.ioc_type, h.value, h.observed, h.source] for h in report.ioc_hits]
        story.append(_list_table(["Type", "IOC value", "Observed in APK", "IOC source"], rows, st))
    else:
        story.append(Paragraph("No matches against the IOC database.", st["body"]))

    story.append(Spacer(1, 10))
    if report.analyst_notes:
        story.append(KeepTogether([
            Paragraph("7. Analyst notes", st["h2"]),
            Paragraph(report.analyst_notes, st["body"]),
        ]))
        story.append(Spacer(1, 10))

    story.append(KeepTogether([
        Paragraph("Declaration", st["h2"]),
        Paragraph(
            "This bundle was generated automatically from static analysis of the file identified above. "
            "Hashes and extracted strings are reproducible from the original file. "
            "Findings are indicative and must be verified by the investigating officer before "
            "use in proceedings.",
            st["small"],
        ),
        Spacer(1, 18),
        Paragraph("Signature of Investigating Officer: ______________________", st["body"]),
    ]))

    def _page(canvas, d):
        _on_page(canvas, d, logo_path, generated)

    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return out
