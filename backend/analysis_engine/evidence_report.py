"""Evidence report compiler: stable JSON + print-friendly PDF.

Both reports are built **only** from data that was actually collected. Fields that
are unavailable are rendered as ``null`` / empty arrays / explicit status strings --
never filled with invented observations. The runtime section always states that no
dynamic telemetry was collected, because this build performs static analysis only.

Branding is neutral (``config.REPORT_BRAND``). No government/police emblem or
endorsement text is added. The report is not described as legally admissible or
court-ready; it carries an explicit limitations section instead.
"""
import hashlib
import json
import os
import re

from . import config, store

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _tool_versions():
    versions = {"engine": config.TOOL_VERSION}
    try:
        import reportlab
        versions["reportlab"] = getattr(reportlab, "Version", "unknown")
    except Exception:
        pass
    try:
        import sklearn
        versions["scikit-learn"] = sklearn.__version__
    except Exception:
        pass
    return versions


def build_json_report(analysis, similarity=None, ioc_result=None, audit_events=None):
    """Assemble the machine-readable report from collected data.

    ``analysis`` is the stored findings payload (see ``store.get_analysis``). The
    other arguments are optional; when absent the report records their absence
    explicitly rather than inventing content.
    """
    findings = analysis.get("findings", analysis)
    missing = []
    if not findings.get("permissions"):
        missing.append("permissions")
    if not (findings.get("urls") or findings.get("ips") or findings.get("domains")):
        missing.append("network_indicators")
    if similarity is None:
        missing.append("similarity_analysis")
    if ioc_result is None:
        missing.append("ioc_matching")

    report = {
        "report_schema_version": "1.0",
        "report_brand": config.REPORT_BRAND,
        "generated_at": store.utc_now(),
        "analysis_id": analysis.get("analysis_id"),
        "file_identity": {
            "filename": findings.get("filename"),
            "sha256": findings.get("sha256"),
            "size_mb": findings.get("size_mb"),
            "is_valid_zip": findings.get("is_valid_zip"),
        },
        "tool_versions": _tool_versions(),
        "findings": {
            "permissions": findings.get("permissions", []),
            "suspicious_api_strings": findings.get("suspicious_apis", []),
            "network_indicators": {
                "urls": findings.get("urls", []),
                "ips": findings.get("ips", []),
                "domains": findings.get("domains", []),
            },
            "extraction_notes": findings.get("extraction_notes", []),
        },
        "risk": {
            "score": findings.get("risk_score"),
            "classification": findings.get("classification"),
            "explanation": findings.get("risk_explanation"),
        },
        "executive_summary": findings.get("executive_briefing"),
        "similarity": similarity,
        "ioc_matches": ioc_result,
        "runtime_observations": {
            "collected": False,
            "note": "No dynamic/runtime telemetry was collected; analysis is static only.",
        },
        "audit_trail": audit_events or [],
        "limitations": [
            "Static analysis only; no sandbox or runtime behaviour was observed.",
            "Permissions and strings are recovered heuristically without a full AXML/DEX parser.",
            "Similarity indicates shared static features only, not shared authorship.",
            "IOC matches reflect the local database only and depend on its provenance/freshness.",
            "Recorded hashes support integrity checks but do not by themselves prove "
            "authenticity or a complete chain of custody.",
        ],
        "missing_data": missing,
    }
    return report


def _safe_report_name(sha256):
    base = _SAFE_NAME_RE.sub("", str(sha256 or "report"))[:64] or "report"
    return f"SENTINEL_evidence_{base}.pdf"


def generate_pdf_report(report, output_dir=None):
    """Render ``report`` (from :func:`build_json_report`) to a PDF.

    Returns ``{"path", "filename", "sha256"}`` where ``sha256`` is the hash of the
    generated PDF bytes (for integrity recording). Filenames are sanitised and the
    output path is confined to ``output_dir`` to prevent path traversal.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    output_dir = output_dir or config.REPORTS_DIR
    os.makedirs(output_dir, exist_ok=True)
    filename = _safe_report_name(report.get("file_identity", {}).get("sha256"))
    # Confine output strictly within output_dir regardless of filename content.
    path = os.path.join(output_dir, os.path.basename(filename))
    if os.path.commonpath([os.path.abspath(output_dir), os.path.abspath(path)]) != os.path.abspath(output_dir):
        raise ValueError("resolved report path escapes the output directory")

    styles = getSampleStyleSheet()
    primary = colors.HexColor("#0f172a")
    muted = colors.HexColor("#64748b")
    title_style = ParagraphStyle("T", parent=styles["Heading1"], fontSize=15,
                                 textColor=primary, spaceAfter=2)
    sub_style = ParagraphStyle("S", parent=styles["Normal"], fontSize=8,
                               textColor=muted, spaceAfter=12)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11,
                        textColor=primary, spaceBefore=10, spaceAfter=5)
    body = ParagraphStyle("B", parent=styles["Normal"], fontSize=9,
                          textColor=colors.HexColor("#334155"), leading=13, spaceAfter=5)

    fi = report.get("file_identity", {})
    risk = report.get("risk", {})
    findings = report.get("findings", {})
    net = findings.get("network_indicators", {})
    story = []

    def grid(rows):
        t = Table(rows, colWidths=[160, 360])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    # Cover
    story.append(Paragraph(f"{report.get('report_brand', 'SENTINEL-CRS')} — Static Analysis Evidence Report", title_style))
    story.append(Paragraph(
        f"Analysis ID: {report.get('analysis_id')} &nbsp;|&nbsp; Generated: {report.get('generated_at')} "
        f"&nbsp;|&nbsp; Schema: {report.get('report_schema_version')}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=primary, spaceAfter=12))

    # 1. Executive summary
    story.append(Paragraph("1. Executive Summary", h2))
    story.append(Paragraph(report.get("executive_summary") or "No executive summary available.", body))

    # 2. File identity
    story.append(Paragraph("2. APK Identity & Integrity", h2))
    story.append(grid([
        [Paragraph("<b>Field</b>", body), Paragraph("<b>Value</b>", body)],
        [Paragraph("Filename", body), Paragraph(str(fi.get("filename")), body)],
        [Paragraph("SHA-256", body), Paragraph(f"<font name='Courier' size=8>{fi.get('sha256')}</font>", body)],
        [Paragraph("Size (MB)", body), Paragraph(str(fi.get("size_mb")), body)],
        [Paragraph("Valid APK archive", body), Paragraph(str(fi.get("is_valid_zip")), body)],
    ]))
    story.append(Spacer(1, 8))

    # 3. Risk
    story.append(Paragraph("3. Risk Assessment", h2))
    story.append(grid([
        [Paragraph("Risk score", body), Paragraph(f"{risk.get('score')} / 100" if risk.get("score") is not None else "null", body)],
        [Paragraph("Classification", body), Paragraph(str(risk.get("classification")), body)],
        [Paragraph("Explanation", body), Paragraph(str(risk.get("explanation") or "Not provided."), body)],
    ]))
    story.append(Spacer(1, 8))

    # 4. Static findings
    story.append(Paragraph("4. Static Analysis Findings", h2))
    perms = findings.get("permissions", [])
    if perms:
        for p in perms:
            story.append(Paragraph(f"• {p.get('name')} <font color='#64748b'>({p.get('level')})</font>", body))
    else:
        story.append(Paragraph("No permissions recovered from the sample.", body))
    apis = findings.get("suspicious_api_strings", [])
    story.append(Paragraph(
        "<b>Suspicious API strings present:</b> " + (", ".join(apis) if apis else "none observed"), body))

    # 5. Network indicators
    story.append(Paragraph("5. Extracted Network Indicators", h2))
    for label, key in (("URLs", "urls"), ("IPs", "ips"), ("Domains", "domains")):
        vals = net.get(key, [])
        story.append(Paragraph(f"<b>{label}:</b> " + (", ".join(vals) if vals else "none extracted"), body))

    # 6. IOC matches
    story.append(Paragraph("6. IOC Matches (local database)", h2))
    ioc = report.get("ioc_matches")
    if not ioc:
        story.append(Paragraph("IOC matching was not performed.", body))
    elif ioc.get("matches"):
        for m in ioc["matches"]:
            story.append(Paragraph(
                f"• [{m['type']}] {m['value']} — source: {m.get('source')}, "
                f"category: {m.get('threat_category')}, confidence: {m.get('confidence')}", body))
    else:
        story.append(Paragraph("No matching IOC found in the local database.", body))

    # 7. Similarity
    story.append(Paragraph("7. Similarity Analysis", h2))
    sim = report.get("similarity")
    if not sim:
        story.append(Paragraph("Similarity analysis was not performed.", body))
    else:
        if sim.get("similar"):
            for s in sim["similar"]:
                story.append(Paragraph(
                    f"• Analysis #{s['analysis_id']} ({s.get('filename')}) — score {s['score']}", body))
        else:
            story.append(Paragraph("No previously analysed APK met the similarity threshold "
                                   f"({sim.get('threshold')}).", body))
        story.append(Paragraph(f"<i>{sim.get('disclaimer', '')}</i>", body))

    # 8. Runtime
    story.append(Paragraph("8. Runtime Observations", h2))
    story.append(Paragraph(report.get("runtime_observations", {}).get("note", ""), body))

    # 9. Limitations & tool versions
    story.append(Paragraph("9. Limitations, Tool Versions & Audit", h2))
    for lim in report.get("limitations", []):
        story.append(Paragraph(f"• {lim}", body))
    story.append(Paragraph("<b>Tool versions:</b> " + json.dumps(report.get("tool_versions", {})), body))
    story.append(Paragraph(f"<b>Audit events recorded:</b> {len(report.get('audit_trail', []))}", body))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=muted, spaceAfter=8))
    story.append(Paragraph(
        "This report was generated by automated static analysis. Recorded hashes support "
        "integrity verification only and do not by themselves establish authenticity, lawful "
        "acquisition, or a complete chain of custody.",
        ParagraphStyle("F", fontName="Helvetica-Oblique", fontSize=7, textColor=muted)))

    SimpleDocTemplate(path, pagesize=letter, rightMargin=40, leftMargin=40,
                      topMargin=40, bottomMargin=40).build(story)

    with open(path, "rb") as fh:
        report_sha256 = hashlib.sha256(fh.read()).hexdigest()
    return {"path": path, "filename": os.path.basename(path), "sha256": report_sha256}
