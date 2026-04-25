"""
cyber_mas/tools/report_generator.py
══════════════════════════════════════════════════════════════════════════════
PDF Threat Report Generator — powered by ReportLab.

Converts a completed analysis report dict (from main.py / correlator)
into a professional multi-page PDF.

REPORT STRUCTURE
────────────────
  Page 1  — Cover page (report ID, timestamp, verdict, unified risk)
  Page 2  — Executive Summary (agent verdicts, risk scores, correlations)
  Page 3+ — Agent Details (email / log / ip — one section per active agent)
  Page N  — MITRE ATT&CK (attack chain, technique table)
  Page N  — Recommendations (numbered, actionable)
  Last    — Raw indicators appendix

USAGE
─────
  from tools.report_generator import generate_pdf

  pdf_path = generate_pdf(report, output_path="reports/report_abc123.pdf")
"""

from __future__ import annotations

import io
import os
import time
from pathlib import Path
from typing import Any

# ReportLab imports
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette (matches dashboard) ────────────────────────────────────────
C_BG       = colors.HexColor("#0d1210")
C_GREEN    = colors.HexColor("#00c060")
C_GREEN_DK = colors.HexColor("#004422")
C_AMBER    = colors.HexColor("#ffaa00")
C_RED      = colors.HexColor("#ff3355")
C_CYAN     = colors.HexColor("#00ddcc")
C_PURPLE   = colors.HexColor("#aa77ff")
C_TEXT     = colors.HexColor("#b8d4bc")
C_DIM      = colors.HexColor("#5a7a5e")
C_BORDER   = colors.HexColor("#1e2e22")
C_WHITE    = colors.white
C_BLACK    = colors.black
C_DARK     = colors.HexColor("#111916")

# Verdict → colour mapping
_VERDICT_COLORS = {
    "critical":   C_RED,
    "high":       colors.HexColor("#ff7799"),
    "medium":     C_AMBER,
    "low":        C_GREEN,
    "phishing":   C_RED,
    "malicious":  C_RED,
    "vulnerable": C_AMBER,
    "suspicious": C_AMBER,
    "spam":       C_AMBER,
    "legitimate": C_GREEN,
    "benign":     C_GREEN,
    "clean":      C_GREEN,
    "uncertain":  C_DIM,
}

def _verdict_color(verdict: str) -> colors.Color:
    return _VERDICT_COLORS.get((verdict or "").lower(), C_DIM)

def _risk_color(score: float) -> colors.Color:
    if score >= 0.85: return C_RED
    if score >= 0.65: return colors.HexColor("#ff7799")
    if score >= 0.40: return C_AMBER
    return C_GREEN


# ══════════════════════════════════════════════════════════════════════════════
# Style definitions
# ══════════════════════════════════════════════════════════════════════════════

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=32, fontName="Helvetica-Bold",
        textColor=C_GREEN, alignment=TA_CENTER, spaceAfter=6,
        leading=38,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=12, fontName="Helvetica",
        textColor=C_DIM, alignment=TA_CENTER, spaceAfter=4,
    )
    s["cover_verdict"] = ParagraphStyle(
        "cover_verdict", fontSize=22, fontName="Helvetica-Bold",
        textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=4,
    )
    s["section_title"] = ParagraphStyle(
        "section_title", fontSize=14, fontName="Helvetica-Bold",
        textColor=C_GREEN, spaceBefore=14, spaceAfter=6,
        borderPad=4,
    )
    s["sub_title"] = ParagraphStyle(
        "sub_title", fontSize=11, fontName="Helvetica-Bold",
        textColor=C_CYAN, spaceBefore=10, spaceAfter=4,
    )
    s["body"] = ParagraphStyle(
        "body", fontSize=9, fontName="Helvetica",
        textColor=C_TEXT, spaceAfter=4, leading=14,
    )
    s["mono"] = ParagraphStyle(
        "mono", fontSize=8, fontName="Courier",
        textColor=C_TEXT, spaceAfter=2, leading=12,
    )
    s["label"] = ParagraphStyle(
        "label", fontSize=8, fontName="Helvetica-Bold",
        textColor=C_DIM, spaceAfter=2,
    )
    s["verdict_text"] = ParagraphStyle(
        "verdict_text", fontSize=11, fontName="Helvetica-Bold",
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    s["risk_num"] = ParagraphStyle(
        "risk_num", fontSize=28, fontName="Helvetica-Bold",
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    s["footer"] = ParagraphStyle(
        "footer", fontSize=7, fontName="Helvetica",
        textColor=C_DIM, alignment=TA_CENTER,
    )
    s["rec_num"] = ParagraphStyle(
        "rec_num", fontSize=10, fontName="Helvetica-Bold",
        textColor=C_AMBER,
    )
    s["rec_text"] = ParagraphStyle(
        "rec_text", fontSize=9, fontName="Helvetica",
        textColor=C_TEXT, leading=13,
    )
    s["mitre_id"] = ParagraphStyle(
        "mitre_id", fontSize=8, fontName="Courier-Bold",
        textColor=C_PURPLE,
    )
    s["mitre_name"] = ParagraphStyle(
        "mitre_name", fontSize=9, fontName="Helvetica-Bold",
        textColor=C_WHITE,
    )
    s["mitre_tactic"] = ParagraphStyle(
        "mitre_tactic", fontSize=8, fontName="Helvetica",
        textColor=C_DIM,
    )
    return s


# ══════════════════════════════════════════════════════════════════════════════
# Page template (dark background + header/footer)
# ══════════════════════════════════════════════════════════════════════════════

class _DarkPageTemplate:
    """Callable for SimpleDocTemplate onFirstPage / onLaterPages."""

    def __init__(self, report_id: str, timestamp: str):
        self.report_id = report_id
        self.timestamp = timestamp

    def _draw_bg(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Top accent bar
        canvas.setFillColor(C_GREEN)
        canvas.rect(0, A4[1] - 8*mm, A4[0], 2, fill=1, stroke=0)
        # Bottom bar
        canvas.setFillColor(C_BORDER)
        canvas.rect(0, 0, A4[0], 8*mm, fill=1, stroke=0)
        # Footer text
        canvas.setFillColor(C_DIM)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(15*mm, 3*mm,
            f"CYBER-MAS THREAT REPORT  |  {self.report_id}  |  {self.timestamp}")
        canvas.drawRightString(A4[0] - 15*mm, 3*mm,
            f"Page {doc.page}")
        canvas.restoreState()

    def first_page(self, canvas, doc):
        self._draw_bg(canvas, doc)

    def later_pages(self, canvas, doc):
        self._draw_bg(canvas, doc)


# ══════════════════════════════════════════════════════════════════════════════
# Section builders
# ══════════════════════════════════════════════════════════════════════════════

def _divider(color=C_BORDER) -> HRFlowable:
    return HRFlowable(width="100%", thickness=1, color=color, spaceAfter=6, spaceBefore=4)


def _section_header(text: str, s: dict) -> list:
    return [
        _divider(C_GREEN),
        Paragraph(text.upper(), s["section_title"]),
        _divider(),
    ]


def _kv_table(rows: list[tuple[str, str]], s: dict) -> Table:
    """Render key-value pairs as a two-column table."""
    data = []
    for key, val in rows:
        data.append([
            Paragraph(key, s["label"]),
            Paragraph(str(val), s["mono"]),
        ])
    t = Table(data, colWidths=[45*mm, 120*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_DARK),
        ("TEXTCOLOR",   (0,0), (-1,-1), C_TEXT),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, C_BG]),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
    ]))
    return t


def _risk_bar_table(score: float, width_mm: float = 150) -> Table:
    """Visual risk bar as a table row."""
    filled = int(score * 40)
    empty  = 40 - filled
    bar    = "█" * filled + "░" * empty
    color  = _risk_color(score)
    data = [[
        Paragraph(f'<font color="#{color.hexval()[2:]}">{bar}</font>  {score:.2f}',
                  ParagraphStyle("bar", fontSize=9, fontName="Courier",
                                 textColor=color)),
    ]]
    t = Table(data, colWidths=[width_mm*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    return t


# ── Cover page ────────────────────────────────────────────────────────────────

def _build_cover(report: dict, s: dict) -> list:
    story = []
    corr      = report.get("correlator", {})
    verdict   = (corr.get("verdict") or "unknown").upper()
    risk      = corr.get("unified_risk", 0.0)
    report_id = report.get("report_id", corr.get("report_id", "N/A"))
    timestamp = report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))
    vc        = _verdict_color(corr.get("verdict", ""))
    rc        = _risk_color(risk)

    story.append(Spacer(1, 30*mm))
    story.append(Paragraph("CYBER-MAS", s["cover_title"]))
    story.append(Paragraph("Multi-Agent Cybersecurity Threat Detection System", s["cover_sub"]))
    story.append(Paragraph("THREAT ANALYSIS REPORT", s["cover_sub"]))
    story.append(Spacer(1, 20*mm))

    # Verdict box
    vc_hex = vc.hexval()
    rc_hex = rc.hexval()
    verdict_data = [[
        Paragraph(
            f'<font color="#{vc_hex[2:]}">{verdict}</font>',
            s["cover_verdict"]
        ),
    ]]
    vt = Table(verdict_data, colWidths=[120*mm])
    vt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_GREEN_DK),
        ("BOX",          (0,0), (-1,-1), 1.5, vc),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
    ]))
    story.append(vt)
    story.append(Spacer(1, 6*mm))

    # Risk score
    risk_data = [[
        Paragraph(
            f'<font color="#{rc_hex[2:]}">{int(risk*100)}%</font>',
            s["risk_num"]
        ),
        Paragraph("UNIFIED RISK", s["cover_sub"]),
    ]]
    rt = Table(risk_data, colWidths=[40*mm, 80*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(rt)
    story.append(Spacer(1, 16*mm))

    # Meta info
    meta_rows = [
        ("Report ID",   report_id),
        ("Timestamp",   timestamp),
        ("Duration",    f"{report.get('duration', corr.get('_duration_secs', '?'))}s"),
        ("Agents",      ", ".join(a.get("agent","?") for a in report.get("agents", []))),
        ("Confidence",  f"{corr.get('confidence', 0.0):.2f}"),
    ]
    story.append(_kv_table(meta_rows, s))
    story.append(PageBreak())
    return story


# ── Executive summary ─────────────────────────────────────────────────────────

def _build_executive_summary(report: dict, s: dict) -> list:
    story = []
    corr = report.get("correlator", {})

    story += _section_header("Executive Summary", s)

    # Agent summary table
    summary = corr.get("agent_summary", {})
    agents  = report.get("agents", [])

    agent_data = [
        [Paragraph("AGENT", s["label"]),
         Paragraph("VERDICT", s["label"]),
         Paragraph("RISK SCORE", s["label"]),
         Paragraph("CONFIDENCE", s["label"])],
    ]
    for agent_result in agents:
        ag  = agent_result.get("agent", "?")
        v   = agent_result.get("verdict", "?")
        r   = agent_result.get("risk_score", 0.0)
        c   = agent_result.get("confidence", 0.0)
        vc  = _verdict_color(v)
        rc  = _risk_color(r)
        agent_data.append([
            Paragraph(ag.upper(), s["mono"]),
            Paragraph(f'<font color="#{vc.hexval()[2:]}">{v.upper()}</font>', s["mono"]),
            Paragraph(f'<font color="#{rc.hexval()[2:]}">{r:.2f}</font>', s["mono"]),
            Paragraph(f"{c:.2f}", s["mono"]),
        ])

    at = Table(agent_data, colWidths=[35*mm, 45*mm, 40*mm, 40*mm])
    at.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
        ("TEXTCOLOR",      (0,0), (-1,0), C_GREEN),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
        ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
        ("LEFTPADDING",    (0,0), (-1,-1), 6),
        ("RIGHTPADDING",   (0,0), (-1,-1), 6),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(at)
    story.append(Spacer(1, 6*mm))

    # Correlation rules
    story.append(Paragraph("Correlation Rules Fired", s["sub_title"]))
    corrs = corr.get("correlations", [])
    if corrs:
        unified_inds = corr.get("unified_indicators", [])
        corr_data = [[Paragraph("RULE", s["label"]), Paragraph("DESCRIPTION", s["label"])]]
        for i, c_rule in enumerate(corrs):
            desc = unified_inds[i] if i < len(unified_inds) else "—"
            corr_data.append([
                Paragraph(c_rule, ParagraphStyle("cr", fontSize=8, fontName="Courier-Bold",
                                                  textColor=C_CYAN)),
                Paragraph(desc, s["body"]),
            ])
        ct = Table(corr_data, colWidths=[50*mm, 115*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
            ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
            ("LEFTPADDING",    (0,0), (-1,-1), 6),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
            ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ]))
        story.append(ct)
    else:
        story.append(Paragraph("No cross-agent correlations detected.", s["body"]))

    story.append(Spacer(1, 6*mm))

    # Holistic reasoning
    story.append(Paragraph("Holistic Reasoning", s["sub_title"]))
    reasoning = corr.get("reasoning", "No reasoning available.")
    reasoning_data = [[Paragraph(reasoning, s["body"])]]
    rt = Table(reasoning_data, colWidths=[165*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LEFTBORDER",   (0,0), (0,-1), 3, C_GREEN),
        ("BOX",          (0,0), (-1,-1), 0.3, C_BORDER),
    ]))
    story.append(rt)
    story.append(PageBreak())
    return story


# ── Agent details ─────────────────────────────────────────────────────────────

def _build_agent_section(result: dict, s: dict) -> list:
    story = []
    agent   = result.get("agent", "?").upper()
    verdict = result.get("verdict", "?")
    risk    = result.get("risk_score", 0.0)
    conf    = result.get("confidence", 0.0)
    vc      = _verdict_color(verdict)

    story += _section_header(f"{agent} Agent Analysis", s)

    # Header row
    vc_hex = vc.hexval()
    header_data = [[
        Paragraph(f'<font color="#{vc_hex[2:]}">{verdict.upper()}</font>', s["cover_verdict"]),
        Paragraph(f"Risk: {risk:.2f}  |  Confidence: {conf:.2f}", s["body"]),
        Paragraph(f"Duration: {result.get('_duration_secs','?')}s", s["body"]),
    ]]
    ht = Table(header_data, colWidths=[50*mm, 80*mm, 35*mm])
    ht.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_GREEN_DK),
        ("BOX",          (0,0), (-1,-1), 0.5, vc),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(ht)
    story.append(Spacer(1, 4*mm))
    story.append(_risk_bar_table(risk))
    story.append(Spacer(1, 4*mm))

    # ── Email agent ──────────────────────────────────────────────────────────
    if result.get("agent") == "email":
        meta = result.get("email_metadata", {})
        if meta:
            story.append(Paragraph("Email Metadata", s["sub_title"]))
            rows = [
                ("Subject",     meta.get("subject", "—")),
                ("Sender",      meta.get("sender", "—")),
                ("Reply-To",    meta.get("reply_to", "—")),
                ("Links",       str(meta.get("link_count", 0))),
                ("Attachments", "YES" if meta.get("has_attachments") else "NO"),
            ]
            rag = result.get("rag_match", {})
            if rag.get("label"):
                rows.append(("RAG Match",
                             f"{rag['label']} (similarity={rag.get('similarity',0):.3f})"))
            story.append(_kv_table(rows, s))
            story.append(Spacer(1, 3*mm))

    # ── Log agent ────────────────────────────────────────────────────────────
    if result.get("agent") == "log":
        stats = result.get("stats", {})
        sigs  = result.get("signatures_hit", [])
        if stats:
            story.append(Paragraph("Log Statistics", s["sub_title"]))
            rows = [
                ("Total lines",    str(stats.get("total_lines", "?"))),
                ("Unique IPs",     str(stats.get("unique_ips", "?"))),
                ("Time span",      f"{stats.get('time_span_secs',0)}s"),
                ("Top sources",    ", ".join(str(s2) for s2 in stats.get("top_sources",[]))),
                ("Error rate",     f"{stats.get('error_rate',0)*100:.1f}%"),
            ]
            story.append(_kv_table(rows, s))
        if sigs:
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph("Signatures Fired", s["sub_title"]))
            sig_data = [[Paragraph(sig, ParagraphStyle(
                "sig", fontSize=9, fontName="Courier-Bold", textColor=C_AMBER,
            ))] for sig in sigs]
            st = Table(sig_data, colWidths=[165*mm])
            st.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, C_BG]),
                ("LEFTPADDING",    (0,0), (-1,-1), 8),
                ("TOPPADDING",     (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
                ("BOX",            (0,0), (-1,-1), 0.3, C_BORDER),
            ]))
            story.append(st)
        story.append(Spacer(1, 3*mm))

    # ── IP agent ─────────────────────────────────────────────────────────────
    if result.get("agent") == "ip":
        story.append(Paragraph("Scan Details", s["sub_title"]))
        rows = [
            ("Target",       result.get("target", "—")),
            ("OS Guess",     result.get("os_guess", "unknown")),
            ("Scan Duration",f"{result.get('scan_duration','?')}s"),
            ("Open Ports",   str(len(result.get("open_ports", [])))),
            ("CVEs Found",   str(len(result.get("cves", [])))),
        ]
        story.append(_kv_table(rows, s))

        ports = result.get("open_ports", [])
        if ports:
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph("Open Ports", s["sub_title"]))
            port_data = [[
                Paragraph("PORT", s["label"]),
                Paragraph("PROTOCOL", s["label"]),
                Paragraph("SERVICE", s["label"]),
                Paragraph("VERSION", s["label"]),
            ]]
            for p in ports[:15]:
                port_data.append([
                    Paragraph(str(p.get("port","?")), s["mono"]),
                    Paragraph(p.get("protocol","?"), s["mono"]),
                    Paragraph(p.get("service","?"), s["mono"]),
                    Paragraph(str(p.get("version",""))[:40], s["mono"]),
                ])
            pt = Table(port_data, colWidths=[20*mm, 25*mm, 40*mm, 80*mm])
            pt.setStyle(TableStyle([
                ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
                ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
                ("LEFTPADDING",    (0,0), (-1,-1), 5),
                ("TOPPADDING",     (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
            ]))
            story.append(pt)

        cves = result.get("cves", [])
        if cves:
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph("CVEs Detected", s["sub_title"]))
            cve_data = [[
                Paragraph("CVE ID", s["label"]),
                Paragraph("CVSS", s["label"]),
                Paragraph("SEVERITY", s["label"]),
                Paragraph("DESCRIPTION", s["label"]),
            ]]
            for c in cves[:10]:
                cvss  = c.get("cvss_score", 0.0)
                sev   = c.get("severity", "?")
                sc    = C_RED if cvss >= 9.0 else C_AMBER if cvss >= 7.0 else C_GREEN
                cve_data.append([
                    Paragraph(c.get("cve_id","?"), ParagraphStyle(
                        "cid", fontSize=8, fontName="Courier-Bold", textColor=C_CYAN)),
                    Paragraph(f'<font color="#{sc.hexval()[2:]}">{cvss}</font>', s["mono"]),
                    Paragraph(sev, s["mono"]),
                    Paragraph(str(c.get("description",""))[:80], s["body"]),
                ])
            ct = Table(cve_data, colWidths=[32*mm, 16*mm, 24*mm, 93*mm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
                ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
                ("LEFTPADDING",    (0,0), (-1,-1), 5),
                ("TOPPADDING",     (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
                ("VALIGN",         (0,0), (-1,-1), "TOP"),
            ]))
            story.append(ct)

    # ── Reasoning ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Agent Reasoning", s["sub_title"]))
    reasoning = result.get("reasoning", "No reasoning available.")
    rd = [[Paragraph(reasoning, s["body"])]]
    rt = Table(rd, colWidths=[165*mm])
    rt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("BOX",          (0,0), (-1,-1), 0.3, C_BORDER),
    ]))
    story.append(rt)

    # ── Indicators ───────────────────────────────────────────────────────────
    indicators = result.get("indicators", [])
    if indicators:
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph("Indicators", s["sub_title"]))
        ind_data = [[Paragraph(str(ind), ParagraphStyle(
            "ind", fontSize=8, fontName="Courier", textColor=C_RED,
        ))] for ind in indicators]
        it = Table(ind_data, colWidths=[165*mm])
        it.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_DARK, C_BG]),
            ("LEFTPADDING",    (0,0), (-1,-1), 8),
            ("TOPPADDING",     (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
            ("BOX",            (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        story.append(it)

    story.append(PageBreak())
    return story


# ── MITRE ATT&CK section ──────────────────────────────────────────────────────

def _build_mitre_section(report: dict, s: dict) -> list:
    story = []

    # Collect techniques from all agents + correlator
    all_techniques = []
    for agent_r in report.get("agents", []):
        all_techniques.extend(agent_r.get("mitre_techniques", []))
    corr = report.get("correlator", {})
    all_techniques.extend(corr.get("mitre_techniques", []))

    # Deduplicate by technique_id
    seen = {}
    for t in all_techniques:
        tid = t.get("technique_id","")
        if tid not in seen or t.get("confidence",0) > seen[tid].get("confidence",0):
            seen[tid] = t
    techniques = sorted(seen.values(), key=lambda x: (x.get("tactic_id",""), x.get("technique_id","")))

    if not techniques:
        return []

    story += _section_header("MITRE ATT&CK Mapping", s)

    # Attack chain
    attack_chain = corr.get("attack_chain", [])
    if not attack_chain:
        # Derive from techniques
        TACTIC_ORDER = ["Initial Access","Execution","Persistence","Privilege Escalation",
                        "Defense Evasion","Credential Access","Discovery","Lateral Movement",
                        "Collection","Command & Control","Exfiltration","Impact"]
        seen_tactics = {t.get("tactic_name") for t in techniques}
        attack_chain = [tc for tc in TACTIC_ORDER if tc in seen_tactics]

    if attack_chain:
        story.append(Paragraph("Attack Chain (Kill Chain Order)", s["sub_title"]))
        chain_data = [[]]
        for i, tactic in enumerate(attack_chain):
            arrow = " ▶ " if i < len(attack_chain)-1 else ""
            chain_data[0].append(
                Paragraph(f"{tactic}{arrow}",
                          ParagraphStyle("chain", fontSize=8, fontName="Helvetica-Bold",
                                         textColor=C_CYAN, alignment=TA_CENTER))
            )
        col_w = 165 / max(len(attack_chain), 1)
        ct = Table(chain_data, colWidths=[col_w*mm]*len(attack_chain))
        ct.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_GREEN_DK),
            ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ]))
        story.append(ct)
        story.append(Spacer(1, 4*mm))

    # Technique table
    story.append(Paragraph(f"Techniques Detected ({len(techniques)})", s["sub_title"]))
    tech_data = [[
        Paragraph("ID", s["label"]),
        Paragraph("TECHNIQUE", s["label"]),
        Paragraph("TACTIC", s["label"]),
        Paragraph("CONFIDENCE", s["label"]),
        Paragraph("TRIGGERED BY", s["label"]),
    ]]
    for t in techniques:
        conf  = t.get("confidence", 0.0)
        cc    = _risk_color(conf)
        tech_data.append([
            Paragraph(t.get("technique_id",""), ParagraphStyle(
                "tid", fontSize=8, fontName="Courier-Bold", textColor=C_PURPLE)),
            Paragraph(t.get("technique_name",""), s["body"]),
            Paragraph(t.get("tactic_name",""), s["body"]),
            Paragraph(f'<font color="#{cc.hexval()[2:]}">{conf:.2f}</font>', s["mono"]),
            Paragraph(str(t.get("source",""))[:30], s["mono"]),
        ])
    tt = Table(tech_data, colWidths=[22*mm, 52*mm, 38*mm, 20*mm, 33*mm])
    tt.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
        ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
        ("LEFTPADDING",    (0,0), (-1,-1), 5),
        ("TOPPADDING",     (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
    ]))
    story.append(tt)
    story.append(PageBreak())
    return story


# ── Recommendations section ───────────────────────────────────────────────────

def _build_recommendations(report: dict, s: dict) -> list:
    story = []
    corr = report.get("correlator", {})
    recs = corr.get("recommendations", [])

    story += _section_header("Recommendations", s)

    if not recs:
        story.append(Paragraph("No recommendations generated.", s["body"]))
        story.append(PageBreak())
        return story

    for i, rec in enumerate(recs, 1):
        rec_data = [[
            Paragraph(f"{i:02d}", s["rec_num"]),
            Paragraph(rec, s["rec_text"]),
        ]]
        rt = Table(rec_data, colWidths=[12*mm, 153*mm])
        rt.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
            ("LEFTPADDING",  (0,0), (0,-1), 8),
            ("LEFTPADDING",  (1,0), (1,-1), 6),
            ("TOPPADDING",   (0,0), (-1,-1), 7),
            ("BOTTOMPADDING",(0,0), (-1,-1), 7),
            ("BOX",          (0,0), (-1,-1), 0.3, C_BORDER),
            ("LINEBEFORE",   (0,0), (0,-1), 3, C_AMBER),
            ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ]))
        story.append(rt)
        story.append(Spacer(1, 2*mm))

    story.append(PageBreak())
    return story


# ── Indicators appendix ───────────────────────────────────────────────────────

def _build_appendix(report: dict, s: dict) -> list:
    story = []
    corr = report.get("correlator", {})
    all_inds = corr.get("indicators", [])

    story += _section_header("Appendix — All Indicators", s)

    if not all_inds:
        story.append(Paragraph("No indicators recorded.", s["body"]))
        return story

    ind_data = [[Paragraph("INDICATOR", s["label"]), Paragraph("SOURCE", s["label"])]]
    for ind in all_inds:
        ind_data.append([
            Paragraph(str(ind), ParagraphStyle(
                "aind", fontSize=8, fontName="Courier", textColor=C_RED)),
            Paragraph("merged", s["mono"]),
        ])
    it = Table(ind_data, colWidths=[120*mm, 45*mm])
    it.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_GREEN_DK),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_DARK, C_BG]),
        ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
        ("LEFTPADDING",    (0,0), (-1,-1), 6),
        ("TOPPADDING",     (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 3),
    ]))
    story.append(it)
    return story


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def generate_pdf(report: dict, output_path: str | None = None) -> str:
    """
    Generate a PDF threat report from a completed analysis report dict.

    Parameters
    ----------
    report      : dict returned by main.run() or the full report from the API
    output_path : where to save the PDF (auto-generated if not provided)

    Returns
    -------
    str — absolute path to the generated PDF file.
    """
    # Ensure output directory exists
    if output_path is None:
        reports_dir = Path(__file__).parents[2] / "reports"
        reports_dir.mkdir(exist_ok=True)
        rid = report.get("report_id",
              report.get("correlator", {}).get("report_id", "unknown"))
        ts  = time.strftime("%Y%m%d_%H%M%S")
        output_path = str(reports_dir / f"threat_report_{rid}_{ts}.pdf")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    corr      = report.get("correlator", {})
    report_id = report.get("report_id", corr.get("report_id", "N/A"))
    timestamp = report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))

    # Build page template
    tmpl = _DarkPageTemplate(report_id, timestamp)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
        title=f"Cyber-MAS Threat Report {report_id}",
        author="Cyber-MAS Multi-Agent System",
        subject="Cybersecurity Threat Analysis Report",
    )

    s = _build_styles()
    story = []

    # ── Assemble pages ────────────────────────────────────────────────────────
    story += _build_cover(report, s)
    story += _build_executive_summary(report, s)

    for agent_result in report.get("agents", []):
        story += _build_agent_section(agent_result, s)

    mitre_pages = _build_mitre_section(report, s)
    if mitre_pages:
        story += mitre_pages

    story += _build_recommendations(report, s)
    story += _build_appendix(report, s)

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(
        story,
        onFirstPage=tmpl.first_page,
        onLaterPages=tmpl.later_pages,
    )

    return str(Path(output_path).resolve())


def generate_pdf_bytes(report: dict) -> bytes:
    """
    Generate the PDF in memory and return as bytes (for email attachment).
    """
    buf = io.BytesIO()

    corr      = report.get("correlator", {})
    report_id = report.get("report_id", corr.get("report_id", "N/A"))
    timestamp = report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))

    tmpl = _DarkPageTemplate(report_id, timestamp)
    doc  = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
    )

    s     = _build_styles()
    story = []
    story += _build_cover(report, s)
    story += _build_executive_summary(report, s)
    for agent_result in report.get("agents", []):
        story += _build_agent_section(agent_result, s)
    mitre_pages = _build_mitre_section(report, s)
    if mitre_pages:
        story += mitre_pages
    story += _build_recommendations(report, s)
    story += _build_appendix(report, s)

    doc.build(story, onFirstPage=tmpl.first_page, onLaterPages=tmpl.later_pages)
    return buf.getvalue()