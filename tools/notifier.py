"""
cyber_mas/tools/notifier.py
══════════════════════════════════════════════════════════════════════════════
Email Notification System — sends threat alerts with PDF reports attached.

TRIGGERS
────────
  Sends after every analysis completion (configurable via NOTIFY_ON_VERDICT).

EMAIL CONTENT
─────────────
  Subject : [CYBER-MAS] {VERDICT} — Unified Risk {score}% — Report {id}
  Body    : Structured HTML with:
              • Verdict + unified risk score (colour-coded)
              • Correlation rules fired
              • MITRE ATT&CK chain
              • Recommendations (numbered)
              • Agent summary table
  Attachment : threat_report_{id}.pdf

CONFIGURATION (via environment variables or .env file)
──────────────────────────────────────────────────────
  NOTIFY_SMTP_HOST      SMTP server hostname   (default: smtp.gmail.com)
  NOTIFY_SMTP_PORT      SMTP port              (default: 587)
  NOTIFY_SMTP_USER      Sender email address
  NOTIFY_SMTP_PASS      Sender password / app password
  NOTIFY_FROM           From address           (defaults to NOTIFY_SMTP_USER)
  NOTIFY_TO             Recipient(s) — comma-separated
  NOTIFY_ON_VERDICT     Min verdict to notify  (default: "low" = always)
                        Options: low | medium | high | critical
  NOTIFY_ENABLED        Set to "false" to disable without removing config

USAGE
─────
  from cyber_mas.tools.notifier import notify

  # After analysis completes:
  notify(report)                           # auto-generates PDF
  notify(report, pdf_path="report.pdf")    # use pre-generated PDF

  # CLI test
  python cyber_mas/tools/notifier.py --test
"""

from __future__ import annotations

import logging
import os
import smtplib
import time
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

log = logging.getLogger(__name__)

# ── Verdict severity order ────────────────────────────────────────────────────
_VERDICT_SEVERITY = {
    "low":       0,
    "clean":     0,
    "benign":    0,
    "legitimate":0,
    "uncertain": 1,
    "suspicious":2,
    "spam":      2,
    "medium":    2,
    "vulnerable":3,
    "high":      3,
    "phishing":  3,
    "malicious": 4,
    "critical":  4,
}

_VERDICT_COLORS = {
    "critical":  "#ff3355",
    "high":      "#ff7799",
    "medium":    "#ffaa00",
    "low":       "#00c060",
    "phishing":  "#ff3355",
    "malicious": "#ff3355",
    "vulnerable":"#ffaa00",
    "suspicious":"#ffcc55",
    "spam":      "#ffcc55",
    "legitimate":"#00c060",
    "benign":    "#00c060",
    "clean":     "#00c060",
    "uncertain": "#888888",
}

def _verdict_color(v: str) -> str:
    return _VERDICT_COLORS.get((v or "").lower(), "#888888")

def _risk_color(score: float) -> str:
    if score >= 0.85: return "#ff3355"
    if score >= 0.65: return "#ff7799"
    if score >= 0.40: return "#ffaa00"
    return "#00c060"


# ══════════════════════════════════════════════════════════════════════════════
# Config loader
# ══════════════════════════════════════════════════════════════════════════════

def _load_config() -> dict:
    """Load SMTP config from environment / .env file."""
    # Try to load .env if python-dotenv is available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    return {
        "enabled":   os.getenv("NOTIFY_ENABLED", "true").lower() not in ("false","0","no"),
        "smtp_host": os.getenv("NOTIFY_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("NOTIFY_SMTP_PORT", "587")),
        "smtp_user": os.getenv("NOTIFY_SMTP_USER", ""),
        "smtp_pass": os.getenv("NOTIFY_SMTP_PASS", ""),
        "from_addr": os.getenv("NOTIFY_FROM", "") or os.getenv("NOTIFY_SMTP_USER", ""),
        "to_addrs":  [a.strip() for a in os.getenv("NOTIFY_TO", "").split(",") if a.strip()],
        "min_verdict": os.getenv("NOTIFY_ON_VERDICT", "low").lower(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# HTML email body builder
# ══════════════════════════════════════════════════════════════════════════════

def _build_html(report: dict) -> str:
    """Build a rich HTML email body from the report dict."""
    corr      = report.get("correlator", {})
    verdict   = corr.get("verdict", "unknown")
    risk      = corr.get("unified_risk", 0.0)
    conf      = corr.get("confidence", 0.0)
    report_id = report.get("report_id", corr.get("report_id", "N/A"))
    timestamp = report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))
    reasoning = corr.get("reasoning", "")
    corrs     = corr.get("correlations", [])
    recs      = corr.get("recommendations", [])
    attack_chain = corr.get("attack_chain", [])

    vc = _verdict_color(verdict)
    rc = _risk_color(risk)

    # Agent summary rows
    agent_rows = ""
    for a in report.get("agents", []):
        ag  = a.get("agent","?").upper()
        av  = a.get("verdict","?")
        ar  = a.get("risk_score", 0.0)
        avc = _verdict_color(av)
        arc = _risk_color(ar)
        agent_rows += f"""
        <tr>
          <td style="padding:6px 10px;font-family:monospace;color:#b8d4bc">{ag}</td>
          <td style="padding:6px 10px;font-weight:bold;color:{avc}">{av.upper()}</td>
          <td style="padding:6px 10px;font-family:monospace;color:{arc}">{ar:.2f}</td>
          <td style="padding:6px 10px;font-family:monospace;color:#5a7a5e">{a.get('_duration_secs','?')}s</td>
        </tr>"""

    # Correlation rows
    corr_rows = ""
    unified_inds = corr.get("unified_indicators", [])
    for i, c_rule in enumerate(corrs):
        desc = unified_inds[i] if i < len(unified_inds) else ""
        corr_rows += f"""
        <tr>
          <td style="padding:5px 10px;font-family:monospace;color:#00ddcc;white-space:nowrap">{c_rule}</td>
          <td style="padding:5px 10px;color:#b8d4bc;font-size:12px">{desc}</td>
        </tr>"""

    # MITRE chain
    chain_html = ""
    if attack_chain:
        steps = " &nbsp;▶&nbsp; ".join(
            f'<span style="color:#00ddcc">{t}</span>' for t in attack_chain
        )
        chain_html = f"""
        <div style="background:#111916;border:1px solid #1e2e22;border-left:3px solid #00ddcc;
                    padding:10px 14px;margin:8px 0;font-family:monospace;font-size:12px">
          {steps}
        </div>"""

    # Recommendations
    rec_html = ""
    for i, rec in enumerate(recs, 1):
        rec_html += f"""
        <div style="display:flex;gap:12px;padding:8px 0;border-bottom:1px solid #1e2e22">
          <span style="color:#ffaa00;font-family:monospace;font-weight:bold;min-width:24px">{i:02d}</span>
          <span style="color:#b8d4bc;font-size:13px">{rec}</span>
        </div>"""

    # Risk bar (ASCII-style)
    filled   = int(risk * 30)
    risk_bar = "█" * filled + "░" * (30 - filled)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#080c0a; font-family:Arial,sans-serif; color:#b8d4bc; }}
  .shell {{ max-width:720px; margin:0 auto; background:#0d1210; }}
  table {{ border-collapse:collapse; width:100%; }}
  td {{ vertical-align:top; }}
</style>
</head>
<body>
<div class="shell">

  <!-- TOP BAR -->
  <div style="background:#00c060;height:4px"></div>

  <!-- HEADER -->
  <div style="background:#111916;padding:20px 24px;border-bottom:1px solid #1e2e22">
    <div style="font-family:monospace;font-size:22px;font-weight:bold;
                color:#00c060;letter-spacing:4px">CYBER-MAS</div>
    <div style="font-size:11px;color:#5a7a5e;letter-spacing:1px;margin-top:2px">
      MULTI-AGENT CYBERSECURITY THREAT DETECTION SYSTEM
    </div>
  </div>

  <!-- VERDICT BANNER -->
  <div style="background:{vc}22;border:1px solid {vc}55;margin:16px;padding:16px 20px;
              border-left:4px solid {vc}">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <div>
        <div style="font-size:11px;color:#5a7a5e;letter-spacing:2px;margin-bottom:4px">VERDICT</div>
        <div style="font-size:28px;font-weight:bold;color:{vc};letter-spacing:3px;
                    font-family:monospace">{verdict.upper()}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:11px;color:#5a7a5e;letter-spacing:2px;margin-bottom:4px">UNIFIED RISK</div>
        <div style="font-size:32px;font-weight:bold;color:{rc};font-family:monospace">{int(risk*100)}%</div>
        <div style="font-family:monospace;font-size:11px;color:{rc};letter-spacing:1px">{risk_bar}</div>
      </div>
    </div>
  </div>

  <!-- META -->
  <div style="margin:0 16px;padding:12px;background:#111916;border:1px solid #1e2e22;
              font-family:monospace;font-size:11px;color:#5a7a5e">
    REPORT ID: <span style="color:#00ddcc">{report_id}</span> &nbsp;|&nbsp;
    TIMESTAMP: <span style="color:#b8d4bc">{timestamp}</span> &nbsp;|&nbsp;
    CONFIDENCE: <span style="color:#b8d4bc">{conf:.2f}</span>
  </div>

  <!-- AGENT SUMMARY -->
  <div style="margin:16px">
    <div style="font-family:monospace;font-size:11px;letter-spacing:2px;
                color:#00c060;margin-bottom:8px">▸ AGENT SUMMARY</div>
    <table style="background:#111916;border:1px solid #1e2e22">
      <tr style="background:#172018">
        <th style="padding:6px 10px;text-align:left;font-size:10px;
                   color:#5a7a5e;letter-spacing:1px">AGENT</th>
        <th style="padding:6px 10px;text-align:left;font-size:10px;
                   color:#5a7a5e;letter-spacing:1px">VERDICT</th>
        <th style="padding:6px 10px;text-align:left;font-size:10px;
                   color:#5a7a5e;letter-spacing:1px">RISK</th>
        <th style="padding:6px 10px;text-align:left;font-size:10px;
                   color:#5a7a5e;letter-spacing:1px">DURATION</th>
      </tr>
      {agent_rows}
    </table>
  </div>

  <!-- CORRELATIONS -->
  {"" if not corrs else f'''
  <div style="margin:16px">
    <div style="font-family:monospace;font-size:11px;letter-spacing:2px;
                color:#00c060;margin-bottom:8px">▸ CORRELATION RULES FIRED</div>
    <table style="background:#111916;border:1px solid #1e2e22">
      {corr_rows}
    </table>
  </div>'''}

  <!-- ATTACK CHAIN -->
  {"" if not attack_chain else f'''
  <div style="margin:16px">
    <div style="font-family:monospace;font-size:11px;letter-spacing:2px;
                color:#00c060;margin-bottom:8px">▸ MITRE ATT&CK CHAIN</div>
    {chain_html}
  </div>'''}

  <!-- REASONING -->
  <div style="margin:16px">
    <div style="font-family:monospace;font-size:11px;letter-spacing:2px;
                color:#00c060;margin-bottom:8px">▸ HOLISTIC REASONING</div>
    <div style="background:#111916;border:1px solid #1e2e22;border-left:3px solid #00c060;
                padding:12px 16px;font-size:13px;line-height:1.7;color:#b8d4bc">
      {reasoning or "No reasoning available."}
    </div>
  </div>

  <!-- RECOMMENDATIONS -->
  {"" if not recs else f'''
  <div style="margin:16px">
    <div style="font-family:monospace;font-size:11px;letter-spacing:2px;
                color:#00c060;margin-bottom:8px">▸ RECOMMENDATIONS</div>
    <div style="background:#111916;border:1px solid #1e2e22;padding:8px 16px">
      {rec_html}
    </div>
  </div>'''}

  <!-- FOOTER -->
  <div style="background:#111916;border-top:1px solid #1e2e22;
              padding:12px 20px;margin-top:16px">
    <div style="font-size:10px;color:#5a7a5e;text-align:center;font-family:monospace">
      CYBER-MAS  —  Automated Threat Detection Report  —  {timestamp}<br/>
      Full PDF report attached to this email.
    </div>
  </div>

  <div style="background:#00c060;height:2px"></div>

</div>
</body>
</html>"""


def _build_plaintext(report: dict) -> str:
    """Plain-text fallback for email clients that don't render HTML."""
    corr      = report.get("correlator", {})
    verdict   = (corr.get("verdict") or "unknown").upper()
    risk      = corr.get("unified_risk", 0.0)
    report_id = report.get("report_id", corr.get("report_id", "N/A"))
    timestamp = report.get("timestamp", "")
    corrs     = corr.get("correlations", [])
    recs      = corr.get("recommendations", [])
    chain     = corr.get("attack_chain", [])

    lines = [
        "=" * 60,
        "CYBER-MAS — THREAT ANALYSIS REPORT",
        "=" * 60,
        f"Report ID  : {report_id}",
        f"Timestamp  : {timestamp}",
        f"Verdict    : {verdict}",
        f"Unified Risk: {risk:.2f} ({int(risk*100)}%)",
        f"Confidence : {corr.get('confidence',0):.2f}",
        "",
    ]

    lines.append("AGENT SUMMARY")
    lines.append("-" * 40)
    for a in report.get("agents", []):
        lines.append(f"  {a.get('agent','?').upper():<10} verdict={a.get('verdict','?')}  risk={a.get('risk_score',0):.2f}")

    if corrs:
        lines += ["", "CORRELATIONS", "-" * 40]
        for c in corrs:
            lines.append(f"  • {c}")

    if chain:
        lines += ["", "MITRE ATT&CK CHAIN", "-" * 40]
        lines.append("  " + " → ".join(chain))

    if recs:
        lines += ["", "RECOMMENDATIONS", "-" * 40]
        for i, r in enumerate(recs, 1):
            lines.append(f"  {i:02d}. {r}")

    reasoning = corr.get("reasoning","")
    if reasoning:
        lines += ["", "REASONING", "-" * 40, f"  {reasoning}"]

    lines += ["", "=" * 60, "Full PDF report attached.", "=" * 60]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SMTP send
# ══════════════════════════════════════════════════════════════════════════════

def _send_email(
    cfg:         dict,
    subject:     str,
    html_body:   str,
    plain_body:  str,
    pdf_bytes:   bytes,
    pdf_filename:str,
) -> bool:
    """
    Send an email via SMTP with a PDF attachment.
    Returns True on success, False on any error (never raises).
    """
    try:
        msg = MIMEMultipart("mixed")
        msg["From"]    = cfg["from_addr"]
        msg["To"]      = ", ".join(cfg["to_addrs"])
        msg["Subject"] = subject

        # Multipart/alternative for HTML + plain text
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain_body, "plain", "utf-8"))
        alt.attach(MIMEText(html_body,  "html",  "utf-8"))
        msg.attach(alt)

        # PDF attachment
        pdf_part = MIMEBase("application", "pdf")
        pdf_part.set_payload(pdf_bytes)
        encoders.encode_base64(pdf_part)
        pdf_part.add_header(
            "Content-Disposition",
            "attachment",
            filename=pdf_filename,
        )
        msg.attach(pdf_part)

        # Send
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            server.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())

        log.info(
            "Notifier: email sent to %s — subject: %s",
            cfg["to_addrs"], subject,
        )
        return True

    except smtplib.SMTPAuthenticationError:
        log.error("Notifier: SMTP authentication failed — check NOTIFY_SMTP_USER/PASS")
        return False
    except smtplib.SMTPException as exc:
        log.error("Notifier: SMTP error: %s", exc)
        return False
    except Exception as exc:
        log.error("Notifier: unexpected error sending email: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def should_notify(report: dict, min_verdict: str = "low") -> bool:
    """
    Return True if this report's verdict meets the minimum notification threshold.
    """
    corr    = report.get("correlator", {})
    verdict = (corr.get("verdict") or "uncertain").lower()
    min_sev = _VERDICT_SEVERITY.get(min_verdict, 0)
    cur_sev = _VERDICT_SEVERITY.get(verdict, 1)
    return cur_sev >= min_sev


def notify(report: dict, pdf_path: str | None = None) -> bool:
    """
    Send an email notification with the PDF report attached.

    Parameters
    ----------
    report   : full report dict from main.run() or correlator
    pdf_path : path to a pre-generated PDF (auto-generated if not provided)

    Returns
    -------
    True on success, False if skipped or failed.
    """
    cfg = _load_config()

    # ── Check enabled ─────────────────────────────────────────────────────────
    if not cfg["enabled"]:
        log.info("Notifier: disabled via NOTIFY_ENABLED=false")
        return False

    # ── Check recipients ──────────────────────────────────────────────────────
    if not cfg["to_addrs"]:
        log.warning("Notifier: NOTIFY_TO not set — skipping notification")
        return False

    if not cfg["smtp_user"] or not cfg["smtp_pass"]:
        log.warning("Notifier: NOTIFY_SMTP_USER or NOTIFY_SMTP_PASS not set — skipping")
        return False

    # ── Check verdict threshold ───────────────────────────────────────────────
    if not should_notify(report, cfg["min_verdict"]):
        corr    = report.get("correlator", {})
        verdict = corr.get("verdict","unknown")
        log.info(
            "Notifier: verdict '%s' below threshold '%s' — skipping",
            verdict, cfg["min_verdict"],
        )
        return False

    # ── Generate PDF ──────────────────────────────────────────────────────────
    corr      = report.get("correlator", {})
    verdict   = (corr.get("verdict") or "unknown").upper()
    risk      = corr.get("unified_risk", 0.0)
    report_id = report.get("report_id", corr.get("report_id", "N/A"))

    log.info("Notifier: generating PDF report …")
    try:
        from tools.report_generator import generate_pdf_bytes
        if pdf_path and Path(pdf_path).exists():
            pdf_bytes = Path(pdf_path).read_bytes()
        else:
            pdf_bytes = generate_pdf_bytes(report)
    except Exception as exc:
        log.error("Notifier: PDF generation failed: %s", exc)
        pdf_bytes = b""   # send email without attachment rather than failing

    pdf_filename = f"threat_report_{report_id}.pdf"

    # ── Build email ───────────────────────────────────────────────────────────
    subject    = f"[CYBER-MAS] {verdict} — Risk {int(risk*100)}% — Report {report_id}"
    html_body  = _build_html(report)
    plain_body = _build_plaintext(report)

    # ── Send ──────────────────────────────────────────────────────────────────
    log.info("Notifier: sending email — %s", subject)
    return _send_email(cfg, subject, html_body, plain_body, pdf_bytes, pdf_filename)


# ══════════════════════════════════════════════════════════════════════════════
# CLI  —  python cyber_mas/tools/notifier.py [--test] [--check]
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser(description="Cyber-MAS Email Notifier")
    parser.add_argument("--test",  action="store_true",
                        help="Send a test notification using mock report data")
    parser.add_argument("--check", action="store_true",
                        help="Check SMTP configuration without sending")
    parser.add_argument("--report", metavar="FILE",
                        help="Send notification for a specific JSON report file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    cfg = _load_config()

    if args.check:
        print("\n  Notifier configuration:")
        print("  " + "─" * 40)
        for k, v in cfg.items():
            if k == "smtp_pass":
                v = "***" if v else "(not set)"
            print(f"  {k:<15} : {v}")
        missing = [k for k in ("smtp_user","smtp_pass","to_addrs") if not cfg[k]]
        if missing:
            print(f"\n  ✗ Missing: {missing}")
        else:
            print("\n  ✓ Configuration looks complete")
        print()

    elif args.report:
        report = json.loads(Path(args.report).read_text())
        ok = notify(report)
        print(f"  {'✓ Sent' if ok else '✗ Failed'}")

    elif args.test:
        MOCK_REPORT = {
            "report_id": "test-001",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration":  42.1,
            "agents": [
                {"agent":"email","verdict":"phishing","risk_score":0.92,
                 "confidence":0.88,"_duration_secs":8.2,
                 "reasoning":"Domain spoofing detected.",
                 "indicators":["domain_spoofing","suspicious_url"],
                 "email_metadata":{"subject":"URGENT: Account suspended",
                                   "sender":"evil@phish.com","reply_to":"",
                                   "has_links":True,"link_count":3,"has_attachments":False},
                 "rag_match":{"label":"spam","similarity":0.91,"excerpt":"..."},
                 "mitre_techniques":[
                   {"technique_id":"T1566","technique_name":"Phishing",
                    "tactic_id":"TA0001","tactic_name":"Initial Access",
                    "description":"Phishing","source":"verdict","confidence":0.85,"url":""}
                 ]},
                {"agent":"log","verdict":"malicious","risk_score":0.88,
                 "confidence":0.90,"_duration_secs":3.1,
                 "reasoning":"SSH brute force followed by root login.",
                 "indicators":["ssh_brute_force","root_compromise"],
                 "signatures_hit":["brute_force","privilege_escalation"],
                 "stats":{"total_lines":10,"unique_ips":1,"time_span_secs":21,
                          "top_sources":["203.0.113.42"],"error_rate":0.7},
                 "mitre_techniques":[
                   {"technique_id":"T1110","technique_name":"Brute Force",
                    "tactic_id":"TA0006","tactic_name":"Credential Access",
                    "description":"Brute force","source":"signature:brute_force",
                    "confidence":0.95,"url":""}
                 ]},
            ],
            "correlator": {
                "report_id":"test-001",
                "verdict":"critical","unified_risk":0.921,"confidence":0.90,
                "reasoning":"Coordinated phishing and SSH brute force attack detected. Same IP appears in both log anomalies and phishing sender. Immediate isolation recommended.",
                "correlations":["C1_shared_ip","C2_phishing_and_breach","C4_multi_vector_high_risk"],
                "unified_indicators":[
                    "Same IPs appear in log anomalies and email sender.",
                    "Phishing + malicious log = coordinated intrusion.",
                    "All agents report risk > 0.6.",
                ],
                "recommendations":[
                    "Immediately isolate 203.0.113.42 from all network segments.",
                    "Force password reset for all accounts — especially root.",
                    "Review all SSH sessions opened in the last 24 hours.",
                    "Block the phishing domain paypa1-verify.com at DNS level.",
                ],
                "agent_summary":{
                    "email":{"verdict":"phishing","risk_score":0.92},
                    "log":  {"verdict":"malicious","risk_score":0.88},
                    "ip":   None,
                },
                "indicators":["domain_spoofing","suspicious_url","ssh_brute_force","root_compromise"],
                "unified_indicators":["Coordinated attack confirmed across 2 agents."],
                "attack_chain":["Initial Access","Credential Access","Privilege Escalation"],
                "mitre_techniques":[],
                "memory_matches":[],
            },
        }

        print("\n  Sending test notification …")
        ok = notify(MOCK_REPORT)
        print(f"  {'✓ Email sent successfully' if ok else '✗ Failed — check logs and config'}\n")

    else:
        parser.print_help()