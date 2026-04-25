"""
tests/test_notification_pipeline.py
══════════════════════════════════════════════════════════════════════════════
End-to-end smoke test for the notification pipeline.

Tests (in order):
  1. PDF generation        — generates a real PDF from mock report
  2. PDF content check     — verifies file size and is valid PDF header
  3. HTML email body       — renders HTML, checks required sections present
  4. Plain text body       — checks all key fields present
  5. should_notify()       — verdict threshold logic
  6. Config check          — reads .env, reports what is / isn't set
  7. SMTP send (optional)  — only runs if NOTIFY_SMTP_USER is set in .env

Run:
  python tests/test_notification_pipeline.py
  python tests/test_notification_pipeline.py --send   # include live SMTP test
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1]))

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("test_notification")

# ══════════════════════════════════════════════════════════════════════════════
# Shared mock report
# ══════════════════════════════════════════════════════════════════════════════

MOCK_REPORT = {
    "report_id": "test-smoke-001",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "duration":  42.1,
    "agents": [
        {
            "agent": "email", "verdict": "phishing",
            "risk_score": 0.92, "confidence": 0.88,
            "_duration_secs": 8.2,
            "reasoning": (
                "The sender domain 'paypa1-verify.com' closely mimics PayPal "
                "using character substitution (1 for l). The email contains "
                "urgency language and a suspicious redirect URL. RAG similarity "
                "to known spam corpus is 0.91."
            ),
            "indicators": ["domain_spoofing", "urgency_language", "suspicious_url"],
            "email_metadata": {
                "subject":         "URGENT: Your PayPal account has been suspended",
                "sender":          "security-alert@paypa1-verify.com",
                "reply_to":        "noreply@203.0.113.42",
                "has_links":       True,
                "link_count":      3,
                "has_attachments": False,
            },
            "rag_match": {"label": "spam", "similarity": 0.91, "excerpt": "Claim your prize..."},
            "mitre_techniques": [
                {
                    "technique_id": "T1566", "technique_name": "Phishing",
                    "tactic_id": "TA0001", "tactic_name": "Initial Access",
                    "description": "Adversaries send phishing messages.",
                    "source": "verdict:phishing", "confidence": 0.85,
                    "url": "https://attack.mitre.org/techniques/T1566/",
                },
                {
                    "technique_id": "T1566.002", "technique_name": "Spearphishing Link",
                    "tactic_id": "TA0001", "tactic_name": "Initial Access",
                    "description": "Adversaries send emails with malicious links.",
                    "source": "email:link_count=3", "confidence": 0.85,
                    "url": "https://attack.mitre.org/techniques/T1566/002/",
                },
            ],
        },
        {
            "agent": "log", "verdict": "malicious",
            "risk_score": 0.88, "confidence": 0.90,
            "_duration_secs": 3.1,
            "reasoning": (
                "Seven consecutive failed SSH login attempts from 203.0.113.42 "
                "spanning 7 seconds, followed by a successful root login. "
                "This is a classic brute-force pattern with confirmed compromise."
            ),
            "indicators": ["ssh_brute_force", "root_compromise"],
            "signatures_hit": ["brute_force", "privilege_escalation"],
            "stats": {
                "total_lines":    10,
                "unique_ips":     1,
                "time_span_secs": 21.0,
                "top_sources":    ["203.0.113.42"],
                "error_rate":     0.7,
            },
            "mitre_techniques": [
                {
                    "technique_id": "T1110", "technique_name": "Brute Force",
                    "tactic_id": "TA0006", "tactic_name": "Credential Access",
                    "description": "Adversaries use brute force.",
                    "source": "signature:brute_force", "confidence": 0.95,
                    "url": "https://attack.mitre.org/techniques/T1110/",
                },
                {
                    "technique_id": "T1548", "technique_name": "Abuse Elevation Control",
                    "tactic_id": "TA0004", "tactic_name": "Privilege Escalation",
                    "description": "Adversaries bypass elevation controls.",
                    "source": "signature:privilege_escalation", "confidence": 0.95,
                    "url": "https://attack.mitre.org/techniques/T1548/",
                },
                {
                    "technique_id": "T1021.004", "technique_name": "SSH",
                    "tactic_id": "TA0008", "tactic_name": "Lateral Movement",
                    "description": "Adversaries use SSH for lateral movement.",
                    "source": "indicator:ssh_brute_force", "confidence": 0.80,
                    "url": "https://attack.mitre.org/techniques/T1021/004/",
                },
            ],
        },
        {
            "agent": "ip", "verdict": "vulnerable",
            "risk_score": 0.79, "confidence": 0.75,
            "_duration_secs": 22.4,
            "reasoning": (
                "Target 203.0.113.42 is running OpenSSH 7.2 which has 3 known "
                "critical CVEs. SMB port 445 is exposed. OS identified as Linux 4.x."
            ),
            "indicators": ["outdated_openssh", "smb_exposed", "High-risk ports open: [22, 445]"],
            "target": "203.0.113.42",
            "os_guess": "Linux 4.x (accuracy 85%)",
            "scan_duration": 18.4,
            "open_ports": [
                {"port": 22,  "protocol": "tcp", "service": "ssh",
                 "version": "OpenSSH 7.2", "state": "open"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds",
                 "version": "", "state": "open"},
                {"port": 80,  "protocol": "tcp", "service": "http",
                 "version": "Apache 2.4.7", "state": "open"},
            ],
            "cves": [
                {
                    "cve_id": "CVE-2016-6515", "cvss_score": 7.8, "severity": "HIGH",
                    "description": "OpenSSH allows remote attackers to cause DoS via crafted packets.",
                    "affected_service": "ssh",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6515",
                },
                {
                    "cve_id": "CVE-2017-0144", "cvss_score": 9.8, "severity": "CRITICAL",
                    "description": "SMBv1 remote code execution (EternalBlue).",
                    "affected_service": "microsoft-ds",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                },
            ],
            "mitre_techniques": [
                {
                    "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                    "tactic_id": "TA0001", "tactic_name": "Initial Access",
                    "description": "Adversaries exploit weaknesses in internet-facing software.",
                    "source": "cve:CVE-2017-0144", "confidence": 0.95,
                    "url": "https://attack.mitre.org/techniques/T1190/",
                },
                {
                    "technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares",
                    "tactic_id": "TA0008", "tactic_name": "Lateral Movement",
                    "description": "Adversaries use SMB for lateral movement.",
                    "source": "port:445/microsoft-ds", "confidence": 0.75,
                    "url": "https://attack.mitre.org/techniques/T1021/002/",
                },
            ],
        },
    ],
    "correlator": {
        "report_id":    "test-smoke-001",
        "verdict":      "critical",
        "unified_risk": 0.921,
        "confidence":   0.90,
        "reasoning": (
            "A coordinated multi-vector attack is confirmed. A phishing email "
            "from a PayPal-spoofing domain coincides with SSH brute-force activity "
            "from 203.0.113.42 that resulted in a successful root login. The same IP "
            "hosts critical CVEs including EternalBlue (CVSS 9.8). Three correlation "
            "rules fired simultaneously. Immediate containment is required."
        ),
        "correlations": [
            "C1_shared_ip",
            "C2_phishing_and_breach",
            "C3_vuln_and_exploit",
            "C4_multi_vector_high_risk",
        ],
        "unified_indicators": [
            "Same IP 203.0.113.42 appears in log anomalies, email sender, and network scan.",
            "Phishing email detected alongside malicious log activity — coordinated intrusion.",
            "Host has known CVEs AND log shows brute_force + privilege_escalation.",
            "All 3 active agents report risk > 0.6 — multi-vector attack confirmed.",
        ],
        "recommendations": [
            "IMMEDIATE: Isolate 203.0.113.42 from all network segments.",
            "URGENT: Force password reset for root and all accounts accessed from this IP.",
            "Block the domain paypa1-verify.com at DNS and email gateway level.",
            "Patch OpenSSH to latest version and disable SMBv1 on all hosts.",
            "Review all outbound connections from 203.0.113.42 in the last 72 hours.",
            "File an incident report and notify the security team.",
        ],
        "agent_summary": {
            "email": {"verdict": "phishing",   "risk_score": 0.92},
            "log":   {"verdict": "malicious",  "risk_score": 0.88},
            "ip":    {"verdict": "vulnerable", "risk_score": 0.79},
        },
        "indicators": [
            "domain_spoofing", "urgency_language", "suspicious_url",
            "ssh_brute_force", "root_compromise",
            "outdated_openssh", "smb_exposed",
        ],
        "unified_indicators_extra": ["Coordinated attack confirmed."],
        "attack_chain": [
            "Initial Access",
            "Credential Access",
            "Privilege Escalation",
            "Lateral Movement",
        ],
        "mitre_techniques": [],
        "memory_matches": [],
        "_duration_secs": 12.3,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Test runner
# ══════════════════════════════════════════════════════════════════════════════

def _ok(msg: str):  print(f"  \033[32m✓\033[0m  {msg}")
def _fail(msg: str):print(f"  \033[31m✗\033[0m  {msg}")
def _warn(msg: str):print(f"  \033[33m~\033[0m  {msg}")
def _head(msg: str):print(f"\n  \033[36m{'─'*50}\033[0m\n  {msg}")


def test_pdf_generation() -> bytes:
    _head("TEST 1 — PDF Generation")
    try:
        from tools.report_generator import generate_pdf_bytes, generate_pdf
        import tempfile, os

        # Test in-memory generation
        pdf_bytes = generate_pdf_bytes(MOCK_REPORT)
        assert len(pdf_bytes) > 1000, "PDF too small"
        assert pdf_bytes[:4] == b"%PDF", "Not a valid PDF"
        _ok(f"In-memory PDF generated — {len(pdf_bytes):,} bytes")

        # Test file-based generation
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmp_path = f.name
        path = generate_pdf(MOCK_REPORT, output_path=tmp_path)
        size = os.path.getsize(path)
        assert size > 1000, "PDF file too small"
        _ok(f"File PDF generated — {size:,} bytes → {path}")
        os.unlink(tmp_path)

        return pdf_bytes

    except ImportError as e:
        _fail(f"reportlab not installed: {e}")
        _warn("Run: pip install reportlab --break-system-packages")
        return b""
    except Exception as e:
        _fail(f"PDF generation failed: {e}")
        import traceback; traceback.print_exc()
        return b""


def test_pdf_sections(pdf_bytes: bytes):
    _head("TEST 2 — PDF Content Verification")
    if not pdf_bytes:
        _warn("Skipped — no PDF bytes")
        return

    # Extract text properly using pdfplumber (zlib-compressed streams
    # cannot be searched with a naive bytes.decode)
    try:
        import io, pdfplumber
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            pdf_str = "\n".join(
                (page.extract_text() or "") for page in pdf.pages
            )
    except ImportError:
        _warn("pdfplumber not installed — falling back to raw decode (may miss text)")
        pdf_str = pdf_bytes.decode("latin-1", errors="replace")
    checks = [
        ("CYBER-MAS",          "Title present"),
        ("CRITICAL",           "Verdict present"),
        ("EXECUTIVE SUMMARY",  "Executive summary section"),
        ("MITRE",              "MITRE ATT&CK section"),
        ("RECOMMENDATIONS",    "Recommendations section"),
        ("T1566",              "Technique ID present"),
        ("CVE-2017-0144",      "CVE present"),
        ("203.0.113.42",       "IP address present"),
    ]
    for needle, desc in checks:
        if needle in pdf_str:
            _ok(desc)
        else:
            _warn(f"{desc} — '{needle}' not found in PDF text")


def test_html_body():
    _head("TEST 3 — HTML Email Body")
    try:
        from tools.notifier import _build_html
        html = _build_html(MOCK_REPORT)

        assert len(html) > 500
        _ok(f"HTML generated — {len(html):,} chars")

        checks = [
            ("CRITICAL",             "Verdict in HTML"),
            ("92%",                  "Risk score"),
            ("test-smoke-001",       "Report ID"),
            ("C1_shared_ip",         "Correlation rule"),
            ("Initial Access",       "MITRE chain"),
            ("IMMEDIATE",            "Recommendation"),
            ("203.0.113.42",         "IP address"),
            ("AGENT SUMMARY",        "Agent summary section"),
            ("HOLISTIC REASONING",   "Reasoning section"),
        ]
        for needle, desc in checks:
            if needle in html:
                _ok(desc)
            else:
                _warn(f"{desc} — '{needle}' not found")

        # Save HTML for visual inspection
        out = Path("reports/test_email_preview.html")
        out.parent.mkdir(exist_ok=True)
        out.write_text(html, encoding="utf-8")
        _ok(f"HTML preview saved → {out}  (open in browser to inspect)")

    except Exception as e:
        _fail(f"HTML build failed: {e}")
        import traceback; traceback.print_exc()


def test_plain_body():
    _head("TEST 4 — Plain Text Email Body")
    try:
        from tools.notifier import _build_plaintext
        text = _build_plaintext(MOCK_REPORT)

        assert len(text) > 100
        _ok(f"Plain text generated — {len(text):,} chars")

        for needle in ["CRITICAL", "0.92", "C1_shared_ip",
                       "Initial Access", "IMMEDIATE", "test-smoke-001"]:
            if needle in text:
                _ok(f"'{needle}' present")
            else:
                _warn(f"'{needle}' not found")

    except Exception as e:
        _fail(f"Plain text build failed: {e}")


def test_should_notify():
    _head("TEST 5 — Verdict Threshold Logic")
    try:
        from tools.notifier import should_notify

        cases = [
            # (verdict, min_threshold, expected_result)
            ("critical", "low",      True),
            ("critical", "critical", True),
            ("high",     "critical", False),
            ("medium",   "medium",   True),
            ("medium",   "high",     False),
            ("low",      "low",      True),
            ("low",      "medium",   False),
            ("phishing", "low",      True),
            ("benign",   "low",      True),
            ("uncertain","medium",   False),
        ]

        all_pass = True
        for verdict, threshold, expected in cases:
            mock = {"correlator": {"verdict": verdict}}
            result = should_notify(mock, threshold)
            ok = result == expected
            if ok:
                _ok(f"verdict={verdict:<12} min={threshold:<10} → {result}")
            else:
                _fail(f"verdict={verdict:<12} min={threshold:<10} → {result} (expected {expected})")
                all_pass = False

        if all_pass:
            _ok("All threshold cases passed")

    except Exception as e:
        _fail(f"should_notify test failed: {e}")


def test_config_check():
    _head("TEST 6 — SMTP Configuration Check")
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    config_keys = {
        "NOTIFY_SMTP_HOST": ("smtp.gmail.com", False),
        "NOTIFY_SMTP_PORT": ("587",            False),
        "NOTIFY_SMTP_USER": ("",               True),   # required
        "NOTIFY_SMTP_PASS": ("",               True),   # required
        "NOTIFY_TO":        ("",               True),   # required
        "NOTIFY_FROM":      ("",               False),
        "NOTIFY_ON_VERDICT":("low",            False),
        "NOTIFY_ENABLED":   ("true",           False),
    }

    missing_required = []
    for key, (default, required) in config_keys.items():
        val = os.getenv(key, default)
        if key == "NOTIFY_SMTP_PASS" and val:
            display = "***" + val[-2:]
        else:
            display = val or "(not set)"

        if required and not val:
            _warn(f"{key:<22} → NOT SET  ← required for sending")
            missing_required.append(key)
        else:
            _ok(f"{key:<22} → {display}")

    if missing_required:
        _warn(f"\n  Add these to your .env file to enable notifications:")
        for k in missing_required:
            _warn(f"    {k}=your-value-here")
    else:
        _ok("All required SMTP variables are set")

    return len(missing_required) == 0


def test_live_smtp(pdf_bytes: bytes):
    _head("TEST 7 — Live SMTP Send (optional)")
    try:
        from tools.notifier import notify, _load_config
        cfg = _load_config()

        if not cfg["smtp_user"] or not cfg["smtp_pass"] or not cfg["to_addrs"]:
            _warn("Skipped — SMTP credentials not configured")
            _warn("Set NOTIFY_SMTP_USER, NOTIFY_SMTP_PASS, NOTIFY_TO in .env to enable")
            return

        _ok(f"Sending to: {cfg['to_addrs']}")
        ok = notify(MOCK_REPORT)
        if ok:
            _ok("Email sent successfully — check your inbox")
        else:
            _fail("Email send failed — check logs for details")

    except Exception as e:
        _fail(f"Live SMTP test failed: {e}")
        import traceback; traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber-MAS notification pipeline test")
    parser.add_argument("--send", action="store_true",
                        help="Include live SMTP send test (requires .env credentials)")
    parser.add_argument("--save-report", action="store_true",
                        help="Save mock report to reports/mock_report.json")
    args = parser.parse_args()

    print("\n" + "═"*60)
    print("  Cyber-MAS — Notification Pipeline Smoke Test")
    print("═"*60)

    if args.save_report:
        out = Path("reports/mock_report.json")
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(MOCK_REPORT, indent=2), encoding="utf-8")
        print(f"\n  Mock report saved → {out}\n")

    pdf_bytes    = test_pdf_generation()
    test_pdf_sections(pdf_bytes)
    test_html_body()
    test_plain_body()
    test_should_notify()
    smtp_ready   = test_config_check()

    if args.send:
        test_live_smtp(pdf_bytes)
    elif smtp_ready:
        _head("SMTP ready — run with --send to test live delivery")
    else:
        _head("Configure .env then run with --send to test live delivery")

    print("\n" + "═"*60 + "\n")