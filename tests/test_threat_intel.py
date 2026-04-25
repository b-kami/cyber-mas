"""
tests/test_threat_intel.py
══════════════════════════════════════════════════════════════════════════════
Smoke test for the threat intelligence client.

Tests:
  1. Private IP detection      — no API calls made for RFC-1918 addresses
  2. Risk computation          — boost and block flag calculations
  3. Summary generation        — human-readable output
  4. MITRE mapping             — categories → technique IDs
  5. Prompt block formatting   — LLM context string
  6. IP extraction             — from mock agent results
  7. Live API calls (optional) — only if keys are set in .env

Run:
  python tests/test_threat_intel.py              # offline tests only
  python tests/test_threat_intel.py --live       # include real API calls
  python tests/test_threat_intel.py --live --ip 1.2.3.4  # specific IP
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)

def _ok(msg):   print(f"  \033[32m✓\033[0m  {msg}")
def _fail(msg): print(f"  \033[31m✗\033[0m  {msg}")
def _warn(msg): print(f"  \033[33m~\033[0m  {msg}")
def _head(msg): print(f"\n  \033[36m{'─'*50}\033[0m\n  {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# Test 1 — Private IP detection
# ══════════════════════════════════════════════════════════════════════════════

def test_private_ip():
    _head("TEST 1 — Private IP Detection")
    from tools.threat_intel import _is_private, enrich_ip

    privates = ["192.168.1.1", "10.0.0.5", "172.16.0.1", "127.0.0.1", "::1"]
    publics  = ["8.8.8.8", "1.1.1.1", "203.0.113.42"]

    for ip in privates:
        assert _is_private(ip), f"{ip} should be private"
        _ok(f"{ip} correctly identified as private")

    for ip in publics:
        assert not _is_private(ip), f"{ip} should be public"
        _ok(f"{ip} correctly identified as public")

    # Private IPs should return instantly with no API calls
    report = enrich_ip("192.168.1.1")
    assert report.sources_queried == []
    assert report.risk_boost == 0.0
    assert report.should_block == False
    _ok("Private IP enrich_ip() returns empty report instantly")


# ══════════════════════════════════════════════════════════════════════════════
# Test 2 — Risk computation
# ══════════════════════════════════════════════════════════════════════════════

def test_risk_computation():
    _head("TEST 2 — Risk Score Computation")
    from tools.threat_intel import (
        ThreatIntelReport, _compute_risk, ABUSE_BLOCK_THRESHOLD
    )

    cases = [
        # (abuse_score, vt_malicious, vt_total, shodan_tags, expected_block)
        (0,   0,  0,  [],              False),
        (30,  0,  0,  [],              False),
        (50,  0,  0,  [],              True),   # at threshold
        (80,  5, 90,  [],              True),
        (0,   5, 90,  [],              True),   # VT alone
        (0,   0,  0,  ["tor"],         True),   # Shodan alone
        (0,   2, 90,  [],              False),  # VT below threshold
        (100,15, 90,  ["scanner","vpn"],True),  # everything maxed
    ]

    all_pass = True
    for abuse, vt_mal, vt_total, stags, expected_block in cases:
        r = ThreatIntelReport(ip="1.2.3.4")
        r.abuse_score  = abuse
        r.vt_malicious = vt_mal
        r.vt_total     = vt_total
        r.shodan_tags  = stags
        _compute_risk(r)

        ok = r.should_block == expected_block
        if ok:
            _ok(f"abuse={abuse:3d} vt={vt_mal}/{vt_total:<3d} "
                f"shodan={stags} → block={r.should_block}  boost=+{r.risk_boost:.3f}")
        else:
            _fail(f"abuse={abuse:3d} vt={vt_mal}/{vt_total:<3d} "
                  f"shodan={stags} → block={r.should_block} (expected {expected_block})")
            all_pass = False

    # Check boost is capped at 0.30
    r = ThreatIntelReport(ip="1.2.3.4")
    r.abuse_score  = 100
    r.vt_malicious = 50
    r.vt_total     = 90
    r.shodan_tags  = list(["tor","scanner","malware","botnet","honeypot"])
    _compute_risk(r)
    assert r.risk_boost <= 0.30, f"Boost not capped: {r.risk_boost}"
    _ok(f"Boost capped at 0.30 (actual: {r.risk_boost})")

    if all_pass:
        _ok("All risk computation cases passed")


# ══════════════════════════════════════════════════════════════════════════════
# Test 3 — Summary generation
# ══════════════════════════════════════════════════════════════════════════════

def test_summary():
    _head("TEST 3 — Summary Generation")
    from tools.threat_intel import (
        ThreatIntelReport, _compute_risk, _build_summary
    )

    r = ThreatIntelReport(ip="203.0.113.42")
    r.abuse_score      = 85
    r.abuse_reports    = 234
    r.abuse_country    = "RU"
    r.abuse_isp        = "AS12345 Evil Corp"
    r.abuse_categories = ["SSH", "Brute-Force", "Hacking"]
    r.vt_malicious     = 12
    r.vt_total         = 90
    r.vt_tags          = ["scanner", "malware"]
    r.shodan_tags      = ["tor", "scanner"]
    r.shodan_org       = "Some Hosting Ltd"
    r.sources_queried  = ["AbuseIPDB", "VirusTotal", "Shodan"]
    _compute_risk(r)
    _build_summary(r)

    assert r.summary
    assert r.should_block
    assert "BLOCK" in r.summary.upper()
    _ok(f"Summary: {r.summary}")

    block_text = r.to_prompt_block()
    assert "203.0.113.42" in block_text
    assert "AbuseIPDB" in block_text
    assert "VirusTotal" in block_text
    assert "Shodan" in block_text
    _ok(f"Prompt block: {len(block_text)} chars")
    for line in block_text.splitlines():
        print(f"     {line}")


# ══════════════════════════════════════════════════════════════════════════════
# Test 4 — MITRE technique mapping
# ══════════════════════════════════════════════════════════════════════════════

def test_mitre_mapping():
    _head("TEST 4 — MITRE Technique Mapping from Intel")
    from tools.threat_intel import (
        ThreatIntelReport, _parse_abuseipdb, _parse_virustotal, _parse_shodan
    )

    r = ThreatIntelReport(ip="1.2.3.4")

    # Simulate AbuseIPDB response with SSH + Brute-Force categories
    abuse_data = {
        "abuseConfidenceScore": 90,
        "totalReports": 100,
        "countryCode": "CN",
        "isp": "Test ISP",
        "domain": "test.com",
        "reports": [
            {"categories": [22, 18]},   # SSH=22, Brute-Force=18
            {"categories": [15, 14]},   # Hacking=15, Port Scan=14
        ]
    }
    _parse_abuseipdb(abuse_data, r)

    expected_from_abuse = {"T1021.004", "T1110", "T1078", "T1046"}
    for tid in expected_from_abuse:
        if tid in r.mitre_techniques:
            _ok(f"Mapped from AbuseIPDB: {tid}")
        else:
            _warn(f"Expected {tid} from AbuseIPDB categories")

    # Simulate VT response with tags
    vt_data = {
        "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 70, "undetected": 10},
        "tags": ["tor", "scanner", "vpn"],
        "reputation": -50,
    }
    _parse_virustotal(vt_data, r)

    for tag, expected_tid in [("tor","T1090"), ("scanner","T1046"), ("vpn","T1572")]:
        if expected_tid in r.mitre_techniques:
            _ok(f"Mapped from VT tag '{tag}': {expected_tid}")
        else:
            _warn(f"Expected {expected_tid} from VT tag '{tag}'")

    _ok(f"Total MITRE techniques mapped: {len(r.mitre_techniques)} → {r.mitre_techniques}")


# ══════════════════════════════════════════════════════════════════════════════
# Test 5 — IP extraction from agent results
# ══════════════════════════════════════════════════════════════════════════════

def test_ip_extraction():
    _head("TEST 5 — IP Extraction from Agent Results")
    from tools.threat_intel import extract_ips_from_results

    mock_results = [
        {
            "agent": "log",
            "stats": {"top_sources": ["203.0.113.42", "192.168.1.1"]},  # private filtered
            "indicators": ["ssh_brute_force from 198.51.100.5"],
        },
        {
            "agent": "email",
            "email_metadata": {
                "sender":   "evil@phish.com",
                "reply_to": "noreply@203.0.113.42",   # IP in reply-to
            },
        },
        {
            "agent": "ip",
            "target": "203.0.113.42",
        },
    ]

    ips = extract_ips_from_results(mock_results)
    _ok(f"Extracted IPs: {ips}")

    assert "203.0.113.42" in ips, "Should extract log source IP"
    assert "198.51.100.5" in ips, "Should extract IP from indicator string"
    assert "192.168.1.1" not in ips, "Should filter private IP"
    _ok("Private IP 192.168.1.1 correctly filtered")
    _ok(f"Deduplicated: {len(ips)} unique public IPs found")


# ══════════════════════════════════════════════════════════════════════════════
# Test 6 — Live API calls (optional)
# ══════════════════════════════════════════════════════════════════════════════

def test_live_apis(ip: str = "1.1.1.1"):
    _head(f"TEST 6 — Live API Calls  (target: {ip})")

    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    has_abuse = bool(os.getenv("ABUSEIPDB_API_KEY"))
    has_vt    = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    has_shodan= bool(os.getenv("SHODAN_API_KEY"))

    _ok(f"ABUSEIPDB_API_KEY : {'SET' if has_abuse else 'NOT SET (will skip)'}")
    _ok(f"VIRUSTOTAL_API_KEY: {'SET' if has_vt    else 'NOT SET (will skip)'}")
    _ok(f"SHODAN_API_KEY    : {'SET' if has_shodan else 'NOT SET (InternetDB used)'}")

    from tools.threat_intel import enrich_ip

    print(f"\n  Querying threat intel for {ip} …")
    print(f"  (VirusTotal has 15s delay on free tier — please wait)\n")

    report = enrich_ip(ip)

    _ok(f"Sources queried : {report.sources_queried or ['none']}")
    _ok(f"Abuse score     : {report.abuse_score}/100  ({report.abuse_reports} reports)")
    _ok(f"VT malicious    : {report.vt_malicious}/{report.vt_total}")
    _ok(f"Shodan ports    : {report.shodan_ports[:8]}")
    _ok(f"Shodan tags     : {report.shodan_tags}")
    _ok(f"Should block    : {report.should_block}")
    _ok(f"Risk boost      : +{report.risk_boost:.3f}")
    _ok(f"MITRE techniques: {report.mitre_techniques}")
    _ok(f"Summary         : {report.summary}")

    print("\n  Full prompt block:")
    print("  " + "─"*48)
    for line in report.to_prompt_block().splitlines():
        print(f"  {line}")

    print(f"\n  Full JSON report:")
    print(json.dumps(report.to_dict(), indent=4))


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intel smoke test")
    parser.add_argument("--live",  action="store_true",
                        help="Include live API tests (requires .env keys)")
    parser.add_argument("--ip",    default="1.1.1.1",
                        help="IP to use for live tests (default: 1.1.1.1)")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  Cyber-MAS — Threat Intel Smoke Test")
    print(f"{'═'*60}")

    test_private_ip()
    test_risk_computation()
    test_summary()
    test_mitre_mapping()
    test_ip_extraction()

    if args.live:
        test_live_apis(args.ip)
    else:
        print(f"\n  \033[33m~\033[0m  Live API tests skipped — run with --live to include")
        print(f"  \033[33m~\033[0m  Use --ip <address> to specify target\n")

    print(f"\n{'═'*60}\n")