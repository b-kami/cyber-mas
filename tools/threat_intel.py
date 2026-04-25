"""
cyber_mas/tools/threat_intel.py
══════════════════════════════════════════════════════════════════════════════
Threat Intelligence Client — AbuseIPDB + VirusTotal + Shodan.

ROLE
────
  Enriches IP addresses with real-time reputation data from three sources:
    • AbuseIPDB  — community-reported abuse score (0-100)
    • VirusTotal — antivirus engine detections (malicious/total engines)
    • Shodan     — exposed services, known tags, historical data

  Results are merged into a single ThreatIntelReport per IP, which is then
  injected into:
    • ip_agent.py    — pre-scan enrichment (before Nmap / NVD)
    • correlator.py  — cross-check all IPs extracted from all agent results

EFFECTS WHEN MALICIOUS IP DETECTED
────────────────────────────────────
  1. Risk score boost   → proportional to abuse confidence
  2. Block flag         → intel_result.should_block = True (score > threshold)
  3. MITRE indicators   → adds T1078 / T1071 based on abuse categories
  4. LLM prompt context → formatted evidence block injected before reasoning

API KEYS (add to .env)
──────────────────────
  ABUSEIPDB_API_KEY   → https://www.abuseipdb.com/account/api
  VIRUSTOTAL_API_KEY  → https://www.virustotal.com/gui/my-apikey
  SHODAN_API_KEY      → https://account.shodan.io/

  All three are optional individually — the client gracefully skips any
  source whose key is missing. Free tier limits:
    AbuseIPDB  : 1,000 checks/day
    VirusTotal : 4 requests/min, 500/day
    Shodan     : 100 queries/month (free plan)

OUTPUT SCHEMA
─────────────
  ThreatIntelReport dataclass:
    ip               : str
    abuse_score      : int       0-100  (AbuseIPDB confidence)
    abuse_reports    : int       total community reports
    abuse_categories : list[str] e.g. ["SSH", "Brute-Force", "Hacking"]
    abuse_country    : str
    abuse_isp        : str
    vt_malicious     : int       engines flagging as malicious
    vt_total         : int       total engines scanned
    vt_tags          : list[str] VirusTotal community tags
    shodan_ports     : list[int] historically seen open ports
    shodan_tags      : list[str] e.g. ["vpn", "tor", "scanner"]
    shodan_vulns     : list[str] CVE IDs from Shodan
    shodan_org       : str
    should_block     : bool      True if any source flags as high-risk
    risk_boost       : float     0.0-0.30 additive boost to agent risk score
    sources_queried  : list[str] which APIs responded
    summary          : str       human-readable one-liner
    mitre_techniques : list[str] technique IDs inferred from intel

USAGE
─────
  from cyber_mas.tools.threat_intel import enrich_ip, enrich_all_ips

  report = enrich_ip("203.0.113.42")
  print(report.abuse_score, report.should_block, report.summary)

  # Batch (used by correlator)
  reports = enrich_all_ips(["1.2.3.4", "5.6.7.8"])

  # CLI
  python cyber_mas/tools/threat_intel.py 203.0.113.42
  python cyber_mas/tools/threat_intel.py --batch 1.2.3.4 5.6.7.8
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

log = logging.getLogger(__name__)

# ── Rate limiting ─────────────────────────────────────────────────────────────
_ABUSEIPDB_DELAY  = 0.3   # seconds between requests
_VIRUSTOTAL_DELAY = 15.0  # free tier: 4 req/min → 15s between calls
_SHODAN_DELAY     = 1.0

# ── Block thresholds ─────────────────────────────────────────────────────────
ABUSE_BLOCK_THRESHOLD = 50    # AbuseIPDB score 0-100
VT_BLOCK_THRESHOLD    = 3     # at least N engines flagging as malicious
SHODAN_BLOCK_TAGS     = {"tor", "scanner", "malware", "botnet", "honeypot"}

# ── Request timeout ───────────────────────────────────────────────────────────
_TIMEOUT = 10  # seconds

# ── AbuseIPDB category map ────────────────────────────────────────────────────
# https://www.abuseipdb.com/categories
_ABUSE_CATEGORIES = {
    1:  "DNS Compromise",    2:  "DNS Poisoning",     3:  "Fraud Orders",
    4:  "DDoS Attack",       5:  "FTP Brute-Force",   6:  "Ping of Death",
    7:  "Phishing",          8:  "Fraud VoIP",        9:  "Open Proxy",
    10: "Web Spam",          11: "Email Spam",        12: "Blog Spam",
    13: "VPN IP",            14: "Port Scan",         15: "Hacking",
    16: "SQL Injection",     17: "Spoofing",          18: "Brute-Force",
    19: "Bad Web Bot",       20: "Exploited Host",    21: "Web App Attack",
    22: "SSH",               23: "IoT Targeted",
}

# ── Category → MITRE technique ───────────────────────────────────────────────
_CATEGORY_MITRE = {
    "SSH":            "T1021.004",  # SSH lateral movement
    "Brute-Force":    "T1110",      # Brute Force
    "Phishing":       "T1566",      # Phishing
    "Port Scan":      "T1046",      # Network Service Discovery
    "SQL Injection":  "T1190",      # Exploit Public-Facing Application
    "Web App Attack": "T1190",
    "DDoS Attack":    "T1499",      # Endpoint DoS
    "Hacking":        "T1078",      # Valid Accounts
    "Exploited Host": "T1068",      # Exploitation for Privilege Escalation
    "Open Proxy":     "T1090",      # Proxy
    "VPN IP":         "T1572",      # Protocol Tunneling
}

# ── Private IP ranges (don't query external APIs for these) ──────────────────
# Note: Python 3.11+ classifies TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) as is_private=True. We exclude them from the private check
# because they're used as mock "public" IPs in docs and tests.
_TEST_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        # Allow documentation TEST-NET ranges through
        if any(addr in net for net in _TEST_NETS):
            return False
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Data model
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatIntelReport:
    ip:               str
    # AbuseIPDB
    abuse_score:      int        = 0
    abuse_reports:    int        = 0
    abuse_categories: list[str]  = field(default_factory=list)
    abuse_country:    str        = ""
    abuse_isp:        str        = ""
    abuse_domain:     str        = ""
    # VirusTotal
    vt_malicious:     int        = 0
    vt_suspicious:    int        = 0
    vt_total:         int        = 0
    vt_tags:          list[str]  = field(default_factory=list)
    vt_community_score: int      = 0
    # Shodan
    shodan_ports:     list[int]  = field(default_factory=list)
    shodan_tags:      list[str]  = field(default_factory=list)
    shodan_vulns:     list[str]  = field(default_factory=list)
    shodan_org:       str        = ""
    shodan_hostnames: list[str]  = field(default_factory=list)
    # Derived
    should_block:     bool       = False
    risk_boost:       float      = 0.0
    sources_queried:  list[str]  = field(default_factory=list)
    summary:          str        = ""
    mitre_techniques: list[str]  = field(default_factory=list)
    errors:           list[str]  = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip":               self.ip,
            "abuse_score":      self.abuse_score,
            "abuse_reports":    self.abuse_reports,
            "abuse_categories": self.abuse_categories,
            "abuse_country":    self.abuse_country,
            "abuse_isp":        self.abuse_isp,
            "vt_malicious":     self.vt_malicious,
            "vt_total":         self.vt_total,
            "vt_tags":          self.vt_tags,
            "shodan_ports":     self.shodan_ports,
            "shodan_tags":      self.shodan_tags,
            "shodan_vulns":     self.shodan_vulns,
            "shodan_org":       self.shodan_org,
            "should_block":     self.should_block,
            "risk_boost":       self.risk_boost,
            "sources_queried":  self.sources_queried,
            "summary":          self.summary,
            "mitre_techniques": self.mitre_techniques,
        }

    def to_prompt_block(self) -> str:
        """Format as evidence string for LLM prompt injection."""
        if not self.sources_queried:
            return f"[THREAT INTEL] {self.ip} — no data available"

        lines = [
            f"[THREAT INTEL REPORT — {self.ip}]",
            f"  Sources queried : {', '.join(self.sources_queried)}",
        ]

        if self.abuse_score > 0 or "AbuseIPDB" in self.sources_queried:
            lines.append(
                f"  AbuseIPDB       : score={self.abuse_score}/100  "
                f"reports={self.abuse_reports}  "
                f"country={self.abuse_country}  isp={self.abuse_isp}"
            )
            if self.abuse_categories:
                lines.append(f"  Abuse types     : {', '.join(self.abuse_categories)}")

        if "VirusTotal" in self.sources_queried:
            lines.append(
                f"  VirusTotal      : {self.vt_malicious}/{self.vt_total} engines flagged malicious"
            )
            if self.vt_tags:
                lines.append(f"  VT tags         : {', '.join(self.vt_tags)}")

        if "Shodan" in self.sources_queried:
            lines.append(
                f"  Shodan          : org={self.shodan_org}  "
                f"open_ports={self.shodan_ports[:8]}"
            )
            if self.shodan_tags:
                lines.append(f"  Shodan tags     : {', '.join(self.shodan_tags)}")
            if self.shodan_vulns:
                lines.append(f"  Shodan CVEs     : {', '.join(self.shodan_vulns[:5])}")

        lines.append(
            f"  Block flag      : {'YES ⚠' if self.should_block else 'NO'}  "
            f"risk_boost=+{self.risk_boost:.2f}"
        )
        if self.mitre_techniques:
            lines.append(f"  MITRE techniques: {', '.join(self.mitre_techniques)}")
        lines.append(f"  Summary         : {self.summary}")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# AbuseIPDB client
# ══════════════════════════════════════════════════════════════════════════════

def _query_abuseipdb(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB v2 API for IP reputation.
    Returns parsed response dict or {} on failure.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key":    api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90,
        "verbose":      True,
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            log.warning("AbuseIPDB: invalid API key")
        elif resp.status_code == 429:
            log.warning("AbuseIPDB: rate limit hit")
        else:
            log.warning("AbuseIPDB: HTTP %d for %s", resp.status_code, ip)
        return {}
    except requests.exceptions.RequestException as e:
        log.warning("AbuseIPDB: request failed for %s: %s", ip, e)
        return {}


def _parse_abuseipdb(data: dict, report: ThreatIntelReport) -> None:
    """Apply AbuseIPDB response data to the report."""
    report.abuse_score    = int(data.get("abuseConfidenceScore", 0))
    report.abuse_reports  = int(data.get("totalReports", 0))
    report.abuse_country  = data.get("countryCode", "")
    report.abuse_isp      = data.get("isp", "")
    report.abuse_domain   = data.get("domain", "")

    # Decode category IDs to names
    categories = set()
    for report_entry in data.get("reports", [])[:50]:
        for cat_id in report_entry.get("categories", []):
            name = _ABUSE_CATEGORIES.get(cat_id)
            if name:
                categories.add(name)
    report.abuse_categories = sorted(categories)

    # MITRE mapping from categories
    for cat in report.abuse_categories:
        tid = _CATEGORY_MITRE.get(cat)
        if tid and tid not in report.mitre_techniques:
            report.mitre_techniques.append(tid)

    report.sources_queried.append("AbuseIPDB")
    log.info("AbuseIPDB: %s → score=%d  reports=%d  categories=%s",
             report.ip, report.abuse_score, report.abuse_reports, report.abuse_categories)


# ══════════════════════════════════════════════════════════════════════════════
# VirusTotal client
# ══════════════════════════════════════════════════════════════════════════════

def _query_virustotal(ip: str, api_key: str) -> dict:
    """
    Query VirusTotal v3 API for IP address report.
    Returns parsed attributes dict or {} on failure.
    """
    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("data", {}).get("attributes", {})
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            log.warning("VirusTotal: invalid API key")
        elif resp.status_code == 429:
            log.warning("VirusTotal: rate limit hit (free tier: 4 req/min)")
        elif resp.status_code == 404:
            log.info("VirusTotal: no data for %s", ip)
        else:
            log.warning("VirusTotal: HTTP %d for %s", resp.status_code, ip)
        return {}
    except requests.exceptions.RequestException as e:
        log.warning("VirusTotal: request failed for %s: %s", ip, e)
        return {}


def _parse_virustotal(data: dict, report: ThreatIntelReport) -> None:
    """Apply VirusTotal response data to the report."""
    last_analysis = data.get("last_analysis_stats", {})
    report.vt_malicious  = int(last_analysis.get("malicious",  0))
    report.vt_suspicious = int(last_analysis.get("suspicious", 0))
    report.vt_total      = sum(last_analysis.values())
    report.vt_tags       = data.get("tags", [])
    report.vt_community_score = int(data.get("reputation", 0))

    # MITRE mapping from VT tags
    tag_mitre = {
        "tor":      "T1090",   # Proxy
        "proxy":    "T1090",
        "vpn":      "T1572",   # Protocol Tunneling
        "scanner":  "T1046",   # Network Service Discovery
        "malware":  "T1071",   # C2
        "botnet":   "T1071",
        "phishing": "T1566",
    }
    for tag in report.vt_tags:
        tid = tag_mitre.get(tag.lower())
        if tid and tid not in report.mitre_techniques:
            report.mitre_techniques.append(tid)

    report.sources_queried.append("VirusTotal")
    log.info("VirusTotal: %s → malicious=%d/%d  tags=%s",
             report.ip, report.vt_malicious, report.vt_total, report.vt_tags)


# ══════════════════════════════════════════════════════════════════════════════
# Shodan client
# ══════════════════════════════════════════════════════════════════════════════

def _query_shodan(ip: str, api_key: str) -> dict:
    """
    Query Shodan InternetDB (free, no key needed) + host API (key needed).
    Falls back to InternetDB if no key is provided.
    Returns merged dict or {} on failure.
    """
    result = {}

    # Always try InternetDB (free, no key, fast)
    try:
        resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["ports"]     = data.get("ports", [])
            result["tags"]      = data.get("tags", [])
            result["vulns"]     = data.get("vulns", [])
            result["hostnames"] = data.get("hostnames", [])
            result["cpes"]      = data.get("cpes", [])
        elif resp.status_code == 404:
            log.info("Shodan InternetDB: no data for %s", ip)
    except requests.exceptions.RequestException as e:
        log.warning("Shodan InternetDB: request failed for %s: %s", ip, e)

    # If key available, enrich with full host API (org, country, etc.)
    if api_key:
        try:
            resp2 = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
                timeout=_TIMEOUT,
            )
            if resp2.status_code == 200:
                host_data = resp2.json()
                result["org"]     = host_data.get("org", "")
                result["country"] = host_data.get("country_name", "")
                # Merge ports if not already from InternetDB
                if "ports" not in result:
                    result["ports"] = host_data.get("ports", [])
                if "tags" not in result:
                    result["tags"] = host_data.get("tags", [])
                if "vulns" not in result:
                    result["vulns"] = list(host_data.get("vulns", {}).keys())
            elif resp2.status_code == 401:
                log.warning("Shodan: invalid API key")
            elif resp2.status_code == 404:
                log.info("Shodan host API: no data for %s", ip)
        except requests.exceptions.RequestException as e:
            log.warning("Shodan host API: request failed for %s: %s", ip, e)

    return result


def _parse_shodan(data: dict, report: ThreatIntelReport) -> None:
    """Apply Shodan response data to the report."""
    report.shodan_ports     = [int(p) for p in data.get("ports", [])]
    report.shodan_tags      = data.get("tags", [])
    report.shodan_vulns     = data.get("vulns", [])
    report.shodan_org       = data.get("org", "")
    report.shodan_hostnames = data.get("hostnames", [])

    # MITRE from Shodan tags
    tag_mitre = {
        "tor":       "T1090",
        "vpn":       "T1572",
        "scanner":   "T1046",
        "malware":   "T1071",
        "botnet":    "T1071",
        "honeypot":  "T1078",
        "self-signed":"T1071",
    }
    for tag in report.shodan_tags:
        tid = tag_mitre.get(tag.lower())
        if tid and tid not in report.mitre_techniques:
            report.mitre_techniques.append(tid)

    report.sources_queried.append("Shodan")
    log.info("Shodan: %s → ports=%s  tags=%s  vulns=%s  org=%s",
             report.ip, report.shodan_ports[:8], report.shodan_tags,
             report.shodan_vulns[:3], report.shodan_org)


# ══════════════════════════════════════════════════════════════════════════════
# Risk aggregation
# ══════════════════════════════════════════════════════════════════════════════

def _compute_risk(report: ThreatIntelReport) -> None:
    """
    Compute should_block flag and risk_boost from all source signals.

    Risk boost scale (additive, capped at 0.30):
      AbuseIPDB score 0-100 → mapped to 0.0-0.15
      VT malicious engines  → each engine adds 0.01, capped at 0.10
      Shodan danger tags    → each tag adds 0.02, capped at 0.05
    """
    boost = 0.0

    # AbuseIPDB contribution
    if report.abuse_score > 0:
        boost += (report.abuse_score / 100) * 0.15
        if report.abuse_score >= ABUSE_BLOCK_THRESHOLD:
            report.should_block = True

    # VirusTotal contribution
    if report.vt_total > 0:
        vt_boost = min(report.vt_malicious * 0.01, 0.10)
        boost   += vt_boost
        if report.vt_malicious >= VT_BLOCK_THRESHOLD:
            report.should_block = True

    # Shodan contribution
    danger_tags = set(report.shodan_tags) & SHODAN_BLOCK_TAGS
    shodan_boost = min(len(danger_tags) * 0.02, 0.05)
    boost       += shodan_boost
    if danger_tags:
        report.should_block = True

    report.risk_boost = round(min(boost, 0.30), 3)


def _build_summary(report: ThreatIntelReport) -> None:
    """Build a concise one-line summary of the threat intel findings."""
    parts = []

    if report.abuse_score > 0:
        level = (
            "HIGH-RISK" if report.abuse_score >= 75 else
            "SUSPICIOUS" if report.abuse_score >= 25 else
            "LOW-RISK"
        )
        parts.append(
            f"AbuseIPDB: {level} (score={report.abuse_score}, "
            f"{report.abuse_reports} reports, {report.abuse_country})"
        )

    if report.vt_malicious > 0:
        parts.append(
            f"VirusTotal: {report.vt_malicious}/{report.vt_total} engines malicious"
        )

    if report.shodan_tags:
        parts.append(f"Shodan: tags=[{', '.join(report.shodan_tags)}]")

    if not parts:
        if report.sources_queried:
            report.summary = f"No threat intelligence found for {report.ip}"
        else:
            report.summary = f"No threat intel sources available for {report.ip}"
        return

    status = "⚠ BLOCK RECOMMENDED" if report.should_block else "monitor"
    report.summary = f"{status} — " + " | ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def enrich_ip(
    ip:            str,
    abuseipdb_key: str | None = None,
    virustotal_key:str | None = None,
    shodan_key:    str | None = None,
) -> ThreatIntelReport:
    """
    Query all available threat intel sources for a single IP address.

    Parameters
    ----------
    ip             : IPv4 address to check
    *_key          : API keys (auto-loaded from env if not provided)

    Returns
    -------
    ThreatIntelReport — always returns, never raises.
    Private/loopback IPs return an empty report instantly.
    """
    # Load keys from env if not passed
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    abuseipdb_key  = abuseipdb_key  or os.getenv("ABUSEIPDB_API_KEY",  "")
    virustotal_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY", "")
    shodan_key     = shodan_key     or os.getenv("SHODAN_API_KEY",     "")

    report = ThreatIntelReport(ip=ip)

    # Skip private IPs
    if _is_private(ip):
        report.summary = f"{ip} is a private/loopback address — no external intel available"
        log.info("Threat intel: skipping private IP %s", ip)
        return report

    log.info("Threat intel: querying %s …", ip)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    if abuseipdb_key:
        data = _query_abuseipdb(ip, abuseipdb_key)
        if data:
            _parse_abuseipdb(data, report)
        time.sleep(_ABUSEIPDB_DELAY)
    else:
        log.info("Threat intel: AbuseIPDB key not set — skipping")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if virustotal_key:
        data = _query_virustotal(ip, virustotal_key)
        if data:
            _parse_virustotal(data, report)
        time.sleep(_VIRUSTOTAL_DELAY)
    else:
        log.info("Threat intel: VirusTotal key not set — skipping")

    # ── Shodan ────────────────────────────────────────────────────────────────
    # Note: InternetDB is queried even without a key
    data = _query_shodan(ip, shodan_key)
    if data:
        _parse_shodan(data, report)
    time.sleep(_SHODAN_DELAY)

    # ── Aggregate ─────────────────────────────────────────────────────────────
    _compute_risk(report)
    _build_summary(report)

    log.info(
        "Threat intel: %s → block=%s  boost=+%.2f  sources=%s",
        ip, report.should_block, report.risk_boost, report.sources_queried,
    )
    return report


def enrich_all_ips(
    ips: list[str],
    **kwargs,
) -> dict[str, ThreatIntelReport]:
    """
    Enrich multiple IPs, returning a dict keyed by IP address.
    Deduplicates IPs, skips private addresses.

    Parameters
    ----------
    ips    : list of IP strings (may contain duplicates / private IPs)
    kwargs : passed through to enrich_ip()

    Returns
    -------
    dict[ip → ThreatIntelReport]
    """
    unique_ips = list(dict.fromkeys(  # preserve order, deduplicate
        ip.strip() for ip in ips if ip.strip()
    ))

    results: dict[str, ThreatIntelReport] = {}
    for ip in unique_ips:
        try:
            results[ip] = enrich_ip(ip, **kwargs)
        except Exception as exc:
            log.warning("Threat intel: unexpected error for %s: %s", ip, exc)
            r = ThreatIntelReport(ip=ip)
            r.errors.append(str(exc))
            results[ip] = r

    return results


def extract_ips_from_results(agent_results: list[dict]) -> list[str]:
    """
    Extract all IP addresses mentioned across a list of agent result dicts.
    Used by the correlator to find IPs to cross-check.
    """
    import re
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ips: list[str] = []

    for r in agent_results:
        # ip_agent target
        if r.get("target"):
            ips += ip_re.findall(str(r["target"]))

        # log agent top_sources
        for src in r.get("stats", {}).get("top_sources", []):
            ips += ip_re.findall(str(src))

        # email agent sender / reply_to
        meta = r.get("email_metadata", {})
        for field in ("sender", "reply_to"):
            ips += ip_re.findall(str(meta.get(field, "")))

        # indicators (may contain IPs)
        for ind in r.get("indicators", []):
            ips += ip_re.findall(str(ind))

    # Filter private IPs
    return [ip for ip in dict.fromkeys(ips) if not _is_private(ip)]


def intel_to_mitre_techniques(reports: dict[str, ThreatIntelReport]) -> list[dict]:
    """
    Convert threat intel MITRE technique IDs to full technique dicts
    compatible with the mitre_mapper output format.
    Used by the correlator to add intel-derived techniques to the report.
    """
    try:
        from tools.mitre_mapper import _TECH_BY_ID
    except ImportError:
        return []

    techniques = []
    seen: set[str] = set()

    for ip, intel in reports.items():
        for tid in intel.mitre_techniques:
            if tid in seen:
                continue
            seen.add(tid)
            entry = _TECH_BY_ID.get(tid)
            if entry:
                techniques.append({
                    "technique_id":   entry["technique_id"],
                    "technique_name": entry["technique_name"],
                    "tactic_id":      entry["tactic_id"],
                    "tactic_name":    entry["tactic_name"],
                    "description":    entry["description"],
                    "source":         f"threat_intel:{ip}",
                    "confidence":     0.90,
                    "url":            f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                })

    return techniques


# ══════════════════════════════════════════════════════════════════════════════
# CLI  —  python cyber_mas/tools/threat_intel.py <ip> [<ip2> ...]
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.INFO,
    )

    parser = argparse.ArgumentParser(
        description="Cyber-MAS Threat Intelligence Client",
        epilog="API keys are auto-loaded from .env file."
    )
    parser.add_argument("ips", nargs="*",
                        help="IP address(es) to check")
    parser.add_argument("--batch", nargs="+", metavar="IP",
                        help="Check multiple IPs")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON")
    args = parser.parse_args()

    targets = list(args.ips or []) + list(args.batch or [])
    if not targets:
        parser.print_help()
        raise SystemExit(0)

    print(f"\n{'═'*60}")
    print(f"  Cyber-MAS — Threat Intelligence")
    print(f"{'═'*60}\n")

    results = enrich_all_ips(targets)

    for ip, report in results.items():
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"  {'─'*56}")
            print(f"  IP     : {ip}")
            print(f"  Block  : {'⚠ YES' if report.should_block else 'NO'}")
            print(f"  Boost  : +{report.risk_boost:.2f}")
            print(f"  Sources: {', '.join(report.sources_queried) or 'none'}")
            if report.abuse_score:
                print(f"  Abuse  : {report.abuse_score}/100  ({report.abuse_reports} reports)  "
                      f"{report.abuse_country}  {report.abuse_isp}")
            if report.vt_malicious:
                print(f"  VT     : {report.vt_malicious}/{report.vt_total} malicious  "
                      f"tags={report.vt_tags}")
            if report.shodan_ports:
                print(f"  Shodan : ports={report.shodan_ports[:8]}  "
                      f"tags={report.shodan_tags}  org={report.shodan_org}")
            if report.mitre_techniques:
                print(f"  MITRE  : {', '.join(report.mitre_techniques)}")
            print(f"  Summary: {report.summary}")
    print()