"""
cyber_mas/agents/correlator.py
══════════════════════════════════════════════════════════════════════════════
Cross-Agent Threat Correlator.

ROLE
────
  Receives the result dicts from one or more specialist agents
  (email, log, ip), finds cross-agent correlations, computes a unified
  threat score, and calls LLaMA for a final holistic assessment.

CORRELATION RULES
─────────────────
  C1  shared_ip           — same IP appears in log + ip agent results
  C2  phishing_and_breach — email verdict=phishing AND log verdict=malicious
  C3  vuln_and_exploit    — ip has open CVEs AND log shows exploitation patterns
  C4  multi_vector        — 3 agents all return risk_score > 0.6
  C5  c2_beacon_and_ip    — log hits malware_c2 signature AND ip agent ran
  C6  recon_pattern       — port_scan in log sigs AND ip agent found many ports

UNIFIED RISK SCORE
──────────────────
  base      = weighted average of individual agent risk scores
  boosters  = each correlation rule that fires adds +0.08 (capped at 1.0)
  final     = min(base + boosters, 1.0)

OUTPUT SCHEMA
─────────────
  {
      "agent"           : "correlator",
      "verdict"         : "critical" | "high" | "medium" | "low" | "uncertain",
      "unified_risk"    : float,      # 0.0 – 1.0
      "confidence"      : float,      # 0.0 – 1.0
      "reasoning"       : str,
      "correlations"    : list[str],  # which rules fired
      "recommendations" : list[str],  # actionable response steps
      "agent_summary"   : {           # per-agent verdicts at a glance
          "email" : {verdict, risk_score} | null,
          "log"   : {verdict, risk_score} | null,
          "ip"    : {verdict, risk_score} | null,
      },
      "indicators"      : list[str],  # merged from all agents + new ones
      "unified_indicators": list[str] # correlator-specific findings
  }

USAGE
─────
  from cyber_mas.agents.correlator import correlate

  # Single agent result
  correlate([email_result])

  # Multiple agents (typical)
  correlate([email_result, log_result, ip_result])
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from cyber_mas.tools.llm_client import ask
from cyber_mas.tools.prompts import correlator_system_prompt, correlator_user_prompt

log = logging.getLogger(__name__)

# ── Verdict thresholds ────────────────────────────────────────────────────────
_RISK_THRESHOLDS = {
    "critical": 0.85,
    "high":     0.65,
    "medium":   0.40,
    "low":      0.0,
}

_VALID_VERDICTS = {"critical", "high", "medium", "low", "uncertain"}

# Weight per agent when computing base risk score
_AGENT_WEIGHTS = {
    "email": 0.30,
    "log":   0.40,   # log evidence is often most reliable
    "ip":    0.30,
}

# Each correlation rule that fires boosts the unified score by this amount
_CORRELATION_BOOST = 0.08

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


# ══════════════════════════════════════════════════════════════════════════════
# Result normalisation
# ══════════════════════════════════════════════════════════════════════════════

def _extract_agent_result(results: list[dict], agent_type: str) -> dict | None:
    """Return the first result dict whose 'agent' field matches *agent_type*."""
    for r in results:
        if str(r.get("agent", "")).lower() == agent_type:
            return r
    return None


def _safe_risk(result: dict | None, default: float = 0.0) -> float:
    if result is None:
        return default
    try:
        return max(0.0, min(1.0, float(result.get("risk_score", default))))
    except (TypeError, ValueError):
        return default


def _safe_verdict(result: dict | None) -> str:
    if result is None:
        return "none"
    return str(result.get("verdict", "none")).lower()


def _collect_indicators(results: list[dict]) -> list[str]:
    """Merge 'indicators' lists from all agent results, deduplicated."""
    seen: set[str] = set()
    merged: list[str] = []
    for r in results:
        for ind in r.get("indicators", []):
            ind_str = str(ind).strip()
            if ind_str and ind_str not in seen:
                seen.add(ind_str)
                merged.append(ind_str)
    return merged


def _collect_ips(results: list[dict]) -> set[str]:
    """
    Extract all IP addresses mentioned across all agent results.
    Looks in: email_metadata sender/reply_to, log stats top_sources,
    ip agent target and open_ports.
    """
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ips: set[str] = set()

    for r in results:
        # ip agent target
        if r.get("agent") == "ip" and r.get("target"):
            ips.update(ip_re.findall(str(r["target"])))

        # log agent top_sources
        stats = r.get("stats", {})
        for src in stats.get("top_sources", []):
            ips.update(ip_re.findall(str(src)))

        # email agent sender / reply_to
        meta = r.get("email_metadata", {})
        for field in ("sender", "reply_to"):
            ips.update(ip_re.findall(str(meta.get(field, ""))))

        # scan through all indicators
        for ind in r.get("indicators", []):
            ips.update(ip_re.findall(str(ind)))

    return ips


# ══════════════════════════════════════════════════════════════════════════════
# Correlation rules
# ══════════════════════════════════════════════════════════════════════════════

def _run_correlations(
    email_r: dict | None,
    log_r:   dict | None,
    ip_r:    dict | None,
    all_ips: set[str],
) -> tuple[list[str], list[str]]:
    """
    Evaluate all correlation rules.

    Returns
    -------
    (correlations_fired: list[str], unified_indicators: list[str])
    """
    fired: list[str] = []
    unified_indicators: list[str] = []

    # ── C1: Shared IP between log sources and ip agent target ─────────────────
    if log_r and ip_r:
        log_ips = set()
        for src in log_r.get("stats", {}).get("top_sources", []):
            ip_match = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", str(src))
            log_ips.update(ip_match)

        ip_target_ips = set(
            re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", str(ip_r.get("target", "")))
        )
        shared = log_ips & ip_target_ips
        if shared:
            fired.append("C1_shared_ip")
            unified_indicators.append(
                f"Same IP(s) {shared} appear in both log anomalies and network scan."
            )

    # ── C2: Phishing email + malicious log activity ───────────────────────────
    if (
        email_r and log_r
        and _safe_verdict(email_r) == "phishing"
        and _safe_verdict(log_r)   == "malicious"
    ):
        fired.append("C2_phishing_and_breach")
        unified_indicators.append(
            "Phishing email detected alongside malicious log activity — "
            "likely coordinated intrusion attempt."
        )

    # ── C3: Open CVEs + exploitation patterns in logs ─────────────────────────
    if ip_r and log_r:
        has_cves    = len(ip_r.get("cves", [])) > 0
        exploit_sigs = {"brute_force", "web_attack", "lateral_movement", "malware_c2"}
        log_sigs    = set(log_r.get("signatures_hit", []))
        overlap     = exploit_sigs & log_sigs
        if has_cves and overlap:
            fired.append("C3_vuln_and_exploit")
            unified_indicators.append(
                f"Host has known CVEs AND log shows exploitation patterns: {list(overlap)}."
            )

    # ── C4: All active agents return high risk ────────────────────────────────
    active = [r for r in [email_r, log_r, ip_r] if r is not None]
    high_risk = [r for r in active if _safe_risk(r) > 0.6]
    if len(active) >= 2 and len(high_risk) == len(active):
        fired.append("C4_multi_vector_high_risk")
        unified_indicators.append(
            f"All {len(active)} active agents report risk > 0.6 — "
            "multi-vector attack is highly probable."
        )

    # ── C5: C2 beaconing in logs + network scan ran ───────────────────────────
    if log_r and ip_r:
        if "malware_c2" in log_r.get("signatures_hit", []):
            fired.append("C5_c2_beacon_and_network_scan")
            unified_indicators.append(
                "C2 beaconing detected in logs; network scan results available "
                "for pivot analysis."
            )

    # ── C6: Port scan in logs + ip agent found many open ports ───────────────
    if log_r and ip_r:
        has_port_scan_sig = "port_scan" in log_r.get("signatures_hit", [])
        many_ports        = len(ip_r.get("open_ports", [])) >= 5
        if has_port_scan_sig and many_ports:
            fired.append("C6_recon_pattern")
            unified_indicators.append(
                f"Port-scan signature in logs + {len(ip_r.get('open_ports', []))} "
                "open ports on scanned host suggests active reconnaissance."
            )

    return fired, unified_indicators


# ══════════════════════════════════════════════════════════════════════════════
# Unified risk score
# ══════════════════════════════════════════════════════════════════════════════

def _compute_unified_risk(
    email_r:      dict | None,
    log_r:        dict | None,
    ip_r:         dict | None,
    correlations: list[str],
) -> float:
    """
    Weighted average of agent scores + correlation boosts, capped at 1.0.
    """
    total_weight = 0.0
    weighted_sum = 0.0

    for agent_type, weight in _AGENT_WEIGHTS.items():
        result = {"email": email_r, "log": log_r, "ip": ip_r}[agent_type]
        if result is not None:
            weighted_sum  += _safe_risk(result) * weight
            total_weight  += weight

    base = (weighted_sum / total_weight) if total_weight > 0 else 0.0
    boost = len(correlations) * _CORRELATION_BOOST
    return min(round(base + boost, 3), 1.0)


def _risk_to_verdict(risk: float) -> str:
    for verdict, threshold in _RISK_THRESHOLDS.items():
        if risk >= threshold:
            return verdict
    return "low"


# ══════════════════════════════════════════════════════════════════════════════
# LLM response parsing
# ══════════════════════════════════════════════════════════════════════════════

def _parse_llm_response(raw: str) -> dict:
    def _try(text: str) -> dict | None:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return None

    parsed = _try(raw)
    if parsed is None:
        m = _JSON_BLOCK_RE.search(raw)
        if m:
            parsed = _try(m.group(1))
    if parsed is None:
        s, e = raw.find("{"), raw.rfind("}")
        if s != -1 and e > s:
            parsed = _try(raw[s : e + 1])

    if parsed is None:
        log.error("Could not parse JSON from LLM response:\n%s", raw[:500])
        return {
            "verdict":         "uncertain",
            "confidence":      0.1,
            "reasoning":       "LLM returned unparseable output.",
            "recommendations": [],
        }

    verdict = str(parsed.get("verdict", "uncertain")).lower().strip()
    if verdict not in _VALID_VERDICTS:
        verdict = "uncertain"

    def _clamp(v: Any, default: float) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return default

    return {
        "verdict":         verdict,
        "confidence":      _clamp(parsed.get("confidence"), 0.5),
        "reasoning":       str(parsed.get("reasoning", "")),
        "recommendations": list(parsed.get("recommendations", [])),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def correlate(agent_results: list[dict]) -> dict:
    """
    Correlate results from multiple specialist agents into a unified assessment.

    Parameters
    ----------
    agent_results : list of result dicts from email_agent, log_agent, ip_agent.
                    Can be 1, 2, or 3 agents — the correlator adapts.

    Returns
    -------
    dict conforming to the OUTPUT SCHEMA above.
    """
    if not agent_results:
        raise ValueError("correlate() requires at least one agent result dict.")

    # ── Step 1 — Extract per-agent results ───────────────────────────────────
    email_r = _extract_agent_result(agent_results, "email")
    log_r   = _extract_agent_result(agent_results, "log")
    ip_r    = _extract_agent_result(agent_results, "ip")

    active_agents = [a for a in [email_r, log_r, ip_r] if a is not None]
    log.info(
        "Correlator: processing results from %d agent(s): %s",
        len(active_agents),
        [r.get("agent") for r in active_agents],
    )

    # ── Step 2 — Collect shared IPs across all results ────────────────────────
    all_ips = _collect_ips(agent_results)

    # ── Step 3 — Run correlation rules ────────────────────────────────────────
    log.info("Correlator: running correlation rules …")
    correlations, unified_indicators = _run_correlations(
        email_r, log_r, ip_r, all_ips
    )
    log.info("Correlator: rules fired → %s", correlations or "none")

    # ── Step 4 — Unified risk score ───────────────────────────────────────────
    unified_risk   = _compute_unified_risk(email_r, log_r, ip_r, correlations)
    pre_llm_verdict = _risk_to_verdict(unified_risk)
    log.info(
        "Correlator: unified_risk=%.3f  pre-LLM verdict=%s",
        unified_risk, pre_llm_verdict,
    )

    # ── Step 5 — Merge all indicators ─────────────────────────────────────────
    all_indicators = _collect_indicators(agent_results)

    # ── Step 6 — Build per-agent summary for prompt + output ─────────────────
    agent_summary = {
        "email": (
            {"verdict": _safe_verdict(email_r), "risk_score": _safe_risk(email_r)}
            if email_r else None
        ),
        "log": (
            {"verdict": _safe_verdict(log_r), "risk_score": _safe_risk(log_r)}
            if log_r else None
        ),
        "ip": (
            {"verdict": _safe_verdict(ip_r), "risk_score": _safe_risk(ip_r)}
            if ip_r else None
        ),
    }

    # ── Step 7 — Build prompts ────────────────────────────────────────────────
    system_prompt = correlator_system_prompt()
    user_prompt   = correlator_user_prompt(
        agent_summary      = agent_summary,
        correlations       = correlations,
        unified_risk       = unified_risk,
        unified_indicators = unified_indicators,
        all_indicators     = all_indicators,
        email_reasoning    = email_r.get("reasoning", "") if email_r else "",
        log_reasoning      = log_r.get("reasoning",  "") if log_r   else "",
        ip_reasoning       = ip_r.get("reasoning",   "") if ip_r    else "",
    )

    # ── Step 8 — LLM call ─────────────────────────────────────────────────────
    log.info("Correlator: calling LLM for holistic assessment …")
    raw_response = ask(system_prompt, user_prompt)

    # ── Step 9 — Parse LLM response ───────────────────────────────────────────
    log.info("Correlator: parsing LLM response …")
    llm_result = _parse_llm_response(raw_response)

    # ── Step 10 — Assemble final result ───────────────────────────────────────
    result = {
        "agent":              "correlator",
        "verdict":            llm_result["verdict"],
        "unified_risk":       unified_risk,
        "confidence":         llm_result["confidence"],
        "reasoning":          llm_result["reasoning"],
        "correlations":       correlations,
        "recommendations":    llm_result["recommendations"],
        "agent_summary":      agent_summary,
        "indicators":         all_indicators,
        "unified_indicators": unified_indicators,
    }

    log.info(
        "Correlator: done — verdict=%s  unified_risk=%.3f  correlations=%d",
        result["verdict"], result["unified_risk"], len(correlations),
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python cyber_mas/agents/correlator.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json as _json

    # Simulate outputs from the three agents (no real LLM/Nmap calls needed
    # for the correlation logic itself — only the final LLM call is real)
    MOCK_EMAIL = {
        "agent":      "email",
        "verdict":    "phishing",
        "risk_score": 0.92,
        "confidence": 0.88,
        "reasoning":  "Domain spoofing, urgency language, suspicious redirect URL.",
        "indicators": ["domain_spoofing", "urgency_language", "suspicious_url"],
        "rag_match":  {"label": "spam", "similarity": 0.91, "excerpt": "Claim your prize..."},
        "email_metadata": {
            "subject":  "URGENT: Account suspended",
            "sender":   "alert@paypa1-verify.com",
            "reply_to": "noreply@203.0.113.42",
            "has_links": True,
            "link_count": 3,
            "has_attachments": False,
        },
    }

    MOCK_LOG = {
        "agent":          "log",
        "verdict":        "malicious",
        "risk_score":     0.88,
        "confidence":     0.90,
        "reasoning":      "7 failed SSH logins from 203.0.113.42 followed by root session.",
        "indicators":     ["ssh_brute_force", "root_compromise"],
        "signatures_hit": ["brute_force", "privilege_escalation"],
        "stats": {
            "total_lines":    10,
            "unique_ips":     1,
            "time_span_secs": 21.0,
            "top_sources":    ["203.0.113.42"],
            "error_rate":     0.7,
        },
    }

    MOCK_IP = {
        "agent":      "ip",
        "verdict":    "vulnerable",
        "risk_score": 0.79,
        "confidence": 0.75,
        "reasoning":  "OpenSSH 7.2 with 3 critical CVEs. SMB port 445 open.",
        "indicators": ["outdated_openssh", "smb_exposed"],
        "target":     "203.0.113.42",
        "open_ports": [
            {"port": 22,  "protocol": "tcp", "service": "ssh",     "version": "OpenSSH 7.2"},
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": ""},
            {"port": 80,  "protocol": "tcp", "service": "http",    "version": "Apache 2.4.7"},
        ],
        "cves": [
            {"cve_id": "CVE-2016-6515", "cvss_score": 7.8, "severity": "HIGH",
             "description": "OpenSSH DoS via crafted packets.", "affected_service": "ssh",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6515"},
        ],
        "os_guess":     "Linux 4.x (accuracy 85%)",
        "scan_duration": 18.4,
    }

    print("\n" + "═" * 60)
    print("  Correlator — smoke-test (3 mock agent results)")
    print("═" * 60 + "\n")

    try:
        result = correlate([MOCK_EMAIL, MOCK_LOG, MOCK_IP])
        print(_json.dumps(result, indent=2))
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print("  Make sure GROQ_API_KEY is set and the venv is active.")