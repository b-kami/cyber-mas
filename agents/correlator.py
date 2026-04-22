"""
cyber_mas/agents/correlator.py  (v2 — with Qdrant memory)
══════════════════════════════════════════════════════════════════════════════
Cross-Agent Threat Correlator — now with persistent threat memory.

CHANGES FROM v1
───────────────
  + Step 3b: Query Qdrant for historically similar threats BEFORE calling LLM
  + Historical context injected into the LLM prompt
  + store_report() called at the end to persist results for future analyses
  + "memory_matches" field added to output schema

CORRELATION RULES (unchanged)
─────────────────
  C1  shared_ip           — same IP in log sources and ip agent target
  C2  phishing_and_breach — email=phishing AND log=malicious
  C3  vuln_and_exploit    — ip has CVEs AND log shows exploitation patterns
  C4  multi_vector        — all active agents return risk_score > 0.6
  C5  c2_beacon_and_ip    — log hits malware_c2 AND ip agent ran
  C6  recon_pattern       — port_scan in log AND ip agent found many ports

OUTPUT SCHEMA
─────────────
  {
      "agent"            : "correlator",
      "verdict"          : "critical"|"high"|"medium"|"low"|"uncertain",
      "unified_risk"     : float,
      "confidence"       : float,
      "reasoning"        : str,
      "correlations"     : list[str],
      "recommendations"  : list[str],
      "agent_summary"    : { email/log/ip: {verdict, risk_score} | null },
      "indicators"       : list[str],
      "unified_indicators": list[str],
      "memory_matches"   : list[{          ← NEW
          similarity, agent_type, verdict,
          risk_score, timestamp, indicators,
          signatures, target, subject
      }]
  }
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

import sys
import os

# Ensure project root is in sys.path so 'python agents/correlator.py' works
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from tools.llm_client import ask
from tools.prompts import correlator_system_prompt, correlator_user_prompt

log = logging.getLogger(__name__)

# ── Verdict thresholds ────────────────────────────────────────────────────────
_RISK_THRESHOLDS = {
    "critical": 0.85,
    "high":     0.65,
    "medium":   0.40,
    "low":      0.0,
}

_VALID_VERDICTS   = {"critical", "high", "medium", "low", "uncertain"}
_AGENT_WEIGHTS    = {"email": 0.30, "log": 0.40, "ip": 0.30}
_CORRELATION_BOOST = 0.08
# Memory boost: each strong historical match (sim > 0.80) with same verdict type
# nudges the score slightly — keeps it honest, not overriding
_MEMORY_BOOST_PER_MATCH = 0.04
_MEMORY_MAX_BOOST       = 0.10

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


# ══════════════════════════════════════════════════════════════════════════════
# Result normalisation (unchanged from v1)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_agent_result(results: list[dict], agent_type: str) -> dict | None:
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
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ips: set[str] = set()
    for r in results:
        if r.get("agent") == "ip" and r.get("target"):
            ips.update(ip_re.findall(str(r["target"])))
        for src in r.get("stats", {}).get("top_sources", []):
            ips.update(ip_re.findall(str(src)))
        meta = r.get("email_metadata", {})
        for field in ("sender", "reply_to"):
            ips.update(ip_re.findall(str(meta.get(field, ""))))
        for ind in r.get("indicators", []):
            ips.update(ip_re.findall(str(ind)))
    return ips


# ══════════════════════════════════════════════════════════════════════════════
# Correlation rules (unchanged from v1)
# ══════════════════════════════════════════════════════════════════════════════

def _run_correlations(
    email_r: dict | None,
    log_r:   dict | None,
    ip_r:    dict | None,
    all_ips: set[str],
) -> tuple[list[str], list[str]]:
    fired: list[str] = []
    unified_indicators: list[str] = []

    # C1 — shared IP
    if log_r and ip_r:
        log_ips = set(re.findall(
            r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
            " ".join(str(s) for s in log_r.get("stats", {}).get("top_sources", []))
        ))
        ip_target_ips = set(re.findall(
            r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
            str(ip_r.get("target", ""))
        ))
        shared = log_ips & ip_target_ips
        if shared:
            fired.append("C1_shared_ip")
            unified_indicators.append(
                f"Same IP(s) {shared} appear in both log anomalies and network scan."
            )

    # C2 — phishing + breach
    if (email_r and log_r
            and _safe_verdict(email_r) == "phishing"
            and _safe_verdict(log_r)   == "malicious"):
        fired.append("C2_phishing_and_breach")
        unified_indicators.append(
            "Phishing email detected alongside malicious log activity — "
            "likely coordinated intrusion attempt."
        )

    # C3 — CVEs + exploitation
    if ip_r and log_r:
        has_cves    = len(ip_r.get("cves", [])) > 0
        exploit_sigs = {"brute_force", "web_attack", "lateral_movement", "malware_c2"}
        overlap     = exploit_sigs & set(log_r.get("signatures_hit", []))
        if has_cves and overlap:
            fired.append("C3_vuln_and_exploit")
            unified_indicators.append(
                f"Host has known CVEs AND log shows exploitation patterns: {list(overlap)}."
            )

    # C4 — all agents high risk
    active    = [r for r in [email_r, log_r, ip_r] if r is not None]
    high_risk = [r for r in active if _safe_risk(r) > 0.6]
    if len(active) >= 2 and len(high_risk) == len(active):
        fired.append("C4_multi_vector_high_risk")
        unified_indicators.append(
            f"All {len(active)} active agents report risk > 0.6 — "
            "multi-vector attack is highly probable."
        )

    # C5 — C2 beaconing + network scan
    if log_r and ip_r:
        if "malware_c2" in log_r.get("signatures_hit", []):
            fired.append("C5_c2_beacon_and_network_scan")
            unified_indicators.append(
                "C2 beaconing detected in logs; network scan available for pivot analysis."
            )

    # C6 — recon pattern
    if log_r and ip_r:
        if "port_scan" in log_r.get("signatures_hit", []) and len(ip_r.get("open_ports", [])) >= 5:
            fired.append("C6_recon_pattern")
            unified_indicators.append(
                f"Port-scan signature in logs + {len(ip_r.get('open_ports',[]))} "
                "open ports — active reconnaissance confirmed."
            )

    return fired, unified_indicators


# ══════════════════════════════════════════════════════════════════════════════
# Qdrant memory query  ← NEW
# ══════════════════════════════════════════════════════════════════════════════

def _query_historical_memory(
    email_r: dict | None,
    log_r:   dict | None,
    ip_r:    dict | None,
) -> tuple[list[Any], str]:
    """
    Query Qdrant for historically similar threats.

    Returns
    -------
    (memory_matches, memory_context_string)
    memory_context_string is injected into the LLM prompt.
    memory_matches is stored in the result for transparency.
    """
    try:
        from tools.qdrant_store import query_memory, MemoryMatch
    except ImportError:
        log.warning("Qdrant not installed — skipping memory query. pip install qdrant-client")
        return [], "Threat memory unavailable (qdrant-client not installed)."

    # Build a combined query text from all active agent contexts
    query_parts = []

    if log_r:
        sigs = log_r.get("signatures_hit", [])
        srcs = log_r.get("stats", {}).get("top_sources", [])
        if sigs:  query_parts.append(f"log signatures: {', '.join(sigs)}")
        if srcs:  query_parts.append(f"source IPs: {', '.join(str(s) for s in srcs)}")
        query_parts.append(f"log verdict: {_safe_verdict(log_r)}")

    if email_r:
        meta = email_r.get("email_metadata", {})
        if meta.get("subject"): query_parts.append(f"email subject: {meta['subject']}")
        if meta.get("sender"):  query_parts.append(f"sender: {meta['sender']}")
        query_parts.append(f"email verdict: {_safe_verdict(email_r)}")

    if ip_r:
        if ip_r.get("target"):  query_parts.append(f"target: {ip_r['target']}")
        cves = [c["cve_id"] for c in ip_r.get("cves", [])[:3]]
        if cves: query_parts.append(f"CVEs: {', '.join(cves)}")
        query_parts.append(f"ip verdict: {_safe_verdict(ip_r)}")

    if not query_parts:
        return [], "No query context available for memory lookup."

    query_text = ". ".join(query_parts)
    log.info("Qdrant: querying memory with: %s", query_text[:120])

    matches = query_memory(free_text=query_text, k=3)

    if not matches:
        log.info("Qdrant: no historical matches above threshold")
        return [], "No similar threats found in historical memory."

    # Build context string for LLM
    context_lines = [
        f"[THREAT MEMORY — {len(matches)} historical match(es) found]",
        "The following similar threats were previously detected:",
        "",
    ]
    for i, m in enumerate(matches, 1):
        context_lines.append(f"  Match {i} (similarity {m.similarity:.2f}):")
        context_lines.append("  " + m.to_context_string().replace("\n", "\n  "))
        context_lines.append("")

    context_lines.append(
        "Consider these historical matches when assessing severity and recommending response actions."
    )

    return matches, "\n".join(context_lines)


# ══════════════════════════════════════════════════════════════════════════════
# Unified risk score (updated — memory boost added)
# ══════════════════════════════════════════════════════════════════════════════

def _compute_unified_risk(
    email_r:        dict | None,
    log_r:          dict | None,
    ip_r:           dict | None,
    correlations:   list[str],
    memory_matches: list[Any],
) -> float:
    total_weight = 0.0
    weighted_sum = 0.0

    for agent_type, weight in _AGENT_WEIGHTS.items():
        result = {"email": email_r, "log": log_r, "ip": ip_r}[agent_type]
        if result is not None:
            weighted_sum += _safe_risk(result) * weight
            total_weight += weight

    base  = (weighted_sum / total_weight) if total_weight > 0 else 0.0
    boost = len(correlations) * _CORRELATION_BOOST

    # Memory boost — strong historical matches with high-risk verdicts
    # add a small confidence nudge (capped)
    memory_boost = 0.0
    high_risk_verdicts = {"malicious", "phishing", "vulnerable", "critical", "high"}
    for m in memory_matches:
        if m.similarity >= 0.75 and m.verdict.lower() in high_risk_verdicts:
            memory_boost += _MEMORY_BOOST_PER_MATCH
    memory_boost = min(memory_boost, _MEMORY_MAX_BOOST)

    total = min(round(base + boost + memory_boost, 3), 1.0)
    log.info(
        "Unified risk: base=%.3f + correlations=%.3f + memory=%.3f = %.3f",
        base, boost, memory_boost, total,
    )
    return total


def _risk_to_verdict(risk: float) -> str:
    for verdict, threshold in _RISK_THRESHOLDS.items():
        if risk >= threshold:
            return verdict
    return "low"


# ══════════════════════════════════════════════════════════════════════════════
# LLM response parsing (unchanged from v1)
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

def correlate(agent_results: list[dict], report_id: str | None = None) -> dict:
    """
    Correlate results from specialist agents into a unified threat assessment.

    Parameters
    ----------
    agent_results : list of result dicts from email_agent, log_agent, ip_agent
    report_id     : unique ID for this run (auto-generated if not supplied)

    Returns
    -------
    dict conforming to the OUTPUT SCHEMA above.
    """
    if not agent_results:
        raise ValueError("correlate() requires at least one agent result dict.")

    if not report_id:
        report_id = str(uuid.uuid4())[:8]

    # ── Step 1 — Extract per-agent results ───────────────────────────────────
    email_r = _extract_agent_result(agent_results, "email")
    log_r   = _extract_agent_result(agent_results, "log")
    ip_r    = _extract_agent_result(agent_results, "ip")

    active = [a for a in [email_r, log_r, ip_r] if a is not None]
    log.info(
        "Correlator: processing %d agent(s): %s",
        len(active), [r.get("agent") for r in active],
    )

    # ── Step 2 — Collect shared IPs ───────────────────────────────────────────
    all_ips = _collect_ips(agent_results)

    # ── Step 3a — Run correlation rules ──────────────────────────────────────
    log.info("Correlator: running correlation rules …")
    correlations, unified_indicators = _run_correlations(email_r, log_r, ip_r, all_ips)
    log.info("Correlator: rules fired → %s", correlations or "none")

    # ── Step 3b — Query Qdrant memory ← NEW ──────────────────────────────────
    log.info("Correlator: querying historical threat memory …")
    memory_matches, memory_context = _query_historical_memory(email_r, log_r, ip_r)
    if memory_matches:
        log.info(
            "Correlator: %d historical match(es) — top similarity=%.3f",
            len(memory_matches), memory_matches[0].similarity,
        )

    # ── Step 4 — Unified risk score ───────────────────────────────────────────
    unified_risk    = _compute_unified_risk(email_r, log_r, ip_r, correlations, memory_matches)
    pre_llm_verdict = _risk_to_verdict(unified_risk)
    log.info("Correlator: unified_risk=%.3f  pre-LLM verdict=%s", unified_risk, pre_llm_verdict)

    # ── Step 5 — Merge indicators ─────────────────────────────────────────────
    all_indicators = _collect_indicators(agent_results)

    # ── Step 6 — Agent summary ────────────────────────────────────────────────
    agent_summary = {
        "email": ({"verdict": _safe_verdict(email_r), "risk_score": _safe_risk(email_r)} if email_r else None),
        "log":   ({"verdict": _safe_verdict(log_r),   "risk_score": _safe_risk(log_r)}   if log_r   else None),
        "ip":    ({"verdict": _safe_verdict(ip_r),    "risk_score": _safe_risk(ip_r)}    if ip_r    else None),
    }

    # ── Step 7 — Build prompts (memory_context injected) ─────────────────────
    system_prompt = correlator_system_prompt()
    user_prompt   = correlator_user_prompt(
        agent_summary       = agent_summary,
        correlations        = correlations,
        unified_risk        = unified_risk,
        unified_indicators  = unified_indicators,
        all_indicators      = all_indicators,
        email_reasoning     = email_r.get("reasoning", "") if email_r else "",
        log_reasoning       = log_r.get("reasoning",  "") if log_r   else "",
        ip_reasoning        = ip_r.get("reasoning",   "") if ip_r    else "",
        memory_context      = memory_context,        # ← injected into prompt
    )

    # ── Step 8 — LLM call ─────────────────────────────────────────────────────
    log.info("Correlator: calling LLM …")
    raw_response = ask(system_prompt, user_prompt)

    # ── Step 9 — Parse LLM response ───────────────────────────────────────────
    llm_result = _parse_llm_response(raw_response)

    # ── Step 10 — Store in Qdrant ← NEW ──────────────────────────────────────
    # Build a correlator-level result to store
    correlator_result_for_memory = {
        "agent":          "correlator",
        "verdict":        llm_result["verdict"],
        "unified_risk":   unified_risk,
        "confidence":     llm_result["confidence"],
        "reasoning":      llm_result["reasoning"],
        "correlations":   correlations,
        "recommendations":llm_result["recommendations"],
        "indicators":     all_indicators,
        "unified_indicators": unified_indicators,
    }

    try:
        from tools.qdrant_store import store_report
        store_report(report_id, agent_results, correlator_result_for_memory)
        log.info("Correlator: analysis persisted to Qdrant (report_id=%s)", report_id)
    except Exception as exc:
        log.warning("Correlator: Qdrant store failed (non-fatal): %s", exc)

    # ── Step 11 — Assemble final result ───────────────────────────────────────
    result = {
        "agent":              "correlator",
        "report_id":          report_id,
        "verdict":            llm_result["verdict"],
        "unified_risk":       unified_risk,
        "confidence":         llm_result["confidence"],
        "reasoning":          llm_result["reasoning"],
        "correlations":       correlations,
        "recommendations":    llm_result["recommendations"],
        "agent_summary":      agent_summary,
        "indicators":         all_indicators,
        "unified_indicators": unified_indicators,
        "memory_matches": [   # serialisable version of MemoryMatch objects
            {
                "similarity":  m.similarity,
                "agent_type":  m.agent_type,
                "verdict":     m.verdict,
                "risk_score":  m.risk_score,
                "timestamp":   m.timestamp,
                "indicators":  m.indicators,
                "signatures":  m.signatures,
                "target":      m.target,
                "subject":     m.subject,
            }
            for m in memory_matches
        ],
    }

    log.info(
        "Correlator: done — verdict=%s  unified_risk=%.3f  correlations=%d  memory_matches=%d",
        result["verdict"], result["unified_risk"],
        len(correlations), len(memory_matches),
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python cyber_mas/agents/correlator.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json as _json

    MOCK_EMAIL = {
        "agent": "email", "verdict": "phishing", "risk_score": 0.92,
        "confidence": 0.88, "reasoning": "Domain spoofing, urgency, redirect URL.",
        "indicators": ["domain_spoofing", "urgency_language", "suspicious_url"],
        "rag_match": {"label": "spam", "similarity": 0.91, "excerpt": "..."},
        "email_metadata": {
            "subject": "URGENT: Account suspended", "sender": "alert@paypa1-verify.com",
            "reply_to": "noreply@203.0.113.42", "has_links": True,
            "link_count": 3, "has_attachments": False,
        },
    }
    MOCK_LOG = {
        "agent": "log", "verdict": "malicious", "risk_score": 0.88,
        "confidence": 0.90, "reasoning": "7 failed SSH logins followed by root session.",
        "indicators": ["ssh_brute_force", "root_compromise"],
        "signatures_hit": ["brute_force", "privilege_escalation"],
        "stats": {"total_lines":10,"unique_ips":1,"time_span_secs":21.0,
                  "top_sources":["203.0.113.42"],"error_rate":0.7},
    }
    MOCK_IP = {
        "agent": "ip", "verdict": "vulnerable", "risk_score": 0.79,
        "confidence": 0.75, "reasoning": "OpenSSH 7.2 with critical CVEs.",
        "indicators": ["outdated_openssh", "smb_exposed"],
        "target": "203.0.113.42",
        "open_ports": [{"port":22,"protocol":"tcp","service":"ssh","version":"OpenSSH 7.2"},
                       {"port":445,"protocol":"tcp","service":"microsoft-ds","version":""}],
        "cves": [{"cve_id":"CVE-2016-6515","cvss_score":7.8,"severity":"HIGH",
                  "description":"OpenSSH DoS","affected_service":"ssh","url":""}],
        "os_guess": "Linux 4.x", "scan_duration": 18.4,
    }

    print("\n" + "="*60)
    print("  Correlator v2 -- smoke-test (with Qdrant memory)")
    print("="*60 + "\n")

    try:
        result = correlate([MOCK_EMAIL, MOCK_LOG, MOCK_IP], report_id="smoke-corr-001")
        # Trim for readable output
        result_display = {k: v for k, v in result.items() if k != "reasoning"}
        result_display["reasoning"] = result.get("reasoning", "")[:200] + "..."
        print(_json.dumps(result_display, indent=2))
        print(f"\n  Memory matches: {len(result.get('memory_matches', []))}")
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print("  Make sure GROQ_API_KEY is set.")