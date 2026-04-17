"""
agents/dispatcher.py
══════════════════════════════════════════════════════════════════════════════
Task Dispatcher Agent — the entry-point for every analysis request.

ROLE
────
  The Dispatcher receives a raw input dict, determines WHAT TYPE of threat
  data it contains, and routes it to the correct specialist agent.
  It never calls the LLM itself — it is pure routing logic.

INPUT SCHEMA
────────────
  {
      "type"    : "email" | "log" | "ip",   # optional — auto-detected if absent
      "payload" : <str | dict | list>        # the actual data to analyse
  }

  If "type" is omitted, the Dispatcher infers it from the payload shape/content.

OUTPUT SCHEMA (passed through from the specialist agent)
────────────
  {
      "agent"      : str,    # which agent handled this
      "verdict"    : str,    # e.g. "phishing", "anomaly", "vulnerable"
      "risk_score" : float,  # 0.0 – 1.0
      "confidence" : float,  # 0.0 – 1.0
      "reasoning"  : str,
      "indicators" : list[str],
      ... (agent-specific extra fields)
  }

USAGE
─────
  from agents.dispatcher import dispatch

  result = dispatch({"type": "email", "payload": raw_email_text})
  result = dispatch({"payload": raw_email_text})          # auto-detect
  result = dispatch({"payload": "192.168.1.1"})           # auto-detect → ip
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# ── Detection heuristics ──────────────────────────────────────────────────────

# Patterns that suggest a raw email (RFC-2822 headers)
_EMAIL_HEADER_RE = re.compile(
    r"^(From |Return-Path:|Received:|MIME-Version:|Content-Type:|"
    r"Subject:|To:|Date:|Message-ID:)",
    re.MULTILINE | re.IGNORECASE,
)

# Patterns that suggest a log line (syslog / apache / CIC-IDS style)
_LOG_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}"   # ISO timestamp
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"        # syslog timestamp
    r"|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?(GET|POST|PUT|DELETE)"  # HTTP log
    r"|\[(?:ERROR|WARN|INFO|DEBUG|CRITICAL)\])",     # log level tag
    re.IGNORECASE,
)

# Valid IPv4 / IPv6 / CIDR / hostname-ish string
_IP_OR_HOST_RE = re.compile(
    r"^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}(/\d{1,2})?$"  # IPv4/CIDR
    r"|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"               # IPv6
    r"|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",  # hostname
    re.IGNORECASE,
)


def _is_valid_ip_or_host(value: str) -> bool:
    """Return True if *value* looks like an IP address, CIDR block, or hostname."""
    value = value.strip()
    # Try stdlib first (strictest check for IPs)
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    # Regex fallback for hostnames
    return bool(_IP_OR_HOST_RE.match(value))


def _detect_type(payload: Any) -> str:
    """
    Infer the payload type from its structure and content.

    Priority order:
      1. list / dict with 'host'/'ip' keys  → "ip"
      2. short string that is a valid IP/host → "ip"
      3. string with RFC-2822 email headers  → "email"
      4. string with log-line patterns       → "log"
      5. fallback                            → "email"  (LLM will handle it)
    """
    # ── Structured scan result (dict or list of dicts) ───────────────────────
    if isinstance(payload, dict):
        if any(k in payload for k in ("host", "ip", "hosts", "targets")):
            return "ip"

    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict):
            if any(k in payload[0] for k in ("host", "ip", "port", "service")):
                return "ip"
        # list of strings — could be log lines or IP addresses
        if payload and isinstance(payload[0], str):
            if _is_valid_ip_or_host(payload[0]):
                return "ip"
            if _LOG_LINE_RE.search(payload[0]):
                return "log"

    # ── Plain string ─────────────────────────────────────────────────────────
    if isinstance(payload, str):
        stripped = payload.strip()

        # single token — IP / hostname?
        if len(stripped.split()) == 1 and _is_valid_ip_or_host(stripped):
            return "ip"

        # multiple lines — check first 20 lines for log patterns
        lines = stripped.splitlines()[:20]
        log_hits = sum(1 for l in lines if _LOG_LINE_RE.search(l))
        if log_hits >= 2:
            return "log"

        # email header fingerprint
        if _EMAIL_HEADER_RE.search(stripped):
            return "email"

        # single log line
        if log_hits == 1:
            return "log"

    # ── Default ──────────────────────────────────────────────────────────────
    log.warning("Could not detect payload type — defaulting to 'email'.")
    return "email"


# ── Agent registry ────────────────────────────────────────────────────────────
# Imported lazily inside _route() to avoid circular imports and slow startup.

_AGENT_REGISTRY: dict[str, str] = {
    "email": "agents.email_agent",
    "log":   "agents.log_agent",
    "ip":    "agents.ip_agent",
}


def _route(task_type: str, payload: Any) -> dict:
    """Import the correct agent module and call its `analyse()` function."""
    module_path = _AGENT_REGISTRY.get(task_type)
    if module_path is None:
        raise ValueError(
            f"Unknown task type '{task_type}'. "
            f"Valid types: {list(_AGENT_REGISTRY)}"
        )

    # lazy import — only load the agent we actually need
    import importlib
    module = importlib.import_module(module_path)

    if not hasattr(module, "analyse"):
        raise AttributeError(
            f"Agent module '{module_path}' must expose an 'analyse(payload)' function."
        )

    log.info("Routing to %s agent …", task_type)
    return module.analyse(payload)


# ── Public API ────────────────────────────────────────────────────────────────

def dispatch(task: dict) -> dict:
    """
    Route a task to the appropriate specialist agent and return its result.

    Parameters
    ----------
    task : dict
        Must contain "payload". Optionally contains "type" to skip detection.

    Returns
    -------
    dict — the agent's full result, augmented with "agent" and "task_type" keys.

    Raises
    ------
    ValueError  — if "payload" is missing or task type is unrecognised.
    RuntimeError — if the agent itself raises an unhandled exception.
    """
    if "payload" not in task:
        raise ValueError("Task dict must contain a 'payload' key.")

    payload   = task["payload"]
    task_type = task.get("type", "").strip().lower()

    # ── Auto-detect if type not supplied ─────────────────────────────────────
    if not task_type:
        task_type = _detect_type(payload)
        log.info("Auto-detected task type: '%s'", task_type)
    else:
        log.info("Explicit task type: '%s'", task_type)

    # ── Dispatch ─────────────────────────────────────────────────────────────
    try:
        result = _route(task_type, payload)
    except Exception as exc:
        log.error("Agent '%s' raised an exception: %s", task_type, exc)
        raise RuntimeError(f"Agent '{task_type}' failed: {exc}") from exc

    # ── Stamp provenance ──────────────────────────────────────────────────────
    result.setdefault("agent",     task_type)
    result.setdefault("task_type", task_type)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python -m agents.dispatcher
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    SAMPLES = [
        # (description, task dict)
        (
            "Explicit email",
            {
                "type":    "email",
                "payload": (
                    "From: winner@lottery.biz\n"
                    "Subject: You have won $1,000,000!\n\n"
                    "Dear user, click the link below to claim your prize."
                ),
            },
        ),
        (
            "Auto-detect: IP string",
            {"payload": "192.168.1.105"},
        ),
        (
            "Auto-detect: log lines",
            {
                "payload": (
                    "2024-03-15 02:13:44 WARN Failed password for root from 10.0.0.9 port 22\n"
                    "2024-03-15 02:13:45 WARN Failed password for root from 10.0.0.9 port 22\n"
                    "2024-03-15 02:13:46 WARN Failed password for root from 10.0.0.9 port 22"
                )
            },
        ),
        (
            "Auto-detect: email (no headers)",
            {"payload": "Congratulations! You have been selected for a free iPhone."},
        ),
    ]

    print("\n" + "═" * 60)
    print("  Dispatcher — detection smoke-test (no agents loaded)")
    print("═" * 60)

    for desc, task in SAMPLES:
        payload = task["payload"]
        explicit = task.get("type", "")
        detected = explicit if explicit else _detect_type(payload)
        preview  = str(payload)[:60].replace("\n", " ")
        print(f"\n  [{desc}]")
        print(f"    payload  : {preview!r}…")
        print(f"    detected : {detected.upper()}")

    print("\n  ✓ Detection logic OK — agents not imported (no LLM calls).")
    print("    To test full dispatch, run main.py with a real payload.\n")