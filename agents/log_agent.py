"""
agents/log_agent.py
══════════════════════════════════════════════════════════════════════════════
Log Anomaly Detection Agent.

PIPELINE
────────
  raw log text (str) or list of log lines
      │
      ▼
  _parse_logs()          — normalise lines into a pandas DataFrame
      │
      ▼
  _run_signatures()      — regex-based threat signature matching
      │
      ▼
  _compute_stats()       — frequency / velocity / entropy stats
      │
      ▼
  llm_client.ask()       — LLaMA 3.3-70B with CoT log-analysis prompt
      │
      ▼
  _parse_llm_response()  — extract strict JSON, validate fields
      │
      ▼
  result dict            — verdict, risk_score, confidence, indicators …

SIGNATURES DETECTED
───────────────────
  • brute_force          — repeated failed auth from same source
  • port_scan            — many distinct ports hit by one IP in short window
  • privilege_escalation — sudo/su failures or unusual root activity
  • lateral_movement     — internal IPs accessing many distinct hosts
  • data_exfiltration    — large outbound transfers or unusual destinations
  • web_attack           — SQLi / XSS / path traversal patterns in HTTP logs
  • malware_c2           — beaconing (periodic connections to same external IP)

OUTPUT SCHEMA
─────────────
  {
      "agent"           : "log",
      "verdict"         : "malicious" | "suspicious" | "benign" | "uncertain",
      "risk_score"      : float,    # 0.0 – 1.0
      "confidence"      : float,    # 0.0 – 1.0
      "reasoning"       : str,
      "indicators"      : list[str],
      "signatures_hit"  : list[str],   # which signatures fired
      "stats"           : {
          "total_lines"     : int,
          "unique_ips"      : int,
          "time_span_secs"  : float,
          "top_sources"     : list[str],
          "error_rate"      : float
      }
  }

USAGE
─────
  from agents.log_agent import analyse

  with open("auth.log") as f:
      result = analyse(f.read())

  print(result["verdict"], result["signatures_hit"])
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

import pandas as pd

import sys
import os
# Ensure project root is in sys.path so 'python agents/log_agent.py' works
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from tools.llm_client import ask
from tools.prompts import log_system_prompt, log_user_prompt

log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Timestamp parsers
# ══════════════════════════════════════════════════════════════════════════════

# Each entry: (regex, strptime_format | None, parser_fn | None)
# We try them in order; first match wins.
_TS_PATTERNS: list[tuple[re.Pattern, str | None]] = [
    # ISO 8601 / syslog-ng:  2024-03-15 02:13:44
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    # Classic syslog:  Mar 15 02:13:44
    (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # Apache / nginx:  15/Mar/2024:02:13:44
    (re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
    # Epoch seconds:   1710468824
    (re.compile(r"\b(1[5-9]\d{8})\b"), None),   # None → special handling
]

_IP_RE    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_PORT_RE  = re.compile(r"(?:port|dport|sport)\s+(\d+)", re.IGNORECASE)
_STATUS_RE = re.compile(r"\b([2345]\d{2})\b")   # HTTP status codes


def _parse_timestamp(line: str) -> datetime | None:
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        ts_str = m.group(1)
        if fmt is None:
            # epoch
            try:
                return datetime.fromtimestamp(int(ts_str))
            except Exception:
                continue
        # replace T separator for ISO format
        ts_str = ts_str.replace("T", " ")
        try:
            dt = datetime.strptime(ts_str, fmt.replace("T", " "))
            # syslog has no year — use current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Log parsing → DataFrame
# ══════════════════════════════════════════════════════════════════════════════

def _parse_logs(raw: str | list) -> pd.DataFrame:
    """
    Convert raw log input to a normalised DataFrame.

    Columns: timestamp (datetime|None), source_ip, line (str), level (str)
    """
    if isinstance(raw, list):
        lines = [str(l) for l in raw]
    else:
        lines = str(raw).splitlines()

    # drop empty lines
    lines = [l.rstrip() for l in lines if l.strip()]

    if not lines:
        return pd.DataFrame(columns=["timestamp", "source_ip", "line", "level"])

    rows = []
    for line in lines:
        ts      = _parse_timestamp(line)
        ips     = _IP_RE.findall(line)
        src_ip  = ips[0] if ips else None

        # log level detection
        level = "INFO"
        upper = line.upper()
        for lvl in ("CRITICAL", "ERROR", "WARN", "WARNING", "DEBUG", "NOTICE"):
            if lvl in upper:
                level = lvl.replace("WARNING", "WARN")
                break

        rows.append({
            "timestamp": ts,
            "source_ip": src_ip,
            "line":      line,
            "level":     level,
        })

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", na_position="last", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Signature definitions
# ══════════════════════════════════════════════════════════════════════════════

# Each signature is a dict:
#   name      : str
#   pattern   : re.Pattern  — applied to each line
#   threshold : int         — how many hits needed to fire

_SIGNATURES = [
    {
        "name": "brute_force",
        "pattern": re.compile(
            r"(failed\s+pass(word)?|authentication\s+fail(ure)?|"
            r"invalid\s+(user|password)|login\s+fail(ed)?|"
            r"access\s+denied|permission\s+denied)",
            re.IGNORECASE,
        ),
        "threshold": 5,       # ≥5 failures total
        "per_ip_threshold": 3,  # or ≥3 from same IP
    },
    {
        "name": "port_scan",
        "pattern": re.compile(
            r"(SYN|connection\s+attempt|refused|reset|RST|"
            r"connect\s+to|destination\s+unreachable)",
            re.IGNORECASE,
        ),
        "threshold": 10,
        "per_ip_threshold": 8,
    },
    {
        "name": "privilege_escalation",
        "pattern": re.compile(
            r"(sudo|su\s|runAs|privilege|setuid|chmod\s+[0-7]*[67][0-7][0-7]|"
            r"sudoers|passwd\s+changed|wheel\s+group)",
            re.IGNORECASE,
        ),
        "threshold": 3,
        "per_ip_threshold": 2,
    },
    {
        "name": "lateral_movement",
        "pattern": re.compile(
            r"(ssh.*from|smb|rdp|psexec|wmi.*exec|winrm|"
            r"net\s+use|net\s+view|\\\\[a-zA-Z0-9])",
            re.IGNORECASE,
        ),
        "threshold": 4,
        "per_ip_threshold": 3,
    },
    {
        "name": "data_exfiltration",
        "pattern": re.compile(
            r"(bytes\s+sent\s*[=:]\s*[1-9]\d{6,}|"   # >1 MB sent
            r"upload|exfil|transfer.*\d{7,}|"
            r"ftp\s+(put|stor)|scp\s+-r|rsync\s+-a)",
            re.IGNORECASE,
        ),
        "threshold": 2,
        "per_ip_threshold": 1,
    },
    {
        "name": "web_attack",
        "pattern": re.compile(
            r"(union\s+select|1=1|or\s+'1'='1|"         # SQLi
            r"<script|javascript:|onerror=|onload=|"    # XSS
            r"\.\./\.\.|%2e%2e|path\s+traversal|"       # path traversal
            r"cmd=|exec\(|eval\(|base64_decode)",        # RCE
            re.IGNORECASE,
        ),
        "threshold": 1,
        "per_ip_threshold": 1,
    },
    {
        "name": "malware_c2",
        "pattern": re.compile(
            r"(beacon|heartbeat|checkin|check-in|"
            r"CONNECT\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"User-Agent:\s*(curl|python-requests|go-http|libwww))",
            re.IGNORECASE,
        ),
        "threshold": 3,
        "per_ip_threshold": 2,
    },
]


def _run_signatures(df: pd.DataFrame) -> list[str]:
    """
    Apply all signatures to the DataFrame.

    Returns a list of signature names that fired.
    """
    hits: list[str] = []

    for sig in _SIGNATURES:
        pattern   = sig["pattern"]
        threshold = sig["threshold"]
        per_ip    = sig["per_ip_threshold"]

        matching  = df[df["line"].str.contains(pattern, regex=True, na=False)]
        total     = len(matching)

        if total >= threshold:
            hits.append(sig["name"])
            continue

        # check per-IP threshold even if total is below global threshold
        if "source_ip" in matching.columns and not matching.empty:
            ip_counts = matching["source_ip"].dropna().value_counts()
            if not ip_counts.empty and ip_counts.iloc[0] >= per_ip:
                hits.append(sig["name"])

    return list(dict.fromkeys(hits))   # deduplicate, preserve order


# ══════════════════════════════════════════════════════════════════════════════
# Statistics
# ══════════════════════════════════════════════════════════════════════════════

def _compute_stats(df: pd.DataFrame) -> dict:
    """Compute summary statistics passed to the LLM as structured context."""
    total = len(df)
    unique_ips = df["source_ip"].nunique()

    # time span
    ts_valid = df["timestamp"].dropna()
    if len(ts_valid) >= 2:
        span = (ts_valid.max() - ts_valid.min()).total_seconds()
    else:
        span = 0.0

    # top source IPs
    top_ips = (
        df["source_ip"]
        .dropna()
        .value_counts()
        .head(5)
        .index.tolist()
    )

    # error / warning rate
    error_lines = df["level"].isin(["ERROR", "CRITICAL", "WARN"]).sum()
    error_rate  = round(error_lines / total, 3) if total else 0.0

    return {
        "total_lines":    total,
        "unique_ips":     int(unique_ips),
        "time_span_secs": round(span, 1),
        "top_sources":    top_ips,
        "error_rate":     error_rate,
    }


def _format_sample_lines(df: pd.DataFrame, n: int = 30) -> str:
    """
    Return up to *n* representative lines for the LLM prompt.
    Prioritises lines that contain errors, warnings, or signature keywords.
    """
    error_mask = df["level"].isin(["ERROR", "CRITICAL", "WARN"])
    error_lines = df[error_mask]["line"].tolist()
    other_lines = df[~error_mask]["line"].tolist()

    # interleave: take up to n//2 errors, fill rest from others
    half = n // 2
    selected = error_lines[:half] + other_lines[:n - min(len(error_lines), half)]
    return "\n".join(selected[:n])


# ══════════════════════════════════════════════════════════════════════════════
# LLM response parsing
# ══════════════════════════════════════════════════════════════════════════════

_VALID_VERDICTS = {"malicious", "suspicious", "benign", "uncertain"}
_JSON_BLOCK_RE  = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


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
            "verdict":    "uncertain",
            "risk_score": 0.5,
            "confidence": 0.1,
            "reasoning":  "LLM returned unparseable output.",
            "indicators": [],
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
        "verdict":    verdict,
        "risk_score": _clamp(parsed.get("risk_score"), 0.5),
        "confidence": _clamp(parsed.get("confidence"), 0.5),
        "reasoning":  str(parsed.get("reasoning", "")),
        "indicators": list(parsed.get("indicators", [])),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def analyse(payload: str | list) -> dict:
    """
    Analyse log lines for anomalies and threat patterns.

    Parameters
    ----------
    payload : str  — multi-line log text
              list — list of log line strings

    Returns
    -------
    dict conforming to the OUTPUT SCHEMA above.
    """
    # ── Step 1 — Parse logs into DataFrame ────────────────────────────────────
    log.info("Log agent: parsing logs …")
    df = _parse_logs(payload)

    if df.empty:
        log.warning("Log agent: no log lines found in payload.")
        return {
            "agent":          "log",
            "verdict":        "uncertain",
            "risk_score":     0.0,
            "confidence":     0.0,
            "reasoning":      "No log lines could be parsed from the payload.",
            "indicators":     [],
            "signatures_hit": [],
            "stats":          _compute_stats(df),
        }

    # ── Step 2 — Signature matching ───────────────────────────────────────────
    log.info("Log agent: running %d signatures …", len(_SIGNATURES))
    signatures_hit = _run_signatures(df)
    log.info("Log agent: signatures fired → %s", signatures_hit or "none")

    # ── Step 3 — Statistics ───────────────────────────────────────────────────
    stats        = _compute_stats(df)
    sample_lines = _format_sample_lines(df, n=30)

    # ── Step 4 — Build prompts ────────────────────────────────────────────────
    system_prompt = log_system_prompt()
    user_prompt   = log_user_prompt(
        log_sample      = sample_lines,
        total_lines     = stats["total_lines"],
        unique_ips      = stats["unique_ips"],
        time_span_secs  = stats["time_span_secs"],
        top_sources     = stats["top_sources"],
        error_rate      = stats["error_rate"],
        signatures_hit  = signatures_hit,
    )

    # ── Step 5 — LLM call ─────────────────────────────────────────────────────
    log.info("Log agent: calling LLM …")
    raw_response = ask(system_prompt, user_prompt)

    # ── Step 6 — Parse + validate ─────────────────────────────────────────────
    log.info("Log agent: parsing LLM response …")
    llm_result = _parse_llm_response(raw_response)

    # ── Step 7 — Assemble result ──────────────────────────────────────────────
    result = {
        "agent":          "log",
        **llm_result,
        "signatures_hit": signatures_hit,
        "stats":          stats,
    }

    log.info(
        "Log agent: done — verdict=%s  risk=%.2f  sigs=%s",
        result["verdict"], result["risk_score"], signatures_hit,
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python agents/log_agent.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json as _json

    # Simulated SSH brute-force attack log
    BRUTE_FORCE_SAMPLE = """\
2024-03-15 02:13:40 WARN sshd: Failed password for root from 203.0.113.42 port 51234 ssh2
2024-03-15 02:13:41 WARN sshd: Failed password for root from 203.0.113.42 port 51235 ssh2
2024-03-15 02:13:42 WARN sshd: Failed password for admin from 203.0.113.42 port 51236 ssh2
2024-03-15 02:13:43 WARN sshd: Failed password for ubuntu from 203.0.113.42 port 51237 ssh2
2024-03-15 02:13:44 WARN sshd: Failed password for user from 203.0.113.42 port 51238 ssh2
2024-03-15 02:13:45 WARN sshd: Failed password for root from 203.0.113.42 port 51239 ssh2
2024-03-15 02:13:46 WARN sshd: Failed password for pi from 203.0.113.42 port 51240 ssh2
2024-03-15 02:13:47 INFO sshd: Accepted password for root from 203.0.113.42 port 51241 ssh2
2024-03-15 02:13:48 INFO sshd: pam_unix(sshd:session): session opened for user root
2024-03-15 02:14:01 INFO sudo: root: TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
"""

    print("\n" + "═" * 60)
    print("  Log Agent — smoke-test (brute-force scenario)")
    print("═" * 60 + "\n")

    try:
        result = analyse(BRUTE_FORCE_SAMPLE)
        print(_json.dumps(result, indent=2))
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print("  Make sure GROQ_API_KEY is set and the venv is active.")