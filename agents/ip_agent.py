"""
cyber_mas/agents/ip_agent.py
══════════════════════════════════════════════════════════════════════════════
IP / Network Scanning & Vulnerability Assessment Agent.

PIPELINE
────────
  IP address / hostname / CIDR
      │
      ▼
  _validate_target()     — safety checks, RFC-1918 / loopback allowed
      │
      ▼
  _run_nmap()            — service + version + OS detection scan
      │
      ▼
  _parse_nmap_results()  — normalise into structured host/port dicts
      │
      ▼
  nvd_client.fetch_cves_for_hosts()  — CVE lookup per service/version
      │
      ▼
  _build_scan_summary()  — format evidence for the LLM prompt
      │
      ▼
  llm_client.ask()       — LLaMA 3.3-70B with CoT IP-analysis prompt
      │
      ▼
  _parse_llm_response()  — extract strict JSON, validate fields
      │
      ▼
  result dict            — verdict, risk_score, cves, open_ports …

NMAP SCAN PROFILE
─────────────────
  -sV   service/version detection
  -O    OS detection (requires root/sudo in Codespace)
  -T4   aggressive timing (fast)
  --open   show only open ports
  Top 1000 ports scanned (default nmap behaviour)
  Timeout: 120 s per host

OUTPUT SCHEMA
─────────────
  {
      "agent"        : "ip",
      "verdict"      : "vulnerable" | "suspicious" | "clean" | "uncertain",
      "risk_score"   : float,     # 0.0 – 1.0
      "confidence"   : float,     # 0.0 – 1.0
      "reasoning"    : str,
      "indicators"   : list[str],
      "target"       : str,
      "open_ports"   : list[{port, protocol, service, version, state}],
      "cves"         : list[{cve_id, cvss_score, severity,
                              description, affected_service, url}],
      "os_guess"     : str,
      "scan_duration": float      # seconds
  }

USAGE
─────
  from cyber_mas.agents.ip_agent import analyse

  result = analyse("192.168.1.1")
  result = analyse({"host": "10.0.0.5", "ports": "22,80,443"})
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Any

import nmap

from cyber_mas.tools.llm_client import ask
from cyber_mas.tools.nvd_client import fetch_cves_for_hosts
from cyber_mas.tools.prompts import ip_system_prompt, ip_user_prompt

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
SCAN_TIMEOUT   = 120          # seconds per host
MAX_CVES_SHOWN = 10           # cap CVEs sent to LLM to avoid token overflow
NMAP_ARGS      = "-sV -T4 --open"   # base args; -O added if we detect root

# Verdicts the LLM may return
_VALID_VERDICTS = {"vulnerable", "suspicious", "clean", "uncertain"}

# Ports considered inherently high-risk when open externally
_HIGH_RISK_PORTS = {
    21, 23, 69, 135, 137, 138, 139, 445, 512, 513, 514,
    1433, 1521, 2375, 2376, 3306, 3389, 4444, 5432, 5900,
    6379, 7001, 8080, 8443, 9200, 27017,
}

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


# ══════════════════════════════════════════════════════════════════════════════
# Target validation
# ══════════════════════════════════════════════════════════════════════════════

def _validate_target(target: str) -> str:
    """
    Validate and normalise the scan target.

    Allows:  IPv4, IPv6, CIDR, hostnames
    Blocks:  clearly invalid strings, multiline injection

    Returns the stripped target string.
    Raises ValueError if the target is invalid.
    """
    target = target.strip()

    # Block shell injection attempts
    if any(c in target for c in (";", "&", "|", "`", "$", "\n", "\r")):
        raise ValueError(f"Invalid target — contains forbidden characters: {target!r}")

    if not target:
        raise ValueError("Target cannot be empty.")

    # Accept IP addresses and CIDR blocks
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # Accept hostnames (rough RFC-1123 check)
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if hostname_re.match(target):
        return target

    # Accept bare labels (single-word hostnames like "router" or "localhost")
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}$", target):
        return target

    raise ValueError(f"Target does not look like a valid IP, CIDR, or hostname: {target!r}")


def _is_private(target: str) -> bool:
    """Return True if the target resolves to a private / loopback address."""
    try:
        addr = ipaddress.ip_address(target)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False   # hostname — assume routable


# ══════════════════════════════════════════════════════════════════════════════
# Nmap scanning
# ══════════════════════════════════════════════════════════════════════════════

def _detect_root() -> bool:
    """Return True if running as root (enables OS detection in Nmap)."""
    try:
        import os
        return os.geteuid() == 0
    except AttributeError:
        return False   # Windows


def _run_nmap(target: str, extra_ports: str | None = None) -> tuple[dict, float]:
    """
    Execute an Nmap scan against *target*.

    Parameters
    ----------
    target      : validated IP / hostname / CIDR
    extra_ports : optional comma-separated port list (e.g. "22,80,443")

    Returns
    -------
    (nmap_result_dict, duration_seconds)

    Raises RuntimeError if nmap is not installed or scan fails.
    """
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError as exc:
        raise RuntimeError(
            "nmap binary not found. Install it with:\n"
            "  sudo apt-get install -y nmap"
        ) from exc

    args = NMAP_ARGS
    if _detect_root():
        args += " -O"   # OS detection needs raw socket access

    if extra_ports:
        args += f" -p {extra_ports}"

    log.info("Nmap: scanning %s with args: %s", target, args)
    t0 = time.perf_counter()

    try:
        scanner.scan(hosts=target, arguments=args, timeout=SCAN_TIMEOUT)
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected error during Nmap scan: {exc}") from exc

    duration = time.perf_counter() - t0
    log.info("Nmap: scan completed in %.1f s", duration)

    return scanner, duration


# ══════════════════════════════════════════════════════════════════════════════
# Nmap result parsing
# ══════════════════════════════════════════════════════════════════════════════

def _parse_nmap_results(scanner: nmap.PortScanner, target: str) -> dict:
    """
    Extract structured data from the nmap PortScanner object.

    Returns
    -------
    {
        hosts: [{
            ip, hostname, state, os_guess,
            ports: [{port, protocol, service, version, state, cpe}]
        }]
    }
    """
    hosts = []

    for host in scanner.all_hosts():
        host_data = scanner[host]
        state     = host_data.state()

        # OS guess (available only with -O and root)
        os_guess = "unknown"
        if "osmatch" in host_data and host_data["osmatch"]:
            top = host_data["osmatch"][0]
            os_guess = f"{top.get('name', 'unknown')} (accuracy {top.get('accuracy', '?')}%)"

        # Hostname
        hostnames = host_data.hostnames()
        hostname  = hostnames[0]["name"] if hostnames else host

        ports = []
        for proto in host_data.all_protocols():
            port_ids = sorted(host_data[proto].keys())
            for port in port_ids:
                port_info = host_data[proto][port]
                if port_info.get("state") != "open":
                    continue

                service = port_info.get("name", "unknown")
                version = " ".join(filter(None, [
                    port_info.get("product", ""),
                    port_info.get("version", ""),
                    port_info.get("extrainfo", ""),
                ])).strip() or "unknown"

                cpe = ""
                if port_info.get("cpe"):
                    cpe = port_info["cpe"]

                ports.append({
                    "port":     port,
                    "protocol": proto,
                    "service":  service,
                    "version":  version,
                    "state":    port_info.get("state", "open"),
                    "cpe":      cpe,
                })

        hosts.append({
            "ip":       host,
            "hostname": hostname,
            "state":    state,
            "os_guess": os_guess,
            "ports":    ports,
        })

    # If scanner found nothing (e.g. host down), return a placeholder
    if not hosts:
        hosts.append({
            "ip":       target,
            "hostname": target,
            "state":    "down or filtered",
            "os_guess": "unknown",
            "ports":    [],
        })

    return {"hosts": hosts}


# ══════════════════════════════════════════════════════════════════════════════
# CVE enrichment helpers
# ══════════════════════════════════════════════════════════════════════════════

def _build_scan_results_for_nvd(parsed: dict) -> list[dict]:
    """
    Reformat parsed nmap data into the shape expected by nvd_client:
    list of {service, version} dicts.
    """
    entries = []
    for host in parsed["hosts"]:
        for p in host["ports"]:
            if p["service"] != "unknown":
                entries.append({
                    "service": p["service"],
                    "version": p["version"],
                })
    return entries


def _high_risk_ports_open(parsed: dict) -> list[int]:
    """Return list of high-risk ports that are open in the scan results."""
    found = []
    for host in parsed["hosts"]:
        for p in host["ports"]:
            if p["port"] in _HIGH_RISK_PORTS:
                found.append(p["port"])
    return sorted(set(found))


# ══════════════════════════════════════════════════════════════════════════════
# LLM prompt context builder
# ══════════════════════════════════════════════════════════════════════════════

def _build_scan_summary(parsed: dict, cves: list[dict]) -> str:
    """
    Format the scan findings into a structured text block for the LLM.
    """
    lines = []
    for host in parsed["hosts"]:
        lines.append(f"Host: {host['ip']} ({host['hostname']})  state={host['state']}")
        lines.append(f"OS:   {host['os_guess']}")
        if host["ports"]:
            lines.append(f"Open ports ({len(host['ports'])}):")
            for p in host["ports"]:
                risk = " ⚠ HIGH-RISK PORT" if p["port"] in _HIGH_RISK_PORTS else ""
                lines.append(
                    f"  {p['port']}/{p['protocol']}  {p['service']}  {p['version']}{risk}"
                )
        else:
            lines.append("  No open ports detected.")
        lines.append("")

    if cves:
        lines.append(f"CVEs found ({len(cves)}, showing top {min(len(cves), MAX_CVES_SHOWN)}):")
        for c in cves[:MAX_CVES_SHOWN]:
            lines.append(
                f"  [{c['cve_id']}]  CVSS={c['cvss_score']}  {c['severity']}"
                f"  — {c['affected_service']}  — {c['description'][:120]}"
            )
    else:
        lines.append("No CVEs found for detected services.")

    return "\n".join(lines)


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

def analyse(payload: str | dict) -> dict:
    """
    Scan an IP / host and assess its vulnerability posture.

    Parameters
    ----------
    payload : str  — IP address, hostname, or CIDR block
              dict — {"host": str, "ports": str (optional)}

    Returns
    -------
    dict conforming to the OUTPUT SCHEMA above.

    Raises
    ------
    ValueError   — invalid target
    RuntimeError — nmap not installed or scan failed
    """
    # ── Normalise payload ─────────────────────────────────────────────────────
    if isinstance(payload, dict):
        target      = str(payload.get("host") or payload.get("ip") or "")
        extra_ports = payload.get("ports")
    else:
        target      = str(payload)
        extra_ports = None

    # ── Step 1 — Validate target ──────────────────────────────────────────────
    log.info("IP agent: validating target '%s' …", target)
    target = _validate_target(target)

    if _is_private(target):
        log.info("IP agent: target %s is private/loopback — scan permitted.", target)

    # ── Step 2 — Nmap scan ────────────────────────────────────────────────────
    log.info("IP agent: starting Nmap scan …")
    try:
        scanner, duration = _run_nmap(target, extra_ports)
    except RuntimeError as exc:
        log.error("IP agent: Nmap failed — %s", exc)
        # Return a graceful partial result rather than crashing
        return {
            "agent":         "ip",
            "verdict":       "uncertain",
            "risk_score":    0.0,
            "confidence":    0.0,
            "reasoning":     str(exc),
            "indicators":    ["nmap_unavailable"],
            "target":        target,
            "open_ports":    [],
            "cves":          [],
            "os_guess":      "unknown",
            "scan_duration": 0.0,
        }

    # ── Step 3 — Parse Nmap results ───────────────────────────────────────────
    log.info("IP agent: parsing scan results …")
    parsed   = _parse_nmap_results(scanner, target)
    all_ports = [p for h in parsed["hosts"] for p in h["ports"]]
    os_guess  = parsed["hosts"][0]["os_guess"] if parsed["hosts"] else "unknown"

    # ── Step 4 — CVE lookup via NVD ───────────────────────────────────────────
    nvd_input = _build_scan_results_for_nvd(parsed)
    if nvd_input:
        log.info("IP agent: querying NVD for %d services …", len(nvd_input))
        cves = fetch_cves_for_hosts(nvd_input)
        log.info("IP agent: %d CVEs returned from NVD", len(cves))
    else:
        log.info("IP agent: no named services found — skipping NVD lookup")
        cves = []

    # High-risk port flags (added as indicators regardless of CVEs)
    risky_ports = _high_risk_ports_open(parsed)

    # ── Step 5 — Build scan summary for LLM ──────────────────────────────────
    scan_summary = _build_scan_summary(parsed, cves)

    # ── Step 6 — Build prompts ────────────────────────────────────────────────
    system_prompt = ip_system_prompt()
    user_prompt   = ip_user_prompt(
        target       = target,
        scan_summary = scan_summary,
        open_ports   = all_ports,
        cve_count    = len(cves),
        top_cves     = cves[:MAX_CVES_SHOWN],
        os_guess     = os_guess,
        risky_ports  = risky_ports,
    )

    # ── Step 7 — LLM call ─────────────────────────────────────────────────────
    log.info("IP agent: calling LLM …")
    raw_response = ask(system_prompt, user_prompt)

    # ── Step 8 — Parse + validate ─────────────────────────────────────────────
    log.info("IP agent: parsing LLM response …")
    llm_result = _parse_llm_response(raw_response)

    # Augment indicators with risky port findings
    if risky_ports:
        llm_result["indicators"].append(
            f"High-risk ports open: {risky_ports}"
        )

    # ── Step 9 — Assemble result ──────────────────────────────────────────────
    result = {
        "agent": "ip",
        **llm_result,
        "target":        target,
        "open_ports":    all_ports,
        "cves":          cves,
        "os_guess":      os_guess,
        "scan_duration": round(duration, 2),
    }

    log.info(
        "IP agent: done — verdict=%s  risk=%.2f  ports=%d  cves=%d",
        result["verdict"], result["risk_score"], len(all_ports), len(cves),
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python cyber_mas/agents/ip_agent.py [target]
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json as _json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    print("\n" + "═" * 60)
    print(f"  IP Agent — smoke-test  →  target: {target}")
    print("═" * 60 + "\n")
    print("  Running Nmap scan … (this may take 20–60 s)\n")

    try:
        result = analyse(target)
        # Truncate CVEs for readable output
        result["cves"] = result["cves"][:3]
        print(_json.dumps(result, indent=2))
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print("  Make sure nmap and GROQ_API_KEY are available.")