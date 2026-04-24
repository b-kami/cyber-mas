"""
cyber_mas/tools/mitre_mapper.py
══════════════════════════════════════════════════════════════════════════════
MITRE ATT&CK Mapping Module.

ROLE
────
  Maps threat indicators, signatures, verdicts, and CVEs from any agent
  result to MITRE ATT&CK techniques and tactics.

  Feeds:
    • dashboard  — visual ATT&CK matrix overlay
    • correlator — technique IDs injected into LLM prompt
    • reports    — structured ATT&CK section in JSON output

MAPPING SOURCES (in priority order)
────────────────────────────────────
  1. Signature names        (log agent: "brute_force", "port_scan" …)
  2. Verdict strings        ("phishing", "malicious", "vulnerable" …)
  3. Indicator strings      (fuzzy keyword match against technique keywords)
  4. CVE IDs                (known CVE → technique mapping)
  5. Open port numbers      (known dangerous port → technique)
  6. Email metadata         (has_attachments, link_count → technique)

OUTPUT SCHEMA
─────────────
  MitreTechnique dataclass:
    technique_id   : str    e.g. "T1110.001"
    technique_name : str    e.g. "Password Guessing"
    tactic_id      : str    e.g. "TA0006"
    tactic_name    : str    e.g. "Credential Access"
    description    : str
    source         : str    what triggered this mapping
    confidence     : float  0.0 – 1.0
    url            : str    ATT&CK MITRE URL

USAGE
─────
  from cyber_mas.tools.mitre_mapper import map_result, map_all_results

  # Single agent result
  techniques = map_result(log_result)

  # All agents at once (deduplicates)
  techniques = map_all_results([email_r, log_r, ip_r, correlator_r])

  # Just the technique IDs (for correlator prompt)
  ids = [t.technique_id for t in techniques]

  # CLI
  python cyber_mas/tools/mitre_mapper.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── ATT&CK base URL ───────────────────────────────────────────────────────────
_BASE_URL = "https://attack.mitre.org/techniques/"


# ══════════════════════════════════════════════════════════════════════════════
# Data model
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MitreTechnique:
    technique_id:   str
    technique_name: str
    tactic_id:      str
    tactic_name:    str
    description:    str
    source:         str         # what triggered this mapping
    confidence:     float       # 0.0 – 1.0
    url:            str = ""

    def __post_init__(self):
        tid = self.technique_id.replace(".", "/")
        self.url = f"{_BASE_URL}{tid}/"

    def to_dict(self) -> dict:
        return {
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "tactic_id":      self.tactic_id,
            "tactic_name":    self.tactic_name,
            "description":    self.description,
            "source":         self.source,
            "confidence":     self.confidence,
            "url":            self.url,
        }

    def to_prompt_line(self) -> str:
        return (
            f"  [{self.technique_id}] {self.technique_name} "
            f"({self.tactic_name}) — triggered by: {self.source}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Master technique catalogue
# ══════════════════════════════════════════════════════════════════════════════
# Schema per entry:
#   technique_id, technique_name, tactic_id, tactic_name, description, keywords

_CATALOGUE: list[dict] = [

    # ── Initial Access ────────────────────────────────────────────────────────
    {
        "technique_id":   "T1566",
        "technique_name": "Phishing",
        "tactic_id":      "TA0001",
        "tactic_name":    "Initial Access",
        "description":    "Adversaries send phishing messages to gain access to victim systems.",
        "keywords":       ["phishing", "phish", "spear", "spearphishing"],
    },
    {
        "technique_id":   "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic_id":      "TA0001",
        "tactic_name":    "Initial Access",
        "description":    "Adversaries send spearphishing emails with malicious attachments.",
        "keywords":       ["attachment", "malicious attachment", "has_attachments"],
    },
    {
        "technique_id":   "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic_id":      "TA0001",
        "tactic_name":    "Initial Access",
        "description":    "Adversaries send spearphishing emails with malicious links.",
        "keywords":       ["suspicious_url", "malicious link", "redirect", "href", "url"],
    },
    {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id":      "TA0001",
        "tactic_name":    "Initial Access",
        "description":    "Adversaries exploit weaknesses in internet-facing software.",
        "keywords":       ["web_attack", "sqli", "xss", "path traversal", "rce",
                           "sql injection", "cross-site", "exploit", "union select"],
    },
    {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic_id":      "TA0001",
        "tactic_name":    "Initial Access",
        "description":    "Adversaries obtain and abuse credentials of existing accounts.",
        "keywords":       ["valid account", "credential", "accepted password",
                           "successful login", "authenticated"],
    },

    # ── Execution ──────────────────────────────────────────────────────────────
    {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic_id":      "TA0002",
        "tactic_name":    "Execution",
        "description":    "Adversaries abuse command and script interpreters.",
        "keywords":       ["bash", "cmd", "powershell", "shell", "exec(", "eval(",
                           "script", "interpreter"],
    },
    {
        "technique_id":   "T1059.004",
        "technique_name": "Unix Shell",
        "tactic_id":      "TA0002",
        "tactic_name":    "Execution",
        "description":    "Adversaries abuse Unix shell commands and scripts.",
        "keywords":       ["/bin/bash", "/bin/sh", "sh -c", "bash -i"],
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    {
        "technique_id":   "T1136",
        "technique_name": "Create Account",
        "tactic_id":      "TA0003",
        "tactic_name":    "Persistence",
        "description":    "Adversaries create accounts to maintain access.",
        "keywords":       ["useradd", "adduser", "net user", "create account",
                           "new account"],
    },
    {
        "technique_id":   "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic_id":      "TA0003",
        "tactic_name":    "Persistence",
        "description":    "Adversaries abuse task scheduling to maintain persistence.",
        "keywords":       ["cron", "crontab", "at ", "scheduled task", "systemd timer"],
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    {
        "technique_id":   "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic_id":      "TA0004",
        "tactic_name":    "Privilege Escalation",
        "description":    "Adversaries bypass elevation controls to get higher-level permissions.",
        "keywords":       ["privilege_escalation", "sudo", "su ", "setuid", "setgid",
                           "wheel", "sudoers", "chmod 777", "privilege"],
    },
    {
        "technique_id":   "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic_id":      "TA0004",
        "tactic_name":    "Privilege Escalation",
        "description":    "Adversaries perform sudo caching and/or use sudoers to elevate privileges.",
        "keywords":       ["sudo:", "sudo failed", "sudo session", "sudo command"],
    },
    {
        "technique_id":   "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic_id":      "TA0004",
        "tactic_name":    "Privilege Escalation",
        "description":    "Adversaries exploit software vulnerabilities to escalate privileges.",
        "keywords":       ["local privilege", "kernel exploit", "dirty cow", "cve-201"],
    },

    # ── Defense Evasion ────────────────────────────────────────────────────────
    {
        "technique_id":   "T1070",
        "technique_name": "Indicator Removal",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
        "description":    "Adversaries delete or alter artifacts to remove evidence.",
        "keywords":       ["log cleared", "history cleared", "rm -rf /var/log",
                           "shred", "wipe", "truncate"],
    },
    {
        "technique_id":   "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic_id":      "TA0005",
        "tactic_name":    "Defense Evasion",
        "description":    "Adversaries attempt to make payloads or signatures harder to detect.",
        "keywords":       ["base64", "obfuscat", "encode", "encrypt payload",
                           "base64_decode"],
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic_id":      "TA0006",
        "tactic_name":    "Credential Access",
        "description":    "Adversaries use brute force techniques to gain access to accounts.",
        "keywords":       ["brute_force", "brute force", "failed password", "failed login",
                           "authentication failure", "invalid user", "repeated failure"],
    },
    {
        "technique_id":   "T1110.001",
        "technique_name": "Password Guessing",
        "tactic_id":      "TA0006",
        "tactic_name":    "Credential Access",
        "description":    "Adversaries guess passwords without prior knowledge of the password.",
        "keywords":       ["password guessing", "dictionary attack", "wordlist"],
    },
    {
        "technique_id":   "T1110.003",
        "technique_name": "Password Spraying",
        "tactic_id":      "TA0006",
        "tactic_name":    "Credential Access",
        "description":    "Adversaries use a single password against many accounts.",
        "keywords":       ["password spray", "spraying", "multiple accounts same password"],
    },
    {
        "technique_id":   "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic_id":      "TA0006",
        "tactic_name":    "Credential Access",
        "description":    "Adversaries search for common password storage locations.",
        "keywords":       [".ssh/id_rsa", "credentials file", "password store",
                           "keychain", "/etc/shadow"],
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic_id":      "TA0007",
        "tactic_name":    "Discovery",
        "description":    "Adversaries scan victim networks to gather info about services.",
        "keywords":       ["port_scan", "port scan", "nmap", "network scan",
                           "service discovery", "syn scan", "connection refused"],
    },
    {
        "technique_id":   "T1082",
        "technique_name": "System Information Discovery",
        "tactic_id":      "TA0007",
        "tactic_name":    "Discovery",
        "description":    "Adversaries gather information about the victim's OS and hardware.",
        "keywords":       ["uname", "system info", "os detection", "whoami", "hostname"],
    },
    {
        "technique_id":   "T1018",
        "technique_name": "Remote System Discovery",
        "tactic_id":      "TA0007",
        "tactic_name":    "Discovery",
        "description":    "Adversaries attempt to get a listing of other systems.",
        "keywords":       ["arp -a", "net view", "nbtstat", "ping sweep",
                           "host discovery"],
    },
    {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic_id":      "TA0007",
        "tactic_name":    "Discovery",
        "description":    "Adversaries enumerate files and directories.",
        "keywords":       ["ls -la", "dir /a", "find /", "directory traversal",
                           "file listing"],
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────
    {
        "technique_id":   "T1021",
        "technique_name": "Remote Services",
        "tactic_id":      "TA0008",
        "tactic_name":    "Lateral Movement",
        "description":    "Adversaries use Valid Accounts to log into remote services.",
        "keywords":       ["lateral_movement", "ssh from", "rdp", "smb", "psexec",
                           "winrm", "wmi", "lateral movement"],
    },
    {
        "technique_id":   "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "tactic_id":      "TA0008",
        "tactic_name":    "Lateral Movement",
        "description":    "Adversaries use Valid Accounts to log into a computer using RDP.",
        "keywords":       ["rdp", "remote desktop", "3389", "mstsc"],
    },
    {
        "technique_id":   "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic_id":      "TA0008",
        "tactic_name":    "Lateral Movement",
        "description":    "Adversaries use Valid Accounts to interact with remote network shares.",
        "keywords":       ["smb", "445", "admin share", "ipc$", "net use", "\\\\"],
    },
    {
        "technique_id":   "T1021.004",
        "technique_name": "SSH",
        "tactic_id":      "TA0008",
        "tactic_name":    "Lateral Movement",
        "description":    "Adversaries use Valid Accounts to log into remote machines using SSH.",
        "keywords":       ["ssh", "sshd", "port 22", "openssh", "ssh session"],
    },

    # ── Collection ────────────────────────────────────────────────────────────
    {
        "technique_id":   "T1560",
        "technique_name": "Archive Collected Data",
        "tactic_id":      "TA0009",
        "tactic_name":    "Collection",
        "description":    "Adversaries archive data before exfiltration.",
        "keywords":       ["tar ", "zip ", "gzip", "7zip", "rar ", "archive"],
    },

    # ── Command and Control ───────────────────────────────────────────────────
    {
        "technique_id":   "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic_id":      "TA0011",
        "tactic_name":    "Command & Control",
        "description":    "Adversaries communicate using OSI application layer protocols.",
        "keywords":       ["malware_c2", "c2", "beacon", "beaconing", "heartbeat",
                           "checkin", "check-in", "command and control"],
    },
    {
        "technique_id":   "T1071.001",
        "technique_name": "Web Protocols",
        "tactic_id":      "TA0011",
        "tactic_name":    "Command & Control",
        "description":    "Adversaries communicate using application layer protocols HTTP/HTTPS.",
        "keywords":       ["http beacon", "https c2", "web c2", "curl beacon",
                           "python-requests"],
    },
    {
        "technique_id":   "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "tactic_id":      "TA0011",
        "tactic_name":    "Command & Control",
        "description":    "Adversaries use OSI non-application layer protocols for C2.",
        "keywords":       ["icmp tunnel", "dns tunnel", "raw socket", "tcp c2"],
    },
    {
        "technique_id":   "T1572",
        "technique_name": "Protocol Tunneling",
        "tactic_id":      "TA0011",
        "tactic_name":    "Command & Control",
        "description":    "Adversaries tunnel network communications to evade detection.",
        "keywords":       ["tunnel", "ssh tunnel", "port forward", "ngrok", "frp"],
    },

    # ── Exfiltration ──────────────────────────────────────────────────────────
    {
        "technique_id":   "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic_id":      "TA0010",
        "tactic_name":    "Exfiltration",
        "description":    "Adversaries steal data by exfiltrating it over an existing C2 channel.",
        "keywords":       ["data_exfiltration", "exfil", "exfiltration", "data theft",
                           "bytes sent", "large transfer"],
    },
    {
        "technique_id":   "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic_id":      "TA0010",
        "tactic_name":    "Exfiltration",
        "description":    "Adversaries steal data via a different protocol than C2.",
        "keywords":       ["ftp put", "scp -r", "rsync -a", "sftp", "ftp stor"],
    },

    # ── Impact ────────────────────────────────────────────────────────────────
    {
        "technique_id":   "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
        "description":    "Adversaries encrypt data on target systems to interrupt availability.",
        "keywords":       ["ransomware", "encrypted files", ".locked", ".crypto",
                           "ransom note"],
    },
    {
        "technique_id":   "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic_id":      "TA0040",
        "tactic_name":    "Impact",
        "description":    "Adversaries perform DoS attacks to degrade system availability.",
        "keywords":       ["dos", "denial of service", "flood", "ddos", "syn flood"],
    },
]

# ── Port → technique mapping ──────────────────────────────────────────────────
_PORT_TECHNIQUE_MAP: dict[int, str] = {
    21:    "T1021",       # FTP → Remote Services
    22:    "T1021.004",   # SSH → SSH
    23:    "T1078",       # Telnet → Valid Accounts
    25:    "T1566",       # SMTP → Phishing
    80:    "T1190",       # HTTP → Exploit Public-Facing Application
    135:   "T1021",       # RPC → Remote Services
    139:   "T1021.002",   # NetBIOS → SMB
    443:   "T1190",       # HTTPS → Exploit Public-Facing Application
    445:   "T1021.002",   # SMB → SMB/Windows Admin Shares
    1433:  "T1190",       # MSSQL → Exploit Public-Facing
    1521:  "T1190",       # Oracle → Exploit Public-Facing
    2375:  "T1190",       # Docker API (unauthenticated) → Exploit Public-Facing
    3306:  "T1190",       # MySQL → Exploit Public-Facing
    3389:  "T1021.001",   # RDP → Remote Desktop Protocol
    4444:  "T1071",       # Metasploit default → C2
    5432:  "T1190",       # PostgreSQL → Exploit Public-Facing
    5900:  "T1021",       # VNC → Remote Services
    6379:  "T1190",       # Redis (unauthenticated) → Exploit Public-Facing
    7001:  "T1190",       # WebLogic → Exploit Public-Facing
    8080:  "T1190",       # HTTP alt → Exploit Public-Facing
    9200:  "T1190",       # Elasticsearch → Exploit Public-Facing
    27017: "T1190",       # MongoDB (unauthenticated) → Exploit Public-Facing
}

# ── CVE prefix → technique mapping ────────────────────────────────────────────
# Maps CVE ID prefixes / known CVEs to technique IDs
_CVE_TECHNIQUE_MAP: dict[str, str] = {
    "CVE-2017-0144": "T1190",      # EternalBlue / SMB
    "CVE-2017-0145": "T1190",      # EternalRomance / SMB
    "CVE-2019-0708": "T1021.001",  # BlueKeep / RDP
    "CVE-2021-44228": "T1190",     # Log4Shell
    "CVE-2021-34527": "T1068",     # PrintNightmare
    "CVE-2020-1472":  "T1068",     # Zerologon
    "CVE-2016-6515":  "T1499",     # OpenSSH DoS
    "CVE-2018-15473": "T1110",     # OpenSSH user enumeration → Brute Force
}

# Build lookup dict from catalogue
_TECH_BY_ID: dict[str, dict] = {e["technique_id"]: e for e in _CATALOGUE}


# ══════════════════════════════════════════════════════════════════════════════
# Mapping engine
# ══════════════════════════════════════════════════════════════════════════════

def _make_technique(entry: dict, source: str, confidence: float) -> MitreTechnique:
    return MitreTechnique(
        technique_id   = entry["technique_id"],
        technique_name = entry["technique_name"],
        tactic_id      = entry["tactic_id"],
        tactic_name    = entry["tactic_name"],
        description    = entry["description"],
        source         = source,
        confidence     = round(confidence, 2),
    )


def _match_keywords(text: str, entry: dict) -> bool:
    """Return True if any keyword in entry matches text (case-insensitive)."""
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in entry["keywords"])


def _map_text(text: str, source: str, confidence: float) -> list[MitreTechnique]:
    """Map a free-text string against the full catalogue."""
    results = []
    for entry in _CATALOGUE:
        if _match_keywords(text, entry):
            results.append(_make_technique(entry, source, confidence))
    return results


def _deduplicate(techniques: list[MitreTechnique]) -> list[MitreTechnique]:
    """
    Deduplicate by technique_id, keeping the entry with highest confidence.
    Sort by tactic_id then technique_id for stable output.
    """
    best: dict[str, MitreTechnique] = {}
    for t in techniques:
        if t.technique_id not in best or t.confidence > best[t.technique_id].confidence:
            best[t.technique_id] = t
    return sorted(best.values(), key=lambda t: (t.tactic_id, t.technique_id))


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def map_result(result: dict) -> list[MitreTechnique]:
    """
    Map a single agent result dict to MITRE ATT&CK techniques.

    Parameters
    ----------
    result : agent result dict (from email_agent, log_agent, ip_agent,
             or correlator)

    Returns
    -------
    list[MitreTechnique] — deduplicated, sorted by tactic then technique ID
    """
    techniques: list[MitreTechnique] = []
    agent = result.get("agent", "unknown")

    # ── 1. Signature names (log agent) ───────────────────────────────────────
    for sig in result.get("signatures_hit", []):
        matches = _map_text(sig, source=f"signature:{sig}", confidence=0.95)
        techniques.extend(matches)

    # ── 2. Verdict ────────────────────────────────────────────────────────────
    verdict = result.get("verdict", "")
    if verdict and verdict not in ("uncertain", "benign", "clean", "low"):
        matches = _map_text(verdict, source=f"verdict:{verdict}", confidence=0.85)
        techniques.extend(matches)

    # ── 3. Indicators ─────────────────────────────────────────────────────────
    for ind in result.get("indicators", []):
        matches = _map_text(str(ind), source=f"indicator:{ind}", confidence=0.80)
        techniques.extend(matches)

    # ── 4. CVE IDs ────────────────────────────────────────────────────────────
    for cve in result.get("cves", []):
        cve_id = cve.get("cve_id", "")
        if cve_id in _CVE_TECHNIQUE_MAP:
            tid = _CVE_TECHNIQUE_MAP[cve_id]
            if tid in _TECH_BY_ID:
                techniques.append(_make_technique(
                    _TECH_BY_ID[tid],
                    source=f"cve:{cve_id}",
                    confidence=0.95,
                ))
        else:
            # Map by CVE description
            desc = cve.get("description", "")
            if desc:
                matches = _map_text(desc, source=f"cve_desc:{cve_id}", confidence=0.70)
                techniques.extend(matches)

    # ── 5. Open ports ─────────────────────────────────────────────────────────
    for port_info in result.get("open_ports", []):
        port = port_info.get("port")
        if port and port in _PORT_TECHNIQUE_MAP:
            tid = _PORT_TECHNIQUE_MAP[port]
            if tid in _TECH_BY_ID:
                techniques.append(_make_technique(
                    _TECH_BY_ID[tid],
                    source=f"port:{port}/{port_info.get('service','?')}",
                    confidence=0.75,
                ))

    # ── 6. Email metadata ────────────────────────────────────────────────────
    meta = result.get("email_metadata", {})
    if meta:
        if meta.get("has_attachments"):
            techniques.append(_make_technique(
                _TECH_BY_ID["T1566.001"],
                source="email:has_attachments",
                confidence=0.85,
            ))
        if meta.get("link_count", 0) > 0:
            techniques.append(_make_technique(
                _TECH_BY_ID["T1566.002"],
                source=f"email:link_count={meta['link_count']}",
                confidence=0.85,
            ))

    # ── 7. Correlation rules ──────────────────────────────────────────────────
    corr_map = {
        "C1_shared_ip":               "T1021",
        "C2_phishing_and_breach":     "T1566",
        "C3_vuln_and_exploit":        "T1190",
        "C4_multi_vector_high_risk":  "T1078",
        "C5_c2_beacon_and_network_scan": "T1071",
        "C6_recon_pattern":           "T1046",
    }
    for corr in result.get("correlations", []):
        if corr in corr_map:
            tid = corr_map[corr]
            if tid in _TECH_BY_ID:
                techniques.append(_make_technique(
                    _TECH_BY_ID[tid],
                    source=f"correlation:{corr}",
                    confidence=0.90,
                ))

    # ── 8. Free-text reasoning (low confidence) ───────────────────────────────
    reasoning = result.get("reasoning", "")
    if reasoning:
        matches = _map_text(reasoning, source="reasoning", confidence=0.60)
        techniques.extend(matches)

    return _deduplicate(techniques)


def map_all_results(results: list[dict]) -> list[MitreTechnique]:
    """
    Map multiple agent results, deduplicating across all of them.

    Parameters
    ----------
    results : list of agent result dicts

    Returns
    -------
    list[MitreTechnique] — globally deduplicated, sorted
    """
    all_techniques: list[MitreTechnique] = []
    for result in results:
        all_techniques.extend(map_result(result))
    return _deduplicate(all_techniques)


def techniques_to_prompt_block(techniques: list[MitreTechnique]) -> str:
    """
    Format techniques as a structured block for injection into the LLM prompt.
    Used by the correlator to give the LLM ATT&CK context.
    """
    if not techniques:
        return "No MITRE ATT&CK techniques mapped."

    # Group by tactic
    by_tactic: dict[str, list[MitreTechnique]] = {}
    for t in techniques:
        by_tactic.setdefault(t.tactic_name, []).append(t)

    lines = ["MITRE ATT&CK TECHNIQUES DETECTED:"]
    for tactic, techs in sorted(by_tactic.items()):
        lines.append(f"\n  [{tactic.upper()}]")
        for t in techs:
            lines.append(f"    {t.to_prompt_line()}")

    return "\n".join(lines)


def get_attack_chain(techniques: list[MitreTechnique]) -> list[str]:
    """
    Return the likely attack chain as an ordered list of tactic names,
    based on the ATT&CK kill chain order.
    """
    TACTIC_ORDER = [
        "TA0001",  # Initial Access
        "TA0002",  # Execution
        "TA0003",  # Persistence
        "TA0004",  # Privilege Escalation
        "TA0005",  # Defense Evasion
        "TA0006",  # Credential Access
        "TA0007",  # Discovery
        "TA0008",  # Lateral Movement
        "TA0009",  # Collection
        "TA0011",  # Command & Control
        "TA0010",  # Exfiltration
        "TA0040",  # Impact
    ]

    seen_tactics = {t.tactic_id: t.tactic_name for t in techniques}
    return [
        seen_tactics[tid]
        for tid in TACTIC_ORDER
        if tid in seen_tactics
    ]


def summary_stats(techniques: list[MitreTechnique]) -> dict:
    """Return a summary statistics dict for the dashboard."""
    if not techniques:
        return {"total": 0, "tactics": [], "by_tactic": {}, "attack_chain": []}

    by_tactic: dict[str, list] = {}
    for t in techniques:
        by_tactic.setdefault(t.tactic_name, []).append(t.technique_id)

    return {
        "total":        len(techniques),
        "tactics":      list(by_tactic.keys()),
        "tactic_count": len(by_tactic),
        "by_tactic":    {k: len(v) for k, v in by_tactic.items()},
        "attack_chain": get_attack_chain(techniques),
        "top_confidence": sorted(
            [{"id": t.technique_id, "name": t.technique_name, "confidence": t.confidence}
             for t in techniques],
            key=lambda x: x["confidence"],
            reverse=True,
        )[:5],
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python cyber_mas/tools/mitre_mapper.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    MOCK_LOG = {
        "agent": "log", "verdict": "malicious", "risk_score": 0.88,
        "reasoning": "7 failed SSH logins from 203.0.113.42 followed by successful root login.",
        "indicators": ["ssh_brute_force", "root_compromise"],
        "signatures_hit": ["brute_force", "privilege_escalation"],
        "stats": {"top_sources": ["203.0.113.42"]},
    }
    MOCK_EMAIL = {
        "agent": "email", "verdict": "phishing", "risk_score": 0.92,
        "reasoning": "Domain spoofing with urgency language and suspicious redirect URL.",
        "indicators": ["domain_spoofing", "suspicious_url"],
        "email_metadata": {"subject": "URGENT", "sender": "evil@phish.com",
                           "has_links": True, "link_count": 3, "has_attachments": True},
    }
    MOCK_IP = {
        "agent": "ip", "verdict": "vulnerable", "risk_score": 0.79,
        "reasoning": "OpenSSH 7.2 with critical CVEs, SMB port open.",
        "indicators": ["outdated_openssh", "smb_exposed"],
        "open_ports": [
            {"port": 22, "service": "ssh"},
            {"port": 445, "service": "microsoft-ds"},
            {"port": 3389, "service": "rdp"},
        ],
        "cves": [
            {"cve_id": "CVE-2016-6515", "cvss_score": 7.8, "description": "OpenSSH DoS"},
            {"cve_id": "CVE-2017-0144", "cvss_score": 9.8, "description": "EternalBlue SMB"},
        ],
    }

    print("\n" + "═"*60)
    print("  MITRE ATT&CK Mapper — smoke-test")
    print("═"*60)

    all_results = [MOCK_LOG, MOCK_EMAIL, MOCK_IP]
    techniques  = map_all_results(all_results)
    stats       = summary_stats(techniques)

    print(f"\n  Total techniques mapped : {stats['total']}")
    print(f"  Tactics covered         : {stats['tactic_count']}")
    print(f"\n  Attack chain:")
    for i, tactic in enumerate(stats["attack_chain"], 1):
        print(f"    {i}. {tactic}")

    print(f"\n  Top confidence mappings:")
    for t in stats["top_confidence"]:
        print(f"    [{t['id']}] {t['name']} — {t['confidence']:.2f}")

    print(f"\n  Full technique list ({len(techniques)}):")
    print("  " + "─"*50)
    for t in techniques:
        print(f"  [{t.technique_id}] {t.technique_name:<40} | {t.tactic_name:<25} | conf={t.confidence:.2f} | src={t.source}")

    print(f"\n  Prompt block preview:")
    print("  " + "─"*50)
    block = techniques_to_prompt_block(techniques)
    for line in block.splitlines()[:20]:
        print("  " + line)

    print("\n  ✓ Smoke-test complete.\n")