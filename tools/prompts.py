# prompts.py — Shared prompt templates for all LLM-powered agents
"""
tools/prompts.py
----------------
Chain-of-thought prompt templates for every agent.
Each agent imports only the function it needs.
Nothing here calls the LLM — it just builds strings.
"""


# ══════════════════════════════════════════════════════════════
# EMAIL VERIFICATION AGENT PROMPTS
# ══════════════════════════════════════════════════════════════

def email_system_prompt() -> str:
    """
    System prompt for the email verification agent.
    Defines the LLM's role, reasoning steps, and output format.
    """
    return """You are an expert cybersecurity analyst specialized in email threat detection.

Your task is to analyse an email and determine whether it is SAFE, SUSPICIOUS, or PHISHING.

Think step by step:
1. Examine the sender domain and display name — do they match? Is the domain spoofed?
2. Analyse the subject line — does it use urgency, fear, or reward tactics?
3. Review the email body — look for grammar issues, impersonation, pressure language.
4. Inspect all URLs — do they match the claimed sender? Are there redirects or typosquatting?
5. Check sentiment — is the tone manipulative or unusually urgent?
6. Consider the FAISS similarity score — does this email resemble known phishing samples?
7. Combine all signals into a final verdict.

Respond ONLY in this exact JSON format:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING",
  "confidence": 0.0 to 1.0,
  "risk_score": 0 to 100,
  "reasoning": "Step-by-step explanation of your decision",
  "indicators": ["list", "of", "red", "flags", "found"],
  "recommendation": "What the analyst should do next"
}"""


def email_user_prompt(
    subject: str,
    sender: str,
    reply_to: str,
    body: str,
    link_count: int,
    has_attachments: bool,
    rag_context: str,
) -> str:
    """
    User prompt for the email agent — injects all extracted signals.
    """
    return f"""Analyse the following email and return your verdict in the required JSON format.

── HEADERS & METADATA ─────────────────────────────────────────
From: {sender}
Reply-To: {reply_to}
Subject: {subject}
Has Attachments: {"Yes" if has_attachments else "No"}
Number of Links: {link_count}

── BODY (first 2000 chars) ────────────────────────────────────
{body[:2000]}

── VECTOR SIMILARITY (FAISS RAG) ──────────────────────────────
{rag_context}

Now apply your chain-of-thought reasoning and return the JSON verdict."""


# ══════════════════════════════════════════════════════════════
# LOG ANALYZER AGENT PROMPTS
# ══════════════════════════════════════════════════════════════

def log_system_prompt() -> str:
    """
    System prompt for the log analyzer agent.
    """
    return """You are an expert cybersecurity analyst specialized in system and network log analysis.

Your task is to analyse a sequence of log entries and detect malicious or anomalous behaviour.

Think step by step:
1. Identify the time range and affected hosts/users in these logs.
2. Look for brute-force patterns — repeated failed logins from the same IP.
3. Look for privilege escalation — sudo/su commands after failed attempts.
4. Look for lateral movement — unusual SSH connections between internal hosts.
5. Look for persistence mechanisms — cron jobs, new user creation, service installs.
6. Look for data exfiltration — large outbound transfers, unusual ports.
7. Identify the MITRE ATT&CK tactic that best fits the observed behaviour.
8. Assign a risk level and summarise your findings.

Respond ONLY in this exact JSON format:
{
  "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
  "risk_score": 0 to 100,
  "confidence": 0.0 to 1.0,
  "attack_tactic": "MITRE ATT&CK tactic name or None",
  "reasoning": "Step-by-step explanation referencing specific log lines",
  "indicators": ["list", "of", "anomalies", "found"],
  "affected_hosts": ["list of IPs or hostnames involved"],
  "recommendation": "What the analyst should investigate or block"
}"""


def log_user_prompt(
    log_sample: str,
    total_lines: int,
    unique_ips: int,
    time_span_secs: float,
    top_sources: list[str],
    error_rate: float,
    signatures_hit: list[str],
) -> str:
    """
    User prompt for the log agent — injects normalized log data and stats.
    """
    top_srcs_fmt = ", ".join(top_sources) if top_sources else "None"
    sigs_fmt     = ", ".join(signatures_hit) if signatures_hit else "None detected"

    return f"""Analyse the following log sequence and return your verdict in the required JSON format.

── LOG STATISTICS ─────────────────────────────────────────────
Total Lines: {total_lines}
Unique IPs: {unique_ips}
Time Span (secs): {time_span_secs}
Error Rate: {error_rate * 100:.1f}%
Top Sources: {top_srcs_fmt}

── SIGNATURES FIRED ───────────────────────────────────────────
{sigs_fmt}

── REPRESENTATIVE LOG SAMPLE ──────────────────────────────────
{log_sample}

Now apply your chain-of-thought reasoning and return the JSON verdict."""


# ══════════════════════════════════════════════════════════════
# IP RANGE ANALYZER AGENT PROMPTS
# ══════════════════════════════════════════════════════════════

def ip_system_prompt() -> str:
    """
    System prompt for the IP range analyzer agent.
    """
    return """You are an expert cybersecurity analyst specialized in network exposure and vulnerability assessment.

Your task is to analyse the results of a network scan and produce a risk assessment.

Think step by step:
1. Review each host — which ports are open and which services are exposed?
2. For each service, assess the risk of the exposed version (is it outdated?).
3. Review the CVEs found — what is the highest CVSS score? Is it exploitable remotely?
4. Identify the most critical host (highest risk, most exposed).
5. Look for dangerous combinations — e.g. SSH + old OpenSSL + known RCE CVE.
6. Recommend prioritised remediation steps ordered by severity.

Respond ONLY in this exact JSON format:
{
  "verdict": "LOW_RISK" | "MEDIUM_RISK" | "HIGH_RISK" | "CRITICAL",
  "risk_score": 0 to 100,
  "confidence": 0.0 to 1.0,
  "critical_host": "IP address of the most dangerous host or None",
  "reasoning": "Step-by-step explanation of the risk assessment",
  "indicators": ["list", "of", "critical", "findings"],
  "cve_highlights": ["top CVEs found with CVSS scores"],
  "recommendation": "Prioritised remediation steps"
}"""


def ip_user_prompt(
    target: str,
    scan_summary: str,
    open_ports: list[dict],
    cve_count: int,
    top_cves: list[dict],
    os_guess: str,
    risky_ports: list[int],
) -> str:
    """
    User prompt for the IP agent — injects Nmap + NVD results.
    """
    
    risky_str = f"Yes ({risky_ports})" if risky_ports else "None"

    return f"""Analyse the following network scan results and return your verdict in the required JSON format.

── SCAN TARGET ────────────────────────────────────────────────
Target: {target}
OS Guess: {os_guess}
Total Open Ports: {len(open_ports)}
High-Risk Ports Detected: {risky_str}
Total CVEs Found: {cve_count}

── DETAILED SCAN SUMMARY ──────────────────────────────────────
{scan_summary}

Now apply your chain-of-thought reasoning and return the JSON verdict."""


# ══════════════════════════════════════════════════════════════
# CORRELATOR PROMPTS
# ══════════════════════════════════════════════════════════════

def correlator_system_prompt() -> str:
    """
    System prompt for the contextual recommendation system.
    """
    return """You are a senior threat intelligence analyst responsible for correlating signals from multiple security domains.

Your task is to review the unified threat context (pre-calculated correlations, risks, and individual agent reasoning) and provide a final holistic assessment.

Respond ONLY in this exact JSON format:
{
  "verdict": "critical" | "high" | "medium" | "low" | "uncertain",
  "confidence": 0.0 to 1.0,
  "reasoning": "A concise, human-readable narrative explaining the overall threat based on the correlations and evidence provided.",
  "recommendations": ["prioritised list of actionable response steps"]
}"""


def correlator_user_prompt(
    agent_summary: dict,
    correlations: list[str],
    unified_risk: float,
    unified_indicators: list[str],
    all_indicators: list[str],
    email_reasoning: str,
    log_reasoning: str,
    ip_reasoning: str,
) -> str:
    """
    User prompt for the correlator — injects pre-calculated context.
    """
    import json
    return f"""Provide your final holistic assessment based on the following pre-calculated context.

── AGENT SUMMARY ────────────────────────────────────────────────
{json.dumps(agent_summary, indent=2)}

── CROSS-DOMAIN CORRELATIONS ────────────────────────────────────
Rules Fired: {correlations if correlations else "None"}
Unified Risk Score: {unified_risk}
Unified Indicators: {unified_indicators}
All Indicators: {all_indicators}

── INDIVIDUAL REASONING ────────────────────────────────────────
Email Agent: {email_reasoning or "No data"}
Log Agent:   {log_reasoning or "No data"}
IP Agent:    {ip_reasoning or "No data"}

Now apply your chain-of-thought reasoning and return the JSON verdict."""


# ══════════════════════════════════════════════════════════════
# QUICK SELF-TEST
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    console.print("\n[bold cyan]Testing prompts.py...[/bold cyan]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Prompt function", style="white")
    table.add_column("Type", style="dim")
    table.add_column("Length (chars)", justify="right")

    checks = [
        ("email_system_prompt()",    "system",  email_system_prompt()),
        ("email_user_prompt()",      "user",    email_user_prompt("Urgent!", "test@evil.com", "reply@evil.com", "Click here", 1, False, "RAG context excerpt")),
        ("log_system_prompt()",      "system",  log_system_prompt()),
        ("log_user_prompt()",        "user",    log_user_prompt(["Jan 1 08:00 sshd: Failed password for root"], [], "08:00→08:05", "1 host")),
        ("ip_system_prompt()",       "system",  ip_system_prompt()),
        ("ip_user_prompt()",         "user",    ip_user_prompt("192.168.1.0/24", [], [])),
        ("correlator_system_prompt()","system", correlator_system_prompt()),
        ("correlator_user_prompt()", "user",    correlator_user_prompt({"email": {"verdict": "phishing", "risk_score": 0.9}}, ["C2_phishing"], 0.95, [], [], "phishing", "", "")),
    ]

    for name, ptype, result in checks:
        table.add_row(name, ptype, str(len(result)))

    console.print(table)
    console.print("\n[bold green]All 8 prompt functions OK.[/bold green]\n")