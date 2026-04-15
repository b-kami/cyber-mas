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
    sender: str,
    subject: str,
    body: str,
    urls: list[str],
    dns_results: dict,
    sentiment: str,
    faiss_score: float,
    similar_sample: str,
) -> str:
    """
    User prompt for the email agent — injects all extracted signals.

    Parameters
    ----------
    sender        : raw From header value
    subject       : email subject line
    body          : plain text body (truncated to 1000 chars)
    urls          : list of URLs found in the email
    dns_results   : dict of domain → DNS lookup result
    sentiment     : TextBlob polarity label (positive/negative/neutral)
    faiss_score   : similarity distance to nearest known phishing sample (lower = more similar)
    similar_sample: excerpt from the closest FAISS match
    """
    urls_str = "\n".join(f"  - {u}" for u in urls) if urls else "  None found"
    dns_str  = "\n".join(f"  {k}: {v}" for k, v in dns_results.items()) if dns_results else "  No DNS data"

    return f"""Analyse the following email and return your verdict in the required JSON format.

── SENDER ─────────────────────────────────────────────────────
{sender}

── SUBJECT ────────────────────────────────────────────────────
{subject}

── BODY (first 1000 chars) ────────────────────────────────────
{body[:1000]}

── URLs FOUND ─────────────────────────────────────────────────
{urls_str}

── DNS VALIDATION ─────────────────────────────────────────────
{dns_str}

── SENTIMENT ANALYSIS ─────────────────────────────────────────
Detected sentiment: {sentiment}

── VECTOR SIMILARITY (FAISS) ──────────────────────────────────
Distance to nearest known phishing sample: {faiss_score:.4f}
(0.0 = identical match, >1.0 = very different)
Closest known sample excerpt: "{similar_sample[:200]}"

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
    log_lines: list[str],
    suricata_alerts: list[str],
    time_range: str,
    host_summary: str,
) -> str:
    """
    User prompt for the log agent — injects normalized log data.

    Parameters
    ----------
    log_lines       : list of normalized log entry strings (max 80 lines)
    suricata_alerts : list of Suricata signature matches (can be empty)
    time_range      : human-readable time window e.g. "2024-01-15 08:00 → 08:45"
    host_summary    : brief summary of unique IPs/hosts seen
    """
    logs_str     = "\n".join(log_lines[:80])
    suricata_str = "\n".join(f"  [ALERT] {a}" for a in suricata_alerts) if suricata_alerts else "  No Suricata alerts triggered"

    return f"""Analyse the following log sequence and return your verdict in the required JSON format.

── TIME RANGE ──────────────────────────────────────────────────
{time_range}

── HOST SUMMARY ────────────────────────────────────────────────
{host_summary}

── SURICATA SIGNATURE ALERTS ───────────────────────────────────
{suricata_str}

── LOG ENTRIES ─────────────────────────────────────────────────
{logs_str}

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
    ip_range: str,
    scan_results: list[dict],
    cve_data: list[dict],
) -> str:
    """
    User prompt for the IP agent — injects Nmap + NVD results.

    Parameters
    ----------
    ip_range     : the CIDR range scanned e.g. "192.168.1.0/24"
    scan_results : list of dicts — one per host with keys:
                   ip, hostname, open_ports, services
    cve_data     : list of dicts — one per CVE with keys:
                   cve_id, cvss_score, description, affected_service
    """
    hosts_str = ""
    for host in scan_results:
        hosts_str += f"\n  Host: {host.get('ip')} ({host.get('hostname', 'unknown')})\n"
        for port_info in host.get("open_ports", []):
            hosts_str += f"    Port {port_info}\n"

    cves_str = ""
    for cve in cve_data[:20]:  # cap at 20 CVEs
        cves_str += (
            f"\n  {cve.get('cve_id')} | CVSS: {cve.get('cvss_score')} | "
            f"{cve.get('affected_service')} | {cve.get('description', '')[:120]}"
        )

    if not cves_str:
        cves_str = "\n  No CVEs found for detected service versions"

    return f"""Analyse the following network scan results and return your verdict in the required JSON format.

── IP RANGE SCANNED ────────────────────────────────────────────
{ip_range}

── HOSTS AND OPEN PORTS ────────────────────────────────────────
{hosts_str if hosts_str else "  No active hosts found"}

── CVEs MATCHED FROM NVD ───────────────────────────────────────
{cves_str}

Now apply your chain-of-thought reasoning and return the JSON verdict."""


# ══════════════════════════════════════════════════════════════
# CORRELATOR PROMPTS
# ══════════════════════════════════════════════════════════════

def correlator_system_prompt() -> str:
    """
    System prompt for the contextual recommendation system.
    """
    return """You are a senior threat intelligence analyst responsible for correlating signals from multiple security domains.

You will receive structured reports from three specialized agents:
- Email verification agent (phishing / spoofing detection)
- Log analyzer agent (intrusion / anomaly detection)
- IP range analyzer agent (network exposure / CVE assessment)

Your task is to identify cross-domain attack patterns — indicators that appear across multiple reports suggesting a coordinated or multi-vector attack.

Think step by step:
1. Extract all IP addresses, domains, and timestamps from each report.
2. Find entities that appear in more than one report (e.g. same IP in email and logs).
3. Check for temporal correlation — did the email arrive shortly before the log anomaly?
4. Identify the likely attack scenario (e.g. phishing → credential theft → lateral movement).
5. Assign an overall threat level considering all three domains together.
6. Produce a unified incident narrative and prioritised response.

Respond ONLY in this exact JSON format:
{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "overall_risk_score": 0 to 100,
  "correlated_entities": ["shared IPs, domains, or patterns found across reports"],
  "attack_scenario": "Likely attack chain description",
  "incident_narrative": "Human-readable summary for the analyst",
  "evidence": {
    "email": "key finding from email agent",
    "logs":  "key finding from log agent",
    "ip":    "key finding from IP agent"
  },
  "response_actions": ["prioritised list of recommended actions"]
}"""


def correlator_user_prompt(
    email_report: dict,
    log_report:   dict,
    ip_report:    dict,
) -> str:
    """
    User prompt for the correlator — injects all three agent reports.

    Parameters
    ----------
    email_report : dict output from email_agent
    log_report   : dict output from log_agent
    ip_report    : dict output from ip_agent
    """
    import json

    def fmt(report: dict) -> str:
        return json.dumps(report, indent=2)

    return f"""Correlate the three agent reports below and return your unified threat assessment.

── EMAIL VERIFICATION REPORT ───────────────────────────────────
{fmt(email_report)}

── LOG ANALYZER REPORT ─────────────────────────────────────────
{fmt(log_report)}

── IP RANGE ANALYZER REPORT ────────────────────────────────────
{fmt(ip_report)}

Now identify cross-domain patterns and return the JSON verdict."""


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
        ("email_user_prompt()",      "user",    email_user_prompt("test@evil.com", "Urgent!", "Click here", ["http://evil.com"], {}, "negative", 0.12, "Verify your account")),
        ("log_system_prompt()",      "system",  log_system_prompt()),
        ("log_user_prompt()",        "user",    log_user_prompt(["Jan 1 08:00 sshd: Failed password for root"], [], "08:00→08:05", "1 host")),
        ("ip_system_prompt()",       "system",  ip_system_prompt()),
        ("ip_user_prompt()",         "user",    ip_user_prompt("192.168.1.0/24", [], [])),
        ("correlator_system_prompt()","system", correlator_system_prompt()),
        ("correlator_user_prompt()", "user",    correlator_user_prompt({"verdict":"PHISHING"}, {"verdict":"MALICIOUS"}, {"verdict":"HIGH_RISK"})),
    ]

    for name, ptype, result in checks:
        table.add_row(name, ptype, str(len(result)))

    console.print(table)
    console.print("\n[bold green]All 8 prompt functions OK.[/bold green]\n")