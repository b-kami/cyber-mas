# Cyber-MAS — Technical Documentation

> **Cyber-MAS** (Cybersecurity Multi-Agent System)
> A modular, AI-powered platform that uses multiple specialized agents to detect cybersecurity threats across three domains: **email phishing**, **system log intrusions**, and **network vulnerabilities**.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Project Structure](#3-project-structure)
4. [Configuration & Environment](#4-configuration--environment)
5. [Dependencies](#5-dependencies)
6. [Tools Layer — Detailed Breakdown](#6-tools-layer--detailed-breakdown)
   - 6.1 [llm_client.py](#61-llm_clientpy--llm-gateway)
   - 6.2 [prompts.py](#62-promptspy--prompt-templates)
   - 6.3 [nvd_client.py](#63-nvd_clientpy--vulnerability-database-client)
   - 6.4 [faiss_store.py](#64-faiss_storepy--vector-similarity-search)
7. [Agents Layer — Detailed Breakdown](#7-agents-layer--detailed-breakdown)
   - 7.1 [email_agent.py](#71-email_agentpy--email-verification-agent)
   - 7.2 [log_agent.py](#72-log_agentpy--log-analyzer-agent)
   - 7.3 [ip_agent.py](#73-ip_agentpy--ip-range-analyzer-agent)
   - 7.4 [correlator.py](#74-correlatorpy--cross-domain-correlator)
   - 7.5 [dispatcher.py](#75-dispatcherpy--task-dispatcher)
8. [Data Layer](#8-data-layer)
9. [How to Run & Test](#9-how-to-run--test)
10. [Current Progress Summary](#10-current-progress-summary)

---

## 1. Project Overview

### What is Cyber-MAS?

Cyber-MAS is a **Multi-Agent System (MAS)** designed for automated cybersecurity threat detection. Instead of relying on a single monolithic tool, the system delegates security tasks to **specialized AI agents**, each expert in a specific domain. A central **dispatcher** routes incoming tasks to the right agent, and a **correlator** cross-references findings across all agents to detect complex, multi-vector attacks.

### Core Concept: RAG + Chain-of-Thought

Each agent follows a **Retrieval-Augmented Generation (RAG)** pattern:

1. **Collect** raw data (email text, log files, Nmap scan results)
2. **Enrich** the data with external tools (DNS lookups, FAISS similarity, NVD CVE queries)
3. **Build** a structured prompt containing all evidence
4. **Send** the prompt to an LLM (LLaMA 3.3-70B via Groq) with chain-of-thought instructions
5. **Return** a structured JSON verdict

### Technology Stack

| Layer          | Technology                                          |
|----------------|-----------------------------------------------------|
| LLM            | LLaMA 3.3-70B via **Groq** cloud API                |
| Embeddings     | **Sentence-Transformers** (all-MiniLM-L6-v2)        |
| Vector Search  | **FAISS** (Facebook AI Similarity Search)            |
| Network Scan   | **python-nmap** (wrapper around Nmap)                |
| CVE Database   | **NIST NVD** REST API v2.0                           |
| DNS Validation | **dnspython**                                        |
| Sentiment      | **TextBlob**                                         |
| URL Parsing    | **tldextract**                                       |
| Data Handling  | **pandas**                                           |
| HTTP Client    | **requests**                                         |
| Config         | **python-dotenv**                                    |
| Validation     | **pydantic**                                         |
| CLI Output     | **rich** (tables, panels, colored terminal output)   |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER / CLI                              │
│                        (main.py)                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DISPATCHER                                  │
│                  (dispatcher.py)                                │
│         Routes tasks to the correct agent                       │
└───────┬──────────────┬──────────────┬───────────────────────────┘
        │              │              │
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ EMAIL AGENT  │ │  LOG AGENT   │ │   IP AGENT   │
│              │ │              │ │              │
│ • RegEx URLs │ │ • pandas     │ │ • Nmap scan  │
│ • DNS lookup │ │ • regex sigs │ │ • NVD CVEs   │
│ • TextBlob   │ │ • Suricata   │ │ • LLM assess │
│ • FAISS sim  │ │ • LLM reason │ │              │
│ • LLM verdict│ │              │ │              │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CORRELATOR                                  │
│                   (correlator.py)                               │
│    Cross-references findings from all 3 agents                  │
│    Detects multi-vector attack patterns                         │
│    Produces unified incident report                             │
└─────────────────────────────────────────────────────────────────┘
                        │
           Shared Tools │ (used by all agents)
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TOOLS LAYER                                │
│                                                                 │
│  llm_client.py   → Central Groq API wrapper                    │
│  prompts.py      → Chain-of-thought prompt templates            │
│  nvd_client.py   → NIST NVD CVE lookups                        │
│  faiss_store.py  → Vector similarity search                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Project Structure

```
cyber-mas/
│
├── .env                  # API keys (GROQ_API_KEY, NVD_API_KEY) — git-ignored
├── .env.example          # Template showing required environment variables
├── .gitignore            # Files excluded from version control
├── README.md             # Project overview (high-level)
├── DOCUMENTATION.md      # This file — detailed technical documentation
├── requirements.txt      # Python dependencies
├── main.py               # CLI entry point (not yet implemented)
│
├── agents/               # Specialized AI agents
│   ├── __init__.py       # Package marker
│   ├── email_agent.py    # Email phishing detection agent (stub)
│   ├── log_agent.py      # System/network log analyzer agent (stub)
│   ├── ip_agent.py       # IP range/vulnerability scanner agent (stub)
│   ├── correlator.py     # Cross-domain signal correlator (stub)
│   └── dispatcher.py     # Task router to specialized agents (stub)
│
├── tools/                # Shared utilities used by agents
│   ├── __init__.py       # Package marker
│   ├── llm_client.py     # ✅ DONE — Groq API wrapper (LLaMA 3.3-70B)
│   ├── prompts.py        # ✅ DONE — All chain-of-thought prompt templates
│   ├── nvd_client.py     # ✅ DONE — NVD REST API client for CVE lookups
│   └── faiss_store.py    # FAISS vector store for similarity search (stub)
│
├── data/                 # Data directories for agent inputs
│   ├── faiss_index/      # FAISS index files (auto-generated, git-ignored content)
│   ├── raw_emails/       # Sample email files for the email agent
│   └── sample_logs/      # Sample log files for the log agent
│
└── venv/                 # Python virtual environment (git-ignored)
```

### Legend

- **✅ DONE** — File is fully implemented and tested
- **stub** — File exists with a placeholder comment, logic not yet written

---

## 4. Configuration & Environment

### `.env` — Secret Configuration (git-ignored)

This file holds API keys. It is **never committed** to version control.

```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

| Variable       | Required? | Purpose                                                     |
|----------------|-----------|-------------------------------------------------------------|
| `GROQ_API_KEY` | **Yes**   | Authenticates with the Groq API to access LLaMA 3.3-70B    |
| `NVD_API_KEY`  | Optional  | Raises NVD rate limit from 5 to 50 requests per 30 seconds |

### `.env.example` — Template

Committed to Git so collaborators know which variables to set:

```env
GROQ_API_KEY=your_key_here
NVD_API_KEY=your_key_here
```

### `.gitignore`

Ensures sensitive and generated files are never pushed to GitHub:

```gitignore
.env              # API keys — NEVER commit
venv/             # Virtual environment
__pycache__/      # Python bytecode cache
*.pyc             # Compiled Python files
data/faiss_index/ # Generated FAISS index binaries
```

---

## 5. Dependencies

All dependencies are listed in `requirements.txt` and installed via:

```bash
pip install -r requirements.txt
```

| Package                | Version | Purpose in the Project                                                 |
|------------------------|---------|------------------------------------------------------------------------|
| `groq`                 | latest  | Python SDK for the Groq cloud API (hosts LLaMA 3.3-70B)               |
| `faiss-cpu`            | latest  | Facebook's vector similarity search library (CPU version)              |
| `sentence-transformers`| latest  | Generates text embeddings for FAISS (uses `all-MiniLM-L6-v2` model)   |
| `tldextract`           | latest  | Extracts domain/subdomain from URLs (e.g. `login.paypal.evil.com`)    |
| `dnspython`            | latest  | Performs DNS lookups (MX, A, TXT records) to validate sender domains   |
| `textblob`             | latest  | Sentiment analysis on email body text (detects urgency/manipulation)   |
| `pandas`               | latest  | Parses and manipulates log data in tabular format                      |
| `requests`             | latest  | HTTP client for calling the NVD REST API                               |
| `python-dotenv`        | latest  | Loads `.env` file into `os.environ` at startup                         |
| `pydantic`             | latest  | Data validation and structured output parsing (agent responses)        |
| `rich`                 | latest  | Beautiful terminal output — tables, panels, colors for self-tests      |
| `python-nmap`          | latest  | Python wrapper around the Nmap network scanner                         |

---

## 6. Tools Layer — Detailed Breakdown

The `tools/` package contains **shared utilities** that agents import. No agent talks to external APIs directly — everything goes through these centralized wrappers.

---

### 6.1 `llm_client.py` — LLM Gateway

**Status: ✅ Fully implemented and tested**

**Purpose:** Central wrapper around the Groq API. Every agent calls the `ask()` function — nothing else in the project communicates with Groq directly.

**Key Design Decisions:**

- **Singleton client**: The `Groq` client is created once (on first call) and reused across all subsequent calls via the `_get_client()` function. This avoids creating a new HTTP connection for every LLM request.
- **Low temperature (0.2)**: Security analysis needs deterministic, consistent outputs — not creative ones. A low temperature ensures the model follows instructions precisely.
- **Model**: `llama-3.3-70b-versatile` — a 70-billion parameter model that balances quality with speed.

**Public API:**

```python
def ask(
    system_prompt: str,    # Defines the LLM's role and output format
    user_prompt:   str,    # The actual data to analyse
    max_tokens:    int = 1024,
    temperature:   float = 0.2,
) -> str:
```

**How it works:**

1. Loads `GROQ_API_KEY` from `.env` via `python-dotenv`
2. Creates a `Groq` client (once, cached as a module-level variable)
3. Sends a `chat.completions.create()` call with a `system` + `user` message pair
4. Returns the raw text response from the LLM
5. Raises `EnvironmentError` if the API key is missing
6. Raises `RuntimeError` if the Groq API call fails

**Self-test:** Run `python tools/llm_client.py` — it sends a test prompt to Groq and prints the response in a styled panel.

**Constants:**

| Constant      | Value                      | Explanation                                    |
|---------------|----------------------------|------------------------------------------------|
| `MODEL`       | `llama-3.3-70b-versatile`  | The LLM model to use on Groq                   |
| `MAX_TOKENS`  | `1024`                     | Maximum response length from the LLM           |
| `TEMPERATURE` | `0.2`                      | Low = deterministic (good for security tasks)   |

---

### 6.2 `prompts.py` — Prompt Templates

**Status: ✅ Fully implemented and tested**

**Purpose:** Contains all chain-of-thought prompt templates for every agent. Each agent imports only the two functions it needs (a `system_prompt` and a `user_prompt`). This file **never calls the LLM** — it only builds formatted strings.

**Design Pattern: System + User prompt pairs**

Every agent uses exactly two prompts:
- **System prompt**: Tells the LLM *who it is*, *how to think* (step-by-step), and *what JSON format* to return.
- **User prompt**: Injects the actual data (email text, log lines, scan results) into a structured template.

**Prompt Functions:**

| Function                     | Agent         | Type   | Description                                                    |
|------------------------------|---------------|--------|----------------------------------------------------------------|
| `email_system_prompt()`      | Email Agent   | system | Defines 7-step reasoning for phishing detection                |
| `email_user_prompt()`        | Email Agent   | user   | Injects sender, body, URLs, DNS, sentiment, FAISS score        |
| `log_system_prompt()`        | Log Agent     | system | Defines 8-step reasoning for intrusion detection + MITRE ATT&CK|
| `log_user_prompt()`          | Log Agent     | user   | Injects log lines, Suricata alerts, time range, host summary   |
| `ip_system_prompt()`         | IP Agent      | system | Defines 6-step reasoning for vulnerability assessment          |
| `ip_user_prompt()`           | IP Agent      | user   | Injects Nmap scan results and NVD CVE matches                  |
| `correlator_system_prompt()` | Correlator    | system | Defines 6-step cross-domain correlation reasoning              |
| `correlator_user_prompt()`   | Correlator    | user   | Injects JSON reports from all 3 agents                         |

**Example: Email System Prompt (abbreviated)**

The LLM is instructed to think step-by-step:
1. Examine sender domain — is it spoofed?
2. Analyse subject line — urgency/fear tactics?
3. Review body — grammar issues, impersonation?
4. Inspect URLs — typosquatting, redirects?
5. Check sentiment — manipulative tone?
6. Consider FAISS score — similar to known phishing?
7. Combine into final verdict

Then respond ONLY in a strict JSON format:
```json
{
  "verdict": "SAFE | SUSPICIOUS | PHISHING",
  "confidence": 0.0,
  "risk_score": 0,
  "reasoning": "...",
  "indicators": ["..."],
  "recommendation": "..."
}
```

**Self-test:** Run `python tools/prompts.py` — it calls all 8 functions with test data and displays a table showing each prompt's character length.

---

### 6.3 `nvd_client.py` — Vulnerability Database Client

**Status: ✅ Fully implemented and tested**

**Purpose:** Queries the **NIST National Vulnerability Database (NVD)** REST API v2.0 to find known CVEs (Common Vulnerabilities and Exposures) for a given software/service name and version. Used exclusively by the IP range analyzer agent.

**Public API:**

```python
def fetch_cves(service_name: str, version: str = "") -> list[dict]:
    """Query NVD for CVEs matching a service, e.g. fetch_cves("openssh", "8.2")"""

def fetch_cves_for_hosts(scan_results: list[dict]) -> list[dict]:
    """Convenience wrapper — runs fetch_cves() for every service found in Nmap output"""
```

**How `fetch_cves()` works:**

1. Builds a keyword string like `"openssh 8.2"`
2. Waits 0.6 seconds (respects NVD rate limit: 5 requests / 30 seconds without API key)
3. Sends a GET request to `https://services.nvd.nist.gov/rest/json/cves/2.0`
4. Parses the JSON response, extracting for each CVE:
   - **CVE ID** (e.g. `CVE-2023-38408`)
   - **CVSS score** — tries v3.1, then v3.0, then v2.0 (highest available)
   - **Severity label** — CRITICAL (≥9.0), HIGH (≥7.0), MEDIUM (≥4.0), LOW (<4.0)
   - **English description**
   - **NVD detail URL**
5. Filters out low-severity CVEs (CVSS < 5.0)
6. Returns results sorted by CVSS score descending (most critical first)
7. Returns an empty list on any HTTP error (the agent continues gracefully)

**How `fetch_cves_for_hosts()` works:**

1. Iterates over every host in the Nmap scan results
2. For each service string (e.g. `"openssh 8.2"`), calls `fetch_cves()`
3. Deduplicates CVEs by ID across all hosts
4. Returns a combined, sorted list

**Internal Helper Functions:**

| Function               | Purpose                                                      |
|------------------------|--------------------------------------------------------------|
| `_get_headers()`       | Adds `apiKey` header if `NVD_API_KEY` is set in `.env`       |
| `_parse_cvss(item)`    | Extracts CVSS score, trying v3.1 → v3.0 → v2.0              |
| `_parse_description()` | Extracts the English-language description from a CVE record  |

**Constants:**

| Constant        | Value  | Explanation                                               |
|-----------------|--------|-----------------------------------------------------------|
| `NVD_BASE_URL`  | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD API endpoint |
| `MAX_RESULTS`   | `10`   | CVEs returned per service query                           |
| `CVSS_MIN`      | `5.0`  | Ignore CVEs with a CVSS score below this threshold        |
| `REQUEST_DELAY` | `0.6`  | Seconds between requests to respect NVD rate limits       |

**Self-test:** Run `python tools/nvd_client.py` — queries NVD for OpenSSH 8.2 CVEs and displays results in a styled table.

---

### 6.4 `faiss_store.py` — Vector Similarity Search

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** Provides a FAISS-based vector store that converts text (email bodies, phishing samples) into numerical embeddings using `sentence-transformers`, indexes them with FAISS, and allows the email agent to find the most similar known phishing sample for a given input email.

**Expected Workflow:**
1. Load known phishing email samples from `data/raw_emails/`
2. Encode them into 384-dimensional vectors using `all-MiniLM-L6-v2`
3. Build a FAISS index and save it to `data/faiss_index/`
4. At analysis time, encode the input email and search the index
5. Return the distance score and the closest matching sample text

---

## 7. Agents Layer — Detailed Breakdown

The `agents/` package contains the five specialized agents. Each agent file currently exists as a **stub** (placeholder comment only) — the logic will be implemented next.

---

### 7.1 `email_agent.py` — Email Verification Agent

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** Analyse an email to determine if it is **SAFE**, **SUSPICIOUS**, or **PHISHING**.

**Planned Pipeline:**
1. Parse raw email (sender, subject, body)
2. Extract URLs using regex
3. Validate sender domain via DNS (MX, A, TXT records with `dnspython`)
4. Analyse domain components with `tldextract` (detect typosquatting)
5. Run sentiment analysis on body text with `TextBlob`
6. Search FAISS index for similar known phishing samples
7. Build the prompt using `email_system_prompt()` + `email_user_prompt()`
8. Send to LLM via `llm_client.ask()`
9. Parse and return the JSON verdict

**Tools it will use:** `llm_client`, `prompts`, `faiss_store`, `tldextract`, `dnspython`, `textblob`

---

### 7.2 `log_agent.py` — Log Analyzer Agent

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** Analyse system/network log entries to detect **intrusions, brute-force attacks, lateral movement, and anomalies**.

**Planned Pipeline:**
1. Load log files from `data/sample_logs/`
2. Normalize and parse log entries with `pandas`
3. Apply regex-based signature detection (failed logins, sudo, SSH, cron)
4. Optionally match against Suricata alert signatures
5. Identify time range and unique hosts
6. Build the prompt using `log_system_prompt()` + `log_user_prompt()`
7. Send to LLM via `llm_client.ask()`
8. Parse and return the JSON verdict (includes MITRE ATT&CK tactic)

**Tools it will use:** `llm_client`, `prompts`, `pandas`, regex

---

### 7.3 `ip_agent.py` — IP Range Analyzer Agent

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** Scan an IP range for open ports, identify running services, and cross-reference them with known CVEs from the NVD.

**Planned Pipeline:**
1. Accept a CIDR range (e.g. `192.168.1.0/24`)
2. Run an Nmap scan using `python-nmap` to find open ports and service versions
3. For each discovered service, query NVD via `nvd_client.fetch_cves_for_hosts()`
4. Build the prompt using `ip_system_prompt()` + `ip_user_prompt()`
5. Send to LLM via `llm_client.ask()`
6. Parse and return the JSON verdict (includes CVE highlights and critical host)

**Tools it will use:** `llm_client`, `prompts`, `nvd_client`, `python-nmap`

---

### 7.4 `correlator.py` — Cross-Domain Correlator

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** A "meta-agent" that receives the structured JSON reports from all three agents and looks for **cross-domain attack patterns** — indicators that suggest a coordinated, multi-vector attack.

**Planned Pipeline:**
1. Receive the JSON output from email_agent, log_agent, and ip_agent
2. Build the prompt using `correlator_system_prompt()` + `correlator_user_prompt()`
3. Send to LLM via `llm_client.ask()`
4. The LLM identifies shared entities (IPs, domains), temporal correlations, and likely attack chains
5. Return a unified threat assessment with an overall risk score

**Example correlation:** If a phishing email contains a URL pointing to `10.0.0.5`, and the log agent detected brute-force SSH from `10.0.0.5`, and the IP agent found that `10.0.0.5` has a critical CVE — the correlator identifies this as a coordinated **phishing → credential theft → exploitation** chain.

**Tools it will use:** `llm_client`, `prompts`

---

### 7.5 `dispatcher.py` — Task Dispatcher

**Status: 🔲 Stub (not yet implemented)**

**Planned Purpose:** The central routing agent that receives user tasks from `main.py` and delegates them to the appropriate specialized agent(s).

**Planned Behaviour:**
- `"analyse this email"` → routes to `email_agent`
- `"check these logs"` → routes to `log_agent`
- `"scan 192.168.1.0/24"` → routes to `ip_agent`
- `"full analysis"` → runs all three agents, then passes results to the `correlator`

---

## 8. Data Layer

The `data/` directory contains subdirectories for input data used by the agents:

```
data/
├── faiss_index/      # FAISS index binary files (auto-generated)
│   └── .gitkeep      # Keeps empty directory in Git
├── raw_emails/       # Sample email files (.eml or .txt) for email agent
│   └── .gitkeep
└── sample_logs/      # Sample log files (syslog, auth.log) for log agent
    └── .gitkeep
```

- **`faiss_index/`**: Will contain the serialized FAISS index after `faiss_store.py` builds it from known phishing samples. This directory is git-ignored (the index is regenerated).
- **`raw_emails/`**: Place `.eml` or `.txt` email files here for the email agent to analyse. Will also hold known phishing samples for building the FAISS index.
- **`sample_logs/`**: Place syslog, auth.log, or similar log files here for the log agent to parse.

---

## 9. How to Run & Test

### Initial Setup

```bash
# 1. Clone the repository
git clone https://github.com/b-kami/cyber-mas.git
cd cyber-mas

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
# On Windows:
.\venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Create your .env file from the template
cp .env.example .env
# Then edit .env and add your actual API keys
```

### Testing Individual Components

Each implemented tool has a built-in self-test when run directly:

```bash
# Test LLM connection (requires valid GROQ_API_KEY in .env)
python tools/llm_client.py

# Test all prompt templates (no API key needed)
python tools/prompts.py

# Test NVD client (queries live NVD API — takes ~2 seconds)
python tools/nvd_client.py
```

### Verify All Dependencies

```bash
python -c "
import groq, faiss, sentence_transformers
import tldextract, dns.resolver, textblob
import pandas, nmap, requests
import dotenv, pydantic, rich
print('All dependencies OK')
"
```

---

## 10. Current Progress Summary

| Component              | File                   | Status              | Description                                  |
|------------------------|------------------------|---------------------|----------------------------------------------|
| **LLM Client**         | `tools/llm_client.py`  | ✅ Done & Tested     | Groq API wrapper, singleton client, `ask()`  |
| **Prompt Templates**   | `tools/prompts.py`     | ✅ Done & Tested     | 8 prompt functions (4 agents × 2 prompts)    |
| **NVD Client**         | `tools/nvd_client.py`  | ✅ Done & Tested     | CVE lookup, CVSS parsing, rate-limit aware   |
| **FAISS Store**        | `tools/faiss_store.py` | 🔲 Stub             | Vector similarity search                     |
| **Email Agent**        | `agents/email_agent.py`| 🔲 Stub             | Phishing detection pipeline                  |
| **Log Agent**          | `agents/log_agent.py`  | 🔲 Stub             | Log intrusion detection pipeline             |
| **IP Agent**           | `agents/ip_agent.py`   | 🔲 Stub             | Network vulnerability scanner pipeline       |
| **Correlator**         | `agents/correlator.py` | 🔲 Stub             | Cross-domain attack pattern detection        |
| **Dispatcher**         | `agents/dispatcher.py` | 🔲 Stub             | Task routing to specialized agents           |
| **CLI Entry Point**    | `main.py`              | 🔲 Stub             | User-facing command-line interface           |
| **Environment**        | `.env` / `.env.example`| ✅ Done              | API key configuration                        |
| **Dependencies**       | `requirements.txt`     | ✅ Done              | All 12 packages listed and installable       |
| **Git Config**         | `.gitignore`           | ✅ Done              | Secrets and generated files excluded         |

### What's Done (Tools Layer)

The entire shared tools layer is built:
- **LLM communication** is working end-to-end with Groq
- **Prompt engineering** is complete for all 4 agents with chain-of-thought reasoning
- **CVE vulnerability lookups** are working against the live NVD API

### What's Next (Agents Layer)

The agent implementations (the actual business logic) are the next step:
1. Implement `faiss_store.py` (FAISS vector index)
2. Implement `email_agent.py` (phishing detection)
3. Implement `log_agent.py` (log analysis)
4. Implement `ip_agent.py` (network scanning)
5. Implement `correlator.py` (cross-domain correlation)
6. Implement `dispatcher.py` (task routing)
7. Implement `main.py` (CLI interface)

---

*Last updated: April 16, 2026*
