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
   - 6.5 [qdrant_store.py](#65-qdrant_storepy--persistent-threat-memory)
7. [Agents Layer — Detailed Breakdown](#7-agents-layer--detailed-breakdown)
   - 7.1 [email_agent.py](#71-email_agentpy--email-verification-agent)
   - 7.2 [log_agent.py](#72-log_agentpy--log-analyzer-agent)
   - 7.3 [ip_agent.py](#73-ip_agentpy--ip-range-analyzer-agent)
   - 7.4 [correlator.py](#74-correlatorpy--cross-domain-correlator)
   - 7.5 [dispatcher.py](#75-dispatcherpy--task-dispatcher)
   - 7.6 [main.py](#76-mainpy--cli-entry-point)
   - 7.7 [dashboard/api.py](#77-dashboardapipy--web-ui-backend)
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
| Vector Search  | **FAISS** (In-Memory Similarity Search)             |
| Threat Memory  | **Qdrant** (Persistent Vector Database)             |
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
| Web UI Backend | **FastAPI**, **uvicorn**                             |
| Frontend       | **HTML/CSS/JS** with Server-Sent Events (SSE)        |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER / CLI                              │
│            (main.py / Web Dashboard via FastAPI)                │
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
│  qdrant_store.py → Persistent threat memory                     │
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
├── main.py               # ✅ DONE — Rich CLI entry point (all agents + correlator)
│
├── dashboard/            # Web UI Backend & Frontend
│   ├── api.py            # ✅ DONE — FastAPI server providing SSE stream
│   └── static/
│       └── index.html    # ✅ DONE — SOC Dashboard UI (HTML/CSS/JS)
│
├── agents/               # Specialized AI agents
│   ├── __init__.py       # Package marker
│   ├── email_agent.py    # ✅ DONE — Email phishing detection agent
│   ├── log_agent.py      # ✅ DONE — System/network log analyzer agent
│   ├── ip_agent.py       # ✅ DONE — IP range/vulnerability scanner agent
│   ├── correlator.py     # ✅ DONE — Cross-domain signal correlator
│   └── dispatcher.py     # ✅ DONE — Task router with auto-detection logic
│
├── tools/                # Shared utilities used by agents
│   ├── __init__.py       # Package marker
│   ├── llm_client.py     # ✅ DONE — Groq API wrapper (LLaMA 3.3-70B)
│   ├── prompts.py        # ✅ DONE — All chain-of-thought prompt templates
│   ├── nvd_client.py     # ✅ DONE — NVD REST API client for CVE lookups
│   ├── faiss_store.py    # ✅ DONE — FAISS vector store for similarity search
│   └── qdrant_store.py   # ✅ DONE — Qdrant vector database for threat memory
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
| `fastapi`              | latest  | Web framework for the dashboard API                                    |
| `uvicorn[standard]`    | latest  | ASGI server to run the FastAPI application                             |
| `python-multipart`     | latest  | Support for form data parsing in FastAPI                               |

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

**Status: ✅ Fully implemented and tested**

**Purpose:** Provides a FAISS-based vector store that converts email text into 384-dimensional numerical embeddings using `sentence-transformers` (all-MiniLM-L6-v2), indexes them with FAISS, and allows the email agent to find the most similar known phishing sample for a given input email.

**Public API:**

```python
def build_index(emails_dir, index_dir, force=False) -> None:
    """One-time setup: load corpus, encode, save .index + meta.json"""

def query(email_text: str, k: int = 1) -> list[dict]:
    """Find the k nearest neighbours in the FAISS index"""

def is_index_ready() -> bool:
    """Return True if the FAISS index files exist on disk"""
```

**How `build_index()` works:**

1. Recursively walks `data/raw_emails/` and loads every email file
2. Parses RFC-2822 email format using Python's `email` module (handles multipart, charset detection)
3. Labels each email as `spam` or `ham` based on parent directory name
4. Encodes all text into 384-dimensional vectors using `all-MiniLM-L6-v2` (batched, normalized)
5. Builds a `faiss.IndexFlatL2` index (exact L2 search — good enough for <10k documents)
6. Saves the index to `data/faiss_index/emails.index`
7. Saves metadata (label, excerpt, source file) to `data/faiss_index/meta.json`

**How `query()` works:**

1. Lazily loads the FAISS index, metadata, and sentence-transformer model (singletons)
2. Encodes the input email text into a 384-dim vector
3. Searches the FAISS index for the `k` nearest neighbours
4. Returns a list of dicts with: `distance`, `similarity` (normalized 0–1), `label`, `excerpt`, `source_file`

**Corpus: SpamAssassin Public Dataset**

The project uses the [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) which has been downloaded and extracted into:
- `data/raw_emails/spam/` — ~500 spam email samples
- `data/raw_emails/easy_ham/` — ~2500 legitimate (ham) email samples

**Index Files (auto-generated):**

| File                              | Description                                   |
|-----------------------------------|-----------------------------------------------|
| `data/faiss_index/emails.index`   | FAISS IndexFlatL2 binary                      |
| `data/faiss_index/meta.json`      | Array of {label, excerpt, source_file} objects |

**Internal Helper Functions:**

| Function              | Purpose                                                           |
|-----------------------|-------------------------------------------------------------------|
| `_label_from_path()`  | Infers spam/ham label from parent directory name                  |
| `_parse_email_text()` | Extracts plain-text body from RFC-2822 email bytes                |
| `_load_corpus()`      | Recursively loads all email files under a directory               |
| `_ensure_loaded()`    | Lazily loads index + model singletons on first query              |

**Constants:**

| Constant        | Value              | Explanation                                  |
|-----------------|--------------------|----------------------------------------------|
| `MODEL_NAME`    | `all-MiniLM-L6-v2` | 22M param sentence-transformer, 384-dim      |
| `EXCERPT_CHARS` | `400`              | Characters stored in metadata for context    |
| `BATCH_SIZE`    | `64`               | Encoding batch size (tune down if OOM)       |
| `MAX_EMAILS`    | `10,000`           | Safety cap on corpus size                    |

**Self-test:** Run `python tools/faiss_store.py --build` to build the index, then `python tools/faiss_store.py --query "You have won a prize!"` to test a query.

---

### 6.5 `qdrant_store.py` — Persistent Threat Memory

**Status: ✅ Fully implemented and tested**

**Purpose:** Provides persistent, cross-session memory by storing every completed analysis report as a vector in Qdrant. The Correlator queries this store to surface historically similar threats before making its final holistic assessment.

**Public API:**

```python
def store_result(report_id: str, result: dict) -> bool:
    """Encode and store an agent result in Qdrant."""

def query_memory(free_text: str = None, k: int = 3) -> list[MemoryMatch]:
    """Search Qdrant for historically similar threats."""

def store_report(report_id: str, agent_results: list[dict], correlator_result: dict) -> None:
    """Convenience function to store all results from a full pipeline run."""
```

**How it works:**
1. Text Serialization: Converts structured analysis data (verdict, indicators, risk, reasoning) into a rich descriptive text block.
2. Vectorization: Uses `sentence-transformers` (`all-MiniLM-L6-v2`, identical to FAISS) to generate a 384-dimensional vector.
3. Storage: Upserts the vector alongside structured metadata (payload) into the `threat_memory` collection.
4. Auto-setup: Uses `qdrant-client[local]` by default to persist data in the `qdrant_local/` folder, requiring no Docker or separate server (though compatible via `QDRANT_URL`).

---

## 7. Agents Layer — Detailed Breakdown

The `agents/` package contains the five specialized agents. Each agent file currently exists as a **stub** (placeholder comment only) — the logic will be implemented next.

---

### 7.1 `email_agent.py` — Email Verification Agent

**Status: ✅ Fully implemented and tested**

**Purpose:** Analyse an email to determine if it is **phishing**, **spam**, or **legitimate**.

**Pipeline:**
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

**Status: ✅ Fully implemented and tested**

**Purpose:** Analyse system/network log entries to detect **intrusions, brute-force attacks, lateral movement, and anomalies**.

**Pipeline:**
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

**Status: ✅ Fully implemented and tested**

**Purpose:** Scan an IP range for open ports, identify running services, and cross-reference them with known CVEs from the NVD.

**Pipeline:**
1. Accept a CIDR range or IP address
2. Run an Nmap scan using `python-nmap` to find open ports, service versions, and OS guess
3. For each discovered service, query NVD via `nvd_client.fetch_cves_for_hosts()`
4. Build the prompt using `ip_system_prompt()` + `ip_user_prompt()`
5. Send to LLM via `llm_client.ask()`
6. Parse and return the JSON verdict (includes CVE highlights, risky ports, and vulnerability status)

**Tools it uses:** `llm_client`, `prompts`, `nvd_client`, `python-nmap`

---

### 7.4 `correlator.py` — Cross-Domain Correlator

**Status: ✅ Fully implemented and tested**

**Purpose:** A "meta-agent" that receives the structured JSON reports from all three agents and looks for **cross-domain attack patterns** — indicators that suggest a coordinated, multi-vector attack.

**Correlation Rules:**
| Rule | Description |
|------|-------------|
| `C1 shared_ip` | Same IP appears in log AND ip agent results |
| `C2 phishing_and_breach` | Email verdict = phishing AND log verdict = malicious |
| `C3 vuln_and_exploit` | IP has open CVEs AND log shows exploitation patterns |
| `C4 multi_vector` | All 3 agents return `risk_score > 0.6` |
| `C5 c2_beacon_and_ip` | Log hits `malware_c2` signature AND ip agent ran |
| `C6 recon_pattern` | `port_scan` in log signatures AND ip agent found many ports |

**Unified Risk Score:** Weighted average of agent scores + `+0.08` boost per correlation rule fired (capped at 1.0)

**Pipeline:**
1. Receive JSON output from one or more agents (email, log, ip)
2. Compute weighted base risk score
3. Apply 6 correlation rules and boost score for each match
4. Query Qdrant (`qdrant_store.query_memory`) for historically similar threats and boost score if matches are found.
5. Derive verdict from final score (critical/high/medium/low)
6. Build prompt using `correlator_system_prompt()` + `correlator_user_prompt()` (injecting memory context)
7. Send to LLM via `llm_client.ask()` for holistic assessment
8. Store the final report into Qdrant (`qdrant_store.store_report`)
9. Return unified result with correlations, memory matches, recommendations, and agent summary

**Tools it uses:** `llm_client`, `prompts`, `qdrant_store`

---

### 7.6 `main.py` — CLI Entry Point

**Status: ✅ Fully implemented and tested**

**Purpose:** The user-facing command-line interface that orchestrates all agents and presents rich, formatted output.

**Key Features:**
- Accepts file paths (`--email`, `--log`, `--ip`) or inline text (`--email-text`, `--log-text`, `--ip-text`)
- Runs any combination of agents in a single command
- Automatically passes results to the correlator (disable with `--no-correlate`)
- Saves full JSON report with `--output report.json`
- Minimal mode with `--quiet`
- Built-in environment health check with `--check`
- FAISS index builder with `--build-index`
- Rich terminal output with colored panels, risk bars, and tables (falls back gracefully if `rich` unavailable)

**Example commands:**
```bash
# Full pipeline — all three agents + correlator
python main.py --email email.eml --log auth.log --ip 192.168.1.1

# Single-agent runs
python main.py --email suspicious.eml
python main.py --log syslog.txt
python main.py --ip scanme.nmap.org

# Inline text (no files needed)
python main.py --email-text "From: evil@hacker.com\nSubject: Urgent!"
python main.py --ip-text "203.0.113.42"

# Save report to JSON
python main.py --email email.eml --output report.json

# Environment health check
python main.py --check

# Build FAISS index
python main.py --build-index
```

---

### 7.7 `dashboard/api.py` — Web UI Backend

**Status: ✅ Fully implemented and tested**

**Purpose:** A FastAPI backend that serves a real-time, industrial "SOC (Security Operations Center)" dashboard. It streams agent execution progress back to the browser using Server-Sent Events (SSE).

**Key Features:**
- Runs the `dispatcher` asynchronously in a thread pool so the event loop remains unblocked.
- Streams real-time `start`, `result`, and `complete` events to the frontend via `/api/analyse`.
- Automatically maps detected threats (from signatures, verdicts, and indicators) to **MITRE ATT&CK** tactics and techniques (e.g., T1110 Brute Force, T1566 Phishing).
- Maintains an in-memory history of the last 50 analysis reports.
- Serves the frontend from `/static/index.html`.

**Frontend (`dashboard/static/index.html`):**
- A pure HTML/CSS/JS single-page application.
- Uses `EventSource` to receive the SSE stream from the FastAPI backend.
- Features a dark "industrial SOC" aesthetic with scanlines, dynamic progress bars, a live log monitor, and detailed MITRE ATT&CK mappings.

**How to run:**
```bash
uvicorn dashboard.api:app --reload --port 8000
```
Then visit `http://localhost:8000` in your browser.

---

### 7.5 `dispatcher.py` — Task Dispatcher

**Status: ✅ Fully implemented and tested**

**Purpose:** The central routing agent that receives user tasks from `main.py` and delegates them to the appropriate specialized agent. It never calls the LLM itself — it is pure routing logic with intelligent auto-detection.

**Public API:**

```python
def dispatch(task: dict) -> dict:
    """
    Route a task to the appropriate specialist agent.
    task must contain "payload". Optionally contains "type" to skip detection.
    """
```

**Input Schema:**

```json
{
    "type":    "email" | "log" | "ip",
    "payload": "<string | dict | list>"
}
```

If `"type"` is omitted, the dispatcher **auto-detects** the payload type using the following priority:

1. **Structured dict/list** with keys like `host`, `ip`, `port` → `"ip"`
2. **Short string** that is a valid IP address or CIDR block → `"ip"`
3. **String with RFC-2822 headers** (From:, Subject:, Received:) → `"email"`
4. **String with log-line patterns** (timestamps, log levels, syslog format) → `"log"`
5. **Fallback** → `"email"` (the LLM will handle ambiguous input)

**How it works:**

1. Validates that `task` contains a `"payload"` key
2. If `"type"` is provided, uses it directly; otherwise runs `_detect_type()` auto-detection
3. Lazily imports the correct agent module from the agent registry
4. Calls the agent's `analyse(payload)` function
5. Stamps `agent` and `task_type` fields onto the result dict
6. Returns the agent's full result

**Agent Registry:**

| Type      | Module                          |
|-----------|----------------------------------|
| `email`   | `cyber_mas.agents.email_agent`   |
| `log`     | `cyber_mas.agents.log_agent`     |
| `ip`      | `cyber_mas.agents.ip_agent`      |

**Internal Detection Functions:**

| Function              | Purpose                                                    |
|-----------------------|------------------------------------------------------------|
| `_detect_type()`      | Infers payload type from structure, regex patterns, and content |
| `_is_valid_ip_or_host()` | Validates IPs, CIDR blocks, and hostnames using `ipaddress` + regex |
| `_route()`            | Lazily imports and calls the correct agent module            |

**Self-test:** Run `python agents/dispatcher.py` — it tests auto-detection on 4 sample payloads (explicit email, auto-detect IP, auto-detect logs, auto-detect email) without calling any LLM.

---

## 8. Data Layer

The `data/` directory contains subdirectories for agent inputs:

```
data/
├── faiss_index/      # FAISS index files (auto-generated, git-ignored content)
│   └── .gitkeep      # Keeps empty directory in Git
├── raw_emails/       # ✅ SpamAssassin public corpus downloaded
│   ├── spam/         # ~500 spam email samples
│   ├── easy_ham/     # ~2500 legitimate (ham) email samples
│   └── .gitkeep
└── sample_logs/      # Sample log files (syslog, auth.log) for log agent
    └── .gitkeep
```

- **`faiss_index/`**: Contains the serialized FAISS index after `faiss_store.py` builds it from the email corpus. This directory is git-ignored (the index is regenerated by running `python tools/faiss_store.py --build`).
- **`raw_emails/`**: Contains the **SpamAssassin public corpus** — ~500 spam emails in `spam/` and ~2500 legitimate emails in `easy_ham/`. Downloaded from [spamassassin.apache.org](https://spamassassin.apache.org/old/publiccorpus/). Also contains the original `.tar.bz2` archives.
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

# 6. Download the SpamAssassin public corpus
cd data/raw_emails/
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2
tar -xjf 20030228_easy_ham.tar.bz2
cd ../..
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
| **FAISS Store**        | `tools/faiss_store.py` | ✅ Done & Tested     | Vector index: build from corpus + query API  |
| **Qdrant Store**       | `tools/qdrant_store.py`| ✅ Done & Tested     | Persistent threat memory vector database     |
| **Dispatcher**         | `agents/dispatcher.py` | ✅ Done & Tested     | Auto-detect payload type + route to agent    |
| **Email Corpus**       | `data/raw_emails/`     | ✅ Downloaded        | SpamAssassin corpus (~3000 emails)           |
| **Email Agent**        | `agents/email_agent.py`| ✅ Done & Tested     | Phishing detection pipeline                  |
| **Log Agent**          | `agents/log_agent.py`  | ✅ Done & Tested     | Log anomaly & intrusion detection pipeline   |
| **IP Agent**           | `agents/ip_agent.py`   | ✅ Done & Tested     | Network vulnerability scanner pipeline       |
| **Correlator**         | `agents/correlator.py` | ✅ Done & Tested     | Cross-domain attack pattern detection + unified risk |
| **CLI Entry Point**    | `main.py`              | ✅ Done & Tested     | Rich CLI: all agents, correlator, JSON output |
| **Web Dashboard API**  | `dashboard/api.py`     | ✅ Done & Tested     | FastAPI backend with SSE streaming and MITRE ATT&CK |
| **Web Dashboard UI**   | `static/index.html`    | ✅ Done & Tested     | Real-time visual SOC interface |
| **Environment**        | `.env` / `.env.example`| ✅ Done              | API key configuration                        |
| **Dependencies**       | `requirements.txt`     | ✅ Done              | All 12 packages listed and installable       |
| **Git Config**         | `.gitignore`           | ✅ Done              | Secrets and generated files excluded         |

### What's Done

The **entire system is now fully implemented** end-to-end:
- **LLM communication** is working with Groq (LLaMA 3.3-70B)
- **Prompt engineering** is complete for all 4 agents with chain-of-thought reasoning
- **CVE vulnerability lookups** are working against the live NVD API
- **FAISS vector store** is implemented — corpus loading, embedding, indexing, and querying
- **SpamAssassin email corpus** has been downloaded (~500 spam + ~2500 ham samples)
- **Dispatcher** auto-detects payload types (email/log/IP) and routes to the correct agent
- **Email Agent** is fully implemented with DNS, FAISS RAG, and NLP sentiment analysis
- **Log Agent** is fully implemented with pandas log parsing and regex threat signatures
- **IP Agent** is fully implemented with Nmap port/service scanning and NVD CVE enrichment
- **Correlator** is fully implemented with 6 correlation rules and weighted risk scoring
- **main.py CLI** is fully implemented with Rich output, JSON export, and all agent orchestration
- **Web Dashboard** is fully implemented with FastAPI, SSE real-time streaming, MITRE mapping, and a visual UI

### Remaining Steps

1. **Build the FAISS index** (one-time setup): `python main.py --build-index`
2. **Run the full pipeline (CLI)**: `python main.py --email email.eml --log auth.log --ip 192.168.1.1`
3. **Run the Web Dashboard**: `uvicorn dashboard.api:app --reload --port 8000`

---

*Last updated: April 22, 2026 — v4 (Dashboard UI added)*
