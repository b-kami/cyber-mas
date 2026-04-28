# 🛡️ Cyber-MAS — Multi-Agent Cybersecurity Threat Detection System

A modular, multi-agent system for automated cybersecurity threat detection and analysis. Built with pure Python, powered by **Groq LLaMA 3.3-70B**, with **MITRE ATT&CK mapping**, **persistent threat memory (Qdrant)**, and a real-time **SOC dashboard**.

> **Status: 🟢 Fully implemented** — All agents, the correlator, MITRE ATT&CK integration, Qdrant memory, Threat Intelligence, Notifications, PDF Reports, Continuous Monitoring, CLI, and the web dashboard are complete.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER / CLIENT                           │
│           main.py (CLI)  ·  dashboard/api.py (Web UI)           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DISPATCHER                                │
│                   (agents/dispatcher.py)                         │
│          Auto-detects payload type & routes to agent             │
└──────┬──────────────────┬──────────────────┬────────────────────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ EMAIL AGENT  │   │  LOG AGENT   │   │   IP AGENT   │
│              │   │              │   │              │
│ • DNS/MX     │   │ • Pandas     │   │ • Nmap scan  │
│ • FAISS RAG  │   │ • Regex sigs │   │ • NVD CVEs   │
│ • TextBlob   │   │ • Suricata   │   │ • OS detect  │
│ • LLM assess │   │ • LLM reason │   │ • LLM assess │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                       CORRELATOR                                │
│                   (agents/correlator.py)                         │
│                                                                 │
│  1. Fires 6 cross-agent correlation rules                       │
│  2. Queries Qdrant for historical similar threats               │
│  3. Maps all findings to MITRE ATT&CK techniques               │
│  4. Computes unified risk score (weighted + boosts)             │
│  5. Sends enriched prompt to LLM for final assessment           │
│  6. Stores results in Qdrant for future sessions                │
└─────────────────────────────────────────────────────────────────┘
                          │
             Shared Tools │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        TOOLS LAYER                              │
│                                                                 │
│  llm_client.py    → Groq API wrapper (LLaMA 3.3-70B)           │
│  prompts.py       → Chain-of-thought prompt templates           │
│  faiss_store.py   → FAISS vector search (email RAG)             │
│  qdrant_store.py  → Persistent threat memory (cross-session)    │
│  mitre_mapper.py  → MITRE ATT&CK technique mapping engine      │
│  nvd_client.py    → NIST NVD CVE lookups                       │
│  threat_intel.py  → AbuseIPDB, VirusTotal, and Shodan lookups   │
│  notifier.py      → Email notification system with PDFs         │
│  report_generator.py → PDF Threat Report generation             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Agents

| Agent | Purpose | Key Tools |
|-------|---------|-----------|
| **Dispatcher** | Auto-detects payload type (email/log/IP) and routes to the correct agent | Rule-based routing, regex detection |
| **Email Agent** | Detects phishing, spoofing, and social engineering in emails | FAISS RAG, DNS (MX/SPF), TextBlob, tldextract, LLM |
| **Log Agent** | Identifies intrusions, brute-force, and anomalies in system/network logs | Pandas, regex signatures, Suricata, LLM |
| **IP Agent** | Scans IP ranges for open ports, services, and known vulnerabilities | python-nmap, NVD CVE API, LLM |
| **Correlator** | Cross-references all agent outputs, detects multi-vector attacks, produces a unified threat assessment | 6 correlation rules, Qdrant memory, MITRE ATT&CK mapper, LLM synthesis |

## 🔧 Shared Tools

| Module | Description |
|--------|-------------|
| `llm_client.py` | Central Groq API wrapper — single `ask()` function for all LLM calls |
| `prompts.py` | Chain-of-thought prompt templates for all 4 agents (system + user prompts) |
| `faiss_store.py` | FAISS vector store for semantic email similarity search (RAG) |
| `qdrant_store.py` | Qdrant vector database for persistent cross-session threat memory |
| `mitre_mapper.py` | Maps signatures, verdicts, CVEs, ports, and indicators to MITRE ATT&CK techniques |
| `nvd_client.py` | NIST NVD REST API v2.0 client for CVE vulnerability lookups |
| `threat_intel.py` | Enriches IPs with reputation data from AbuseIPDB, VirusTotal, and Shodan |
| `notifier.py` | Email notification system that sends threat alerts with attached PDF reports |
| `report_generator.py` | PDF Threat Report generator powered by ReportLab |

---

## 📁 Project Structure

```
cyber-mas/
├── main.py                  # CLI entry point — runs agents + correlator
├── monitor.py               # Continuous Monitoring Engine (tails logs, IMAP, recurring Nmap)
├── requirements.txt         # Python dependencies (16 packages)
├── .env.example             # API key template
├── .gitignore               # Secrets & generated files excluded
├── README.md                # This file
├── DOCUMENTATION.md         # Comprehensive technical documentation
│
├── dashboard/               # Web UI (SOC Dashboard)
│   ├── api.py               # FastAPI backend with SSE streaming
│   └── static/
│       └── index.html       # Real-time SOC dashboard (HTML/CSS/JS)
│
├── agents/                  # Specialized AI agents
│   ├── __init__.py
│   ├── dispatcher.py        # Task router with auto-detection
│   ├── email_agent.py       # Email phishing detection
│   ├── log_agent.py         # Log anomaly & intrusion detection
│   ├── ip_agent.py          # IP/CVE vulnerability scanning
│   └── correlator.py        # Cross-agent threat correlation
│
├── tools/                   # Shared utilities
│   ├── __init__.py
│   ├── llm_client.py        # Groq API wrapper
│   ├── prompts.py           # All prompt templates
│   ├── faiss_store.py       # FAISS vector store
│   ├── qdrant_store.py      # Qdrant persistent memory
│   ├── mitre_mapper.py      # MITRE ATT&CK mapping engine
│   ├── nvd_client.py        # NVD CVE API client
│   ├── threat_intel.py      # AbuseIPDB, VirusTotal, Shodan client
│   ├── notifier.py          # Email notification system
│   └── report_generator.py  # PDF report generator
│
└── data/
    ├── raw_emails/           # SpamAssassin corpus (spam + ham)
    ├── faiss_index/          # Auto-generated FAISS index files
    └── sample_logs/          # Sample log files for analysis
```

---

## 🚀 Quick Start

### 1. Clone & setup

```bash
git clone https://github.com/b-kami/cyber-mas.git
cd cyber-mas
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
```

Edit `.env`:

```env
GROQ_API_KEY=gsk_...        # Required — https://console.groq.com
NVD_API_KEY=xxxxxxxx...     # Optional — https://nvd.nist.gov/developers/request-an-api-key
```

### 3. Download the SpamAssassin corpus (for Email Agent RAG)

```bash
cd data/raw_emails/
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2
tar -xjf 20030228_easy_ham.tar.bz2
cd ../..
```

### 4. Build the FAISS index (one-time)

```bash
python main.py --build-index
```

### 5. Verify setup

```bash
python main.py --check        # Environment health check
python tools/llm_client.py    # Test Groq LLM connection
```

### 6. Run analyses

```bash
# Full pipeline — all 3 agents + correlator
python main.py --email path/to/email.eml --log path/to/auth.log --ip 192.168.1.1

# Single-agent runs
python main.py --email suspicious.eml
python main.py --log syslog.txt
python main.py --ip scanme.nmap.org

# Inline text (no files needed)
python main.py --email-text "From: evil@hacker.com\nSubject: Urgent action required!"
python main.py --ip-text "203.0.113.42"

# Save JSON report
python main.py --email email.eml --log auth.log --output report.json

# Raw JSON output (for piping)
python main.py --email email.eml --json

# Skip correlator
python main.py --email email.eml --no-correlate
```

### 7. Continuous Monitoring

```bash
# Watch a log file for new lines
python main.py --watch-log /var/log/auth.log

# Poll an IMAP inbox for new emails
python main.py --watch-email-imap

# Run recurring Nmap scans against an IP
python main.py --watch-ip 192.168.1.1

# Watch all configured sources simultaneously
python main.py --watch-all --watch-log /var/log/auth.log --watch-ip 10.0.0.5
```

### 8. Run the Web Dashboard

```bash
uvicorn dashboard.api:app --reload --port 8000
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## 🗺️ MITRE ATT&CK Integration

The system automatically maps all detected threats to the **MITRE ATT&CK** framework:

- **35+ techniques** across **12 tactics** in the mapping catalogue
- **8 mapping sources**: signatures, verdicts, indicators, CVE IDs, open ports, email metadata, correlation rules, and free-text reasoning
- **Confidence scoring**: each mapping carries a confidence level (0.0–1.0) based on the source
- **Attack chain reconstruction**: tactics are ordered by the ATT&CK kill chain to show the attack lifecycle
- **LLM-enhanced**: technique context is injected into the correlator's LLM prompt for better recommendations

The dashboard displays MITRE techniques for each agent result and the correlator's unified attack chain.

---

## 🧠 Persistent Threat Memory (Qdrant)

The system maintains cross-session memory using **Qdrant** vector database:

- Every analysis result is encoded (sentence-transformers) and stored as a vector with structured metadata
- Before making its final assessment, the correlator queries Qdrant for historically similar threats
- Historical matches are injected into the LLM prompt (so the model can consider past attack patterns)
- Strong historical matches with high-risk verdicts provide a small confidence boost to the unified risk score
- **Zero-config**: runs in-process with local storage by default (`qdrant_local/`), or connects to a Docker/remote instance via `QDRANT_URL`

---

## 🔗 Correlation Rules

The correlator fires 6 cross-agent rules to detect multi-vector attacks:

| Rule | Name | Trigger Condition |
|------|------|-------------------|
| C1 | `shared_ip` | Same IP appears in both log sources and IP agent target |
| C2 | `phishing_and_breach` | Email verdict = phishing AND log verdict = malicious |
| C3 | `vuln_and_exploit` | IP has known CVEs AND log shows exploitation patterns |
| C4 | `multi_vector` | All active agents report risk_score > 0.6 |
| C5 | `c2_beacon_and_ip` | Log hits `malware_c2` signature AND IP agent ran |
| C6 | `recon_pattern` | `port_scan` in log AND IP agent found ≥5 open ports |

Each fired rule boosts the unified risk score by `+0.08`.

---

## 🛡️ Threat Intelligence

The system automatically enriches extracted IP addresses using real-time threat intelligence:

- **AbuseIPDB**: Community-reported abuse scores and categories
- **VirusTotal**: Malicious engine detections and community tags
- **Shodan**: Exposed services, tags, and known vulnerabilities

Strong findings increase the unified risk score, recommend immediate blocking, and inject additional MITRE ATT&CK techniques (e.g. T1078, T1071).

---

## 🔔 Notifications & PDF Reports

When a threat exceeds a configured severity threshold, the system:

1. Generates a comprehensive **PDF Threat Report** using ReportLab.
2. Sends an **HTML Email Notification** with the PDF attached via SMTP.
3. Logs the alert to `alerts.jsonl` for SIEM ingestion.

---

## 🔑 API Keys

| Key | Source | Required |
|-----|--------|----------|
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) | ✅ Yes |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | Optional (raises rate limit from 5→50 req/30s) |
| `QDRANT_URL` | Your Qdrant instance | Optional (defaults to local in-process storage) |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com/account/api) | Optional |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Optional |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Optional |
| `IMAP_*` | IMAP Mailbox (e.g. `IMAP_USER`, `IMAP_PASS`) | Optional (for email monitoring) |
| `NOTIFY_*` | SMTP Server (e.g. `NOTIFY_SMTP_USER`, `NOTIFY_SMTP_PASS`) | Optional (for notifications) |

---

## ✅ Implementation Status

| Component | File | Status |
|-----------|------|--------|
| LLM Client | `tools/llm_client.py` | ✅ Done |
| Prompt Templates | `tools/prompts.py` | ✅ Done |
| NVD CVE Client | `tools/nvd_client.py` | ✅ Done |
| FAISS Vector Store | `tools/faiss_store.py` | ✅ Done |
| Qdrant Threat Memory | `tools/qdrant_store.py` | ✅ Done |
| MITRE ATT&CK Mapper | `tools/mitre_mapper.py` | ✅ Done |
| Threat Intelligence | `tools/threat_intel.py` | ✅ Done |
| Email Notifier | `tools/notifier.py` | ✅ Done |
| PDF Report Gen | `tools/report_generator.py` | ✅ Done |
| Dispatcher | `agents/dispatcher.py` | ✅ Done |
| Email Agent | `agents/email_agent.py` | ✅ Done |
| Log Agent | `agents/log_agent.py` | ✅ Done |
| IP Agent | `agents/ip_agent.py` | ✅ Done |
| Correlator | `agents/correlator.py` | ✅ Done |
| Monitor Engine | `monitor.py` | ✅ Done |
| CLI Entry Point | `main.py` | ✅ Done |
| Web Dashboard API | `dashboard/api.py` | ✅ Done |
| Web Dashboard UI | `dashboard/static/index.html` | ✅ Done |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **LLM** | LLaMA 3.3-70B via **Groq** cloud API |
| **Embeddings** | **Sentence-Transformers** (all-MiniLM-L6-v2, 384-dim) |
| **Vector Search (RAG)** | **FAISS** (CPU, IndexFlatL2) |
| **Threat Memory** | **Qdrant** (persistent vector database) |
| **Threat Framework** | **MITRE ATT&CK** (35+ techniques, 12 tactics) |
| **Network Scanning** | **python-nmap** (Nmap wrapper) |
| **CVE Database** | **NIST NVD** REST API v2.0 |
| **DNS Validation** | **dnspython** (MX, A, TXT records) |
| **NLP / Sentiment** | **TextBlob** |
| **URL Parsing** | **tldextract** |
| **Data Processing** | **Pandas** |
| **HTTP Client** | **requests** |
| **Config** | **python-dotenv** |
| **Validation** | **Pydantic** |
| **CLI Output** | **Rich** (tables, panels, progress bars) |
| **PDF Generation** | **ReportLab** |
| **Email Monitoring** | Python **imaplib** |
| **Web Backend** | **FastAPI** + **Uvicorn** |
| **Web Frontend** | **HTML/CSS/JS** with Server-Sent Events (SSE) |

---

## 📝 License

This project is developed as part of a **PFE** (Projet de Fin d'Études).

---

## 👤 Author

**b-kami** — [github.com/b-kami](https://github.com/b-kami)

---

*Last updated: April 28, 2026 — v6 (Threat Intel, Notifications, PDF Reports, Continuous Monitoring)*