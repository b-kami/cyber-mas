# 🛡️ Cyber MAS — Multi-Agent Cybersecurity System

A modular, multi-agent system for automated cybersecurity threat detection and analysis. Built with pure Python, powered by **Groq LLaMA 3.3-70B**, and designed for real-world security workflows.

> **Status: 🟢 Fully implemented** — All agents, the correlator, and the CLI are complete.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                     main.py (CLI)                    │
│                         │                            │
│                   ┌─────▼─────┐                      │
│                   │ Dispatcher │                      │
│                   └─────┬─────┘                      │
│           ┌─────────────┼─────────────┐              │
│     ┌─────▼─────┐ ┌─────▼─────┐ ┌────▼──────┐       │
│     │   Email   │ │    Log    │ │    IP     │       │
│     │   Agent   │ │   Agent   │ │   Agent   │       │
│     └─────┬─────┘ └─────┬─────┘ └────┬──────┘       │
│           └─────────────┼─────────────┘              │
│                   ┌─────▼──────┐                     │
│                   │ Correlator │                      │
│                   └────────────┘                     │
└─────────────────────────────────────────────────────┘
```

### Agents

| Agent | Purpose | Tools Used |
|-------|---------|------------|
| **Dispatcher** | Routes incoming tasks to the appropriate specialist agent | Rule-based routing |
| **Email Agent** | Analyzes emails for phishing, spoofing, and social engineering | FAISS vector search, RegEx, DNS (MX/SPF), RAG + LLM |
| **Log Agent** | Parses and analyzes system/network logs for anomalies | Pandas, regex signatures, LLM chain-of-thought |
| **IP Agent** | Scans IP ranges and identifies vulnerabilities | python-nmap, NVD API (CVE lookup), LLM |
| **Correlator** | Cross-analyzes all agent outputs, fires 6 correlation rules, computes unified risk | LLM synthesis, weighted scoring |

### Shared Tools

| Module | Description |
|--------|-------------|
| `llm_client.py` | Groq API wrapper (LLaMA 3.3-70B) — single entry point for all LLM calls |
| `faiss_store.py` | FAISS vector store for semantic similarity search |
| `nvd_client.py` | NVD REST API client for CVE vulnerability lookups |
| `prompts.py` | Centralized prompt templates for all agents |

---

## 📁 Project Structure

```
cyber-mas/
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
├── .env.example             # API key template
├── .gitignore
├── README.md
│
├── agents/
│   ├── __init__.py
│   ├── dispatcher.py        # Task routing logic
│   ├── email_agent.py       # Email threat analysis
│   ├── log_agent.py         # Log anomaly detection
│   ├── ip_agent.py          # IP/CVE vulnerability scanning
│   └── correlator.py        # Cross-agent threat correlation
│
├── tools/
│   ├── __init__.py
│   ├── llm_client.py        # Groq API wrapper
│   ├── faiss_store.py       # FAISS vector store
│   ├── nvd_client.py        # NVD CVE API client
│   └── prompts.py           # Shared prompt templates
│
└── data/
    ├── raw_emails/           # Raw email samples (.eml, .txt)
    ├── faiss_index/          # Persisted FAISS index files
    └── sample_logs/          # Sample log files for analysis
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/b-kami/cyber-mas.git
cd cyber-mas
```

### 2. Create a virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```env
GROQ_API_KEY=gsk_...        # https://console.groq.com
NVD_API_KEY=xxxxxxxx...     # https://nvd.nist.gov/developers/request-an-api-key
```

### 5. Download the SpamAssassin Corpus (for Email Agent)

```bash
cd data/raw_emails/
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
curl -LO https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2
tar -xjf 20030228_spam.tar.bz2
tar -xjf 20030228_easy_ham.tar.bz2
cd ../..
```

### 6. Verify the LLM connection

```bash
python tools/llm_client.py
```

### 7. Build the FAISS index (one-time)

Required for the Email Agent's RAG similarity search:

```bash
python main.py --build-index
```

### 8. Run the system

```bash
# Full pipeline — email + log + IP + correlator
python main.py --email path/to/email.eml --log path/to/auth.log --ip 192.168.1.1

# Single-agent runs
python main.py --email suspicious.eml
python main.py --log syslog.txt
python main.py --ip scanme.nmap.org

# Inline text (no files needed)
python main.py --email-text "From: evil@hacker.com\nSubject: Urgent action required!"
python main.py --ip-text "203.0.113.42"

# Save full JSON report
python main.py --email email.eml --log auth.log --output report.json

# Environment health check
python main.py --check
```

---

## 🔑 API Keys

| Key | Source | Required |
|-----|--------|----------|
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) | ✅ Yes |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | ✅ Yes (for IP Agent CVE lookups) |

---

## ✅ Implementation Status

| Component | Status |
|-----------|--------|
| LLM Client (`tools/llm_client.py`) | ✅ Done |
| Prompt Templates (`tools/prompts.py`) | ✅ Done |
| NVD CVE Client (`tools/nvd_client.py`) | ✅ Done |
| FAISS Vector Store (`tools/faiss_store.py`) | ✅ Done |
| Dispatcher (`agents/dispatcher.py`) | ✅ Done |
| Email Agent (`agents/email_agent.py`) | ✅ Done |
| Log Agent (`agents/log_agent.py`) | ✅ Done |
| IP Agent (`agents/ip_agent.py`) | ✅ Done |
| Correlator (`agents/correlator.py`) | ✅ Done |
| CLI Entry Point (`main.py`) | ✅ Done |

---

## 🛠️ Tech Stack

- **Language:** Python 3.10+
- **LLM Provider:** Groq (LLaMA 3.3-70B Versatile)
- **Vector Search:** FAISS (CPU)
- **Embeddings:** Sentence-Transformers
- **DNS Analysis:** dnspython
- **NLP:** TextBlob
- **Data Processing:** Pandas
- **CLI Output:** Rich
- **Validation:** Pydantic
- **Network Scanning:** python-nmap
- **CVE Database:** NVD REST API

---

## 📝 License

This project is developed as part of a PFE (Projet de Fin d'Études).

---

## 👤 Author

**b-kami** — [github.com/b-kami](https://github.com/b-kami)