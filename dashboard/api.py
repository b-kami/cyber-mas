"""
dashboard/api.py
══════════════════════════════════════════════════════════════════════════════
Cyber-MAS  —  FastAPI backend for the SOC Dashboard.

ENDPOINTS
─────────
  GET  /                          → serves index.html
  GET  /static/*                  → static assets
  POST /api/analyse               → run full pipeline, stream SSE events
  GET  /api/status                → environment health check
  GET  /api/history               → last N completed reports
  POST /api/analyse/email         → email agent only
  POST /api/analyse/log           → log agent only
  POST /api/analyse/ip            → ip agent only

SSE EVENT STREAM  (POST /api/analyse)
──────────────────────────────────────
  data: {"event": "start",      "agent": "email"}
  data: {"event": "result",     "agent": "email",     "data": {...}}
  data: {"event": "start",      "agent": "log"}
  data: {"event": "result",     "agent": "log",       "data": {...}}
  data: {"event": "start",      "agent": "ip"}
  data: {"event": "result",     "agent": "ip",        "data": {...}}
  data: {"event": "correlating"}
  data: {"event": "complete",   "data": {...}}          ← full report
  data: {"event": "error",      "message": "..."}

RUN
───
  cd cyber-mas
  uvicorn dashboard.api:app --reload --port 8000
  # then open http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

log = logging.getLogger("cyber_mas.api")

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Cyber-MAS SOC Dashboard",
    description="Multi-Agent Cybersecurity Threat Detection API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files from dashboard/static/
_STATIC_DIR = Path(__file__).parent / "static"
_STATIC_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# In-memory report history (last 50 reports)
_history: deque[dict] = deque(maxlen=50)

# MITRE ATT&CK mapping
_MITRE_MAP = {
    "brute_force":          {"id": "T1110",  "name": "Brute Force",                      "tactic": "Credential Access"},
    "port_scan":            {"id": "T1046",  "name": "Network Service Discovery",         "tactic": "Discovery"},
    "privilege_escalation": {"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "lateral_movement":     {"id": "T1021",  "name": "Remote Services",                   "tactic": "Lateral Movement"},
    "data_exfiltration":    {"id": "T1041",  "name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration"},
    "web_attack":           {"id": "T1190",  "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "malware_c2":           {"id": "T1071",  "name": "Application Layer Protocol",        "tactic": "Command & Control"},
    "phishing":             {"id": "T1566",  "name": "Phishing",                          "tactic": "Initial Access"},
    "domain_spoofing":      {"id": "T1566.001","name":"Spearphishing Attachment",         "tactic": "Initial Access"},
    "suspicious_url":       {"id": "T1566.002","name":"Spearphishing Link",              "tactic": "Initial Access"},
}


# ══════════════════════════════════════════════════════════════════════════════
# Request / Response models
# ══════════════════════════════════════════════════════════════════════════════

class AnalyseRequest(BaseModel):
    email_text:  str | None = None
    log_text:    str | None = None
    ip_target:   str | None = None

class SingleAgentRequest(BaseModel):
    payload: str


# ══════════════════════════════════════════════════════════════════════════════
# SSE helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sse(event_dict: dict) -> str:
    """Format a dict as an SSE data line."""
    return f"data: {json.dumps(event_dict, default=str)}\n\n"


def _enrich_with_mitre(result: dict) -> dict:
    """
    Add real MITRE ATT&CK technique mappings to an agent result
    using the mitre_mapper module.
    """
    try:
        from tools.mitre_mapper import map_result
        techniques = map_result(result)
        result["mitre_techniques"] = [t.to_dict() for t in techniques]
    except Exception as exc:
        log.warning("MITRE mapping failed: %s", exc)
        result["mitre_techniques"] = []
    return result



async def _run_agent_async(task: dict) -> dict:
    """Run a dispatcher task in a thread pool (agents are synchronous)."""
    loop = asyncio.get_event_loop()

    def _sync():
        from agents.dispatcher import dispatch
        return dispatch(task)

    return await loop.run_in_executor(None, _sync)


async def _run_correlator_async(agent_results: list[dict]) -> dict:
    loop = asyncio.get_event_loop()

    def _sync():
        from agents.correlator import correlate
        return correlate(agent_results)

    return await loop.run_in_executor(None, _sync)


async def _notify_async(report: dict) -> None:
    """Send email notification in background — does not block SSE stream."""
    loop = asyncio.get_event_loop()
    try:
        def _sync():
            from tools.notifier import notify
            notify(report)
        await loop.run_in_executor(None, _sync)
    except Exception as exc:
        log.warning("Background notification failed: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the dashboard HTML."""
    index = _STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    raise HTTPException(404, "index.html not found in dashboard/static/")


@app.get("/api/status")
async def status():
    """Environment health check."""
    import shutil
    from tools.faiss_store import is_index_ready

    checks = {
        "groq_api_key":  bool(os.getenv("GROQ_API_KEY")),
        "nvd_api_key":   bool(os.getenv("NVD_API_KEY")),
        "nmap_binary":   bool(shutil.which("nmap")),
        "faiss_index":   is_index_ready(),
        "history_count": len(_history),
    }
    checks["ready"] = checks["groq_api_key"]
    return checks


@app.get("/api/history")
async def history(limit: int = 10):
    """Return last N completed analysis reports."""
    items = list(_history)[-limit:]
    return {"reports": list(reversed(items)), "total": len(_history)}


@app.post("/api/analyse")
async def analyse(req: AnalyseRequest):
    """
    Run the full pipeline and stream results as Server-Sent Events.
    The client connects with EventSource and receives agent results one by one.
    """
    if not req.email_text and not req.log_text and not req.ip_target:
        raise HTTPException(400, "Provide at least one of: email_text, log_text, ip_target")

    async def _stream() -> AsyncGenerator[str, None]:
        report_id    = str(uuid.uuid4())[:8]
        agent_results: list[dict] = []
        t_start      = time.perf_counter()

        yield _sse({"event": "init", "report_id": report_id,
                    "agents": [
                        a for a, v in [
                            ("email", req.email_text),
                            ("log",   req.log_text),
                            ("ip",    req.ip_target),
                        ] if v
                    ]})

        # ── Run each agent ────────────────────────────────────────────────────
        tasks = []
        if req.email_text:
            tasks.append(("email", {"type": "email", "payload": req.email_text}))
        if req.log_text:
            tasks.append(("log",   {"type": "log",   "payload": req.log_text}))
        if req.ip_target:
            tasks.append(("ip",    {"type": "ip",    "payload": req.ip_target}))

        for agent_name, task in tasks:
            yield _sse({"event": "start", "agent": agent_name})
            t0 = time.perf_counter()

            try:
                result = await _run_agent_async(task)
                result = _enrich_with_mitre(result)
                result["_duration_secs"] = round(time.perf_counter() - t0, 2)
                agent_results.append(result)
                yield _sse({"event": "result", "agent": agent_name, "data": result})

            except Exception as exc:
                log.error("Agent %s failed: %s", agent_name, exc)
                err_result = {
                    "agent": agent_name, "verdict": "uncertain",
                    "risk_score": 0.0, "confidence": 0.0,
                    "reasoning": str(exc), "indicators": [],
                    "mitre_techniques": [], "_duration_secs": 0.0,
                }
                agent_results.append(err_result)
                yield _sse({"event": "result", "agent": agent_name, "data": err_result})

        # ── Correlate ─────────────────────────────────────────────────────────
        yield _sse({"event": "correlating"})
        try:
            corr = await _run_correlator_async(agent_results)
            corr["_duration_secs"] = round(time.perf_counter() - t_start, 2)
        except Exception as exc:
            log.error("Correlator failed: %s", exc)
            corr = {
                "agent": "correlator", "verdict": "uncertain",
                "unified_risk": 0.0, "confidence": 0.0,
                "reasoning": str(exc), "correlations": [],
                "recommendations": [], "agent_summary": {},
                "indicators": [], "unified_indicators": [],
            }

        # ── Build full report ─────────────────────────────────────────────────
        report = {
            "report_id":   report_id,
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration":    round(time.perf_counter() - t_start, 2),
            "agents":      agent_results,
            "correlator":  corr,
        }
        _history.append(report)

        yield _sse({"event": "complete", "data": report})

        # Fire-and-forget notification (don't block the SSE stream)
        asyncio.create_task(_notify_async(report))

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.post("/api/analyse/email")
async def analyse_email(req: SingleAgentRequest):
    result = await _run_agent_async({"type": "email", "payload": req.payload})
    return _enrich_with_mitre(result)


@app.post("/api/analyse/log")
async def analyse_log(req: SingleAgentRequest):
    result = await _run_agent_async({"type": "log", "payload": req.payload})
    return _enrich_with_mitre(result)


@app.post("/api/analyse/ip")
async def analyse_ip(req: SingleAgentRequest):
    result = await _run_agent_async({"type": "ip", "payload": req.payload})
    return _enrich_with_mitre(result)