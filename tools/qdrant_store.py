"""
cyber_mas/tools/qdrant_store.py
══════════════════════════════════════════════════════════════════════════════
Persistent Threat Memory Store — powered by Qdrant.

ROLE
────
  Every completed analysis is encoded and stored as a vector in Qdrant.
  Before calling the LLM, the correlator queries this store to surface
  historically similar threats — giving the system cross-session memory.

ARCHITECTURE
────────────
  Runtime flow:
    analysis result dict
          │
          ▼
    _build_memory_text()    — serialize result into a descriptive text blob
          │
          ▼
    SentenceTransformer     — encode to 384-dim vector (same model as FAISS)
          │
          ▼
    Qdrant collection       — upsert(vector + payload)

  Query flow:
    incoming analysis context
          │
          ▼
    _build_query_text()     — serialize query context to text
          │
          ▼
    SentenceTransformer     — encode to vector
          │
          ▼
    Qdrant.search()         — top-k nearest neighbours
          │
          ▼
    list[MemoryMatch]       — structured matches with similarity scores

QDRANT SETUP (Codespace)
────────────────────────
  Option A — Docker (recommended):
    docker run -p 6333:6333 -v $(pwd)/qdrant_data:/qdrant/storage qdrant/qdrant

  Option B — In-process (no Docker, dev only):
    pip install qdrant-client[local]
    → uses QdrantClient(path="./qdrant_local") — persists to disk automatically

  This module auto-detects which mode to use:
    • QDRANT_URL env var set  → remote/Docker mode
    • Otherwise              → in-process local mode (zero-config)

COLLECTION SCHEMA
─────────────────
  Collection : "threat_memory"
  Vector dim : 384  (all-MiniLM-L6-v2, normalised)
  Distance   : Cosine

  Payload fields stored per point:
    report_id     : str
    timestamp     : str   (ISO 8601)
    agent_type    : str   ("email" | "log" | "ip" | "correlator")
    verdict       : str
    risk_score    : float
    confidence    : float
    indicators    : list[str]
    signatures    : list[str]   (log agent)
    target        : str         (ip agent)
    subject       : str         (email agent)
    sender        : str         (email agent)
    correlations  : list[str]   (correlator)
    summary_text  : str         (the text that was encoded)

USAGE
─────
  from cyber_mas.tools.qdrant_store import store_result, query_memory

  # Store a completed analysis
  store_result(report_id="abc123", result=agent_result_dict)

  # Query for similar past threats
  matches = query_memory(context_text="SSH brute force root 203.0.113.42", k=3)
  for m in matches:
      print(m.similarity, m.verdict, m.summary_text)

  # CLI smoke-test
  python cyber_mas/tools/qdrant_store.py
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ── Model (shared with faiss_store — same encoder, consistent vector space) ───
MODEL_NAME = "all-MiniLM-L6-v2"
VECTOR_DIM = 384
COLLECTION  = "threat_memory"

# ── Similarity threshold below which matches are considered too weak ──────────
MIN_SIMILARITY = 0.55

# ── Lazy singletons ──────────────────────────────────────────────────────────
_client = None
_model  = None


# ══════════════════════════════════════════════════════════════════════════════
# Client initialisation
# ══════════════════════════════════════════════════════════════════════════════

def _get_client():
    """
    Return a QdrantClient instance.

    Priority:
      1. QDRANT_URL env var → connect to remote/Docker instance
      2. Local in-process mode → data persisted to ./qdrant_local/
    """
    global _client
    if _client is not None:
        return _client

    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams

    qdrant_url = os.getenv("QDRANT_URL", "").strip()

    if qdrant_url:
        api_key = os.getenv("QDRANT_API_KEY", None)
        log.info("Qdrant: connecting to remote instance at %s", qdrant_url)
        _client = QdrantClient(url=qdrant_url, api_key=api_key)
    else:
        local_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "qdrant_local"
        )
        log.info("Qdrant: using local in-process storage at %s", local_path)
        _client = QdrantClient(path=local_path)

    # Ensure collection exists
    existing = [c.name for c in _client.get_collections().collections]
    if COLLECTION not in existing:
        log.info("Qdrant: creating collection '%s' (dim=%d, cosine)", COLLECTION, VECTOR_DIM)
        _client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
    else:
        count = _client.count(COLLECTION).count
        log.info("Qdrant: collection '%s' ready — %d points", COLLECTION, count)

    return _client


def _get_model():
    """Return the SentenceTransformer model (loaded once)."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        log.info("Qdrant: loading sentence-transformer '%s' …", MODEL_NAME)
        _model = SentenceTransformer(MODEL_NAME)
    return _model


# ══════════════════════════════════════════════════════════════════════════════
# Text serialisation — turns a result dict into a descriptive string
# ══════════════════════════════════════════════════════════════════════════════

def _build_memory_text(result: dict) -> str:
    """
    Serialize an agent result into a rich descriptive text for encoding.

    The text is designed to surface semantically when queried with similar
    threat descriptions — it packs in all high-signal fields.
    """
    parts = []
    agent   = result.get("agent", "unknown")
    verdict = result.get("verdict", "unknown")
    risk    = result.get("risk_score", result.get("unified_risk", 0.0))

    parts.append(f"Agent: {agent}. Verdict: {verdict}. Risk: {risk:.2f}.")

    # Indicators
    inds = result.get("indicators", [])
    if inds:
        parts.append(f"Indicators: {', '.join(str(i) for i in inds)}.")

    # Log-specific
    sigs = result.get("signatures_hit", [])
    if sigs:
        parts.append(f"Threat signatures: {', '.join(sigs)}.")

    stats = result.get("stats", {})
    if stats:
        parts.append(
            f"Log stats: {stats.get('total_lines',0)} lines, "
            f"{stats.get('unique_ips',0)} unique IPs, "
            f"top sources: {', '.join(str(s) for s in stats.get('top_sources',[]))}."
        )

    # Email-specific
    meta = result.get("email_metadata", {})
    if meta:
        parts.append(
            f"Email subject: {meta.get('subject','')}. "
            f"Sender: {meta.get('sender','')}. "
            f"Reply-To: {meta.get('reply_to','')}. "
            f"Links: {meta.get('link_count',0)}."
        )
    rag = result.get("rag_match", {})
    if rag and rag.get("label"):
        parts.append(f"Similar known email: {rag['label']} (similarity {rag.get('similarity',0):.2f}).")

    # IP-specific
    target = result.get("target", "")
    if target:
        parts.append(f"Target IP/host: {target}.")

    ports = result.get("open_ports", [])
    if ports:
        port_strs = [f"{p['port']}/{p.get('service','?')}" for p in ports[:8]]
        parts.append(f"Open ports: {', '.join(port_strs)}.")

    cves = result.get("cves", [])
    if cves:
        cve_strs = [f"{c['cve_id']} CVSS={c['cvss_score']}" for c in cves[:5]]
        parts.append(f"CVEs: {', '.join(cve_strs)}.")

    # Correlator-specific
    corrs = result.get("correlations", [])
    if corrs:
        parts.append(f"Correlation rules fired: {', '.join(corrs)}.")

    recs = result.get("recommendations", [])
    if recs:
        parts.append(f"Recommendations: {'; '.join(recs[:3])}.")

    # Reasoning (trimmed)
    reasoning = result.get("reasoning", "")
    if reasoning:
        parts.append(f"Reasoning: {reasoning[:300]}")

    return " ".join(parts)


def _build_query_text(
    agent_type:  str | None = None,
    verdict:     str | None = None,
    indicators:  list[str]  | None = None,
    signatures:  list[str]  | None = None,
    target:      str | None = None,
    subject:     str | None = None,
    sender:      str | None = None,
    free_text:   str | None = None,
) -> str:
    """Build a query string from structured fields or free text."""
    if free_text:
        return free_text

    parts = []
    if agent_type: parts.append(f"Agent: {agent_type}.")
    if verdict:    parts.append(f"Verdict: {verdict}.")
    if indicators: parts.append(f"Indicators: {', '.join(indicators)}.")
    if signatures: parts.append(f"Signatures: {', '.join(signatures)}.")
    if target:     parts.append(f"Target: {target}.")
    if subject:    parts.append(f"Subject: {subject}.")
    if sender:     parts.append(f"Sender: {sender}.")
    return " ".join(parts) if parts else "threat analysis"


# ══════════════════════════════════════════════════════════════════════════════
# Result dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MemoryMatch:
    """A single result from a Qdrant similarity search."""
    point_id:    str
    similarity:  float
    report_id:   str
    timestamp:   str
    agent_type:  str
    verdict:     str
    risk_score:  float
    indicators:  list[str]  = field(default_factory=list)
    signatures:  list[str]  = field(default_factory=list)
    target:      str        = ""
    subject:     str        = ""
    sender:      str        = ""
    correlations:list[str]  = field(default_factory=list)
    summary_text:str        = ""

    def to_context_string(self) -> str:
        """
        Format this match as a concise evidence string for the LLM prompt.
        """
        age = _human_age(self.timestamp)
        parts = [
            f"[HISTORICAL MATCH — similarity {self.similarity:.2f}]",
            f"  {age} — {self.agent_type.upper()} agent — verdict: {self.verdict.upper()} — risk: {self.risk_score:.2f}",
        ]
        if self.indicators:
            parts.append(f"  Indicators: {', '.join(self.indicators[:5])}")
        if self.signatures:
            parts.append(f"  Signatures: {', '.join(self.signatures)}")
        if self.target:
            parts.append(f"  Target: {self.target}")
        if self.subject:
            parts.append(f"  Email subject: {self.subject}")
        if self.correlations:
            parts.append(f"  Correlations: {', '.join(self.correlations)}")
        return "\n".join(parts)


def _human_age(ts: str) -> str:
    """Convert an ISO timestamp to a human-readable age string."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts)
        now = datetime.now()
        diff = now - dt.replace(tzinfo=None)
        secs = int(diff.total_seconds())
        if secs < 60:       return f"{secs}s ago"
        if secs < 3600:     return f"{secs//60}m ago"
        if secs < 86400:    return f"{secs//3600}h ago"
        return f"{secs//86400}d ago"
    except Exception:
        return ts


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def store_result(report_id: str, result: dict) -> bool:
    """
    Encode and store an agent result in Qdrant.

    Parameters
    ----------
    report_id : unique identifier for this analysis run
    result    : agent result dict (from any agent or the correlator)

    Returns
    -------
    True on success, False on any error (never raises — storage failures
    must not crash the analysis pipeline).
    """
    try:
        from qdrant_client.models import PointStruct

        client = _get_client()
        model  = _get_model()

        summary_text = _build_memory_text(result)

        vector = model.encode(
            summary_text,
            normalize_embeddings=True,
            convert_to_numpy=True,
        ).astype("float32").tolist()

        # Deterministic point ID from report_id + agent so re-runs overwrite
        point_id_str = f"{report_id}:{result.get('agent','unknown')}"
        point_id = int(hashlib.md5(point_id_str.encode()).hexdigest()[:16], 16) % (2**63)

        payload = {
            "report_id":   report_id,
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
            "agent_type":  result.get("agent", "unknown"),
            "verdict":     result.get("verdict", "unknown"),
            "risk_score":  float(result.get("risk_score", result.get("unified_risk", 0.0))),
            "confidence":  float(result.get("confidence", 0.0)),
            "indicators":  [str(i) for i in result.get("indicators", [])],
            "signatures":  result.get("signatures_hit", []),
            "target":      result.get("target", ""),
            "correlations":result.get("correlations", []),
            "summary_text":summary_text[:1000],
            # email fields
            "subject":     result.get("email_metadata", {}).get("subject", ""),
            "sender":      result.get("email_metadata", {}).get("sender", ""),
        }

        client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(id=point_id, vector=vector, payload=payload)],
        )

        log.info(
            "Qdrant: stored result — report=%s agent=%s verdict=%s",
            report_id, result.get("agent"), result.get("verdict"),
        )
        return True

    except Exception as exc:
        log.warning("Qdrant: store_result failed (non-fatal): %s", exc)
        return False


def query_memory(
    free_text:   str | None = None,
    agent_type:  str | None = None,
    verdict:     str | None = None,
    indicators:  list[str]  | None = None,
    signatures:  list[str]  | None = None,
    target:      str | None = None,
    subject:     str | None = None,
    sender:      str | None = None,
    k:           int        = 3,
    min_similarity: float   = MIN_SIMILARITY,
) -> list[MemoryMatch]:
    """
    Search Qdrant for historically similar threats.

    Parameters
    ----------
    free_text      : raw text query (takes priority if provided)
    agent_type     : filter by agent ("email", "log", "ip", "correlator")
    verdict/etc    : structured fields to build query from
    k              : number of results to return
    min_similarity : discard results below this threshold

    Returns
    -------
    list[MemoryMatch] sorted by similarity descending.
    Returns [] on any error — never raises.
    """
    try:
        from qdrant_client.models import Filter, FieldCondition, MatchValue

        client = _get_client()
        model  = _get_model()

        # Check collection has data
        count = client.count(COLLECTION).count
        if count == 0:
            log.info("Qdrant: collection is empty — no historical matches")
            return []

        query_text = _build_query_text(
            agent_type=agent_type, verdict=verdict,
            indicators=indicators, signatures=signatures,
            target=target, subject=subject, sender=sender,
            free_text=free_text,
        )

        vector = model.encode(
            query_text,
            normalize_embeddings=True,
            convert_to_numpy=True,
        ).astype("float32").tolist()

        # Optional agent_type filter
        search_filter = None
        if agent_type:
            search_filter = Filter(
                must=[FieldCondition(
                    key="agent_type",
                    match=MatchValue(value=agent_type),
                )]
            )

        hits = client.search(
            collection_name=COLLECTION,
            query_vector=vector,
            limit=k,
            query_filter=search_filter,
            with_payload=True,
        )

        results = []
        for hit in hits:
            if hit.score < min_similarity:
                continue
            p = hit.payload or {}
            results.append(MemoryMatch(
                point_id    = str(hit.id),
                similarity  = round(float(hit.score), 4),
                report_id   = p.get("report_id", ""),
                timestamp   = p.get("timestamp", ""),
                agent_type  = p.get("agent_type", ""),
                verdict      = p.get("verdict", ""),
                risk_score   = float(p.get("risk_score", 0.0)),
                indicators   = p.get("indicators", []),
                signatures   = p.get("signatures", []),
                target       = p.get("target", ""),
                subject      = p.get("subject", ""),
                sender       = p.get("sender", ""),
                correlations = p.get("correlations", []),
                summary_text = p.get("summary_text", ""),
            ))

        log.info(
            "Qdrant: query returned %d match(es) above threshold %.2f",
            len(results), min_similarity,
        )
        return results

    except Exception as exc:
        log.warning("Qdrant: query_memory failed (non-fatal): %s", exc)
        return []


def store_report(report_id: str, agent_results: list[dict], correlator_result: dict | None = None) -> None:
    """
    Convenience function — store all agent results + correlator from a full report.
    Called once per analysis run after all agents complete.
    """
    for result in agent_results:
        store_result(report_id, result)
    if correlator_result:
        store_result(report_id, correlator_result)


def collection_stats() -> dict:
    """Return basic stats about the threat memory collection."""
    try:
        client = _get_client()
        info   = client.get_collection(COLLECTION)
        count  = client.count(COLLECTION).count
        return {
            "collection":  COLLECTION,
            "point_count": count,
            "vector_dim":  VECTOR_DIM,
            "status":      str(info.status),
        }
    except Exception as exc:
        return {"error": str(exc)}


def clear_memory() -> bool:
    """Delete all points from the collection (useful for testing)."""
    try:
        client = _get_client()
        client.delete_collection(COLLECTION)
        global _client
        _client = None   # force re-init so collection is recreated
        _get_client()    # recreate empty collection
        log.info("Qdrant: collection cleared and recreated")
        return True
    except Exception as exc:
        log.error("Qdrant: clear_memory failed: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python cyber_mas/tools/qdrant_store.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    print("\n" + "═"*60)
    print("  Qdrant Store — smoke-test")
    print("═"*60 + "\n")

    # 1. Stats before
    print("  [1] Collection stats (before):")
    print(" ", json.dumps(collection_stats(), indent=4))

    # 2. Store mock results
    MOCK_RESULTS = [
        {
            "agent": "log", "verdict": "malicious", "risk_score": 0.88,
            "confidence": 0.90,
            "reasoning": "7 failed SSH logins from 203.0.113.42 followed by root session.",
            "indicators": ["ssh_brute_force", "root_compromise"],
            "signatures_hit": ["brute_force", "privilege_escalation"],
            "stats": {"total_lines":10,"unique_ips":1,"time_span_secs":21.0,
                      "top_sources":["203.0.113.42"],"error_rate":0.7},
        },
        {
            "agent": "email", "verdict": "phishing", "risk_score": 0.92,
            "confidence": 0.88,
            "reasoning": "Domain spoofing, urgency language, suspicious redirect.",
            "indicators": ["domain_spoofing", "urgency_language", "suspicious_url"],
            "email_metadata": {
                "subject": "URGENT: Your PayPal account has been suspended",
                "sender": "security-alert@paypa1-verify.com",
                "reply_to": "noreply@paypa1-verify.com",
                "has_links": True, "link_count": 3, "has_attachments": False,
            },
            "rag_match": {"label": "spam", "similarity": 0.91, "excerpt": "Claim your prize..."},
        },
        {
            "agent": "ip", "verdict": "vulnerable", "risk_score": 0.79,
            "confidence": 0.75,
            "reasoning": "OpenSSH 7.2 with critical CVEs. SMB port open.",
            "indicators": ["outdated_openssh", "smb_exposed"],
            "target": "203.0.113.42",
            "open_ports": [{"port":22,"protocol":"tcp","service":"ssh","version":"OpenSSH 7.2"}],
            "cves": [{"cve_id":"CVE-2016-6515","cvss_score":7.8,"severity":"HIGH",
                      "description":"OpenSSH DoS","affected_service":"ssh","url":""}],
            "os_guess": "Linux 4.x", "scan_duration": 18.4,
        },
    ]

    print("\n  [2] Storing 3 mock agent results...")
    rid = "smoke-test-001"
    for r in MOCK_RESULTS:
        ok = store_result(rid, r)
        print(f"     {r['agent']:12s} → {'OK' if ok else 'FAIL'}")

    # 3. Stats after
    print("\n  [3] Collection stats (after):")
    print(" ", json.dumps(collection_stats(), indent=4))

    # 4. Query
    print("\n  [4] Querying for 'SSH brute force root login attack'...")
    matches = query_memory(free_text="SSH brute force root login attack", k=3)
    if matches:
        for m in matches:
            print(f"\n     similarity={m.similarity:.4f}  agent={m.agent_type}  verdict={m.verdict}")
            print(f"     {m.to_context_string()[:200]}")
    else:
        print("     No matches above threshold.")

    print("\n  [5] Querying for 'PayPal phishing email urgent'...")
    matches2 = query_memory(free_text="PayPal phishing email urgent account suspended", k=2)
    if matches2:
        for m in matches2:
            print(f"\n     similarity={m.similarity:.4f}  agent={m.agent_type}  verdict={m.verdict}")
    else:
        print("     No matches above threshold.")

    print("\n  ✓ Smoke-test complete.\n")