"""
agents/email_agent.py
══════════════════════════════════════════════════════════════════════════════
Email Phishing Detection Agent.

PIPELINE
────────
  raw email text
      │
      ▼
  _preprocess()          — extract headers + body, clean text
      │
      ▼
  faiss_store.query()    — find nearest known email in corpus (RAG)
      │
      ▼
  _build_rag_context()   — format FAISS match as evidence string
      │
      ▼
  llm_client.ask()       — LLaMA 3.3-70B with CoT phishing prompt
      │
      ▼
  _parse_llm_response()  — extract strict JSON, validate fields
      │
      ▼
  result dict            — verdict, risk_score, confidence, indicators …

OUTPUT SCHEMA
─────────────
  {
      "agent"           : "email",
      "verdict"         : "phishing" | "spam" | "legitimate" | "uncertain",
      "risk_score"      : float,   # 0.0 – 1.0
      "confidence"      : float,   # 0.0 – 1.0
      "reasoning"       : str,
      "indicators"      : list[str],
      "rag_match"       : {
          "label"       : str,
          "similarity"  : float,
          "excerpt"     : str
      },
      "email_metadata"  : {
          "subject"     : str,
          "sender"      : str,
          "reply_to"    : str,
          "has_links"   : bool,
          "link_count"  : int,
          "has_attachments" : bool
      }
  }

USAGE
─────
  from agents.email_agent import analyse

  with open("suspicious.eml") as f:
      result = analyse(f.read())

  print(result["verdict"], result["risk_score"])
"""

from __future__ import annotations

import email
import json
import logging
import re
import sys
import os
from typing import Any

# Ensure project root is in sys.path so 'python agents/email_agent.py' works
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from tools.faiss_store import is_index_ready, query as faiss_query
from tools.llm_client import ask
from tools.prompts import email_system_prompt, email_user_prompt

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_LINK_TAG_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"']", re.IGNORECASE)

# Verdict strings the LLM is allowed to return
_VALID_VERDICTS = {"phishing", "spam", "legitimate", "uncertain"}

# Similarity threshold above which the RAG match is considered strong evidence
_RAG_HIGH_SIMILARITY = 0.75


# ══════════════════════════════════════════════════════════════════════════════
# Pre-processing
# ══════════════════════════════════════════════════════════════════════════════

def _extract_header(msg: email.message.Message, header: str) -> str:
    """Return a decoded header value or empty string."""
    val = msg.get(header, "") or ""
    # Simple decode — handles Q-encoding loosely
    try:
        from email.header import decode_header
        parts = decode_header(val)
        decoded = []
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(chunk)
        return " ".join(decoded).strip()
    except Exception:
        return str(val).strip()


def _extract_body(msg: email.message.Message) -> str:
    """Walk a (possibly multipart) message and return the plain-text body."""
    parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, errors="replace"))

    body = "\n".join(parts)
    # Collapse excessive blank lines
    body = re.sub(r"\n{3,}", "\n\n", body)
    return body.strip()


def _count_links(raw_text: str) -> int:
    """Count URLs in plain text and href attributes combined."""
    url_matches  = _URL_RE.findall(raw_text)
    href_matches = _LINK_TAG_RE.findall(raw_text)
    return len(set(url_matches + href_matches))


def _has_attachments(msg: email.message.Message) -> bool:
    """Return True if the message contains any non-text attachment."""
    for part in msg.walk():
        disposition = part.get("Content-Disposition", "")
        if "attachment" in disposition.lower():
            return True
        ct = part.get_content_type()
        if ct not in ("text/plain", "text/html", "multipart/alternative",
                      "multipart/mixed", "multipart/related"):
            if part.get_payload(decode=True):
                return True
    return False


def _preprocess(raw_email: str) -> dict:
    """
    Parse a raw email string.

    Returns
    -------
    dict with keys:
        subject, sender, reply_to, body, has_links,
        link_count, has_attachments, full_text
    """
    try:
        msg = email.message_from_string(raw_email)
    except Exception as exc:
        log.warning("email.message_from_string failed: %s — using raw text", exc)
        return {
            "subject": "",
            "sender": "",
            "reply_to": "",
            "body": raw_email,
            "has_links": bool(_URL_RE.search(raw_email)),
            "link_count": _count_links(raw_email),
            "has_attachments": False,
            "full_text": raw_email,
        }

    subject   = _extract_header(msg, "Subject")
    sender    = _extract_header(msg, "From")
    reply_to  = _extract_header(msg, "Reply-To")
    body      = _extract_body(msg)
    link_count = _count_links(raw_email)   # scan full raw for URLs too

    return {
        "subject":         subject,
        "sender":          sender,
        "reply_to":        reply_to,
        "body":            body,
        "has_links":       link_count > 0,
        "link_count":      link_count,
        "has_attachments": _has_attachments(msg),
        "full_text":       body or raw_email,   # fallback if body empty
    }


# ══════════════════════════════════════════════════════════════════════════════
# RAG context
# ══════════════════════════════════════════════════════════════════════════════

def _build_rag_context(email_text: str) -> tuple[str, dict]:
    """
    Query FAISS for the nearest known email.

    Returns
    -------
    (rag_context_string, rag_match_dict)
    rag_context_string is injected into the LLM prompt.
    rag_match_dict is stored in the final result for transparency.
    """
    if not is_index_ready():
        log.warning(
            "FAISS index not found — skipping RAG. "
            "Run: python tools/faiss_store.py --build"
        )
        return (
            "No reference database available. Analyse based on content alone.",
            {"label": "unknown", "similarity": 0.0, "excerpt": ""},
        )

    try:
        matches = faiss_query(email_text, k=1)
    except Exception as exc:
        log.warning("FAISS query failed: %s — skipping RAG", exc)
        return (
            "Reference database query failed. Analyse based on content alone.",
            {"label": "unknown", "similarity": 0.0, "excerpt": ""},
        )

    if not matches:
        return (
            "No similar email found in the reference database.",
            {"label": "unknown", "similarity": 0.0, "excerpt": ""},
        )

    m = matches[0]
    label      = m["label"].upper()          # SPAM / HAM / UNKNOWN
    similarity = m["similarity"]
    excerpt    = m["excerpt"][:300]

    strength = (
        "STRONG" if similarity >= _RAG_HIGH_SIMILARITY
        else "MODERATE" if similarity >= 0.5
        else "WEAK"
    )

    rag_context = (
        f"[REFERENCE DATABASE MATCH — {strength} SIGNAL]\n"
        f"The most similar email in our corpus was labelled: {label}\n"
        f"Similarity score: {similarity:.3f} (0=unrelated, 1=identical)\n"
        f"Reference excerpt:\n\"{excerpt}\"\n"
        f"Use this as supporting evidence, not as a definitive verdict."
    )

    rag_match = {
        "label":      m["label"],
        "similarity": similarity,
        "excerpt":    excerpt,
    }

    return rag_context, rag_match


# ══════════════════════════════════════════════════════════════════════════════
# LLM response parsing
# ══════════════════════════════════════════════════════════════════════════════

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


def _parse_llm_response(raw: str) -> dict:
    """
    Extract and validate the JSON payload from the LLM's response.

    Tries, in order:
      1. Parse the entire response as JSON
      2. Extract a ```json ... ``` code block
      3. Find the first { … } span in the response

    Returns a validated dict.  Falls back to a safe default on failure.
    """
    def _try_parse(text: str) -> dict | None:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return None

    # Strategy 1 — whole response
    parsed = _try_parse(raw)

    # Strategy 2 — fenced code block
    if parsed is None:
        m = _JSON_BLOCK_RE.search(raw)
        if m:
            parsed = _try_parse(m.group(1))

    # Strategy 3 — first { … } span (greedy)
    if parsed is None:
        start = raw.find("{")
        end   = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            parsed = _try_parse(raw[start : end + 1])

    if parsed is None:
        log.error("Could not parse JSON from LLM response:\n%s", raw[:500])
        return {
            "verdict":    "uncertain",
            "risk_score": 0.5,
            "confidence": 0.1,
            "reasoning":  "LLM returned unparseable output.",
            "indicators": [],
        }

    # ── Validate and normalise fields ─────────────────────────────────────────
    verdict = str(parsed.get("verdict", "uncertain")).lower().strip()
    if verdict not in _VALID_VERDICTS:
        log.warning("LLM returned unknown verdict '%s' — setting 'uncertain'", verdict)
        verdict = "uncertain"

    def _clamp(val: Any, default: float) -> float:
        try:
            return max(0.0, min(1.0, float(val)))
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
    Analyse an email for phishing / spam indicators.

    Parameters
    ----------
    payload : str  — raw email text (RFC-2822 or plain body)
              dict — {"raw": str} or {"body": str, "subject": str, ...}

    Returns
    -------
    dict conforming to the OUTPUT SCHEMA above.
    """
    # ── Normalise payload ─────────────────────────────────────────────────────
    if isinstance(payload, dict):
        raw_email = payload.get("raw") or payload.get("body") or str(payload)
    else:
        raw_email = str(payload)

    # ── Step 1 — Pre-process ──────────────────────────────────────────────────
    log.info("Email agent: pre-processing …")
    meta = _preprocess(raw_email)

    # ── Step 2 — RAG retrieval ────────────────────────────────────────────────
    log.info("Email agent: querying FAISS index …")
    rag_context, rag_match = _build_rag_context(meta["full_text"])

    # ── Step 3 — Build prompts ────────────────────────────────────────────────
    system_prompt = email_system_prompt()
    user_prompt   = email_user_prompt(
        subject      = meta["subject"],
        sender       = meta["sender"],
        reply_to     = meta["reply_to"],
        body         = meta["body"] or meta["full_text"],
        link_count   = meta["link_count"],
        has_attachments = meta["has_attachments"],
        rag_context  = rag_context,
    )

    # ── Step 4 — LLM call ─────────────────────────────────────────────────────
    log.info("Email agent: calling LLM …")
    raw_response = ask(system_prompt, user_prompt)

    # ── Step 5 — Parse + validate ─────────────────────────────────────────────
    log.info("Email agent: parsing LLM response …")
    llm_result = _parse_llm_response(raw_response)

    # ── Step 6 — Assemble final result ────────────────────────────────────────
    result = {
        "agent":   "email",
        **llm_result,
        "rag_match": rag_match,
        "email_metadata": {
            "subject":          meta["subject"],
            "sender":           meta["sender"],
            "reply_to":         meta["reply_to"],
            "has_links":        meta["has_links"],
            "link_count":       meta["link_count"],
            "has_attachments":  meta["has_attachments"],
        },
    }

    log.info(
        "Email agent: done — verdict=%s  risk=%.2f  confidence=%.2f",
        result["verdict"], result["risk_score"], result["confidence"],
    )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI smoke-test  —  python -m agents.email_agent
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json as _json

    PHISHING_SAMPLE = """\
From: security-alert@paypa1-verify.com
Reply-To: noreply@paypa1-verify.com
To: victim@example.com
Subject: URGENT: Your PayPal account has been suspended

Dear PayPal Customer,

We have detected suspicious activity on your account.
Your account access has been temporarily limited.

To restore your account, please verify your information immediately:

http://paypa1-verify.com/restore?token=abc123&user=victim

Failure to verify within 24 hours will result in permanent suspension.

PayPal Security Team
"""

    print("\n" + "═" * 60)
    print("  Email Agent — smoke-test")
    print("═" * 60)
    print("  Analysing a simulated phishing email …\n")

    try:
        result = analyse(PHISHING_SAMPLE)
        print(_json.dumps(result, indent=2))
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print("  Make sure GROQ_API_KEY is set and the venv is active.")