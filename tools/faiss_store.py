"""
cyber_mas/tools/faiss_store.py
══════════════════════════════════════════════════════════════════════════════
FAISS vector index over the SpamAssassin email corpus.

ROLES
─────
  • build_index()   — one-time setup: encode corpus → save .index + meta.json
  • query()         — runtime:        find nearest neighbour for an email text

CORPUS FORMAT (SpamAssassin public corpus)
──────────────────────────────────────────
  data/raw_emails/
      spam/           ← spam/*.txt   (or spam_2/, spam_assassin/, etc.)
      easy_ham/       ← easy_ham/*.txt
      hard_ham/       ← hard_ham/*.txt  (optional)

  Any .txt file whose parent directory name contains "spam" is labelled
  "spam"; everything else is "ham".  The loader is forgiving of mixed
  directory layouts (flat, nested, with/without sub-folders).

INDEX FILES
───────────────────────────────────────────────────────────────────────────
  data/faiss_index/emails.index   — FAISS IndexFlatL2 binary
  data/faiss_index/meta.json      — [{label, excerpt, source_file}, ...]

USAGE
─────
  # one-time build (Codespace / any Linux machine with enough RAM)
  python cyber_mas/tools/faiss_store.py --build

  # optional smoke-test query after build
  python cyber_mas/tools/faiss_store.py --query "Congratulations! You won a prize."

  # from code
  from cyber_mas.tools.faiss_store import query
  distance, label, excerpt = query(email_text, k=1)
"""

from __future__ import annotations

import argparse
import email
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] faiss_store — %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[1]          # …/cyber_mas/tools/ → go up 1 level

RAW_EMAILS_DIR  = _PROJECT_ROOT / "data" / "raw_emails"
FAISS_INDEX_DIR = _PROJECT_ROOT / "data" / "faiss_index"
INDEX_PATH      = FAISS_INDEX_DIR / "emails.index"
META_PATH       = FAISS_INDEX_DIR / "meta.json"

# ── Model ─────────────────────────────────────────────────────────────────────
MODEL_NAME   = "all-MiniLM-L6-v2"   # 22 M params, 384-dim, fast & accurate
EXCERPT_CHARS = 400                  # characters stored in meta for context
BATCH_SIZE    = 64                   # encoding batch — tune down if OOM
MAX_EMAILS    = 10_000               # safety cap (full corpus ~6 k — fine)

# ── Singleton state (loaded lazily at query time) ─────────────────────────────
_index: Optional[faiss.Index] = None
_meta:  Optional[list[dict]]  = None
_model: Optional[SentenceTransformer] = None


# ══════════════════════════════════════════════════════════════════════════════
# Corpus loading
# ══════════════════════════════════════════════════════════════════════════════

def _label_from_path(path: Path) -> str:
    """Infer spam / ham label from the file's parent directory name."""
    parts = [p.lower() for p in path.parts]
    for part in reversed(parts[:-1]):   # walk ancestors, nearest first
        if "spam" in part:
            return "spam"
        if "ham" in part:
            return "ham"
    return "unknown"


def _parse_email_text(raw: bytes) -> str:
    """Extract plain-text body from a raw RFC-2822 email bytestring."""
    try:
        msg = email.message_from_bytes(raw)
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

        body = "\n".join(parts).strip()
        # collapse whitespace runs
        body = re.sub(r"\s+", " ", body)
        return body if body else "[empty body]"

    except Exception:
        # fallback: treat entire file as plain text
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return "[unparseable email]"


def _load_corpus(emails_dir: Path) -> list[dict]:
    """
    Recursively walk *emails_dir* and load every .txt file.

    Returns a list of dicts:
        {label: str, text: str, excerpt: str, source_file: str}
    """
    if not emails_dir.exists():
        raise FileNotFoundError(
            f"Email corpus directory not found: {emails_dir}\n"
            "Download the SpamAssassin public corpus and extract it there.\n"
            "https://spamassassin.apache.org/old/publiccorpus/"
        )

    files = sorted(emails_dir.rglob("*.txt"))
    if not files:
        # some distributions use no extension — try all files
        files = [
            p for p in sorted(emails_dir.rglob("*"))
            if p.is_file() and not p.suffix or p.suffix in (".txt", "")
        ]

    if not files:
        raise FileNotFoundError(
            f"No email files found under {emails_dir}. "
            "Make sure .txt files exist in spam/ and easy_ham/ sub-directories."
        )

    log.info("Found %d email files under %s", len(files), emails_dir)
    records: list[dict] = []

    for path in files[:MAX_EMAILS]:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            log.warning("Cannot read %s: %s", path, exc)
            continue

        label = _label_from_path(path)
        text  = _parse_email_text(raw)
        excerpt = text[:EXCERPT_CHARS]

        records.append({
            "label":       label,
            "text":        text,
            "excerpt":     excerpt,
            "source_file": str(path.relative_to(_PROJECT_ROOT)),
        })

    log.info(
        "Loaded %d emails — spam: %d  ham: %d  unknown: %d",
        len(records),
        sum(1 for r in records if r["label"] == "spam"),
        sum(1 for r in records if r["label"] == "ham"),
        sum(1 for r in records if r["label"] == "unknown"),
    )
    return records


# ══════════════════════════════════════════════════════════════════════════════
# Index building
# ══════════════════════════════════════════════════════════════════════════════

def build_index(
    emails_dir: Path = RAW_EMAILS_DIR,
    index_dir:  Path = FAISS_INDEX_DIR,
    force:      bool = False,
) -> None:
    """
    Build FAISS index from the SpamAssassin corpus and persist to disk.

    Parameters
    ----------
    emails_dir : directory containing spam/ and easy_ham/ sub-dirs
    index_dir  : destination for emails.index and meta.json
    force      : overwrite existing index without prompting
    """
    if INDEX_PATH.exists() and META_PATH.exists() and not force:
        log.info(
            "Index already exists at %s — use --force to rebuild.", index_dir
        )
        return

    index_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load corpus ──────────────────────────────────────────────────────
    t0 = time.perf_counter()
    records = _load_corpus(emails_dir)
    texts = [r["text"] for r in records]
    log.info("Corpus loaded in %.1f s", time.perf_counter() - t0)

    # ── 2. Encode ───────────────────────────────────────────────────────────
    log.info("Loading sentence-transformer model '%s' …", MODEL_NAME)
    model = SentenceTransformer(MODEL_NAME)

    log.info("Encoding %d documents in batches of %d …", len(texts), BATCH_SIZE)
    t1 = time.perf_counter()
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,   # cosine similarity via inner product
        convert_to_numpy=True,
    ).astype("float32")
    log.info("Encoded %d vectors (dim=%d) in %.1f s",
             len(embeddings), embeddings.shape[1], time.perf_counter() - t1)

    # ── 3. Build FAISS index ─────────────────────────────────────────────────
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)   # exact L2; good enough for <10k docs
    index.add(embeddings)
    log.info("FAISS index built — %d vectors indexed", index.ntotal)

    # ── 4. Persist ──────────────────────────────────────────────────────────
    faiss.write_index(index, str(INDEX_PATH))
    log.info("Index saved → %s", INDEX_PATH)

    # strip heavy 'text' field before saving meta (excerpts are enough)
    meta = [
        {"label": r["label"], "excerpt": r["excerpt"], "source_file": r["source_file"]}
        for r in records
    ]
    META_PATH.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("Metadata saved → %s  (%d entries)", META_PATH, len(meta))

    total = time.perf_counter() - t0
    log.info("✓ Build complete in %.1f s — ready for queries.", total)


# ══════════════════════════════════════════════════════════════════════════════
# Runtime helpers (lazy load)
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_loaded() -> None:
    """Load index, metadata, and model into module-level singletons."""
    global _index, _meta, _model

    if _index is not None:
        return   # already loaded

    if not INDEX_PATH.exists() or not META_PATH.exists():
        raise FileNotFoundError(
            "FAISS index not found. Run first:\n"
            "  python cyber_mas/tools/faiss_store.py --build"
        )

    log.info("Loading FAISS index from %s …", INDEX_PATH)
    _index = faiss.read_index(str(INDEX_PATH))

    log.info("Loading metadata from %s …", META_PATH)
    _meta = json.loads(META_PATH.read_text(encoding="utf-8"))

    log.info("Loading sentence-transformer model '%s' …", MODEL_NAME)
    _model = SentenceTransformer(MODEL_NAME)

    log.info("Ready — %d vectors in index.", _index.ntotal)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def query(
    email_text: str,
    k: int = 1,
) -> list[dict]:
    """
    Find the *k* nearest neighbours in the FAISS index for *email_text*.

    Parameters
    ----------
    email_text : raw email string (headers + body, or body only)
    k          : number of neighbours to return (default 1)

    Returns
    -------
    List of dicts, length k, each with:
        distance    : float  — L2 distance (lower = more similar)
        label       : str    — "spam" | "ham" | "unknown"
        excerpt     : str    — first ~400 chars of the matched email
        source_file : str    — relative path to the original file
        similarity  : float  — 1 / (1 + distance), in [0, 1]

    Raises
    ------
    FileNotFoundError if index has not been built yet.
    """
    _ensure_loaded()

    # normalise input the same way as during build
    clean = re.sub(r"\s+", " ", email_text).strip()

    vec = _model.encode(
        [clean],
        normalize_embeddings=True,
        convert_to_numpy=True,
    ).astype("float32")

    distances, indices = _index.search(vec, k)

    results: list[dict] = []
    for dist, idx in zip(distances[0], indices[0]):
        if idx == -1:          # FAISS returns -1 when k > ntotal
            continue
        meta_entry = _meta[idx]
        results.append({
            "distance":    float(dist),
            "similarity":  float(1.0 / (1.0 + dist)),   # normalised [0,1]
            "label":       meta_entry["label"],
            "excerpt":     meta_entry["excerpt"],
            "source_file": meta_entry["source_file"],
        })

    return results


def is_index_ready() -> bool:
    """Return True if the FAISS index files exist on disk."""
    return INDEX_PATH.exists() and META_PATH.exists()


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry-point
# ══════════════════════════════════════════════════════════════════════════════

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Build or query the Cyber-MAS FAISS email index.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
────────
  # Build index from corpus (run once)
  python cyber_mas/tools/faiss_store.py --build

  # Force rebuild even if index exists
  python cyber_mas/tools/faiss_store.py --build --force

  # Query the index
  python cyber_mas/tools/faiss_store.py --query "You have won a lottery prize!"

  # Query with k=3 nearest neighbours
  python cyber_mas/tools/faiss_store.py --query "Invoice attached" --k 3
""",
    )
    parser.add_argument("--build", action="store_true",
                        help="Build FAISS index from data/raw_emails/")
    parser.add_argument("--force", action="store_true",
                        help="Force rebuild even if index already exists")
    parser.add_argument("--query", metavar="TEXT",
                        help="Query text to find nearest email(s)")
    parser.add_argument("--k", type=int, default=1,
                        help="Number of neighbours to return (default: 1)")
    parser.add_argument("--emails-dir", type=Path, default=RAW_EMAILS_DIR,
                        help=f"Path to raw email corpus (default: {RAW_EMAILS_DIR})")
    parser.add_argument("--index-dir", type=Path, default=FAISS_INDEX_DIR,
                        help=f"Path to index output dir (default: {FAISS_INDEX_DIR})")

    args = parser.parse_args()

    if not args.build and not args.query:
        parser.print_help()
        sys.exit(0)

    # ── Build ────────────────────────────────────────────────────────────────
    if args.build:
        try:
            build_index(
                emails_dir=args.emails_dir,
                index_dir=args.index_dir,
                force=args.force,
            )
        except FileNotFoundError as exc:
            log.error("%s", exc)
            sys.exit(1)

    # ── Query ────────────────────────────────────────────────────────────────
    if args.query:
        try:
            results = query(args.query, k=args.k)
        except FileNotFoundError as exc:
            log.error("%s", exc)
            sys.exit(1)

        print(f"\n{'─'*60}")
        print(f"  Query : {args.query[:80]}")
        print(f"{'─'*60}")
        for i, r in enumerate(results, 1):
            print(f"\n  Result #{i}")
            print(f"    label      : {r['label'].upper()}")
            print(f"    similarity : {r['similarity']:.4f}  (distance={r['distance']:.4f})")
            print(f"    source     : {r['source_file']}")
            print(f"    excerpt    : {r['excerpt'][:200]!r}")
        print()


if __name__ == "__main__":
    _cli()