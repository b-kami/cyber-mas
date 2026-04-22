"""
main.py
══════════════════════════════════════════════════════════════════════════════
Cyber-MAS  —  Multi-Agent Cybersecurity Threat Detection System
CLI entry point.

USAGE
─────
  # Full pipeline (all three agents + correlator)
  python main.py --email path/to/email.eml --log path/to/auth.log --ip 192.168.1.1

  # Any combination of agents
  python main.py --email suspicious.eml
  python main.py --log syslog.txt --ip 10.0.0.5
  python main.py --ip scanme.nmap.org

  # Pass inline text instead of files
  python main.py --email-text "From: attacker@evil.com\nSubject: Click here"
  python main.py --log-text  "2024-03-15 02:13:44 WARN Failed password for root"
  python main.py --ip-text   "203.0.113.42"

  # Output options
  python main.py --email email.eml --output report.json   # save JSON report
  python main.py --email email.eml --no-correlate         # skip correlator
  python main.py --email email.eml --quiet                # minimal output

  # Utility
  python main.py --build-index                            # build FAISS index
  python main.py --check                                  # environment check
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# ── Ensure project root is always in sys.path (fixes ModuleNotFoundError) ────
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("main")

# ── Rich (optional — graceful fallback to plain print) ────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None


# ══════════════════════════════════════════════════════════════════════════════
# Display helpers
# ══════════════════════════════════════════════════════════════════════════════

_VERDICT_COLORS = {
    # correlator verdicts
    "critical":    "bold red",
    "high":        "red",
    "medium":      "yellow",
    "low":         "green",
    # agent verdicts
    "phishing":    "bold red",
    "malicious":   "bold red",
    "vulnerable":  "red",
    "spam":        "yellow",
    "suspicious":  "yellow",
    "legitimate":  "green",
    "benign":      "green",
    "clean":       "green",
    "uncertain":   "dim",
}


def _color(verdict: str) -> str:
    return _VERDICT_COLORS.get(verdict.lower(), "white")


def _risk_bar(score: float, width: int = 20) -> str:
    """ASCII risk bar: ████████░░░░░░░░░░░░ 0.42"""
    filled = int(score * width)
    bar    = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {score:.2f}"


def _print_banner() -> None:
    if _RICH:
        console.print(Panel.fit(
            "[bold cyan]Cyber-MAS[/bold cyan]  •  "
            "Multi-Agent Cybersecurity Threat Detection\n"
            "[dim]LLaMA 3.3-70B via Groq  •  FAISS  •  Nmap  •  NVD[/dim]",
            border_style="cyan",
        ))
    else:
        print("\n" + "═" * 60)
        print("  Cyber-MAS  —  Multi-Agent Cybersecurity Threat Detection")
        print("═" * 60 + "\n")


def _print_agent_result(result: dict, quiet: bool = False) -> None:
    """Pretty-print a single agent result."""
    agent   = result.get("agent", "?").upper()
    verdict = result.get("verdict", "?")
    risk    = result.get("risk_score", result.get("unified_risk", 0.0))
    conf    = result.get("confidence", 0.0)

    if _RICH and not quiet:
        color = _color(verdict)
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("key",   style="dim", width=18)
        table.add_column("value", style="white")

        table.add_row("Agent",      f"[bold]{agent}[/bold]")
        table.add_row("Verdict",    f"[{color}]{verdict.upper()}[/{color}]")
        table.add_row("Risk score", _risk_bar(risk))
        table.add_row("Confidence", f"{conf:.2f}")

        if result.get("signatures_hit"):
            table.add_row("Signatures", ", ".join(result["signatures_hit"]))

        if result.get("email_metadata"):
            m = result["email_metadata"]
            table.add_row("Subject",  m.get("subject", ""))
            table.add_row("Sender",   m.get("sender", ""))
            table.add_row("Links",    str(m.get("link_count", 0)))

        if result.get("target"):
            table.add_row("Target",      result["target"])
            table.add_row("Open ports",  str(len(result.get("open_ports", []))))
            table.add_row("CVEs found",  str(len(result.get("cves", []))))

        if result.get("reasoning") and not quiet:
            reasoning = result["reasoning"][:300]
            table.add_row("Reasoning", reasoning)

        console.print(Panel(table, title=f"[bold]{agent} Agent[/bold]",
                            border_style=color))
    else:
        print(f"\n  [{agent} AGENT]")
        print(f"  Verdict    : {verdict.upper()}")
        print(f"  Risk score : {_risk_bar(risk)}")
        print(f"  Confidence : {conf:.2f}")
        if result.get("reasoning") and not quiet:
            print(f"  Reasoning  : {result['reasoning'][:200]}")


def _print_correlator_result(result: dict, quiet: bool = False) -> None:
    """Pretty-print the correlator's unified assessment."""
    verdict = result.get("verdict", "?")
    risk    = result.get("unified_risk", 0.0)
    conf    = result.get("confidence", 0.0)
    corrs   = result.get("correlations", [])
    recs    = result.get("recommendations", [])

    if _RICH:
        color = _color(verdict)
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("key",   style="dim", width=18)
        table.add_column("value", style="white")

        table.add_row("Verdict",      f"[{color} bold]{verdict.upper()}[/{color} bold]")
        table.add_row("Unified risk", _risk_bar(risk))
        table.add_row("Confidence",   f"{conf:.2f}")

        if corrs:
            table.add_row("Correlations", "\n".join(f"• {c}" for c in corrs))
        else:
            table.add_row("Correlations", "[dim]none[/dim]")

        summary = result.get("agent_summary", {})
        for ag, val in summary.items():
            if val:
                table.add_row(
                    f"  {ag.capitalize()}",
                    f"{val['verdict']}  risk={val['risk_score']:.2f}",
                )

        if result.get("reasoning") and not quiet:
            table.add_row("Reasoning", result["reasoning"][:400])

        if recs and not quiet:
            table.add_row(
                "Recommendations",
                "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs)),
            )

        console.print(Panel(table, title="[bold]UNIFIED THREAT ASSESSMENT[/bold]",
                            border_style=color))
    else:
        print("\n" + "═" * 60)
        print("  UNIFIED THREAT ASSESSMENT")
        print("═" * 60)
        print(f"  Verdict      : {verdict.upper()}")
        print(f"  Unified risk : {_risk_bar(risk)}")
        print(f"  Confidence   : {conf:.2f}")
        if corrs:
            print(f"  Correlations : {', '.join(corrs)}")
        if recs and not quiet:
            print("  Recommendations:")
            for i, r in enumerate(recs, 1):
                print(f"    {i}. {r}")
        if result.get("reasoning") and not quiet:
            print(f"  Reasoning    : {result['reasoning'][:300]}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Environment check
# ══════════════════════════════════════════════════════════════════════════════

def _check_environment() -> bool:
    """Verify all required dependencies and API keys are present."""
    ok = True
    checks = []

    # GROQ_API_KEY
    if os.getenv("GROQ_API_KEY"):
        checks.append(("GROQ_API_KEY",  "✓", "set"))
    else:
        checks.append(("GROQ_API_KEY",  "✗", "MISSING - export GROQ_API_KEY=..."))
        ok = False

    # NVD_API_KEY (optional but recommended)
    if os.getenv("NVD_API_KEY"):
        checks.append(("NVD_API_KEY",   "✓", "set"))
    else:
        checks.append(("NVD_API_KEY",   "~", "not set - NVD rate limit applies (public)"))

    # nmap binary
    import shutil
    if shutil.which("nmap"):
        checks.append(("nmap binary",   "✓", "found"))
    else:
        checks.append(("nmap binary",   "~", "not found - ip_agent will be unavailable"))

    # FAISS index
    from tools.faiss_store import is_index_ready
    if is_index_ready():
        checks.append(("FAISS index",   "✓", "ready"))
    else:
        checks.append(("FAISS index",   "~",
                        "not built - run: python main.py --build-index"))

    # Python packages
    for pkg in ("groq", "faiss", "sentence_transformers", "nmap", "pandas"):
        real_pkg = "faiss" if pkg == "faiss" else pkg
        try:
            __import__(real_pkg if real_pkg != "faiss" else "faiss")
            checks.append((f"pkg:{pkg}", "✓", "installed"))
        except ImportError:
            checks.append((f"pkg:{pkg}", "✗", f"pip install {pkg}"))
            ok = False

    print("\n  Environment check:")
    print("  " + "-" * 50)
    for name, status, detail in checks:
        sym = {"✓": "OK", "✗": "FAIL", "~": "WARN"}.get(status, "?")
        print(f"  [{sym:4}] {name:<22} {detail}")
    print()

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# Argument parsing
# ══════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyber-mas",
        description="Cyber-MAS — Multi-Agent Cybersecurity Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Input sources ─────────────────────────────────────────────────────────
    inputs = p.add_argument_group("Input sources (mix and match)")
    inputs.add_argument("--email",      metavar="FILE",
                        help="Path to a .eml or .txt email file")
    inputs.add_argument("--email-text", metavar="TEXT",
                        help="Raw email string (inline)")
    inputs.add_argument("--log",        metavar="FILE",
                        help="Path to a log file")
    inputs.add_argument("--log-text",   metavar="TEXT",
                        help="Raw log text (inline)")
    inputs.add_argument("--ip",         metavar="TARGET",
                        help="IP address, hostname, or CIDR to scan")
    inputs.add_argument("--ip-text",    metavar="TARGET",
                        help="Alias for --ip (inline)")

    # ── Output options ────────────────────────────────────────────────────────
    out = p.add_argument_group("Output options")
    out.add_argument("--output",      metavar="FILE",
                     help="Save full JSON report to this path")
    out.add_argument("--quiet",       action="store_true",
                     help="Print only verdicts and risk scores")
    out.add_argument("--no-correlate",action="store_true",
                     help="Skip the correlator (raw agent outputs only)")
    out.add_argument("--json",        action="store_true",
                     help="Print raw JSON to stdout (implies --quiet)")

    # ── Utility ───────────────────────────────────────────────────────────────
    util = p.add_argument_group("Utility")
    util.add_argument("--build-index", action="store_true",
                      help="Build FAISS email index from data/raw_emails/")
    util.add_argument("--force-rebuild", action="store_true",
                      help="Force rebuild of FAISS index even if it exists")
    util.add_argument("--check",      action="store_true",
                      help="Check environment and exit")
    util.add_argument("--verbose",    action="store_true",
                      help="Enable DEBUG logging")

    return p


# ══════════════════════════════════════════════════════════════════════════════
# Input loading
# ══════════════════════════════════════════════════════════════════════════════

def _load_file(path: str, label: str) -> str:
    p = Path(path)
    if not p.exists():
        log.error("%s file not found: %s", label, path)
        sys.exit(1)
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.error("Cannot read %s file %s: %s", label, path, exc)
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Main pipeline
# ══════════════════════════════════════════════════════════════════════════════

def run(args: argparse.Namespace) -> dict:
    """
    Execute the full pipeline based on parsed CLI arguments.

    Returns
    -------
    dict — the complete report (all agent results + correlator if applicable)
    """
    from agents.dispatcher import dispatch
    from agents.correlator import correlate

    report: dict = {
        "meta":    {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")},
        "agents":  [],
        "correlator": None,
    }

    agent_results: list[dict] = []
    quiet = args.quiet or args.json

    # ── Collect tasks ─────────────────────────────────────────────────────────
    tasks: list[dict] = []

    email_text = args.email_text or (_load_file(args.email, "email") if args.email else None)
    if email_text:
        tasks.append({"type": "email", "payload": email_text})

    log_text = args.log_text or (_load_file(args.log, "log") if args.log else None)
    if log_text:
        tasks.append({"type": "log", "payload": log_text})

    ip_target = args.ip or args.ip_text
    if ip_target:
        tasks.append({"type": "ip", "payload": ip_target})

    if not tasks:
        log.error("No input provided. Use --email, --log, or --ip.")
        sys.exit(1)

    # ── Run each agent via dispatcher ─────────────────────────────────────────
    for task in tasks:
        t_type = task["type"].upper()
        log.info("─" * 40)
        log.info("Dispatching: %s", t_type)
        t0 = time.perf_counter()

        try:
            result = dispatch(task)
        except Exception as exc:
            log.error("%s agent failed: %s", t_type, exc)
            result = {
                "agent":      task["type"],
                "verdict":    "uncertain",
                "risk_score": 0.0,
                "confidence": 0.0,
                "reasoning":  str(exc),
                "indicators": [f"agent_error: {exc}"],
            }

        elapsed = time.perf_counter() - t0
        log.info("%s agent completed in %.1f s", t_type, elapsed)
        result["_duration_secs"] = round(elapsed, 2)

        agent_results.append(result)
        report["agents"].append(result)

        if not args.json:
            _print_agent_result(result, quiet=quiet)

    # ── Correlate if multiple agents OR always if only 1 ─────────────────────
    if not args.no_correlate:
        log.info("─" * 40)
        log.info("Running correlator …")
        t0 = time.perf_counter()

        try:
            corr_result = correlate(agent_results)
        except Exception as exc:
            log.error("Correlator failed: %s", exc)
            corr_result = {
                "agent":         "correlator",
                "verdict":       "uncertain",
                "unified_risk":  0.0,
                "confidence":    0.0,
                "reasoning":     str(exc),
                "correlations":  [],
                "recommendations": [],
                "agent_summary": {},
                "indicators":    [],
                "unified_indicators": [],
            }

        elapsed = time.perf_counter() - t0
        log.info("Correlator completed in %.1f s", elapsed)
        corr_result["_duration_secs"] = round(elapsed, 2)

        report["correlator"] = corr_result

        if not args.json:
            _print_correlator_result(corr_result, quiet=quiet)

    return report


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.json:
        _print_banner()

    # ── Utility modes ─────────────────────────────────────────────────────────
    if args.check:
        ok = _check_environment()
        sys.exit(0 if ok else 1)

    if args.build_index:
        from tools.faiss_store import build_index
        build_index(force=args.force_rebuild)
        sys.exit(0)

    # ── Pipeline ──────────────────────────────────────────────────────────────
    t_total = time.perf_counter()
    report  = run(args)
    elapsed = time.perf_counter() - t_total

    report["meta"]["total_duration_secs"] = round(elapsed, 2)

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json:
        print(json.dumps(report, indent=2, default=str))

    # ── Save report ───────────────────────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        if not args.json:
            if _RICH:
                console.print(f"\n[dim]Report saved → {out_path}[/dim]")
            else:
                print(f"\n  Report saved → {out_path}")

    if not args.json:
        if _RICH:
            console.print(f"[dim]Total time: {elapsed:.1f} s[/dim]\n")
        else:
            print(f"  Total time: {elapsed:.1f} s\n")


if __name__ == "__main__":
    main()