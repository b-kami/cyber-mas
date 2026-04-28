"""
main.py  (v2 — standard mode + continuous monitoring)
══════════════════════════════════════════════════════════════════════════════
Cyber-MAS CLI entry point.

STANDARD MODE  (one-shot analysis)
────────────────────────────────────
  # Direct input
  python main.py --email alert.eml --log auth.log --ip 192.168.1.1

  # Inline text
  python main.py --email-text "From: evil@phish.com ..."
  python main.py --log-text  "2024-03-15 02:13:44 WARN Failed password ..."
  python main.py --ip-text   "203.0.113.42"

  # Pick from folder (interactive selector)
  python main.py --email-dir data/raw_emails/
  python main.py --log-dir   data/sample_logs/
  python main.py --email-dir data/raw_emails/ --log-dir data/sample_logs/

  # Output options
  python main.py --email alert.eml --output report.json
  python main.py --email alert.eml --json
  python main.py --email alert.eml --quiet
  python main.py --email alert.eml --no-correlate

CONTINUOUS MONITORING MODE
───────────────────────────
  # Watch a log file
  python main.py --watch-log /var/log/auth.log

  # Watch IMAP inbox
  python main.py --watch-email-imap

  # Watch an IP (recurring Nmap scans)
  python main.py --watch-ip 192.168.1.1

  # Run all three simultaneously
  python main.py --watch-all --watch-log /var/log/auth.log --watch-ip 10.0.0.5

  # Tuning
  python main.py --watch-log auth.log --interval 30   # check every 30s
  python main.py --watch-ip 10.0.0.1  --ip-interval 300  # scan every 5min
  python main.py --watch-all --alert-log alerts.jsonl     # custom alert log

UTILITY
────────
  python main.py --check           # environment check
  python main.py --build-index     # build FAISS email index
  python main.py --monitor-status  # show watcher config without starting
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("cyber_mas.main")

# ── Rich (optional) ───────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich         import box
    _RICH   = True
    console = Console()
except ImportError:
    _RICH   = False
    console = None


# ══════════════════════════════════════════════════════════════════════════════
# Display helpers (unchanged from v1)
# ══════════════════════════════════════════════════════════════════════════════

_VERDICT_COLORS = {
    "critical": "bold red",  "high": "red",      "medium": "yellow",
    "low": "green",           "phishing": "bold red", "malicious": "bold red",
    "vulnerable": "red",      "suspicious": "yellow", "spam": "yellow",
    "legitimate": "green",    "benign": "green",  "clean": "green",
    "uncertain": "dim",
}

def _color(verdict: str) -> str:
    return _VERDICT_COLORS.get(verdict.lower(), "white")

def _risk_bar(score: float, width: int = 20) -> str:
    filled = int(score * width)
    return "█" * filled + "░" * (width - filled) + f" {score:.2f}"

def _print_banner() -> None:
    if _RICH:
        console.print(Panel.fit(
            "[bold cyan]Cyber-MAS[/bold cyan]  •  "
            "Multi-Agent Cybersecurity Threat Detection\n"
            "[dim]LLaMA 3.3-70B via Groq  •  FAISS  •  Nmap  •  NVD  •  "
            "Qdrant  •  MITRE ATT&CK[/dim]",
            border_style="cyan",
        ))
    else:
        print("\n" + "═"*60)
        print("  Cyber-MAS  —  Multi-Agent Cybersecurity Threat Detection")
        print("═"*60 + "\n")

def _print_agent_result(result: dict, quiet: bool = False) -> None:
    agent   = result.get("agent","?").upper()
    verdict = result.get("verdict","?")
    risk    = result.get("risk_score", result.get("unified_risk", 0.0))
    conf    = result.get("confidence", 0.0)
    if _RICH and not quiet:
        color = _color(verdict)
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        t.add_column("key",   style="dim", width=18)
        t.add_column("value", style="white")
        t.add_row("Agent",      f"[bold]{agent}[/bold]")
        t.add_row("Verdict",    f"[{color}]{verdict.upper()}[/{color}]")
        t.add_row("Risk score", _risk_bar(risk))
        t.add_row("Confidence", f"{conf:.2f}")
        if result.get("signatures_hit"):
            t.add_row("Signatures", ", ".join(result["signatures_hit"]))
        if result.get("reasoning") and not quiet:
            t.add_row("Reasoning", result["reasoning"][:250])
        console.print(Panel(t, title=f"[bold]{agent} Agent[/bold]",
                            border_style=color))
    else:
        print(f"\n  [{agent} AGENT]  verdict={verdict.upper()}  "
              f"risk={_risk_bar(risk)}  conf={conf:.2f}")

def _print_correlator_result(result: dict, quiet: bool = False) -> None:
    verdict = result.get("verdict","?")
    risk    = result.get("unified_risk", 0.0)
    conf    = result.get("confidence", 0.0)
    corrs   = result.get("correlations", [])
    recs    = result.get("recommendations", [])
    chain   = result.get("attack_chain", [])
    if _RICH:
        color = _color(verdict)
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        t.add_column("key",   style="dim", width=18)
        t.add_column("value", style="white")
        t.add_row("Verdict",      f"[{color} bold]{verdict.upper()}[/{color} bold]")
        t.add_row("Unified risk", _risk_bar(risk))
        t.add_row("Confidence",   f"{conf:.2f}")
        if corrs:
            t.add_row("Correlations", "\n".join(f"• {c}" for c in corrs))
        if chain:
            t.add_row("Attack chain", " → ".join(chain))
        if result.get("reasoning") and not quiet:
            t.add_row("Reasoning", result["reasoning"][:350])
        if recs and not quiet:
            t.add_row("Recommendations",
                      "\n".join(f"{i+1}. {r}" for i,r in enumerate(recs)))
        console.print(Panel(t, title="[bold]UNIFIED THREAT ASSESSMENT[/bold]",
                            border_style=color))
    else:
        print(f"\n{'═'*60}\n  UNIFIED: verdict={verdict.upper()}  "
              f"risk={_risk_bar(risk)}")
        if recs and not quiet:
            for i,r in enumerate(recs,1):
                print(f"  {i}. {r}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# File picker — interactive selector from a directory
# ══════════════════════════════════════════════════════════════════════════════

def _pick_file(directory: str, extensions: list[str], label: str) -> str | None:
    """
    Interactive file picker.
    Lists files in *directory* matching *extensions*, user selects one.
    Returns file contents as string, or None if cancelled.
    """
    d = Path(directory)
    if not d.exists():
        log.error("Directory not found: %s", directory)
        return None

    files = sorted([
        f for f in d.rglob("*")
        if f.is_file() and (not extensions or f.suffix.lower() in extensions)
    ])

    if not files:
        log.error("No matching files found in %s (extensions=%s)", directory, extensions)
        return None

    print(f"\n  {label} — select a file from {directory}:")
    print(f"  {'─'*48}")
    for i, f in enumerate(files[:50], 1):
        size = f.stat().st_size
        print(f"  {i:3d}.  {f.relative_to(d)}  [{size:,} bytes]")
    print(f"  {'─'*48}")
    print(f"   0.  Cancel")

    while True:
        try:
            choice = input(f"\n  Enter number (1-{min(len(files),50)}) or 0 to cancel: ").strip()
            n = int(choice)
            if n == 0:
                return None
            if 1 <= n <= min(len(files), 50):
                selected = files[n-1]
                print(f"  Selected: {selected.name}\n")
                return selected.read_text(encoding="utf-8", errors="replace")
            print(f"  Invalid choice — enter 1-{min(len(files),50)} or 0")
        except (ValueError, KeyboardInterrupt):
            return None


# ══════════════════════════════════════════════════════════════════════════════
# Environment check
# ══════════════════════════════════════════════════════════════════════════════

def _check_environment() -> bool:
    import shutil
    from tools.faiss_store import is_index_ready
    ok = True
    checks = []

    checks.append(("GROQ_API_KEY",
                   "✓" if os.getenv("GROQ_API_KEY") else "✗",
                   "set" if os.getenv("GROQ_API_KEY") else "MISSING"))
    checks.append(("NVD_API_KEY",
                   "~" if not os.getenv("NVD_API_KEY") else "✓",
                   "set" if os.getenv("NVD_API_KEY") else "not set (rate limited)"))
    checks.append(("ABUSEIPDB_API_KEY",
                   "✓" if os.getenv("ABUSEIPDB_API_KEY") else "~",
                   "set" if os.getenv("ABUSEIPDB_API_KEY") else "not set (threat intel disabled)"))
    checks.append(("VIRUSTOTAL_API_KEY",
                   "✓" if os.getenv("VIRUSTOTAL_API_KEY") else "~",
                   "set" if os.getenv("VIRUSTOTAL_API_KEY") else "not set"))
    checks.append(("IMAP_USER",
                   "✓" if os.getenv("IMAP_USER") else "~",
                   "set" if os.getenv("IMAP_USER") else "not set (IMAP watch disabled)"))
    checks.append(("NOTIFY_SMTP_USER",
                   "✓" if os.getenv("NOTIFY_SMTP_USER") else "~",
                   "set" if os.getenv("NOTIFY_SMTP_USER") else "not set (notifications disabled)"))
    checks.append(("nmap binary",
                   "✓" if shutil.which("nmap") else "~",
                   "found" if shutil.which("nmap") else "not found (ip_agent disabled)"))
    checks.append(("FAISS index",
                   "✓" if is_index_ready() else "~",
                   "ready" if is_index_ready() else "not built — run --build-index"))

    if not os.getenv("GROQ_API_KEY"):
        ok = False

    print("\n  Environment check:")
    print("  " + "─"*50)
    for name, status, detail in checks:
        sym = {"✓":"OK","✗":"FAIL","~":"WARN"}.get(status,"?")
        print(f"  [{sym:4}] {name:<22} {detail}")
    print()
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ══════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyber-mas",
        description="Cyber-MAS — Multi-Agent Cybersecurity Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Standard mode inputs ──────────────────────────────────────────────────
    si = p.add_argument_group("Standard mode — direct inputs")
    si.add_argument("--email",      metavar="FILE",   help="Email file (.eml/.txt)")
    si.add_argument("--email-text", metavar="TEXT",   help="Raw email string")
    si.add_argument("--email-dir",  metavar="DIR",    help="Pick email from directory")
    si.add_argument("--log",        metavar="FILE",   help="Log file")
    si.add_argument("--log-text",   metavar="TEXT",   help="Raw log text")
    si.add_argument("--log-dir",    metavar="DIR",    help="Pick log from directory")
    si.add_argument("--ip",         metavar="TARGET", help="IP / hostname / CIDR")
    si.add_argument("--ip-text",    metavar="TARGET", help="Alias for --ip")

    # ── Standard mode output ──────────────────────────────────────────────────
    so = p.add_argument_group("Standard mode — output")
    so.add_argument("--output",       metavar="FILE",  help="Save JSON report")
    so.add_argument("--quiet",        action="store_true")
    so.add_argument("--no-correlate", action="store_true")
    so.add_argument("--json",         action="store_true", help="Raw JSON to stdout")

    # ── Continuous monitoring mode ────────────────────────────────────────────
    cm = p.add_argument_group("Continuous monitoring mode")
    cm.add_argument("--watch-log",         metavar="FILE",   help="Tail this log file")
    cm.add_argument("--watch-email-imap",  action="store_true", help="Poll IMAP inbox")
    cm.add_argument("--watch-ip",          metavar="TARGET", help="Recurring Nmap scan")
    cm.add_argument("--watch-all",         action="store_true",
                    help="Enable all configured watchers simultaneously")
    cm.add_argument("--interval",          type=int, default=60,
                    help="Log/IMAP check interval in seconds (default: 60)")
    cm.add_argument("--ip-interval",       type=int, default=300,
                    help="IP scan interval in seconds (default: 300)")
    cm.add_argument("--log-min-lines",     type=int, default=3,
                    help="Min new log lines to trigger analysis (default: 3)")
    cm.add_argument("--alert-log",         metavar="FILE", default="alerts.jsonl",
                    help="Alert log file path (default: alerts.jsonl)")
    cm.add_argument("--no-notify",         action="store_true",
                    help="Disable email notifications in watch mode")
    cm.add_argument("--min-severity",      type=int, default=1,
                    help="Min alert severity to notify (1=low,2=suspicious,3=high,4=critical)")

    # ── Utility ───────────────────────────────────────────────────────────────
    ut = p.add_argument_group("Utility")
    ut.add_argument("--build-index",   action="store_true")
    ut.add_argument("--force-rebuild", action="store_true")
    ut.add_argument("--check",         action="store_true")
    ut.add_argument("--monitor-status",action="store_true",
                    help="Show watch mode config without starting")
    ut.add_argument("--verbose",       action="store_true")

    return p


# ══════════════════════════════════════════════════════════════════════════════
# Standard mode pipeline
# ══════════════════════════════════════════════════════════════════════════════

def _load_file(path: str, label: str) -> str:
    p = Path(path)
    if not p.exists():
        log.error("%s file not found: %s", label, path)
        sys.exit(1)
    return p.read_text(encoding="utf-8", errors="replace")


def run_standard(args: argparse.Namespace) -> dict:
    from agents.dispatcher import dispatch
    from agents.correlator import correlate

    report: dict = {
        "meta":       {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")},
        "agents":     [],
        "correlator": None,
    }
    agent_results: list[dict] = []
    quiet = args.quiet or args.json
    tasks: list[dict] = []

    # ── Resolve email input ───────────────────────────────────────────────────
    email_text = None
    if args.email_text:
        email_text = args.email_text
    elif args.email:
        email_text = _load_file(args.email, "email")
    elif args.email_dir:
        email_text = _pick_file(args.email_dir, [".eml", ".txt", ""], "EMAIL")
        if not email_text:
            log.info("No email selected — skipping email agent")
    if email_text:
        tasks.append({"type": "email", "payload": email_text})

    # ── Resolve log input ─────────────────────────────────────────────────────
    log_text = None
    if args.log_text:
        log_text = args.log_text
    elif args.log:
        log_text = _load_file(args.log, "log")
    elif args.log_dir:
        log_text = _pick_file(args.log_dir, [".log", ".txt", ""], "LOG")
        if not log_text:
            log.info("No log selected — skipping log agent")
    if log_text:
        tasks.append({"type": "log", "payload": log_text})

    # ── Resolve IP input ──────────────────────────────────────────────────────
    ip_target = args.ip or args.ip_text
    if ip_target:
        tasks.append({"type": "ip", "payload": ip_target})

    if not tasks:
        log.error("No input provided. Use --email, --log, --ip or their -dir / -text variants.")
        sys.exit(1)

    # ── Run agents ────────────────────────────────────────────────────────────
    for task in tasks:
        t_type = task["type"].upper()
        log.info("Dispatching: %s", t_type)
        t0 = time.perf_counter()
        try:
            result = dispatch(task)
        except Exception as exc:
            log.error("%s agent failed: %s", t_type, exc)
            result = {
                "agent": task["type"], "verdict": "uncertain",
                "risk_score": 0.0, "confidence": 0.0,
                "reasoning": str(exc), "indicators": [],
            }
        result["_duration_secs"] = round(time.perf_counter() - t0, 2)
        agent_results.append(result)
        report["agents"].append(result)
        if not args.json:
            _print_agent_result(result, quiet=quiet)

    # ── Correlate ─────────────────────────────────────────────────────────────
    if not args.no_correlate:
        log.info("Running correlator …")
        t0 = time.perf_counter()
        try:
            corr = correlate(agent_results)
        except Exception as exc:
            log.error("Correlator failed: %s", exc)
            corr = {
                "agent":"correlator","verdict":"uncertain","unified_risk":0.0,
                "confidence":0.0,"reasoning":str(exc),"correlations":[],
                "recommendations":[],"agent_summary":{},"indicators":[],
                "unified_indicators":[],"memory_matches":[],"mitre_techniques":[],
            }
        corr["_duration_secs"] = round(time.perf_counter() - t0, 2)
        report["correlator"] = corr
        if not args.json:
            _print_correlator_result(corr, quiet=quiet)

        # ── Notify ────────────────────────────────────────────────────────────
        if not args.json:
            try:
                from tools.notifier import notify
                notify(report)
            except Exception as exc:
                log.warning("Notification failed (non-fatal): %s", exc)

    return report


# ══════════════════════════════════════════════════════════════════════════════
# Continuous monitoring mode
# ══════════════════════════════════════════════════════════════════════════════

def run_monitor(args: argparse.Namespace) -> None:
    from monitor import MonitorEngine

    engine = MonitorEngine(
        alert_log    = args.alert_log,
        notify       = not args.no_notify,
        min_severity = args.min_severity,
    )

    # Determine which watchers to add
    watch_log   = args.watch_log
    watch_imap  = args.watch_email_imap
    watch_ip    = args.watch_ip

    # --watch-all enables everything that is configured
    if args.watch_all:
        watch_imap = True
        if not watch_log and not watch_ip:
            log.warning(
                "--watch-all set but neither --watch-log nor --watch-ip provided. "
                "Only IMAP watcher will start."
            )

    if not watch_log and not watch_imap and not watch_ip:
        log.error(
            "No watchers configured. Add one or more of:\n"
            "  --watch-log FILE\n"
            "  --watch-email-imap\n"
            "  --watch-ip TARGET\n"
            "  --watch-all"
        )
        sys.exit(1)

    if watch_log:
        engine.add_log_watcher(
            watch_log,
            interval  = args.interval,
            min_lines = args.log_min_lines,
        )
        log.info("Log watcher configured: %s (interval=%ds)", watch_log, args.interval)

    if watch_imap:
        imap_configured = bool(os.getenv("IMAP_USER") and os.getenv("IMAP_PASS"))
        if not imap_configured:
            log.error(
                "IMAP watch requested but IMAP_USER or IMAP_PASS not set in .env\n"
                "Add:\n  IMAP_HOST=imap.gmail.com\n  IMAP_USER=you@gmail.com\n"
                "  IMAP_PASS=your-app-password"
            )
            sys.exit(1)
        engine.add_imap_watcher(interval=args.interval)
        log.info("IMAP watcher configured (interval=%ds)", args.interval)

    if watch_ip:
        engine.add_ip_watcher(
            watch_ip,
            interval = args.ip_interval,
            drift    = 0.10,
        )
        log.info("IP watcher configured: %s (interval=%ds)", watch_ip, args.ip_interval)

    if args.monitor_status:
        print("\n  Watch mode configuration:")
        for w in engine.status()["watchers"]:
            print(f"    {w['name']}  interval={w['interval']}s")
        print()
        return

    engine.run()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load .env
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

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

    # ── Detect mode ───────────────────────────────────────────────────────────
    is_watch_mode = any([
        args.watch_log,
        args.watch_email_imap,
        args.watch_ip,
        args.watch_all,
        args.monitor_status,
    ])

    if is_watch_mode:
        # ── Continuous monitoring mode ─────────────────────────────────────
        run_monitor(args)

    else:
        # ── Standard mode ──────────────────────────────────────────────────
        t0     = time.perf_counter()
        report = run_standard(args)
        elapsed= time.perf_counter() - t0
        report.setdefault("meta",{})["total_duration_secs"] = round(elapsed, 2)

        if args.json:
            print(json.dumps(report, indent=2, default=str))

        if args.output:
            out = Path(args.output)
            out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            if not args.json:
                if _RICH:
                    console.print(f"[dim]Report saved → {out}[/dim]")
                else:
                    print(f"  Report saved → {out}")

        if not args.json:
            if _RICH:
                console.print(f"[dim]Total time: {elapsed:.1f}s[/dim]\n")
            else:
                print(f"  Total time: {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()