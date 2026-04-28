"""
cyber_mas/monitor.py
══════════════════════════════════════════════════════════════════════════════
Continuous Monitoring Engine — three parallel watchers.

WATCHERS
────────
  LogWatcher        — tails a log file, feeds new lines to log_agent
  EmailImapWatcher  — polls an IMAP mailbox for UNSEEN emails
  IPWatcher         — recurring Nmap scans, diffs against previous result

ALERT PIPELINE (on high-risk finding)
──────────────────────────────────────
  1. Print colour-coded alert to terminal
  2. Send email notification with PDF report attached
  3. Append structured entry to alert log file (JSONL format)

THREADING MODEL
───────────────
  Each watcher runs in its own daemon thread.
  A shared AlertQueue (thread-safe) collects findings.
  The main thread drains the queue: prints + notifies + logs.
  Ctrl-C cleanly stops all watchers.

IMAP CONFIG (.env)
──────────────────
  IMAP_HOST       e.g. imap.gmail.com
  IMAP_PORT       993 (SSL) or 143 (STARTTLS)
  IMAP_USER       your-email@gmail.com
  IMAP_PASS       app-password (Gmail) or regular password
  IMAP_FOLDER     INBOX  (default)
  IMAP_SSL        true   (default)
  IMAP_MARK_READ  false  (whether to mark analysed emails as read)

USAGE
─────
  # From main.py (preferred)
  python main.py --watch-log /var/log/auth.log --watch-ip 192.168.1.1
  python main.py --watch-email-imap --interval 60
  python main.py --watch-all --log /var/log/auth.log --ip 10.0.0.5

  # Direct import
  from cyber_mas.monitor import MonitorEngine
  engine = MonitorEngine(alert_log="alerts.jsonl")
  engine.add_log_watcher("/var/log/auth.log", interval=30)
  engine.add_imap_watcher(interval=60)
  engine.add_ip_watcher("192.168.1.1", interval=300)
  engine.run()   # blocks until Ctrl-C
"""

from __future__ import annotations

import imaplib
import email as email_lib
import json
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

# ── Colour codes for terminal output ─────────────────────────────────────────
_R  = "\033[31m"   # red
_Y  = "\033[33m"   # yellow
_G  = "\033[32m"   # green
_C  = "\033[36m"   # cyan
_M  = "\033[35m"   # magenta
_B  = "\033[1m"    # bold
_DIM= "\033[2m"    # dim
_RS = "\033[0m"    # reset

_VERDICT_COLOR = {
    "critical":   _R + _B,
    "high":       _R,
    "medium":     _Y,
    "low":        _G,
    "phishing":   _R + _B,
    "malicious":  _R + _B,
    "vulnerable": _Y,
    "suspicious": _Y,
    "legitimate": _G,
    "benign":     _G,
    "clean":      _G,
    "uncertain":  _DIM,
}

def _vc(verdict: str) -> str:
    return _VERDICT_COLOR.get((verdict or "").lower(), _DIM)

# ── Alert severity ordering ───────────────────────────────────────────────────
_SEVERITY = {
    "critical": 5, "malicious": 5, "phishing": 4,
    "high": 4, "vulnerable": 3, "suspicious": 3,
    "medium": 3, "low": 1, "benign": 0, "clean": 0,
    "legitimate": 0, "uncertain": 1,
}

def _sev(verdict: str) -> int:
    return _SEVERITY.get((verdict or "").lower(), 1)


# ══════════════════════════════════════════════════════════════════════════════
# Alert dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Alert:
    alert_id:   str
    timestamp:  str
    source:     str          # "log_watcher" | "imap_watcher" | "ip_watcher"
    verdict:    str
    risk_score: float
    summary:    str          # one-line human description
    report:     dict = field(default_factory=dict)   # full pipeline report
    severity:   int  = 0

    def __post_init__(self):
        self.severity = _sev(self.verdict)

    def to_jsonl(self) -> str:
        return json.dumps({
            "alert_id":  self.alert_id,
            "timestamp": self.timestamp,
            "source":    self.source,
            "verdict":   self.verdict,
            "risk_score":self.risk_score,
            "summary":   self.summary,
        }, ensure_ascii=False)

    def to_terminal(self) -> str:
        vc  = _vc(self.verdict)
        ts  = self.timestamp[11:19]   # HH:MM:SS
        bar = "█" * int(self.risk_score * 20) + "░" * (20 - int(self.risk_score * 20))
        return (
            f"\n{_B}{'─'*64}{_RS}\n"
            f"  {_C}[{ts}]{_RS}  {_B}{self.source.upper()}{_RS}\n"
            f"  Verdict   : {vc}{self.verdict.upper()}{_RS}\n"
            f"  Risk      : {vc}{bar}{_RS} {self.risk_score:.2f}\n"
            f"  Summary   : {self.summary}\n"
            f"{_B}{'─'*64}{_RS}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Shared alert queue
# ══════════════════════════════════════════════════════════════════════════════

class AlertQueue:
    """Thread-safe queue for alerts produced by watchers."""
    def __init__(self):
        self._q: queue.Queue[Alert] = queue.Queue()

    def put(self, alert: Alert):
        self._q.put(alert)

    def drain(self, timeout: float = 0.2) -> list[Alert]:
        alerts = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                alerts.append(self._q.get_nowait())
            except queue.Empty:
                break
        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# Base watcher
# ══════════════════════════════════════════════════════════════════════════════

class BaseWatcher(threading.Thread):
    """Base class for all watchers — runs as a daemon thread."""

    def __init__(self, alert_queue: AlertQueue, interval: int, name: str):
        super().__init__(daemon=True, name=name)
        self.alert_queue = alert_queue
        self.interval    = interval
        self._stop_event = threading.Event()
        self._running    = False

    def stop(self):
        self._stop_event.set()

    def _should_stop(self) -> bool:
        return self._stop_event.is_set()

    def _sleep_interval(self):
        """Sleep interval seconds, waking every second to check stop event."""
        for _ in range(self.interval):
            if self._stop_event.is_set():
                return
            time.sleep(1)

    def _make_report(self, payload: dict, source: str) -> dict:
        """Run the full dispatcher + correlator pipeline and return report."""
        from agents.dispatcher import dispatch
        from agents.correlator import correlate

        report_id     = str(uuid.uuid4())[:8]
        agent_result  = dispatch(payload)
        corr_result   = correlate([agent_result], report_id=report_id)

        return {
            "report_id": report_id,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "agents":    [agent_result],
            "correlator": corr_result,
        }

    def _emit_alert(self, source: str, verdict: str, risk: float,
                    summary: str, report: dict):
        alert = Alert(
            alert_id  = str(uuid.uuid4())[:8],
            timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            source    = source,
            verdict   = verdict,
            risk_score= risk,
            summary   = summary,
            report    = report,
        )
        self.alert_queue.put(alert)

    def watch(self):
        """Override in subclasses — called once per interval."""
        raise NotImplementedError

    def run(self):
        self._running = True
        log.info("[%s] started (interval=%ds)", self.name, self.interval)
        while not self._should_stop():
            try:
                self.watch()
            except Exception as exc:
                log.error("[%s] unhandled error: %s", self.name, exc)
            self._sleep_interval()
        log.info("[%s] stopped", self.name)


# ══════════════════════════════════════════════════════════════════════════════
# Log Watcher — tail a log file
# ══════════════════════════════════════════════════════════════════════════════

class LogWatcher(BaseWatcher):
    """
    Tails a log file. Every `interval` seconds, reads new lines appended
    since the last check and feeds them to the log agent.

    Emits an alert whenever verdict is not 'benign' / 'uncertain'.
    """

    def __init__(
        self,
        log_path:    str,
        alert_queue: AlertQueue,
        interval:    int  = 30,
        min_lines:   int  = 3,    # minimum new lines to trigger analysis
        min_severity:int  = 1,    # alert if severity >= this
    ):
        super().__init__(alert_queue, interval, name="LogWatcher")
        self.log_path     = Path(log_path)
        self.min_lines    = min_lines
        self.min_severity = min_severity
        self._file_pos    = 0     # byte offset into file
        self._last_result: dict | None = None

    def _read_new_lines(self) -> list[str]:
        """Read lines appended since last check."""
        if not self.log_path.exists():
            log.warning("[LogWatcher] file not found: %s", self.log_path)
            return []

        lines = []
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace") as f:
                # Handle log rotation — file shrunk
                size = self.log_path.stat().st_size
                if size < self._file_pos:
                    log.info("[LogWatcher] log rotation detected — resetting position")
                    self._file_pos = 0

                f.seek(self._file_pos)
                new_content = f.read()
                self._file_pos = f.tell()
                lines = [l for l in new_content.splitlines() if l.strip()]
        except OSError as e:
            log.error("[LogWatcher] cannot read %s: %s", self.log_path, e)

        return lines

    def watch(self):
        new_lines = self._read_new_lines()

        if len(new_lines) < self.min_lines:
            if new_lines:
                log.debug("[LogWatcher] %d new line(s) — below threshold %d",
                          len(new_lines), self.min_lines)
            return

        log.info("[LogWatcher] %d new line(s) — analysing …", len(new_lines))

        try:
            report = self._make_report(
                {"type": "log", "payload": "\n".join(new_lines)},
                source="log_watcher",
            )
        except Exception as exc:
            log.error("[LogWatcher] analysis failed: %s", exc)
            return

        corr    = report.get("correlator", {})
        verdict = corr.get("verdict", "uncertain")
        risk    = corr.get("unified_risk", 0.0)
        sigs    = report["agents"][0].get("signatures_hit", [])

        summary = (
            f"{len(new_lines)} new log lines | "
            f"sigs={sigs or 'none'} | "
            f"risk={risk:.2f} | "
            f"{self.log_path.name}"
        )

        if _sev(verdict) >= self.min_severity:
            self._emit_alert("log_watcher", verdict, risk, summary, report)
        else:
            log.info("[LogWatcher] verdict=%s risk=%.2f — below alert threshold",
                     verdict, risk)


# ══════════════════════════════════════════════════════════════════════════════
# IMAP Email Watcher
# ══════════════════════════════════════════════════════════════════════════════

class EmailImapWatcher(BaseWatcher):
    """
    Polls an IMAP mailbox for UNSEEN emails.
    Each new email is fetched, analysed by the email agent,
    and optionally marked as read.
    """

    def __init__(
        self,
        alert_queue:  AlertQueue,
        interval:     int  = 60,
        min_severity: int  = 2,     # alert if severity >= this (2 = suspicious)
        mark_read:    bool = False,
        # IMAP credentials — loaded from env if not passed
        host:   str | None = None,
        port:   int | None = None,
        user:   str | None = None,
        password: str | None = None,
        folder: str = "INBOX",
        use_ssl:bool = True,
    ):
        super().__init__(alert_queue, interval, name="ImapWatcher")
        self.min_severity = min_severity
        self.mark_read    = mark_read
        self._load_config(host, port, user, password, folder, use_ssl)
        self._processed_uids: set[bytes] = set()

    def _load_config(self, host, port, user, password, folder, use_ssl):
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass

        self.host    = host     or os.getenv("IMAP_HOST",   "imap.gmail.com")
        self.port    = port     or int(os.getenv("IMAP_PORT", "993"))
        self.user    = user     or os.getenv("IMAP_USER",   "")
        self.password= password or os.getenv("IMAP_PASS",   "")
        self.folder  = folder   or os.getenv("IMAP_FOLDER", "INBOX")
        self.use_ssl = use_ssl
        if os.getenv("IMAP_SSL", "true").lower() == "false":
            self.use_ssl = False
        if os.getenv("IMAP_MARK_READ", "false").lower() == "true":
            self.mark_read = True

    def _connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL | None:
        """Connect and authenticate to the IMAP server."""
        if not self.user or not self.password:
            log.error("[ImapWatcher] IMAP_USER or IMAP_PASS not set in .env")
            return None
        try:
            if self.use_ssl:
                conn = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                conn = imaplib.IMAP4(self.host, self.port)
                conn.starttls()
            conn.login(self.user, self.password)
            log.debug("[ImapWatcher] connected to %s:%d as %s", self.host, self.port, self.user)
            return conn
        except imaplib.IMAP4.error as e:
            log.error("[ImapWatcher] IMAP connection failed: %s", e)
            return None
        except OSError as e:
            log.error("[ImapWatcher] network error: %s", e)
            return None

    def _fetch_unseen(self, conn: imaplib.IMAP4) -> list[tuple[bytes, str]]:
        """
        Fetch UNSEEN emails from the mailbox.
        Returns list of (uid, raw_email_text) tuples.
        """
        try:
            conn.select(self.folder, readonly=not self.mark_read)
            _, uid_data = conn.uid("search", None, "UNSEEN")
            uids = uid_data[0].split() if uid_data and uid_data[0] else []
        except imaplib.IMAP4.error as e:
            log.error("[ImapWatcher] search failed: %s", e)
            return []

        results = []
        for uid in uids:
            if uid in self._processed_uids:
                continue
            try:
                _, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if msg_data and msg_data[0]:
                    raw = msg_data[0][1]
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    results.append((uid, raw))
                    if self.mark_read:
                        conn.uid("store", uid, "+FLAGS", "\\Seen")
            except Exception as e:
                log.warning("[ImapWatcher] fetch uid %s failed: %s", uid, e)

        return results

    def _extract_subject(self, raw_email: str) -> str:
        """Extract subject line for display."""
        try:
            msg = email_lib.message_from_string(raw_email)
            return msg.get("Subject", "(no subject)")[:80]
        except Exception:
            return "(unknown subject)"

    def watch(self):
        conn = self._connect()
        if conn is None:
            return

        try:
            emails = self._fetch_unseen(conn)
            if not emails:
                log.debug("[ImapWatcher] no new UNSEEN emails")
                return

            log.info("[ImapWatcher] %d new email(s) to analyse", len(emails))

            for uid, raw_email in emails:
                subject = self._extract_subject(raw_email)
                log.info("[ImapWatcher] analysing: %s", subject[:60])

                try:
                    report = self._make_report(
                        {"type": "email", "payload": raw_email},
                        source="imap_watcher",
                    )
                except Exception as exc:
                    log.error("[ImapWatcher] analysis failed for uid %s: %s", uid, exc)
                    self._processed_uids.add(uid)
                    continue

                corr    = report.get("correlator", {})
                verdict = corr.get("verdict", "uncertain")
                risk    = corr.get("unified_risk", 0.0)

                summary = (
                    f"Subject: {subject} | "
                    f"verdict={verdict} | "
                    f"risk={risk:.2f} | "
                    f"from={report['agents'][0].get('email_metadata',{}).get('sender','?')[:40]}"
                )

                if _sev(verdict) >= self.min_severity:
                    self._emit_alert("imap_watcher", verdict, risk, summary, report)
                else:
                    log.info("[ImapWatcher] verdict=%s risk=%.2f — below threshold",
                             verdict, risk)

                self._processed_uids.add(uid)

                # Small delay between emails to avoid hammering the LLM
                time.sleep(2)

        finally:
            try:
                conn.logout()
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# IP Watcher — recurring Nmap scans
# ══════════════════════════════════════════════════════════════════════════════

class IPWatcher(BaseWatcher):
    """
    Runs recurring Nmap scans against a target.
    Alerts when:
      - verdict changes from previous scan
      - new open ports are discovered
      - risk score increases by more than drift_threshold
      - new CVEs are found
    """

    def __init__(
        self,
        target:          str,
        alert_queue:     AlertQueue,
        interval:        int   = 300,   # 5 minutes default
        drift_threshold: float = 0.10,  # alert if risk changes by this much
        min_severity:    int   = 2,
    ):
        super().__init__(alert_queue, interval, name=f"IPWatcher({target})")
        self.target          = target
        self.drift_threshold = drift_threshold
        self.min_severity    = min_severity
        self._prev_result: dict | None = None
        self._scan_count     = 0

    def _diff_scan(self, current: dict, previous: dict) -> list[str]:
        """
        Compare current scan result against previous.
        Returns a list of change descriptions.
        """
        changes = []
        corr_curr = current.get("correlator", {})
        corr_prev = previous.get("correlator", {})

        # Verdict change
        v_curr = corr_curr.get("verdict", "")
        v_prev = corr_prev.get("verdict", "")
        if v_curr != v_prev:
            changes.append(f"verdict changed: {v_prev} → {v_curr}")

        # Risk drift
        r_curr = corr_curr.get("unified_risk", 0.0)
        r_prev = corr_prev.get("unified_risk", 0.0)
        drift  = r_curr - r_prev
        if abs(drift) >= self.drift_threshold:
            direction = "↑" if drift > 0 else "↓"
            changes.append(f"risk {direction} {r_prev:.2f} → {r_curr:.2f} (Δ{drift:+.2f})")

        # New open ports
        curr_agent = next((a for a in current.get("agents", []) if a.get("agent") == "ip"), {})
        prev_agent = next((a for a in previous.get("agents", []) if a.get("agent") == "ip"), {})

        curr_ports = {p["port"] for p in curr_agent.get("open_ports", [])}
        prev_ports = {p["port"] for p in prev_agent.get("open_ports", [])}
        new_ports  = curr_ports - prev_ports
        closed     = prev_ports - curr_ports

        if new_ports:
            changes.append(f"new open ports: {sorted(new_ports)}")
        if closed:
            changes.append(f"ports closed: {sorted(closed)}")

        # New CVEs
        curr_cves = {c["cve_id"] for c in curr_agent.get("cves", [])}
        prev_cves = {c["cve_id"] for c in prev_agent.get("cves", [])}
        new_cves  = curr_cves - prev_cves
        if new_cves:
            changes.append(f"new CVEs detected: {new_cves}")

        return changes

    def watch(self):
        self._scan_count += 1
        log.info("[IPWatcher] scan #%d for %s …", self._scan_count, self.target)

        try:
            report = self._make_report(
                {"type": "ip", "payload": self.target},
                source="ip_watcher",
            )
        except Exception as exc:
            log.error("[IPWatcher] analysis failed: %s", exc)
            return

        corr    = report.get("correlator", {})
        verdict = corr.get("verdict", "uncertain")
        risk    = corr.get("unified_risk", 0.0)

        # First scan — always emit if severity meets threshold
        if self._prev_result is None:
            log.info("[IPWatcher] baseline scan complete — verdict=%s risk=%.2f",
                     verdict, risk)
            if _sev(verdict) >= self.min_severity:
                agent = next((a for a in report.get("agents",[]) if a.get("agent")=="ip"), {})
                ports = [p["port"] for p in agent.get("open_ports", [])]
                summary = (
                    f"Baseline scan: {self.target} | "
                    f"verdict={verdict} | risk={risk:.2f} | "
                    f"ports={ports[:8]} | "
                    f"cves={len(agent.get('cves',[]))}"
                )
                self._emit_alert("ip_watcher", verdict, risk, summary, report)
        else:
            # Subsequent scans — diff against previous
            changes = self._diff_scan(report, self._prev_result)
            if changes:
                summary = (
                    f"Scan #{self._scan_count}: {self.target} | "
                    f"CHANGES: {' | '.join(changes)} | "
                    f"verdict={verdict} risk={risk:.2f}"
                )
                log.info("[IPWatcher] changes detected: %s", changes)
                self._emit_alert("ip_watcher", verdict, risk, summary, report)
            else:
                log.info("[IPWatcher] scan #%d — no changes detected (verdict=%s risk=%.2f)",
                         self._scan_count, verdict, risk)

        self._prev_result = report


# ══════════════════════════════════════════════════════════════════════════════
# Alert handler — drains queue, prints, notifies, logs
# ══════════════════════════════════════════════════════════════════════════════

class AlertHandler:
    """
    Drains the alert queue and dispatches each alert to:
      1. Terminal (always)
      2. Email notification (if notifier is configured)
      3. Alert log file (JSONL)
    """

    def __init__(
        self,
        alert_log:    str  = "alerts.jsonl",
        notify:       bool = True,
        min_severity: int  = 1,
    ):
        self.alert_log    = Path(alert_log)
        self.notify       = notify
        self.min_severity = min_severity
        self.alert_log.parent.mkdir(parents=True, exist_ok=True)
        self._notifier_available = self._check_notifier()

    def _check_notifier(self) -> bool:
        try:
            from tools.notifier import notify as _notify
            return True
        except ImportError:
            return False

    def handle(self, alert: Alert):
        """Process a single alert through all three channels."""

        # 1. Terminal
        print(alert.to_terminal())

        # 2. Alert log file (JSONL — one JSON object per line)
        try:
            with self.alert_log.open("a", encoding="utf-8") as f:
                f.write(alert.to_jsonl() + "\n")
            log.debug("Alert written to %s", self.alert_log)
        except OSError as e:
            log.error("Failed to write alert log: %s", e)

        # 3. Email notification
        if self.notify and self._notifier_available and alert.severity >= self.min_severity:
            try:
                from tools.notifier import notify as send_notify
                # Run in background thread to not block the handler
                t = threading.Thread(
                    target=send_notify,
                    args=(alert.report,),
                    daemon=True,
                    name=f"Notify-{alert.alert_id}",
                )
                t.start()
                log.info("Email notification dispatched for alert %s", alert.alert_id)
            except Exception as exc:
                log.warning("Failed to dispatch notification: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# Monitor Engine — orchestrates all watchers
# ══════════════════════════════════════════════════════════════════════════════

class MonitorEngine:
    """
    Orchestrates multiple watchers running in parallel threads.
    Drains the shared alert queue in the main thread.
    """

    def __init__(
        self,
        alert_log:    str  = "alerts.jsonl",
        notify:       bool = True,
        min_severity: int  = 1,
    ):
        self._alert_queue  = AlertQueue()
        self._watchers:    list[BaseWatcher] = []
        self._handler      = AlertHandler(alert_log, notify, min_severity)
        self._running      = False

    def add_log_watcher(
        self,
        log_path:  str,
        interval:  int = 30,
        min_lines: int = 3,
    ) -> "MonitorEngine":
        w = LogWatcher(log_path, self._alert_queue, interval, min_lines)
        self._watchers.append(w)
        return self

    def add_imap_watcher(
        self,
        interval:  int  = 60,
        mark_read: bool = False,
        **kwargs,
    ) -> "MonitorEngine":
        w = EmailImapWatcher(self._alert_queue, interval, mark_read=mark_read, **kwargs)
        self._watchers.append(w)
        return self

    def add_ip_watcher(
        self,
        target:   str,
        interval: int   = 300,
        drift:    float = 0.10,
    ) -> "MonitorEngine":
        w = IPWatcher(target, self._alert_queue, interval, drift)
        self._watchers.append(w)
        return self

    def _print_startup_banner(self):
        print(f"\n{_B}{'═'*64}{_RS}")
        print(f"  {_C}{_B}CYBER-MAS — CONTINUOUS MONITORING{_RS}")
        print(f"{'═'*64}")
        for w in self._watchers:
            print(f"  {_G}▸{_RS} {w.name}  (interval={w.interval}s)")
        print(f"{'─'*64}")
        print(f"  {_DIM}Ctrl-C to stop  |  Alerts → {self._handler.alert_log}{_RS}")
        print(f"{'═'*64}\n")

    def _print_status(self, cycle: int):
        ts = datetime.now().strftime("%H:%M:%S")
        active = sum(1 for w in self._watchers if w.is_alive())
        print(
            f"\r{_DIM}[{ts}] monitoring active — "
            f"{active}/{len(self._watchers)} watchers running  "
            f"cycle #{cycle}{_RS}",
            end="", flush=True,
        )

    def run(self):
        """Start all watchers and block until Ctrl-C."""
        if not self._watchers:
            log.error("No watchers configured — nothing to monitor")
            return

        self._print_startup_banner()

        # Start all watcher threads
        for w in self._watchers:
            w.start()

        self._running = True
        cycle = 0

        try:
            while self._running:
                cycle += 1

                # Drain alert queue
                alerts = self._alert_queue.drain(timeout=1.0)
                for alert in alerts:
                    self._handler.handle(alert)

                # Status line (overwritten each second)
                if not alerts:
                    self._print_status(cycle)

                # Check if all watchers have died
                if not any(w.is_alive() for w in self._watchers):
                    log.error("All watchers have stopped — exiting")
                    break

                time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n\n{_Y}  Stopping all watchers …{_RS}")

        finally:
            for w in self._watchers:
                w.stop()
            # Drain any remaining alerts
            remaining = self._alert_queue.drain(timeout=2.0)
            for alert in remaining:
                self._handler.handle(alert)
            print(f"  {_G}Monitor stopped cleanly.{_RS}\n")

    def status(self) -> dict:
        """Return current status of all watchers."""
        return {
            "running":  self._running,
            "watchers": [
                {
                    "name":    w.name,
                    "alive":   w.is_alive(),
                    "interval":w.interval,
                }
                for w in self._watchers
            ],
        }