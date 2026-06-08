"""
sin.hardware.burnin
════════════════════
Burn-in telemetry agent — hardware quality gate for IoT device manufacturers.

Runs continuous telemetry polling against a device for a configured duration,
collecting CPU load, memory usage, uptime, and response time at each interval.
Produces a PASS / WARNING / FAIL verdict at completion.

Design
──────
- Sessions are stored in a module-level dict (in-memory, survives container lifetime)
- Each session runs in a daemon thread — no new Celery infrastructure needed
- Polling uses existing SNMP and HTTP probe infrastructure
- Thread stops cleanly via threading.Event

Verdict logic
─────────────
  FAIL:    CPU > 95% for CPU_FAIL_CONSECUTIVE samples in a row
           OR device unreachable for UNREACHABLE_FAIL_S seconds
           OR uptime decreased (unexpected reboot detected)
  WARNING: CPU > CPU_WARN_THRESHOLD for 3+ consecutive samples
           OR memory > MEM_WARN_THRESHOLD
  PASS:    neither FAIL nor WARNING triggered
"""
from __future__ import annotations

import socket
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.hardware.burnin")

# ── Thresholds ────────────────────────────────────────────────────────────────
CPU_FAIL_THRESHOLD    = 95.0   # % CPU — fail if exceeded consecutively
CPU_FAIL_CONSECUTIVE  = 5      # samples in a row at fail threshold → FAIL
CPU_WARN_THRESHOLD    = 80.0   # % CPU — warn if exceeded consecutively
CPU_WARN_CONSECUTIVE  = 3      # samples in a row at warn threshold → WARNING
MEM_WARN_THRESHOLD    = 90.0   # % memory
UNREACHABLE_FAIL_S    = 60     # seconds unreachable → FAIL
DEFAULT_DURATION_S    = 3600   # 1 hour
DEFAULT_POLL_S        = 30     # poll every 30 seconds
PING_TIMEOUT_S        = 2      # socket connect timeout for reachability check


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class BurninConfig:
    duration_s:    int   = DEFAULT_DURATION_S
    poll_interval_s: int = DEFAULT_POLL_S

    def validate(self) -> None:
        if self.duration_s < 60:
            raise ValueError("duration_s must be >= 60")
        if self.poll_interval_s < 5:
            raise ValueError("poll_interval_s must be >= 5")
        if self.poll_interval_s >= self.duration_s:
            raise ValueError("poll_interval_s must be less than duration_s")


@dataclass
class MetricSample:
    timestamp:        str
    cpu_percent:      Optional[float]
    memory_percent:   Optional[float]
    uptime_s:         Optional[int]
    response_time_ms: Optional[int]
    reachable:        bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BurninSession:
    session_id:   str
    ip:           str
    config:       BurninConfig
    status:       str          = "running"    # running | completed | stopped
    verdict:      str          = "PENDING"    # PENDING | PASS | WARNING | FAIL
    started_at:   str          = field(default_factory=lambda: _now_iso())
    completed_at: Optional[str] = None
    samples:      List[MetricSample] = field(default_factory=list)
    failures:     List[str]    = field(default_factory=list)
    warnings:     List[str]    = field(default_factory=list)
    _stop_event:  threading.Event = field(default_factory=threading.Event, repr=False)

    def elapsed_s(self) -> int:
        started = datetime.fromisoformat(self.started_at)
        return int((datetime.now(timezone.utc) - started).total_seconds())

    def progress_pct(self) -> float:
        return min(100.0, round(self.elapsed_s() / self.config.duration_s * 100, 1))

    def remaining_s(self) -> int:
        return max(0, self.config.duration_s - self.elapsed_s())

    def latest_sample(self) -> Optional[MetricSample]:
        return self.samples[-1] if self.samples else None

    def to_report(self) -> dict:
        latest = self.latest_sample()
        return {
            "session_id":       self.session_id,
            "ip":               self.ip,
            "status":           self.status,
            "verdict":          self.verdict,
            "progress_pct":     self.progress_pct(),
            "elapsed_s":        self.elapsed_s(),
            "remaining_s":      self.remaining_s(),
            "samples_collected": len(self.samples),
            "latest":           latest.to_dict() if latest else None,
            "failures":         self.failures,
            "warnings":         self.warnings,
            "config": {
                "duration_s":      self.config.duration_s,
                "poll_interval_s": self.config.poll_interval_s,
            },
        }


# ── Module-level session registry ─────────────────────────────────────────────
_SESSIONS: Dict[str, BurninSession] = {}
_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Telemetry collection ──────────────────────────────────────────────────────

def _check_reachable(ip: str, port: int = 80) -> tuple[bool, Optional[int]]:
    """
    TCP connect to port 80 (or 554 if 80 fails).
    Returns (reachable, response_time_ms).
    """
    for p in (port, 554, 8000):
        t0 = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(PING_TIMEOUT_S)
                s.connect((ip, p))
            return True, int((time.monotonic() - t0) * 1000)
        except OSError:
            continue
    return False, None


def _collect_sample(ip: str) -> MetricSample:
    """
    Collect one telemetry sample. Uses SNMP first, HTTP fallback.
    Never raises — returns a sample with reachable=False on total failure.
    """
    reachable, response_time_ms = _check_reachable(ip)
    cpu: Optional[float] = None
    mem: Optional[float] = None
    uptime: Optional[int] = None

    if reachable:
        # SNMP — primary telemetry source
        try:
            from sin.scanner.snmp_telemetry import SNMPTelemetryProber
            data = SNMPTelemetryProber().probe(ip, [161])
            if data:
                cpu_raw = data.get("cpu_percent")
                if cpu_raw is not None:
                    cpu = float(str(cpu_raw).replace("%", "").strip())
                mem_raw = data.get("storage_usage")
                if mem_raw is not None:
                    mem = float(str(mem_raw).replace("%", "").strip())
                uptime_raw = data.get("uptime_seconds") or data.get("uptime_s")
                if uptime_raw is not None:
                    uptime = int(uptime_raw)
        except Exception as exc:
            logger.debug("[burnin] SNMP probe failed for %s: %s", ip, exc)

        # ISAPI fallback — Hikvision cameras
        if cpu is None:
            try:
                from sin.scanner.isapi_intel import isapi_prober
                telemetry = isapi_prober.probe_telemetry(ip, [80, 8000])
                if telemetry:
                    cpu_raw = telemetry.get("cpu_usage")
                    if cpu_raw is not None:
                        cpu = float(str(cpu_raw).replace("%", "").strip())
            except Exception as exc:
                logger.debug("[burnin] ISAPI fallback failed for %s: %s", ip, exc)

    return MetricSample(
        timestamp=_now_iso(),
        cpu_percent=cpu,
        memory_percent=mem,
        uptime_s=uptime,
        response_time_ms=response_time_ms,
        reachable=reachable,
    )


# ── Verdict evaluation ────────────────────────────────────────────────────────

def _evaluate_verdict(session: BurninSession) -> None:
    """
    Evaluate pass/fail/warning criteria against all collected samples.
    Mutates session.verdict, session.failures, session.warnings in place.
    Called after each sample and at session completion.
    """
    samples = session.samples
    if not samples:
        session.verdict = "PENDING"
        return

    # ── FAIL: consecutive CPU overload ────────────────────────────────────────
    cpu_fail_streak = 0
    for s in samples:
        if s.cpu_percent is not None and s.cpu_percent > CPU_FAIL_THRESHOLD:
            cpu_fail_streak += 1
            if cpu_fail_streak >= CPU_FAIL_CONSECUTIVE:
                msg = (f"CPU load exceeded {CPU_FAIL_THRESHOLD}% for "
                       f"{CPU_FAIL_CONSECUTIVE} consecutive samples")
                if msg not in session.failures:
                    session.failures.append(msg)
        else:
            cpu_fail_streak = 0

    # ── FAIL: sustained unreachability ────────────────────────────────────────
    unreachable_start: Optional[str] = None
    for s in samples:
        if not s.reachable:
            if unreachable_start is None:
                unreachable_start = s.timestamp
            else:
                start = datetime.fromisoformat(unreachable_start)
                current = datetime.fromisoformat(s.timestamp)
                gap_s = (current - start).total_seconds()
                if gap_s >= UNREACHABLE_FAIL_S:
                    msg = f"Device unreachable for {int(gap_s)}s"
                    if msg not in session.failures:
                        session.failures.append(msg)
        else:
            unreachable_start = None

    # ── FAIL: unexpected reboot (uptime decreased) ────────────────────────────
    prev_uptime: Optional[int] = None
    for s in samples:
        if s.uptime_s is not None:
            if prev_uptime is not None and s.uptime_s < prev_uptime - 30:
                msg = (f"Unexpected reboot detected: uptime dropped from "
                       f"{prev_uptime}s to {s.uptime_s}s")
                if msg not in session.failures:
                    session.failures.append(msg)
            prev_uptime = s.uptime_s

    # ── WARNING: elevated CPU ─────────────────────────────────────────────────
    cpu_warn_streak = 0
    for s in samples:
        if s.cpu_percent is not None and s.cpu_percent > CPU_WARN_THRESHOLD:
            cpu_warn_streak += 1
            if cpu_warn_streak >= CPU_WARN_CONSECUTIVE:
                msg = (f"CPU load exceeded {CPU_WARN_THRESHOLD}% for "
                       f"{CPU_WARN_CONSECUTIVE} consecutive samples")
                if msg not in session.warnings:
                    session.warnings.append(msg)
        else:
            cpu_warn_streak = 0

    # ── WARNING: high memory ──────────────────────────────────────────────────
    for s in samples:
        if s.memory_percent is not None and s.memory_percent > MEM_WARN_THRESHOLD:
            msg = f"Memory usage exceeded {MEM_WARN_THRESHOLD}%"
            if msg not in session.warnings:
                session.warnings.append(msg)
            break

    # ── Set verdict ───────────────────────────────────────────────────────────
    if session.failures:
        session.verdict = "FAIL"
    elif session.warnings:
        session.verdict = "WARNING"
    else:
        session.verdict = "PASS"


# ── Poll loop ─────────────────────────────────────────────────────────────────

def _poll_loop(session: BurninSession) -> None:
    """
    Background thread: polls device at config.poll_interval_s until
    duration_s elapsed or stop_event is set.
    """
    logger.info("[burnin] Session %s started for %s (duration=%ds, interval=%ds)",
                session.session_id, session.ip,
                session.config.duration_s, session.config.poll_interval_s)

    deadline = time.monotonic() + session.config.duration_s

    while not session._stop_event.is_set() and time.monotonic() < deadline:
        sample = _collect_sample(session.ip)
        with _LOCK:
            session.samples.append(sample)
            _evaluate_verdict(session)
            logger.debug(
                "[burnin] %s sample: reachable=%s cpu=%s mem=%s uptime=%s verdict=%s",
                session.ip, sample.reachable, sample.cpu_percent,
                sample.memory_percent, sample.uptime_s, session.verdict,
            )
        session._stop_event.wait(timeout=session.config.poll_interval_s)

    with _LOCK:
        session.status = "completed" if not session._stop_event.is_set() else "stopped"
        session.completed_at = _now_iso()
        if not session.samples:
            session.verdict = "FAIL"
            session.failures.append("No telemetry collected — device never responded")
        _evaluate_verdict(session)

    logger.info("[burnin] Session %s %s — verdict=%s failures=%d warnings=%d samples=%d",
                session.session_id, session.status,
                session.verdict, len(session.failures),
                len(session.warnings), len(session.samples))


# ── Public API ────────────────────────────────────────────────────────────────

class BurninAgent:
    """Manages burn-in sessions. Stateless — sessions live in module-level _SESSIONS."""

    def start(self, ip: str, config: BurninConfig) -> str:
        """Start a new burn-in session. Returns session_id."""
        config.validate()
        session_id = str(uuid.uuid4())
        session = BurninSession(
            session_id=session_id,
            ip=ip,
            config=config,
        )
        with _LOCK:
            _SESSIONS[session_id] = session

        thread = threading.Thread(
            target=_poll_loop,
            args=(session,),
            daemon=True,
            name=f"burnin-{session_id[:8]}",
        )
        thread.start()
        logger.info("[burnin] Started session %s for %s", session_id, ip)
        return session_id

    def stop(self, session_id: str) -> dict:
        """Signal a running session to stop. Returns final report."""
        session = self._get(session_id)
        session._stop_event.set()
        # Give thread up to 5s to update status
        for _ in range(10):
            time.sleep(0.5)
            if session.status != "running":
                break
        return session.to_report()

    def report(self, session_id: str) -> dict:
        """Return current report for a session."""
        return self._get(session_id).to_report()

    def list_sessions(self) -> list:
        """Return summary of all known sessions."""
        with _LOCK:
            return [
                {
                    "session_id": s.session_id,
                    "ip":         s.ip,
                    "status":     s.status,
                    "verdict":    s.verdict,
                    "progress_pct": s.progress_pct(),
                    "started_at": s.started_at,
                }
                for s in _SESSIONS.values()
            ]

    def _get(self, session_id: str) -> BurninSession:
        with _LOCK:
            session = _SESSIONS.get(session_id)
        if session is None:
            raise KeyError(f"Session not found: {session_id}")
        return session


# Module-level singleton
burnin_agent = BurninAgent()
