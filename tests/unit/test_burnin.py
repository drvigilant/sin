"""
tests/unit/test_burnin.py
══════════════════════════
Unit tests for sin.hardware.burnin.

All I/O (SNMP, ISAPI, TCP) is mocked.
No live devices required.
"""
import time
import threading
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from sin.hardware.burnin import (
    CPU_FAIL_CONSECUTIVE,
    CPU_FAIL_THRESHOLD,
    CPU_WARN_CONSECUTIVE,
    CPU_WARN_THRESHOLD,
    MEM_WARN_THRESHOLD,
    UNREACHABLE_FAIL_S,
    BurninAgent,
    BurninConfig,
    BurninSession,
    MetricSample,
    _collect_sample,
    _evaluate_verdict,
    _now_iso,
)

IP = "192.168.30.50"


# ── BurninConfig ──────────────────────────────────────────────────────────────

class TestBurninConfig:
    def test_defaults(self):
        c = BurninConfig()
        assert c.duration_s == 3600
        assert c.poll_interval_s == 30

    def test_validate_accepts_valid(self):
        BurninConfig(duration_s=120, poll_interval_s=10).validate()

    def test_validate_rejects_short_duration(self):
        with pytest.raises(ValueError, match="duration_s"):
            BurninConfig(duration_s=30, poll_interval_s=10).validate()

    def test_validate_rejects_short_interval(self):
        with pytest.raises(ValueError, match="poll_interval_s"):
            BurninConfig(duration_s=120, poll_interval_s=2).validate()

    def test_validate_rejects_interval_gte_duration(self):
        with pytest.raises(ValueError):
            BurninConfig(duration_s=60, poll_interval_s=60).validate()


# ── MetricSample ──────────────────────────────────────────────────────────────

class TestMetricSample:
    def test_to_dict_contains_all_fields(self):
        s = MetricSample(
            timestamp=_now_iso(),
            cpu_percent=45.2,
            memory_percent=60.0,
            uptime_s=3600,
            response_time_ms=12,
            reachable=True,
        )
        d = s.to_dict()
        for key in ("timestamp", "cpu_percent", "memory_percent",
                    "uptime_s", "response_time_ms", "reachable"):
            assert key in d


# ── BurninSession ─────────────────────────────────────────────────────────────

class TestBurninSession:
    def _make_session(self) -> BurninSession:
        return BurninSession(
            session_id="test-123",
            ip=IP,
            config=BurninConfig(duration_s=120, poll_interval_s=10),
        )

    def test_initial_verdict_is_pending(self):
        s = self._make_session()
        assert s.verdict == "PENDING"

    def test_progress_pct_is_zero_at_start(self):
        s = self._make_session()
        assert s.progress_pct() == 0.0

    def test_remaining_s_equals_duration_at_start(self):
        s = self._make_session()
        assert s.remaining_s() == s.config.duration_s

    def test_latest_sample_none_when_empty(self):
        s = self._make_session()
        assert s.latest_sample() is None

    def test_to_report_contains_required_keys(self):
        s = self._make_session()
        report = s.to_report()
        for key in ("session_id", "ip", "status", "verdict", "progress_pct",
                    "elapsed_s", "remaining_s", "samples_collected",
                    "latest", "failures", "warnings", "config"):
            assert key in report


# ── _evaluate_verdict ─────────────────────────────────────────────────────────

def _make_sample(cpu=None, mem=None, uptime=None, reachable=True) -> MetricSample:
    return MetricSample(
        timestamp=_now_iso(),
        cpu_percent=cpu,
        memory_percent=mem,
        uptime_s=uptime,
        response_time_ms=10,
        reachable=reachable,
    )

def _make_session_with_samples(samples) -> BurninSession:
    s = BurninSession(
        session_id="test",
        ip=IP,
        config=BurninConfig(duration_s=600, poll_interval_s=30),
    )
    s.samples = samples
    return s


class TestEvaluateVerdict:
    def test_pass_on_normal_samples(self):
        samples = [_make_sample(cpu=30.0, mem=50.0) for _ in range(5)]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict == "PASS"

    def test_fail_on_sustained_high_cpu(self):
        samples = [_make_sample(cpu=CPU_FAIL_THRESHOLD + 1) for _ in range(CPU_FAIL_CONSECUTIVE)]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict == "FAIL"
        assert len(session.failures) == 1

    def test_no_fail_on_cpu_below_consecutive_threshold(self):
        # 4 high CPU samples — one short of the fail threshold
        samples = [_make_sample(cpu=CPU_FAIL_THRESHOLD + 1) for _ in range(CPU_FAIL_CONSECUTIVE - 1)]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict != "FAIL"

    def test_fail_resets_on_normal_cpu_between_spikes(self):
        """Streak resets when CPU drops below threshold."""
        samples = (
            [_make_sample(cpu=CPU_FAIL_THRESHOLD + 1)] * (CPU_FAIL_CONSECUTIVE - 1)
            + [_make_sample(cpu=10.0)]
            + [_make_sample(cpu=CPU_FAIL_THRESHOLD + 1)] * (CPU_FAIL_CONSECUTIVE - 1)
        )
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict != "FAIL"

    def test_warning_on_elevated_cpu(self):
        samples = [_make_sample(cpu=CPU_WARN_THRESHOLD + 1) for _ in range(CPU_WARN_CONSECUTIVE)]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict == "WARNING"
        assert len(session.warnings) == 1

    def test_warning_on_high_memory(self):
        samples = [_make_sample(cpu=10.0, mem=MEM_WARN_THRESHOLD + 1)]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict == "WARNING"

    def test_fail_overrides_warning(self):
        """A device with both fail and warn conditions → FAIL."""
        high_cpu = [_make_sample(cpu=CPU_FAIL_THRESHOLD + 1) for _ in range(CPU_FAIL_CONSECUTIVE)]
        high_mem = [_make_sample(cpu=10.0, mem=MEM_WARN_THRESHOLD + 1)]
        session = _make_session_with_samples(high_cpu + high_mem)
        _evaluate_verdict(session)
        assert session.verdict == "FAIL"

    def test_fail_on_unexpected_reboot(self):
        samples = [
            _make_sample(uptime=7200),
            _make_sample(uptime=60),   # dropped by > 30s → reboot
        ]
        session = _make_session_with_samples(samples)
        _evaluate_verdict(session)
        assert session.verdict == "FAIL"
        assert any("reboot" in f.lower() for f in session.failures)

    def test_pending_on_no_samples(self):
        session = _make_session_with_samples([])
        _evaluate_verdict(session)
        assert session.verdict == "PENDING"


# ── BurninAgent ───────────────────────────────────────────────────────────────

class TestBurninAgent:
    def test_start_returns_session_id(self):
        config = BurninConfig(duration_s=120, poll_interval_s=10)
        with patch("sin.hardware.burnin._collect_sample", return_value=_make_sample(cpu=20.0)):
            agent = BurninAgent()
            sid = agent.start(IP, config)
        assert isinstance(sid, str) and len(sid) == 36  # UUID format
        agent.stop(sid)

    def test_report_returns_dict(self):
        config = BurninConfig(duration_s=120, poll_interval_s=10)
        with patch("sin.hardware.burnin._collect_sample", return_value=_make_sample(cpu=20.0)):
            agent = BurninAgent()
            sid = agent.start(IP, config)
            report = agent.report(sid)
        assert report["session_id"] == sid
        assert report["ip"] == IP
        agent.stop(sid)

    def test_stop_changes_status(self):
        config = BurninConfig(duration_s=3600, poll_interval_s=10)
        with patch("sin.hardware.burnin._collect_sample", return_value=_make_sample()):
            agent = BurninAgent()
            sid = agent.start(IP, config)
            report = agent.stop(sid)
        assert report["status"] in ("stopped", "completed")

    def test_unknown_session_raises(self):
        agent = BurninAgent()
        with pytest.raises(KeyError):
            agent.report("nonexistent-session-id")

    def test_list_sessions_includes_started(self):
        config = BurninConfig(duration_s=120, poll_interval_s=10)
        with patch("sin.hardware.burnin._collect_sample", return_value=_make_sample()):
            agent = BurninAgent()
            sid = agent.start(IP, config)
            sessions = agent.list_sessions()
        assert any(s["session_id"] == sid for s in sessions)
        agent.stop(sid)
