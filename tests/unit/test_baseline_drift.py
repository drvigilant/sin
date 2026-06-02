"""
tests.unit.test_baseline_drift
Phase 3 / Task 1 — Baseline drift alerting: RISK_ESCALAT events.
"""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from sin.agent.baseline import BaselineEngine
from sin.storage.models import DeviceBaseline


def _make_baseline(ip="192.168.1.10", baseline_risk_score=30,
                   last_risk_score=None, baseline_ports=None,
                   baseline_vendor="Hikvision", baseline_vulnerabilities=None,
                   baseline_jarm_hash=""):
    bl = MagicMock(spec=DeviceBaseline)
    bl.ip_address               = ip
    bl.baseline_risk_score      = baseline_risk_score
    bl.last_risk_score          = last_risk_score
    bl.baseline_ports           = baseline_ports or []
    bl.baseline_vendor          = baseline_vendor
    bl.baseline_vulnerabilities = baseline_vulnerabilities or []
    bl.baseline_jarm_hash       = baseline_jarm_hash
    return bl


def _make_db(baseline):
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = baseline
    return db


def _device(ip="192.168.1.10", risk_score=50, **kwargs):
    return {"ip_address": ip, "risk_score": risk_score, "open_ports": [], **kwargs}


class TestSnapshot:
    def test_first_call_creates_baseline_with_last_risk_score(self):
        engine = BaselineEngine()
        db = _make_db(None)
        device = _device(risk_score=45, open_ports=[80, 554])
        engine.snapshot(device, db)
        db.add.assert_called_once()
        created = db.add.call_args[0][0]
        assert created.last_risk_score == 45
        assert created.baseline_risk_score == 45

    def test_second_call_updates_last_risk_score_only(self):
        engine = BaselineEngine()
        existing = _make_baseline(baseline_risk_score=30, last_risk_score=30)
        db = _make_db(existing)
        engine.snapshot(_device(risk_score=55), db)
        assert existing.last_risk_score == 55
        db.add.assert_not_called()

    def test_empty_ip_is_a_noop(self):
        engine = BaselineEngine()
        db = _make_db(None)
        engine.snapshot({"ip_address": "", "risk_score": 50}, db)
        db.add.assert_not_called()


class TestRiskEscalatScanToScan:
    def test_emits_when_delta_equals_threshold(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=40, baseline_risk_score=40)
        events = engine.detect_drift(_device(risk_score=50), _make_db(bl))
        assert "RISK_ESCALAT" in [e["event_type"] for e in events]

    def test_emits_when_delta_exceeds_threshold(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=30, baseline_risk_score=30)
        events = engine.detect_drift(_device(risk_score=70), _make_db(bl))
        assert "RISK_ESCALAT" in [e["event_type"] for e in events]

    def test_no_emit_when_delta_below_threshold(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=40, baseline_risk_score=40)
        events = engine.detect_drift(_device(risk_score=49), _make_db(bl))
        assert "RISK_ESCALAT" not in [e["event_type"] for e in events]

    def test_no_emit_on_first_scan_when_last_risk_none(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=None, baseline_risk_score=None)
        events = engine.detect_drift(_device(risk_score=80), _make_db(bl))
        assert "RISK_ESCALAT" not in [e["event_type"] for e in events]

    def test_no_emit_when_score_decreases(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=70, baseline_risk_score=70)
        events = engine.detect_drift(_device(risk_score=45), _make_db(bl))
        assert "RISK_ESCALAT" not in [e["event_type"] for e in events]

    def test_no_emit_when_score_unchanged(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=50, baseline_risk_score=50)
        events = engine.detect_drift(_device(risk_score=50), _make_db(bl))
        assert "RISK_ESCALAT" not in [e["event_type"] for e in events]

    def test_severity_high_for_moderate_delta(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=40, baseline_risk_score=40)
        events = engine.detect_drift(_device(risk_score=55), _make_db(bl))
        escalat = [e for e in events if e["event_type"] == "RISK_ESCALAT"]
        assert escalat and escalat[0]["severity"] == "HIGH"

    def test_severity_critical_for_large_delta(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=20, baseline_risk_score=20)
        events = engine.detect_drift(_device(risk_score=55), _make_db(bl))
        escalat = [e for e in events if e["event_type"] == "RISK_ESCALAT"]
        assert escalat and escalat[0]["severity"] == "CRITICAL"

    def test_description_contains_both_scores(self):
        engine = BaselineEngine()
        bl = _make_baseline(last_risk_score=30, baseline_risk_score=30)
        events = engine.detect_drift(_device(ip="10.0.0.5", risk_score=65), _make_db(bl))
        escalat = [e for e in events if e["event_type"] == "RISK_ESCALAT"]
        assert escalat
        desc = escalat[0]["description"]
        assert "30" in desc and "65" in desc and "10.0.0.5" in desc


class TestRiskEscalatedVsBaseline:
    def test_still_fires_on_large_delta_vs_original_baseline(self):
        engine = BaselineEngine()
        bl = _make_baseline(baseline_risk_score=20, last_risk_score=45)
        events = engine.detect_drift(_device(risk_score=55), _make_db(bl))
        assert "RISK_ESCALATED" in [e["event_type"] for e in events]

    def test_no_baseline_returns_empty(self):
        engine = BaselineEngine()
        db = _make_db(None)
        assert engine.detect_drift(_device(risk_score=99), db) == []
