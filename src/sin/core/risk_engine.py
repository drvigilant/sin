"""
sin.core.risk_engine
═════════════════════
Public risk-scoring API for the SIN platform.

Enterprise fix in this revision
─────────────────────────────────
PROBLEM:  Two independent scoring engines existed side-by-side:
            • core/risk_engine.py    — simple additive score (0-100 int)
            • agent/decision.py      — weighted confidence model (0.0-1.0 float)
          They used different weights, different scales, and were wired to
          different parts of the stack.  The API and the database could show
          completely different risk scores for the same device — silently.

FIX:      This module is now a thin facade over DecisionEngine.
          calculate_risk() still returns the exact same dict shape
          { risk_score, risk_level, risk_reasons } so any future caller
          gets consistent numbers without changing their code.
          The actual scoring logic lives in ONE place: agent/decision.py.

          The old additive logic is preserved below as _legacy_calculate_risk()
          for reference and emergency fallback only.
"""

from __future__ import annotations

from typing import Dict

from sin.agent.decision import DecisionEngine
from sin.agent.signal_mapper import normalize_host

_engine = DecisionEngine()


def calculate_risk(device: dict) -> Dict:
    """
    Score *device* and return a risk summary dict.

    Return shape (unchanged from original):
        {
            "risk_score":   int   0-100,
            "risk_level":   str   CRITICAL | HIGH | MEDIUM | LOW,
            "risk_reasons": list[str],
        }

    Internally delegates to DecisionEngine so scores are always
    consistent with what runner.py and the DB store.
    """
    # Normalise so DecisionEngine sees sig_id fields
    normalised = normalize_host(dict(device))
    verdict = _engine.evaluate(normalised)

    return {
        "risk_score":   round(verdict.confidence * 100),
        "risk_level":   verdict.severity,
        "risk_reasons": verdict.reasons,
    }


# ── Legacy implementation (kept for reference, not called) ────────────────────

def _legacy_calculate_risk(device: dict) -> Dict:
    """
    Original additive scorer — preserved for audit trail.
    Do not call this directly; use calculate_risk() above.
    """
    score = 0
    reasons = []

    for v in device.get("vulnerabilities", []):
        sev = v.get("severity", "").upper()
        if sev == "CRITICAL":
            score += 40
            reasons.append("Critical vulnerability detected")
        elif sev == "HIGH":
            score += 25
            reasons.append("High severity vulnerability")
        elif sev == "MEDIUM":
            score += 15
        elif sev == "LOW":
            score += 5

    ports = device.get("open_ports", [])
    if 23 in ports:
        score += 30
        reasons.append("Telnet exposed (port 23)")
    if 21 in ports:
        score += 20
        reasons.append("FTP exposed (port 21)")
    if 554 in ports:
        score += 20
        reasons.append("RTSP camera stream exposed")
    if 1883 in ports:
        score += 15
        reasons.append("MQTT exposed")

    vendor = (device.get("vendor") or "").lower()
    if any(v in vendor for v in ["hikvision", "dahua", "axis"]):
        score += 15
        reasons.append("CCTV device (high-risk target)")
    elif any(v in vendor for v in ["mikrotik", "ubiquiti", "cisco"]):
        score += 10
        reasons.append("Network infrastructure device")

    score = min(score, 100)
    level = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 60 else
        "MEDIUM"   if score >= 30 else
        "LOW"
    )
    return {
        "risk_score":   score,
        "risk_level":   level,
        "risk_reasons": list(set(reasons)),
    }
