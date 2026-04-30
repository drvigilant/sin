"""
sin.agent.baseline
══════════════════
Behavioral baseline engine.

After the first scan of a device, snapshot() stores a golden-state record.
Every subsequent scan calls detect_drift() to compare the current state
against the baseline and return a list of SecurityEvent-compatible dicts.

Drift categories
─────────────────
PORT_OPENED      — a port not in the baseline is now open (CRITICAL if IoT port)
PORT_CLOSED      — a port in the baseline is no longer open (INFO)
VENDOR_CHANGED   — manufacturer string changed (CRITICAL — may indicate device swap)
NEW_CVE          — a CVE not in the baseline is now detected (HIGH)
CVE_RESOLVED     — a CVE in the baseline is no longer detected (INFO)
RISK_ESCALATED   — risk score rose ≥ 25 points vs baseline (HIGH)
JARM_CHANGED     — TLS fingerprint changed (CRITICAL — may indicate MITM or firmware change)
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from sqlalchemy.orm import Session

from sin.storage.models import DeviceBaseline
from sin.utils.logger import get_logger

logger = get_logger("sin.agent.baseline")

# IoT/camera ports that are particularly suspicious when newly opened
_HIGH_RISK_PORTS = {23, 34567, 37777, 502, 47808, 1883, 4840}


class BaselineEngine:

    # ── Public API ─────────────────────────────────────────────────────────────

    def snapshot(self, device: Dict, db: Session) -> None:
        """
        Store a golden-state baseline for the device.
        Called on first discovery; does NOT overwrite an existing baseline.
        The session is NOT committed here — caller owns the transaction.
        """
        ip = device.get("ip_address", "")
        if not ip:
            return

        existing = db.query(DeviceBaseline).filter_by(ip_address=ip).first()
        if existing:
            return  # Baseline already exists — preserve the original golden state

        cves = self._extract_cves(device)
        baseline = DeviceBaseline(
            ip_address             = ip,
            baseline_ports         = sorted(device.get("open_ports", [])),
            baseline_vendor        = (device.get("manufacturer") or device.get("vendor") or "").strip(),
            baseline_vulnerabilities = cves,
            baseline_risk_score    = device.get("risk_score", 0),
            baseline_jarm_hash     = device.get("jarm_hash") or "",
        )
        db.add(baseline)
        logger.info("📐 Baseline snapshot created for %s | ports=%s cves=%d",
                    ip, baseline.baseline_ports, len(cves))

    def detect_drift(self, device: Dict, db: Session) -> List[Dict]:
        """
        Compare the device's current state against its stored baseline.
        Returns a list of drift-event dicts compatible with SecurityEvent schema.
        Returns [] if no baseline exists (first-time device) or no drift detected.
        """
        ip = device.get("ip_address", "")
        if not ip:
            return []

        baseline = db.query(DeviceBaseline).filter_by(ip_address=ip).first()
        if not baseline:
            return []  # First scan — no baseline to compare against yet

        events: List[Dict] = []

        # ── Port drift ────────────────────────────────────────────────────────
        current_ports  = set(device.get("open_ports", []))
        baseline_ports = set(baseline.baseline_ports or [])

        new_ports    = current_ports - baseline_ports
        closed_ports = baseline_ports - current_ports

        for port in new_ports:
            sev = "CRITICAL" if port in _HIGH_RISK_PORTS else "WARNING"
            events.append({
                "event_type":  "PORT_OPENED",
                "severity":    sev,
                "description": (
                    f"[DRIFT] {ip}: Port {port} newly opened vs baseline. "
                    f"Baseline ports: {sorted(baseline_ports)}."
                ),
            })
            logger.warning("🔀 DRIFT PORT_OPENED %s port=%d severity=%s", ip, port, sev)

        for port in closed_ports:
            events.append({
                "event_type":  "PORT_CLOSED",
                "severity":    "INFO",
                "description": (
                    f"[DRIFT] {ip}: Port {port} closed vs baseline. "
                    "Service may have stopped or been patched."
                ),
            })

        # ── Vendor drift ──────────────────────────────────────────────────────
        current_vendor = (device.get("manufacturer") or device.get("vendor") or "").strip()
        bl_vendor = (baseline.baseline_vendor or "").strip()
        if bl_vendor and current_vendor and current_vendor.lower() != bl_vendor.lower():
            events.append({
                "event_type":  "VENDOR_CHANGED",
                "severity":    "CRITICAL",
                "description": (
                    f"[DRIFT] {ip}: Manufacturer changed '{bl_vendor}' → '{current_vendor}'. "
                    "Possible device swap or ARP spoofing."
                ),
            })
            logger.warning("🔀 DRIFT VENDOR_CHANGED %s '%s' → '%s'", ip, bl_vendor, current_vendor)

        # ── CVE drift ─────────────────────────────────────────────────────────
        current_cves  = set(self._extract_cves(device))
        baseline_cves = set(baseline.baseline_vulnerabilities or [])

        new_cves      = current_cves - baseline_cves
        resolved_cves = baseline_cves - current_cves

        if new_cves:
            events.append({
                "event_type":  "NEW_CVE",
                "severity":    "HIGH",
                "description": (
                    f"[DRIFT] {ip}: New CVE(s) detected vs baseline: "
                    f"{', '.join(sorted(new_cves))}."
                ),
            })
            logger.warning("🔀 DRIFT NEW_CVE %s cves=%s", ip, sorted(new_cves))

        if resolved_cves:
            events.append({
                "event_type":  "CVE_RESOLVED",
                "severity":    "INFO",
                "description": (
                    f"[DRIFT] {ip}: CVE(s) no longer detected (patched or false-positive cleared): "
                    f"{', '.join(sorted(resolved_cves))}."
                ),
            })

        # ── Risk escalation ───────────────────────────────────────────────────
        current_risk = device.get("risk_score") or 0
        if baseline.baseline_risk_score is not None:
            delta = current_risk - baseline.baseline_risk_score
            if delta >= 25:
                events.append({
                    "event_type":  "RISK_ESCALATED",
                    "severity":    "HIGH",
                    "description": (
                        f"[DRIFT] {ip}: Risk score rose {delta} points "
                        f"({baseline.baseline_risk_score} → {current_risk}) vs baseline."
                    ),
                })
                logger.warning("🔀 DRIFT RISK_ESCALATED %s +%d", ip, delta)

        # ── JARM TLS fingerprint drift ────────────────────────────────────────
        current_jarm = (device.get("jarm_hash") or "").strip()
        bl_jarm = (baseline.baseline_jarm_hash or "").strip()
        if bl_jarm and current_jarm and current_jarm != bl_jarm:
            events.append({
                "event_type":  "JARM_CHANGED",
                "severity":    "CRITICAL",
                "description": (
                    f"[DRIFT] {ip}: TLS fingerprint (JARM) changed. "
                    f"Baseline: {bl_jarm[:20]}... | Current: {current_jarm[:20]}... "
                    "Possible firmware update, MITM proxy, or TLS terminator inserted."
                ),
            })
            logger.warning("🔀 DRIFT JARM_CHANGED %s", ip)

        if events:
            logger.info("🔀 Drift detected on %s: %d event(s)", ip, len(events))
        return events

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_cves(device: Dict) -> List[str]:
        return [
            v.get("cve", "").upper()
            for v in device.get("vulnerabilities", [])
            if v.get("cve")
        ]


# ── Module-level singleton ─────────────────────────────────────────────────────
baseline_engine = BaselineEngine()
