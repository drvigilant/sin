"""
sin.agent.runner
════════════════
Orchestrates a full assessment pass with Enterprise Deduplication.
"""

from __future__ import annotations

import os
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, List

from sqlalchemy.orm import Session

from sin.agent.baseline import baseline_engine
from sin.agent.decision import DecisionEngine, ThreatVerdict
from sin.agent.mitigation import MitigationEngine
from sin.agent.signal_mapper import normalize_host
from sin.discovery.network import NetworkDiscovery
from sin.response.alert import DiscordAlerter
from sin.scanner.audit import AuditEngine
from sin.storage import models
from sin.storage.database import SessionLocal
from sin.utils.logger import get_logger

logger = get_logger("sin.agent.runner")

# ── Runtime config ────────────────────────────────────────────────────────────
_DRY_RUN              = False
_CONFIDENCE_THRESHOLD = float(os.getenv("SIN_CONFIDENCE_THRESHOLD", "0.80"))

# ── IoT classification constants ──────────────────────────────────────────────
_IOT_HARD_PORTS = {554, 8554, 37777, 34567, 8000, 9000, 1883, 8883, 5683, 47808, 502, 4840}
_IOT_VENDORS    = {
    "xiongmai", "h264dvr", "hikvision", "dahua", "axis",
    "reolink", "amcrest", "uniview", "hanwha", "vivotek",
}
_MANAGED_OS = {"windows", "ubuntu", "debian", "centos", "fedora", "macos", "proxmox"}


def _is_iot(asset: Dict) -> bool:
    ports   = set(asset.get("open_ports", []))
    mfr     = (asset.get("manufacturer") or asset.get("vendor") or "").lower()
    banners = str(asset.get("banners", {})).lower()
    os_hint = asset.get("os_family", "").lower()

    if any(v in mfr or v in banners for v in _IOT_VENDORS):
        return True
    if _IOT_HARD_PORTS.intersection(ports):
        return True
    if any(h in os_hint for h in _MANAGED_OS):
        return False
    if {445, 3389}.intersection(ports) and not _IOT_HARD_PORTS.intersection(ports):
        return False

    _WEB_MANAGED = {80, 443, 8080, 8443, 22}
    if ports.issubset(_WEB_MANAGED) and not _IOT_HARD_PORTS.intersection(ports):
        return False

    return bool(_IOT_HARD_PORTS.intersection(ports))


class AgentRunner:
    def __init__(self) -> None:
        self.discovery  = NetworkDiscovery()
        self.auditor    = AuditEngine()
        self.decision   = DecisionEngine()
        self.mitigation = MitigationEngine(dry_run=False)
        self.alerter    = DiscordAlerter()
        self.session_id = str(uuid.uuid4())

        logger.info(
            f"AgentRunner init | session={self.session_id} "
            f"dry_run={_DRY_RUN} threshold={_CONFIDENCE_THRESHOLD}"
        )

    def run_assessment(self, subnet: str) -> List[Dict]:
        logger.info(f"[{self.session_id}] Assessment started | target={subnet}.0/24")
        start_time = datetime.now(timezone.utc)

        raw_assets = self.discovery.execute_subnet_scan(subnet)
        iot_assets = [a for a in raw_assets if _is_iot(a)]

        logger.info(
            f"[{self.session_id}] Discovery | total={len(raw_assets)} iot={len(iot_assets)}"
        )

        enriched: List[Dict] = [self._process_asset(a) for a in iot_assets]

        end_time = datetime.now(timezone.utc)
        self._persist(subnet, start_time, end_time, enriched)

        elapsed = (end_time - start_time).total_seconds()
        logger.info(
            f"[{self.session_id}] Complete | audited={len(enriched)} elapsed={elapsed:.1f}s"
        )
        return enriched

    def _process_asset(self, asset: Dict) -> Dict:
        ip = asset.get("ip_address", "?")
        vulns, _audit_score, _audit_action = self.auditor.evaluate_asset(asset)
        asset["vulnerabilities"] = vulns
        asset = normalize_host(asset)
        verdict: ThreatVerdict = self.decision.evaluate(asset)

        asset["risk_score"]   = round(verdict.confidence * 100)
        asset["risk_level"]   = verdict.severity
        asset["risk_reasons"] = verdict.reasons
        asset["verdict"] = {
            "score":      verdict.score,
            "confidence": verdict.confidence,
            "severity":   verdict.severity,
            "action":     verdict.recommended_action,
            "signals":    verdict.signal_count,
        }

        logger.info(
            f"[VERDICT] ip={ip} severity={verdict.severity} "
            f"confidence={verdict.confidence:.2f} "
            f"action={verdict.recommended_action} "
            f"signals={verdict.signal_count} vulns={len(vulns)}"
        )

        if verdict.is_actionable(_CONFIDENCE_THRESHOLD):
            logger.warning(
                f"[MITIGATE] {ip} | {verdict.severity} | "
                f"confidence={verdict.confidence:.2f} | "
                f"dry_run={_DRY_RUN}"
            )
            try:
                result = self.mitigation.isolate(asset, verdict)
                asset["mitigation_rule_id"] = result.rule_id
                asset["mitigation_action"]  = result.action_type
            except Exception as exc:
                logger.error(f"[MITIGATE] Failed for {ip}: {exc}", exc_info=True)
                asset["mitigation_rule_id"] = None
                asset["mitigation_action"]  = "error"
        else:
            asset["mitigation_rule_id"] = None
            asset["mitigation_action"]  = "none"

        return asset

    def _persist(
        self,
        subnet: str,
        start: datetime,
        end: datetime,
        assets: List[Dict],
    ) -> None:
        db: Session = SessionLocal()
        try:
            session_row = models.ScanSession(
                session_uuid=self.session_id,
                subnet_target=subnet,
                start_time=start,
                end_time=end,
            )
            db.add(session_row)
            db.flush()

            for asset in assets:
                ip = asset.get("ip_address", "")

                db.add(models.DeviceLog(
                    scan_id         = session_row.id,
                    ip_address      = ip,
                    hostname        = asset.get("hostname"),
                    status          = "online",
                    vendor          = asset.get("manufacturer") or asset.get("vendor"),
                    os_family       = asset.get("os_family"),
                    open_ports      = asset.get("open_ports", []),
                    protocols       = list(asset.get("services", {}).values()),
                    vulnerabilities = asset.get("vulnerabilities", []),
                    mac_address     = asset.get("mac_address"),
                    device_type     = asset.get("device_type"),
                    risk_score      = asset.get("risk_score", 0),
                    risk_level      = asset.get("risk_level", "UNKNOWN"),
                    risk_reasons    = asset.get("risk_reasons", []),
                    jarm_hash       = asset.get("jarm_hash"),
                ))

                # UPGRADE: Vulnerability Deduplication Logic
                for vuln in asset.get("vulnerabilities", []):
                    # Construct the description once
                    description = (
                        f"[{vuln.get('cve', 'N/A')}] "
                        f"{vuln.get('type', 'Unknown')}: "
                        f"{vuln.get('description', '')}"
                    )

                    # CHECK: Does this exact issue already exist for this IP?
                    exists = db.query(models.SecurityEvent).filter(
                        models.SecurityEvent.ip_address == ip,
                        models.SecurityEvent.description == description
                    ).first()

                    if not exists:
                        # Only add if it's a NEW discovery
                        db.add(models.SecurityEvent(
                            ip_address  = ip,
                            event_type  = "VULN_DETECTED",
                            severity    = vuln.get("severity", "INFO"),
                            description = description,
                        ))

                # Baseline drift detection
                drift_events = baseline_engine.detect_drift(asset, db)
                for drift in drift_events:
                    db.add(models.SecurityEvent(
                        ip_address  = ip,
                        event_type  = drift["event_type"],
                        severity    = drift["severity"],
                        description = drift["description"],
                    ))

                baseline_engine.snapshot(asset, db)

                if asset.get("risk_score", 0) >= 60:
                    try:
                        self.alerter.send_critical_alert(ip, asset.get("vulnerabilities", []))
                    except Exception as exc:
                        logger.warning(f"Discord alert failed for {ip}: {exc}")

            db.commit()
            logger.info(f"[{self.session_id}] Persisted {len(assets)} devices.")

        except Exception as exc:
            db.rollback()
            logger.error(f"[{self.session_id}] Persist failed: {exc}", exc_info=True)
        finally:
            db.close()
