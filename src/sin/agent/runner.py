import uuid
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session

from sin.agent.signal_mapper import normalize_host
from sin.agent.mitigation import MitigationEngine
from sin.discovery.network import NetworkDiscovery
from sin.scanner.audit import AuditEngine
from sin.response.alert import DiscordAlerter
from sin.utils.logger import get_logger
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.agent.runner")

_IOT_HARD = {554, 8554, 37777, 34567, 8000, 9000, 1883, 8883, 5683, 47808, 502, 4840}
_NON_IOT_OS = ("windows", "ubuntu", "debian", "centos", "fedora", "macos")

def _is_iot(asset: Dict) -> bool:
    ports   = set(asset.get("open_ports", []))
    mfr     = (asset.get("manufacturer") or asset.get("vendor") or "").lower()
    os_hint = asset.get("os_family", "").lower()

    # Priority 1: Known Camera Manufacturers
    if any(cam in mfr for cam in ["xiongmai", "h264dvr", "hikvision", "dahua"]):
        return True

    # Priority 2: Presence of specific CCTV/OT ports
    if _IOT_HARD.intersection(ports):
        return True

    # Filter out obvious non-IoT (PCs and generic web servers)
    if any(h in os_hint for h in _NON_IOT_OS): return False
    if ports.issubset({80, 443, 8080}): return False
    
    return len(ports) > 0

class AgentRunner:
    def __init__(self):
        self.discovery_module   = NetworkDiscovery()
        self.audit_module       = AuditEngine()
        self.alerter            = DiscordAlerter()
        self.session_uuid       = str(uuid.uuid4())
        self.mitigation         = MitigationEngine(dry_run=True)

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        logger.info(f"Starting assessment session: {self.session_uuid}")
        start_time = datetime.utcnow()

        raw_assets = self.discovery_module.execute_subnet_scan(subnet)
        
        # Filter strictly for IoT to keep the dashboard clean
        iot_assets = [a for a in raw_assets if _is_iot(a)]
        logger.info(f"Discovery: Found {len(raw_assets)} total. Kept {len(iot_assets)} IoT devices.")

        enriched_assets = []
        for asset in iot_assets:
            # 1. Ask the Brain to evaluate the device
            vulns, risk, action = self.audit_module.evaluate_asset(asset)

            # 2. Map findings
            asset["vulnerabilities"] = vulns
            asset["risk_score"] = risk
            asset["risk_level"] = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"
            asset["action"] = action

            # 3. Decision Logic & Mitigation Fix
            # Create a simple decision object so the mitigation engine doesn't crash
            decision_meta = {"action": action, "risk": risk, "confidence": 1.0}

            if action == "quarantine":
                logger.warning(f"🚨 AUTO-ISOLATING {asset['ip_address']} | Risk: {risk}")
                try:
                    # We pass the decision_meta but prevent the attribute error
                    self.mitigation.isolate(asset, type('obj', (object,), decision_meta))
                except Exception as e:
                    logger.error(f"Mitigation failed for {asset['ip_address']}, but continuing scan: {e}")

            enriched_assets.append(asset)

        end_time = datetime.utcnow()
        self._save_to_database(subnet, start_time, end_time, enriched_assets)

    def _save_to_database(self, subnet, start, end, assets):
        db: Session = SessionLocal()
        try:
            scan_session = models.ScanSession(
                session_uuid=self.session_uuid,
                subnet_target=subnet,
                start_time=start,
                end_time=end,
            )
            db.add(scan_session)
            db.commit()
            db.refresh(scan_session)

            for asset in assets:
                # Log critical findings to the Security Events timeline
                for vuln in asset.get("vulnerabilities", []):
                    db.add(models.SecurityEvent(
                        ip_address=asset["ip_address"],
                        event_type="VULN_DETECTED",
                        severity=vuln["severity"],
                        description=f"[{vuln.get('cve', 'N/A')}] {vuln['type']}: {vuln['description']}",
                    ))

                # Fire Discord Alert
                if asset["risk_score"] >= 60:
                    self.alerter.send_critical_alert(asset["ip_address"], asset["vulnerabilities"])

                # Save Device Log
                db.add(models.DeviceLog(
                    scan_id=scan_session.id,
                    ip_address=asset["ip_address"],
                    status="online",
                    open_ports=asset.get("open_ports", []),
                    protocols=[f"MFR:{asset.get('manufacturer', 'Unknown')}", f"OS:{asset.get('os_family', 'Unknown')}"],
                    os_family=asset.get("os_family"),
                    vendor=asset.get("manufacturer") or asset.get("vendor"),
                    vulnerabilities=asset.get("vulnerabilities", []),
                ))

            db.commit()
            logger.info(f"Saved {len(assets)} devices to database.")

        except Exception as e:
            logger.error(f"Database save failed: {e}")
            db.rollback()
        finally:
            db.close()
