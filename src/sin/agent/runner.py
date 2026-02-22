import json
import os
import uuid
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session

from sin.discovery.network import NetworkDiscovery
from sin.scanner.analyzer import StateAnalyzer
from sin.scanner.fingerprint import DeviceFingerprinter
from sin.scanner.audit import VulnerabilityAuditor
from sin.response.alert import DiscordAlerter
from sin.utils.logger import get_logger
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.agent.runner")

class AgentRunner:
    def __init__(self):
        self.discovery_module = NetworkDiscovery()
        self.fingerprint_module = DeviceFingerprinter()
        self.audit_module = VulnerabilityAuditor()
        self.alerter = DiscordAlerter()
        self.session_uuid = str(uuid.uuid4())

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        logger.info(f"Starting assessment session: {self.session_uuid}")
        start_time = datetime.utcnow()

        # Phase 1: Discovery
        raw_assets = self.discovery_module.execute_subnet_scan(subnet)

        enriched_assets = []
        for asset in raw_assets:
            # Phase 2: Fingerprinting
            analysis = self.fingerprint_module.analyze_asset(
                asset['ip_address'],
                asset['open_ports']
            )
            asset.update(analysis)

            # Phase 3: Vulnerability Auditing
            vulns = self.audit_module.audit_device(
                asset['ip_address'],
                asset['open_ports']
            )
            asset['vulnerabilities'] = vulns

            if vulns:
                logger.warning(f"⚠️ Vulnerabilities found on {asset['ip_address']}")
                self.alerter.send_critical_alert(asset['ip_address'], vulns)

            enriched_assets.append(asset)

        end_time = datetime.utcnow()
        self._save_to_database(subnet, start_time, end_time, enriched_assets)

    def _save_to_database(self, subnet, start, end, assets):
        db: Session = SessionLocal()
        analyzer = StateAnalyzer(db) # Initialize our new brain

        try:
            scan_session = models.ScanSession(
                session_uuid=self.session_uuid,
                subnet_target=subnet,
                start_time=start,
                end_time=end
            )
            db.add(scan_session)
            db.commit()
            db.refresh(scan_session)

            for asset in assets:
                # --- THE DIFF ENGINE LOGIC ---
                changes = analyzer.analyze_changes(asset)
                
                # If there are critical changes, scream to Discord!
                critical_changes = [c for c in changes if c['severity'] in ['WARNING', 'CRITICAL']]
                if critical_changes:
                    logger.warning(f"⚠️ State changes detected on {asset['ip_address']}")
                    self.alerter.send_critical_alert(
                        asset['ip_address'], 
                        critical_changes  
                    )
                # ------------------------------

                device = models.DeviceLog(
                    scan_id=scan_session.id,
                    ip_address=asset['ip_address'],
                    status=asset['status'],
                    open_ports=asset['open_ports'],
                    protocols=asset['protocol_hints'],
                    os_family=asset.get('os_family'),
                    vendor=asset.get('vendor'),
                    vulnerabilities=asset.get('vulnerabilities', [])
                )
                db.add(device)

            db.commit()
            logger.info(f"✅ Saved {len(assets)} devices to Database.")

        except Exception as e:
            logger.error(f"❌ Database save failed: {e}")
            db.rollback()
        finally:
            db.close()

    def _persist_json(self, data: Dict, directory: str) -> None:
        pass
