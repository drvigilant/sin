import json
import os
import uuid
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session

# CHANGED: Added Fingerprinter import
from sin.discovery.network import NetworkDiscovery
from sin.scanner.fingerprint import DeviceFingerprinter 
from sin.utils.logger import get_logger
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.agent.runner")

class AgentRunner:
    def __init__(self):
        self.discovery_module = NetworkDiscovery()
        # CHANGED: Initialize Fingerprinter
        self.fingerprint_module = DeviceFingerprinter()
        self.session_uuid = str(uuid.uuid4())

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        logger.info(f"Starting assessment session: {self.session_uuid}")
        start_time = datetime.utcnow()
        
        # Phase 1: Discovery
        raw_assets = self.discovery_module.execute_subnet_scan(subnet)
        
        # Phase 2: Fingerprinting & Analysis
        enriched_assets = []
        for asset in raw_assets:
            # Analyze each found device
            analysis = self.fingerprint_module.analyze_asset(
                asset['ip_address'], 
                asset['open_ports']
            )
            # Merge results
            asset.update(analysis)
            enriched_assets.append(asset)
            logger.info(f"Fingerprinted {asset['ip_address']}: {analysis['os_family']} ({analysis['vendor']})")

        end_time = datetime.utcnow()
        
        # Phase 3: Persistence
        self._save_to_database(subnet, start_time, end_time, enriched_assets)

    def _save_to_database(self, subnet, start, end, assets):
        db: Session = SessionLocal()
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
                device = models.DeviceLog(
                    scan_id=scan_session.id,
                    ip_address=asset['ip_address'],
                    status=asset['status'],
                    open_ports=asset['open_ports'],
                    protocols=asset['protocol_hints'],
                    # NEW: Save fingerprint data
                    os_family=asset.get('os_family'),
                    vendor=asset.get('vendor')
                )
                db.add(device)
            
            db.commit()
            logger.info(f"✅ Saved {len(assets)} enriched devices to Database.")
            
        except Exception as e:
            logger.error(f"❌ Database save failed: {e}")
            db.rollback()
        finally:
            db.close()
