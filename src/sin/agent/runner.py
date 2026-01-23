import json
import os
import uuid
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session
from sin.discovery.network import NetworkDiscovery
from sin.utils.logger import get_logger
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.agent.runner")

class AgentRunner:
    """
    Primary execution controller for the SIN security agent.
    """
    
    def __init__(self):
        self.discovery_module = NetworkDiscovery()
        # Generate a unique ID for this specific scan run
        self.session_uuid = str(uuid.uuid4())

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        """
        Executes a full assessment cycle: Discovery -> Analysis -> Storage.
        """
        logger.info(f"Starting assessment session: {self.session_uuid}")
        start_time = datetime.utcnow()
        
        # Phase 1: Discovery
        assets = self.discovery_module.execute_subnet_scan(subnet)
        
        end_time = datetime.utcnow()
        
        # Phase 2: Database Persistence (The "Memory")
        self._save_to_database(subnet, start_time, end_time, assets)

        # Phase 3: JSON Backup (Optional, but good for debugging)
        report = {
            "metadata": {
                "session_id": self.session_uuid,
                "timestamp": start_time.isoformat(),
                "agent_version": "0.1.0"
            },
            "network_topology": {
                "target_subnet": subnet,
                "total_hosts": len(assets)
            },
            "assets": assets
        }
        self._persist_json(report, output_dir)

    def _save_to_database(self, subnet, start, end, assets):
        """Saves scan results to PostgreSQL."""
        db: Session = SessionLocal()
        try:
            # 1. Create the Session Record
            scan_session = models.ScanSession(
                session_uuid=self.session_uuid,
                subnet_target=subnet,
                start_time=start,
                end_time=end
            )
            db.add(scan_session)
            db.commit()
            db.refresh(scan_session)
            
            # 2. Create Device Records
            for asset in assets:
                device = models.DeviceLog(
                    scan_id=scan_session.id,
                    ip_address=asset['ip_address'],
                    status=asset['status'],
                    open_ports=asset['open_ports'],  # SQLAlchemy handles JSON serialization automatically
                    protocols=asset['protocol_hints']
                )
                db.add(device)
            
            db.commit()
            logger.info(f"✅ Successfully saved {len(assets)} devices to Database.")
            
        except Exception as e:
            logger.error(f"❌ Database save failed: {e}")
            db.rollback()
        finally:
            db.close()

    def _persist_json(self, data: Dict, directory: str) -> None:
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        filepath = os.path.join(directory, f"scan_{self.session_uuid}.json")
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Report backup saved to {filepath}")
        except IOError as e:
            logger.error(f"Failed to persist JSON report: {e}")
