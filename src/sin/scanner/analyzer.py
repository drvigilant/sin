from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from sin.storage import models
from sin.utils.logger import get_logger
from datetime import datetime

logger = get_logger("sin.scanner.analyzer")

class StateAnalyzer:
    """
    Compares current network state against historical data to detect anomalies.
    """
    def __init__(self, db_session: Session):
        self.db = db_session

    def analyze_changes(self, current_asset: Dict) -> List[Dict]:
        """
        Compares a newly scanned asset against its last known state in the database.
        Returns a list of 'Events' (changes detected).
        """
        events = []
        ip = current_asset['ip_address']
        
        # 1. Fetch the MOST RECENT past record for this IP
        last_record = self.db.query(models.DeviceLog)\
            .filter(models.DeviceLog.ip_address == ip)\
            .order_by(models.DeviceLog.id.desc())\
            .first()

        # 2. Heuristic: Brand New Device Detection
        if not last_record:
            events.append({
                "type": "NEW_ASSET",
                "severity": "INFO",
                "description": f"First time seeing device at {ip} on the network."
            })
            return events

        # 3. Heuristic: Port State Changes (The most critical indicator of compromise)
        past_ports = set(last_record.open_ports or [])
        current_ports = set(current_asset.get('open_ports', []))
        
        new_ports = current_ports - past_ports
        closed_ports = past_ports - current_ports
        
        if new_ports:
            events.append({
                "type": "PORT_OPENED",
                "severity": "WARNING",
                "description": f"New ports opened on {ip}: {list(new_ports)}"
            })
            
        if closed_ports:
            events.append({
                "type": "PORT_CLOSED",
                "severity": "INFO",
                "description": f"Ports closed on {ip}: {list(closed_ports)}"
            })

        # 4. Heuristic: OS/Vendor Spoofing or Changes
        if last_record.os_family and current_asset.get('os_family'):
            if last_record.os_family != current_asset.get('os_family'):
                events.append({
                    "type": "OS_MISMATCH",
                    "severity": "CRITICAL",
                    "description": f"OS Fingerprint changed from {last_record.os_family} to {current_asset.get('os_family')}. Potential spoofing or MITM attack."
                })

        return events
