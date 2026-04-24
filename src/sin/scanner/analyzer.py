from typing import List, Dict
from sqlalchemy.orm import Session
from sin.storage import models
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.analyzer")

class StateAnalyzer:
    def __init__(self, db_session: Session):
        self.db = db_session

    def analyze_changes(self, current_asset: Dict) -> List[Dict]:
        events = []
        ip = current_asset['ip_address']

        last_record = self.db.query(models.DeviceLog)\
            .filter(models.DeviceLog.ip_address == ip)\
            .order_by(models.DeviceLog.id.desc())\
            .first()

        if not last_record:
            events.append({
                "type": "NEW_ASSET",
                "severity": "INFO",
                "description": f"New device discovered at {ip}."
            })
            return events

        past_ports    = set(last_record.open_ports or [])
        current_ports = set(current_asset.get('open_ports', []))

        # Nothing changed — skip entirely, no alert
        if past_ports == current_ports:
            return []

        new_ports    = current_ports - past_ports
        closed_ports = past_ports - current_ports

        if new_ports:
            events.append({
                "type": "PORT_OPENED",
                "severity": "WARNING",
                "description": f"New ports opened on {ip}: {sorted(new_ports)}"
            })

        if closed_ports:
            events.append({
                "type": "PORT_CLOSED",
                "severity": "INFO",
                "description": f"Ports closed on {ip}: {sorted(closed_ports)}"
            })

        # OS change — normalise before comparing to avoid false alarms
        def _norm(os: str) -> str:
            os = (os or "").lower()
            if "windows" in os: return "windows"
            if "linux"   in os: return "linux"
            if "routeros" in os: return "routeros"
            if "unifi"   in os: return "unifi"
            return os.strip()

        last_os    = _norm(last_record.os_family or "")
        current_os = _norm(current_asset.get('os_family', ''))

        if last_os and current_os and last_os != current_os:
            events.append({
                "type": "OS_MISMATCH",
                "severity": "CRITICAL",
                "description": f"OS fingerprint changed on {ip}: {last_record.os_family} → {current_asset.get('os_family')}. Possible spoofing."
            })

        return events
