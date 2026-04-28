import json
import subprocess
import uuid
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.discovery.network")

class NetworkDiscovery:
    def __init__(self):
        # Dynamically resolve the path to your compiled Go binary
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Maps to ~/dhairyas/sin/scanner/sin-sensor
        self.go_sensor_path = os.path.abspath(os.path.join(current_dir, "../../../scanner/sin-sensor"))

    def execute_subnet_scan(self, subnet_cidr: str = None) -> List[Dict]:
        target_subnet = subnet_cidr or "192.168.30"
        target_subnet = target_subnet.split('/')[0].replace('.0', '')
        
        # Strip the CIDR notation if present (Go binary expects "192.168.30")
        if ".0/24" in target_subnet:
            target_subnet = target_subnet.replace(".0/24", "")

        session_id = str(uuid.uuid4())[:8].upper()
        logger.info(f"[{session_id}] ⚡ Firing High-Speed Go Sensor on {target_subnet}.0/24")

        try:
            # Execute the compiled Go binary
            result = subprocess.check_output([self.go_sensor_path, target_subnet], text=True)
            
            # Find the start of the JSON array to ignore any terminal text
            json_start = result.find('[')
            if json_start == -1:
                logger.error(f"[{session_id}] No JSON payload returned from Go Sensor.")
                return []
                
            json_payload = result[json_start:]
            devices = json.loads(json_payload)
            
            # Map the Go JSON into the exact structure the Python Hub expects
            enriched_devices = []
            for d in devices:
        # Generate a unique MAC placeholder tied to the IP to prevent database overwrite bugs
                fallback_mac = f"Unknown-MAC-for-{d.get('ip_address')}"
        
                enriched_devices.append({
                    "scan_session_id": session_id,
                    "ip_address": d.get("ip_address"),
                    "status": d.get("status"),
                    "mac_address": "Resolved via Network", 
                    "hostname": "Unknown",
                    "manufacturer": d.get("manufacturer"),
                    "os_family": d.get("os_family"),
                    "device_type": d.get("device_type"),
                    "open_ports": d.get("open_ports"),
                    "services": d.get("banners", {}),
                    "vulnerabilities": [],
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "scan_method": "Go Concurrent Sensor v1.0"
                })

            logger.info(f"[{session_id}] Go Sensor complete. Ingested {len(enriched_devices)} live assets in seconds.")
            return enriched_devices

        except subprocess.CalledProcessError as e:
            logger.error(f"[{session_id}] Go Sensor crashed: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"[{session_id}] Failed to parse Go Sensor JSON: {e}")
            return []
