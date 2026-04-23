"""
sin.discovery.network v6.0 (Two-Phase Async IoT Optimized Scanner)
"""
import socket
import uuid
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Optional

from sin.utils.logger import get_logger
import nmap

logger = get_logger("sin.discovery.network")

class NetworkDiscovery:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
        # Phase 1: Lightweight IoT Port Sweep
        self.iot_ports = "80,443,554,8554,1883,1900,502,5683,8080,8888,37777,34567"
        self.sweep_args = "-Pn -T4 --max-retries 1 --host-timeout 10s --open"
        
        # Phase 2: Targeted Deep Scan
        self.deep_args = "-A -T4 -Pn --max-retries 1 --host-timeout 60s"

    def _get_local_subnet(self) -> str:
        """Automatically detects the local network subnet."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            octets = local_ip.split('.')
            return f"{octets[0]}.{octets[1]}.{octets[2]}"
        except Exception as e:
            logger.error(f"Failed to auto-detect subnet: {e}. Defaulting to 192.168.1")
            return "192.168.1"

    def execute_subnet_scan(self, subnet_cidr: str = None) -> List[Dict]:
        if not subnet_cidr:
            subnet_cidr = self._get_local_subnet()
            
        target_range = f"{subnet_cidr}.0/24"
        session_id = str(uuid.uuid4())[:8].upper()
        
        # --- PHASE 1: LIGHTWEIGHT SWEEP ---
        logger.info(f"[{session_id}] Phase 1: Fast IoT Sweep on {target_range} (Ports: {self.iot_ports})")
        try:
            self.nm.scan(hosts=target_range, ports=self.iot_ports, arguments=self.sweep_args)
        except Exception as e:
            logger.error(f"Phase 1 Sweep Failed: {e}")
            return []

        iot_candidates = self.nm.all_hosts()
        if not iot_candidates:
            logger.info(f"[{session_id}] Scan complete. No IoT candidates found on subnet.")
            return []

        logger.info(f"[{session_id}] Sweep complete. Found {len(iot_candidates)} likely IoT candidates. Initiating Phase 2...")

        # --- PHASE 2: CONCURRENT DEEP SCAN ---
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(self._deep_scan_target, ip, session_id): ip for ip in iot_candidates}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    data = future.result()
                    if data:
                        results.append(data)
                except Exception as e:
                    logger.error(f"Deep scan failed for {ip}: {e}")

        logger.info(f"[{session_id}] Assessment complete. Extracted {len(results)} confirmed devices.")
        return results

    def _deep_scan_target(self, ip: str, session_id: str) -> Optional[Dict]:
        """Performs the intensive nmap -A scan on a single verified target."""
        local_nm = nmap.PortScanner() # Use local instance for thread safety
        
        try:
            local_nm.scan(ip, arguments=self.deep_args)
        except Exception:
            return None

        if ip not in local_nm.all_hosts():
            return None

        host_data = local_nm[ip]
        
        # Extract Hardware & OS Info
        mac_addr = host_data.get("addresses", {}).get("mac", "Hidden by NAT")
        hostname = host_data.hostname() or "Unresolved"
        
        os_family = "Unknown"
        if "osmatch" in host_data and len(host_data["osmatch"]) > 0:
            os_family = host_data["osmatch"][0].get("name", "Unknown")

        vendor = host_data.get("vendor", {}).get(mac_addr, "Generic")

        # Process Ports & Services
        open_ports = []
        services_dict = {}
        iot_score = 0

        if "tcp" in host_data:
            for port, srv in host_data["tcp"].items():
                if srv["state"] == "open":
                    open_ports.append(port)
                    svc_name = srv.get("product") or srv.get("name") or f"TCP/{port}"
                    services_dict[port] = svc_name
                    
                    # Heuristic Scoring
                    if port in [554, 8554, 37777, 34567]: iot_score += 3 # High confidence Video/NVR
                    elif port in [1883, 5683, 502]: iot_score += 2       # Moderate confidence OT/IoT
                    elif port in [8080, 8888, 1900]: iot_score += 1      # Low confidence generic web
                    
                    if "camera" in svc_name.lower() or "dvr" in svc_name.lower(): iot_score += 3

                    # CPE Vendor Overrides
                    cpe = srv.get("cpe", "").lower()
                    if "hikvision" in cpe: vendor = "Hikvision"; iot_score += 5
                    elif "dahua" in cpe: vendor = "Dahua"; iot_score += 5

        # IoT Confidence Classification
        if iot_score >= 4:
            device_type = "Confirmed IoT / Camera"
            confidence = "High"
        elif iot_score >= 2:
            device_type = "Likely IoT / Embedded"
            confidence = "Moderate"
        elif 445 in open_ports or 3389 in open_ports:
            device_type = "Windows Server/PC"
            confidence = "Not IoT"
        else:
            device_type = "Generic Network Node"
            confidence = "Low"

        return {
            "scan_session_id": session_id,
            "ip_address": ip,
            "status": "online",
            "mac_address": mac_addr,
            "hostname": hostname,
            "manufacturer": vendor,
            "os_family": os_family,
            "device_type": f"{device_type} (Confidence: {confidence})",
            "open_ports": open_ports,
            "services": services_dict,
            "vulnerabilities": [],
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "scan_method": "Optimized Two-Phase"
        }
