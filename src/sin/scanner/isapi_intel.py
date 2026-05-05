"""
sin.scanner.isapi_intel
═══════════════════════
Live Telemetry via ISAPI (Intelligent Security API).
Used by Hikvision and white-labeled OEMs (like Securus) to expose
real-time CPU, RAM, and Storage metrics.
"""

import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from typing import Dict, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.isapi_intel")

class ISAPIProber:
    TIMEOUT = 3

    def probe_telemetry(self, ip: str, open_ports: list) -> Dict[str, str]:
        """Pull live hardware diagnostics via unauthenticated ISAPI endpoint."""
        # ISAPI usually lives on port 80 or 8080
        target_ports = [p for p in [80, 8080] if p in open_ports]
        metrics = {}

        for port in target_ports:
            url = f"http://{ip}:{port}/ISAPI/System/status"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SIN-EDR/4.0"})
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as response:
                    if response.status == 200:
                        xml_data = response.read().decode("utf-8")
                        metrics = self._parse_status_xml(xml_data)
                        if metrics:
                            logger.info(f"📊 ISAPI Telemetry pulled for {ip}: {metrics}")
                            break
            except urllib.error.HTTPError as e:
                # If 401, the endpoint exists but requires auth.
                # Many firmware versions leave /System/status unauthenticated.
                pass
            except Exception:
                pass
                
        return metrics

    def _parse_status_xml(self, xml_string: str) -> Dict[str, str]:
        """Extract CPU, RAM, and internal temperature from ISAPI XML."""
        metrics = {}
        try:
            # Strip XML namespaces for easier parsing
            xml_string = xml_string.replace('xmlns="http://www.isapi.org/ver20/XMLSchema"', '')
            root = ET.fromstring(xml_string)
            
            cpu_elem = root.find('.//cpuUtilization')
            if cpu_elem is not None:
                metrics['cpu_usage'] = cpu_elem.text + "%"
                
            ram_elem = root.find('.//memoryUsage')
            if ram_elem is not None:
                metrics['ram_usage'] = ram_elem.text + "MB"
                
            temp_elem = root.find('.//deviceTemperature')
            if temp_elem is not None:
                metrics['temperature'] = temp_elem.text + "°C"
                
        except ET.ParseError:
            pass
            
        return metrics

# Singleton
isapi_prober = ISAPIProber()
