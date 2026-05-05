"""
sin.scanner.onvif_intel
═══════════════════════
Deep Active Interrogation via ONVIF (Open Network Video Interface Forum).
Bypasses layer-2 ARP limitations to extract hardcoded MACs, firmware versions,
and hardware models directly from the camera's API.
"""

import urllib.request
import urllib.error
import re
from typing import Dict, List, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.onvif_intel")

class ONVIFProber:
    TIMEOUT = 3

    # Minimal SOAP payload to get device info (Works unauthenticated on many older cameras)
    INFO_PAYLOAD = """<?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
      <s:Body>
        <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
      </s:Body>
    </s:Envelope>"""

    # Minimal SOAP payload to get MAC address
    NET_PAYLOAD = """<?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
      <s:Body>
        <GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>
      </s:Body>
    </s:Envelope>"""

    def probe(self, ip: str, open_ports: List[int]) -> Dict[str, str]:
        """Attempt to extract deep hardware info via ONVIF."""
        # Common ONVIF ports
        candidates = [p for p in [80, 8080, 8899, 8000] if p in open_ports]
        if not candidates:
            # If no known ports, try 80 anyway as a hail mary
            candidates = [80]

        extracted_data = {}

        for port in candidates:
            url = f"http://{ip}:{port}/onvif/device_service"
            
            # 1. Try fetching Device Info (Firmware, Model, Manufacturer)
            info_resp = self._send_soap(url, self.INFO_PAYLOAD)
            if info_resp:
                extracted_data["manufacturer"] = self._extract_xml(info_resp, "Manufacturer")
                extracted_data["model"] = self._extract_xml(info_resp, "Model")
                extracted_data["firmware"] = self._extract_xml(info_resp, "FirmwareVersion")
                extracted_data["serial"] = self._extract_xml(info_resp, "SerialNumber")

            # 2. Try fetching Network Interfaces (MAC Address)
            net_resp = self._send_soap(url, self.NET_PAYLOAD)
            if net_resp:
                mac = self._extract_xml(net_resp, "HwAddress")
                if mac:
                    extracted_data["mac_address"] = mac.replace("-", ":").upper()

            if extracted_data:
                logger.info(f"👁️ ONVIF Interrogation Success for {ip}: {extracted_data}")
                break # Stop trying ports once we get a hit

        return extracted_data

    def _send_soap(self, url: str, payload: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url, 
                data=payload.encode("utf-8"), 
                headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "SIN-EDR/4.0"}
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as response:
                if response.status == 200:
                    return response.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            # 401 means ONVIF is there, but requires auth. (We'll tackle auth later).
            if e.code == 401:
                logger.debug(f"ONVIF at {url} requires authentication.")
        except Exception:
            pass
        return None

    def _extract_xml(self, xml_string: str, tag: str) -> str:
        """Fast regex extraction to avoid heavy XML parsers."""
        match = re.search(f"<{tag}[^>]*>(.*?)</{tag}>", xml_string, re.IGNORECASE)
        if not match:
            # Try namespaced tag e.g., <tt:Manufacturer>
            match = re.search(f"<[^>]+:{tag}[^>]*>(.*?)</[^>]+:{tag}>", xml_string, re.IGNORECASE)
        return match.group(1).strip() if match else ""

# Singleton
onvif_prober = ONVIFProber()
