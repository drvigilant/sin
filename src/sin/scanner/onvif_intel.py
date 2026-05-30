"""
sin.scanner.onvif_intel
═══════════════════════
Unauthenticated ONVIF GetDeviceInformation prober.

Confirmed working against Securus/Xiongmai cameras on 192.168.30.x:
  - Port 80  → cameras: .3, .4, .12, .13, .27
  - Port 8899 → cameras: .5, .22
  - Content-Type MUST be application/soap+xml (not text/xml)
  - No authentication required — cameras respond to bare SOAP envelope
"""

import urllib.request
import urllib.error
import re
from typing import Dict, List, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.onvif_intel")

# Minimal unauthenticated ONVIF envelope — no WS-Security header needed
DEVICE_INFO_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body>'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    '</s:Body>'
    '</s:Envelope>'
)

# Ports to try in order — confirmed from live camera probing
ONVIF_PORTS = [80, 8899, 8080, 8000]


def _send_onvif(ip: str, port: int, timeout: int = 4) -> Optional[str]:
    """Send unauthenticated ONVIF GetDeviceInformation. Returns raw XML or None."""
    url = f"http://{ip}:{port}/onvif/device_service"
    try:
        req = urllib.request.Request(
            url,
            data=DEVICE_INFO_PAYLOAD.encode("utf-8"),
            headers={
                # Must be application/soap+xml — text/xml causes HTTP 200 with HTML 404 body
                "Content-Type": "application/soap+xml",
                "User-Agent":   "SIN-EDR/4.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read().decode("utf-8", errors="ignore")
                # Verify it's actually an ONVIF response not an HTML error page
                if "Manufacturer" in body or "GetDeviceInformationResponse" in body:
                    return body
    except Exception:
        pass
    return None


def _extract(xml: str, tag: str) -> str:
    """Extract tag value handling both prefixed and unprefixed tags."""
    # Try tds:Tag first, then any namespace prefix, then bare tag
    for pattern in [
        f"<tds:{tag}>(.*?)</tds:{tag}>",
        f"<[^>]+:{tag}[^>]*>(.*?)</[^>]+:{tag}>",
        f"<{tag}[^>]*>(.*?)</{tag}>",
    ]:
        m = re.search(pattern, xml, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()
    return ""


class ONVIFProber:
    """
    Probe a camera for device information via unauthenticated ONVIF.
    Tries ONVIF_PORTS in order, returns first successful result.
    """

    TIMEOUT = 4

    def probe(self, ip: str, open_ports: List[int]) -> Dict[str, str]:
        """
        Returns dict with manufacturer, model, firmware, serial, mac_address.
        Returns {} if camera does not respond to ONVIF on any port.
        """
        # Only try ports that are actually open on this device
        candidates = [p for p in ONVIF_PORTS if p in open_ports]
        # Always try at least port 80 as fallback
        if not candidates:
            candidates = [80]

        for port in candidates:
            xml = _send_onvif(ip, port, self.TIMEOUT)
            if xml:
                result = self._parse(xml, ip, port)
                if result:
                    return result

        return {}

    def _parse(self, xml: str, ip: str, port: int) -> Dict[str, str]:
        manufacturer = _extract(xml, "Manufacturer")
        model        = _extract(xml, "Model")
        firmware     = _extract(xml, "FirmwareVersion")
        serial       = _extract(xml, "SerialNumber")
        hardware_id  = _extract(xml, "HardwareId")

        if not manufacturer and not firmware:
            return {}

        result = {
            "manufacturer":    manufacturer or "Unknown",
            "model":           model or manufacturer or "Unknown",
            "firmware":        firmware,
            "serial":          serial,
            "hardware_id":     hardware_id,
            "onvif_port":      str(port),
        }

        logger.info(
            f"ONVIF {ip}:{port} → "
            f"mfr={manufacturer} model={model} "
            f"fw={firmware} serial={serial}"
        )
        return result
