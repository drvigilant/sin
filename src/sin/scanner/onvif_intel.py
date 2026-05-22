"""
sin.scanner.onvif_intel
═══════════════════════
Authenticated ONVIF probing with credential vault fallback.
Tries unauthenticated first, then WS-Security digest auth.
"""
import urllib.request
import urllib.error
import hashlib
import base64
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.onvif_intel")

INFO_PAYLOAD_TMPL = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>{auth_header}</s:Header>
  <s:Body>
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"""

NET_PAYLOAD_TMPL = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>{auth_header}</s:Header>
  <s:Body>
    <GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"""


def _build_auth_header(username: str, password: str) -> str:
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode()
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest_raw = hashlib.sha1(
        nonce_bytes + created.encode() + password.encode()
    ).digest()
    digest_b64 = base64.b64encode(digest_raw).decode()
    return f"""<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsse:UsernameToken>
    <wsse:Username>{username}</wsse:Username>
    <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest_b64}</wsse:Password>
    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
    <wsu:Created>{created}</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>"""


def _send_soap(url: str, payload: str, timeout: int = 5) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "User-Agent": "SIN-EDR/4.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "401"
    except Exception:
        pass
    return None


def _extract_xml(xml_string: str, tag: str) -> str:
    match = re.search(f"<{tag}[^>]*>(.*?)</{tag}>", xml_string, re.IGNORECASE)
    if not match:
        match = re.search(
            f"<[^>]+:{tag}[^>]*>(.*?)</[^>]+:{tag}>", xml_string, re.IGNORECASE
        )
    return match.group(1).strip() if match else ""


class ONVIFProber:
    TIMEOUT = 5

    def probe(self, ip: str, open_ports: List[int]) -> Dict[str, str]:
        candidates = [p for p in [80, 8080, 8899, 8000] if p in open_ports] or [80]
        for port in candidates:
            url = f"http://{ip}:{port}/onvif/device_service"
            result = self._probe_url(url, ip)
            if result:
                return result
        return {}

    def _probe_url(self, url: str, ip: str) -> Dict[str, str]:
        # Try unauthenticated first
        result = self._fetch_device_info(url, auth_header="")
        if result and result != "401":
            return result

        # Auth required — pull from vault
        try:
            from sin.storage.credential_vault import vault
            creds = vault.get_for_device(ip)
        except Exception:
            creds = []

        for cred in creds:
            auth = _build_auth_header(cred["username"], cred["password"])
            result = self._fetch_device_info(url, auth_header=auth)
            if result and result != "401":
                try:
                    from sin.storage.credential_vault import vault
                    vault.mark_success(cred["id"], ip)
                except Exception:
                    pass
                logger.info(f"ONVIF auth success on {ip} with user={cred['username']}")
                return result

        return {}

    def _fetch_device_info(self, url: str, auth_header: str):
        info_payload = INFO_PAYLOAD_TMPL.format(auth_header=auth_header)
        resp = _send_soap(url, info_payload, self.TIMEOUT)

        if resp == "401":
            return "401"
        if not resp:
            return {}

        data = {
            "manufacturer": _extract_xml(resp, "Manufacturer"),
            "model":        _extract_xml(resp, "Model"),
            "firmware":     _extract_xml(resp, "FirmwareVersion"),
            "serial":       _extract_xml(resp, "SerialNumber"),
        }

        # Get MAC via network interfaces
        net_payload = NET_PAYLOAD_TMPL.format(auth_header=auth_header)
        net_resp = _send_soap(url, net_payload, self.TIMEOUT)
        if net_resp and net_resp != "401":
            mac = _extract_xml(net_resp, "HwAddress")
            if mac:
                data["mac_address"] = mac.replace("-", ":").upper()

        if any(data.values()):
            logger.info(f"ONVIF data from {url}: {data}")

        return data if any(data.values()) else {}


onvif_prober = ONVIFProber()
