import socket
import requests
from typing import List, Dict
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.audit")

class VulnerabilityAuditor:
    """
    Active security module that verifies vulnerabilities.
    """
    
    def __init__(self):
        # Common credentials to test (Username, Password)
        self.default_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password'),
            ('user', 'user')
        ]

    def audit_device(self, ip: str, open_ports: List[int]) -> List[Dict]:
        """
        Runs targeted checks based on open ports.
        Returns a list of vulnerability objects.
        """
        findings = []
        
        # Check 1: Unencrypted Telnet (Port 23)
        if 23 in open_ports:
            findings.append({
                "severity": "CRITICAL",
                "type": "Insecure Protocol",
                "description": "Telnet service detected. Traffic is unencrypted."
            })

        # Check 2: HTTP Basic Auth Default Creds (Port 80/8080)
        # Note: We use a short timeout to avoid hanging the scan
        for port in [80, 8080]:
            if port in open_ports:
                if self._check_http_defaults(ip, port):
                    findings.append({
                        "severity": "HIGH",
                        "type": "Default Credentials",
                        "description": f"Accessible via HTTP Basic Auth (admin/admin) on port {port}"
                    })

        return findings

    def _check_http_defaults(self, ip: str, port: int) -> bool:
        """
        Tries to login to HTTP services with admin/admin.
        """
        target_url = f"http://{ip}:{port}"
        try:
            # We specifically look for 401 (Unauthorized) first to confirm Auth is needed,
            # then try to bypass it.
            # For this simple test, we just try to login.
            for user, pwd in self.default_creds:
                try:
                    r = requests.get(target_url, auth=(user, pwd), timeout=2)
                    # If we get a 200 OK after being prompted for auth, we're in.
                    if r.status_code == 200:
                        return True
                except requests.exceptions.RequestException:
                    continue
        except:
            pass
        return False
