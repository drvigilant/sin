"""
sin.scanner.cred_check
══════════════════════
Default credential checker for IoT cameras and DVRs.

Safety contract
───────────────
• Max 3 credential attempts per device total — prevents account lockout.
• 3-second timeout per request — avoids blocking the scan pipeline.
• Never retries on network errors.
• Only tests known, publicly documented factory defaults — no brute-force.

Supported vendors
──────────────────
• Hikvision  — tests /ISAPI/Security/userCheck (requires auth)
• Dahua      — tests /cgi-bin/snapshot.cgi (requires auth)
• Xiongmai   — tests port 80 root (HTTP Basic is common on web panel)
• Generic    — tests device root path with Basic, then Digest

Returns a vulnerability dict if default creds are confirmed, else None.
"""

from __future__ import annotations

import urllib.request
import urllib.error
import urllib.parse
import base64
import hashlib
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.cred_check")

TIMEOUT_S   = 3
MAX_ATTEMPTS = 3

# ── Per-vendor credential tables (factory defaults, publicly documented) ───────
# Order matters: most-likely first.
_HIKVISION_CREDS: List[Tuple[str, str]] = [
    ("admin", "12345"),
    ("admin", "admin"),
    ("admin", ""),
]
_DAHUA_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", ""),
    ("888888", "888888"),
]
_XIONGMAI_CREDS: List[Tuple[str, str]] = [
    ("admin", "888888"),
    ("admin", ""),
    ("admin", "admin"),
]
_GENERIC_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("root",  "root"),
    ("root",  ""),
    ("user",  "user"),
]

# Vendor → (candidate_creds, test_path)
_VENDOR_PROFILES: Dict[str, Tuple[List[Tuple[str, str]], str]] = {
    "hikvision": (_HIKVISION_CREDS, "/ISAPI/Security/userCheck"),
    "dahua":     (_DAHUA_CREDS,     "/cgi-bin/snapshot.cgi"),
    "xiongmai":  (_XIONGMAI_CREDS,  "/"),
    "generic":   (_GENERIC_CREDS,   "/"),
}


class CredChecker:
    """Default credential checker. Stateless — safe to call in parallel."""

    def check(self, device_data: Dict) -> Optional[Dict]:
        """
        Test default credentials against a device.
        Returns a vulnerability dict on success, None if no default creds found.
        """
        ip    = device_data.get("ip_address", "")
        ports = set(device_data.get("open_ports", []))
        mfr   = (device_data.get("manufacturer") or "").lower()

        http_port = self._pick_http_port(ports)
        if not http_port:
            return None  # No HTTP service reachable — skip

        vendor_key = self._resolve_vendor(mfr)
        creds, path = _VENDOR_PROFILES[vendor_key]

        base_url = f"http://{ip}:{http_port}"
        auth_type = self._probe_auth_type(base_url + path)
        if auth_type is None:
            return None  # Endpoint unreachable or open (no auth needed)

        hit = self._try_creds(base_url + path, creds, auth_type)
        if hit is None:
            return None

        user, pw = hit
        logger.warning("🔑 Default creds confirmed on %s:%d — %s/%s (%s)",
                       ip, http_port, user, pw or "<blank>", vendor_key)
        return {
            "severity":    "CRITICAL",
            "type":        "DEFAULT_CREDS_FOUND",
            "description": (
                f"Default credentials confirmed: user='{user}' password='{pw or '<blank>'}' "
                f"on http://{ip}:{http_port}{path} ({vendor_key} profile, {auth_type} auth). "
                "Attacker can fully control this device without privilege escalation."
            ),
            "confidence": 1.0,
            "engine":     "cred_check",
            "epss":       0.0,
            "priority_score": 9.5,
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _pick_http_port(self, ports: set) -> Optional[int]:
        """Choose the most likely HTTP management port from open ports."""
        for candidate in (80, 8080, 8000, 443, 8443):
            if candidate in ports:
                return candidate
        return None

    def _resolve_vendor(self, mfr: str) -> str:
        for key in ("hikvision", "dahua", "xiongmai"):
            if key in mfr:
                return key
        return "generic"

    def _probe_auth_type(self, url: str) -> Optional[str]:
        """
        Make one unauthenticated GET to determine auth type.
        Returns 'basic', 'digest', or None (open / unreachable).
        Does NOT count against the MAX_ATTEMPTS limit.
        """
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SIN-Scanner/3.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                if resp.status == 200:
                    return None  # Endpoint is open — no auth needed
        except urllib.error.HTTPError as e:
            if e.code == 401:
                www_auth = e.headers.get("WWW-Authenticate", "").lower()
                if "digest" in www_auth:
                    return "digest"
                return "basic"
        except Exception:
            pass
        return None  # Unreachable / error

    def _try_creds(
        self,
        url: str,
        creds: List[Tuple[str, str]],
        auth_type: str,
    ) -> Optional[Tuple[str, str]]:
        """Try up to MAX_ATTEMPTS credential pairs. Return the first that works."""
        for user, pw in creds[:MAX_ATTEMPTS]:
            try:
                if auth_type == "digest":
                    success = self._try_digest(url, user, pw)
                else:
                    success = self._try_basic(url, user, pw)

                if success:
                    return user, pw
            except Exception as exc:
                logger.debug("Cred check error for %s: %s", url, exc)
        return None

    def _try_basic(self, url: str, user: str, pw: str) -> bool:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent":    "SIN-Scanner/3.0",
                "Authorization": f"Basic {token}",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code not in (401, 403)
        except Exception:
            return False

    def _try_digest(self, url: str, user: str, pw: str) -> bool:
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, user, pw)
        handler = urllib.request.HTTPDigestAuthHandler(mgr)
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, headers={"User-Agent": "SIN-Scanner/3.0"})
        try:
            with opener.open(req, timeout=TIMEOUT_S) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code not in (401, 403)
        except Exception:
            return False


# ── Module-level singleton ─────────────────────────────────────────────────────
cred_checker = CredChecker()
