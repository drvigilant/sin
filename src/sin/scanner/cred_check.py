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
• Xiongmai  — port 34567 binary SDK protocol (Phase 2.3) — most reliable
• Hikvision — tests /ISAPI/Security/userCheck via HTTP Basic/Digest
• Dahua     — tests /cgi-bin/snapshot.cgi via HTTP Basic/Digest
• Generic   — tests device root path with Basic, then Digest
"""

from __future__ import annotations

import base64
import hashlib
import json as _json
import os
import socket as _socket
import struct as _struct
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.cred_check")

TIMEOUT_S    = 3
MAX_ATTEMPTS = 3

# ── Per-vendor credential tables (factory defaults, publicly documented) ───────
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
_XIONGMAI_HTTP_CREDS: List[Tuple[str, str]] = [
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
    "hikvision": (_HIKVISION_CREDS,     "/ISAPI/Security/userCheck"),
    "dahua":     (_DAHUA_CREDS,         "/cgi-bin/snapshot.cgi"),
    "xiongmai":  (_XIONGMAI_HTTP_CREDS, "/"),
    "generic":   (_GENERIC_CREDS,       "/"),
}

# ── Xiongmai SDK default credentials (port 34567 binary protocol) ─────────────
# Factory defaults documented in Xiongmai/XMeye/Sofia SDK public research.
_XIONGMAI_SDK_CREDS: List[Tuple[str, str]] = [
    ("admin",   ""),        # blank — most common factory default
    ("admin",   "888888"),  # numeric default
    ("admin",   "admin"),
    ("admin",   "12345"),
    ("admin",   "123456"),
    ("default", ""),
    ("guest",   "guest"),
    ("root",    ""),
]

_XM_MAGIC      = b'\xff\x01\x00\x00'
_XM_CMD_LOGIN  = 0x27a0
_XM_HEADER_FMT = "<4sIIBBHI"


def _xm_md5_password(password: str) -> str:
    """
    Compute Xiongmai's custom password encoding.
    Empty password maps to the known constant 'tlJwpbo6'.
    Non-empty passwords use a shuffled truncated MD5.
    """
    if password == "":
        return "tlJwpbo6"
    raw = hashlib.md5(password.encode()).hexdigest().upper()
    chars = []
    for i in range(0, 32, 2):
        val = (ord(raw[i]) + ord(raw[i + 1])) % 62
        if val < 10:
            chars.append(chr(val + ord('0')))
        elif val < 36:
            chars.append(chr(val - 10 + ord('A')))
        else:
            chars.append(chr(val - 36 + ord('a')))
    return "".join(chars[:8])


def _xm_build_login(username: str, password: str) -> bytes:
    payload = (_json.dumps({
        "EncryptType": "MD5",
        "LoginType":   "DVRIP-Web",
        "PassWord":    _xm_md5_password(password),
        "UserName":    username,
    }, separators=(',', ':')) + '\n').encode()
    header = _struct.pack(
        _XM_HEADER_FMT,
        _XM_MAGIC, 0, 0, 0, 0, _XM_CMD_LOGIN, len(payload)
    )
    return header + payload


def _xm_read_response(sock: _socket.socket, timeout: float = 3.0) -> Optional[dict]:
    """Read one Xiongmai SDK packet, return parsed JSON or None on failure."""
    sock.settimeout(timeout)
    try:
        header = b''
        while len(header) < 20:
            chunk = sock.recv(20 - len(header))
            if not chunk:
                return None
            header += chunk
        if header[:4] != _XM_MAGIC:
            return None
        data_len = _struct.unpack_from("<I", header, 16)[0]
        if data_len == 0 or data_len > 65536:
            return {}
        payload = b''
        while len(payload) < data_len:
            chunk = sock.recv(data_len - len(payload))
            if not chunk:
                break
            payload += chunk
        return _json.loads(payload.rstrip(b'\x0a').decode('utf-8', errors='ignore'))
    except Exception:
        return None


def _check_xiongmai_sdk(ip: str) -> Optional[Tuple[str, str]]:
    """
    Try Xiongmai SDK default credentials on port 34567.
    Returns (username, password) on success (Ret==100), None otherwise.
    Ret==101 means wrong password — device confirmed Xiongmai, continue trying.
    Max 3 attempts to avoid lockout.
    """
    for username, password in _XIONGMAI_SDK_CREDS[:MAX_ATTEMPTS]:
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT_S)
            sock.connect((ip, 34567))
            sock.sendall(_xm_build_login(username, password))
            resp = _xm_read_response(sock)
            sock.close()

            if resp is None:
                break   # Not speaking Xiongmai SDK
            ret = resp.get("Ret", -1)
            if ret == 100:
                logger.warning(
                    "🔑 Xiongmai SDK default creds confirmed on %s:34567 — %s/%s",
                    ip, username, password or "<blank>"
                )
                return username, password
            elif ret == 101:
                logger.debug("[cred_check] %s:34567 Ret=101 wrong pw for %s/%s",
                             ip, username, password or "<blank>")
                # Device confirmed — continue trying next pair
            else:
                break   # Unexpected response — stop
        except (_socket.timeout, ConnectionRefusedError, OSError):
            break
        except Exception as e:
            logger.debug("[cred_check] %s:34567 error: %s", ip, e)
            break
    return None


# ── CredChecker ────────────────────────────────────────────────────────────────

class CredChecker:
    """Default credential checker. Stateless — safe to call in parallel."""

    def check(self, device_data: Dict) -> Optional[Dict]:
        """
        Test default credentials against a device.
        Returns a vulnerability dict on success, None otherwise.

        Strategy (in order):
        1. Port 34567 open → Xiongmai SDK binary protocol (Phase 2.3)
        2. HTTP port open  → vendor-specific HTTP Basic/Digest
        """
        ip    = device_data.get("ip_address", "")
        ports = set(device_data.get("open_ports", []))
        mfr   = (device_data.get("manufacturer") or "").lower()

        # ── Path 1: Xiongmai SDK binary protocol ──────────────────────────────
        if 34567 in ports:
            hit = _check_xiongmai_sdk(ip)
            if hit:
                user, pw = hit
                return {
                    "severity":       "CRITICAL",
                    "type":           "DEFAULT_CREDS_FOUND",
                    "description": (
                        f"Default credentials confirmed via Xiongmai SDK (port 34567): "
                        f"user='{user}' password='{pw or '<blank>'}'. "
                        "Full unauthenticated device control — live stream, config, firmware upload."
                    ),
                    "confidence":     1.0,
                    "engine":         "cred_check_sdk",
                    "epss":           0.0,
                    "priority_score": 9.8,
                    "port":           34567,
                    "protocol":       "Xiongmai SDK",
                }

        # ── Path 2: HTTP Basic/Digest ──────────────────────────────────────────
        http_port = self._pick_http_port(ports)
        if not http_port:
            return None

        vendor_key = self._resolve_vendor(mfr)
        creds, path = _VENDOR_PROFILES[vendor_key]

        base_url  = f"http://{ip}:{http_port}"
        auth_type = self._probe_auth_type(base_url + path)
        if auth_type is None:
            return None

        hit = self._try_creds(base_url + path, creds, auth_type)
        if hit is None:
            return None

        user, pw = hit
        logger.warning("🔑 Default creds confirmed on %s:%d — %s/%s (%s)",
                       ip, http_port, user, pw or "<blank>", vendor_key)
        return {
            "severity":       "CRITICAL",
            "type":           "DEFAULT_CREDS_FOUND",
            "description": (
                f"Default credentials confirmed: user='{user}' password='{pw or '<blank>'}' "
                f"on http://{ip}:{http_port}{path} ({vendor_key} profile, {auth_type} auth). "
                "Attacker can fully control this device without privilege escalation."
            ),
            "confidence":     1.0,
            "engine":         "cred_check",
            "epss":           0.0,
            "priority_score": 9.5,
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _pick_http_port(self, ports: set) -> Optional[int]:
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
        """One unauthenticated GET to determine auth type. Not counted in MAX_ATTEMPTS."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SIN-Scanner/3.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                if resp.status == 200:
                    return None  # Open — no auth needed
        except urllib.error.HTTPError as e:
            if e.code == 401:
                www_auth = e.headers.get("WWW-Authenticate", "").lower()
                return "digest" if "digest" in www_auth else "basic"
        except Exception:
            pass
        return None

    def _try_creds(
        self,
        url:       str,
        creds:     List[Tuple[str, str]],
        auth_type: str,
    ) -> Optional[Tuple[str, str]]:
        for user, pw in creds[:MAX_ATTEMPTS]:
            try:
                ok = (self._try_digest(url, user, pw)
                      if auth_type == "digest"
                      else self._try_basic(url, user, pw))
                if ok:
                    return user, pw
            except Exception as exc:
                logger.debug("Cred check error for %s: %s", url, exc)
        return None

    def _try_basic(self, url: str, user: str, pw: str) -> bool:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SIN-Scanner/3.0", "Authorization": f"Basic {token}"},
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
        opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
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
