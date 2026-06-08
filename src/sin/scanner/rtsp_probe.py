"""
sin.scanner.rtsp_probe
══════════════════════
Tests RTSP streams for:
  1. Unauthenticated access  — CRITICAL  (probe)
  2. Default credential acceptance — HIGH  (probe_with_creds)

RTSP uses the same WWW-Authenticate / Authorization mechanism as HTTP.
Both Basic and Digest (RFC 2617) auth are supported.

Safety contract
───────────────
- MAX_CRED_ATTEMPTS = 3 per device — prevents account lockout.
- 4-second socket timeout per connection.
- Only tests publicly documented factory defaults.
"""

import base64
import hashlib
import re
import socket
from typing import Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.rtsp_probe")

# ── Constants ─────────────────────────────────────────────────────────────────
RTSP_PORTS        = [554, 8554, 10554]
MAX_CRED_ATTEMPTS = 3

# ── Common RTSP paths ─────────────────────────────────────────────────────────
RTSP_PATHS = [
    "/",
    "/live",
    "/stream",
    "/live/ch00_0",
    "/cam/realmonitor?channel=1&subtype=0",          # Dahua
    "/Streaming/Channels/101",                        # Hikvision
    "/h264Preview_01_main",                           # Hikvision alt
    "/live/main",
    "/video1",
    "/ch01.264",                                      # Xiongmai/Generic DVR
    "/user=admin&password=&channel=1&stream=0.sdp",  # Generic
    "/onvif1",
]

VENDOR_PATHS: Dict[str, List[str]] = {
    "hikvision": [
        "/Streaming/Channels/101",
        "/Streaming/Channels/102",
        "/h264Preview_01_main",
        "/h264Preview_01_sub",
    ],
    "dahua": [
        "/cam/realmonitor?channel=1&subtype=0",
        "/cam/realmonitor?channel=1&subtype=1",
    ],
    "xiongmai": [
        "/ch01.264",
        "/ch02.264",
        "/live/ch00_0",
        "/live/ch00_1",
    ],
    "axis": [
        "/axis-media/media.amp",
        "/mjpg/video.mjpg",
    ],
}

# ── Default RTSP credentials — factory defaults only (publicly documented) ────
RTSP_CREDS: Dict[str, List[Tuple[str, str]]] = {
    "hikvision": [
        ("admin", "12345"),
        ("admin", "admin"),
        ("admin", ""),
    ],
    "dahua": [
        ("admin", "admin"),
        ("admin", ""),
        ("888888", "888888"),
    ],
    "axis": [
        ("root", "pass"),
        ("root", ""),
        ("admin", "admin"),
    ],
    "xiongmai": [
        ("admin", "888888"),
        ("admin", ""),
        ("admin", "admin"),
    ],
    "generic": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "12345"),
        ("root", "root"),
    ],
}


# ── Module-level helpers ──────────────────────────────────────────────────────

def _vendor_key(vendor: str) -> str:
    """Map a free-form vendor string to a credential table key."""
    v = vendor.lower()
    for key in ("hikvision", "dahua", "axis", "xiongmai"):
        if key in v:
            return key
    return "generic"


def _ordered_paths(vendor: str) -> List[str]:
    """Vendor-specific paths first, then generic. Deduplicated, order preserved."""
    paths: List[str] = []
    vendor_lower = vendor.lower()
    for v, vp in VENDOR_PATHS.items():
        if v in vendor_lower:
            paths.extend(vp)
    paths.extend(RTSP_PATHS)
    seen: set = set()
    result: List[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def _parse_digest_challenge(www_auth: str) -> Optional[Dict[str, str]]:
    """
    Parse a WWW-Authenticate: Digest ... header.
    Returns dict with at least 'realm' and 'nonce', or None if not valid Digest.
    """
    if not www_auth.lower().startswith("digest"):
        return None
    params: Dict[str, str] = {}
    for match in re.finditer(r'(\w+)=["\']?([^"\'>,\s]+)["\']?', www_auth):
        params[match.group(1).lower()] = match.group(2)
    if "realm" in params and "nonce" in params:
        return params
    return None


def _digest_response(
    username: str, password: str, realm: str,
    nonce: str, method: str, uri: str,
) -> str:
    """Compute RTSP/HTTP Digest auth response per RFC 2617."""
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def _build_basic_auth(username: str, password: str) -> str:
    """Return Base64-encoded Basic auth token."""
    return base64.b64encode(f"{username}:{password}".encode()).decode()


# ── RTSPProbe ─────────────────────────────────────────────────────────────────

class RTSPProbe:
    TIMEOUT = 4

    # ── Public interface ──────────────────────────────────────────────────────

    def probe(self, ip: str, port: int = 554, vendor: str = "") -> Optional[Dict]:
        """
        Test for unauthenticated RTSP stream access (no credentials required).
        Returns a CRITICAL finding if a 200 OK is received without auth.
        """
        for path in _ordered_paths(vendor):
            if self._try_path(ip, port, path):
                logger.warning(
                    "RTSP OPEN: %s:%d%s — unauthenticated access confirmed", ip, port, path
                )
                return {
                    "severity":    "CRITICAL",
                    "type":        "Unauthenticated RTSP Stream",
                    "cve":         "CWE-306",
                    "description": (
                        f"Live video stream accessible without credentials at "
                        f"rtsp://{ip}:{port}{path}. Anyone on the network can "
                        f"view this camera feed. Immediate authentication required."
                    ),
                    "in_kev":   False,
                    "rtsp_url": f"rtsp://{ip}:{port}{path}",
                    "engine":   "rtsp_probe",
                }
        return None

    def probe_with_creds(
        self, ip: str, port: int = 554, vendor: str = ""
    ) -> Optional[Dict]:
        """
        Test default credentials against an RTSP stream that requires authentication.
        Supports Basic and Digest (RFC 2617) auth.

        Returns a HIGH finding if default credentials are accepted.
        Returns None if the stream is open (no auth needed) or no default creds work.

        Connection budget: 1 auth-probe + MAX_CRED_ATTEMPTS per path, max 3 paths.
        """
        cred_list = RTSP_CREDS[_vendor_key(vendor)][:MAX_CRED_ATTEMPTS]

        for path in _ordered_paths(vendor)[:3]:
            auth_type, challenge = self._probe_auth_type(ip, port, path)

            if auth_type is None or auth_type == "none":
                # None  = no RTSP response on this path, try next
                # none  = open stream, probe() handles this case
                continue

            for username, password in cred_list:
                ok = False
                if auth_type == "basic":
                    ok = self._try_basic(ip, port, path, username, password)
                elif auth_type == "digest" and challenge:
                    ok = self._try_digest(ip, port, path, username, password, challenge)

                if ok:
                    logger.warning(
                        "RTSP default creds confirmed: %s:%d%s — %s/%s (%s auth)",
                        ip, port, path, username, password or "<blank>", auth_type,
                    )
                    return {
                        "severity":    "HIGH",
                        "type":        "RTSP Default Credentials",
                        "cve":         "CWE-1392",
                        "description": (
                            f"RTSP stream at rtsp://{ip}:{port}{path} accepts default "
                            f"credentials (user='{username}' "
                            f"password='{password or '<blank>'}' auth={auth_type}). "
                            "Anyone with network access can view the live video feed."
                        ),
                        "in_kev":      False,
                        "rtsp_url":    f"rtsp://{ip}:{port}{path}",
                        "credentials": {"username": username, "password": password},
                        "auth_type":   auth_type,
                        "engine":      "rtsp_probe",
                    }

            # Found an auth-protected path; all creds rejected — stop here.
            break

        return None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _try_path(self, ip: str, port: int, path: str) -> bool:
        """
        Send OPTIONS then DESCRIBE without credentials.
        Returns True if 200 OK is received (unauthenticated access confirmed).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))

                s.sendall((
                    f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\nUser-Agent: SIN-Scanner/1.0\r\n\r\n"
                ).encode())
                resp1 = s.recv(1024).decode(errors="ignore")
                if "RTSP/1.0" not in resp1:
                    return False

                s.sendall((
                    f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 2\r\nUser-Agent: SIN-Scanner/1.0\r\n"
                    f"Accept: application/sdp\r\n\r\n"
                ).encode())
                resp2 = s.recv(2048).decode(errors="ignore")

                if "401" in resp2 or "403" in resp2:
                    return False
                if "200 OK" in resp2 and "sdp" in resp2.lower():
                    return True
                if "200 OK" in resp2:
                    return True

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return False

    def _probe_auth_type(
        self, ip: str, port: int, path: str
    ) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Send unauthenticated DESCRIBE to determine the auth scheme.

        Returns:
          ("basic",  None)       — Basic auth required
          ("digest", challenge)  — Digest auth required; challenge contains realm+nonce
          ("none",   None)       — Stream is open (no auth)
          (None,     None)       — No valid RTSP response on this path
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))

                s.sendall((
                    f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\nUser-Agent: SIN-Scanner/1.0\r\n\r\n"
                ).encode())
                resp1 = s.recv(1024).decode(errors="ignore")
                if "RTSP/1.0" not in resp1:
                    return None, None

                s.sendall((
                    f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 2\r\nUser-Agent: SIN-Scanner/1.0\r\n"
                    f"Accept: application/sdp\r\n\r\n"
                ).encode())
                resp2 = s.recv(2048).decode(errors="ignore")

                if "200 OK" in resp2:
                    return "none", None

                if "401" not in resp2:
                    return None, None

                for line in resp2.splitlines():
                    if line.lower().startswith("www-authenticate:"):
                        www_auth = line[len("www-authenticate:"):].strip()
                        if "digest" in www_auth.lower():
                            challenge = _parse_digest_challenge(www_auth)
                            if challenge:
                                return "digest", challenge
                        if "basic" in www_auth.lower():
                            return "basic", None

                # 401 without a parseable WWW-Authenticate — attempt Basic anyway
                return "basic", None

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None, None

    def _try_basic(
        self, ip: str, port: int, path: str, username: str, password: str
    ) -> bool:
        """Send DESCRIBE with Basic auth. Returns True on 200 OK."""
        token = _build_basic_auth(username, password)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))
                s.sendall((
                    f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\nUser-Agent: SIN-Scanner/1.0\r\n"
                    f"Accept: application/sdp\r\n"
                    f"Authorization: Basic {token}\r\n\r\n"
                ).encode())
                resp = s.recv(2048).decode(errors="ignore")
                return "200 OK" in resp
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _try_digest(
        self, ip: str, port: int, path: str,
        username: str, password: str, challenge: Dict,
    ) -> bool:
        """Send DESCRIBE with Digest auth (RFC 2617). Returns True on 200 OK."""
        realm    = challenge.get("realm", "")
        nonce    = challenge.get("nonce", "")
        uri      = f"rtsp://{ip}:{port}{path}"
        response = _digest_response(username, password, realm, nonce, "DESCRIBE", uri)
        auth_hdr = (
            f'Digest username="{username}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", response="{response}"'
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))
                s.sendall((
                    f"DESCRIBE {uri} RTSP/1.0\r\n"
                    f"CSeq: 1\r\nUser-Agent: SIN-Scanner/1.0\r\n"
                    f"Accept: application/sdp\r\n"
                    f"Authorization: {auth_hdr}\r\n\r\n"
                ).encode())
                resp = s.recv(2048).decode(errors="ignore")
                return "200 OK" in resp
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


# Module-level singleton
rtsp_probe = RTSPProbe()
