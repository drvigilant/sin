"""
sin.scanner.dvrip_probe
═══════════════════════
Probes Xiongmai/Dahua devices on TCP 34567 (DVRIP binary protocol).

Capabilities
────────────
  1. Port detection          — is TCP 34567 open?
  2. Auth probe              — anonymous → vault credentials → default list
  3. Device fingerprint      — DeviceType, ChannelNum, firmware from login response
  4. Deep analysis           — config pull, network settings, DDNS, user skeleton,
                               connected channel topology (NVR/DVR), RSA key exposure

Safety contract
───────────────
  - MAX_DEFAULT_ATTEMPTS = 3 — stops before triggering lockout (Xiongmai locks at 5)
  - Vault credentials are tried first at priority order, counted separately
  - Lockout detection: Ret=206 → immediate stop, mark device as locked
  - Socket timeout: 3 seconds per attempt
"""

import hashlib
import json
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.dvrip_probe")

# ── Constants ──────────────────────────────────────────────────────────────────
DVRIP_PORT          = 34567
SOCKET_TIMEOUT      = 3
MAX_DEFAULT_ATTEMPTS = 3

RET_OK        = 100
RET_LOCKED    = 206
RET_BAD_CREDS = 203

# Xiongmai factory defaults — ordered by prevalence
DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "123456"),
]

# Config names that yield useful intelligence on this firmware generation
DEEP_ANALYSIS_KEYS = [
    "NetWork.NetCommon",       # IP, MAC, gateway
    "NetWork.NetDDNS.[0]",     # DDNS key, hostname, credentials
    "NetWork.NetEmail.[0]",    # SMTP server, credentials
    "NetWork.NetFTP.[0]",      # FTP exfil credentials
    "NetWork.NetNTP.[0]",      # NTP server
    "General.Location",        # Timezone, DST
    "Camera.Param.[0]",        # Sensor parameters
    "AVEnc.VideoColor.[0]",    # Video encoding
    "Storage.Snapshot.[0]",    # Storage mask
    "Simplify.Encode",         # Stream config
]


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class DVRIPAuthResult:
    success: bool
    ret_code: int
    username: str = ""
    password: str = ""
    credential_id: Optional[int] = None   # vault ID if from vault
    session_id: int = 0
    device_type: str = ""
    channel_num: int = 0
    alive_interval: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DVRIPProbeResult:
    ip: str
    port_open: bool = False
    locked: bool = False
    auth: Optional[DVRIPAuthResult] = None
    deep_analysis: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def authenticated(self) -> bool:
        return self.auth is not None and self.auth.success

    @property
    def severity(self) -> str:
        if not self.port_open:
            return "none"
        if self.authenticated:
            if self.auth.password == "":
                return "critical"   # no password at all
            return "high"           # default credential
        if self.locked:
            return "medium"         # locked but port exposed
        return "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "port_open": self.port_open,
            "locked": self.locked,
            "authenticated": self.authenticated,
            "severity": self.severity,
            "auth": {
                "success": self.auth.success,
                "ret_code": self.auth.ret_code,
                "username": self.auth.username,
                "password_redacted": "***" if self.auth.password else "(empty)",
                "device_type": self.auth.device_type,
                "channel_num": self.auth.channel_num,
                "credential_id": self.auth.credential_id,
            } if self.auth else None,
            "deep_analysis": self.deep_analysis,
            "error": self.error,
        }


# ── Protocol helpers ───────────────────────────────────────────────────────────

def _sofia_hash(password: str) -> str:
    """Xiongmai Sofia MD5 hash — not standard MD5."""
    md5 = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join([chars[sum(x) % 62] for x in zip(md5[::2], md5[1::2])])


def _make_packet(session: int, seq: int, code: int, data: Dict) -> bytes:
    payload = json.dumps(data, separators=(",", ":")).encode() + b"\x0a\x00"
    header = struct.pack("<BBHIIHHI", 0xFF, 0x01, 0, session, seq, 0, code, len(payload))
    return header + payload


def _recv_packet(sock: socket.socket) -> Optional[Dict]:
    try:
        header = b""
        while len(header) < 20:
            chunk = sock.recv(20 - len(header))
            if not chunk:
                return None
            header += chunk
        _, _, _, _, _, _, _, length = struct.unpack("<BBHIIHHI", header)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.rstrip(b"\x0a\x00"))
    except Exception:
        return None


def _connect(ip: str) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((ip, DVRIP_PORT))
        return s
    except Exception:
        return None


def _attempt_login(ip: str, username: str, password: str) -> Tuple[int, Dict]:
    """Single login attempt. Returns (ret_code, full_response)."""
    s = _connect(ip)
    if s is None:
        return -1, {}
    try:
        payload = {
            "EncryptType": "MD5",
            "LoginType": "DVRIP-Web",
            "PassWord": _sofia_hash(password),
            "UserName": username,
        }
        s.send(_make_packet(0, 0, 1000, payload))
        resp = _recv_packet(s)
        if resp is None:
            return -1, {}
        return resp.get("Ret", -1), resp
    except Exception:
        return -1, {}
    finally:
        try:
            s.close()
        except Exception:
            pass


def _get_config(sock: socket.socket, session: int, name: str) -> Optional[Any]:
    """Pull a named config block from an authenticated session."""
    try:
        sock.send(_make_packet(session, 1, 1042, {"Name": name, "SessionID": hex(session)}))
        resp = _recv_packet(sock)
        if resp and resp.get("Ret") == RET_OK:
            return resp.get(name)
        return None
    except Exception:
        return None


# ── Main probe class ───────────────────────────────────────────────────────────

class DVRIPProbe:
    """
    Probe a single device on TCP 34567.

    Usage:
        probe = DVRIPProbe()
        result = probe.probe("192.168.30.162")
        result = probe.probe("192.168.30.86", vault_creds=[{"username":"admin","password":"Aaaa1111","id":1}])
        result = probe.probe("192.168.30.86", vault_creds=[...], deep=True)
    """

    def probe(
        self,
        ip: str,
        vault_creds: Optional[List[Dict]] = None,
        deep: bool = False,
    ) -> DVRIPProbeResult:
        result = DVRIPProbeResult(ip=ip)

        # 1 — Port check
        s = _connect(ip)
        if s is None:
            result.error = "connection_refused"
            return result
        s.close()
        result.port_open = True

        # 2 — Build credential list: vault first (high priority), then defaults
        candidates: List[Tuple[str, str, Optional[int]]] = []

        if vault_creds:
            for vc in sorted(vault_creds, key=lambda x: x.get("priority", 0), reverse=True):
                candidates.append((vc["username"], vc["password"], vc.get("id")))

        # Add defaults up to MAX_DEFAULT_ATTEMPTS, skip any already in vault
        vault_pairs = {(c[0], c[1]) for c in candidates}
        default_count = 0
        for user, pwd in DEFAULT_CREDENTIALS:
            if default_count >= MAX_DEFAULT_ATTEMPTS:
                break
            if (user, pwd) not in vault_pairs:
                candidates.append((user, pwd, None))
                default_count += 1

        # 3 — Auth sweep
        auth_result = None
        for username, password, cred_id in candidates:
            ret, resp = _attempt_login(ip, username, password)

            if ret == RET_LOCKED:
                result.locked = True
                logger.warning(f"[dvrip_probe] {ip} account locked (Ret=206)")
                break

            if ret == RET_OK:
                auth_result = DVRIPAuthResult(
                    success=True,
                    ret_code=ret,
                    username=username,
                    password=password,
                    credential_id=cred_id,
                    session_id=int(resp.get("SessionID", "0x0"), 16),
                    device_type=resp.get("DeviceType ", resp.get("DeviceType", "")),
                    channel_num=resp.get("ChannelNum", 0),
                    alive_interval=resp.get("AliveInterval", 0),
                    extra=resp,
                )
                logger.info(
                    f"[dvrip_probe] {ip} authenticated as {username}/"
                    f"{'(empty)' if not password else '***'} "
                    f"DeviceType={auth_result.device_type} Channels={auth_result.channel_num}"
                )
                break
            else:
                logger.debug(f"[dvrip_probe] {ip} Ret={ret} for {username}/{repr(password)}")

        result.auth = auth_result

        # 4 — Deep analysis if authenticated and requested
        if deep and auth_result and auth_result.success:
            result.deep_analysis = self._deep_analysis(ip, auth_result)

        return result

    def _deep_analysis(self, ip: str, auth: DVRIPAuthResult) -> Dict[str, Any]:
        """Pull all intelligence from an authenticated session."""
        analysis: Dict[str, Any] = {
            "session_id": hex(auth.session_id),
            "device_type": auth.device_type,
            "channel_num": auth.channel_num,
            "configs": {},
            "secrets_found": [],
            "rsa_public_key": None,
        }

        s = _connect(ip)
        if s is None:
            analysis["error"] = "reconnect_failed"
            return analysis

        try:
            # Re-authenticate for deep session
            payload = {
                "EncryptType": "MD5",
                "LoginType": "DVRIP-Web",
                "PassWord": _sofia_hash(auth.password),
                "UserName": auth.username,
            }
            s.send(_make_packet(0, 0, 1000, payload))
            resp = _recv_packet(s)
            if not resp or resp.get("Ret") != RET_OK:
                analysis["error"] = "reauth_failed"
                return analysis

            session = int(resp.get("SessionID", "0x0"), 16)

            # Pull RSA key (no auth required in protocol but we do it here too)
            s.send(_make_packet(session, 1, 1010, {"Name": "", "SessionID": hex(session)}))
            enc_resp = _recv_packet(s)
            if enc_resp and enc_resp.get("Ret") == RET_OK:
                analysis["rsa_public_key"] = {
                    "bits": enc_resp.get("Bits"),
                    "communicate_bits": enc_resp.get("CommunicateBits"),
                    "algo": enc_resp.get("EncryptAlgo"),
                    "modulus": enc_resp.get("PublicKey", "").split(",")[0],
                    "exponent": enc_resp.get("PublicKey", "").split(",")[1] if "," in enc_resp.get("PublicKey", "") else None,
                }

            # Pull config blocks
            for name in DEEP_ANALYSIS_KEYS:
                val = _get_config(s, session, name)
                if val is not None:
                    analysis["configs"][name] = val
                    # Secret detection
                    self._detect_secrets(name, val, analysis["secrets_found"])

        except Exception as e:
            analysis["error"] = str(e)
        finally:
            try:
                s.close()
            except Exception:
                pass

        return analysis

    def _detect_secrets(self, config_name: str, value: Any, secrets: List[Dict]) -> None:
        """Scan config values for credentials and sensitive strings."""
        if not isinstance(value, dict):
            return

        sensitive_keys = {
            "Password", "PassWord", "password", "UserName", "userName",
            "DDNSKey", "Key", "Token", "Secret", "AuthCode",
        }

        def _scan(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full_path = f"{path}.{k}" if path else k
                    if k in sensitive_keys and v and str(v).strip():
                        secrets.append({
                            "config": config_name,
                            "key": full_path,
                            "value_present": True,
                            "value_empty": not bool(str(v).strip()),
                        })
                    _scan(v, full_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f"{path}[{i}]")

        _scan(value)


# Module-level singleton
dvrip_probe = DVRIPProbe()
