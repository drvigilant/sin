"""
sin.scanner.http_fingerprint
═════════════════════════════
Deep HTTP fingerprinting for IoT cameras, DVRs, and NVRs.

Probes port 80 (and 8080 if present) to extract:
  - Vendor / Manufacturer
  - Model name
  - Firmware version
  - Device type
  - Serial number (if exposed)
  - Web UI framework fingerprint

Detection logic:
  1. Check HTTP response headers (Server, WWW-Authenticate, X-* headers)
  2. Check page <title> and body patterns on root + known login paths
  3. Check specific API endpoints (/ISAPI, /cgi-bin, /api/v1/info)
  4. Check port 34567 banner (Xiongmai SDK magic bytes)

Vendor coverage:
  Hikvision, Dahua, Xiongmai/XMeye/Sofia, Reolink, Annke, Securus,
  Amcrest, Uniview, Axis, Bosch, Hanwha, TP-Link Tapo, Vivotek,
  MikroTik, Ubiquiti, generic GoAhead-Webs DVRs
"""

from __future__ import annotations

import re
import socket
import struct
import urllib.request
import urllib.error
from typing import Dict, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.http_fingerprint")

TIMEOUT = 4

# ── Signature database ─────────────────────────────────────────────────────────
# Each entry: (pattern_in_blob, {fields to set if matched})
# Checked in order — first full match wins for vendor, all non-conflicting fields merge.

_HTTP_SIGS = [
    # Hikvision
    (r"hikvision",            {"vendor": "Hikvision", "device_type": "IP Camera/NVR"}),
    (r"webs.*hikvision",      {"vendor": "Hikvision", "device_type": "IP Camera/NVR"}),
    (r"/doc/page/login\.asp", {"vendor": "Hikvision", "device_type": "IP Camera/NVR"}),
    (r"isapi/system/deviceinfo|hikvision.*isapi|isapi.*hikvision",  {"vendor": "Hikvision", "device_type": "IP Camera/NVR"}),
    # Dahua
    (r"dahua",                {"vendor": "Dahua", "device_type": "IP Camera/NVR"}),
    (r"dh-ipc",               {"vendor": "Dahua", "device_type": "IP Camera"}),
    (r"lechange",             {"vendor": "Dahua (LeChange)", "device_type": "IP Camera"}),
    # Xiongmai / XMeye / Sofia
    (r"xmeye",                {"vendor": "Xiongmai (XMeye)", "device_type": "DVR/NVR"}),
    (r"xiongmai",             {"vendor": "Xiongmai", "device_type": "DVR/NVR"}),
    (r"sofia",                {"vendor": "Xiongmai (Sofia)", "device_type": "DVR/NVR"}),
    (r"goahead-webs",         {"vendor": "Xiongmai/Generic DVR", "device_type": "DVR/NVR"}),
    (r"h\.264 dvr",           {"vendor": "Xiongmai/Generic DVR", "device_type": "DVR"}),
    (r"h264 dvr",             {"vendor": "Xiongmai/Generic DVR", "device_type": "DVR"}),
    (r"dvr login",            {"vendor": "Generic DVR", "device_type": "DVR"}),
    (r"ipc login",            {"vendor": "Generic IPC", "device_type": "IP Camera"}),
    (r"nvr login",            {"vendor": "Generic NVR", "device_type": "NVR"}),
    # Securus (Xiongmai OEM)
    (r"securus",              {"vendor": "Securus (Xiongmai OEM)", "device_type": "DVR/NVR"}),
    # Reolink
    (r"reolink",              {"vendor": "Reolink", "device_type": "IP Camera/NVR"}),
    # Annke
    (r"annke",                {"vendor": "Annke", "device_type": "IP Camera/NVR"}),
    # Amcrest
    (r"amcrest",              {"vendor": "Amcrest", "device_type": "IP Camera/NVR"}),
    # Uniview
    (r"uniview",              {"vendor": "Uniview", "device_type": "IP Camera/NVR"}),
    (r"unv",                  {"vendor": "Uniview", "device_type": "IP Camera/NVR"}),
    # Axis
    (r"axis communications",  {"vendor": "Axis", "device_type": "IP Camera"}),
    (r"vapix",                {"vendor": "Axis", "device_type": "IP Camera"}),
    # Bosch
    (r"bosch security",       {"vendor": "Bosch", "device_type": "IP Camera"}),
    # Hanwha / Samsung
    (r"hanwha",               {"vendor": "Hanwha Vision", "device_type": "IP Camera"}),
    (r"samsung techwin",      {"vendor": "Hanwha Vision (Samsung)", "device_type": "IP Camera"}),
    # TP-Link Tapo
    (r"tapo",                 {"vendor": "TP-Link Tapo", "device_type": "IP Camera"}),
    # Vivotek
    (r"vivotek",              {"vendor": "Vivotek", "device_type": "IP Camera"}),
    # MikroTik
    (r"mikrotik",             {"vendor": "MikroTik", "device_type": "Router"}),
    (r"routeros",             {"vendor": "MikroTik", "device_type": "Router"}),
    # Ubiquiti
    (r"ubiquiti",             {"vendor": "Ubiquiti", "device_type": "Network Device"}),
    (r"unifi",                {"vendor": "Ubiquiti UniFi", "device_type": "Network Device"}),
    # Generic patterns
    (r"ip camera",            {"device_type": "IP Camera"}),
    (r"network camera",       {"device_type": "IP Camera"}),
    (r"web camera",           {"device_type": "IP Camera"}),
    (r"ipcam",                {"device_type": "IP Camera"}),
]

# Known login paths to probe — returns rich device info
_PROBE_PATHS = [
    "/",
    "/Login.htm",                        # Hikvision
    "/doc/page/login.asp",               # Hikvision ISAPI
    "/ISAPI/System/deviceInfo",          # Hikvision device info (XML, often unauth)
    "/cgi-bin/main-cgi",                 # Dahua
    "/RPC2",                             # Dahua RPC
    "/cgi-bin/snapshot.cgi",             # Dahua snapshot
    "/login.htm",                        # generic
    "/index.html",
    "/index.htm",
    "/api/v1/info",                      # Reolink
    "/api/camera/description",           # generic
    "/cgi-bin/hi3510/ptzctrl.cgi",       # HiSilicon-based
    "/web/",                             # Uniview
]

# ── Firmware extraction patterns ───────────────────────────────────────────────
_FW_PATTERNS = [
    r'[Ff]irmware["\s:]+([VvBb]?[\d]+\.[\d]+\.[\d]+[\w\.\-]*)',
    r'[Ss]oftware["\s:]+([VvBb]?[\d]+\.[\d]+\.[\d]+[\w\.\-]*)',
    r'[Vv]ersion["\s:]+([VvBb]?[\d]+\.[\d]+\.[\d]+[\w\.\-]*)',
    r'[Bb]uild[\s:]+(\d{8,})',
    r'fw[\s:=]+([VvBb]?[\d]+\.[\d]+\.[\d]+[\w\.\-]*)',
    r'<version>([^<]+)</version>',
    r'"version"\s*:\s*"([^"]+)"',
    r'APP\s+[\w\-]+\s+(V[\d\.]+)',
    r'V(1\.\d{2}\.\d{2}\.[\w\.]+)',       # Hikvision firmware format
]

# ── Model extraction patterns ──────────────────────────────────────────────────
_MODEL_PATTERNS = [
    r'[Mm]odel[\s:"]+([A-Z]{2,}[\-\w]+)',
    r'<deviceName>([^<]+)</deviceName>',
    r'<model>([^<]+)</model>',
    r'"model"\s*:\s*"([^"]+)"',
    r'"deviceModel"\s*:\s*"([^"]+)"',
    r'(DS-[\w\-]+)',          # Hikvision model
    r'(IPC-[\w\-]+)',         # Dahua model
    r'(NVR[\-\d]+)',          # Generic NVR
    r'(DVR[\-\d]+)',          # Generic DVR
    r'(HWC-[\w\-]+)',         # Hanwha
    r'(AXIS\s+[A-Z\d\s]+)',   # Axis
]

# ── Serial extraction ──────────────────────────────────────────────────────────
_SERIAL_PATTERNS = [
    r'<serialNumber>([^<]+)</serialNumber>',
    r'"serialNumber"\s*:\s*"([^"]+)"',
    r'[Ss]erial[\s:"#]+([A-Z0-9]{6,})',
    r'SN[:\s]+([A-Z0-9]{6,})',
]


def _http_get(ip: str, port: int, path: str) -> Optional[tuple]:
    """Returns (headers_str, body_str) or None on failure."""
    url = f"http://{ip}:{port}{path}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SIN-EDR/4.0)",
                "Accept": "*/*",
            }
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            headers = str(resp.headers)
            body = resp.read(8192).decode("utf-8", errors="ignore")
            return headers, body
    except urllib.error.HTTPError as e:
        # 401 = endpoint exists, auth required — still useful headers
        try:
            headers = str(e.headers)
            body = e.read(2048).decode("utf-8", errors="ignore")
            return headers, body
        except Exception:
            return str(e.headers) if hasattr(e, 'headers') else "", ""
    except Exception:
        return None


def _probe_sdk_port(ip: str) -> Optional[str]:
    """
    Port 34567 Xiongmai SDK identification.
    Send the GetDeviceInfo magic packet and check response signature.
    Returns vendor string if confirmed Xiongmai-family, None otherwise.
    """
    MAGIC = b'\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\x00\x00\x00'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 34567))
        s.send(MAGIC)
        resp = s.recv(512)
        s.close()
        if resp and len(resp) > 4:
            # Xiongmai SDK responses start with 0xff 0x01 or 0xa0
            if resp[0] in (0xff, 0xa0, 0x00) and len(resp) > 20:
                try:
                    text = resp.decode('utf-8', errors='ignore')
                    if any(k in text.lower() for k in ['ok', 'sofia', 'general', 'system']):
                        return "Xiongmai (Sofia SDK confirmed)"
                except Exception:
                    pass
                return "Xiongmai/Generic DVR (SDK port confirmed)"
    except Exception:
        pass
    return None


# ── Xiongmai SDK login probe (Phase 2.1) ──────────────────────────────────────
# The SDK login packet is a 20-byte header:
#   Bytes 0-3 : magic  0xff 0x01 0x00 0x00
#   Bytes 4-7 : session ID (zeros for pre-auth)
#   Bytes 8-11: sequence number (zeros)
#   Byte 12   : channel (0x00)
#   Byte 13   : reserved (0x00)
#   Bytes 14-15: command 0xa0 0x27  → OPLogin
#   Bytes 16-19: payload length (little-endian uint32)
# The JSON payload that follows is a standard Sophia login request.
_XM_HEADER_FMT = "<4sIIBBHI"   # magic, sid, seq, ch, res, cmd, datalen
_XM_MAGIC      = b'\xff\x01\x00\x00'
_XM_CMD_LOGIN  = 0x27a0        # OPLogin command id
_XM_CMD_SYSINFO = 0x27f8       # OPSystemInfo command id

def _xm_build_packet(cmd: int, payload: bytes) -> bytes:
    header = struct.pack(
        _XM_HEADER_FMT,
        _XM_MAGIC,   # magic
        0,           # session id
        0,           # sequence
        0,           # channel
        0,           # reserved
        cmd,         # command
        len(payload),
    )
    return header + payload


def _xm_recv_packet(sock: socket.socket, timeout: float = 3.0) -> Optional[bytes]:
    """Read one complete Xiongmai SDK packet; returns raw payload bytes."""
    sock.settimeout(timeout)
    try:
        header = b''
        while len(header) < 20:
            chunk = sock.recv(20 - len(header))
            if not chunk:
                return None
            header += chunk
        if len(header) < 20 or header[:4] != _XM_MAGIC:
            return None
        data_len = struct.unpack_from("<I", header, 16)[0]
        if data_len == 0 or data_len > 65536:
            return b''
        payload = b''
        while len(payload) < data_len:
            chunk = sock.recv(data_len - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload
    except Exception:
        return None


def probe_xiongmai_sdk(ip: str) -> Dict:
    """
    Send Xiongmai SDK login + OPSystemInfo request on port 34567.
    Parse the JSON response to extract SN, BuildDate, HardWareVersion, SoftWareVersion.

    Returns a dict with any of: vendor, model, firmware, serial_number, device_type.
    Empty dict on failure (no port open / not Xiongmai / no parseable data).
    """
    import json as _json

    result: Dict = {}

    login_payload = _json.dumps({
        "EncryptType": "MD5",
        "LoginType":   "DVRIP-Web",
        "PassWord":    "tlJwpbo6",   # MD5 of empty string — Xiongmai default
        "UserName":    "admin",
    }, separators=(',', ':')).encode() + b'\x0a'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, 34567))

        # ── Step 1: send login ──────────────────────────────────────────────────
        s.sendall(_xm_build_packet(_XM_CMD_LOGIN, login_payload))
        login_resp_raw = _xm_recv_packet(s)

        if login_resp_raw is None:
            s.close()
            return result

        # Mark as Xiongmai regardless of auth outcome
        result["vendor"]      = "Xiongmai (Sofia SDK)"
        result["device_type"] = "DVR/NVR"

        try:
            login_resp = _json.loads(login_resp_raw.rstrip(b'\x0a').decode('utf-8', errors='ignore'))
            ret_code = login_resp.get("Ret", -1)
            # 100 = OK, 101 = wrong password but device confirmed
            session_id = login_resp.get("SessionID", "0x0")
        except Exception:
            login_resp = {}
            ret_code   = -1
            session_id = "0x0"

        logger.debug(f"[xm_sdk] {ip} login Ret={ret_code} sid={session_id}")

        # ── Step 2: request OPSystemInfo (works even with wrong creds on many fw) ─
        sysinfo_payload = _json.dumps({
            "Name": "SystemInfo",
        }, separators=(',', ':')).encode() + b'\x0a'

        # Embed session id returned from login if available
        try:
            sid_int = int(session_id, 16) if isinstance(session_id, str) else int(session_id)
        except Exception:
            sid_int = 0

        si_header = struct.pack(
            _XM_HEADER_FMT,
            _XM_MAGIC,
            sid_int,
            1,           # seq
            0, 0,
            _XM_CMD_SYSINFO,
            len(sysinfo_payload),
        )
        s.sendall(si_header + sysinfo_payload)
        si_raw = _xm_recv_packet(s, timeout=3.0)
        s.close()

        if si_raw:
            try:
                si = _json.loads(si_raw.rstrip(b'\x0a').decode('utf-8', errors='ignore'))
                # Response may be nested under "SystemInfo" key or flat
                info = si.get("SystemInfo", si)

                sn       = info.get("SerialNo") or info.get("SN") or info.get("serialNumber")
                build    = info.get("BuildDate") or info.get("BuildTime")
                hw_ver   = info.get("HardWareVersion") or info.get("HardwareVersion")
                sw_ver   = info.get("SoftWareVersion") or info.get("SoftwareVersion")
                board    = info.get("BoardType")  or info.get("HardWareType")

                if sn:
                    result["serial_number"] = str(sn).strip()
                if hw_ver:
                    result["model"] = str(hw_ver).strip()
                if sw_ver:
                    result["firmware"] = str(sw_ver).strip()
                elif build:
                    result["firmware"] = f"Build {str(build).strip()}"
                if board and result.get("model") in (None, "Unknown", ""):
                    result["model"] = str(board).strip()

                logger.info(f"[xm_sdk] {ip} OPSystemInfo → SN={sn} HW={hw_ver} SW={sw_ver} Build={build}")
            except Exception as parse_err:
                logger.debug(f"[xm_sdk] {ip} OPSystemInfo parse error: {parse_err}")

    except Exception as e:
        logger.debug(f"[xm_sdk] {ip} connection failed: {e}")

    return result


def fingerprint(ip: str, open_ports: list) -> Dict:
    """
    Run full HTTP + SDK fingerprinting on a device.
    Returns dict with any discovered: vendor, model, firmware, serial_number, device_type
    """
    result: Dict = {}
    http_ports = [p for p in [80, 8080, 8000] if p in open_ports]
    all_blobs = []

    # ── HTTP probing ───────────────────────────────────────────────────────────
    for port in http_ports:
        for path in _PROBE_PATHS:
            resp = _http_get(ip, port, path)
            if resp is None:
                continue
            headers, body = resp
            blob = (headers + " " + body).lower()
            all_blobs.append(blob)

            # Extract from headers first
            for line in headers.splitlines():
                line_l = line.lower()
                # Server header — most useful
                if line_l.startswith("server:"):
                    srv = line.split(":", 1)[1].strip()
                    result.setdefault("_server_header", srv)
                # WWW-Authenticate realm often has model
                if "www-authenticate" in line_l and "realm" in line_l:
                    realm = re.search(r'realm="([^"]+)"', line, re.I)
                    if realm:
                        result.setdefault("_realm", realm.group(1))

            # Extract firmware version
            if "firmware" not in result or result.get("firmware") in ("Unknown", "", None):
                for pat in _FW_PATTERNS:
                    m = re.search(pat, body, re.I)
                    if m:
                        fw = m.group(1).strip()
                        if len(fw) >= 4 and len(fw) <= 60:
                            result["firmware"] = fw
                            break

            # Extract model
            if "model" not in result or result.get("model") in ("Unknown", "", None):
                for pat in _MODEL_PATTERNS:
                    m = re.search(pat, body, re.I)
                    if m:
                        mdl = m.group(1).strip()
                        if len(mdl) >= 3 and len(mdl) <= 60:
                            result["model"] = mdl
                            break

            # Extract serial
            if "serial_number" not in result:
                for pat in _SERIAL_PATTERNS:
                    m = re.search(pat, body, re.I)
                    if m:
                        sn = m.group(1).strip()
                        if len(sn) >= 6:
                            result["serial_number"] = sn
                            break

            # Check page title for model hints
            title_m = re.search(r'<title>([^<]+)</title>', body, re.I)
            if title_m:
                raw_title = title_m.group(1).strip()
                result.setdefault("_page_title", raw_title)
                # Parse "BRAND MODEL | DEVICE_TYPE" format (Xiongmai/Securus/XMeye)
                # e.g. "SECURUS CRIMSON | IPC" -> model=CRIMSON, device_type=IP Camera
                if "|" in raw_title and not result.get("model"):
                    parts = [p.strip() for p in raw_title.split("|")]
                    left  = parts[0].strip()
                    right = parts[1].strip() if len(parts) > 1 else ""
                    left_words = left.split()
                    if len(left_words) >= 2:
                        result["model"] = " ".join(left_words[1:])
                    elif len(left_words) == 1:
                        result["model"] = left_words[0]
                    if right.upper() in ("IPC", "IP CAMERA"):
                        result.setdefault("device_type", "IP Camera")
                    elif right.upper() in ("DVR", "NVR", "DVR/NVR"):
                        result.setdefault("device_type", "DVR/NVR")

            # Stop probing paths once we have enough
            if result.get("vendor") and result.get("firmware"):
                break

        if result.get("vendor") and result.get("firmware"):
            break

    # ── Port 34567 SDK probe (Phase 2.1 — full Xiongmai binary interrogation) ──
    if 34567 in open_ports:
        sdk_data = probe_xiongmai_sdk(ip)
        if sdk_data:
            # Merge: never overwrite fields already found via HTTP
            for k, v in sdk_data.items():
                if not result.get(k) or result[k] in ("Unknown", "", None):
                    result[k] = v
        elif not result.get("vendor"):
            # Fallback: old magic-byte probe to at least confirm vendor
            sdk_vendor = _probe_sdk_port(ip)
            if sdk_vendor:
                result["vendor"] = sdk_vendor
                result.setdefault("device_type", "DVR/NVR")

    # ── Signature matching on all collected blobs ──────────────────────────────
    combined = " ".join(all_blobs)

    # Also add server header and realm to combined for matching
    combined += " " + result.get("_server_header", "").lower()
    combined += " " + result.get("_realm", "").lower()
    combined += " " + result.get("_page_title", "").lower()

    for pattern, fields in _HTTP_SIGS:
        if re.search(pattern, combined, re.I):
            for k, v in fields.items():
                if k not in result or result[k] in ("Unknown", "", None):
                    result[k] = v

    # ── GoAhead-Webs = Xiongmai/generic DVR ───────────────────────────────────
    server = result.get("_server_header", "").lower()
    if "goahead" in server:
        result.setdefault("vendor", "Xiongmai/Generic DVR (GoAhead)")
        result.setdefault("device_type", "DVR/NVR")

    # ── Infer from port 34567 alone if still unknown ──────────────────────────
    if 34567 in open_ports and not result.get("vendor"):
        result["vendor"] = "Xiongmai/Generic DVR"
        result.setdefault("device_type", "DVR/NVR")

    # ── Infer from port 554 (RTSP) ────────────────────────────────────────────
    if 554 in open_ports and not result.get("device_type"):
        result["device_type"] = "IP Camera/DVR"

    # Clean internal keys
    result.pop("_server_header", None)
    result.pop("_realm", None)
    result.pop("_page_title", None)

    if result:
        logger.info(f"[fingerprint] {ip} → {result}")

    return result


# Singleton
http_fingerprinter = type('_FP', (), {'fingerprint': staticmethod(fingerprint)})()
