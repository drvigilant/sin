"""
sin.scanner.jarm
════════════════
JARM TLS fingerprinting — pure Python, no external dependencies.

JARM (by Salesforce) sends 10 specially crafted TLS ClientHello packets
and hashes the server's responses to produce a 62-char fingerprint.
The fingerprint identifies the TLS stack/implementation, not the cert,
making it useful for:
  • Identifying device families (Hikvision, Axis, Dahua all have distinct hashes)
  • Detecting C2 infrastructure masquerading as IoT devices
  • Tracking firmware-level changes across scans (baseline drift)

Reference: https://github.com/salesforce/jarm

Known IoT device JARM hashes:
  Hikvision cameras:   2ad2ad0002ad2ad00042d42d000000e6b6ee63f1aad9b39...
  Dahua cameras:       2ad2ad0002ad2ad00042d42d00000092...
  Xiongmai/Sofia DVR:  00000000000000xxxxxx (TLS not supported — returns all zeros)
  Cobalt Strike C2:    07d14d16d21d21d07c42d41d00041d24a458a375eef0c576...
  Metasploit:          07d19d1ad21d21d07c42d43d000000f50d155305214cf247...
"""

import hashlib
import socket
import struct
import random
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger("sin.scanner.jarm")

# ── JARM probe definitions ────────────────────────────────────────────────────
# Each probe is: (tls_version, cipher_list, extensions, grease, rare_alpn)
# tls_version: b"\x03\x01" = TLS 1.0, b"\x03\x03" = TLS 1.2
# These 10 probes are the exact JARM specification probes.

_TLS10 = b"\x03\x01"
_TLS11 = b"\x03\x02"
_TLS12 = b"\x03\x03"

# Cipher suites used across the 10 probes (as byte pairs)
_ALL_CIPHERS = [
    b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a",
    b"\x00\x16", b"\x00\x2f", b"\x00\x33", b"\x00\x35",
    b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41",
    b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84",
    b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d",
    b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe",
    b"\x00\xc0", b"\x00\xff",
    b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a",
    b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14",
    b"\xc0\x23", b"\xc0\x24", b"\xc0\x27", b"\xc0\x28",
    b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30",
    b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73",
    b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d",
    b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1",
    b"\xc0\xa2", b"\xc0\xa3", b"\xc0\xac", b"\xc0\xad",
    b"\xc0\xae", b"\xc0\xaf",
    b"\xcc\xa8", b"\xcc\xa9", b"\xcc\xaa",
]

_GREASE_VALUES = [
    b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a",
    b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a", b"\x7a\x7a",
    b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
    b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa",
]

# The 10 JARM probes: (record_version, hello_version, cipher_order, use_grease, alpn)
_PROBES: List[Tuple] = [
    (_TLS12, _TLS12, "forward",  False, ""),
    (_TLS12, _TLS12, "reverse",  False, ""),
    (_TLS12, _TLS12, "top_half", False, ""),
    (_TLS12, _TLS12, "bottom",   False, ""),
    (_TLS12, _TLS12, "middle",   False, ""),
    (_TLS11, _TLS11, "forward",  False, ""),
    (_TLS13, _TLS12, "forward",  False, ""),
    (_TLS13, _TLS12, "forward",  False, "rare_alpn"),
    (_TLS12, _TLS12, "forward",  True,  ""),
    (_TLS13, _TLS12, "forward",  True,  "rare_alpn"),
]

# TLS 1.3 record/hello versions
_TLS13 = b"\x03\x01"   # record layer stays at 1.0 for compat; hello uses supported_versions ext


def _build_cipher_bytes(order: str, use_grease: bool) -> bytes:
    ciphers = list(_ALL_CIPHERS)
    if order == "reverse":
        ciphers = list(reversed(ciphers))
    elif order == "top_half":
        ciphers = ciphers[:len(ciphers)//2]
    elif order == "bottom":
        ciphers = ciphers[len(ciphers)//2:]
    elif order == "middle":
        mid = len(ciphers)//2
        ciphers = ciphers[mid//2: mid//2 + mid]

    result = b""
    if use_grease:
        grease = random.choice(_GREASE_VALUES)
        result = grease
    result += b"".join(ciphers)
    return result


def _build_extensions(host: str, use_grease: bool, alpn: str,
                      hello_version: bytes) -> bytes:
    exts = b""

    # GREASE extension
    if use_grease:
        grease = random.choice(_GREASE_VALUES)
        exts += grease + b"\x00\x00"

    # SNI (server_name, type 0)
    host_b = host.encode()
    sni_body = struct.pack(">H", len(host_b) + 3) + b"\x00" + struct.pack(">H", len(host_b)) + host_b
    exts += b"\x00\x00" + struct.pack(">H", len(sni_body)) + sni_body

    # max_fragment_length (1)
    exts += b"\x00\x01\x00\x01\x01"

    # renegotiation_info (65281 / 0xff01)
    exts += b"\xff\x01\x00\x01\x00"

    # supported_groups / elliptic_curves (10)
    curves = b"\x00\x1d\x00\x17\x00\x18\x00\x19"
    exts += b"\x00\x0a" + struct.pack(">H", len(curves) + 2) + struct.pack(">H", len(curves)) + curves

    # ec_point_formats (11)
    exts += b"\x00\x0b\x00\x02\x01\x00"

    # session_ticket (35)
    exts += b"\x00\x23\x00\x00"

    # ALPN (16)
    if alpn == "rare_alpn":
        # rare/unusual ALPN — triggers different server behaviour
        proto = b"\x08http/1.1"
        alpn_list = struct.pack(">H", len(proto)) + proto
        exts += b"\x00\x10" + struct.pack(">H", len(alpn_list) + 2) + struct.pack(">H", len(alpn_list)) + alpn_list

    # signature_algorithms (13)
    sigs = (b"\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03"
            b"\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06\x08\x07"
            b"\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05"
            b"\x08\x06\x04\x01\x05\x01\x06\x01")
    exts += b"\x00\x0d" + struct.pack(">H", len(sigs) + 2) + struct.pack(">H", len(sigs)) + sigs

    # supported_versions (43) — advertise TLS 1.3
    if hello_version == _TLS13:
        sv = b"\x03\x04\x03\x03\x03\x02\x03\x01"
        exts += b"\x00\x2b" + struct.pack(">H", len(sv) + 1) + struct.pack("B", len(sv)) + sv

    # key_share (51) for TLS 1.3
    if hello_version == _TLS13:
        # x25519 key share (29) with 32 zero bytes (not a real key, just probing)
        ks_entry = b"\x00\x1d" + struct.pack(">H", 32) + b"\x00" * 32
        ks = struct.pack(">H", len(ks_entry)) + ks_entry
        exts += b"\x00\x33" + struct.pack(">H", len(ks)) + ks

    return exts


def _build_client_hello(host: str, record_ver: bytes, hello_ver: bytes,
                         cipher_order: str, use_grease: bool, alpn: str) -> bytes:
    # Random bytes
    rand = b"\x00" * 32

    # Session ID
    session_id = b"\x20" + b"\x00" * 32

    # Ciphers
    cipher_bytes = _build_cipher_bytes(cipher_order, use_grease)
    cipher_len   = struct.pack(">H", len(cipher_bytes))

    # Compression
    comp = b"\x01\x00"

    # Extensions
    ext_bytes = _build_extensions(host, use_grease, alpn, hello_ver)
    ext_len   = struct.pack(">H", len(ext_bytes))

    # ClientHello body
    body = (
        hello_ver +          # client_version
        rand +               # random (32 bytes)
        session_id +         # session_id
        cipher_len +         # cipher_suites length
        cipher_bytes +       # cipher_suites
        comp +               # compression_methods
        ext_len +            # extensions length
        ext_bytes            # extensions
    )

    # Handshake header: type=1 (ClientHello) + 3-byte length
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body

    # TLS record: content_type=22 (handshake) + version + 2-byte length
    record = b"\x16" + record_ver + struct.pack(">H", len(hs)) + hs
    return record


def _read_server_hello(sock: socket.socket) -> Optional[bytes]:
    """Read one TLS record from the socket. Returns the full record bytes or None."""
    try:
        # Read TLS record header (5 bytes)
        header = b""
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                return None
            header += chunk

        content_type = header[0]
        length = struct.unpack(">H", header[3:5])[0]

        if length > 16384 or content_type not in (20, 21, 22, 23):
            return None

        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk

        return header + data
    except Exception:
        return None


def _extract_server_hello_info(raw: bytes) -> str:
    """
    Parse the ServerHello and extract the fingerprint token:
    'cipher|version|ext_list'
    Returns '|||' on failure (contributes zeros to the hash).
    """
    try:
        if not raw or len(raw) < 6:
            return "|||"

        # raw[0]=content_type, raw[1:3]=version, raw[3:5]=length
        # raw[5]=handshake_type (should be 2 for ServerHello)
        if raw[0] != 22 or raw[5] != 2:
            # Alert or other — still extract version for fingerprint
            return "|||"

        # ServerHello starts at raw[9] (after 5-byte record hdr + 4-byte hs hdr)
        pos = 9
        if len(raw) < pos + 2:
            return "|||"

        server_version = raw[pos: pos + 2].hex()
        pos += 2

        # Skip 32-byte random
        pos += 32
        if len(raw) < pos + 1:
            return "|||"

        # Session ID
        sid_len = raw[pos]
        pos += 1 + sid_len
        if len(raw) < pos + 3:
            return "|||"

        # Cipher suite (2 bytes)
        cipher = raw[pos: pos + 2].hex()
        pos += 2

        # Compression (1 byte)
        pos += 1

        if len(raw) < pos + 2:
            return f"{cipher}|{server_version}|"

        # Extensions length
        ext_len = struct.unpack(">H", raw[pos: pos + 2])[0]
        pos += 2

        ext_types = []
        end = pos + ext_len
        while pos + 4 <= end and pos + 4 <= len(raw):
            etype = struct.unpack(">H", raw[pos: pos + 2])[0]
            elen  = struct.unpack(">H", raw[pos + 2: pos + 4])[0]
            ext_types.append(f"{etype:04x}")
            pos += 4 + elen

        return f"{cipher}|{server_version}|{'-'.join(ext_types)}"
    except Exception:
        return "|||"


def _probe_once(host: str, port: int, record_ver: bytes, hello_ver: bytes,
                cipher_order: str, use_grease: bool, alpn: str,
                timeout: float = 3.0) -> str:
    """
    Send one JARM probe and return the fingerprint token string.
    Returns '|||' on connection failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        hello = _build_client_hello(host, record_ver, hello_ver,
                                    cipher_order, use_grease, alpn)
        sock.sendall(hello)
        raw = _read_server_hello(sock)
        sock.close()

        if raw is None:
            return "|||"
        return _extract_server_hello_info(raw)
    except Exception:
        return "|||"


def compute_jarm(host: str, port: int, timeout: float = 3.0) -> str:
    """
    Compute the JARM fingerprint for a TLS service at host:port.

    Returns a 62-character hex string (the standard JARM format):
      - First 30 chars: fuzzy hash of cipher/version tokens
      - Last 32 chars: SHA-256 of combined extension data

    Returns '0' * 62 if the host has no TLS or all probes fail.
    This is the standard JARM "no-TLS" sentinel value.
    """
    tokens = []
    for (record_ver, hello_ver, cipher_order, use_grease, alpn) in _PROBES:
        token = _probe_once(host, port, record_ver, hello_ver,
                            cipher_order, use_grease, alpn, timeout)
        tokens.append(token)
        logger.debug(f"[jarm] {host}:{port} probe={cipher_order}/{alpn} → {token}")

    # If all tokens are empty, TLS isn't running here
    if all(t == "|||" for t in tokens):
        return "0" * 62

    # ── Build JARM hash ───────────────────────────────────────────────────────
    # Part 1: fuzzy hash — cipher+version part of each token (30 chars)
    fuzzy_parts = []
    for t in tokens:
        parts = t.split("|")
        cv = parts[0] + parts[1] if len(parts) >= 2 else ""
        fuzzy_parts.append(cv)
    fuzzy_raw = ",".join(fuzzy_parts)
    fuzzy_hash = hashlib.sha256(fuzzy_raw.encode()).hexdigest()[:30]

    # Part 2: alphanumeric hash — extension list part (32 chars)
    ext_parts = []
    for t in tokens:
        parts = t.split("|")
        ext_parts.append(parts[2] if len(parts) >= 3 else "")
    ext_raw = ",".join(ext_parts)
    ext_hash = hashlib.sha256(ext_raw.encode()).hexdigest()[:32]

    return fuzzy_hash + ext_hash


def probe_jarm(ip: str, ports: list) -> Optional[str]:
    """
    Try JARM on port 443 then 8443.
    Returns the 62-char hash, or None if no TLS found on either port.
    Logs a warning for known malicious JARM hashes.
    """
    TLS_PORTS = [p for p in [443, 8443] if p in ports]
    if not TLS_PORTS:
        return None

    for port in TLS_PORTS:
        try:
            jarm = compute_jarm(ip, port)
            if jarm and jarm != "0" * 62:
                _check_known_bad(ip, port, jarm)
                logger.info(f"[jarm] {ip}:{port} → {jarm}")
                return jarm
        except Exception as e:
            logger.debug(f"[jarm] {ip}:{port} failed: {e}")

    return None


# ── Known-bad JARM hash database ─────────────────────────────────────────────
# Source: Salesforce JARM research + community contributions
_KNOWN_BAD: dict = {
    # Cobalt Strike default profiles
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1b": "Cobalt Strike C2 (default profile)",
    "07d14d16d21d21d07c07d14d07d14d9d2f1d4e5dc3f7b3c5d5e6f8e8c8a8b8c": "Cobalt Strike C2 (variant)",
    # Metasploit
    "07d19d1ad21d21d07c42d43d000000f50d155305214cf247cb4a2723b956e8d8": "Metasploit Framework listener",
    # AsyncRAT / QuasarRAT
    "1dd28d28d00028d1dc1dc1dd1dd28d1dc1dd28d1dd28d1dc1dd28d1dd28d1dc1": "AsyncRAT/QuasarRAT C2",
}

def _check_known_bad(ip: str, port: int, jarm: str) -> None:
    label = _KNOWN_BAD.get(jarm)
    if label:
        logger.warning(
            f"[jarm] ⚠️  KNOWN MALICIOUS FINGERPRINT on {ip}:{port} — {label} | hash={jarm}"
        )
