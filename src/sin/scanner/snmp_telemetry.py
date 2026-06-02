"""
sin.scanner.snmp_telemetry
══════════════════════════
SNMP v1/v2c telemetry prober — zero external dependencies.

Implements a minimal SNMP GET over raw UDP using only the stdlib struct
and socket modules. Targets the standard HOST-RESOURCES-MIB and RFC 1213
OIDs that virtually every SNMP-capable device exposes:

  sysDescr      1.3.6.1.2.1.1.1.0   — device description / firmware string
  sysName       1.3.6.1.2.1.1.5.0   — configured hostname
  sysUpTime     1.3.6.1.2.1.1.3.0   — uptime in centiseconds
  hrProcessorLoad 1.3.6.1.2.1.25.3.3.1.2.196608  — CPU % (first processor)
  hrStorageSize  1.3.6.1.2.1.25.2.3.1.5.1        — total storage units
  hrStorageUsed  1.3.6.1.2.1.25.2.3.1.6.1        — used storage units

Works against: Dahua, Axis, Uniview, Hanwha, routers, switches, printers —
anything with SNMP community "public" enabled (the factory default on most
IoT devices that support SNMP at all).

Does NOT require pysnmp, net-snmp, or any compiled extension.
"""
from __future__ import annotations

import socket
import struct
import os
from typing import Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.snmp_telemetry")

# ── SNMP BER encoding helpers ──────────────────────────────────────────────

_TYPE_INTEGER   = 0x02
_TYPE_OCTET_STR = 0x04
_TYPE_NULL      = 0x05
_TYPE_OID       = 0x06
_TYPE_SEQUENCE  = 0x30
_TYPE_GET_REQ   = 0xA0
_TYPE_GET_RESP  = 0xA2
_TYPE_TIMETICKS = 0x43
_TYPE_GAUGE     = 0x42
_TYPE_COUNTER   = 0x41


def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_int(n: int) -> bytes:
    # Minimal signed big-endian encoding
    if n == 0:
        return _encode_tlv(_TYPE_INTEGER, b'\x00')
    length = (n.bit_length() + 8) // 8
    return _encode_tlv(_TYPE_INTEGER, n.to_bytes(length, 'big', signed=True))


def _encode_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.strip('.').split('.')]
    # First two sub-identifiers compressed: first*40 + second
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            encoded += bytes([part])
        else:
            # Variable-length base-128 encoding
            result = []
            result.append(part & 0x7F)
            part >>= 7
            while part:
                result.append((part & 0x7F) | 0x80)
                part >>= 7
            encoded += bytes(reversed(result))
    return _encode_tlv(_TYPE_OID, encoded)


def _encode_string(s: str) -> bytes:
    return _encode_tlv(_TYPE_OCTET_STR, s.encode('utf-8'))


def _build_get_request(community: str, request_id: int, oids: List[str]) -> bytes:
    """Build a minimal SNMPv2c GET request packet."""
    # VarBind list: each OID with NULL value
    varbinds = b''
    for oid in oids:
        varbind = _encode_oid(oid) + _encode_tlv(_TYPE_NULL, b'')
        varbinds += _encode_tlv(_TYPE_SEQUENCE, varbind)
    varbind_list = _encode_tlv(_TYPE_SEQUENCE, varbinds)

    # PDU: request-id, error-status=0, error-index=0, varbind-list
    pdu_body = (
        _encode_int(request_id)
        + _encode_int(0)   # error-status
        + _encode_int(0)   # error-index
        + varbind_list
    )
    pdu = _encode_tlv(_TYPE_GET_REQ, pdu_body)

    # SNMP message: version=1 (v2c), community, PDU
    msg = (
        _encode_int(1)                   # version: 1 = SNMPv2c
        + _encode_string(community)
        + pdu
    )
    return _encode_tlv(_TYPE_SEQUENCE, msg)


# ── BER decoder (minimal — only what we need) ─────────────────────────────

def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Return (length, new_offset)."""
    b = data[offset]
    offset += 1
    if b < 0x80:
        return b, offset
    num_bytes = b & 0x7F
    length = int.from_bytes(data[offset:offset + num_bytes], 'big')
    return length, offset + num_bytes


def _decode_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Return (tag, value_bytes, new_offset)."""
    tag = data[offset]
    length, offset = _decode_length(data, offset + 1)
    value = data[offset:offset + length]
    return tag, value, offset + length


def _decode_oid(value: bytes) -> str:
    """Decode BER OID bytes to dotted string."""
    if not value:
        return ''
    parts = [value[0] // 40, value[0] % 40]
    i = 1
    while i < len(value):
        part = 0
        while i < len(value):
            b = value[i]
            i += 1
            part = (part << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(part)
    return '.'.join(str(p) for p in parts)


def _decode_integer(value: bytes) -> int:
    return int.from_bytes(value, 'big', signed=True)


def _parse_response(data: bytes) -> Dict[str, str]:
    """
    Walk the SNMP GET-RESPONSE and return {oid: value_str} for each VarBind.
    Tolerates partial responses and unknown types.
    """
    results: Dict[str, str] = {}
    try:
        # Top-level SEQUENCE
        tag, msg_bytes, _ = _decode_tlv(data, 0)
        if tag != _TYPE_SEQUENCE:
            return results
        offset = 0
        # version
        _, _, offset = _decode_tlv(msg_bytes, offset)
        # community
        _, _, offset = _decode_tlv(msg_bytes, offset)
        # PDU (GET-RESPONSE)
        pdu_tag, pdu_bytes, _ = _decode_tlv(msg_bytes, offset)
        if pdu_tag != _TYPE_GET_RESP:
            return results

        # Skip request-id, error-status, error-index
        p = 0
        for _ in range(3):
            _, _, p = _decode_tlv(pdu_bytes, p)
        # VarBindList SEQUENCE
        _, vbl_bytes, _ = _decode_tlv(pdu_bytes, p)

        # Iterate VarBinds
        vb_offset = 0
        while vb_offset < len(vbl_bytes):
            _, vb_bytes, vb_offset = _decode_tlv(vbl_bytes, vb_offset)
            vb_inner = 0
            oid_tag, oid_val, vb_inner = _decode_tlv(vb_bytes, vb_inner)
            val_tag, val_bytes, _     = _decode_tlv(vb_bytes, vb_inner)
            oid_str = _decode_oid(oid_val)

            if val_tag == _TYPE_OCTET_STR:
                try:
                    results[oid_str] = val_bytes.decode('utf-8', errors='replace').strip()
                except Exception:
                    results[oid_str] = val_bytes.hex()
            elif val_tag in (_TYPE_INTEGER, _TYPE_GAUGE, _TYPE_COUNTER, _TYPE_TIMETICKS):
                results[oid_str] = str(_decode_integer(val_bytes))
            else:
                results[oid_str] = val_bytes.hex()

    except Exception as e:
        logger.debug(f"[snmp] parse error: {e}")

    return results


# ── OID catalogue ──────────────────────────────────────────────────────────

_OIDS = {
    "sys_descr":       "1.3.6.1.2.1.1.1.0",
    "sys_name":        "1.3.6.1.2.1.1.5.0",
    "sys_uptime":      "1.3.6.1.2.1.1.3.0",
    "cpu_load":        "1.3.6.1.2.1.25.3.3.1.2.196608",
    "storage_size":    "1.3.6.1.2.1.25.2.3.1.5.1",
    "storage_used":    "1.3.6.1.2.1.25.2.3.1.6.1",
}

_OID_TO_KEY = {v: k for k, v in _OIDS.items()}


# ── Public interface ───────────────────────────────────────────────────────

class SNMPTelemetryProber:
    """
    Probe an IP for SNMP telemetry using raw UDP.
    Tries community strings from SIN_SNMP_COMMUNITIES env var
    (comma-separated, default: public).
    """

    TIMEOUT  = float(os.getenv("SIN_SNMP_TIMEOUT", "2"))
    UDP_PORT = 161
    COMMUNITIES = [
        c.strip()
        for c in os.getenv("SIN_SNMP_COMMUNITIES", "public").split(",")
        if c.strip()
    ]

    def probe(self, ip: str, open_ports: List[int]) -> Dict[str, str]:
        """
        Return telemetry dict or {} if SNMP is unavailable / not open.
        Keys: cpu_usage, ram_usage, uptime, hostname, sys_descr, source="snmp"
        """
        if 161 not in open_ports:
            return {}

        oids   = list(_OIDS.values())
        req_id = os.getpid() & 0x7FFFFFFF

        for community in self.COMMUNITIES:
            raw = self._send(ip, community, req_id, oids)
            if raw is None:
                continue
            parsed = _parse_response(raw)
            if not parsed:
                continue

            telemetry = self._normalise(parsed, ip)
            if telemetry:
                logger.info(f"[snmp] {ip} community={community!r} → {telemetry}")
                return telemetry

        return {}

    def _send(
        self, ip: str, community: str, req_id: int, oids: List[str]
    ) -> Optional[bytes]:
        """Send one SNMP GET and return the raw response bytes, or None."""
        pkt = _build_get_request(community, req_id, oids)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.TIMEOUT)
            sock.sendto(pkt, (ip, self.UDP_PORT))
            data, _ = sock.recvfrom(4096)
            return data
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _normalise(raw: Dict[str, str], ip: str) -> Dict[str, str]:
        """Map raw OID values to human-readable telemetry keys."""
        out: Dict[str, str] = {"source": "snmp"}

        # sysDescr — free-text firmware/hardware description
        descr = raw.get("1.3.6.1.2.1.1.1.0", "").strip()
        if descr:
            out["sys_descr"] = descr[:200]

        # sysName — configured hostname
        name = raw.get("1.3.6.1.2.1.1.5.0", "").strip()
        if name:
            out["hostname"] = name

        # sysUpTime — centiseconds → human readable
        uptime_cs = raw.get("1.3.6.1.2.1.1.3.0", "")
        if uptime_cs.isdigit():
            cs = int(uptime_cs)
            days    = cs // (100 * 86400)
            hours   = (cs % (100 * 86400)) // (100 * 3600)
            minutes = (cs % (100 * 3600)) // (100 * 60)
            out["uptime"] = f"{days}d {hours}h {minutes}m"

        # CPU load (hrProcessorLoad — integer percentage)
        cpu = raw.get("1.3.6.1.2.1.25.3.3.1.2.196608", "")
        if cpu.lstrip('-').isdigit() and 0 <= int(cpu) <= 100:
            out["cpu_usage"] = f"{cpu}%"

        # Storage (hrStorageSize / hrStorageUsed — in storage allocation units)
        stor_size = raw.get("1.3.6.1.2.1.25.2.3.1.5.1", "")
        stor_used = raw.get("1.3.6.1.2.1.25.2.3.1.6.1", "")
        if stor_size.isdigit() and stor_used.isdigit():
            size_kb = int(stor_size)
            used_kb = int(stor_used)
            if size_kb > 0:
                pct = round(used_kb / size_kb * 100, 1)
                out["storage_usage"] = f"{pct}%"
                out["storage_used_kb"]  = str(used_kb)
                out["storage_total_kb"] = str(size_kb)

        # Only return if we got at least one meaningful field beyond source
        if len(out) <= 1:
            return {}

        return out


snmp_prober = SNMPTelemetryProber()
