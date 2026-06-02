"""
tests/unit/test_snmp_telemetry.py
Unit tests for sin.scanner.snmp_telemetry
All network I/O is mocked — no real SNMP traffic sent.
"""
import socket
import struct
from unittest.mock import MagicMock, patch
import pytest

from sin.scanner.snmp_telemetry import (
    SNMPTelemetryProber,
    _build_get_request,
    _parse_response,
    _encode_oid,
    _encode_int,
    snmp_prober,
)


# ── Encoding helpers ───────────────────────────────────────────────────────

def test_encode_int_zero():
    data = _encode_int(0)
    assert data[0] == 0x02          # INTEGER tag
    assert data[-1] == 0x00

def test_encode_int_positive():
    data = _encode_int(100)
    assert data[0] == 0x02
    assert int.from_bytes(data[2:], 'big') == 100

def test_encode_oid_sysDescr():
    data = _encode_oid("1.3.6.1.2.1.1.1.0")
    assert data[0] == 0x06          # OID tag
    assert len(data) > 2

def test_build_get_request_returns_bytes():
    pkt = _build_get_request("public", 1, ["1.3.6.1.2.1.1.1.0"])
    assert isinstance(pkt, bytes)
    assert len(pkt) > 10
    assert pkt[0] == 0x30           # outer SEQUENCE tag

def test_build_get_request_embeds_community():
    pkt = _build_get_request("mycommunity", 42, ["1.3.6.1.2.1.1.1.0"])
    assert b"mycommunity" in pkt


# ── Response builder (creates minimal valid SNMP GET-RESPONSE) ─────────────

def _build_tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    return bytes([tag, 0x81, n]) + value

def _build_int_val(n: int) -> bytes:
    return _build_tlv(0x02, n.to_bytes(max(1, (n.bit_length()+8)//8), 'big'))

def _build_octet(s: str) -> bytes:
    return _build_tlv(0x04, s.encode())

def _build_timeticks(n: int) -> bytes:
    return _build_tlv(0x43, n.to_bytes(4, 'big'))

def _build_gauge(n: int) -> bytes:
    return _build_tlv(0x42, n.to_bytes(4, 'big'))

def _oid_bytes(dotted: str) -> bytes:
    from sin.scanner.snmp_telemetry import _encode_oid
    raw = _encode_oid(dotted)
    return raw  # full TLV

def _build_response(varbinds: list) -> bytes:
    """varbinds: list of (oid_str, value_tlv_bytes)"""
    vbl = b''
    for oid, val_tlv in varbinds:
        oid_tlv = _oid_bytes(oid)
        vb = _build_tlv(0x30, oid_tlv + val_tlv)
        vbl += vb
    vbl_seq = _build_tlv(0x30, vbl)

    pdu_body = (
        _build_int_val(1)    # request-id
        + _build_int_val(0)  # error-status
        + _build_int_val(0)  # error-index
        + vbl_seq
    )
    pdu = _build_tlv(0xA2, pdu_body)   # GET-RESPONSE

    msg = (
        _build_int_val(1)              # version: SNMPv2c
        + _build_octet("public")       # community
        + pdu
    )
    return _build_tlv(0x30, msg)


# ── Parser tests ───────────────────────────────────────────────────────────

def test_parse_response_sysDescr():
    pkt = _build_response([
        ("1.3.6.1.2.1.1.1.0", _build_octet("Linux DVR 4.9.0")),
    ])
    result = _parse_response(pkt)
    assert "1.3.6.1.2.1.1.1.0" in result
    assert result["1.3.6.1.2.1.1.1.0"] == "Linux DVR 4.9.0"

def test_parse_response_integer_gauge():
    pkt = _build_response([
        ("1.3.6.1.2.1.25.3.3.1.2.196608", _build_gauge(42)),
    ])
    result = _parse_response(pkt)
    assert result.get("1.3.6.1.2.1.25.3.3.1.2.196608") == "42"

def test_parse_response_timeticks():
    pkt = _build_response([
        ("1.3.6.1.2.1.1.3.0", _build_timeticks(360000)),  # 1 hour
    ])
    result = _parse_response(pkt)
    assert "1.3.6.1.2.1.1.3.0" in result

def test_parse_response_empty_bytes():
    result = _parse_response(b"")
    assert result == {}

def test_parse_response_garbage():
    result = _parse_response(b"\xff\xfe\xfd\xfc")
    assert isinstance(result, dict)


# ── Normaliser tests ───────────────────────────────────────────────────────

def test_normalise_cpu_usage():
    raw = {"1.3.6.1.2.1.25.3.3.1.2.196608": "55"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert result.get("cpu_usage") == "55%"

def test_normalise_cpu_out_of_range_ignored():
    raw = {"1.3.6.1.2.1.25.3.3.1.2.196608": "200"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert "cpu_usage" not in result

def test_normalise_sys_descr():
    raw = {"1.3.6.1.2.1.1.1.0": "Dahua Technology DVR"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert result.get("sys_descr") == "Dahua Technology DVR"

def test_normalise_hostname():
    raw = {"1.3.6.1.2.1.1.5.0": "camera-lobby"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert result.get("hostname") == "camera-lobby"

def test_normalise_uptime_formatting():
    # 360000 centiseconds = 1 hour
    raw = {"1.3.6.1.2.1.1.3.0": "360000"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert "uptime" in result
    assert "1h" in result["uptime"]

def test_normalise_storage():
    raw = {
        "1.3.6.1.2.1.25.2.3.1.5.1": "1000",
        "1.3.6.1.2.1.25.2.3.1.6.1": "600",
    }
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert result.get("storage_usage") == "60.0%"
    assert result.get("storage_total_kb") == "1000"

def test_normalise_empty_raw_returns_empty():
    result = SNMPTelemetryProber._normalise({}, "10.0.0.1")
    assert result == {}

def test_normalise_includes_source_snmp():
    raw = {"1.3.6.1.2.1.1.1.0": "Linux"}
    result = SNMPTelemetryProber._normalise(raw, "10.0.0.1")
    assert result.get("source") == "snmp"


# ── Probe method tests (mocked UDP) ───────────────────────────────────────

def _full_response_pkt():
    return _build_response([
        ("1.3.6.1.2.1.1.1.0",               _build_octet("Axis P3245-V")),
        ("1.3.6.1.2.1.1.5.0",               _build_octet("axis-entrance")),
        ("1.3.6.1.2.1.1.3.0",               _build_timeticks(8640000)),  # 1 day
        ("1.3.6.1.2.1.25.3.3.1.2.196608",   _build_gauge(23)),
        ("1.3.6.1.2.1.25.2.3.1.5.1",        _build_gauge(4096)),
        ("1.3.6.1.2.1.25.2.3.1.6.1",        _build_gauge(1024)),
    ])

def test_probe_returns_empty_when_port_161_not_open():
    prober = SNMPTelemetryProber()
    result = prober.probe("10.0.0.1", [80, 443])
    assert result == {}

def test_probe_returns_telemetry_on_success():
    prober = SNMPTelemetryProber()
    with patch.object(prober, "_send", return_value=_full_response_pkt()):
        result = prober.probe("10.0.0.1", [161])
    assert result.get("cpu_usage") == "23%"
    assert result.get("hostname")  == "axis-entrance"
    assert result.get("sys_descr") == "Axis P3245-V"
    assert result.get("source")    == "snmp"

def test_probe_returns_empty_on_timeout():
    prober = SNMPTelemetryProber()
    with patch.object(prober, "_send", return_value=None):
        result = prober.probe("10.0.0.1", [161])
    assert result == {}

def test_probe_tries_all_communities_before_giving_up():
    prober = SNMPTelemetryProber()
    prober.COMMUNITIES = ["private", "public", "admin"]
    call_count = 0
    def fake_send(ip, community, req_id, oids):
        nonlocal call_count
        call_count += 1
        return None
    with patch.object(prober, "_send", side_effect=fake_send):
        result = prober.probe("10.0.0.1", [161])
    assert call_count == 3
    assert result == {}

def test_probe_stops_at_first_successful_community():
    prober = SNMPTelemetryProber()
    prober.COMMUNITIES = ["public", "private"]
    call_count = 0
    def fake_send(ip, community, req_id, oids):
        nonlocal call_count
        call_count += 1
        if community == "public":
            return _full_response_pkt()
        return None
    with patch.object(prober, "_send", side_effect=fake_send):
        result = prober.probe("10.0.0.1", [161])
    assert call_count == 1
    assert result.get("cpu_usage") == "23%"

def test_send_returns_none_on_socket_timeout():
    prober = SNMPTelemetryProber()
    prober.TIMEOUT = 0.001
    # Send to a non-routable address — will time out
    result = prober._send("192.0.2.1", "public", 1, ["1.3.6.1.2.1.1.1.0"])
    assert result is None

def test_singleton_exists():
    assert snmp_prober is not None
    assert isinstance(snmp_prober, SNMPTelemetryProber)
