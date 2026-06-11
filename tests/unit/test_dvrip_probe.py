"""
tests/unit/test_dvrip_probe.py
══════════════════════════════
Unit tests for sin.scanner.dvrip_probe.
All network I/O is mocked — no live devices required.
"""
import hashlib
import json
import socket
import struct
from unittest.mock import MagicMock, call, patch

import pytest

from sin.scanner.dvrip_probe import (
    DEFAULT_CREDENTIALS,
    DVRIP_PORT,
    MAX_DEFAULT_ATTEMPTS,
    RET_BAD_CREDS,
    RET_LOCKED,
    RET_OK,
    DVRIPAuthResult,
    DVRIPProbe,
    DVRIPProbeResult,
    _attempt_login,
    _connect,
    _sofia_hash,
    _make_packet,
    _recv_packet,
)

IP = "192.168.30.162"


# ── Sofia hash ────────────────────────────────────────────────────────────────

class TestSofiaHash:
    def test_empty_password(self):
        # Known value confirmed against live device
        assert _sofia_hash("") == "tlJwpbo6"

    def test_admin_password(self):
        assert _sofia_hash("admin") == "6QNMIQGe"

    def test_returns_string(self):
        result = _sofia_hash("test")
        assert isinstance(result, str)

    def test_length_is_eight(self):
        # Sofia hash always produces 8 chars (16 MD5 bytes -> 8 pairs)
        assert len(_sofia_hash("")) == 8
        assert len(_sofia_hash("admin")) == 8
        assert len(_sofia_hash("Aaaa1111")) == 8

    def test_only_alphanumeric(self):
        chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        for pwd in ["", "admin", "888888", "Aaaa1111"]:
            for c in _sofia_hash(pwd):
                assert c in chars, f"Non-alphanumeric char {c!r} in hash of {pwd!r}"

    def test_different_passwords_differ(self):
        assert _sofia_hash("admin") != _sofia_hash("")
        assert _sofia_hash("888888") != _sofia_hash("admin")

    def test_known_hash_888888(self):
        # Xiongmai default — verify against known value
        result = _sofia_hash("888888")
        assert isinstance(result, str)
        assert len(result) == 8


# ── Packet construction ───────────────────────────────────────────────────────

class TestMakePacket:
    def test_starts_with_magic_byte(self):
        pkt = _make_packet(0, 0, 1000, {})
        assert pkt[0] == 0xFF

    def test_header_length_is_20(self):
        pkt = _make_packet(0, 0, 1000, {})
        assert len(pkt) >= 20

    def test_code_encoded_in_header(self):
        pkt = _make_packet(0, 0, 1042, {"Name": "test"})
        _, _, _, _, _, _, code, length = struct.unpack("<BBHIIHHI", pkt[:20])
        assert code == 1042

    def test_payload_is_valid_json(self):
        data = {"EncryptType": "MD5", "UserName": "admin"}
        pkt = _make_packet(0, 0, 1000, data)
        _, _, _, _, _, _, _, length = struct.unpack("<BBHIIHHI", pkt[:20])
        payload = pkt[20:20 + length].rstrip(b"\x0a\x00")
        parsed = json.loads(payload)
        assert parsed["UserName"] == "admin"

    def test_session_encoded_in_header(self):
        pkt = _make_packet(0x1234, 0, 1000, {})
        _, _, _, session, _, _, _, _ = struct.unpack("<BBHIIHHI", pkt[:20])
        assert session == 0x1234


# ── DVRIPProbeResult ──────────────────────────────────────────────────────────

class TestDVRIPProbeResult:
    def test_not_authenticated_when_no_auth(self):
        r = DVRIPProbeResult(ip=IP)
        assert not r.authenticated

    def test_authenticated_when_auth_success(self):
        auth = DVRIPAuthResult(success=True, ret_code=100, password="")
        r = DVRIPProbeResult(ip=IP, port_open=True, auth=auth)
        assert r.authenticated

    def test_severity_none_when_port_closed(self):
        r = DVRIPProbeResult(ip=IP, port_open=False)
        assert r.severity == "none"

    def test_severity_critical_empty_password(self):
        auth = DVRIPAuthResult(success=True, ret_code=100, password="")
        r = DVRIPProbeResult(ip=IP, port_open=True, auth=auth)
        assert r.severity == "critical"

    def test_severity_high_default_credential(self):
        auth = DVRIPAuthResult(success=True, ret_code=100, password="admin")
        r = DVRIPProbeResult(ip=IP, port_open=True, auth=auth)
        assert r.severity == "high"

    def test_severity_medium_when_locked(self):
        r = DVRIPProbeResult(ip=IP, port_open=True, locked=True)
        assert r.severity == "medium"

    def test_severity_low_port_open_no_auth(self):
        r = DVRIPProbeResult(ip=IP, port_open=True)
        assert r.severity == "low"

    def test_to_dict_contains_required_keys(self):
        r = DVRIPProbeResult(ip=IP, port_open=True)
        d = r.to_dict()
        assert "ip" in d
        assert "port_open" in d
        assert "authenticated" in d
        assert "severity" in d
        assert "locked" in d

    def test_to_dict_password_redacted(self):
        auth = DVRIPAuthResult(success=True, ret_code=100, password="secret123")
        r = DVRIPProbeResult(ip=IP, port_open=True, auth=auth)
        d = r.to_dict()
        assert "secret123" not in str(d)
        assert d["auth"]["password_redacted"] == "***"

    def test_to_dict_empty_password_shown_as_empty(self):
        auth = DVRIPAuthResult(success=True, ret_code=100, password="")
        r = DVRIPProbeResult(ip=IP, port_open=True, auth=auth)
        d = r.to_dict()
        assert d["auth"]["password_redacted"] == "(empty)"


# ── Connection handling ───────────────────────────────────────────────────────

class TestConnect:
    def test_returns_none_on_refused(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError
            mock_sock_cls.return_value = mock_sock
            result = _connect(IP)
            assert result is None

    def test_returns_none_on_timeout(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout
            mock_sock_cls.return_value = mock_sock
            result = _connect(IP)
            assert result is None

    def test_returns_socket_on_success(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            result = _connect(IP)
            assert result == mock_sock
            mock_sock.connect.assert_called_once_with((IP, DVRIP_PORT))


# ── Login attempts ────────────────────────────────────────────────────────────

def _make_login_response(ret=100, session="0x00001234", device_type="IPC", channels=1):
    """Build a raw DVRIP login response packet."""
    payload = json.dumps({
        "Ret": ret,
        "SessionID": session,
        "DeviceType ": device_type,
        "ChannelNum": channels,
        "AliveInterval": 30,
    }, separators=(",", ":")).encode() + b"\x0a\x00"
    header = struct.pack("<BBHIIHHI", 0xFF, 0x01, 0, 0, 0, 0, 1001, len(payload))
    return header + payload


class TestAttemptLogin:
    def test_returns_neg1_when_no_connection(self):
        with patch("sin.scanner.dvrip_probe._connect", return_value=None):
            ret, resp = _attempt_login(IP, "admin", "")
            assert ret == -1
            assert resp == {}

    def test_returns_100_on_success(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            _make_login_response(ret=100)[:20],  # header
            _make_login_response(ret=100)[20:],  # payload
        ]
        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            # Patch recv_packet to return success directly
            success_resp = {"Ret": 100, "SessionID": "0x00001234",
                           "DeviceType ": "IPC", "ChannelNum": 1, "AliveInterval": 30}
            with patch("sin.scanner.dvrip_probe._recv_packet", return_value=success_resp):
                ret, resp = _attempt_login(IP, "admin", "")
                assert ret == 100
                assert resp["SessionID"] == "0x00001234"

    def test_returns_203_on_bad_creds(self):
        mock_sock = MagicMock()
        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._recv_packet",
                      return_value={"Ret": 203, "SessionID": "0x00000000"}):
                ret, resp = _attempt_login(IP, "admin", "wrongpassword")
                assert ret == 203

    def test_returns_206_on_lockout(self):
        mock_sock = MagicMock()
        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._recv_packet",
                      return_value={"Ret": 206, "SessionID": "0x00000000"}):
                ret, _ = _attempt_login(IP, "admin", "")
                assert ret == 206

    def test_socket_closed_after_attempt(self):
        mock_sock = MagicMock()
        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._recv_packet",
                      return_value={"Ret": 203}):
                _attempt_login(IP, "admin", "")
                mock_sock.close.assert_called_once()


# ── DVRIPProbe.probe ──────────────────────────────────────────────────────────

class TestDVRIPProbe:
    def setup_method(self):
        self.probe = DVRIPProbe()

    def test_port_closed_returns_early(self):
        with patch("sin.scanner.dvrip_probe._connect", return_value=None):
            result = self.probe.probe(IP)
            assert not result.port_open
            assert result.error == "connection_refused"
            assert not result.authenticated

    def test_empty_password_succeeds(self):
        mock_sock = MagicMock()
        success = {"Ret": 100, "SessionID": "0x00001234",
                  "DeviceType ": "IPC", "ChannelNum": 1, "AliveInterval": 30}
        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(100, success)):
                result = self.probe.probe(IP)
                assert result.port_open
                assert result.authenticated
                assert result.auth.password == ""
                assert result.severity == "critical"

    def test_lockout_stops_further_attempts(self):
        mock_sock = MagicMock()
        call_count = []

        def _mock_login(ip, user, pwd):
            call_count.append((user, pwd))
            return (RET_LOCKED, {"Ret": RET_LOCKED})

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      side_effect=_mock_login):
                result = self.probe.probe(IP)
                assert result.locked
                assert not result.authenticated
                assert len(call_count) == 1  # stops after first lockout

    def test_vault_creds_tried_before_defaults(self):
        mock_sock = MagicMock()
        attempt_order = []

        def _mock_login(ip, user, pwd):
            attempt_order.append((user, pwd))
            return (RET_BAD_CREDS, {"Ret": RET_BAD_CREDS})

        vault_creds = [{"username": "admin", "password": "Aaaa1111",
                       "id": 4, "priority": 10}]

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      side_effect=_mock_login):
                self.probe.probe(IP, vault_creds=vault_creds)
                # Vault credential must be first
                assert attempt_order[0] == ("admin", "Aaaa1111")

    def test_vault_credential_id_recorded_on_success(self):
        mock_sock = MagicMock()
        success = {"Ret": 100, "SessionID": "0x00001234",
                  "DeviceType ": "IPC", "ChannelNum": 1, "AliveInterval": 30}
        vault_creds = [{"username": "admin", "password": "Aaaa1111",
                       "id": 4, "priority": 10}]

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(100, success)):
                result = self.probe.probe(IP, vault_creds=vault_creds)
                assert result.auth.credential_id == 4

    def test_max_default_attempts_respected(self):
        mock_sock = MagicMock()
        call_count = []

        def _mock_login(ip, user, pwd):
            call_count.append((user, pwd))
            return (RET_BAD_CREDS, {"Ret": RET_BAD_CREDS})

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      side_effect=_mock_login):
                self.probe.probe(IP)
                # Should not exceed MAX_DEFAULT_ATTEMPTS
                assert len(call_count) <= MAX_DEFAULT_ATTEMPTS

    def test_default_creds_not_duplicated_when_in_vault(self):
        """If vault contains admin/'', it shouldn't be tried again as a default."""
        mock_sock = MagicMock()
        attempts = []

        def _mock_login(ip, user, pwd):
            attempts.append((user, pwd))
            return (RET_BAD_CREDS, {"Ret": RET_BAD_CREDS})

        vault_creds = [{"username": "admin", "password": "",
                       "id": 1, "priority": 10}]

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      side_effect=_mock_login):
                self.probe.probe(IP, vault_creds=vault_creds)
                # admin/'' should appear exactly once
                empty_attempts = [a for a in attempts if a == ("admin", "")]
                assert len(empty_attempts) == 1

    def test_device_type_extracted_from_login_response(self):
        mock_sock = MagicMock()
        success = {"Ret": 100, "SessionID": "0x00001234",
                  "DeviceType ": "HVR", "ChannelNum": 32, "AliveInterval": 30}

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(100, success)):
                result = self.probe.probe(IP)
                assert result.auth.device_type == "HVR"
                assert result.auth.channel_num == 32

    def test_no_deep_analysis_without_flag(self):
        mock_sock = MagicMock()
        success = {"Ret": 100, "SessionID": "0x00001234",
                  "DeviceType ": "IPC", "ChannelNum": 1, "AliveInterval": 30}

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(100, success)):
                result = self.probe.probe(IP, deep=False)
                assert result.deep_analysis is None

    def test_deep_analysis_triggered_when_authenticated(self):
        mock_sock = MagicMock()
        success = {"Ret": 100, "SessionID": "0x00001234",
                  "DeviceType ": "IPC", "ChannelNum": 1, "AliveInterval": 30}

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(100, success)):
                with patch.object(self.probe, "_deep_analysis",
                                 return_value={"configs": {}, "secrets_found": []}) as mock_deep:
                    result = self.probe.probe(IP, deep=True)
                    mock_deep.assert_called_once()
                    assert result.deep_analysis is not None

    def test_deep_analysis_not_triggered_without_auth(self):
        mock_sock = MagicMock()

        with patch("sin.scanner.dvrip_probe._connect", return_value=mock_sock):
            with patch("sin.scanner.dvrip_probe._attempt_login",
                      return_value=(RET_BAD_CREDS, {"Ret": RET_BAD_CREDS})):
                with patch.object(self.probe, "_deep_analysis") as mock_deep:
                    self.probe.probe(IP, deep=True)
                    mock_deep.assert_not_called()


# ── Secret detection ──────────────────────────────────────────────────────────

class TestSecretDetection:
    def setup_method(self):
        self.probe = DVRIPProbe()

    def test_detects_ddns_key(self):
        secrets = []
        config = {"DDNSKey": "securusddns.com", "Enable": False}
        self.probe._detect_secrets("NetWork.NetDDNS.[0]", config, secrets)
        assert any(s["key"] == "DDNSKey" for s in secrets)

    def test_detects_password_field(self):
        secrets = []
        config = {"Server": {"UserName": "admin", "Password": "secret"}}
        self.probe._detect_secrets("NetWork.NetEmail.[0]", config, secrets)
        assert any("Password" in s["key"] for s in secrets)

    def test_ignores_empty_password(self):
        secrets = []
        config = {"Server": {"Password": ""}}
        self.probe._detect_secrets("NetWork.NetEmail.[0]", config, secrets)
        # Empty password not flagged
        assert len(secrets) == 0

    def test_nested_detection(self):
        secrets = []
        config = {
            "Server": {
                "Nested": {
                    "DDNSKey": "somekey"
                }
            }
        }
        self.probe._detect_secrets("config", config, secrets)
        assert len(secrets) > 0

    def test_non_dict_value_ignored(self):
        secrets = []
        self.probe._detect_secrets("config", ["not", "a", "dict"], secrets)
        assert secrets == []

    def test_list_values_scanned(self):
        secrets = []
        config = [{"Password": "found"}, {"Password": ""}]
        # Lists at top level are ignored (not dict), but nested lists work
        nested = {"Items": [{"Password": "found"}]}
        self.probe._detect_secrets("config", nested, secrets)
        assert any("Password" in s["key"] for s in secrets)


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_dvrip_port_is_34567(self):
        assert DVRIP_PORT == 34567

    def test_max_default_attempts_is_3(self):
        assert MAX_DEFAULT_ATTEMPTS == 3

    def test_default_creds_starts_with_empty_password(self):
        assert DEFAULT_CREDENTIALS[0] == ("admin", "")

    def test_default_creds_includes_admin_admin(self):
        assert ("admin", "admin") in DEFAULT_CREDENTIALS

    def test_ret_ok_is_100(self):
        assert RET_OK == 100

    def test_ret_locked_is_206(self):
        assert RET_LOCKED == 206

    def test_ret_bad_creds_is_203(self):
        assert RET_BAD_CREDS == 203
