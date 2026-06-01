"""
Unit tests for Phase 2 tasks:
  Task 1 — scan-stuck bug (Redis TTL + try/finally guarantee)
  Task 2 — Xiongmai SDK binary probe (probe_xiongmai_sdk)
  Task 3 — weighted composite risk scoring (_composite_score / _risk_level)
"""
import json
import os
import socket
import struct
import sys
import types
import unittest
from unittest.mock import MagicMock, patch, call

# ── Stub the database module before any sin.api import touches it ─────────────
# server.py → AgentRunner → baseline → models → database, which raises
# RuntimeError when SIN_DB_PASSWORD is unset.  Inject a lightweight stub so
# the import chain succeeds without a live Postgres connection.
_db_stub = types.ModuleType("sin.storage.database")
_db_stub.Base = MagicMock()
_db_stub.SessionLocal = MagicMock()
_db_stub.engine = MagicMock()
sys.modules.setdefault("sin.storage.database", _db_stub)

# Also stub models so they don't re-trigger the database import
_models_stub = types.ModuleType("sin.storage.models")
for _cls in ("DeviceLog", "ScanSession", "SecurityEvent", "User",
             "RefreshToken", "DeviceBaseline"):
    setattr(_models_stub, _cls, MagicMock())
sys.modules.setdefault("sin.storage.models", _models_stub)

# ─────────────────────────────────────────────────────────────────────────────
# TASK 1 — Scan-stuck bug
# ─────────────────────────────────────────────────────────────────────────────

class TestScanStuckBug(unittest.TestCase):
    """TTL is 300 s (5 min) and _set_scan_running(False) is called even on crash."""

    def _make_redis_mock(self):
        r = MagicMock()
        r.ping.return_value = True
        return r

    def test_setex_ttl_is_300(self):
        """_set_scan_running(True) must use a 300-second TTL, not 3600."""
        from sin.api import server as srv
        r = self._make_redis_mock()
        with patch.object(srv, "_redis_client", return_value=r):
            srv._set_scan_running(True)
        r.setex.assert_called_once()
        _key, ttl, _val = r.setex.call_args.args
        self.assertEqual(
            ttl, 300,
            f"Expected TTL=300 but got {ttl}. "
            "Change r.setex(_SCAN_REDIS_KEY, 3600, '1') → 300 in server.py."
        )

    def test_scan_running_cleared_on_runner_crash(self):
        """run_scan_job must call _set_scan_running(False) even when runner raises."""
        from sin.api import server as srv
        cleared = []
        orig_set = srv._set_scan_running

        def track(v):
            cleared.append(v)

        with patch.object(srv, "_set_scan_running", side_effect=track), \
             patch.object(srv, "AgentRunner") as MockRunner:
            MockRunner.return_value.run_assessment.side_effect = RuntimeError("boom")
            try:
                srv.run_scan_job("192.168.30.0/24")
            except Exception:
                pass
        self.assertIn(
            False, cleared,
            "_set_scan_running(False) was never called after runner crash."
        )

    def test_scan_running_cleared_on_success(self):
        """run_scan_job calls _set_scan_running(False) on normal completion."""
        from sin.api import server as srv
        cleared = []
        with patch.object(srv, "_set_scan_running", side_effect=lambda v: cleared.append(v)), \
             patch.object(srv, "AgentRunner"):
            srv.run_scan_job("192.168.30.0/24")
        self.assertIn(False, cleared)


# ─────────────────────────────────────────────────────────────────────────────
# TASK 2 — Xiongmai SDK binary probe
# ─────────────────────────────────────────────────────────────────────────────

# Helpers to build realistic Xiongmai SDK response packets
_XM_MAGIC = b'\xff\x01\x00\x00'
_HEADER_FMT = "<4sIIBBHI"

def _build_xm_response(cmd: int, payload: bytes) -> bytes:
    header = struct.pack(_HEADER_FMT, _XM_MAGIC, 0, 0, 0, 0, cmd, len(payload))
    return header + payload


class TestProbeXiongmaiSDK(unittest.TestCase):
    """probe_xiongmai_sdk must extract model/firmware/serial from port-34567 responses."""

    def _mock_socket(self, responses: list):
        """
        Build a mock socket whose recv() calls cycle through `responses`.
        Each element is either raw bytes (returned directly) or a dict
        {cmd, payload} that gets packed as a proper XM packet.
        """
        sock = MagicMock()
        recv_iter = iter(responses)

        def fake_recv(n):
            try:
                return next(recv_iter)
            except StopIteration:
                return b''

        sock.recv.side_effect = fake_recv
        return sock

    def _make_login_resp_bytes(self, ret=100, session_id="0x00000001"):
        payload = (json.dumps({
            "Ret": ret,
            "SessionID": session_id,
            "Name": "OPLogin",
        }) + '\n').encode()
        pkt = _build_xm_response(0x27a0, payload)
        # Split into 20-byte header chunk + rest to exercise recv loop
        return pkt[:20], pkt[20:]

    def _make_sysinfo_resp_bytes(self, sn="SN20230601ABC", hw="HW-V1.0", sw="V2.800.0000000.1", build="2023-06-01"):
        payload = (json.dumps({
            "Ret": 100,
            "Name": "SystemInfo",
            "SystemInfo": {
                "SerialNo":       sn,
                "HardWareVersion": hw,
                "SoftWareVersion": sw,
                "BuildDate":      build,
            }
        }) + '\n').encode()
        pkt = _build_xm_response(0x27f8, payload)
        return pkt[:20], pkt[20:]

    def test_extracts_model_firmware_serial(self):
        from sin.scanner.http_fingerprint import probe_xiongmai_sdk

        login_h, login_b   = self._make_login_resp_bytes()
        sysinfo_h, sysinfo_b = self._make_sysinfo_resp_bytes(
            sn="SN20230601ABC",
            hw="HW-V1.0",
            sw="V2.800.0000000.1.R",
        )
        responses = [login_h, login_b, sysinfo_h, sysinfo_b]

        fake_sock = MagicMock()
        recv_iter = iter(responses)
        fake_sock.recv.side_effect = lambda n: next(recv_iter, b'')

        with patch("socket.socket") as MockSock:
            MockSock.return_value.__enter__ = lambda s: s
            MockSock.return_value.__exit__ = MagicMock(return_value=False)
            MockSock.return_value = fake_sock

            result = probe_xiongmai_sdk("192.168.30.4")

        self.assertIn("vendor", result, "vendor missing from SDK probe result")
        self.assertIn("Xiongmai", result["vendor"])
        self.assertEqual(result.get("serial_number"), "SN20230601ABC")
        self.assertEqual(result.get("model"), "HW-V1.0")
        self.assertIn("V2.800", result.get("firmware", ""))

    def test_connection_refused_returns_empty(self):
        from sin.scanner.http_fingerprint import probe_xiongmai_sdk
        with patch("socket.socket") as MockSock:
            MockSock.return_value.connect.side_effect = ConnectionRefusedError
            result = probe_xiongmai_sdk("192.168.30.4")
        self.assertEqual(result, {})

    def test_vendor_set_even_without_sysinfo(self):
        """
        If login succeeds but OPSystemInfo returns garbage, vendor must still be set.
        """
        from sin.scanner.http_fingerprint import probe_xiongmai_sdk

        login_h, login_b = self._make_login_resp_bytes(ret=101)
        # Corrupt sysinfo — magic OK but garbage payload
        bad_sysinfo = _build_xm_response(0x27f8, b'not json\n')
        si_h, si_b = bad_sysinfo[:20], bad_sysinfo[20:]

        responses = [login_h, login_b, si_h, si_b]
        fake_sock = MagicMock()
        recv_iter = iter(responses)
        fake_sock.recv.side_effect = lambda n: next(recv_iter, b'')

        with patch("socket.socket") as MockSock:
            MockSock.return_value = fake_sock
            result = probe_xiongmai_sdk("192.168.30.4")

        self.assertIn("vendor", result)
        self.assertIn("Xiongmai", result["vendor"])

    def test_fingerprint_uses_sdk_probe_for_34567(self):
        """fingerprint() must call probe_xiongmai_sdk when 34567 is in open_ports."""
        from sin.scanner import http_fingerprint as hfp

        with patch.object(hfp, "probe_xiongmai_sdk", return_value={
            "vendor": "Xiongmai (Sofia SDK)",
            "model": "HW-V2.0",
            "firmware": "V4.02.R11",
            "serial_number": "SNTEST001",
            "device_type": "DVR/NVR",
        }) as mock_probe, \
        patch.object(hfp, "_http_get", return_value=None):

            result = hfp.fingerprint("192.168.30.4", [80, 554, 34567])

        mock_probe.assert_called_once_with("192.168.30.4")
        self.assertEqual(result["vendor"], "Xiongmai (Sofia SDK)")
        self.assertEqual(result["model"], "HW-V2.0")
        self.assertEqual(result["firmware"], "V4.02.R11")
        self.assertEqual(result["serial_number"], "SNTEST001")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 3 — Weighted composite risk scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestCompositeRiskScoring(unittest.TestCase):
    """
    _compute_risk() must produce realistic, differentiated scores.

    Rules (Phase 3.1):
      - Score = highest finding weight + capped secondary bonus (max +20)
      - CRITICAL requires has_rce AND creds_confirmed
      - HIGH     requires score >= 50 (with or without rce)
      - MEDIUM   score >= 25
      - LOW      score < 25
      - Max auto score = 99 (100 reserved for human-confirmed compromise)
    """

    def setUp(self):
        from sin.scanner.audit import _compute_risk
        self._score = lambda findings, creds=False: _compute_risk(findings, creds)

    # ── score correctness ─────────────────────────────────────────────────────

    def test_empty_findings_score_zero(self):
        score, level = self._score([])
        self.assertEqual(score, 0)
        self.assertEqual(level, "LOW")

    def test_score_never_exceeds_99(self):
        # Pile on many CRITICAL findings — score must stay ≤ 99
        many = [{"severity": "CRITICAL", "type": "Remote Code Execution",
                 "cve": "CVE-2018-10088", "in_kev": True, "epss": 0.99}] * 10
        score, _ = self._score(many, creds=True)
        self.assertLessEqual(score, 99, f"Score {score} exceeded 99 — auto scoring must never hit 100")

    def test_single_rce_finding_scores_high(self):
        # CVE-2018-10088 weight=85 → base 85, no bonus → HIGH
        score, level = self._score([
            {"severity": "CRITICAL", "type": "Remote Code Execution",
             "cve": "CVE-2018-10088"}
        ])
        self.assertGreaterEqual(score, 50, f"RCE finding should score >= 50, got {score}")
        self.assertIn(level, ("HIGH", "CRITICAL"))

    def test_http_only_scores_medium(self):
        # weight=30 → MEDIUM band
        score, level = self._score([
            {"severity": "LOW", "type": "Unencrypted Management HTTP", "cve": ""}
        ])
        self.assertGreaterEqual(score, 25)
        self.assertEqual(level, "MEDIUM")

    def test_rtsp_only_scores_medium(self):
        score, level = self._score([
            {"severity": "MEDIUM", "type": "Privacy Leak (RTSP)", "cve": ""}
        ])
        self.assertEqual(level, "MEDIUM")

    # ── level correctness ─────────────────────────────────────────────────────

    def test_critical_requires_rce_and_confirmed_creds(self):
        score, level = self._score([
            {"severity": "CRITICAL", "type": "Remote Code Execution",
             "cve": "CVE-2018-10088"},
            {"severity": "CRITICAL", "type": "DEFAULT_CREDS_FOUND", "cve": ""},
        ], creds=True)
        self.assertEqual(level, "CRITICAL",
            f"RCE + confirmed creds must be CRITICAL, got {level} (score={score})")

    def test_rce_without_creds_is_high_not_critical(self):
        # 192.168.30.4 profile: RCE port open, no cred confirmation
        score, level = self._score([
            {"severity": "CRITICAL", "type": "Remote Code Execution",
             "cve": "CVE-2018-10088", "in_kev": True, "epss": 0.9},
            {"severity": "MEDIUM",   "type": "Privacy Leak (RTSP)", "cve": ""},
            {"severity": "LOW",      "type": "Unencrypted Management HTTP", "cve": ""},
        ], creds=False)
        self.assertEqual(level, "HIGH",
            f"RCE without confirmed creds must be HIGH not CRITICAL, got {level} (score={score})")

    def test_smb_without_creds_is_not_critical(self):
        score, level = self._score([
            {"severity": "CRITICAL", "type": "Windows SMB Exposure", "cve": ""}
        ], creds=False)
        self.assertNotEqual(level, "CRITICAL",
            f"SMB alone (no creds) must not be CRITICAL under Phase 3.1 rules, got {level}")
        self.assertEqual(level, "HIGH")

    def test_telnet_alone_not_pegged_to_100(self):
        # Old additive scoring gave telnet +95 → capped 100; new must be < 85
        score, level = self._score([
            {"severity": "CRITICAL", "type": "Cleartext Management Telnet", "cve": ""}
        ])
        self.assertLess(score, 85,
            f"Telnet alone scored {score} — additive inflation bug still present")
        self.assertEqual(level, "HIGH")

    def test_low_level_clean(self):
        score, level = self._score([])
        self.assertEqual(level, "LOW")
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
