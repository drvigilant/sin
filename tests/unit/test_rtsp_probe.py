"""
tests/unit/test_rtsp_probe.py
══════════════════════════════
Unit tests for sin.scanner.rtsp_probe.

All network I/O is mocked — no live devices required.
"""

import base64
import hashlib
import socket
from unittest.mock import MagicMock, patch

import pytest

from sin.scanner.rtsp_probe import (
    MAX_CRED_ATTEMPTS,
    RTSP_CREDS,
    RTSPProbe,
    _build_basic_auth,
    _digest_response,
    _ordered_paths,
    _parse_digest_challenge,
    _vendor_key,
)

IP   = "192.168.1.10"
PORT = 554
PATH = "/stream"


# ── Socket mock helper ────────────────────────────────────────────────────────

def _make_socket_mock(*recv_responses):
    """Mock socket context-manager returning recv_responses in sequence."""
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: mock_sock
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.side_effect = [
        r.encode() if isinstance(r, str) else r
        for r in recv_responses
    ]
    return mock_sock


# ── _vendor_key ───────────────────────────────────────────────────────────────

class TestVendorKey:
    def test_hikvision(self):
        assert _vendor_key("hikvision") == "hikvision"

    def test_hikvision_mixed_case(self):
        assert _vendor_key("Hikvision NVR") == "hikvision"

    def test_dahua(self):
        assert _vendor_key("Dahua DVR") == "dahua"

    def test_axis(self):
        assert _vendor_key("AXIS P3245") == "axis"

    def test_xiongmai(self):
        assert _vendor_key("xiongmai dvr") == "xiongmai"

    def test_unknown_returns_generic(self):
        assert _vendor_key("securus camera") == "generic"

    def test_empty_returns_generic(self):
        assert _vendor_key("") == "generic"


# ── _ordered_paths ────────────────────────────────────────────────────────────

class TestOrderedPaths:
    def test_hikvision_paths_come_first(self):
        paths = _ordered_paths("hikvision")
        assert paths[0] == "/Streaming/Channels/101"

    def test_dahua_paths_come_first(self):
        paths = _ordered_paths("dahua")
        assert paths[0] == "/cam/realmonitor?channel=1&subtype=0"

    def test_generic_paths_always_present(self):
        paths = _ordered_paths("unknown vendor")
        assert "/stream" in paths
        assert "/live" in paths

    def test_no_duplicates(self):
        paths = _ordered_paths("hikvision")
        assert len(paths) == len(set(paths))

    def test_unknown_vendor_first_path_is_root(self):
        """For unknown vendors no vendor block is prepended — first path is generic '/'."""
        paths = _ordered_paths("unknown_vendor_xyz")
        assert paths[0] == "/"


# ── _parse_digest_challenge ───────────────────────────────────────────────────

class TestParseDigestChallenge:
    def test_valid_digest_header(self):
        header = 'Digest realm="IPCamera", nonce="abc123xyz"'
        result = _parse_digest_challenge(header)
        assert result is not None
        assert result["realm"] == "IPCamera"
        assert result["nonce"] == "abc123xyz"

    def test_basic_auth_returns_none(self):
        assert _parse_digest_challenge('Basic realm="camera"') is None

    def test_missing_nonce_returns_none(self):
        assert _parse_digest_challenge('Digest realm="camera"') is None

    def test_missing_realm_returns_none(self):
        assert _parse_digest_challenge('Digest nonce="abc"') is None

    def test_extra_fields_parsed(self):
        header = 'Digest realm="cam", nonce="xyz", algorithm=MD5, qop="auth"'
        result = _parse_digest_challenge(header)
        assert result is not None
        assert result["realm"] == "cam"


# ── _digest_response ──────────────────────────────────────────────────────────

class TestDigestResponse:
    def test_rfc2617_computation(self):
        """Verify the MD5 chain matches RFC 2617 exactly."""
        username = "admin"
        password = "12345"
        realm    = "IPCamera"
        nonce    = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        method   = "DESCRIBE"
        uri      = "rtsp://192.168.1.1:554/stream"

        ha1      = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2      = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        assert _digest_response(username, password, realm, nonce, method, uri) == expected

    def test_returns_32_char_hex(self):
        result = _digest_response("admin", "", "realm", "nonce", "DESCRIBE", "/")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)


# ── _build_basic_auth ─────────────────────────────────────────────────────────

class TestBuildBasicAuth:
    def test_encodes_correctly(self):
        token = _build_basic_auth("admin", "12345")
        decoded = base64.b64decode(token).decode()
        assert decoded == "admin:12345"

    def test_blank_password(self):
        token = _build_basic_auth("admin", "")
        decoded = base64.b64decode(token).decode()
        assert decoded == "admin:"


# ── RTSPProbe._try_path ───────────────────────────────────────────────────────

class TestTryPath:
    def setup_method(self):
        self.probe = RTSPProbe()

    def test_returns_true_on_200_with_sdp(self):
        mock_sock = _make_socket_mock(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n",
            "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n",
        )
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_path(IP, PORT, PATH) is True

    def test_returns_true_on_200_without_sdp_body(self):
        """Some cameras return 200 OK without SDP — still counts as open."""
        mock_sock = _make_socket_mock(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n",
            "RTSP/1.0 200 OK\r\n\r\n",
        )
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_path(IP, PORT, PATH) is True

    def test_returns_false_on_401(self):
        mock_sock = _make_socket_mock(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n",
            "RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"cam\", nonce=\"x\"\r\n\r\n",
        )
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_path(IP, PORT, PATH) is False

    def test_returns_false_on_connection_refused(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect.side_effect = ConnectionRefusedError
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_path(IP, PORT, PATH) is False

    def test_returns_false_on_non_rtsp_response(self):
        """HTTP server on port 554 should not be flagged."""
        mock_sock = _make_socket_mock("HTTP/1.1 200 OK\r\n\r\n")
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_path(IP, PORT, PATH) is False


# ── RTSPProbe._try_basic ──────────────────────────────────────────────────────

class TestTryBasic:
    def setup_method(self):
        self.probe = RTSPProbe()

    def test_returns_true_on_200(self):
        mock_sock = _make_socket_mock(
            "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n"
        )
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_basic(IP, PORT, PATH, "admin", "12345") is True

    def test_returns_false_on_401(self):
        mock_sock = _make_socket_mock("RTSP/1.0 401 Unauthorized\r\n\r\n")
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_basic(IP, PORT, PATH, "admin", "wrong") is False

    def test_returns_false_on_timeout(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect.side_effect = socket.timeout
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_basic(IP, PORT, PATH, "admin", "12345") is False


# ── RTSPProbe._try_digest ─────────────────────────────────────────────────────

class TestTryDigest:
    def setup_method(self):
        self.probe   = RTSPProbe()
        self.challenge = {"realm": "IPCamera", "nonce": "abc123"}

    def test_returns_true_on_200(self):
        mock_sock = _make_socket_mock(
            "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n"
        )
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_digest(
                IP, PORT, PATH, "admin", "12345", self.challenge
            ) is True

    def test_returns_false_on_401(self):
        mock_sock = _make_socket_mock("RTSP/1.0 401 Unauthorized\r\n\r\n")
        with patch("sin.scanner.rtsp_probe.socket.socket", return_value=mock_sock):
            assert self.probe._try_digest(
                IP, PORT, PATH, "admin", "wrong", self.challenge
            ) is False


# ── RTSPProbe.probe ───────────────────────────────────────────────────────────

class TestProbe:
    def setup_method(self):
        self.probe = RTSPProbe()

    def test_returns_critical_finding_on_open_stream(self):
        with patch.object(self.probe, "_try_path", return_value=True):
            result = self.probe.probe(IP, PORT, vendor="hikvision")
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert result["type"] == "Unauthenticated RTSP Stream"
        assert result["engine"] == "rtsp_probe"
        assert IP in result["rtsp_url"]

    def test_returns_none_when_no_open_path(self):
        with patch.object(self.probe, "_try_path", return_value=False):
            assert self.probe.probe(IP, PORT, vendor="hikvision") is None

    def test_finding_url_includes_matched_path(self):
        with patch.object(
            self.probe, "_try_path",
            side_effect=lambda ip, port, path: path == "/stream",
        ):
            result = self.probe.probe(IP, PORT, vendor="")
        assert result is not None
        assert result["rtsp_url"] == f"rtsp://{IP}:{PORT}/stream"

    def test_cwe_306_cited(self):
        with patch.object(self.probe, "_try_path", return_value=True):
            result = self.probe.probe(IP, PORT)
        assert result["cve"] == "CWE-306"


# ── RTSPProbe.probe_with_creds ────────────────────────────────────────────────

class TestProbeWithCreds:
    def setup_method(self):
        self.probe = RTSPProbe()

    def test_returns_high_finding_on_basic_match(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=("basic", None)), \
             patch.object(self.probe, "_try_basic", return_value=True):
            result = self.probe.probe_with_creds(IP, PORT, vendor="hikvision")
        assert result is not None
        assert result["severity"] == "HIGH"
        assert result["type"] == "RTSP Default Credentials"
        assert result["auth_type"] == "basic"
        assert result["engine"] == "rtsp_probe"

    def test_returns_high_finding_on_digest_match(self):
        challenge = {"realm": "IPCamera", "nonce": "abc123"}
        with patch.object(self.probe, "_probe_auth_type", return_value=("digest", challenge)), \
             patch.object(self.probe, "_try_digest", return_value=True):
            result = self.probe.probe_with_creds(IP, PORT, vendor="hikvision")
        assert result is not None
        assert result["severity"] == "HIGH"
        assert result["auth_type"] == "digest"

    def test_finding_includes_credential_dict(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=("basic", None)), \
             patch.object(self.probe, "_try_basic", return_value=True):
            result = self.probe.probe_with_creds(IP, PORT, vendor="hikvision")
        assert "credentials" in result
        assert "username" in result["credentials"]
        assert "password" in result["credentials"]

    def test_returns_none_when_no_creds_match(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=("basic", None)), \
             patch.object(self.probe, "_try_basic", return_value=False):
            assert self.probe.probe_with_creds(IP, PORT, vendor="generic") is None

    def test_returns_none_on_open_stream(self):
        """Open streams are handled by probe() — probe_with_creds() must skip them."""
        with patch.object(self.probe, "_probe_auth_type", return_value=("none", None)):
            assert self.probe.probe_with_creds(IP, PORT, vendor="generic") is None

    def test_returns_none_on_no_rtsp_response(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=(None, None)):
            assert self.probe.probe_with_creds(IP, PORT, vendor="generic") is None

    def test_respects_max_cred_attempts(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=("basic", None)), \
             patch.object(self.probe, "_try_basic", return_value=False) as mock_try:
            self.probe.probe_with_creds(IP, PORT, vendor="generic")
        assert mock_try.call_count == MAX_CRED_ATTEMPTS

    def test_cwe_1392_cited(self):
        with patch.object(self.probe, "_probe_auth_type", return_value=("basic", None)), \
             patch.object(self.probe, "_try_basic", return_value=True):
            result = self.probe.probe_with_creds(IP, PORT, vendor="hikvision")
        assert result["cve"] == "CWE-1392"
