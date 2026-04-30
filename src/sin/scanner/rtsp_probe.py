"""
sin.scanner.rtsp_probe
══════════════════════
Tests RTSP streams for unauthenticated access.
Tries common stream paths without credentials.
If it connects — flags CRITICAL immediately.
"""
import socket
import re
from typing import Dict, List, Optional
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.rtsp_probe")

# Common RTSP paths used by major camera vendors
RTSP_PATHS = [
    "/",
    "/live",
    "/stream",
    "/live/ch00_0",
    "/cam/realmonitor?channel=1&subtype=0",  # Dahua
    "/Streaming/Channels/101",               # Hikvision
    "/h264Preview_01_main",                  # Hikvision alt
    "/live/main",
    "/video1",
    "/ch01.264",                             # Xiongmai/Generic DVR
    "/user=admin&password=&channel=1&stream=0.sdp",  # Generic
    "/onvif1",
]

VENDOR_PATHS = {
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


class RTSPProbe:
    TIMEOUT = 4

    def probe(self, ip: str, port: int = 554, vendor: str = "") -> Optional[Dict]:
        """
        Attempts unauthenticated RTSP OPTIONS + DESCRIBE on common paths.
        Returns finding dict if stream is accessible without credentials, else None.
        """
        vendor_lower = vendor.lower()

        # Build path list — vendor-specific first, then generic
        paths = []
        for v, vp in VENDOR_PATHS.items():
            if v in vendor_lower:
                paths.extend(vp)
        paths.extend(RTSP_PATHS)

        # Deduplicate preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)

        for path in unique_paths:
            result = self._try_path(ip, port, path)
            if result:
                logger.warning(
                    f"RTSP OPEN: {ip}:{port}{path} — "
                    f"unauthenticated access confirmed"
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
                    "in_kev":      False,
                    "rtsp_url":    f"rtsp://{ip}:{port}{path}",
                    "engine":      "rtsp_probe",
                }

        return None

    def _try_path(self, ip: str, port: int, path: str) -> bool:
        """
        Sends RTSP OPTIONS then DESCRIBE. 
        200 OK on DESCRIBE without auth = unauthenticated access.
        401 = auth required (good).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.TIMEOUT)
                s.connect((ip, port))

                # Step 1: OPTIONS
                options_req = (
                    f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"User-Agent: SIN-Scanner/1.0\r\n\r\n"
                )
                s.sendall(options_req.encode())
                resp1 = s.recv(1024).decode(errors="ignore")

                # If server didn't respond at all, skip
                if "RTSP/1.0" not in resp1:
                    return False

                # Step 2: DESCRIBE (this is where auth is enforced)
                describe_req = (
                    f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 2\r\n"
                    f"User-Agent: SIN-Scanner/1.0\r\n"
                    f"Accept: application/sdp\r\n\r\n"
                )
                s.sendall(describe_req.encode())
                resp2 = s.recv(2048).decode(errors="ignore")

                # 200 OK = stream accessible without auth
                if "200 OK" in resp2 and "sdp" in resp2.lower():
                    return True

                # 401/403 = auth required = camera is protected
                if "401" in resp2 or "403" in resp2:
                    return False

                # Some cameras return 200 without SDP body
                if "200 OK" in resp2:
                    return True

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return False


# Module-level singleton
rtsp_probe = RTSPProbe()
