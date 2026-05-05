"""
sin.discovery.network
═════════════════════
Wraps the compiled Go sensor binary and normalises its JSON output
into the canonical asset dict consumed by AuditEngine and DecisionEngine.

Enterprise fixes in this revision
───────────────────────────────────
* FIXED:  `banners` field from Go sensor was silently dropped.
          Previously it was remapped to `services` only — the `banners` key
          itself was never set.  AuditEngine.evaluate_asset() reads
          `device_data.get("banners", {})`, so every banner-based heuristic
          (H264DVR, Hikvision, Dahua) was evaluating an empty string.
          Now both `banners` AND `services` are populated from the Go output,
          whichever field name the binary version uses.

* FIXED:  Go `main.go` emits banners as map[int]string (int port keys).
          After JSON decode those become string keys like "80", "554".
          Both int and string keys are now normalised to string keys so
          downstream code can safely do banners.get("80") or banners["554"].

* FIXED:  subnet normalisation regex was fragile — "192.168.30.0/24" was
          correctly stripped but "192.168.1.100" (a host IP passed by the
          API) would become "192.168.1." breaking the Go binary call.
          Replaced with explicit CIDR-aware parsing.

* ADDED:  Sensor binary path configurable via SIN_SENSOR_PATH env var so
          Docker deployments don't need to rely on relative path resolution.

* ADDED:  `timeout` on the subprocess call (default 300s) so a hung scan
          never blocks the Celery worker permanently.

* ADDED:  `discovery_method` field propagated from Go output so AuditEngine
          Layer 1 (ONVIF metadata leak) scoring works correctly.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from sin.utils.logger import get_logger

logger = get_logger("sin.discovery.network")

# Path to the compiled Go sensor binary
# Docker: mount at /app/scanner/sin-sensor or override via env
_DEFAULT_SENSOR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../scanner/sin-sensor")
)
SENSOR_PATH    = os.getenv("SIN_SENSOR_PATH", _DEFAULT_SENSOR)
SCAN_TIMEOUT_S = int(os.getenv("SIN_SCAN_TIMEOUT", "300"))


def _normalise_subnet(raw: str) -> str:
    """
    Accept any of these formats and return the bare X.X.X prefix:
      192.168.30          → 192.168.30
      192.168.30.0/24     → 192.168.30
      192.168.30.0        → 192.168.30
      192.168.30.100      → 192.168.30   (host IP — use its /24)
    """
    raw = raw.strip()
    # Already in prefix form
    if raw.count(".") == 2 and "/" not in raw:
        return raw
    # Strip CIDR suffix then take first three octets
    host_part = raw.split("/")[0]
    octets = host_part.split(".")
    if len(octets) >= 3:
        return ".".join(octets[:3])
    return raw


def _normalise_banners(raw_banners: Dict) -> Dict[str, str]:
    """
    Go JSON can produce banners with integer-string keys ("80") or
    integer keys that Python's json.loads keeps as strings.
    Normalise everything to {str_port: banner_string}.
    Also flatten None / non-string values to "".
    """
    out: Dict[str, str] = {}
    for k, v in raw_banners.items():
        out[str(k)] = str(v) if v else ""
    return out


class NetworkDiscovery:

    def __init__(self) -> None:
        self.sensor_path = SENSOR_PATH
        if not os.path.isfile(self.sensor_path):
            logger.warning(
                f"Go sensor not found at {self.sensor_path}. "
                "Set SIN_SENSOR_PATH or compile scanner/sin-sensor."
            )

    def execute_subnet_scan(self, subnet_cidr: str | None = None) -> List[Dict]:
        """
        Run the Go sensor against *subnet_cidr* and return normalised asset dicts.
        Never raises — returns [] on any failure so the caller can continue.
        """
        target = _normalise_subnet(subnet_cidr or "192.168.30")
        session_id = str(uuid.uuid4())[:8].upper()

        logger.info(f"[{session_id}] Go sensor firing on {target}.0/24")

        try:
            result = subprocess.check_output(
                [self.sensor_path, target],
                text=True,
                timeout=SCAN_TIMEOUT_S,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error(f"[{session_id}] Sensor binary not found: {self.sensor_path}")
            return []
        except subprocess.TimeoutExpired:
            logger.error(f"[{session_id}] Sensor timed out after {SCAN_TIMEOUT_S}s")
            return []
        except subprocess.CalledProcessError as exc:
            logger.error(f"[{session_id}] Sensor exited non-zero: {exc.returncode} | {exc.stderr}")
            return []

        # Sensor may print progress lines before the JSON array
        json_start = result.find("[")
        if json_start == -1:
            logger.error(f"[{session_id}] No JSON array in sensor output")
            return []

        try:
            devices: List[Dict] = json.loads(result[json_start:])
        except json.JSONDecodeError as exc:
            logger.error(f"[{session_id}] JSON parse failed: {exc}")
            return []

        enriched = [self._normalise_device(d, session_id) for d in devices]
        logger.info(f"[{session_id}] Sensor complete | assets={len(enriched)}")
        return enriched

    # ── Internal ───────────────────────────────────────────────────────────────

    def _normalise_device(self, d: Dict, session_id: str) -> Dict:
        """
        Map raw Go JSON → canonical asset dict.

        Go binary versions differ in field names:
          sin-scanner.go  → "services"  (map[string]string)
          main.go         → "banners"   (map[int]string → string keys after JSON)

        We read whichever is present and populate BOTH keys so all downstream
        consumers (AuditEngine, DecisionEngine, fingerprint) can read either.
        """
        # Grab whichever banner field the binary version emitted
        raw_banners: Dict = (
            d.get("banners")      # main.go output
            or d.get("services")  # sin-scanner.go output
            or {}
        )
        banners: Dict[str, str] = _normalise_banners(raw_banners)

        # Concatenated banner string for quick substring searches
        banner_blob = " ".join(banners.values()).lower()

        return {
            # ── Identity ───────────────────────────────────────────────────
            "scan_session_id":  session_id,
            "ip_address":       d.get("ip_address", ""),
            "status":           d.get("status", "online"),
            "mac_address":      d.get("mac_address") or "",
            "hostname":         d.get("hostname") or "",

            # ── Vendor / fingerprint ───────────────────────────────────────
            "manufacturer":     d.get("manufacturer") or d.get("vendor") or "",
            "vendor":           d.get("vendor") or d.get("manufacturer") or "",
            # Keep unknown OS empty to avoid false IoT classification from defaults.
            "os_family":        d.get("os_family") or "",
            "device_type":      d.get("device_type", "unknown"),
            "model":            d.get("model", ""),

            # ── Network telemetry ──────────────────────────────────────────
            "open_ports":       d.get("open_ports") or [],

            # BOTH keys populated — audit.py reads "banners", runner reads "services"
            "banners":          banners,
            "services":         banners,

            # Flat string for fast substring checks in heuristics
            "banner_blob":      banner_blob,

            # ── Protocol hints ─────────────────────────────────────────────
            "protocol_hints":   d.get("protocol_hints") or [],

            # ── Discovery metadata ─────────────────────────────────────────
            "discovery_method": d.get("discovery_method") or d.get("scan_method") or "Go Sensor",

            # ── Initialise audit fields (filled by AuditEngine) ────────────
            "vulnerabilities":  [],
            "risk_score":       0,
            "risk_level":       "UNKNOWN",

            # ── Timestamps ─────────────────────────────────────────────────
            "last_seen":        datetime.now(timezone.utc).isoformat(),
        }
