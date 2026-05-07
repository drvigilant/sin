"""
sin.agent.runner
════════════════
Orchestrates a full assessment pass with Enterprise Deduplication.
"""

from __future__ import annotations

import os
import uuid
import json
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List

from sqlalchemy.orm import Session

from sin.agent.baseline import baseline_engine
from sin.agent.decision import DecisionEngine, ThreatVerdict
from sin.agent.mitigation import MitigationEngine
from sin.agent.signal_mapper import normalize_host
from sin.discovery.network import NetworkDiscovery
from sin.response.alert import DiscordAlerter
from sin.scanner.audit import AuditEngine
from sin.storage import models
from sin.storage.database import SessionLocal
from sin.utils.logger import get_logger

logger = get_logger("sin.agent.runner")

_DRY_RUN              = False
_CONFIDENCE_THRESHOLD = float(os.getenv("SIN_CONFIDENCE_THRESHOLD", "0.80"))

# STRICT IOT PORTS: Removed ambiguous ports like 80, 443, and 8000. 
# It MUST have an RTSP or specialized industrial port to be considered IoT by default.
_STRICT_IOT_PORTS = {554, 8554, 37777, 34567, 1883, 8883, 5683, 47808, 502, 4840}
_STRICT_CAMERA_PORTS = {554, 8554, 37777, 34567}
_IOT_VENDORS    = {
    "xiongmai", "h264dvr", "hikvision", "dahua", "axis",
    "reolink", "amcrest", "uniview", "hanwha", "vivotek",
}
_MANAGED_OS = {"windows", "ubuntu", "debian", "centos", "fedora", "macos", "proxmox", "linux kernel"}
_NON_IOT_HOSTNAME_TOKENS = {
    "desktop-", "laptop-", "workstation", "thinkpad", "macbook", "surface", "pc-", "win-"
}
_WINDOWS_PC_MAC_OUIS = {
    "d4:5d:64",  # Dell
    "b8:ca:3a",  # Dell
    "f0:1f:af",  # HP
    "3c:d9:2b",  # HP
    "00:50:56",  # VMware (dev machines)
    "00:0c:29",  # VMware
}
_CAMERA_BANNER_TOKENS = {
    "rtsp", "onvif", "h264dvr", "ip camera", "network camera", "camera login",
    "hikvision", "dahua", "xiongmai", "axis", "vivotek", "reolink", "amcrest", "uniview",
}
# Common camera/security OUI prefixes (first 3 bytes)
_CAMERA_MAC_OUIS = {
    "00:40:8c",  # Axis
    "44:19:b6",  # Hikvision
    "bc:ad:28",  # Dahua
    "ac:cc:8e",  # Vivotek
    "ec:71:db",  # Reolink
}


def _normalise_mac_prefix(raw_mac: str) -> str:
    mac = (raw_mac or "").lower().replace("-", ":")
    parts = [p for p in mac.split(":") if p]
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])

def _broadcast_ws(event_type: str, message: str):
    """Pushes instantaneous state changes to the WebSocket UI via Redis."""
    try:
        import redis
        r = redis.Redis(host=os.getenv("SIN_REDIS_HOST", "redis"), port=int(os.getenv("SIN_REDIS_PORT", "6379")))
        payload = json.dumps({
            "type": event_type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        r.publish("sin:ws:stream", payload)
    except Exception as e:
        logger.debug(f"Failed to broadcast WS event: {e}")


def _policy_enabled(policy_name: str, default: bool = False) -> bool:
    """Read policy flags from Redis with safe defaults."""
    try:
        import redis
        r = redis.Redis(
            host=os.getenv("SIN_REDIS_HOST", "redis"),
            port=int(os.getenv("SIN_REDIS_PORT", "6379")),
            password=os.getenv("SIN_REDIS_PASSWORD", ""),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        raw = r.get("sin:policies")
        if not raw:
            return default
        policies = json.loads(raw)
        return bool(policies.get(policy_name, default))
    except Exception:
        return default

def _is_iot(asset: Dict, whitelisted_macs: set) -> bool:
    # 1. Check UI Whitelist
    mac = str(asset.get("mac_address", "")).lower()
    if mac in whitelisted_macs:
        return False

    raw_ports = asset.get("open_ports", [])
    ports = {int(p) for p in raw_ports if str(p).isdigit()}
    
    mfr      = (asset.get("manufacturer") or asset.get("vendor") or "").lower()
    banners_map = asset.get("banners", {}) or {}
    banners  = f"{asset.get('banner_blob', '')} {str(banners_map)}".lower()
    os_hint  = str(asset.get("os_family", "")).lower()
    hostname = str(asset.get("hostname", "")).lower()
    mac_oui  = _normalise_mac_prefix(mac)
    device_type = str(asset.get("device_type", "")).lower()

    # 2. HARD DROP: Known managed endpoints and developer workstations.
    if any(token in hostname for token in _NON_IOT_HOSTNAME_TOKENS):
        return False
    if any(h in os_hint for h in _MANAGED_OS) and "embedded" not in os_hint:
        return False
    if device_type in {"desktop", "laptop", "workstation", "server"}:
        return False
    if _normalise_mac_prefix(mac) in _WINDOWS_PC_MAC_OUIS:
    	return False

    # 3. HARD INCLUSION SIGNALS (must be explicit, not inferred)
    has_strict_iot_port = bool(_STRICT_IOT_PORTS.intersection(ports))
    has_camera_port = bool(_STRICT_CAMERA_PORTS.intersection(ports))
    has_camera_vendor = any(v in mfr or v in banners for v in _IOT_VENDORS)
    has_camera_banner = any(token in banners for token in _CAMERA_BANNER_TOKENS)
    has_camera_oui = mac_oui in _CAMERA_MAC_OUIS
    has_iot_type = any(t in device_type for t in {"camera", "iot", "nvr", "dvr"})

    # 4. Absolute default-deny:
    # - Accept if explicit camera protocol signature is present.
    # - Accept if a camera vendor/OUI/type is corroborated by at least one strict IoT port.
    if has_camera_banner and has_camera_port:
        return True
    if has_camera_vendor and (has_camera_port or has_strict_iot_port):
        return True
    if has_camera_oui and (has_camera_port or has_strict_iot_port):
        return True
    if has_iot_type and (has_camera_port or has_strict_iot_port):
        return True

    # 5. DEFAULT DENY: deny unless explicitly proven IoT/camera.
    return False

class AgentRunner:
    def __init__(self) -> None:
        self.discovery  = NetworkDiscovery()
        self.auditor    = AuditEngine()
        self.decision   = DecisionEngine()
        self.mitigation = MitigationEngine(dry_run=False)
        self.alerter    = DiscordAlerter()
        self.session_id = str(uuid.uuid4())

        logger.info(f"AgentRunner init | session={self.session_id} dry_run={_DRY_RUN} threshold={_CONFIDENCE_THRESHOLD}")

    def _get_whitelisted_macs(self) -> set:
        db: Session = SessionLocal()
        try:
            rows = db.query(models.DeviceLog).filter(models.DeviceLog.status == "whitelisted").all()
            return {str(r.mac_address).lower() for r in rows if r.mac_address}
        except Exception as e:
            logger.error(f"Failed to fetch whitelist: {e}")
            return set()
        finally:
            db.close()

    def run_assessment(self, subnet: str) -> List[Dict]:
        if not _policy_enabled("network_discovery_enabled", True):
            logger.warning(f"[{self.session_id}] Discovery blocked by policy network_discovery_enabled=false")
            _broadcast_ws("SCAN_COMPLETE", "Network discovery disabled by policy.")
            return []

        logger.info(f"[{self.session_id}] Assessment started | target={subnet}.0/24")
        _broadcast_ws("SCAN_START", f"Active discovery initiated on {subnet}.0/24")

        start_time = datetime.now(timezone.utc)
        
        whitelisted_macs = self._get_whitelisted_macs()
        raw_assets = self.discovery.execute_subnet_scan(subnet)
        
        # Apply the new Default-Deny IoT filter
        iot_assets = [a for a in raw_assets if _is_iot(a, whitelisted_macs)]

        total_assets = len(iot_assets)
        _broadcast_ws("SCAN_PROGRESS", json.dumps({"current": 0, "total": total_assets}))

        enriched: List[Dict] = []
        
        # Multi-Threaded Execution (Drops scan from 1m 23s down to ~10s)
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            future_to_asset = {executor.submit(self._process_asset, asset): asset for asset in iot_assets}
            for idx, future in enumerate(concurrent.futures.as_completed(future_to_asset)):
                try:
                    enriched.append(future.result())
                    _broadcast_ws("SCAN_PROGRESS", json.dumps({"current": idx + 1, "total": total_assets}))
                except Exception as exc:
                    logger.error(f"Audit thread failed: {exc}")

        end_time = datetime.now(timezone.utc)
        self._persist(subnet, start_time, end_time, enriched)

        elapsed = (end_time - start_time).total_seconds()
        logger.info(f"[{self.session_id}] Complete | audited={len(enriched)} elapsed={elapsed:.1f}s")
        _broadcast_ws("SCAN_COMPLETE", f"Assessment complete. Audited {len(enriched)} assets.")
        return enriched

    def _process_asset(self, asset: Dict) -> Dict:
        ip = asset.get("ip_address", "?")
        vulns, _audit_score, _audit_action = self.auditor.evaluate_asset(asset)
        asset["vulnerabilities"] = vulns
        asset = normalize_host(asset)
        verdict: ThreatVerdict = self.decision.evaluate(asset)

        asset["risk_score"]   = round(verdict.confidence * 100)
        asset["risk_level"]   = verdict.severity
        asset["risk_reasons"] = verdict.reasons
        asset["verdict"] = {
            "score":      verdict.score,
            "confidence": verdict.confidence,
            "severity":   verdict.severity,
            "action":     verdict.recommended_action,
            "signals":    verdict.signal_count,
        }

        auto_quarantine_critical = _policy_enabled("auto_quarantine_critical", True)
        force_auto_quarantine = auto_quarantine_critical and asset.get("risk_score", 0) > 90

        if verdict.is_actionable(_CONFIDENCE_THRESHOLD) or force_auto_quarantine:
            try:
                result = self.mitigation.isolate(asset, verdict)
                asset["mitigation_rule_id"] = result.rule_id
                asset["mitigation_action"]  = result.action_type
                if force_auto_quarantine and not verdict.is_actionable(_CONFIDENCE_THRESHOLD):
                    _broadcast_ws("MITIGATION", f"Auto-quarantined {ip} (risk>{asset.get('risk_score', 0)})")
                else:
                    _broadcast_ws("MITIGATION", f"Quarantined {ip} ({verdict.severity} Risk)")
            except Exception as exc:
                logger.error(f"[MITIGATE] Failed for {ip}: {exc}", exc_info=True)
                asset["mitigation_rule_id"] = None
                asset["mitigation_action"]  = "error"
        else:
            asset["mitigation_rule_id"] = None
            asset["mitigation_action"]  = "none"

        return asset

    def _persist(self, subnet: str, start: datetime, end: datetime, assets: List[Dict]) -> None:
        db: Session = SessionLocal()
        try:
            session_row = models.ScanSession(
                session_uuid=self.session_id,
                subnet_target=subnet,
                start_time=start,
                end_time=end,
            )
            db.add(session_row)
            db.flush()

            for asset in assets:
                ip = asset.get("ip_address", "")

                db.add(models.DeviceLog(
                    scan_id         = session_row.id,
                    ip_address      = ip,
                    hostname        = asset.get("hostname"),
                    status          = "online",
                    vendor          = asset.get("manufacturer") or asset.get("vendor"),
                    os_family       = asset.get("os_family"),
                    open_ports      = asset.get("open_ports", []),
                    protocols       = list(asset.get("services", {}).values()),
                    vulnerabilities = asset.get("vulnerabilities", []),
                    mac_address     = asset.get("mac_address"),
                    device_type     = asset.get("device_type"),
                    firmware        = asset.get("firmware"),
                    serial_number   = asset.get("serial") or asset.get("serial_number"),
                    model           = asset.get("model"),
                    risk_score      = asset.get("risk_score", 0),
                    risk_level      = asset.get("risk_level", "UNKNOWN"),
                    risk_reasons    = asset.get("risk_reasons", []),
                    jarm_hash       = asset.get("jarm_hash"),
                    telemetry       = asset.get("telemetry", {}),
                ))

                for vuln in asset.get("vulnerabilities", []):
                    description = f"[{vuln.get('cve', 'N/A')}] {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}"
                    exists = db.query(models.SecurityEvent).filter(
                        models.SecurityEvent.ip_address == ip,
                        models.SecurityEvent.description == description
                    ).first()
                    if not exists:
                        db.add(models.SecurityEvent(
                            ip_address  = ip,
                            event_type  = "VULN_DETECTED",
                            severity    = vuln.get("severity", "INFO"),
                            description = description,
                        ))

                drift_events = baseline_engine.detect_drift(asset, db)
                for drift in drift_events:
                    db.add(models.SecurityEvent(
                        ip_address  = ip,
                        event_type  = drift["event_type"],
                        severity    = drift["severity"],
                        description = drift["description"],
                    ))

                baseline_engine.snapshot(asset, db)

                if asset.get("risk_score", 0) >= 60:
                    try:
                        self.alerter.send_critical_alert(ip, asset.get("vulnerabilities", []))
                    except Exception as exc:
                        pass

            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error(f"[{self.session_id}] Persist failed: {exc}", exc_info=True)
        finally:
            db.close()
