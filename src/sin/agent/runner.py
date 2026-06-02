"""
sin.agent.runner
"""
from __future__ import annotations
import os, uuid, json, concurrent.futures
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
_DRY_RUN = False
_CONFIDENCE_THRESHOLD = float(os.getenv("SIN_CONFIDENCE_THRESHOLD", "0.80"))
_STRICT_IOT_PORTS = {554, 8554, 37777, 34567, 1883, 8883, 5683, 47808, 502, 4840}
_STRICT_CAMERA_PORTS = {554, 8554, 37777, 34567}
_IOT_VENDORS = {"xiongmai","h264dvr","hikvision","dahua","axis","reolink","amcrest","uniview","hanwha","vivotek"}
_MANAGED_OS = {"windows","ubuntu","debian","centos","fedora","macos","proxmox","linux kernel"}
_NON_IOT_HOSTNAME_TOKENS = {"desktop-","laptop-","workstation","thinkpad","macbook","surface","pc-","win-"}
_WINDOWS_PC_MAC_OUIS = {"d4:5d:64","b8:ca:3a","f0:1f:af","3c:d9:2b","00:50:56","00:0c:29"}
_CAMERA_BANNER_TOKENS = {"rtsp","onvif","h264dvr","ip camera","network camera","camera login","hikvision","dahua","xiongmai","axis","vivotek","reolink","amcrest","uniview"}
_CAMERA_MAC_OUIS = {"00:40:8c","44:19:b6","bc:ad:28","ac:cc:8e","ec:71:db"}
_DANGEROUS_PORTS = {554:"Unauthenticated RTSP Stream",23:"Telnet Exposed",21:"FTP Cleartext",34567:"Sofia DVR Protocol",37777:"Dahua SDK",8000:"Hikvision SDK",1883:"MQTT Exposed",502:"Modbus ICS"}

def _normalise_mac_prefix(raw_mac: str) -> str:
    mac = (raw_mac or "").lower().replace("-", ":")
    parts = [p for p in mac.split(":") if p]
    if len(parts) < 3: return ""
    return ":".join(parts[:3])

def _broadcast_ws(event_type: str, message: str):
    """Publish event to Redis Pub/Sub — picked up by ws_manager fan-out."""
    try:
        from sin.api.ws_manager import publish_event
        msg = json.loads(message) if isinstance(message, str) else message
        publish_event(event_type, msg)
    except Exception as e:
        logger.debug(f"WS broadcast failed: {e}")

def _policy_enabled(policy_name: str, default: bool = False) -> bool:
    try:
        import redis
        r = redis.Redis(host=os.getenv("SIN_REDIS_HOST","redis"), port=int(os.getenv("SIN_REDIS_PORT","6379")), password=os.getenv("SIN_REDIS_PASSWORD",""), decode_responses=True, socket_connect_timeout=2)
        raw = r.get("sin:policies")
        if not raw: return default
        return bool(json.loads(raw).get(policy_name, default))
    except Exception:
        return default

def _is_iot(asset: Dict, whitelisted_macs: set) -> bool:
    mac = str(asset.get("mac_address","")).lower()
    if mac in whitelisted_macs: return False
    ports = {int(p) for p in asset.get("open_ports",[]) if str(p).isdigit()}
    mfr = (asset.get("manufacturer") or asset.get("vendor") or "").lower()
    banners = f"{asset.get('banner_blob','')} {str(asset.get('banners',{}) or {})}".lower()
    os_hint = str(asset.get("os_family","")).lower()
    hostname = str(asset.get("hostname","")).lower()
    device_type = str(asset.get("device_type","")).lower()
    mac_oui = _normalise_mac_prefix(mac)
    if any(t in hostname for t in _NON_IOT_HOSTNAME_TOKENS): return False
    if any(h in os_hint for h in _MANAGED_OS) and "embedded" not in os_hint: return False
    if device_type in {"desktop","laptop","workstation","server"}: return False
    if _normalise_mac_prefix(mac) in _WINDOWS_PC_MAC_OUIS: return False
    has_strict_iot_port = bool(_STRICT_IOT_PORTS.intersection(ports))
    has_camera_port = bool(_STRICT_CAMERA_PORTS.intersection(ports))
    has_camera_vendor = any(v in mfr or v in banners for v in _IOT_VENDORS)
    has_camera_banner = any(t in banners for t in _CAMERA_BANNER_TOKENS)
    has_camera_oui = mac_oui in _CAMERA_MAC_OUIS
    has_iot_type = any(t in device_type for t in {"camera","iot","nvr","dvr"})
    if has_camera_banner and has_camera_port: return True
    if has_camera_vendor and (has_camera_port or has_strict_iot_port): return True
    if has_camera_oui and (has_camera_port or has_strict_iot_port): return True
    if has_iot_type and (has_camera_port or has_strict_iot_port): return True
    return False

class AgentRunner:
    def __init__(self):
        self.discovery = NetworkDiscovery()
        self.auditor = AuditEngine()
        self.decision = DecisionEngine()
        self.mitigation = MitigationEngine(dry_run=False)
        self.alerter = DiscordAlerter()
        self.session_id = str(uuid.uuid4())
        logger.info(f"AgentRunner init | session={self.session_id}")

    def _get_whitelisted_macs(self) -> set:
        db = SessionLocal()
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
            _broadcast_ws("SCAN_COMPLETE", "Network discovery disabled by policy.")
            return []
        logger.info(f"[{self.session_id}] Assessment started | target={subnet}.0/24")
        _broadcast_ws("SCAN_START", f"Active discovery initiated on {subnet}.0/24")
        start_time = datetime.now(timezone.utc)
        whitelisted_macs = self._get_whitelisted_macs()
        raw_assets = self.discovery.execute_subnet_scan(subnet)
        iot_assets = [a for a in raw_assets if _is_iot(a, whitelisted_macs)]
        total_assets = len(iot_assets)
        _broadcast_ws("SCAN_PROGRESS", json.dumps({"current": 0, "total": total_assets}))
        enriched: List[Dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            future_to_asset = {executor.submit(self._process_asset, asset): asset for asset in iot_assets}
            for idx, future in enumerate(concurrent.futures.as_completed(future_to_asset)):
                try:
                    enriched.append(future.result())
                    _broadcast_ws("SCAN_PROGRESS", json.dumps({"current": idx+1, "total": total_assets}))
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

        # ── Stage 0: MAC + OUI resolution ────────────────────────────────────
        # Runs first so audit engine has accurate vendor/MAC context
        try:
            from sin.scanner.mac_resolver import MACResolver
            mac_data = MACResolver().resolve(ip)
            if mac_data.get("mac_address") and mac_data["mac_address"] != "Unknown":
                if not asset.get("mac_address") or asset["mac_address"] in ("Unknown", "", None):
                    asset["mac_address"] = mac_data["mac_address"]
            # OUI vendor enriches manufacturer when Go sensor missed it
            if mac_data.get("vendor") and mac_data["vendor"] != "Unknown":
                if not asset.get("manufacturer") or asset["manufacturer"] in ("Unknown", "", None):
                    asset["manufacturer"] = mac_data["vendor"]
                    asset["vendor"] = mac_data["vendor"]
        except Exception as exc:
            logger.debug(f"[runner] MAC resolve failed {ip}: {exc}")

        # ── Stage 0b: SNMP telemetry (port 161 if open, or try anyway) ──────
        # Provides: sysDescr, sysName, uptime, CPU%, storage — zero auth needed
        try:
            from sin.scanner.snmp_telemetry import SNMPTelemetryProber
            snmp_data = SNMPTelemetryProber().probe(ip, asset.get("open_ports", []))
            if snmp_data:
                asset["snmp_telemetry"] = snmp_data
                # Enrich hostname if SNMP has it and we don't
                if snmp_data.get("hostname") and asset.get("hostname") in (None, "Unknown", ""):
                    asset["hostname"] = snmp_data["hostname"]
                # Enrich description / OS hint
                if snmp_data.get("description"):
                    asset.setdefault("snmp_description", snmp_data["description"])
                logger.info(
                    f"[runner] SNMP {ip} → "
                    f"host={snmp_data.get('hostname','?')} "
                    f"cpu={snmp_data.get('cpu_percent','?')}% "
                    f"uptime={snmp_data.get('uptime_human','?')}"
                )
        except Exception as exc:
            logger.debug(f"[runner] SNMP probe failed {ip}: {exc}")

        # ── AuditEngine: evidence-based findings + calibrated score ───────────
        vulns, audit_score, _audit_action = self.auditor.evaluate_asset(asset)
        asset["vulnerabilities"] = vulns
        asset = normalize_host(asset)

        vendor = asset.get("manufacturer") or asset.get("vendor") or "Unknown"
        ports  = asset.get("open_ports", [])
        _broadcast_ws("FLOW_NEW", {"src": ip, "dst": "192.168.30.1", "proto": "TCP"})
        for port, label in _DANGEROUS_PORTS.items():
            if port in set(ports):
                _broadcast_ws("TRAFFIC_ALERT", {"anomaly": f"{ip} [{vendor}] — {label} (:{port})"})

        # ── DecisionEngine: device-type damper + packet signal enrichment ─────
        # We do NOT use verdict.confidence as the final score — that path
        # accumulates +0.80 per CRITICAL finding additively and always hits 100.
        # Instead, AuditEngine's score is authoritative; DecisionEngine's
        # confidence damper (device-type adjustment) is applied on top.
        verdict: ThreatVerdict = self.decision.evaluate(asset)
        device_type = asset.get("device_type", "unknown")
        damper = {
            "router": 1.0, "camera": 1.0, "nvr_dvr": 1.0,
            "iot": 0.95, "workstation": 0.70, "server": 0.60,
            "printer": 0.80, "unknown": 0.85,
        }.get(device_type, 0.85)

        final_score = min(int(round(audit_score * damper)), 99)

        # Severity from the AuditEngine risk_level (already set on asset by evaluate_asset)
        risk_level = asset.get("risk_level") or verdict.severity

        asset["risk_score"]   = final_score
        asset["risk_level"]   = risk_level
        asset["risk_reasons"] = verdict.reasons
        asset["verdict"]      = {
            "score":      round(audit_score / 100, 4),
            "confidence": round(final_score  / 100, 4),
            "severity":   risk_level,
            "action":     verdict.recommended_action,
            "signals":    verdict.signal_count,
        }
        # ── Quarantine gate — THREE conditions must ALL be true ──────────────
        # 1. SIN_AUTO_QUARANTINE env var must be "true" (default: false for safety)
        # 2. Redis policy auto_quarantine_critical must be enabled
        # 3. DecisionEngine verdict must be actionable at threshold
        # This triple-gate prevents cameras from being isolated during testing
        # or when the operator has disabled auto-response.
        _env_quarantine    = os.getenv("SIN_AUTO_QUARANTINE", "false").lower() == "true"
        auto_quarantine_critical = _policy_enabled("auto_quarantine_critical", False)
        force_auto_quarantine = (
            _env_quarantine and
            auto_quarantine_critical and
            asset.get("risk_score", 0) > 90
        )
        if _env_quarantine and (verdict.is_actionable(_CONFIDENCE_THRESHOLD) or force_auto_quarantine):
            try:
                result = self.mitigation.isolate(asset, verdict)
                asset["mitigation_rule_id"] = result.rule_id
                asset["mitigation_action"] = result.action_type
                _broadcast_ws("MITIGATION", f"Quarantined {ip} ({verdict.severity} Risk)")
            except Exception as exc:
                logger.error(f"[MITIGATE] Failed for {ip}: {exc}", exc_info=True)
                asset["mitigation_rule_id"] = None
                asset["mitigation_action"] = "error"
        else:
            asset["mitigation_rule_id"] = None
            asset["mitigation_action"] = "none"
        return asset

    def _persist(self, subnet: str, start: datetime, end: datetime, assets: List[Dict]) -> None:
        db = SessionLocal()
        try:
            session_row = models.ScanSession(session_uuid=self.session_id, subnet_target=subnet, start_time=start, end_time=end)
            db.add(session_row)
            db.flush()
            for asset in assets:
                ip = asset.get("ip_address", "")
                # Merge SNMP telemetry into the telemetry JSON field
                telemetry = {**(asset.get("telemetry") or {}), **(asset.get("snmp_telemetry") or {})}
                db.add(models.DeviceLog(scan_id=session_row.id, ip_address=ip, hostname=asset.get("hostname"), status="online", vendor=asset.get("manufacturer") or asset.get("vendor"), os_family=asset.get("os_family"), open_ports=asset.get("open_ports",[]), protocols=list(asset.get("services",{}).values()), vulnerabilities=asset.get("vulnerabilities",[]), mac_address=asset.get("mac_address"), device_type=asset.get("device_type"), firmware=asset.get("firmware"), serial_number=asset.get("serial") or asset.get("serial_number"), model=asset.get("model"), risk_score=asset.get("risk_score",0), risk_level=asset.get("risk_level","UNKNOWN"), risk_reasons=asset.get("risk_reasons",[]), jarm_hash=asset.get("jarm_hash"), telemetry=telemetry))
                for vuln in asset.get("vulnerabilities", []):
                    description = f"[{vuln.get('cve','N/A')}] {vuln.get('type','Unknown')}: {vuln.get('description','')}"
                    exists = db.query(models.SecurityEvent).filter(models.SecurityEvent.ip_address == ip, models.SecurityEvent.description == description).first()
                    if not exists:
                        db.add(models.SecurityEvent(ip_address=ip, event_type="VULN_DETECTED", severity=vuln.get("severity","INFO"), description=description))
                drift_events = baseline_engine.detect_drift(asset, db)
                for drift in drift_events:
                    db.add(models.SecurityEvent(ip_address=ip, event_type=drift["event_type"], severity=drift["severity"], description=drift["description"]))
                baseline_engine.snapshot(asset, db)
                if asset.get("risk_score", 0) >= 60:
                    try:
                        self.alerter.send_critical_alert(ip, asset.get("vulnerabilities", []))
                    except Exception as exc:
                        logger.error(f"[ALERT] Discord notification failed for {ip}: {exc}")
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error(f"[{self.session_id}] Persist failed: {exc}", exc_info=True)
        finally:
            db.close()
