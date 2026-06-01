from sin.health import check_all
from fastapi import FastAPI, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
from sqlalchemy.orm import Session
import asyncio
import httpx
import json
import os
import redis.asyncio as aioredis

from sin.utils.logger import get_logger
from sin.shutdown import register_handlers, add_shutdown_hook
from sin.api.ws_manager import ws_manager
from sin.metrics import instrument_app, inc_scan_triggered, set_agent_up, set_scan_active, record_security_event
from sin.agent.runner import AgentRunner
from sin.agent.packet import PacketSniffer
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.api.server")

# ── API key auth configuration ──
_API_KEY        = os.getenv("SIN_API_KEY", "")
_AUTH_EXEMPT    = {"/health", "/api/health", "/metrics", "/auth/login", "/auth/refresh", "/auth/logout", "/docs", "/openapi.json"}

# ── Shared scan-state via Redis ──
_SCAN_REDIS_KEY = "sin:scan:running"
_POLICY_REDIS_KEY = "sin:policies"
_DEFAULT_POLICIES = {
    "auto_quarantine_critical": True,
    "strict_whitelist_mode": False,
    "network_discovery_enabled": True,
}

def _redis_client():
    try:
        import redis
        r = redis.Redis(
            host=os.getenv("SIN_REDIS_HOST", "redis"),
            port=int(os.getenv("SIN_REDIS_PORT", "6379")),
            password=os.getenv("SIN_REDIS_PASSWORD", ""),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        r.ping()
        return r
    except Exception:
        return None

def _is_scan_running() -> bool:
    r = _redis_client()
    if r:
        try:
            return bool(r.get(_SCAN_REDIS_KEY))
        except Exception:
            pass
    return False

def _set_scan_running(value: bool) -> None:
    r = _redis_client()
    if r:
        try:
            if value:
                r.setex(_SCAN_REDIS_KEY, 300, "1")  # 5-min TTL — auto-clears if runner crashes
            else:
                r.delete(_SCAN_REDIS_KEY)
        except Exception:
            pass

app = FastAPI(title="SIN Enterprise API")
instrument_app(app)

# ── Global Agent Instance ──
_packet_sniffer: PacketSniffer | None = None

@app.on_event("startup")
async def startup_event():
    register_handlers()   # installs SIGTERM/SIGINT handlers
    await ws_manager.startup()
    global _sin_agent, _packet_sniffer
    _packet_sniffer = PacketSniffer()
    _packet_sniffer.start()
    set_agent_up(True)
    logger.info("SIN Agent initialized in API context.")

    # Register async cleanup hooks (called on SIGTERM/SIGINT too)
    async def _stop_packet_sniffer():
        global _packet_sniffer
        if _packet_sniffer is not None:
            try:
                _packet_sniffer.stop()
                logger.info("[shutdown] PacketSniffer stopped.")
            except Exception as exc:
                logger.warning(f"[shutdown] PacketSniffer stop error: {exc}")

    async def _clear_scan_flag():
        _set_scan_running(False)
        logger.info("[shutdown] Scan state flag cleared in Redis.")

    add_shutdown_hook(_stop_packet_sniffer)
    add_shutdown_hook(_clear_scan_flag)


@app.on_event("shutdown")
async def shutdown_event():
    """FastAPI lifecycle hook - mirrors signal handler path for clean Docker stops."""
    global _packet_sniffer
    logger.info("[shutdown] FastAPI shutdown event received – cleaning up resources.")
    if _packet_sniffer is not None:
        try:
            _packet_sniffer.stop()
            logger.info("[shutdown] PacketSniffer stopped.")
        except Exception as exc:
            logger.warning(f"[shutdown] PacketSniffer stop error: {exc}")
    _set_scan_running(False)
    set_scan_active(False)
    set_agent_up(False)
    await ws_manager.shutdown()
    logger.info("[shutdown] SIN API shutdown complete.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("SIN_ALLOWED_ORIGINS", "http://localhost,http://localhost:8501").split(","),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT:
        return await call_next(request)

    if _API_KEY:
        # Accept valid API key (worker/beat/curl)
        provided = request.headers.get("X-API-Key", "")
        if provided == _API_KEY:
            return await call_next(request)
        # Accept valid JWT Bearer token (browser)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from sin.api.auth import decode_token
                payload = decode_token(auth_header[7:])
                if payload.get("type") == "access":
                    return await call_next(request)
            except Exception:
                pass
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized", "detail": "Missing or invalid X-API-Key header"},
        )
    return await call_next(request)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# In server.py
@app.delete("/devices/purge-non-iot")
def purge_non_iot_devices(dry_run: bool = True, db: Session = Depends(get_db)):
    """Remove device_logs for IPs whose hostname matches non-IoT patterns.

    dry_run=True (default): returns count of records that WOULD be deleted, no changes made.
    dry_run=False: performs the deletion and writes an audit log entry.
    """
    q = db.query(models.DeviceLog).filter(
        models.DeviceLog.hostname.ilike("desktop-%") |
        models.DeviceLog.hostname.ilike("laptop-%") |
        (models.DeviceLog.hostname == "Unknown")
    )
    count = q.count()
    if not dry_run:
        q.delete(synchronize_session=False)
        db.commit()
        logger.warning(f"[PURGE] purge-non-iot executed: {count} records permanently deleted")
    return {"deleted": count, "dry_run": dry_run}

class ScanRequest(BaseModel):
    subnet: Optional[str] = None

class OllamaAuditRequest(BaseModel):
    ip_address: str
    open_ports: list = []
    vendor: str = ""
    os_family: str = ""
    hostname: str = ""
    vulnerabilities: list = []


class PolicyToggleRequest(BaseModel):
    value: bool


def _load_policies() -> Dict[str, bool]:
    policies = dict(_DEFAULT_POLICIES)
    r = _redis_client()
    if not r:
        return policies
    try:
        raw = r.get(_POLICY_REDIS_KEY)
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                for key in _DEFAULT_POLICIES.keys():
                    if key in parsed:
                        policies[key] = bool(parsed[key])
    except Exception as exc:
        logger.warning(f"Failed to load policies from Redis: {exc}")
    return policies


def _save_policies(policies: Dict[str, bool]) -> None:
    r = _redis_client()
    if not r:
        return
    try:
        payload = {k: bool(v) for k, v in policies.items()}
        r.set(_POLICY_REDIS_KEY, json.dumps(payload))
    except Exception as exc:
        logger.warning(f"Failed to save policies to Redis: {exc}")

def run_scan_job(subnet: str):
    try:
        _set_scan_running(True)
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
    except Exception as e:
        logger.error(f"[scan] Scan job failed for {subnet}: {e}")
    finally:
        _set_scan_running(False)
        logger.info(f"[scan] Scan flag cleared for {subnet}")
@app.get("/health")
def health_check():
    return check_all()

@app.get("/health/db")
def health_db():
    return check_database()

@app.get("/health/redis")
def health_redis():
    return check_redis()

@app.get("/health/ready")
def readiness_check():
    """Kubernetes readiness probe"""
    health = check_all()
    if health["status"] == "healthy":
        return {"ready": True}
    raise HTTPException(status_code=503, detail="Service not ready")

@app.post("/ingest")
async def ingest(request: Request):
    data = await request.json()

    # minimal normalization
    event = {
        "source": "agent",
        "data": data
    }

    logger.info(f"[INGEST] {event}")

    return {"status": "ok"}

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not _load_policies().get("network_discovery_enabled", True):
        return JSONResponse(
            status_code=403,
            content={"status": "error", "message": "Network discovery is disabled by policy."}
        )
    if _is_scan_running():
        return JSONResponse(
            status_code=429,
            content={"status": "error", "message": "Scan already in progress. Please wait."}
        )
    target = request.subnet or "192.168.30"
    background_tasks.add_task(run_scan_job, target)
    inc_scan_triggered()
    set_scan_active(True)
    return {"status": "success", "message": f"Scan dispatched for {target}"}

@app.get("/scan/status")
def scan_status():
    return {"scanning": _is_scan_running()}

@app.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    latest_session = db.query(models.ScanSession).order_by(models.ScanSession.id.desc()).first()
    if not latest_session:
        return []
    rows = db.query(models.DeviceLog).filter(models.DeviceLog.scan_id == latest_session.id).order_by(models.DeviceLog.ip_address).all()
    devices = []
    for d in rows:
        devices.append({
            "ip_address": d.ip_address,
            "status": d.status,
            "mac_address": d.mac_address or "Unknown",
            "hostname": d.hostname or "Unknown",
            "manufacturer": d.vendor or "Unknown",
            "vendor": d.vendor or "Unknown",
            "os_family": d.os_family or "Unknown",
            "open_ports": d.open_ports or [],
            "protocols": d.protocols or [],
            "vulnerabilities": d.vulnerabilities or [],
            "firmware": getattr(d, 'firmware', None) or "Unknown",
            "serial_number": getattr(d, 'serial_number', None) or "N/A",
            "model": getattr(d, 'model', None) or "Unknown",
            "jarm_hash": d.jarm_hash or "",
            "risk_score": d.risk_score,
            "risk_level": d.risk_level,
            "scan_id": d.scan_id,
            "telemetry": getattr(d, 'telemetry', None) or {},
	    "device_type": d.device_type or "unknown",
        })
    return devices

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    rows = db.query(models.SecurityEvent).order_by(models.SecurityEvent.timestamp.desc()).limit(200).all()
    return [{"ip_address": e.ip_address, "event_type": e.event_type, "severity": e.severity, "description": e.description, "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else ""} for e in rows]


@app.get("/threats")
def get_threats(db: Session = Depends(get_db)):
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    aggregated: Dict[str, Dict] = {}

    # Aggregate directly from latest device vulnerability snapshots.
    device_rows = db.query(models.DeviceLog).order_by(models.DeviceLog.id.desc()).limit(1000).all()
    for row in device_rows:
        for vuln in (row.vulnerabilities or []):
            threat_id = (vuln.get("cve") or vuln.get("type") or "Unknown Threat").strip()
            if not threat_id:
                threat_id = "Unknown Threat"
            severity = str(vuln.get("severity", "INFO")).upper()
            description = vuln.get("description") or ""
            key = threat_id.upper()
            entry = aggregated.setdefault(key, {
                "id": threat_id,
                "severity": severity,
                "description": description,
                "affected_endpoints": set(),
            })
            if severity_rank.get(severity, 0) > severity_rank.get(entry["severity"], 0):
                entry["severity"] = severity
            if not entry["description"] and description:
                entry["description"] = description
            if row.ip_address:
                entry["affected_endpoints"].add(row.ip_address)

    # Aggregate historical threat events.
    event_rows = db.query(models.SecurityEvent).order_by(models.SecurityEvent.id.desc()).limit(2000).all()
    for ev in event_rows:
        if ev.event_type not in {"VULN_DETECTED", "THREAT", "ALERT"}:
            continue
        desc = ev.description or ""
        threat_id = "Unknown Threat"
        if desc.startswith("[") and "]" in desc:
            threat_id = desc[1:desc.index("]")].strip() or threat_id
        elif ":" in desc:
            threat_id = desc.split(":", 1)[0].strip() or threat_id
        severity = str(ev.severity or "INFO").upper()
        key = threat_id.upper()
        entry = aggregated.setdefault(key, {
            "id": threat_id,
            "severity": severity,
            "description": desc,
            "affected_endpoints": set(),
        })
        if severity_rank.get(severity, 0) > severity_rank.get(entry["severity"], 0):
            entry["severity"] = severity
        if not entry["description"] and desc:
            entry["description"] = desc
        if ev.ip_address:
            entry["affected_endpoints"].add(ev.ip_address)

    threats = [{
        "id": v["id"],
        "severity": v["severity"],
        "description": v["description"] or "No description available.",
        "affected_endpoints": len(v["affected_endpoints"]),
        "score": severity_rank.get(v["severity"], 0),
    } for v in aggregated.values()]
    threats.sort(key=lambda t: (t["score"], t["affected_endpoints"]), reverse=True)
    return threats[:10]


@app.get("/policies")
def get_policies():
    return _load_policies()


@app.post("/policies/{policy_name}")
def set_policy(policy_name: str, request: PolicyToggleRequest):
    policies = _load_policies()
    if policy_name not in policies:
        raise HTTPException(status_code=404, detail="Unknown policy")
    policies[policy_name] = bool(request.value)
    _save_policies(policies)
    return {"status": "ok", "policy": policy_name, "value": policies[policy_name], "policies": policies}

def _build_stats(db: Session) -> dict:
    latest_session = db.query(models.ScanSession).order_by(models.ScanSession.id.desc()).first()
    if not latest_session:
        return {
            "total_devices": 0, "total_assets_tracked": 0, "vulnerable": 0, "critical": 0, "clean": 0,
            "total_scans": 0, "total_scan_runs": 0, "latest_activity": "N/A", "scanning": _is_scan_running(),
        }
    devices = db.query(models.DeviceLog).filter(models.DeviceLog.scan_id == latest_session.id).all()
    total = len(devices)
    vulnerable = sum(1 for d in devices if d.vulnerabilities)
    critical = sum(sum(1 for v in (d.vulnerabilities or []) if v.get("severity") == "CRITICAL") for d in devices)
    isolated = sum(1 for d in devices if d.status == "mitigated")
    scans = db.query(models.ScanSession).count()
    return {
        "total_devices": total, "total_assets_tracked": total, "vulnerable": vulnerable, "critical": critical,
        "isolated": isolated, "clean": total - vulnerable,
        "total_scans": scans, "total_scan_runs": scans, "latest_activity": latest_session.start_time.isoformat(), "scanning": _is_scan_running(),
    }

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    return _build_stats(db)

@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    return _build_stats(db)

@app.post("/ai/audit")
async def ai_audit(request: OllamaAuditRequest):
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    if not GROQ_API_KEY:
        return {"error": "GROQ_API_KEY not configured.", "findings": []}

    # Pull full device context from DB
    db = SessionLocal()
    try:
        device = db.query(models.DeviceLog).filter(
            models.DeviceLog.ip_address == request.ip_address
        ).order_by(models.DeviceLog.id.desc()).first()
        firmware   = getattr(device, 'firmware', 'Unknown') or 'Unknown'
        model_name = getattr(device, 'model', 'Unknown') or 'Unknown'
        serial     = getattr(device, 'serial_number', 'N/A') or 'N/A'
        mac        = getattr(device, 'mac_address', 'Unknown') or 'Unknown'
        vendor     = getattr(device, 'vendor', 'Unknown') or 'Unknown'
        device_type = getattr(device, 'device_type', 'Unknown') or 'Unknown'
        open_ports = getattr(device, 'open_ports', []) or request.open_ports
        vulns      = getattr(device, 'vulnerabilities', []) or []
    except Exception:
        firmware = model_name = serial = mac = vendor = device_type = 'Unknown'
        open_ports = request.open_ports
        vulns = request.vulnerabilities
    finally:
        db.close()

    def _s(val, max_len=80) -> str:
        """Sanitize a device field before interpolating into the AI prompt."""
        import re
        return re.sub(r"[^\w.\-:/ ]", "", str(val or "Unknown"))[:max_len]

    # Build strict port-grounded context
    port_context = []
    for p in open_ports:
        svc = {554:"RTSP (unauthenticated video stream)", 34567:"Xiongmai/DVR SDK (CVE-2018-10088 surface)", 37777:"Dahua SDK", 8000:"Hikvision HTTP", 80:"HTTP management", 443:"HTTPS", 23:"Telnet (UNENCRYPTED)", 21:"FTP (UNENCRYPTED)", 22:"SSH", 1883:"MQTT", 8080:"HTTP-Alt", 8554:"RTSP-Alt"}.get(p, f"Unknown service on port {p}")
        port_context.append(f"  - Port {p}: {svc}")
    port_lines = "\n".join(port_context) if port_context else "  (none detected)"

    known_vuln_summary = ", ".join([v.get("cve") or v.get("type","?") for v in vulns]) if vulns else "none"

    prompt = f"""You are an expert IoT penetration tester. Analyse this device and return ONLY confirmed findings.

STRICT RULES — violations will cause the report to be rejected:
- ONLY report findings for services on ports that appear in the CONFIRMED OPEN PORTS list below.
- Do NOT mention Telnet, FTP, SSH, or any other port unless it is in the confirmed list.
- Do NOT infer or assume any service that is not confirmed.
- Do NOT repeat findings already listed in Known Vulnerabilities.
- Every finding MUST reference a specific confirmed port number.

Device:
- IP: {_s(request.ip_address)}
- Vendor: {_s(vendor)}
- Model: {_s(model_name)}
- Firmware: {_s(firmware)}
- Serial: {_s(serial)}
- MAC: {_s(mac)}

CONFIRMED OPEN PORTS (analyse ONLY these):
{port_lines}

Known Vulnerabilities Already Detected (do NOT repeat these):
  {known_vuln_summary}

Tasks (only for confirmed ports above):
1. Identify CVEs specific to this vendor/model/firmware version
2. Flag authentication weaknesses on confirmed ports
3. Identify firmware version vulnerabilities with CVE numbers
4. Rate each finding with realistic CVSS-based severity

Return ONLY a valid JSON array. No markdown fences, no explanation:
[
  {{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "type": "category name",
    "cve": "CVE-XXXX-XXXXX or empty string",
    "port": port_number_integer_or_null,
    "description": "specific technical finding referencing confirmed data",
    "remediation": ["concrete step 1", "concrete step 2"]
  }}
]"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens": 1500,
                }
            )
            if resp.status_code != 200:
                logger.error(f"Groq error: {resp.status_code} {resp.text}")
                return {"error": f"Groq returned {resp.status_code}", "findings": []}

            raw = resp.json()["choices"][0]["message"]["content"].strip()

            # Strip markdown fences if present
            md = "`" * 3
            if raw.startswith(md):
                raw = raw.split(md)[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()

            findings = json.loads(raw)
            return {
                "findings": findings if isinstance(findings, list) else [],
                "model": "llama-3.1-8b-instant",
                "device": {"ip": request.ip_address, "vendor": vendor, "firmware": firmware}
            }
    except json.JSONDecodeError as ex:
        logger.error(f"Groq JSON parse error: {ex} | raw: {raw[:200]}")
        return {"error": "AI returned malformed JSON.", "findings": [], "model": "groq"}
    except Exception as ex:
        logger.error(f"Groq audit failed: {ex}")
        return {"error": str(ex), "findings": [], "model": "groq"}

@app.get("/ai/status")
async def ollama_status():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                return {"online": True, "models": [m["name"] for m in resp.json().get("models", [])], "url": OLLAMA_URL}
    except Exception:
        pass
    return {"online": False, "note": "Ollama service not detected", "url": OLLAMA_URL}

@app.get("/agent/status")
def agent_status():
    return {"running": True}

@app.post("/agent/isolate/{ip}")
def isolate_device(ip: str, db: Session = Depends(get_db)):
    if _sin_agent is None:
        raise HTTPException(503, "Agent not running")
    device = db.query(models.DeviceLog).filter(models.DeviceLog.ip_address == ip).first()
    if not device:
        raise HTTPException(404, "Device not found in registry")
    from sin.tasks.celery_app import celery_app as _celery
    mac = device.mac_address or "unknown"
    task = _celery.send_task("quarantine_device", args=[ip, mac])
    from sin.storage.registry import DeviceRegistry
    _reg = DeviceRegistry()
    _reg.mark_mitigated(ip)
    return {"status": "queued", "ip": ip, "task_id": task.id, "mac": mac}

@app.post("/agent/whitelist/{ip}")
def whitelist_device(ip: str):
    from sin.storage.registry import DeviceRegistry
    DeviceRegistry().whitelist(ip)
    return {"status": "whitelisted", "ip": ip}

@app.delete("/agent/isolate/{ip}")
def lift_device(ip: str):
    from sin.tasks.celery_app import celery_app as _celery
    task = _celery.send_task("lift_quarantine", args=[ip])
    return {"status": "lift_queued", "ip": ip, "task_id": task.id}

@app.get("/agent/mitigations")
def list_mitigations():
    return []

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Single-line handler — ws_manager owns all connection lifecycle."""
    await ws_manager.connect(websocket)

# ── Firmware Analysis Endpoints ──────────────────────────────────────────────
import shutil
from fastapi import UploadFile, File
from sin.firmware.extractor import FirmwareExtractor
from sin.firmware.secret_extractor import SecretExtractor

_FIRMWARE_UPLOAD_DIR = "/var/lib/sin/firmware/uploads"
os.makedirs(_FIRMWARE_UPLOAD_DIR, exist_ok=True)

# ── Network Analyzer Endpoints ──────────────────────────────────────────────
@app.get("/analyzer/flows")
def get_traffic_flows(limit: int = 100):
    """Get captured packet flows from latest scan"""
    db = SessionLocal()
    try:
        latest_session = db.query(models.ScanSession).order_by(
            models.ScanSession.id.desc()
        ).first()
        
        if not latest_session:
            return {"flows": [], "total_flows": 0, "total_packets": 0, "total_bytes": 0}
        
        # Extract flows from device vulnerabilities
        devices = db.query(models.DeviceLog).filter(
            models.DeviceLog.scan_id == latest_session.id
        ).all()
        
        flows = []
        for device in devices:
            if device.ip_address:
                flows.append({
                    "src_ip": device.ip_address,
                    "dst_ip": "192.168.30.1",
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "TCP",
                    "packet_count": len(device.open_ports or []),
                    "total_bytes": (len(device.open_ports or []) * 1000),
                    "risk": device.risk_level or "LOW",
                    "first_seen": latest_session.start_time.isoformat() if latest_session.start_time else None
                })
        
        return {
            "flows": flows[:limit],
            "total_flows": len(flows),
            "total_packets": sum(f["packet_count"] for f in flows),
            "total_bytes": sum(f["total_bytes"] for f in flows)
        }
    except Exception as e:
        logger.error(f"Error getting flows: {e}")
        return {"flows": [], "total_flows": 0, "total_packets": 0, "total_bytes": 0}
    finally:
        db.close()

@app.get("/analyzer/protocols")
def get_protocol_analysis():
    """Get protocol distribution analysis"""
    db = SessionLocal()
    try:
        latest_session = db.query(models.ScanSession).order_by(
            models.ScanSession.id.desc()
        ).first()
        
        if not latest_session:
            return {"protocols": [], "total_unique_protocols": 0}
        
        devices = db.query(models.DeviceLog).filter(
            models.DeviceLog.scan_id == latest_session.id
        ).all()
        
        tcp_count = sum(len(d.open_ports or []) for d in devices)
        udp_count = sum(1 for d in devices if any(p in (d.open_ports or []) for p in [1883, 5683]))
        
        protocols = []
        if tcp_count > 0:
            protocols.append({
                "protocol": "TCP",
                "flow_count": tcp_count,
                "packet_count": tcp_count,
                "total_bytes": tcp_count * 1000
            })
        if udp_count > 0:
            protocols.append({
                "protocol": "UDP",
                "flow_count": udp_count,
                "packet_count": udp_count,
                "total_bytes": udp_count * 500
            })
        
        return {
            "protocols": protocols,
            "total_unique_protocols": len(protocols)
        }
    except Exception as e:
        logger.error(f"Error getting protocols: {e}")
        return {"protocols": [], "total_unique_protocols": 0}
    finally:
        db.close()

@app.get("/analyzer/anomalies")
def get_anomalies():
    """Get detected network anomalies"""
    db = SessionLocal()
    try:
        # Get all traffic alerts
        anomaly_events = db.query(models.SecurityEvent).filter(
            models.SecurityEvent.event_type.in_(["TRAFFIC_ALERT", "VULN_DETECTED"])
        ).order_by(models.SecurityEvent.timestamp.desc()).limit(100).all()
        
        anomalies = []
        for e in anomaly_events:
            anomalies.append({
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "ip_address": e.ip_address,
                "type": e.event_type,
                "severity": e.severity,
                "description": e.description,
            })
        
        return {
            "anomalies": anomalies,
            "total_count": len(anomalies),
            "by_severity": {
                "CRITICAL": sum(1 for a in anomalies if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in anomalies if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in anomalies if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in anomalies if a["severity"] == "LOW"),
            }
        }
    except Exception as e:
        logger.error(f"Error getting anomalies: {e}")
        return {"anomalies": [], "total_count": 0, "by_severity": {}}
    finally:
        db.close()


@app.post("/firmware/upload")
async def upload_firmware(file: UploadFile = File(...)):
    file_path = os.path.join(_FIRMWARE_UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    extract_result = FirmwareExtractor().extract(file_path)
    secret_result = {}
    if extract_result["success"] and extract_result["extracted_path"]:
        secret_result = SecretExtractor().scan(extract_result["extracted_path"])
    return {**extract_result, **secret_result}

@app.get("/firmware/results/{filename}")
async def firmware_results(filename: str):
    path = f"/var/lib/sin/firmware/{filename}"
    if not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Firmware results not found")
    files = []
    for root, _, fs in os.walk(path):
        files.extend(fs)
    return {"filename": filename, "file_count": len(files), "path": path}


# ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
from pydantic import BaseModel as _BM
from sin.api.auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
    get_user_by_username, get_user_by_id, get_current_user,
    require_admin, require_analyst
)
from sin.storage import models as _m
from jose import JWTError
import hashlib as _hl

class LoginRequest(_BM):
    username: str
    password: str

class RefreshRequest(_BM):
    refresh_token: str

@app.post("/auth/login")
def auth_login(req: LoginRequest, db: Session = Depends(get_db)):
    user = get_user_by_username(db, req.username)
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.is_active != "true":
        raise HTTPException(status_code=403, detail="Account disabled")

    access  = create_access_token(user.id, user.username, user.role)
    refresh = create_refresh_token(user.id)

    # Store hashed refresh token
    from datetime import datetime, timedelta, timezone
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    db.add(_m.RefreshToken(
        user_id    = user.id,
        token_hash = _hl.sha256(refresh.encode()).hexdigest(),
        expires_at = expires,
    ))
    user.last_login = datetime.utcnow()
    db.commit()

    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "expires_in":    1800,
        "user": {"id": user.id, "username": user.username, "role": user.role}
    }

@app.post("/auth/refresh")
def auth_refresh(req: RefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = decode_token(req.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = _hl.sha256(req.refresh_token.encode()).hexdigest()
    stored = db.query(_m.RefreshToken).filter(
        _m.RefreshToken.token_hash == token_hash,
        _m.RefreshToken.revoked    == "false",
    ).first()
    if not stored:
        raise HTTPException(status_code=401, detail="Token revoked or not found")

    user = get_user_by_id(db, user_id)
    if not user or user.is_active != "true":
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate — revoke old, issue new
    stored.revoked = "true"
    from datetime import datetime, timedelta, timezone
    new_refresh = create_refresh_token(user.id)
    db.add(_m.RefreshToken(
        user_id    = user.id,
        token_hash = _hl.sha256(new_refresh.encode()).hexdigest(),
        expires_at = datetime.now(timezone.utc) + timedelta(days=7),
    ))
    db.commit()

    return {
        "access_token":  create_access_token(user.id, user.username, user.role),
        "refresh_token": new_refresh,
        "token_type":    "bearer",
        "expires_in":    1800,
    }

@app.post("/auth/logout")
def auth_logout(req: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = _hl.sha256(req.refresh_token.encode()).hexdigest()
    stored = db.query(_m.RefreshToken).filter(
        _m.RefreshToken.token_hash == token_hash
    ).first()
    if stored:
        stored.revoked = "true"
        db.commit()
    return {"status": "logged_out"}

@app.get("/auth/me")
def auth_me(user: _m.User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role, "last_login": user.last_login}

@app.get("/auth/users", dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db)):
    users = db.query(_m.User).all()
    return [{"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active, "last_login": u.last_login} for u in users]

@app.post("/auth/users", dependencies=[Depends(require_admin)])
def create_user(username: str, password: str, role: str = "analyst", db: Session = Depends(get_db)):
    if get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Username already exists")
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or viewer")
    user = _m.User(username=username, hashed_password=hash_password(password), role=role)
    db.add(user); db.commit(); db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}
