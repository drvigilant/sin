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
from sin.agent.runner import AgentRunner
from sin.agent.core import SINAgent
from sin.agent.packet import PacketSniffer
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.api.server")

# ── API key auth configuration ──
_API_KEY        = os.getenv("SIN_API_KEY", "")
_AUTH_EXEMPT    = {"/health", "/api/health"}

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
                r.setex(_SCAN_REDIS_KEY, 3600, "1")
            else:
                r.delete(_SCAN_REDIS_KEY)
        except Exception:
            pass

app = FastAPI(title="SIN Enterprise API")

# ── Global Agent Instance ──
_sin_agent = None
_packet_sniffer: PacketSniffer | None = None

@app.on_event("startup")
async def startup_event():
    global _sin_agent, _packet_sniffer
    _sin_agent = SINAgent()
    _packet_sniffer = PacketSniffer()
    _packet_sniffer.start()
    logger.info("SIN Agent initialized in API context.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT:
        return await call_next(request)

    if _API_KEY:
        provided = request.headers.get("X-API-Key", "")
        if provided != _API_KEY:
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

class ScanRequest(BaseModel):
    subnet: Optional[str] = None

class OllamaAuditRequest(BaseModel):
    ip_address: str
    open_ports: list
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
    _set_scan_running(True)
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
    except Exception as e:
        logger.error(f"Background scan crashed: {e}")
    finally:
        _set_scan_running(False)

@app.get("/health")
def health_check():
    return {"status": "online", "api": "SIN Enterprise"}

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
        })
    return devices

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    rows = db.query(models.SecurityEvent).order_by(models.SecurityEvent.timestamp.desc()).limit(200).all()
    return [{"ip_address": e.ip_address, "event_type": e.event_type, "severity": e.severity, "description": e.description, "timestamp": e.timestamp.isoformat() if e.timestamp else ""} for e in rows]


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
async def ollama_audit(request: OllamaAuditRequest):
    prompt = f"""You are an expert IoT security analyst.
Analyse this network device and identify vulnerabilities, misconfigurations, or security risks.
Be concise and specific. Return ONLY a JSON array of findings, no other text.

Device:
- IP: {request.ip_address}
- Open Ports: {request.open_ports}
- Vendor: {request.vendor or 'Unknown'}
- OS: {request.os_family or 'Unknown'}
- Existing Findings: {json.dumps(request.vulnerabilities)}

Return format (JSON array only, no markdown):
[{{"severity": "HIGH|MEDIUM|LOW", "type": "category", "description": "finding"}}]"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"}
            )
            if resp.status_code != 200:
                return {"error": f"Ollama returned {resp.status_code}", "findings": []}
            
            raw = resp.json().get("response", "[]").strip()
            
            # CRITICAL FIX: Generate backticks dynamically to prevent copy-paste terminal breaks
            md_marker = "`" * 3
            if raw.startswith(md_marker):
                raw = raw.split(md_marker)[1]
                if raw.startswith("json"): 
                    raw = raw[4:]
            
            findings = json.loads(raw)
            return {"findings": findings if isinstance(findings, list) else [], "model": OLLAMA_MODEL}
    except Exception:
        return {"error": "Ollama not reachable. Setup Ollama to enable AI insights.", "findings": [], "model": OLLAMA_MODEL}

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
    if _sin_agent is None:
        return {"running": False, "note": "SINAgent not started"}
    return {"running": True}

@app.post("/agent/isolate/{ip}")
def isolate_device(ip: str, db: Session = Depends(get_db)):
    if _sin_agent is None:
        raise HTTPException(503, "Agent not running")

    device = db.query(models.DeviceLog).filter(models.DeviceLog.ip_address == ip).first()
    if not device:
        raise HTTPException(404, "Device not found in registry")

    from sin.agent.decision import ThreatVerdict
    verdict = ThreatVerdict(severity="CRITICAL", confidence=1.0, recommended_action="isolate")

    result = _sin_agent.mitigation.isolate({"ip_address": ip, "mac_address": device.mac_address or "unknown"}, verdict)
    _sin_agent.registry.mark_mitigated(ip)

    return {"status": "isolated", "ip": ip, "details": result.details}

@app.post("/agent/whitelist/{ip}")
def whitelist_device(ip: str):
    if _sin_agent is None: raise HTTPException(503, "Agent not running")
    _sin_agent.whitelist_device(ip)
    return {"status": "whitelisted", "ip": ip}

@app.post("/agent/lift/{ip}")
def lift_isolation(ip: str):
    if _sin_agent is None: raise HTTPException(503, "Agent not running")
    return _sin_agent.lift_isolation(ip)

@app.get("/agent/mitigations")
def list_mitigations():
    return [] if _sin_agent is None else _sin_agent.mitigation.list_active()

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    
    r = aioredis.Redis(
        host=os.getenv("SIN_REDIS_HOST", "redis"),
        port=int(os.getenv("SIN_REDIS_PORT", "6379")),
        password=os.getenv("SIN_REDIS_PASSWORD", ""),
        decode_responses=True
    )
    pubsub = r.pubsub()
    await pubsub.subscribe("sin:ws:stream")
    
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message:
                await websocket.send_json(json.loads(message["data"]))
            await asyncio.sleep(0.2)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await pubsub.unsubscribe("sin:ws:stream")
        await r.close()
