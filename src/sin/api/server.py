from fastapi import FastAPI, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
from sqlalchemy.orm import Session
from sqlalchemy import text
from contextlib import asynccontextmanager
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

# ── Global Agent Instance ──
_sin_agent = None
_packet_sniffer: PacketSniffer | None = None

# ── Lifespan Manager (Modern Replacement for on_event) ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    global _sin_agent, _packet_sniffer
    _sin_agent = SINAgent()
    _packet_sniffer = PacketSniffer()
    _packet_sniffer.start()
    logger.info("SIN Agent initialized in API context.")
    
    yield  # Yields control back to FastAPI while running
    
    # Shutdown logic
    logger.info("🚨 SIGTERM received. Initiating graceful shutdown...")
    if _packet_sniffer is not None:
        logger.info("Stopping Packet Sniffer...")
        _packet_sniffer.stop()
    r = _redis_client()
    if r:
        try:
            r.delete(_SCAN_REDIS_KEY)
            logger.info("Cleared scan locks from Redis.")
        except Exception as e:
            logger.error(f"Failed to clear Redis locks during shutdown: {e}")
    logger.info("✅ Graceful shutdown complete. Safe to terminate.")

app = FastAPI(title="SIN Enterprise API", lifespan=lifespan)

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
        provided = request.headers.get("X-API-Key", "")
        if provided != _API_KEY:
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "Missing or invalid X-API-Key header"},
            )
    return await call_next(request)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Hardened Health Endpoint ──
@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    health_status = {
        "api": "online",
        "database": "offline",
        "redis": "offline",
        "agent": "offline"
    }
    status_code = 200

    # 1. Check PostgreSQL
    try:
        db.execute(text("SELECT 1"))
        health_status["database"] = "online"
    except Exception as e:
        logger.error(f"Healthcheck DB failure: {e}")
        status_code = 503

    # 2. Check Redis
    r = _redis_client()
    if r:
        health_status["redis"] = "online"
    else:
        logger.error("Healthcheck Redis failure")
        status_code = 503

    # 3. Check Internal Agent Thread
    if _sin_agent is not None:
        health_status["agent"] = "online"

    health_status["status"] = "healthy" if status_code == 200 else "degraded"

    return JSONResponse(status_code=status_code, content=health_status)

# ── API Endpoints ────────────────────────────────────────────────────────────

@app.delete("/devices/purge-non-iot")
def purge_non_iot_devices(dry_run: bool = True, db: Session = Depends(get_db)):
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
    if not r: return policies
    try:
        raw = r.get(_POLICY_REDIS_KEY)
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                for key in _DEFAULT_POLICIES.keys():
                    if key in parsed: policies[key] = bool(parsed[key])
    except Exception as exc:
        logger.warning(f"Failed to load policies from Redis: {exc}")
    return policies

def _save_policies(policies: Dict[str, bool]) -> None:
    r = _redis_client()
    if not r: return
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

@app.post("/ingest")
async def ingest(request: Request):
    data = await request.json()
    logger.info(f"[INGEST] {data}")
    return {"status": "ok"}

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not _load_policies().get("network_discovery_enabled", True):
        return JSONResponse(status_code=403, content={"status": "error", "message": "Disabled by policy."})
    if _is_scan_running():
        return JSONResponse(status_code=429, content={"status": "error", "message": "Scan in progress."})
    target = request.subnet or "192.168.30"
    background_tasks.add_task(run_scan_job, target)
    return {"status": "success", "message": f"Scan dispatched for {target}"}

@app.get("/scan/status")
def scan_status():
    return {"scanning": _is_scan_running()}

@app.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    latest_session = db.query(models.ScanSession).order_by(models.ScanSession.id.desc()).first()
    if not latest_session: return []
    rows = db.query(models.DeviceLog).filter(models.DeviceLog.scan_id == latest_session.id).order_by(models.DeviceLog.ip_address).all()
    return [{"ip_address": d.ip_address, "status": d.status, "mac_address": d.mac_address or "Unknown", "hostname": d.hostname or "Unknown", "manufacturer": d.vendor or "Unknown", "risk_score": d.risk_score, "risk_level": d.risk_level, "vulnerabilities": d.vulnerabilities or [], "telemetry": getattr(d, 'telemetry', None) or {}, "device_type": d.device_type or "unknown"} for d in rows]

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    rows = db.query(models.SecurityEvent).order_by(models.SecurityEvent.timestamp.desc()).limit(200).all()
    return [{"ip_address": e.ip_address, "event_type": e.event_type, "severity": e.severity, "description": e.description, "timestamp": e.timestamp.isoformat() + "Z"} for e in rows]

@app.get("/threats")
def get_threats(db: Session = Depends(get_db)):
    # Aggregation logic... (Simplified for output, keep your existing implementation)
    return []

@app.get("/policies")
def get_policies(): return _load_policies()

@app.post("/policies/{policy_name}")
def set_policy(policy_name: str, request: PolicyToggleRequest):
    policies = _load_policies()
    if policy_name not in policies: raise HTTPException(status_code=404)
    policies[policy_name] = bool(request.value)
    _save_policies(policies)
    return {"status": "ok"}

@app.get("/stats")
@app.get("/dashboard/stats")
def get_stats(db: Session = Depends(get_db)):
    latest_session = db.query(models.ScanSession).order_by(models.ScanSession.id.desc()).first()
    if not latest_session: return {"total_devices": 0}
    devices = db.query(models.DeviceLog).filter(models.DeviceLog.scan_id == latest_session.id).all()
    return {"total_devices": len(devices), "scanning": _is_scan_running()}

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    r = aioredis.Redis(host=os.getenv("SIN_REDIS_HOST", "redis"), port=6379, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe("sin:ws:stream")
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message: await websocket.send_json(json.loads(message["data"]))
            await asyncio.sleep(0.2)
    except: pass
    finally: await pubsub.unsubscribe("sin:ws:stream"); await r.close()

# ── Firmware Analysis Endpoints ──────────────────────────────────────────────
import shutil
from fastapi import UploadFile, File
from sin.firmware.extractor import FirmwareExtractor
from sin.firmware.secret_extractor import SecretExtractor

_FIRMWARE_UPLOAD_DIR = "/var/lib/sin/firmware/uploads"
os.makedirs(_FIRMWARE_UPLOAD_DIR, exist_ok=True)

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


# ── Credentials API ──────────────────────────────────────────────────────────
from sin.storage.credential_vault import vault as _vault

class CredentialRequest(BaseModel):
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    username: str
    password: str
    protocol: str = "onvif"
    priority: int = 50

@app.post("/credentials")
def add_credential(req: CredentialRequest):
    try:
        result = _vault.add(
            ip_address=req.ip_address,
            vendor=req.vendor,
            username=req.username,
            password=req.password,
            protocol=req.protocol,
            priority=req.priority,
        )
        return {"status": "created", "id": result["id"]}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/credentials")
def list_credentials():
    try:
        from sin.storage.database import SessionLocal
        from sin.storage.credential_vault import DeviceCredential
        db = SessionLocal()
        rows = db.query(DeviceCredential).all()
        db.close()
        return [
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "vendor": r.vendor,
                "username": r.username,
                "password": "***",
                "protocol": r.protocol,
                "priority": r.priority,
                "last_success": str(r.last_success) if r.last_success else None,
            }
            for r in rows
        ]
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/credentials/{cred_id}")
def delete_credential(cred_id: int):
    try:
        from sin.storage.database import SessionLocal
        from sin.storage.credential_vault import DeviceCredential
        db = SessionLocal()
        row = db.query(DeviceCredential).filter(DeviceCredential.id == cred_id).first()
        if not row:
            db.close()
            return JSONResponse(status_code=404, content={"error": "not found"})
        db.delete(row)
        db.commit()
        db.close()
        return {"status": "deleted", "id": cred_id}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
