from fastapi import FastAPI, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
import asyncio
import httpx
import json
import os

from sin.utils.logger import get_logger
from sin.agent.runner import AgentRunner
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.api.server")

app = FastAPI(title="SIN Enterprise API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_sin_agent = None
_scan_running = False   # global scan lock for status endpoint

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


def run_scan_job(subnet: str):
    global _scan_running
    _scan_running = True
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
    except Exception as e:
        logger.error(f"Background scan crashed: {e}")
    finally:
        _scan_running = False


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "online", "api": "SIN Enterprise"}


# ── Scan ───────────────────────────────────────────────────────────────────

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    target = request.subnet or "192.168.30"
    background_tasks.add_task(run_scan_job, target)
    return {"status": "success", "message": f"Scan dispatched for {target}"}


@app.get("/scan/status")
def scan_status():
    """Dashboard polls this to know when scan finishes and should refresh."""
    return {"scanning": _scan_running}


# ── Devices — LATEST SCAN ONLY ─────────────────────────────────────────────

@app.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    # Get the most recent scan session
    latest_session = db.query(models.ScanSession)\
        .order_by(models.ScanSession.id.desc()).first()

    if not latest_session:
        return []

    # Return only devices from the latest scan
    rows = db.query(models.DeviceLog)\
        .filter(models.DeviceLog.scan_id == latest_session.id)\
        .order_by(models.DeviceLog.ip_address).all()

    devices = []
    for d in rows:
        # Parse MAC/hostname/manufacturer from protocols field
        mac = "Unknown"
        hostname = "Unknown"
        manufacturer = d.vendor or "Unknown"

        for hint in (d.protocols or []):
            if hint.startswith("MAC:"):
                mac = hint[4:]
            elif hint.startswith("HOST:"):
                hostname = hint[5:]
            elif hint.startswith("MFR:"):
                manufacturer = hint[4:]

        devices.append({
            "ip_address":      d.ip_address,
            "status":          d.status,
            "mac_address":     mac,
            "hostname":        hostname,
            "manufacturer":    manufacturer,
            "vendor":          d.vendor or "Unknown",
            "os_family":       d.os_family or "Unknown",
            "open_ports":      d.open_ports or [],
            "protocols":       d.protocols or [],
            "vulnerabilities": d.vulnerabilities or [],
            "scan_id":         d.scan_id,
        })
    return devices


# ── Events ─────────────────────────────────────────────────────────────────

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    rows = db.query(models.SecurityEvent)\
        .order_by(models.SecurityEvent.timestamp.desc())\
        .limit(200).all()
    return [{
        "ip_address":  e.ip_address,
        "event_type":  e.event_type,
        "severity":    e.severity,
        "description": e.description,
        "timestamp":   e.timestamp.isoformat() if e.timestamp else "",
    } for e in rows]


# ── Stats ──────────────────────────────────────────────────────────────────

def _build_stats(db: Session) -> dict:
    latest_session = db.query(models.ScanSession)\
        .order_by(models.ScanSession.id.desc()).first()

    if not latest_session:
        return {
            "total_devices": 0, "total_assets_tracked": 0,
            "vulnerable": 0, "critical": 0, "clean": 0,
            "total_scans": 0, "total_scan_runs": 0,
            "latest_activity": "N/A", "scanning": _scan_running,
        }

    devices = db.query(models.DeviceLog)\
        .filter(models.DeviceLog.scan_id == latest_session.id).all()

    total      = len(devices)
    vulnerable = sum(1 for d in devices if d.vulnerabilities)
    critical   = sum(
        sum(1 for v in (d.vulnerabilities or []) if v.get("severity") == "CRITICAL")
        for d in devices
    )
    clean  = total - vulnerable
    scans  = db.query(models.ScanSession).count()

    return {
        "total_devices":        total,
        "total_assets_tracked": total,
        "vulnerable":           vulnerable,
        "critical":             critical,
        "clean":                clean,
        "total_scans":          scans,
        "total_scan_runs":      scans,
        "latest_activity":      latest_session.start_time.isoformat(),
        "scanning":             _scan_running,
    }


@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    return _build_stats(db)


@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    return _build_stats(db)


# ── Ollama AI Audit ────────────────────────────────────────────────────────

@app.post("/ai/audit")
async def ollama_audit(request: OllamaAuditRequest):
    """
    Ask local Ollama to analyse a device and return vulnerability findings.
    Falls back gracefully if Ollama is not running.
    """
    prompt = f"""You are an expert IoT security analyst.
Analyse this network device and identify vulnerabilities, misconfigurations, or security risks.
Be concise and specific. Return ONLY a JSON array of findings, no other text.

Device:
- IP: {request.ip_address}
- Open Ports: {request.open_ports}
- Vendor/Manufacturer: {request.vendor or 'Unknown'}
- OS: {request.os_family or 'Unknown'}
- Hostname: {request.hostname or 'Unknown'}

Return format (JSON array only, no markdown):
[{{"severity": "HIGH|MEDIUM|LOW", "type": "short category", "description": "detailed finding"}}]

If no issues found, return: []"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                }
            )
            if resp.status_code != 200:
                return {"error": f"Ollama returned {resp.status_code}", "findings": []}

            raw = resp.json().get("response", "[]")
            # Clean and parse
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            findings = json.loads(raw)
            if not isinstance(findings, list):
                findings = []
            return {"findings": findings, "model": OLLAMA_MODEL}

    except httpx.ConnectError:
        return {"error": "Ollama not reachable", "findings": [], "model": OLLAMA_MODEL}
    except json.JSONDecodeError:
        return {"error": "Ollama returned invalid JSON", "findings": [], "model": OLLAMA_MODEL}
    except Exception as e:
        return {"error": str(e), "findings": [], "model": OLLAMA_MODEL}


@app.get("/ai/status")
async def ollama_status():
    """Check if Ollama is running and which models are available."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                models_list = [m["name"] for m in resp.json().get("models", [])]
                return {"online": True, "models": models_list, "url": OLLAMA_URL}
    except Exception:
        pass
    return {"online": False, "models": [], "url": OLLAMA_URL}


# ── Agent control ──────────────────────────────────────────────────────────

@app.get("/agent/status")
def agent_status():
    if _sin_agent is None:
        return {"running": False, "note": "SINAgent not started"}
    return {"running": True}


@app.post("/agent/whitelist/{ip}")
def whitelist_device(ip: str):
    if _sin_agent is None:
        raise HTTPException(503, "Agent not running")
    _sin_agent.whitelist_device(ip)
    return {"status": "whitelisted", "ip": ip}


@app.post("/agent/lift/{ip}")
def lift_isolation(ip: str):
    if _sin_agent is None:
        raise HTTPException(503, "Agent not running")
    return _sin_agent.lift_isolation(ip)


@app.get("/agent/mitigations")
def list_mitigations():
    if _sin_agent is None:
        return []
    return _sin_agent.mitigation.list_active()


# ── WebSocket live event feed ──────────────────────────────────────────────

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    if _sin_agent is None:
        await websocket.send_json({"kind": "error", "msg": "Agent not running"})
        await websocket.close()
        return
    q = _sin_agent.subscribe()
    try:
        while True:
            data = await asyncio.wait_for(q.get(), timeout=30)
            await websocket.send_json(data)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        _sin_agent.unsubscribe(q)
