from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
import asyncio

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

# Global SINAgent instance (started separately via sin.agent.core)
_sin_agent = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class ScanRequest(BaseModel):
    subnet: Optional[str] = None


def run_scan_job(subnet: str):
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
    except Exception as e:
        logger.error(f"Background scan crashed: {e}")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "online", "api": "SIN Enterprise"}


# ── Scan ──────────────────────────────────────────────────────────────────────

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    target = request.subnet or "192.168.30"
    background_tasks.add_task(run_scan_job, target)
    return {"status": "success", "message": f"Scan dispatched for {target}"}


# ── Devices ───────────────────────────────────────────────────────────────────

@app.get("/devices")
def get_devices(db: Session = Depends(get_db)):
    rows = db.query(models.DeviceLog)\
        .order_by(models.DeviceLog.id.desc()).all()
    seen = set()
    devices = []
    for d in rows:
        if d.ip_address in seen:
            continue
        seen.add(d.ip_address)
        devices.append({
            "ip_address":      d.ip_address,
            "status":          d.status,
            "manufacturer":    d.vendor or "Unknown",
            "vendor":          d.vendor or "Unknown",
            "os_family":       d.os_family or "Unknown",
            "hostname":        d.hostname or "Unknown",
            "open_ports":      d.open_ports or [],
            "protocols":       d.protocols or [],
            "vulnerabilities": d.vulnerabilities or [],
        })
    return devices


# ── Events ────────────────────────────────────────────────────────────────────

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


# ── Stats (original + dashboard alias) ───────────────────────────────────────

def _build_stats(db: Session) -> dict:
    all_devices = db.query(models.DeviceLog).all()
    seen = set()
    unique = []
    for d in all_devices:
        if d.ip_address not in seen:
            seen.add(d.ip_address)
            unique.append(d)
    total      = len(unique)
    vulnerable = sum(1 for d in unique if d.vulnerabilities)
    critical   = sum(
        sum(1 for v in (d.vulnerabilities or []) if v.get("severity") == "CRITICAL")
        for d in unique
    )
    clean = total - vulnerable
    scans = db.query(models.ScanSession).count()
    latest = db.query(models.ScanSession)\
        .order_by(models.ScanSession.start_time.desc()).first()
    return {
        "total_devices":        total,
        "total_assets_tracked": total,
        "vulnerable":           vulnerable,
        "critical":             critical,
        "clean":                clean,
        "total_scans":          scans,
        "total_scan_runs":      scans,
        "latest_activity":      latest.start_time.isoformat() if latest else "N/A",
    }


@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    return _build_stats(db)


@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    return _build_stats(db)


# ── Agent control endpoints ───────────────────────────────────────────────────

@app.get("/agent/status")
def agent_status():
    if _sin_agent is None:
        return {"running": False, "note": "SINAgent not started"}
    return {
        "running":        True,
        "auto_mitigate":  _sin_agent.decision is not None,
        "dry_run":        _sin_agent.mitigation.dry_run,
    }


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
    result = _sin_agent.lift_isolation(ip)
    return result


@app.get("/agent/mitigations")
def list_mitigations():
    if _sin_agent is None:
        return []
    return _sin_agent.mitigation.list_active()


# ── WebSocket live event feed ─────────────────────────────────────────────────

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
