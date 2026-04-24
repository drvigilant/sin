from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional, List
from sqlalchemy.orm import Session

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

@app.get("/health")
def health_check():
    return {"status": "online", "api": "SIN Enterprise"}

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    target = request.subnet or "192.168.30"
    background_tasks.add_task(run_scan_job, target)
    return {"status": "success", "message": f"Scan dispatched for {target}"}

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
            "ip_address":     d.ip_address,
            "status":         d.status,
            "vendor":         d.vendor or "Unknown",
            "os_family":      d.os_family or "Unknown",
            "hostname":       d.hostname or "Unknown",
            "open_ports":     d.open_ports or [],
            "protocols":      d.protocols or [],
            "vulnerabilities": d.vulnerabilities or [],
        })
    return devices

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

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
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
    clean      = total - vulnerable
    scans      = db.query(models.ScanSession).count()
    return {
        "total_devices": total,
        "vulnerable":    vulnerable,
        "critical":      critical,
        "clean":         clean,
        "total_scans":   scans,
    }
