from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from sqlalchemy import desc, func

from sin.storage.database import get_db
from sin.storage import models
from sin.api import schemas
from sin.storage.models import SecurityEvent, DeviceLog, ScanSession

app = FastAPI(
    title="SIN Enterprise API",
    description="Shadows In The Network - Security Agent Interface",
    version="0.1.0"
)

@app.get("/")
def health_check():
    return {"status": "online", "system": "SIN Agent"}

@app.get("/devices", response_model=List[schemas.DeviceResponse])
def get_all_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Get a list of all devices ever discovered.
    """
    devices = db.query(models.DeviceLog).offset(skip).limit(limit).all()
    return devices

@app.get("/scans", response_model=List[schemas.ScanSessionResponse])
def get_scan_history(db: Session = Depends(get_db)):
    """
    Get history of all scan sessions.
    """
    scans = db.query(models.ScanSession).order_by(models.ScanSession.start_time.desc()).all()

    # Enrich with device count
    results = []
    for s in scans:
        s.device_count = len(s.devices)
        results.append(s)
    return results

@app.get("/events")
def get_latest_events(limit: int = 50, db: Session = Depends(get_db)):
    """
    Fetches the most recent security events and anomalies for the timeline UI.
    """
    try:
        # Query the database for the latest events, sorted by newest first
        events = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit).all()

        # Format the data to send to the dashboard
        return [
            {
                "id": e.id,
                "ip_address": e.ip_address,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None
            }
            for e in events
        ]
    except Exception as e:
        return {"error": str(e)}

@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Provides high-level metrics for the top of the dashboard.
    """
    try:
        # Count unique IP addresses tracked
        total_assets = db.query(func.count(func.distinct(DeviceLog.ip_address))).scalar() or 0

        # Count total scan sessions run
        total_scans = db.query(ScanSession).count()

        # Get the timestamp of the most recent scan
        latest_scan = db.query(ScanSession).order_by(desc(ScanSession.end_time)).first()
        latest_time = latest_scan.end_time.isoformat() if latest_scan and latest_scan.end_time else "No scans yet"

        return {
            "total_assets_tracked": total_assets,
            "total_scan_runs": total_scans,
            "latest_activity": latest_time
        }
    except Exception as e:
        return {"error": str(e)}
