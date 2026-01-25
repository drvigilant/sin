from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from sin.storage.database import get_db
from sin.storage import models
from sin.api import schemas

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

@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Aggregated statistics for the dashboard.
    """
    total_devices = db.query(models.DeviceLog).count()
    total_scans = db.query(models.ScanSession).count()
    
    # Count unique vendors
    vendors = db.query(models.DeviceLog.vendor, models.DeviceLog.os_family).all()
    
    return {
        "total_assets_tracked": total_devices,
        "total_scan_runs": total_scans,
        "latest_activity": datetime.utcnow()
    }
