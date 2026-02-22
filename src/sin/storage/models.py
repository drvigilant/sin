# ... (previous imports remain)
# Ensure JSON is imported from sqlalchemy
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from sin.storage.database import Base

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_uuid = Column(String, unique=True, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    subnet_target = Column(String)
    devices = relationship("DeviceLog", back_populates="scan")

class DeviceLog(Base):
    __tablename__ = "device_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_sessions.id"))
    
    ip_address = Column(String, index=True)
    hostname = Column(String, nullable=True)
    status = Column(String)
    vendor = Column(String, nullable=True)
    os_family = Column(String, nullable=True)
    
    open_ports = Column(JSON)
    protocols = Column(JSON)
    
    # NEW: Store list of found risks
    # Example: [{"severity": "HIGH", "type": "Weak Creds", "description": "Default admin/admin detected"}]
    vulnerabilities = Column(JSON, default=[]) 
    
    scan = relationship("ScanSession", back_populates="devices")

class SecurityEvent(Base):
    """
    Stores historical anomalies, state changes, and heuristic alerts.
    """
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    event_type = Column(String)  # e.g., 'PORT_OPENED', 'HEURISTIC_FLAG'
    severity = Column(String)    # e.g., 'INFO', 'WARNING', 'CRITICAL'
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
