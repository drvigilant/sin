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
    
    # NEW: Fingerprinting details
    vendor = Column(String, nullable=True)      # e.g., "Hikvision", "Apple"
    os_family = Column(String, nullable=True)   # e.g., "Linux", "Windows"
    
    open_ports = Column(JSON)
    protocols = Column(JSON)
    
    scan = relationship("ScanSession", back_populates="devices")
