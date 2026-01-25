from pydantic import BaseModel
from typing import List, Optional, Any
from datetime import datetime

# Schema for a single Device
class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    hostname: Optional[str] = None
    status: str
    vendor: Optional[str] = None
    os_family: Optional[str] = None
    open_ports: List[int] = []
    
    class Config:
        from_attributes = True

# Schema for a Scan Session
class ScanSessionResponse(BaseModel):
    session_uuid: str
    start_time: datetime
    end_time: Optional[datetime]
    subnet_target: str
    device_count: int

    class Config:
        from_attributes = True
