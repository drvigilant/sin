"""
sin.storage.models
══════════════════
SQLAlchemy ORM models for the SIN platform.

Enterprise fix in this revision
─────────────────────────────────
PROBLEM:  DeviceLog was missing critical fields that are computed during every
          scan but never persisted:
            • mac_address   — lost on restart, dashboard shows "Unknown" forever
            • device_type   — camera / nvr_dvr / iot — needed for dashboard filters
            • risk_score    — 0-100 int, computed by DecisionEngine
            • risk_level    — CRITICAL/HIGH/MEDIUM/LOW
            • risk_reasons  — list of human-readable evidence strings
            • first_seen    — when the device was first discovered
            • last_seen     — timestamp of most recent scan where device appeared
            • jarm_hash     — TLS fingerprint (populated in a future step)

          Without these, the API /devices endpoint could never return risk data,
          the dashboard risk columns were always blank, and there was no way
          to track when a new device appeared on the network.

FIX:      New columns added with safe defaults (nullable / server_default).
          All existing columns are UNCHANGED — no renames, no type changes.
          The companion init_db.py handles ALTER TABLE for existing deployments.
"""

from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Float, Text
from sqlalchemy.orm import relationship

from sin.storage.database import Base


class ScanSession(Base):
    """One row per triggered scan — groups all DeviceLog rows from that run."""
    __tablename__ = "scan_sessions"

    id            = Column(Integer, primary_key=True, index=True)
    session_uuid  = Column(String, unique=True, index=True)
    start_time    = Column(DateTime, default=datetime.utcnow)
    end_time      = Column(DateTime, nullable=True)
    subnet_target = Column(String)

    devices = relationship("DeviceLog", back_populates="scan")


class DeviceLog(Base):
    """
    One row per device per scan session.
    Carries the full security posture snapshot at the time of the scan.
    """
    __tablename__ = "device_logs"

    # ── Primary key + scan link ────────────────────────────────────────────
    id      = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_sessions.id"))

    # ── Identity (existing columns — unchanged) ────────────────────────────
    ip_address = Column(String, index=True)
    hostname   = Column(String, nullable=True)
    status     = Column(String)
    vendor     = Column(String, nullable=True)
    os_family  = Column(String, nullable=True)

    # ── Network telemetry (existing columns — unchanged) ───────────────────
    open_ports = Column(JSON)
    protocols  = Column(JSON)

    # ── Vulnerability findings (existing column — unchanged) ───────────────
    # List of dicts: [{severity, type, description, cve}, ...]
    vulnerabilities = Column(JSON, default=list)

    # ── NEW: Device identity fields ────────────────────────────────────────
    mac_address = Column(String, nullable=True)   # ARP-resolved MAC
    device_type = Column(String, nullable=True)   # camera | nvr_dvr | iot | router

    # ── NEW: Risk verdict (populated by DecisionEngine) ───────────────────
    risk_score   = Column(Integer,  nullable=True)   # 0-100
    risk_level   = Column(String,   nullable=True)   # CRITICAL|HIGH|MEDIUM|LOW
    risk_reasons = Column(JSON,     default=list)    # list[str] evidence chain

    # ── NEW: TLS fingerprint (populated by JARM step — future) ────────────
    jarm_hash = Column(String, nullable=True)

    # ── NEW: Temporal tracking ─────────────────────────────────────────────
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Relationship ───────────────────────────────────────────────────────
    scan = relationship("ScanSession", back_populates="devices")
     
    # ── NEW: Live Hardware Telemetry ──────────────────────────────────────────
    telemetry = Column(JSON, default=dict) # NEW: Stores ISAPI/SNMP data like CPU, RAM, Temp

    firmware      = Column(String, nullable=True) # NEW: Firmware version
    serial_number = Column(String, nullable=True) # NEW: Hardware serial
    model = Column(String, nullable=True) 

class DeviceBaseline(Base):
    """
    Golden-state snapshot for each device — taken on first discovery.
    Subsequent scans compare current state against this baseline to detect drift.
    """
    __tablename__ = "device_baselines"

    id           = Column(Integer, primary_key=True, index=True)
    ip_address   = Column(String, unique=True, index=True, nullable=False)

    # Baseline network state
    baseline_ports         = Column(JSON,    default=list)   # list[int]
    baseline_vendor        = Column(String,  nullable=True)
    baseline_vulnerabilities = Column(JSON,  default=list)   # list[str] — CVE IDs only
    baseline_risk_score    = Column(Integer, nullable=True)
    baseline_jarm_hash     = Column(String,  nullable=True)

    # Rolling risk score — updated every scan so detect_drift() can diff scan-to-scan
    last_risk_score = Column(Integer, nullable=True)

    # Lifecycle
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecurityEvent(Base):
    """
    Stores historical anomalies, state changes, and heuristic alerts.
    One row per finding — multiple rows per scan per device.
    """
    __tablename__ = "security_events"

    id          = Column(Integer, primary_key=True, index=True)
    ip_address  = Column(String, index=True)
    event_type  = Column(String)    # PORT_OPENED | VULN_DETECTED | DRIFT | NEW_DEVICE
    severity    = Column(String)    # INFO | WARNING | CRITICAL
    description = Column(Text)      # Changed String → Text for long CVE descriptions
    timestamp   = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, unique=True, index=True, nullable=False)
    email         = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    role          = Column(String, default="analyst")   # admin | analyst | viewer
    is_active     = Column(String, default="true")
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_login    = Column(DateTime, nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked    = Column(String, default="false")
    created_at = Column(DateTime, default=datetime.utcnow)
