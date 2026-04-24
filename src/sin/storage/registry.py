"""
sin.storage.registry
Uses existing PostgreSQL DB (SessionLocal + models).
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sin.storage.database import SessionLocal
from sin.storage.models import DeviceLog, SecurityEvent, ScanSession
from sin.utils.logger import get_logger

logger = get_logger("sin.storage.registry")

# Simple file-based whitelist (no extra migration needed)
_WHITELIST_PATH = Path("/var/lib/sin/whitelist.json")


def _load_whitelist() -> set:
    try:
        _WHITELIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _WHITELIST_PATH.exists():
            return set(json.loads(_WHITELIST_PATH.read_text()))
    except Exception:
        pass
    return set()


def _save_whitelist(wl: set) -> None:
    try:
        _WHITELIST_PATH.write_text(json.dumps(list(wl)))
    except Exception as e:
        logger.error(f"Whitelist save failed: {e}")


class DeviceRegistry:

    def __init__(self):
        self._whitelist: set = _load_whitelist()

    # ── Core methods used by agent/core.py ───────────────────────────────────

    def exists(self, ip: str) -> bool:
        db = SessionLocal()
        try:
            return db.query(DeviceLog).filter(
                DeviceLog.ip_address == ip
            ).first() is not None
        finally:
            db.close()

    def upsert(self, host: dict) -> None:
        """Insert or update the latest scan record for this IP."""
        db = SessionLocal()
        try:
            record = db.query(DeviceLog).filter(
                DeviceLog.ip_address == host["ip_address"]
            ).first()

            if record:
                record.hostname        = host.get("hostname")
                record.status          = host.get("status", "online")
                record.vendor          = host.get("manufacturer")
                record.os_family       = host.get("os_family")
                record.open_ports      = host.get("open_ports", [])
                record.protocols       = host.get("protocol_hints", [])
                record.vulnerabilities = host.get("vulnerabilities", [])
            else:
                record = DeviceLog(
                    scan_id        = None,
                    ip_address     = host["ip_address"],
                    hostname       = host.get("hostname"),
                    status         = host.get("status", "online"),
                    vendor         = host.get("manufacturer"),
                    os_family      = host.get("os_family"),
                    open_ports     = host.get("open_ports", []),
                    protocols      = host.get("protocol_hints", []),
                    vulnerabilities= host.get("vulnerabilities", []),
                )
                db.add(record)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"upsert failed for {host.get('ip_address')}: {e}")
        finally:
            db.close()

    def get_all_in_subnet(self, subnet: str) -> List[str]:
        """Return all IPs whose prefix matches subnet (e.g. '192.168.30')."""
        db = SessionLocal()
        try:
            rows = db.query(DeviceLog.ip_address).filter(
                DeviceLog.ip_address.like(f"{subnet}.%"),
                DeviceLog.status == "online",
            ).all()
            return [r.ip_address for r in rows]
        finally:
            db.close()

    def mark_offline(self, ip: str) -> None:
        db = SessionLocal()
        try:
            db.query(DeviceLog).filter(
                DeviceLog.ip_address == ip
            ).update({"status": "offline"})
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"mark_offline failed for {ip}: {e}")
        finally:
            db.close()

    def log_event(self, payload: dict) -> None:
        db = SessionLocal()
        try:
            event = SecurityEvent(
                ip_address  = payload.get("payload", {}).get("ip", "agent"),
                event_type  = payload.get("kind", "UNKNOWN"),
                severity    = payload.get("payload", {}).get("severity", "INFO"),
                description = json.dumps(payload.get("payload", {}))[:500],
                timestamp   = datetime.utcnow(),
            )
            db.add(event)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"log_event failed: {e}")
        finally:
            db.close()

    def mark_mitigated(self, ip: str, lifted: bool = False) -> None:
        db = SessionLocal()
        try:
            status = "mitigated" if not lifted else "online"
            db.query(DeviceLog).filter(
                DeviceLog.ip_address == ip
            ).update({"status": status})
            db.commit()
        except Exception as e:
            db.rollback()
        finally:
            db.close()

    # ── Whitelist ─────────────────────────────────────────────────────────────

    def whitelist(self, ip: str) -> None:
        self._whitelist.add(ip)
        _save_whitelist(self._whitelist)

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist
