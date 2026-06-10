"""
conftest.py — pytest session fixtures for SIN test suite.

Stubs out the database layer before any test module is imported.
This allows unit tests to run without a live Postgres connection
while integration tests (which need the real DB) are skipped
unless SIN_DB_PASSWORD is set in the environment.
"""
import os
import sys
import types

# ── Stub database before any sin.* import touches it ─────────────────────────
# database.py raises RuntimeError if SIN_DB_PASSWORD is unset.
# We inject a lightweight stub so unit tests can import freely.
if "sin.storage.database" not in sys.modules:
    _db = types.ModuleType("sin.storage.database")
    _db.Base         = type("Base",         (), {})
    _db.SessionLocal = type("SessionLocal", (), {})()
    _db.engine       = type("engine",       (), {})()
    _db.get_db       = lambda: iter([None])
    sys.modules["sin.storage.database"] = _db

if "sin.storage.models" not in sys.modules:
    _m = types.ModuleType("sin.storage.models")
    for _cls in ("DeviceLog", "ScanSession", "SecurityEvent", "User", "RefreshToken"):
        setattr(_m, _cls, type(_cls, (), {
            "__tablename__": _cls.lower(),
            "__init__":      lambda self, **kw: None,
        }))

    # DeviceBaseline needs real attributes for MagicMock(spec=DeviceBaseline) to work
    class _DeviceBaseline:
        __tablename__            = "device_baselines"
        ip_address               = None
        baseline_risk_score      = None
        last_risk_score          = None
        baseline_ports           = []
        baseline_vendor          = ""
        baseline_vulnerabilities = []
        baseline_jarm_hash       = ""
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    _m.DeviceBaseline = _DeviceBaseline
    sys.modules["sin.storage.models"] = _m
