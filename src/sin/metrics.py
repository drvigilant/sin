"""
sin.metrics - Prometheus instrumentation for the SIN IoT Security Platform

Exposes:
  HTTP layer (via middleware):
    sin_http_requests_total{method, endpoint, status_code}
    sin_http_request_duration_seconds{method, endpoint}

  Scan lifecycle:
    sin_scans_triggered_total          - counter
    sin_scan_active                    - gauge (0|1, sourced from Redis)

  Device posture (DB-sourced, polled on scrape):
    sin_devices_total                  - gauge
    sin_devices_by_risk_total{level}   - gauge  (CRITICAL|HIGH|MEDIUM|LOW)
    sin_vulnerabilities_total          - gauge

  Security events (accumulated counter):
    sin_security_events_total{event_type, severity}

  System:
    sin_agent_up                       - gauge (0|1)
    sin_api_info{version, env}         - gauge (always 1, labels carry metadata)

Usage:
    from sin.metrics import instrument_app
    instrument_app(app)          # in server.py, after app = FastAPI(...)

    from sin.metrics import inc_scan_triggered, set_agent_up
    inc_scan_triggered()
    set_agent_up(True)
"""

import time
from typing import TYPE_CHECKING

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
)
from fastapi import Request, Response
from fastapi.routing import APIRoute
from starlette.routing import Match

from sin.utils.logger import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = get_logger("sin.metrics")

# ── Metric definitions ────────────────────────────────────────────────────────

HTTP_REQUESTS = Counter(
    "sin_http_requests_total",
    "Total HTTP requests handled by the SIN API",
    ["method", "endpoint", "status_code"],
)

HTTP_LATENCY = Histogram(
    "sin_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

SCANS_TRIGGERED = Counter(
    "sin_scans_triggered_total",
    "Number of network scans triggered via the API",
)

SCAN_ACTIVE = Gauge(
    "sin_scan_active",
    "1 if a network scan is currently running, 0 otherwise",
)

DEVICES_TOTAL = Gauge(
    "sin_devices_total",
    "Total IoT devices seen in the most recent scan session",
)

DEVICES_BY_RISK = Gauge(
    "sin_devices_by_risk_total",
    "Device count by risk level in the most recent scan session",
    ["level"],
)

VULNERABILITIES_TOTAL = Gauge(
    "sin_vulnerabilities_total",
    "Total vulnerability findings across all devices in the latest scan",
)

SECURITY_EVENTS = Counter(
    "sin_security_events_total",
    "Cumulative security events emitted by the SIN agent",
    ["event_type", "severity"],
)

AGENT_UP = Gauge(
    "sin_agent_up",
    "1 if the SIN agent is running inside the API process, 0 otherwise",
)

API_INFO = Info(
    "sin_api",
    "SIN API build metadata",
)

# ── Public helpers (called from server.py) ────────────────────────────────────

def inc_scan_triggered() -> None:
    SCANS_TRIGGERED.inc()


def set_scan_active(active: bool) -> None:
    SCAN_ACTIVE.set(1 if active else 0)


def set_agent_up(up: bool) -> None:
    AGENT_UP.set(1 if up else 0)


def record_security_event(event_type: str, severity: str) -> None:
    SECURITY_EVENTS.labels(
        event_type=event_type.upper(),
        severity=(severity or "INFO").upper(),
    ).inc()


# ── Route normalizer (prevents high-cardinality label explosion) ──────────────

def _normalize_path(request: Request) -> str:
    """
    Return the matched route template instead of the raw URL path.

    /devices/192.168.1.5  →  /devices/{ip}
    /policies/auto_q...   →  /policies/{policy_name}
    /metrics              →  /metrics
    Unmatched paths       →  UNKNOWN
    """
    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            if isinstance(route, APIRoute):
                return route.path
    return "UNKNOWN"


# ── Middleware ────────────────────────────────────────────────────────────────

async def _metrics_middleware(request: Request, call_next):
    # Skip instrumentation for the /metrics endpoint itself
    if request.url.path == "/metrics":
        return await call_next(request)

    endpoint = _normalize_path(request)
    method = request.method

    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    HTTP_REQUESTS.labels(
        method=method,
        endpoint=endpoint,
        status_code=str(response.status_code),
    ).inc()

    HTTP_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)

    return response


# ── Device/scan gauge refresh (called during /metrics scrape) ─────────────────

def _refresh_device_gauges() -> None:
    """Pull latest device posture from the DB and update gauges."""
    from sin.storage.database import SessionLocal
    from sin.storage import models

    db = SessionLocal()
    try:
        latest = (
            db.query(models.ScanSession)
            .order_by(models.ScanSession.id.desc())
            .first()
        )
        if not latest:
            DEVICES_TOTAL.set(0)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                DEVICES_BY_RISK.labels(level=level).set(0)
            VULNERABILITIES_TOTAL.set(0)
            return

        devices = (
            db.query(models.DeviceLog)
            .filter(models.DeviceLog.scan_id == latest.id)
            .all()
        )

        DEVICES_TOTAL.set(len(devices))

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vuln_count = 0
        for d in devices:
            level = (d.risk_level or "LOW").upper()
            if level in risk_counts:
                risk_counts[level] += 1
            vuln_count += len(d.vulnerabilities or [])

        for level, count in risk_counts.items():
            DEVICES_BY_RISK.labels(level=level).set(count)

        VULNERABILITIES_TOTAL.set(vuln_count)

    except Exception as exc:
        logger.warning(f"[metrics] device gauge refresh failed: {exc}")
    finally:
        db.close()


def _refresh_scan_gauge() -> None:
    """Sync the scan-active gauge with the Redis flag."""
    import os
    import redis as _redis

    try:
        r = _redis.Redis(
            host=os.getenv("SIN_REDIS_HOST", "redis"),
            port=int(os.getenv("SIN_REDIS_PORT", "6379")),
            password=os.getenv("SIN_REDIS_PASSWORD", ""),
            socket_connect_timeout=2,
            decode_responses=True,
        )
        active = bool(r.get("sin:scan:running"))
        SCAN_ACTIVE.set(1 if active else 0)
    except Exception:
        pass  # Redis down — leave gauge at last known value


# ── instrument_app ────────────────────────────────────────────────────────────

def instrument_app(app: "FastAPI", version: str = "1.0.0", env: str = "production") -> None:
    """
    Attach Prometheus instrumentation to a FastAPI app.

    Adds:
      - HTTP middleware for request counting + latency
      - GET /metrics  endpoint (Prometheus text format)

    Call once after `app = FastAPI(...)`, before adding routes.
    """
    from sin.core.config import settings as _settings

    _version = version or _settings.VERSION
    _env = env or _settings.ENV

    API_INFO.info({"version": _version, "env": _env})

    # Middleware must be added before routes are registered
    app.middleware("http")(_metrics_middleware)

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint():
        """
        Prometheus scrape endpoint.
        Refreshes device/scan gauges on every scrape so values are current.
        """
        _refresh_device_gauges()
        _refresh_scan_gauge()
        return Response(
            content=generate_latest(REGISTRY),
            media_type=CONTENT_TYPE_LATEST,
        )

    logger.info(
        "[metrics] Prometheus instrumentation attached",
        extra={"version": _version, "env": _env},
    )
