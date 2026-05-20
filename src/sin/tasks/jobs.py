import os
from celery import shared_task
from sin.agent.runner import AgentRunner
from sin.utils.logger import get_logger

logger = get_logger("sin.tasks.jobs")

_SCAN_REDIS_KEY = "sin:scan:running"


def _get_redis():
    try:
        import redis
        r = redis.Redis(
            host=os.getenv("SIN_REDIS_HOST", "redis"),
            port=int(os.getenv("SIN_REDIS_PORT", "6379")),
            password=os.getenv("SIN_REDIS_PASSWORD", ""),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        r.ping()
        return r
    except Exception:
        return None


@shared_task(name="run_network_scan", queue="scan", acks_late=True, max_retries=3)
def run_network_scan(subnet="192.168.30"):
    r = _get_redis()
    if r:
        try:
            r.setex(_SCAN_REDIS_KEY, 3600, "1")
        except Exception:
            pass

    logger.info(f"⏳ Starting scheduled scan for {subnet}...")
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
        logger.info("✅ Scheduled scan completed successfully.")
    finally:
        if r:
            try:
                r.delete(_SCAN_REDIS_KEY)
            except Exception:
                pass

    return "Scan Complete"

# ── Quarantine Tasks (run on worker: network_mode=host, NET_RAW) ──────────────
from sin.agent.mitigation import MitigationEngine
from sin.agent.decision import ThreatVerdict

_mitigation_engine = MitigationEngine(dry_run=False)

@shared_task(name="quarantine_device", queue="celery", acks_late=True)
def quarantine_device(ip: str, mac: str = "unknown"):
    logger.info(f"[QUARANTINE] Received task for {ip}")
    verdict = ThreatVerdict(severity="CRITICAL", confidence=1.0, recommended_action="isolate")
    result = _mitigation_engine.isolate({"ip_address": ip, "mac_address": mac}, verdict)
    return {"ip": ip, "status": result.details.get("status"), "details": result.details}

@shared_task(name="lift_quarantine", queue="celery", acks_late=True)
def lift_quarantine(ip: str):
    logger.info(f"[LIFT] Received lift task for {ip}")
    result = _mitigation_engine.lift_isolation(ip)
    return result
