import os
from celery import Celery
from celery.schedules import crontab

REDIS_HOST     = os.getenv("SIN_REDIS_HOST", "localhost")
REDIS_PORT     = os.getenv("SIN_REDIS_PORT", "6379")
REDIS_PASSWORD = os.getenv("SIN_REDIS_PASSWORD", "")

if REDIS_PASSWORD:
    BROKER_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
else:
    BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"

celery_app = Celery(
    "sin_tasks",
    broker=BROKER_URL,
    backend=BROKER_URL,
    include=["sin.tasks.jobs"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)

# ── ADDITION 1: tell redbeat which Redis to use ──────────────────────────────
celery_app.conf.redbeat_redis_url = BROKER_URL
# ─────────────────────────────────────────────────────────────────────────────

celery_app.conf.beat_schedule = {
    "scan-network-every-5-minutes": {
        "task": "run_network_scan",
        "schedule": 300.0,
        "args": (os.getenv("SIN_SCAN_SUBNET", "192.168.30"),)
    },
}

# ── ADDITION 2: use Redis-backed scheduler instead of the pickle file ─────────
celery_app.conf.beat_scheduler = "redbeat.RedBeatScheduler"
# ─────────────────────────────────────────────────────────────────────────────

celery_app.conf.task_acks_late = True
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.beat_max_loop_interval = 300

# ── ADDITION 3: lock interval so redbeat and beat_max_loop_interval agree ────
celery_app.conf.redbeat_lock_timeout = 450   # 1.5× beat_max_loop_interval
# ─────────────────────────────────────────────────────────────────────────────
