import os
from celery import Celery
from celery.schedules import crontab

REDIS_HOST = os.getenv("SIN_REDIS_HOST", "localhost")
REDIS_PASSWORD = os.getenv("SIN_REDIS_PASSWORD", "")

if REDIS_PASSWORD:
    BROKER_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:6379/0"
else:
    BROKER_URL = f"redis://{REDIS_HOST}:6379/0"

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

celery_app.conf.beat_schedule = {
    "scan-network-every-5-minutes": {
        "task": "run_network_scan",
        "schedule": 300.0,
        "args": (os.getenv("SIN_SCAN_SUBNET", "192.168.30"),)
    },
}
