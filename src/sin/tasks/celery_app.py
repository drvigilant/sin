import os
from celery import Celery
from celery.schedules import crontab

# Define the Redis URL (using the docker container name 'redis')
REDIS_HOST = os.getenv("SIN_REDIS_HOST", "localhost")
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
)

# NEW: The Schedule Configuration
celery_app.conf.beat_schedule = {
    "scan-network-every-5-minutes": {
        "task": "run_network_scan",  # Name of the task in jobs.py
        "schedule": 300.0,           # Run every 300 seconds (5 mins)
        "args": ("172.21.41.0/24",)  # Your subnet
    },
}
