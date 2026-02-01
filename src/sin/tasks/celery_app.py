import os
from celery import Celery

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
