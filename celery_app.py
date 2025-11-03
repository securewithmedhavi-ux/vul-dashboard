# celery_app.py
import os
from celery import Celery

BROKER = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
BACKEND = os.getenv("CELERY_RESULT_BACKEND", BROKER)

celery = Celery(
    "vulndashboard",
    broker=BROKER,
    backend=BACKEND,
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# ✅ Import task so it’s properly registered with this Celery instance
try:
    from tasks import run_scan_task
    celery.register_task(run_scan_task)
    print("✅ Celery task 'vulndashboard.run_scan_task' registered successfully.")
except Exception as e:
    print(f"[WARN] Task registration failed: {e}")

if __name__ == "__main__":
    celery.start()