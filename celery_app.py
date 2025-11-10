# celery_app.py
from celery import Celery
import os

def make_celery(app=None):
    """
    Create and configure a Celery instance.
    This function avoids circular imports.
    """
    celery = Celery(
        "vulndashboard",
        broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
        backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
        include=["tasks"]  # Ensure Celery knows where to find your tasks
    )

    if app:
        celery.conf.update(app.config)

        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask

    print("✅ Celery task 'vulndashboard.run_scan_task' registered successfully.")
    return celery


# Allow worker to start directly from this file
celery = make_celery()
