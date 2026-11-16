"""Celery 应用与定时任务。"""
from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery("phishguard", broker=settings.redis_url, backend=settings.redis_url, include=["app.worker.tasks"])
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Shanghai",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    beat_schedule={
        "heartbeat": {"task": "phishguard.heartbeat", "schedule": 60.0},
        "sync-all-mailboxes": {"task": "phishguard.sync_all", "schedule": float(settings.sync_interval_seconds)},
        "cleanup-raw-mail": {"task": "phishguard.cleanup_raw", "schedule": crontab(hour=3, minute=30)},
    },
)


@celery_app.task(name="phishguard.heartbeat")
def heartbeat() -> str:
    return "ok"
