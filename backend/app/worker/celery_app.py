"""Celery 应用。M0 阶段只有心跳任务，IMAP 同步、检测、处置任务在 M2 加入。"""
from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery("phishguard", broker=settings.redis_url, backend=settings.redis_url)
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
    },
)


@celery_app.task(name="phishguard.heartbeat")
def heartbeat() -> str:
    return "ok"
