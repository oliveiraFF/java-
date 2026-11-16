"""后台任务：定时同步所有邮箱、单个邮箱同步、隔离原文清理。"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import redis
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import decrypt_credential
from app.db.session import SessionLocal
from app.models import Email, Mailbox, MailboxStatus
from app.services import audit
from app.services import settings as settings_svc
from app.services.detection import process_raw
from app.services.imap import ImapError, MailboxClient
from app.worker.celery_app import celery_app

log = logging.getLogger("phishguard.worker")
MAX_CONSECUTIVE_FAILURES = 5


def _lock(mailbox_id: int):
    """同一邮箱同一时间只允许一个同步任务。"""
    r = redis.Redis.from_url(get_settings().redis_url)
    return r.lock(f"phishguard:sync:{mailbox_id}", timeout=600, blocking=False)


@celery_app.task(name="phishguard.sync_all")
def sync_all() -> int:
    with SessionLocal() as db:
        ids = db.scalars(select(Mailbox.id).where(Mailbox.status == MailboxStatus.active)).all()
    for mid in ids:
        sync_mailbox.delay(mid)
    return len(ids)


@celery_app.task(name="phishguard.sync_mailbox")
def sync_mailbox(mailbox_id: int) -> dict:
    lock = _lock(mailbox_id)
    if not lock.acquire(blocking=False):
        return {"skipped": "already running"}
    try:
        return _sync(mailbox_id)
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


def _sync(mailbox_id: int) -> dict:
    stats = {"new": 0, "phishing": 0, "suspicious": 0, "errors": 0}
    with SessionLocal() as db:
        mb = db.get(Mailbox, mailbox_id)
        if mb is None or mb.status != MailboxStatus.active:
            return {"skipped": "inactive"}
        observe = bool(settings_svc.get_all(db)["observe_mode"])
        try:
            with MailboxClient(mb.imap_host, mb.imap_port, mb.use_ssl, mb.username, decrypt_credential(mb.credential_enc)) as mc:
                for folder in mb.folders:
                    state, messages = mc.fetch_new(folder, (mb.sync_state or {}).get(folder))
                    if state.pop("reset", False):
                        audit.record(db, "mailbox.uidvalidity_reset", target_type="mailbox", target_id=mb.id, detail={"folder": folder})
                    mb.sync_state = {**(mb.sync_state or {}), folder: state}
                    db.commit()
                    for msg in messages:
                        try:
                            result = process_raw(db, mc, mb, folder, state["uidvalidity"], msg.uid, msg.size, msg.raw, observe)
                            if result is not None:
                                stats["new"] += 1
                                v = result[1].verdict.value
                                stats[v] = stats.get(v, 0) + 1
                        except Exception:  # noqa: BLE001 - 单封邮件出错不能中断整个同步
                            db.rollback()
                            stats["errors"] += 1
                            log.exception("邮箱 %s 邮件 UID %s 处理失败", mb.id, msg.uid)
                        # 每封邮件处理完就推进游标，崩溃重启后不会重复处理
                        state["last_uid"] = max(state["last_uid"], msg.uid)
                        mb.sync_state = {**(mb.sync_state or {}), folder: dict(state)}
                        db.commit()
            mb.last_synced_at, mb.last_error, mb.consecutive_failures = datetime.now(UTC), None, 0
        except ImapError as exc:
            db.rollback()
            mb = db.get(Mailbox, mailbox_id)
            mb.consecutive_failures += 1
            mb.last_error = str(exc)
            if mb.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                mb.status = MailboxStatus.error
                audit.record(db, "mailbox.auto_paused", target_type="mailbox", target_id=mb.id, detail={"error": str(exc)})
            log.warning("邮箱 %s 同步失败（连续 %s 次）：%s", mb.id, mb.consecutive_failures, exc)
        db.commit()
    return stats


@celery_app.task(name="phishguard.cleanup_raw")
def cleanup_raw() -> int:
    """删除超过保留期的隔离邮件原文。"""
    with SessionLocal() as db:
        days = int(settings_svc.get_all(db)["raw_retention_days"])
        cutoff = datetime.now(UTC) - timedelta(days=days)
        rows = db.scalars(select(Email).where(Email.raw_path.is_not(None), Email.created_at < cutoff)).all()
        for e in rows:
            try:
                Path(e.raw_path).unlink(missing_ok=True)
            except OSError:
                continue
            e.raw_path = None
        db.commit()
    return len(rows)
