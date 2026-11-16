"""检测流水线：解析 → 白名单 → 检测 → 入库 → 处置。

api（手动检测）和 worker（自动检测）共用同一个 Engine 实例工厂。
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import phishguard_detector
from app.core.config import get_settings
from app.models import AllowlistEntry, AllowlistType, Detection, Email, EmailStatus, Mailbox, Verdict
from app.services import settings as settings_svc
from app.services.imap import MailboxClient
from phishguard_detector import domains as D
from phishguard_detector.engine import Engine
from phishguard_detector.fusion import FusionConfig
from phishguard_detector.parser import ParsedEmail, parse_bytes

log = logging.getLogger("phishguard.detection")


@lru_cache
def get_engine() -> Engine:
    eng = Engine.from_model_dir(get_settings().model_dir)
    log.info("检测引擎已加载，模型：%s", [m.name for m in eng.models] or "无（仅规则）")
    return eng


def engine_for(db: Session) -> Engine:
    """共享已加载的模型，按当前系统设置生成独立的融合配置（不修改共享实例，避免并发请求互相影响）。"""
    s = settings_svc.get_all(db)
    cfg = FusionConfig(phishing_threshold=s["phishing_threshold"], suspicious_threshold=s["suspicious_threshold"])
    return Engine(get_engine().models, cfg)


def match_allowlist(db: Session, pe: ParsedEmail) -> AllowlistEntry | None:
    now = datetime.now(UTC)
    candidates = {(AllowlistType.sender, pe.from_addr), (AllowlistType.domain, pe.from_domain),
                  (AllowlistType.domain, D.registrable(pe.from_domain))}
    conds = [((AllowlistEntry.type == t) & (AllowlistEntry.value == v)) for t, v in candidates if v]
    if not conds:
        return None
    entry = db.scalar(select(AllowlistEntry).where(or_(*conds))
                      .where(or_(AllowlistEntry.expires_at.is_(None), AllowlistEntry.expires_at > now)).limit(1))
    if entry:
        entry.hit_count += 1
    return entry


def store_email(db: Session, mailbox: Mailbox, folder: str, uidvalidity: int, uid: int, size: int,
                pe: ParsedEmail) -> Email | None:
    """写入 emails 表；同一封邮件重复同步时返回 None（幂等）。"""
    received = None
    if pe.date:
        try:
            received = datetime.fromisoformat(pe.date)
        except ValueError:
            received = None
    email = Email(mailbox_id=mailbox.id, folder=folder, uid_validity=uidvalidity, uid=uid, size=size,
                  message_id=pe.message_id[:998], from_addr=pe.from_addr[:320], from_name=pe.from_name[:512],
                  reply_to=pe.reply_to[:320], to_addrs=pe.to_addrs[:50], subject=pe.subject,
                  received_at=received or datetime.now(UTC), body_excerpt=pe.text[:4000],
                  urls=[u.__dict__ for u in pe.urls[:100]], attachments=[a.__dict__ for a in pe.attachments[:50]],
                  auth_results=pe.auth_results)
    try:
        with db.begin_nested():
            db.add(email)
            db.flush()
    except IntegrityError:
        return None
    return email


def detect_and_store(db: Session, email: Email, pe: ParsedEmail, observe_mode: bool) -> Detection:
    allow = match_allowlist(db, pe)
    det = engine_for(db).detect_parsed(pe, allowlisted=allow is not None)
    v = det.verdict
    row = Detection(email_id=email.id, risk_score=v.risk_score, verdict=Verdict(v.verdict), rule_score=v.rule_score,
                    rule_hits=[h.__dict__ for h in det.rules.hits], model_scores=v.model_scores, summary=v.summary,
                    allowlisted=v.allowlisted, engine_version=phishguard_detector.__version__,
                    latency_ms=round(det.latency_ms, 1), observe_mode=observe_mode)
    db.add(row)
    email.status = EmailStatus.detected
    db.flush()
    return row


def save_raw(email: Email, raw: bytes) -> str:
    d = Path(get_settings().raw_mail_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{email.id}.eml"
    p.write_bytes(raw)
    os.chmod(p, 0o600)
    return str(p)


def act(db: Session, mc: MailboxClient, mailbox: Mailbox, email: Email, det: Detection, raw: bytes) -> None:
    """根据判定处置。观察模式下只记录不处置。单封失败不影响其他邮件。"""
    if det.observe_mode:
        return
    try:
        if det.verdict == Verdict.phishing:
            email.raw_path = save_raw(email, raw)
            email.quarantine_uid = mc.move(email.folder, email.uid, mailbox.quarantine_folder)
            email.status = EmailStatus.quarantined
            notify(db, email, det)
        elif det.verdict == Verdict.suspicious:
            if mc.flag(email.folder, email.uid):
                email.status = EmailStatus.flagged
    except Exception as exc:  # noqa: BLE001
        email.action_error = f"处置失败：{type(exc).__name__}: {exc}"[:500]
        log.warning("邮件 %s 处置失败：%s", email.id, exc)


def notify(db: Session, email: Email, det: Detection) -> None:
    """企业微信 / 钉钉群机器人告警。只发送主题、发件人和风险分，不发送正文。"""
    url = settings_svc.get_all(db).get("webhook_url") or ""
    if not url.startswith("https://"):
        return
    text = f"【PhishGuard】已隔离一封钓鱼邮件\n发件人：{email.from_addr}\n主题：{email.subject[:100]}\n风险分：{det.risk_score}\n{det.summary[:200]}"
    body = {"msgtype": "text", "text": {"content": text}}
    try:
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()  # noqa: S310 - URL 由管理员配置且限定 https
    except Exception as exc:  # noqa: BLE001
        log.warning("告警推送失败：%s", exc)


def process_raw(db: Session, mc: MailboxClient, mailbox: Mailbox, folder: str, uidvalidity: int, uid: int,
                size: int, raw: bytes, observe_mode: bool) -> tuple[Email, Detection] | None:
    """处理一封新邮件；同一封邮件重复同步时返回 None。"""
    pe = parse_bytes(raw)
    email = store_email(db, mailbox, folder, uidvalidity, uid, size, pe)
    if email is None:
        return None
    det = detect_and_store(db, email, pe, observe_mode)
    act(db, mc, mailbox, email, det, raw)
    return email, det
