from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.api.deps import client_ip, get_or_404, require
from app.core.errors import AppError
from app.core.security import decrypt_credential
from app.db.session import get_db
from app.models import Detection, Email, EmailStatus, Feedback, FeedbackLabel, Mailbox, User, UserRole, Verdict
from app.schemas import BatchResult, EmailBrief, EmailDetail, FeedbackIn, IdsIn, Page
from app.services import audit
from app.services.imap import ImapError, MailboxClient

router = APIRouter(tags=["emails"])
viewer, operator, admin = require(UserRole.viewer), require(UserRole.operator), require(UserRole.admin)
MAX_BATCH_IMAP = 50


def _brief(e: Email) -> EmailBrief:
    b = EmailBrief.model_validate(e)
    if e.detection:
        b.risk_score, b.verdict = e.detection.risk_score, e.detection.verdict
    return b


@router.get("/emails", response_model=Page[EmailBrief])
def list_emails(page: int = 1, size: int = 20, verdict: Verdict | None = None, status: EmailStatus | None = None,
                mailbox_id: int | None = None, q: str | None = None, date_from: datetime | None = None,
                date_to: datetime | None = None, db: Session = Depends(get_db), _: User = Depends(viewer)):
    size = max(1, min(size, 100))
    stmt = select(Email).outerjoin(Detection).options(joinedload(Email.detection))
    if verdict:
        stmt = stmt.where(Detection.verdict == verdict)
    if status:
        stmt = stmt.where(Email.status == status)
    if mailbox_id:
        stmt = stmt.where(Email.mailbox_id == mailbox_id)
    if q:
        like = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(Email.subject.ilike(like), Email.from_addr.ilike(like), Email.from_name.ilike(like)))
    if date_from:
        stmt = stmt.where(Email.received_at >= date_from)
    if date_to:
        stmt = stmt.where(Email.received_at < date_to)
    total = db.scalar(select(func.count()).select_from(stmt.with_only_columns(Email.id).subquery())) or 0
    rows = db.scalars(stmt.order_by(Email.received_at.desc().nullslast(), Email.id.desc())
                      .offset((max(page, 1) - 1) * size).limit(size)).unique().all()
    return Page(items=[_brief(e) for e in rows], total=total, page=page, size=size)


@router.get("/emails/{email_id}", response_model=EmailDetail)
def get_email(email_id: int, db: Session = Depends(get_db), _: User = Depends(viewer)):
    e = get_or_404(db, Email, email_id, "邮件")
    d = EmailDetail.model_validate(e)
    if e.detection:
        d.risk_score, d.verdict = e.detection.risk_score, e.detection.verdict
    return d


@router.post("/emails/{email_id}/feedback", status_code=201)
def feedback(email_id: int, body: FeedbackIn, request: Request, db: Session = Depends(get_db), me: User = Depends(operator)):
    e = get_or_404(db, Email, email_id, "邮件")
    db.add(Feedback(email_id=e.id, label=body.label, comment=body.comment, created_by=me.id,
                    score_at_feedback=e.detection.risk_score if e.detection else None))
    audit.record(db, "email.feedback", user=me, target_type="email", target_id=e.id, detail={"label": body.label.value}, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.get("/quarantine", response_model=Page[EmailBrief])
def quarantine(page: int = 1, size: int = 20, db: Session = Depends(get_db), _: User = Depends(operator)):
    return list_emails(page=page, size=size, status=EmailStatus.quarantined, db=db, _=_)


def _imap_batch(db: Session, ids: list[int], op) -> BatchResult:
    """按邮箱分组，每个邮箱只建立一次 IMAP 连接。"""
    if len(ids) > MAX_BATCH_IMAP:
        raise AppError(400, "BATCH_TOO_LARGE", f"一次最多处理 {MAX_BATCH_IMAP} 封邮件")
    emails = db.scalars(select(Email).where(Email.id.in_(ids), Email.status == EmailStatus.quarantined)).all()
    result = BatchResult(ok=[], failed={i: "邮件不存在或不在隔离区" for i in ids if i not in {e.id for e in emails}})
    by_mb: dict[int, list[Email]] = {}
    for e in emails:
        by_mb.setdefault(e.mailbox_id, []).append(e)
    for mb_id, group in by_mb.items():
        mb = db.get(Mailbox, mb_id)
        try:
            with MailboxClient(mb.imap_host, mb.imap_port, mb.use_ssl, mb.username, decrypt_credential(mb.credential_enc)) as mc:
                for e in group:
                    try:
                        op(mc, mb, e)
                        result.ok.append(e.id)
                    except Exception as exc:  # noqa: BLE001
                        result.failed[e.id] = f"{type(exc).__name__}: {exc}"[:200]
        except ImapError as exc:
            for e in group:
                result.failed[e.id] = str(exc)
    return result


def _locate(mc: MailboxClient, mb: Mailbox, e: Email) -> int:
    uid = e.quarantine_uid or mc.find_uid(mb.quarantine_folder, e.message_id)
    if not uid:
        raise LookupError("在隔离文件夹中找不到这封邮件，可能已被手动移动或删除")
    return uid


@router.post("/quarantine/release", response_model=BatchResult)
def release(body: IdsIn, request: Request, db: Session = Depends(get_db), me: User = Depends(operator)):
    def op(mc, mb, e):
        mc.move(mb.quarantine_folder, _locate(mc, mb, e), e.folder)
        e.status, e.quarantine_uid = EmailStatus.released, None
        db.add(Feedback(email_id=e.id, label=FeedbackLabel.false_positive, comment="管理员从隔离区放行", created_by=me.id,
                        score_at_feedback=e.detection.risk_score if e.detection else None))

    res = _imap_batch(db, body.ids, op)
    audit.record(db, "quarantine.release", user=me, target_type="email", target_id=",".join(map(str, res.ok)),
                 detail={"ok": res.ok, "failed": {str(k): v for k, v in res.failed.items()}}, ip=client_ip(request))
    db.commit()
    return res


@router.post("/quarantine/delete", response_model=BatchResult)
def delete(body: IdsIn, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)):
    def op(mc, mb, e):
        mc.delete(mb.quarantine_folder, _locate(mc, mb, e))
        if e.raw_path:
            Path(e.raw_path).unlink(missing_ok=True)
        e.status, e.raw_path, e.quarantine_uid = EmailStatus.deleted, None, None

    res = _imap_batch(db, body.ids, op)
    audit.record(db, "quarantine.delete", user=me, target_type="email", target_id=",".join(map(str, res.ok)),
                 detail={"ok": res.ok, "failed": {str(k): v for k, v in res.failed.items()}}, ip=client_ip(request))
    db.commit()
    return res
