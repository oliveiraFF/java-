"""总览统计。"""
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import Date, cast, func, select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db.session import get_db
from app.models import Detection, Email, EmailStatus, Feedback, FeedbackLabel, Mailbox, MailboxStatus, User, UserRole, Verdict

router = APIRouter(prefix="/stats", tags=["stats"])
viewer = require(UserRole.viewer)


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(viewer)):
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since30 = now - timedelta(days=30)

    def count(*conds):
        return db.scalar(select(func.count(Email.id)).outerjoin(Detection).where(*conds)) or 0

    quarantined_30 = count(Email.created_at >= since30, Detection.verdict == Verdict.phishing)
    false_pos_30 = db.scalar(select(func.count(Feedback.id)).where(Feedback.created_at >= since30,
                                                                   Feedback.label == FeedbackLabel.false_positive)) or 0
    return {
        "today": {"detected": count(Email.created_at >= today),
                  "phishing": count(Email.created_at >= today, Detection.verdict == Verdict.phishing),
                  "suspicious": count(Email.created_at >= today, Detection.verdict == Verdict.suspicious)},
        "quarantined_now": count(Email.status == EmailStatus.quarantined),
        "pending_review": count(Detection.verdict == Verdict.suspicious, Email.status.in_([EmailStatus.detected, EmailStatus.flagged])),
        "false_positive_rate_30d": round(false_pos_30 / quarantined_30, 4) if quarantined_30 else None,
        "mailboxes": {s.value: db.scalar(select(func.count(Mailbox.id)).where(Mailbox.status == s)) or 0 for s in MailboxStatus},
    }


@router.get("/trend")
def trend(days: int = 30, db: Session = Depends(get_db), _: User = Depends(viewer)):
    days = max(1, min(days, 180))
    since = (datetime.now(UTC) - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    day = cast(Email.created_at, Date)
    rows = db.execute(select(day, Detection.verdict, func.count(Email.id)).join(Detection)
                      .where(Email.created_at >= since).group_by(day, Detection.verdict)).all()
    series = {(since + timedelta(days=i)).date().isoformat(): {"safe": 0, "suspicious": 0, "phishing": 0} for i in range(days)}
    for d, v, n in rows:
        if d.isoformat() in series:
            series[d.isoformat()][v.value] = n
    return [{"date": k, **v} for k, v in series.items()]


@router.get("/top-rules")
def top_rules(days: int = 30, limit: int = 10, db: Session = Depends(get_db), _: User = Depends(viewer)):
    since = datetime.now(UTC) - timedelta(days=max(1, min(days, 180)))
    c: Counter = Counter()
    names = {}
    for hits in db.scalars(select(Detection.rule_hits).where(Detection.created_at >= since, Detection.verdict != Verdict.safe)):
        for h in hits or []:
            c[h["rule_id"]] += 1
            names[h["rule_id"]] = h["name"]
    return [{"rule_id": rid, "name": names[rid], "count": n} for rid, n in c.most_common(max(1, min(limit, 30)))]
