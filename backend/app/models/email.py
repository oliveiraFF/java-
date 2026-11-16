import enum
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Float, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class EmailStatus(str, enum.Enum):
    pending = "pending"  # 已拉取，等待检测
    detected = "detected"  # 已检测，未处置
    quarantined = "quarantined"  # 已移入隔离文件夹
    flagged = "flagged"  # 已打可疑标记
    released = "released"  # 管理员放行
    deleted = "deleted"  # 管理员删除
    error = "error"


class Verdict(str, enum.Enum):
    safe = "safe"
    suspicious = "suspicious"
    phishing = "phishing"


class Email(TimestampMixin, Base):
    __tablename__ = "emails"
    __table_args__ = (
        UniqueConstraint("mailbox_id", "folder", "uid_validity", "uid", name="uq_email_imap_uid"),
        Index("ix_emails_received_at", "received_at"),
        Index("ix_emails_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, default=1, server_default="1", nullable=False)
    mailbox_id: Mapped[int] = mapped_column(ForeignKey("mailboxes.id", ondelete="CASCADE"), nullable=False, index=True)
    folder: Mapped[str] = mapped_column(String(255), nullable=False)
    uid_validity: Mapped[int] = mapped_column(BigInteger, nullable=False)
    uid: Mapped[int] = mapped_column(BigInteger, nullable=False)
    message_id: Mapped[str] = mapped_column(String(998), default="", nullable=False)
    from_addr: Mapped[str] = mapped_column(String(320), default="", nullable=False)
    from_name: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    reply_to: Mapped[str] = mapped_column(String(320), default="", nullable=False)
    to_addrs: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    body_excerpt: Mapped[str] = mapped_column(Text, default="", nullable=False)
    urls: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    attachments: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    auth_results: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[EmailStatus] = mapped_column(Enum(EmailStatus, name="email_status"), default=EmailStatus.pending, nullable=False)
    raw_path: Mapped[str | None] = mapped_column(String(512), nullable=True)  # 仅隔离邮件保存原文
    quarantine_uid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # 在隔离文件夹中的 UID
    action_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    detection: Mapped["Detection | None"] = relationship(back_populates="email", uselist=False, cascade="all, delete-orphan")


class Detection(TimestampMixin, Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict, name="verdict"), nullable=False, index=True)
    rule_score: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    rule_hits: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    model_scores: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowlisted: Mapped[bool] = mapped_column(default=False, nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    observe_mode: Mapped[bool] = mapped_column(default=False, nullable=False)  # 检测时处于观察模式（不处置）

    email: Mapped[Email] = relationship(back_populates="detection")


class FeedbackLabel(str, enum.Enum):
    confirmed_phishing = "confirmed_phishing"
    false_positive = "false_positive"
    false_negative = "false_negative"


class Feedback(TimestampMixin, Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    label: Mapped[FeedbackLabel] = mapped_column(Enum(FeedbackLabel, name="feedback_label"), nullable=False)
    comment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    score_at_feedback: Mapped[int | None] = mapped_column(Integer, nullable=True)
