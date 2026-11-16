import enum
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AllowlistType(str, enum.Enum):
    sender = "sender"  # 完整发件地址
    domain = "domain"  # 发件域名
    url_domain = "url_domain"  # 链接域名


class AllowlistEntry(TimestampMixin, Base):
    __tablename__ = "allowlist"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "value", name="uq_allowlist_value"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, default=1, server_default="1", nullable=False)
    type: Mapped[AllowlistType] = mapped_column(Enum(AllowlistType, name="allowlist_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(320), nullable=False)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, default=1, server_default="1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="", nullable=False)  # 冗余，用户删除后仍可追溯
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
