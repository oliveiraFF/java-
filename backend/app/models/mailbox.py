import enum
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class MailboxStatus(str, enum.Enum):
    active = "active"
    paused = "paused"
    error = "error"


class Mailbox(TimestampMixin, Base):
    __tablename__ = "mailboxes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(BigInteger, default=1, server_default="1", nullable=False)
    address: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    imap_host: Mapped[str] = mapped_column(String(255), nullable=False)
    imap_port: Mapped[int] = mapped_column(Integer, default=993, nullable=False)
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)  # 多数服务商与邮箱地址相同
    credential_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # Fernet 加密的授权码
    folders: Mapped[list] = mapped_column(JSONB, default=lambda: ["INBOX"], nullable=False)
    quarantine_folder: Mapped[str] = mapped_column(String(255), default="PhishGuard-隔离", nullable=False)
    sync_state: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)  # {folder: {uidvalidity, last_uid}}
    capabilities: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    status: Mapped[MailboxStatus] = mapped_column(Enum(MailboxStatus, name="mailbox_status"), default=MailboxStatus.active, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
