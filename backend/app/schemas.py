"""接口请求/响应模型。"""
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.models import AllowlistType, EmailStatus, FeedbackLabel, MailboxStatus, UserRole, Verdict

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------- 认证与用户 ----------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserOut"


class RefreshIn(BaseModel):
    refresh_token: str


class UserOut(ORM):
    id: int
    username: str
    role: UserRole
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: UserRole = UserRole.viewer


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


# ---------- 邮箱 ----------
class MailboxIn(BaseModel):
    address: str = Field(min_length=3, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    imap_host: str = Field(min_length=1, max_length=255)
    imap_port: int = Field(default=993, ge=1, le=65535)
    use_ssl: bool = True
    username: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=1, max_length=512, description="邮箱授权码，只写不读")
    folders: list[str] = Field(default_factory=lambda: ["INBOX"], min_length=1)
    quarantine_folder: str = Field(default="PhishGuard-隔离", min_length=1, max_length=255)


class MailboxUpdate(BaseModel):
    status: MailboxStatus | None = None
    password: str | None = Field(default=None, min_length=1, max_length=512)
    folders: list[str] | None = None


class MailboxOut(ORM):
    id: int
    address: str
    imap_host: str
    imap_port: int
    use_ssl: bool
    username: str
    folders: list[str]
    quarantine_folder: str
    capabilities: list[str]
    status: MailboxStatus
    last_error: str | None
    last_synced_at: datetime | None
    created_at: datetime


class ConnectionTestOut(BaseModel):
    ok: bool
    message: str
    capabilities: list[str] = []
    supports_move: bool = False
    supports_idle: bool = False
    folders: list[str] = []


# ---------- 邮件与检测 ----------
class DetectionOut(ORM):
    risk_score: int
    verdict: Verdict
    rule_score: int
    rule_hits: list[dict]
    model_scores: dict
    summary: str
    allowlisted: bool
    observe_mode: bool
    latency_ms: float


class EmailBrief(ORM):
    id: int
    mailbox_id: int
    folder: str
    from_addr: str
    from_name: str
    subject: str
    received_at: datetime | None
    status: EmailStatus
    risk_score: int | None = None
    verdict: Verdict | None = None


class EmailDetail(EmailBrief):
    reply_to: str
    to_addrs: list[str]
    message_id: str
    body_excerpt: str
    urls: list[dict]
    attachments: list[dict]
    auth_results: dict
    action_error: str | None
    detection: DetectionOut | None


class FeedbackIn(BaseModel):
    label: FeedbackLabel
    comment: str = Field(default="", max_length=2000)


class IdsIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)


class BatchResult(BaseModel):
    ok: list[int]
    failed: dict[int, str]


class DetectTextIn(BaseModel):
    raw: str | None = Field(default=None, description="完整邮件原文（含邮件头）")
    subject: str | None = None
    body: str | None = None
    sender: str | None = None


# ---------- 白名单与设置 ----------
class AllowlistIn(BaseModel):
    type: AllowlistType
    value: str = Field(min_length=1, max_length=320)
    reason: str = Field(default="", max_length=500)
    expires_at: datetime | None = None


class AllowlistOut(ORM):
    id: int
    type: AllowlistType
    value: str
    reason: str
    expires_at: datetime | None
    hit_count: int
    created_at: datetime


class SettingsIn(BaseModel):
    phishing_threshold: int | None = Field(default=None, ge=1, le=100)
    suspicious_threshold: int | None = Field(default=None, ge=1, le=100)
    observe_mode: bool | None = None
    raw_retention_days: int | None = Field(default=None, ge=1, le=365)
    webhook_url: str | None = Field(default=None, max_length=1000)


class AuditOut(ORM):
    id: int
    created_at: datetime
    username: str
    action: str
    target_type: str
    target_id: str
    detail: dict
    ip: str


TokenOut.model_rebuild()
