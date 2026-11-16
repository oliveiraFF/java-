from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import AuditLog, User


def record(db: Session, action: str, *, user: User | None = None, target_type: str = "", target_id: str | int = "",
           detail: dict | None = None, ip: str = "") -> None:
    """写一条审计日志（随调用方事务一起提交）。detail 中不得包含密码、授权码等敏感信息。"""
    db.add(AuditLog(created_at=datetime.now(UTC), user_id=user.id if user else None, username=user.username if user else "system",
                    action=action, target_type=target_type, target_id=str(target_id), detail=detail or {}, ip=ip))
