from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_or_404, require
from app.core.errors import AppError
from app.core.security import hash_password
from app.db.session import get_db
from app.models import AuditLog, User, UserRole
from app.schemas import AuditOut, Page, UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(tags=["users"])
admin_only = require(UserRole.admin)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin_only)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin_only)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise AppError(409, "USERNAME_TAKEN", "用户名已存在")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, "user.create", user=me, target_type="user", target_id=user.id, detail={"username": user.username, "role": user.role.value}, ip=client_ip(request))
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin_only)):
    user = get_or_404(db, User, user_id, "用户")
    if user.id == me.id and (body.role not in (None, UserRole.admin) or body.is_active is False):
        raise AppError(400, "CANNOT_DEMOTE_SELF", "不能降低自己的权限或停用自己的账号")
    changes = {}
    if body.role is not None:
        user.role, changes["role"] = body.role, body.role.value
    if body.is_active is not None:
        user.is_active, changes["is_active"] = body.is_active, body.is_active
    if body.password:
        user.password_hash, changes["password"] = hash_password(body.password), "已重置"
    audit.record(db, "user.update", user=me, target_type="user", target_id=user.id, detail=changes, ip=client_ip(request))
    db.commit()
    return user


@router.get("/audit-logs", response_model=Page[AuditOut])
def audit_logs(page: int = 1, size: int = 50, action: str | None = None, db: Session = Depends(get_db), _: User = Depends(admin_only)):
    size = max(1, min(size, 200))
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action == action)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    items = db.scalars(q.order_by(AuditLog.id.desc()).offset((max(page, 1) - 1) * size).limit(size)).all()
    return Page(items=[AuditOut.model_validate(x) for x in items], total=total, page=page, size=size)
