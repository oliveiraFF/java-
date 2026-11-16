from datetime import UTC, datetime, timedelta

import jwt
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_user
from app.core.errors import AppError
from app.core.security import create_token, decode_token, hash_password, verify_password
from app.db.session import get_db
from app.models import User
from app.schemas import LoginIn, RefreshIn, TokenOut, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILURES = 5
LOCK_MINUTES = 15
# 用户不存在时也做一次哈希，避免通过响应时间判断用户名是否存在
_DUMMY_HASH = hash_password("timing-equalizer")


def _tokens(user: User) -> TokenOut:
    return TokenOut(access_token=create_token(user.id, user.role.value, "access"),
                    refresh_token=create_token(user.id, user.role.value, "refresh"),
                    user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    now = datetime.now(UTC)
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None:
        verify_password(body.password, _DUMMY_HASH)
        raise AppError(401, "LOGIN_FAILED", "用户名或密码错误")
    if user.locked_until and user.locked_until > now:
        minutes = max(1, int((user.locked_until - now).total_seconds() // 60) + 1)
        raise AppError(423, "ACCOUNT_LOCKED", f"登录失败次数过多，请 {minutes} 分钟后再试")
    if not verify_password(body.password, user.password_hash) or not user.is_active:
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILURES:
            user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
            user.failed_logins = 0
            audit.record(db, "user.locked", user=user, target_type="user", target_id=user.id, ip=client_ip(request))
        db.commit()
        raise AppError(401, "LOGIN_FAILED", "用户名或密码错误")
    user.failed_logins, user.locked_until = 0, None
    audit.record(db, "user.login", user=user, target_type="user", target_id=user.id, ip=client_ip(request))
    db.commit()
    return _tokens(user)


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token, "refresh")
    except jwt.PyJWTError:
        raise AppError(401, "UNAUTHORIZED", "登录已过期，请重新登录") from None
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise AppError(401, "UNAUTHORIZED", "账号不存在或已停用")
    return _tokens(user)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
