"""接口依赖：数据库会话、当前用户、角色校验。"""
from collections.abc import Callable

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.security import decode_token
from app.db.session import get_db
from app.models import User, UserRole

_bearer = HTTPBearer(auto_error=False)
_RANK = {UserRole.viewer: 0, UserRole.operator: 1, UserRole.admin: 2}


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)) -> User:
    if cred is None:
        raise AppError(401, "UNAUTHORIZED", "请先登录")
    try:
        payload = decode_token(cred.credentials, "access")
    except jwt.ExpiredSignatureError:
        raise AppError(401, "TOKEN_EXPIRED", "登录已过期，请重新登录") from None
    except jwt.PyJWTError:
        raise AppError(401, "UNAUTHORIZED", "登录状态无效，请重新登录") from None
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise AppError(401, "UNAUTHORIZED", "账号不存在或已停用")
    return user


def require(role: UserRole) -> Callable[..., User]:
    """要求当前用户角色不低于 role（viewer < operator < admin）。"""

    def dep(user: User = Depends(current_user)) -> User:
        if _RANK[user.role] < _RANK[role]:
            raise AppError(403, "FORBIDDEN", "当前账号没有执行此操作的权限")
        return user

    return dep


def get_or_404(db: Session, model, obj_id: int, what: str):
    obj = db.get(model, obj_id)
    if obj is None:
        raise AppError(404, "NOT_FOUND", f"{what}不存在")
    return obj


def client_ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")
