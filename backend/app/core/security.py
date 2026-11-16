"""密码哈希、JWT 令牌、邮箱授权码加解密。"""
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from cryptography.fernet import Fernet

from app.core.config import get_settings

JWT_ALG = "HS256"


def create_token(user_id: int, role: str, kind: str = "access") -> str:
    s = get_settings()
    ttl = timedelta(minutes=s.jwt_access_minutes) if kind == "access" else timedelta(days=s.jwt_refresh_days)
    now = datetime.now(UTC)
    payload = {"sub": str(user_id), "role": role, "typ": kind, "iat": now, "exp": now + ttl}
    return jwt.encode(payload, s.jwt_secret, algorithm=JWT_ALG)


def decode_token(token: str, kind: str = "access") -> dict:
    """校验签名、有效期和令牌类型；失败抛 jwt.PyJWTError。"""
    payload = jwt.decode(token, get_settings().jwt_secret, algorithms=[JWT_ALG])
    if payload.get("typ") != kind:
        raise jwt.InvalidTokenError("令牌类型不匹配")
    return payload


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


def _fernet() -> Fernet:
    key = get_settings().credential_key
    if not key:
        raise RuntimeError("CREDENTIAL_KEY 未配置，无法加密邮箱凭证")
    return Fernet(key.encode("ascii"))


def encrypt_credential(plain: str) -> bytes:
    return _fernet().encrypt(plain.encode("utf-8"))


def decrypt_credential(token: bytes) -> str:
    return _fernet().decrypt(token).decode("utf-8")
