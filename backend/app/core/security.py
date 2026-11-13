"""密码哈希与邮箱授权码加解密。"""
import bcrypt
from cryptography.fernet import Fernet

from app.core.config import get_settings


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
