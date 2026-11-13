from cryptography.fernet import Fernet

from app.core import config, security


def test_password_hash_roundtrip():
    h = security.hash_password("s3cret-密码")
    assert security.verify_password("s3cret-密码", h)
    assert not security.verify_password("wrong", h)


def test_credential_encrypt_roundtrip(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_KEY", Fernet.generate_key().decode())
    config.get_settings.cache_clear()
    token = security.encrypt_credential("授权码abc123")
    assert b"abc123" not in token
    assert security.decrypt_credential(token) == "授权码abc123"
    config.get_settings.cache_clear()
