"""测试使用独立的 phishguard_test 数据库：开始时创建并迁移，结束时删除，不影响开发数据。"""
import os

import psycopg
import pytest
from sqlalchemy.engine import make_url

from tests.helpers import login

_main = os.environ.get("DATABASE_URL", "")
if _main.startswith("postgresql"):
    _url = make_url(_main)
    # 防止本模块被重复导入时把 _test 后缀叠加两次
    TEST_DB = _url.database if _url.database.endswith("_test") else f"{_url.database}_test"
    os.environ["DATABASE_URL"] = _url.set(database=TEST_DB).render_as_string(hide_password=False)
    _admin_dsn = _url.set(drivername="postgresql", database="postgres").render_as_string(hide_password=False)
else:
    TEST_DB, _admin_dsn = None, None
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("CREDENTIAL_KEY", "A" * 43 + "=")  # 合法的 Fernet 测试密钥（32 个零字节）


def _admin(sql: str) -> None:
    with psycopg.connect(_admin_dsn, autocommit=True) as conn:
        conn.execute(sql)


@pytest.fixture(scope="session")
def database():
    if not TEST_DB:
        pytest.skip("需要 PostgreSQL（在 docker compose 的 api 容器中运行）")
    _admin(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
    _admin(f'CREATE DATABASE "{TEST_DB}"')
    from alembic import command
    from alembic.config import Config

    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(Config("alembic.ini"), "head")
    yield
    from app.db.session import engine

    engine.dispose()
    _admin(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')


@pytest.fixture(scope="session")
def client(database):
    from fastapi.testclient import TestClient

    from app.core.security import hash_password
    from app.db.session import SessionLocal
    from app.main import app
    from app.models import User, UserRole

    with SessionLocal() as db:
        for name, role in (("admin", UserRole.admin), ("operator", UserRole.operator), ("viewer", UserRole.viewer)):
            db.add(User(username=name, password_hash=hash_password(f"{name}-pass-123"), role=role))
        db.commit()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_h(client):
    return login(client, "admin")


@pytest.fixture(scope="session")
def operator_h(client):
    return login(client, "operator")


@pytest.fixture(scope="session")
def viewer_h(client):
    return login(client, "viewer")
