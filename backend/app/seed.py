"""首次启动时根据环境变量创建管理员账号；已存在则跳过。"""
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import User, UserRole


def main() -> None:
    s = get_settings()
    if not s.admin_password:
        print("[seed] 未设置 ADMIN_PASSWORD，跳过创建管理员")
        return
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == s.admin_username)):
            print(f"[seed] 管理员 {s.admin_username} 已存在，跳过")
            return
        db.add(User(username=s.admin_username, password_hash=hash_password(s.admin_password), role=UserRole.admin))
        db.commit()
        print(f"[seed] 已创建管理员 {s.admin_username}")


if __name__ == "__main__":
    main()
