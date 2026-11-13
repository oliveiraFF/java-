#!/bin/sh
set -e
echo "[start] 执行数据库迁移"
alembic upgrade head
echo "[start] 初始化管理员账号"
python -m app.seed
echo "[start] 启动 API"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
