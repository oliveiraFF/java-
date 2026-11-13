"""健康检查：数据库、Redis、检测引擎与模型文件状态。"""
import os
import time

import redis
from fastapi import APIRouter, Response
from sqlalchemy import text

import phishguard_detector
from app import __version__
from app.core.config import get_settings
from app.db.session import engine

router = APIRouter(tags=["health"])


def _check_db() -> dict:
    t = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"ok": True, "latency_ms": round((time.perf_counter() - t) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001 - 健康检查需要吞掉所有异常
        return {"ok": False, "error": type(exc).__name__}


def _check_redis() -> dict:
    t = time.perf_counter()
    try:
        redis.Redis.from_url(get_settings().redis_url, socket_timeout=2).ping()
        return {"ok": True, "latency_ms": round((time.perf_counter() - t) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__}


def _check_models() -> dict:
    model_dir = get_settings().model_dir
    files = sorted(os.listdir(model_dir)) if os.path.isdir(model_dir) else []
    return {"dir": model_dir, "files": files, "loaded": False}


@router.get("/health")
def health(response: Response) -> dict:
    db, rds = _check_db(), _check_redis()
    ok = db["ok"] and rds["ok"]
    response.status_code = 200 if ok else 503
    return {
        "status": "ok" if ok else "degraded",
        "version": __version__,
        "detector_version": phishguard_detector.__version__,
        "checks": {"database": db, "redis": rds, "models": _check_models()},
    }
