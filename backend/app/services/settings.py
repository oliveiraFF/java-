"""系统设置：存在 settings 表，未设置时使用默认值。"""
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Setting

DEFAULTS: dict[str, Any] = {
    "phishing_threshold": 80,
    "suspicious_threshold": 50,
    "observe_mode": True,  # 观察模式：只检测不处置，新接入时默认开启
    "raw_retention_days": 30,
    "webhook_url": "",  # 企业微信 / 钉钉群机器人
}


def get_all(db: Session) -> dict[str, Any]:
    out = dict(DEFAULTS)
    out["observe_mode"] = get_settings().observe_mode_default
    out["raw_retention_days"] = get_settings().raw_retention_days
    for row in db.query(Setting).all():
        out[row.key] = row.value.get("v")
    return out


def update(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    for k, v in values.items():
        if k not in DEFAULTS:
            continue
        row = db.get(Setting, k)
        if row is None:
            db.add(Setting(key=k, value={"v": v}))
        else:
            row.value = {"v": v}
    db.flush()
    return get_all(db)
