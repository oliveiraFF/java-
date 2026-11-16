"""白名单与系统设置。"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_or_404, require
from app.core.errors import AppError
from app.db.session import get_db
from app.models import AllowlistEntry, AllowlistType, User, UserRole
from app.schemas import AllowlistIn, AllowlistOut, SettingsIn
from app.services import audit
from app.services import settings as settings_svc

router = APIRouter(tags=["admin"])
admin = require(UserRole.admin)


@router.get("/allowlist", response_model=list[AllowlistOut])
def list_allowlist(db: Session = Depends(get_db), _: User = Depends(require(UserRole.operator))):
    return db.scalars(select(AllowlistEntry).order_by(AllowlistEntry.id.desc())).all()


@router.post("/allowlist", response_model=AllowlistOut, status_code=201)
def add_allowlist(body: AllowlistIn, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)):
    value = body.value.strip().lower()
    if body.type == AllowlistType.sender and "@" not in value:
        raise AppError(400, "INVALID_VALUE", "发件人白名单需要填写完整邮箱地址")
    if body.type != AllowlistType.sender and ("@" in value or "/" in value):
        raise AppError(400, "INVALID_VALUE", "域名白名单只填写域名，例如 example.com")
    if db.scalar(select(AllowlistEntry).where(AllowlistEntry.type == body.type, AllowlistEntry.value == value)):
        raise AppError(409, "ALREADY_EXISTS", "该条目已在白名单中")
    entry = AllowlistEntry(type=body.type, value=value, reason=body.reason, expires_at=body.expires_at, created_by=me.id)
    db.add(entry)
    db.flush()
    audit.record(db, "allowlist.add", user=me, target_type="allowlist", target_id=entry.id,
                 detail={"type": body.type.value, "value": value, "reason": body.reason}, ip=client_ip(request))
    db.commit()
    return entry


@router.delete("/allowlist/{entry_id}", status_code=204)
def remove_allowlist(entry_id: int, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)):
    entry = get_or_404(db, AllowlistEntry, entry_id, "白名单条目")
    audit.record(db, "allowlist.remove", user=me, target_type="allowlist", target_id=entry.id,
                 detail={"type": entry.type.value, "value": entry.value}, ip=client_ip(request))
    db.delete(entry)
    db.commit()


@router.get("/settings")
def get_settings_api(db: Session = Depends(get_db), _: User = Depends(require(UserRole.viewer))):
    return settings_svc.get_all(db)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)):
    values = body.model_dump(exclude_none=True)
    cur = settings_svc.get_all(db)
    sus, phi = values.get("suspicious_threshold", cur["suspicious_threshold"]), values.get("phishing_threshold", cur["phishing_threshold"])
    if sus >= phi:
        raise AppError(400, "INVALID_THRESHOLD", "“可疑”阈值必须低于“钓鱼”阈值")
    if values.get("webhook_url") and not values["webhook_url"].startswith("https://"):
        raise AppError(400, "INVALID_WEBHOOK", "告警地址必须以 https:// 开头")
    out = settings_svc.update(db, values)
    audit.record(db, "settings.update", user=me, target_type="settings",
                 detail={k: ("已设置" if k == "webhook_url" and v else v) for k, v in values.items()}, ip=client_ip(request))
    db.commit()
    return out
