"""手动检测：上传 .eml 或粘贴内容，同步返回检测报告，不入库。"""
from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.errors import AppError
from app.db.session import get_db
from app.models import User, UserRole
from app.schemas import DetectTextIn
from app.services.detection import engine_for, match_allowlist
from phishguard_detector.parser import parse_bytes, parse_text

router = APIRouter(prefix="/detect", tags=["detect"])
operator = require(UserRole.operator)
MAX_UPLOAD = 25 * 1024 * 1024


def _run(db: Session, pe) -> dict:
    allow = match_allowlist(db, pe)
    det = engine_for(db).detect_parsed(pe, allowlisted=allow is not None)
    db.rollback()  # 手动检测不改变白名单命中计数
    return det.to_dict()


@router.post("/eml")
async def detect_eml(file: UploadFile = File(...), db: Session = Depends(get_db), _: User = Depends(operator)):
    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise AppError(413, "FILE_TOO_LARGE", "文件超过 25MB")
    if not raw.strip():
        raise AppError(400, "EMPTY_FILE", "文件为空")
    return _run(db, parse_bytes(raw))


@router.post("/text")
def detect_text(body: DetectTextIn, db: Session = Depends(get_db), _: User = Depends(operator)):
    if body.raw and body.raw.strip():
        pe = parse_bytes(body.raw.encode("utf-8", errors="replace"))
    elif (body.subject or "").strip() or (body.body or "").strip():
        pe = parse_text(body.subject or "", body.body or "", body.sender or "")
    else:
        raise AppError(400, "EMPTY_INPUT", "请粘贴邮件原文，或填写主题和正文")
    return _run(db, pe)
