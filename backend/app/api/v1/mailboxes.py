from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_or_404, require
from app.core.errors import AppError
from app.core.security import encrypt_credential
from app.db.session import get_db
from app.models import Mailbox, MailboxStatus, User, UserRole
from app.schemas import ConnectionTestOut, MailboxIn, MailboxOut, MailboxUpdate
from app.services import audit
from app.services import settings as settings_svc
from app.services.imap import ImapError, MailboxClient, test_connection

router = APIRouter(prefix="/mailboxes", tags=["mailboxes"])
admin_only = require(UserRole.admin)

# 常见服务商预设（前端下拉框使用）
PRESETS = [
    {"name": "腾讯企业邮", "imap_host": "imap.exmail.qq.com", "imap_port": 993},
    {"name": "阿里企业邮", "imap_host": "imap.qiye.aliyun.com", "imap_port": 993},
    {"name": "网易企业邮", "imap_host": "imap.qiye.163.com", "imap_port": 993},
    {"name": "QQ 邮箱", "imap_host": "imap.qq.com", "imap_port": 993},
    {"name": "163 邮箱", "imap_host": "imap.163.com", "imap_port": 993},
    {"name": "Outlook", "imap_host": "outlook.office365.com", "imap_port": 993},
]


@router.get("/presets")
def presets(_: User = Depends(admin_only)):
    return PRESETS


@router.get("", response_model=list[MailboxOut])
def list_mailboxes(db: Session = Depends(get_db), _: User = Depends(require(UserRole.viewer))):
    return db.scalars(select(Mailbox).order_by(Mailbox.id)).all()


@router.post("/test", response_model=ConnectionTestOut)
def test(body: MailboxIn, _: User = Depends(admin_only)):
    return test_connection(body.imap_host, body.imap_port, body.use_ssl, body.username or body.address, body.password)


@router.post("", response_model=MailboxOut, status_code=201)
def create(body: MailboxIn, request: Request, db: Session = Depends(get_db), me: User = Depends(admin_only)):
    if db.scalar(select(Mailbox).where(Mailbox.address == body.address.lower())):
        raise AppError(409, "MAILBOX_EXISTS", "该邮箱已接入")
    if body.backfill and not settings_svc.get_all(db)["observe_mode"]:
        # 回扫的是员工已经读过的历史邮件，只允许在观察模式下检测，避免误把历史邮件移走
        raise AppError(400, "BACKFILL_NEEDS_OBSERVE", "回扫历史邮件需要先在设置中开启观察模式")
    username = body.username or body.address
    try:
        with MailboxClient(body.imap_host, body.imap_port, body.use_ssl, username, body.password) as mc:
            caps = mc.capabilities
            existing = set(mc.folders())
            missing = [f for f in body.folders if f not in existing]
            if missing:
                raise AppError(400, "FOLDER_NOT_FOUND", f"邮箱中不存在文件夹：{'、'.join(missing)}")
            mc.ensure_folder(body.quarantine_folder)
            # 记录当前位置：默认不检测接入前的历史邮件；选择回扫时把游标往前挪 N 封
            state = {f: mc.rewind(f, mc.fetch_new(f, None)[0], body.backfill) for f in body.folders}
    except ImapError as exc:
        raise AppError(400, "IMAP_CONNECT_FAILED", str(exc)) from None
    for s in state.values():
        s.pop("reset", None)
    mb = Mailbox(address=body.address.lower(), imap_host=body.imap_host, imap_port=body.imap_port, use_ssl=body.use_ssl,
                 username=username, credential_enc=encrypt_credential(body.password), folders=body.folders,
                 quarantine_folder=body.quarantine_folder, sync_state=state, capabilities=caps)
    db.add(mb)
    db.flush()
    audit.record(db, "mailbox.create", user=me, target_type="mailbox", target_id=mb.id,
                 detail={"address": mb.address, "host": mb.imap_host, "ssl": mb.use_ssl, "backfill": body.backfill}, ip=client_ip(request))
    db.commit()
    if body.backfill:
        from app.worker.tasks import sync_mailbox  # 延迟导入

        sync_mailbox.delay(mb.id)  # 立即开始检测回扫的邮件
    return mb


@router.patch("/{mailbox_id}", response_model=MailboxOut)
def update(mailbox_id: int, body: MailboxUpdate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin_only)):
    mb = get_or_404(db, Mailbox, mailbox_id, "邮箱")
    changes = {}
    if body.password:
        mb.credential_enc, changes["password"] = encrypt_credential(body.password), "已更新"
    if body.folders:
        mb.folders, changes["folders"] = body.folders, body.folders
    if body.status is not None:
        mb.status, changes["status"] = body.status, body.status.value
        if body.status == MailboxStatus.active:
            mb.consecutive_failures, mb.last_error = 0, None
    audit.record(db, "mailbox.update", user=me, target_type="mailbox", target_id=mb.id, detail=changes, ip=client_ip(request))
    db.commit()
    return mb


@router.post("/{mailbox_id}/sync")
def sync_now(mailbox_id: int, db: Session = Depends(get_db), _: User = Depends(require(UserRole.operator))):
    from app.worker.tasks import sync_mailbox  # 延迟导入，避免 API 启动时依赖 worker 模块

    get_or_404(db, Mailbox, mailbox_id, "邮箱")
    sync_mailbox.delay(mailbox_id)
    return {"queued": True}


@router.delete("/{mailbox_id}", status_code=204)
def delete(mailbox_id: int, request: Request, db: Session = Depends(get_db), me: User = Depends(admin_only)):
    mb = get_or_404(db, Mailbox, mailbox_id, "邮箱")
    audit.record(db, "mailbox.delete", user=me, target_type="mailbox", target_id=mb.id, detail={"address": mb.address}, ip=client_ip(request))
    db.delete(mb)
    db.commit()
