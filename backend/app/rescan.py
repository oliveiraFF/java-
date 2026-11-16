"""运维命令：重新检测某个邮箱最近的 N 封邮件（例如更换模型之后）。

只允许在观察模式下运行：会删除这些邮件已有的检测记录，从邮箱重新拉取并检测，
邮件本身不会被移动。已被隔离、放行、删除的邮件记录不会被删除（避免丢失处置历史）。

用法（api 容器内）：python -m app.rescan <mailbox_id> <n>
"""
import sys

from sqlalchemy import delete, select

from app.core.security import decrypt_credential
from app.db.session import SessionLocal
from app.models import Email, EmailStatus, Mailbox
from app.services import settings as settings_svc
from app.services.imap import MailboxClient
from app.worker.tasks import _sync

SAFE_TO_RESET = (EmailStatus.pending, EmailStatus.detected, EmailStatus.flagged, EmailStatus.error)


def main(mailbox_id: int, n: int) -> None:
    with SessionLocal() as db:
        if not settings_svc.get_all(db)["observe_mode"]:
            sys.exit("请先在设置中开启观察模式，再重新检测历史邮件")
        mb = db.get(Mailbox, mailbox_id)
        if mb is None:
            sys.exit(f"邮箱 {mailbox_id} 不存在")
        with MailboxClient(mb.imap_host, mb.imap_port, mb.use_ssl, mb.username, decrypt_credential(mb.credential_enc)) as mc:
            state = {f: mc.rewind(f, mc.fetch_new(f, None)[0], n) for f in mb.folders}
        floor = {f: s["last_uid"] for f, s in state.items()}
        removed = 0
        for f, last in floor.items():
            ids = db.scalars(select(Email.id).where(Email.mailbox_id == mb.id, Email.folder == f, Email.uid > last,
                                                    Email.status.in_(SAFE_TO_RESET))).all()
            if ids:
                db.execute(delete(Email).where(Email.id.in_(ids)))
                removed += len(ids)
        for s in state.values():
            s.pop("reset", None)
        mb.sync_state = state
        db.commit()
    print(f"已清除 {removed} 条旧检测记录，开始重新检测")
    print(_sync(mailbox_id))


if __name__ == "__main__":
    main(int(sys.argv[1]), int(sys.argv[2]))
