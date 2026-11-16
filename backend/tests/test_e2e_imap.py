"""端到端测试：GreenMail 模拟邮件服务器 → 同步 → 检测 → 隔离 → 放行。

需要先启动：docker compose --profile test up -d greenmail
并设置 GREENMAIL_HOST（compose 网络内为 greenmail）。未设置时跳过。
测试账号 e2e@corp.test / e2e-pass 仅存在于本地 GreenMail 容器，专供本测试使用
（alice@corp.test 留给开发环境演示数据）。测试开始前会清空该账号，可以反复运行。
"""
import os
import smtplib
import time
from email.message import EmailMessage

import pytest

HOST = os.environ.get("GREENMAIL_HOST")
pytestmark = pytest.mark.skipif(not HOST, reason="未设置 GREENMAIL_HOST，跳过 IMAP 端到端测试")
USER, PASS = "e2e@corp.test", "e2e-pass"
QUARANTINE = "PhishGuard-隔离"


def reset_mailbox() -> None:
    """清空测试账号的收件箱和隔离文件夹中的邮件，保证测试可重复运行。

    只删除邮件、保留文件夹：GreenMail 在删除含邮件的文件夹时会直接断开连接。
    """
    from imapclient import IMAPClient

    with IMAPClient(HOST, port=3143, ssl=False, timeout=10) as c:
        c.login(USER, PASS)
        for folder in ("INBOX", QUARANTINE):
            if not c.folder_exists(folder):
                continue
            c.select_folder(folder)
            uids = c.search(["ALL"])
            if uids:
                c.delete_messages(uids)
                c.expunge()


def send(subject: str, sender: str, html: str | None = None, text: str | None = None, headers: dict | None = None):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, USER, subject
    msg["Message-ID"] = f"<{time.time_ns()}@test>"
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(text or "see html")
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(HOST, 3025, timeout=10) as s:
        s.send_message(msg)
    return msg["Message-ID"]


def imap_folder_subjects(folder: str) -> list[str]:
    from imapclient import IMAPClient

    with IMAPClient(HOST, port=3143, ssl=False, timeout=10) as c:
        c.login(USER, PASS)
        if not c.folder_exists(folder):
            raise AssertionError(f"IMAP 文件夹不存在：{folder}")
        c.select_folder(folder, readonly=True)
        uids = c.search(["ALL"])
        data = c.fetch(uids, [b"BODY.PEEK[HEADER.FIELDS (SUBJECT)]"]) if uids else {}
        return [v[b"BODY[HEADER.FIELDS (SUBJECT)]"].decode().strip().removeprefix("Subject: ") for v in data.values()]


def test_sync_detect_quarantine_release(client, admin_h, operator_h):
    from app.db.session import SessionLocal
    from app.models import Email
    from app.worker.tasks import _sync

    reset_mailbox()
    r = client.post("/api/v1/mailboxes", headers=admin_h, json={
        "address": USER, "imap_host": HOST, "imap_port": 3143, "use_ssl": False, "password": PASS})
    assert r.status_code == 201, r.text
    mb = r.json()
    assert imap_folder_subjects(QUARANTINE) == []  # 接入时已自动创建空的隔离文件夹
    assert client.put("/api/v1/settings", headers=admin_h, json={"observe_mode": False}).status_code == 200

    send("Your PayPal account has been limited", '"PayPal" <service@paypa1.com>',
         html='<p>We noticed unusual activity. Please verify your account within 24 hours.</p>'
              '<a href="http://198.51.100.7/login">https://www.paypal.com/signin</a>',
         headers={"Authentication-Results": "mx.corp.test; spf=fail; dkim=none; dmarc=fail"})
    send("Lunch tomorrow", "tom@corp.test", text="Hi Alice, shall we have lunch at noon tomorrow? Thanks, Tom")
    time.sleep(1)

    stats = _sync(mb["id"])
    assert stats["new"] == 2, stats

    with SessionLocal() as db:
        rows = {e.subject: e for e in db.query(Email).filter(Email.mailbox_id == mb["id"])}
        phish, ok = rows["Your PayPal account has been limited"], rows["Lunch tomorrow"]
        assert phish.detection.verdict.value == "phishing" and phish.status.value == "quarantined"
        assert phish.raw_path and os.path.exists(phish.raw_path)
        assert ok.detection.verdict.value == "safe" and ok.status.value == "detected"
        phish_id = phish.id

    assert "Your PayPal account has been limited" in imap_folder_subjects(QUARANTINE)
    assert "Your PayPal account has been limited" not in imap_folder_subjects("INBOX")
    assert "Lunch tomorrow" in imap_folder_subjects("INBOX")

    # 重复同步不会重复入库
    assert _sync(mb["id"])["new"] == 0

    # 放行：回到收件箱，并自动记录一条误报反馈
    r = client.post("/api/v1/quarantine/release", headers=operator_h, json={"ids": [phish_id]})
    assert r.status_code == 200 and r.json()["ok"] == [phish_id], r.text
    assert "Your PayPal account has been limited" in imap_folder_subjects("INBOX")
    assert client.get(f"/api/v1/emails/{phish_id}", headers=operator_h).json()["status"] == "released"

    detail = client.get(f"/api/v1/emails/{phish_id}", headers=operator_h).json()
    assert detail["detection"]["summary"] and detail["detection"]["rule_hits"]
    assert client.get("/api/v1/stats/top-rules", headers=operator_h).json()
    client.put("/api/v1/settings", headers=admin_h, json={"observe_mode": True})
