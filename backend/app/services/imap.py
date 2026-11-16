"""IMAP 客户端封装：连接测试、增量拉取、隔离、标记、放行、删除。

约定：
- 拉取一律用 BODY.PEEK，不改变用户邮件的已读状态；
- 首次同步不回扫历史邮件，只记录当前位置；
- 服务器不支持 MOVE 时，降级为 COPY + 标记删除 + EXPUNGE；
- UIDVALIDITY 变化（邮箱被重建）时重置游标。
"""
from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Iterator
from dataclasses import dataclass

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError, LoginError

SUSPICIOUS_KEYWORD = "$PhishGuard_Suspicious"
MAX_FETCH_BYTES = 25 * 1024 * 1024
TRUNCATE_BYTES = 2 * 1024 * 1024  # 超大邮件只取前 2MB（邮件头 + 正文开头），附件内容不需要
BATCH = 20
TIMEOUT = 30

_COPYUID = re.compile(rb"COPYUID\s+\d+\s+[\d:,]+\s+([\d:,]+)", re.I)


class ImapError(Exception):
    """面向用户的 IMAP 错误，message 为中文说明。"""


@dataclass
class FetchedMessage:
    uid: int
    size: int
    raw: bytes
    truncated: bool


def _friendly(exc: Exception) -> str:
    if isinstance(exc, LoginError):
        return "登录失败：用户名或授权码错误。请在邮箱设置中开启 IMAP 并生成授权码（不是登录密码）"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "连接超时：请检查 IMAP 服务器地址和端口，或稍后重试"
    if isinstance(exc, socket.gaierror):
        return "无法解析服务器地址，请检查 IMAP 服务器名称"
    if isinstance(exc, ConnectionRefusedError):
        return "服务器拒绝连接，请检查端口和是否启用 SSL"
    if isinstance(exc, ssl.SSLError):
        return "SSL 握手失败：端口与 SSL 设置可能不匹配（常见为 993 + SSL）"
    return f"IMAP 错误：{type(exc).__name__}: {exc}"[:500]


class MailboxClient:
    def __init__(self, host: str, port: int, use_ssl: bool, username: str, password: str):
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.username, self.password = username, password
        self.c: IMAPClient | None = None

    def __enter__(self) -> MailboxClient:
        try:
            ctx = ssl.create_default_context() if self.use_ssl else None
            self.c = IMAPClient(self.host, port=self.port, ssl=self.use_ssl, ssl_context=ctx, timeout=TIMEOUT, use_uid=True)
            self.c.login(self.username, self.password)
        except Exception as exc:  # noqa: BLE001
            self._close()
            raise ImapError(_friendly(exc)) from exc
        return self

    def __exit__(self, *exc) -> None:
        self._close()

    def _close(self) -> None:
        if self.c is not None:
            try:
                self.c.logout()
            except Exception:  # noqa: BLE001
                pass
            self.c = None

    # ---------- 能力与文件夹 ----------
    @property
    def capabilities(self) -> list[str]:
        return sorted(c.decode() if isinstance(c, bytes) else str(c) for c in self.c.capabilities())

    def has(self, cap: str) -> bool:
        return self.c.has_capability(cap)

    def folders(self) -> list[str]:
        return [name for _flags, _delim, name in self.c.list_folders()]

    def ensure_folder(self, name: str) -> None:
        if not self.c.folder_exists(name):
            self.c.create_folder(name)

    # ---------- 拉取 ----------
    def fetch_new(self, folder: str, state: dict | None) -> tuple[dict, Iterator[FetchedMessage]]:
        """返回 (新的同步状态, 新邮件迭代器)。调用方应在每封邮件处理完后保存状态。"""
        info = self.c.select_folder(folder, readonly=True)
        uidvalidity = int(info[b"UIDVALIDITY"])
        uidnext = int(info.get(b"UIDNEXT", 0) or 0)
        state = dict(state or {})
        if not state or state.get("uidvalidity") != uidvalidity:
            # 首次同步或邮箱被重建：只记录当前位置，不回扫历史
            last = (uidnext - 1) if uidnext else max(self.c.search(["ALL"]) or [0])
            return {"uidvalidity": uidvalidity, "last_uid": int(last), "reset": bool(state)}, iter(())
        last_uid = int(state.get("last_uid", 0))
        uids = sorted(u for u in self.c.search(["UID", f"{last_uid + 1}:*"]) if u > last_uid)
        return {"uidvalidity": uidvalidity, "last_uid": last_uid}, self._fetch(uids)

    def rewind(self, folder: str, state: dict, n: int) -> dict:
        """把同步游标往前挪，使下次同步检测文件夹中最近的 n 封邮件（接入时回扫用）。"""
        if n <= 0:
            return state
        self.c.select_folder(folder, readonly=True)
        uids = sorted(self.c.search(["ALL"]))
        if not uids:
            return state
        start = uids[-n] if len(uids) >= n else uids[0]
        return {**state, "last_uid": start - 1}

    def _fetch(self, uids: list[int]) -> Iterator[FetchedMessage]:
        for i in range(0, len(uids), BATCH):
            chunk = uids[i:i + BATCH]
            sizes = self.c.fetch(chunk, [b"RFC822.SIZE"])
            small = [u for u in chunk if int(sizes.get(u, {}).get(b"RFC822.SIZE", 0)) <= MAX_FETCH_BYTES]
            big = [u for u in chunk if u not in small]
            got = self.c.fetch(small, [b"BODY.PEEK[]"]) if small else {}
            if big:
                got.update(self.c.fetch(big, [f"BODY.PEEK[]<0.{TRUNCATE_BYTES}>".encode()]))
            for u in chunk:
                data = got.get(u, {})
                raw = data.get(b"BODY[]") or data.get(b"BODY[]<0>") or b""
                yield FetchedMessage(uid=u, size=int(sizes.get(u, {}).get(b"RFC822.SIZE", len(raw))), raw=raw, truncated=u in big)

    # ---------- 处置 ----------
    def move(self, folder: str, uid: int, dest: str) -> int | None:
        """把邮件移到 dest，返回目标文件夹中的新 UID（服务器支持 UIDPLUS 时）。"""
        self.c.select_folder(folder)
        if self.has("MOVE"):
            resp = self.c.move([uid], dest)
        else:
            resp = self.c.copy([uid], dest)
            self.c.add_flags([uid], [b"\\Deleted"], silent=True)
            if self.has("UIDPLUS"):
                self.c.uid_expunge([uid])
            else:
                self.c.expunge()
        return _parse_copyuid(resp)

    def flag(self, folder: str, uid: int, keyword: str = SUSPICIOUS_KEYWORD) -> bool:
        """打可疑标记；服务器不允许自定义关键字时返回 False。"""
        info = self.c.select_folder(folder)
        perm = info.get(b"PERMANENTFLAGS", ())
        if b"\\*" not in perm:
            return False
        self.c.add_flags([uid], [keyword.encode()], silent=True)
        return True

    def find_uid(self, folder: str, message_id: str) -> int | None:
        if not message_id:
            return None
        self.c.select_folder(folder)
        hits = self.c.search(["HEADER", "Message-ID", message_id])
        return max(hits) if hits else None

    def delete(self, folder: str, uid: int) -> None:
        self.c.select_folder(folder)
        self.c.add_flags([uid], [b"\\Deleted"], silent=True)
        if self.has("UIDPLUS"):
            self.c.uid_expunge([uid])
        else:
            self.c.expunge()


def _parse_copyuid(resp) -> int | None:
    text = resp if isinstance(resp, bytes) else str(resp).encode()
    m = _COPYUID.search(text)
    if not m:
        return None
    try:
        return int(m.group(1).split(b":")[0].split(b",")[0])
    except ValueError:
        return None


def test_connection(host: str, port: int, use_ssl: bool, username: str, password: str) -> dict:
    """连接测试：登录、读取能力、列出文件夹。不修改邮箱内容。"""
    try:
        with MailboxClient(host, port, use_ssl, username, password) as mc:
            caps = mc.capabilities
            folders = mc.folders()
            return {"ok": True, "message": "连接成功", "capabilities": caps, "supports_move": "MOVE" in caps,
                    "supports_idle": "IDLE" in caps, "folders": folders}
    except ImapError as exc:
        return {"ok": False, "message": str(exc)}
    except IMAPClientError as exc:
        return {"ok": False, "message": _friendly(exc)}
