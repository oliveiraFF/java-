"""邮件解析：原始 .eml 字节 → ParsedEmail。

只做静态解析：不打开链接、不执行附件、不渲染 HTML。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_TEXT_CHARS = 200_000  # 防止超长正文拖慢后续处理

_URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]{}]+)""")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_WS_RE = re.compile(r"[ \t\r\f\v]+")


@dataclass
class UrlRef:
    href: str
    text: str | None = None  # HTML 中 <a> 的显示文本；纯文本里的链接为 None
    domain: str | None = None
    text_domain: str | None = None  # 显示文本本身像 URL 时提取出的域名


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    from_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addrs: list[str] = field(default_factory=list)
    date: str | None = None
    message_id: str = ""
    text: str = ""  # 合并后的纯文本正文（含 HTML 转文本）
    has_html: bool = False
    has_form: bool = False
    urls: list[UrlRef] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    received_count: int = 0
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    @property
    def reply_to_domain(self) -> str:
        return self.reply_to.rsplit("@", 1)[-1].lower() if "@" in self.reply_to else ""

    def model_input(self) -> str:
        """送入文本模型的输入：主题 + 正文。"""
        return f"{self.subject}\n{self.text}".strip()

    def to_dict(self) -> dict:
        return asdict(self)


def domain_of(url: str) -> str | None:
    u = url if "://" in url else "http://" + url
    try:
        host = urlsplit(u).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


class _HtmlExtractor(HTMLParser):
    """从 HTML 中提取可见文本、<a> 链接（href + 显示文本）和表单。"""

    _SKIP = {"script", "style", "head", "title"}
    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[UrlRef] = []
        self.has_form = False
        self._skip = 0
        self._a_href: str | None = None
        self._a_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag == "a":
            self._a_href = dict(attrs).get("href")
            self._a_text = []
        elif tag == "form" or (tag == "input" and (dict(attrs).get("type") or "").lower() == "password"):
            self.has_form = True
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._BLOCK:
            # 块级元素结束也要换行，否则 <p>…</p><a>…</a> 的文字会粘在一起
            self.parts.append("\n")
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag == "a" and self._a_href is not None:
            href = self._a_href.strip()
            if href.lower().startswith(("http://", "https://", "www.")):
                text = "".join(self._a_text).strip() or None
                self.links.append(UrlRef(href=href, text=text))
            self._a_href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._a_href is not None:
            self._a_text.append(data)

    def text(self) -> str:
        return _normalize("".join(self.parts))


def _normalize(s: str) -> str:
    lines = (_WS_RE.sub(" ", ln).strip() for ln in s.splitlines())
    out, blank = [], 0
    for ln in lines:
        if ln:
            out.append(ln)
            blank = 0
        elif blank == 0:
            out.append("")
            blank = 1
    return "\n".join(out).strip()


def _finalize_urls(urls: list[UrlRef]) -> list[UrlRef]:
    seen, out = set(), []
    for u in urls:
        key = (u.href, u.text)
        if key in seen:
            continue
        seen.add(key)
        u.domain = domain_of(u.href)
        if u.text and _URL_RE.fullmatch(u.text.strip()):
            u.text_domain = domain_of(u.text.strip())
        out.append(u)
    return out


def _decode_part(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]
    pe = ParsedEmail()

    pe.subject = str(msg.get("Subject", "") or "").strip()
    pe.from_name, pe.from_addr = parseaddr(str(msg.get("From", "") or ""))
    pe.from_addr = pe.from_addr.lower()
    pe.reply_to = parseaddr(str(msg.get("Reply-To", "") or ""))[1].lower()
    pe.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1].lower()
    pe.to_addrs = [a.lower() for _, a in getaddresses([str(v) for v in msg.get_all("To", [])]) if a]
    pe.message_id = str(msg.get("Message-ID", "") or "").strip()
    try:
        d = msg.get("Date")
        pe.date = parsedate_to_datetime(str(d)).isoformat() if d else None
    except (TypeError, ValueError):
        pe.date = None
    pe.received_count = len(msg.get_all("Received", []))
    pe.headers = {k: str(v) for k, v in msg.items() if k.lower() in ("x-mailer", "user-agent", "authentication-results", "received-spf")}

    for header in msg.get_all("Authentication-Results", []) or []:
        for mech, result in _AUTH_RE.findall(str(header)):
            pe.auth_results.setdefault(mech.lower(), result.lower())
    if "spf" not in pe.auth_results and msg.get("Received-SPF"):
        pe.auth_results["spf"] = str(msg.get("Received-SPF")).split()[0].lower()

    texts: list[str] = []
    urls: list[UrlRef] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and not ctype.startswith("text/")):
            payload = part.get_payload(decode=True) or b""
            pe.attachments.append(Attachment(filename=filename, content_type=ctype, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
            continue
        if ctype == "text/plain":
            body = _decode_part(part)
            texts.append(body)
            urls.extend(UrlRef(href=m) for m in _URL_RE.findall(body))
        elif ctype == "text/html":
            pe.has_html = True
            ex = _HtmlExtractor()
            try:
                ex.feed(_decode_part(part))
            except Exception:  # noqa: BLE001 - 畸形 HTML 不应中断解析
                pass
            texts.append(ex.text())
            urls.extend(ex.links)
            urls.extend(UrlRef(href=m) for m in _URL_RE.findall(ex.text()))
            pe.has_form = pe.has_form or ex.has_form

    pe.text = _normalize("\n\n".join(t for t in texts if t))[:MAX_TEXT_CHARS]
    pe.urls = _finalize_urls(urls)
    return pe


def parse_text(subject: str = "", body: str = "", sender: str = "") -> ParsedEmail:
    """只有主题/正文（例如公开数据集的 CSV）时构造 ParsedEmail。"""
    pe = ParsedEmail(subject=(subject or "").strip(), text=_normalize(body or "")[:MAX_TEXT_CHARS])
    pe.from_name, pe.from_addr = parseaddr(sender or "")
    pe.from_addr = pe.from_addr.lower()
    pe.urls = _finalize_urls([UrlRef(href=m) for m in _URL_RE.findall(pe.text)])
    return pe
