"""规则引擎：对 ParsedEmail 逐条执行规则，输出命中列表与规则分。

每条规则返回证据字符串（命中）或 None（未命中）。证据会原样展示在工作台的
"检测依据"中，所以要写成用户看得懂的中文。
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from phishguard_detector import domains as D
from phishguard_detector.parser import ParsedEmail

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

URGENCY = re.compile(
    r"立即|马上|尽快|24\s*小时内|48\s*小时内|今天之内|限时|逾期|最后通知|紧急"
    r"|\burgent(ly)?\b|\bimmediately\b|\bwithin\s+(24|48|72)\s+hours\b|\bact\s+now\b|\bfinal\s+notice\b|\bas\s+soon\s+as\s+possible\b",
    re.I,
)
CREDENTIAL = re.compile(
    r"验证(您的)?(账户|账号|身份|密码)|重新登录|输入(您的)?密码|更新(您的)?(账户|账号)信息|确认(您的)?(账户|账号)"
    r"|\bverify\s+your\s+(account|identity|password|information)\b|\bconfirm\s+your\s+(account|password|identity)\b"
    r"|\b(log|sign)\s*in\s+to\s+(verify|confirm|restore)\b|\bupdate\s+your\s+(account|billing|payment)\b|\breset\s+your\s+password\b",
    re.I,
)
MONEY = re.compile(
    r"汇款|转账|打款|付款到|更换(收款)?账户|变更(收款)?账户|新的?收款账户|发票|退税|补贴|中奖"
    r"|\bwire\s+transfer\b|\bbank\s+transfer\b|\bnew\s+(bank\s+)?account\s+details\b|\bpayment\s+(details|information)\s+(has|have)\s+changed\b"
    r"|\bgift\s+cards?\b|\bbeneficiary\b|\b(million|thousand)\s+(us\s+)?dollars\b|\binheritance\b",
    re.I,
)
THREAT = re.compile(
    r"冻结|停用|注销|封禁|被限制|异常登录|安全警告|将被删除"
    r"|\bsuspend(ed)?\b|\blocked\b|\bdeactivat(e|ed|ion)\b|\bunusual\s+(sign-?in|activity)\b|\bwill\s+be\s+(closed|deleted|terminated)\b",
    re.I,
)
EXEC_TITLE = re.compile(r"总经理|董事长|总裁|老板|财务|人事|hr\b|ceo\b|cfo\b|director|manager|admin|管理员|it\s*support|helpdesk", re.I)
LOGIN_PATH = re.compile(r"login|signin|sign-in|verify|account|secure|update|password|webscr|auth", re.I)

DANGEROUS_EXT = {"exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "iso", "img", "msi", "jar", "ps1", "html", "htm", "svg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}


@dataclass
class RuleHit:
    rule_id: str
    name: str
    category: str
    weight: int
    evidence: str
    critical: bool = False


@dataclass
class Rule:
    rule_id: str
    name: str
    category: str  # header / sender / url / content / attachment
    weight: int
    check: Callable[[ParsedEmail], str | None]
    critical: bool = False


def _ext(name: str | None) -> list[str]:
    return [p.lower() for p in (name or "").split(".")[1:]]


# ---------------- 邮件头 ----------------
def _spf(pe):
    r = pe.auth_results.get("spf")
    return f"SPF 校验结果为 {r}，发件服务器未被发件域授权" if r in ("fail", "softfail") else None


def _dkim(pe):
    r = pe.auth_results.get("dkim")
    return f"DKIM 签名校验结果为 {r}，邮件可能被篡改或伪造" if r == "fail" else None


def _dmarc(pe):
    r = pe.auth_results.get("dmarc")
    return f"DMARC 校验结果为 {r}，发件人地址未通过发件域的身份策略" if r == "fail" else None


def _reply_to(pe):
    if pe.reply_to_domain and pe.from_domain and D.registrable(pe.reply_to_domain) != D.registrable(pe.from_domain):
        return f"回复地址（{pe.reply_to}）与发件人域名（{pe.from_domain}）不一致，回信会发给他人"
    return None


def _return_path(pe):
    rp = pe.return_path.rsplit("@", 1)[-1] if "@" in pe.return_path else ""
    if rp and pe.from_domain and D.registrable(rp) != D.registrable(pe.from_domain):
        return f"退信地址域名（{rp}）与发件人域名（{pe.from_domain}）不一致"
    return None


# ---------------- 发件人 ----------------
def _name_has_email(pe):
    m = _EMAIL_IN_TEXT.search(pe.from_name or "")
    if m and m.group(0).lower() != pe.from_addr:
        return f"发件人显示名中写着 {m.group(0)}，实际发件地址却是 {pe.from_addr}"
    return None


def _name_brand_spoof(pe):
    name = (pe.from_name or "").lower()
    if not name or not pe.from_domain:
        return None
    sender_brand = D.official_brand(pe.from_domain)
    for brand in D.BRANDS:
        if len(brand) >= 4 and re.search(rf"\b{re.escape(brand)}\b", name) and sender_brand != brand:
            return f"显示名自称“{pe.from_name}”，但发件域名 {pe.from_domain} 不属于该品牌"
    for zh, brand in D.BRAND_ALIASES_ZH.items():
        if zh in pe.from_name and sender_brand != brand:
            return f"显示名自称“{pe.from_name}”，但发件域名 {pe.from_domain} 不属于该机构"
    return None


def _freemail_exec(pe):
    if pe.from_domain in D.FREEMAIL and EXEC_TITLE.search(pe.from_name or ""):
        return f"使用个人免费邮箱（{pe.from_domain}）却以“{pe.from_name}”的身份发信，常见于冒充领导或财务"
    return None


def _sender_lookalike(pe):
    hit = D.lookalike_brand(pe.from_domain)
    if hit:
        return f"发件域名 {pe.from_domain} 疑似仿冒 {hit[0]}（{hit[1]}）"
    if D.is_punycode(pe.from_domain):
        return f"发件域名 {pe.from_domain} 使用国际化编码，可能用形近字符冒充其他域名"
    return None


# ---------------- 链接 ----------------
def _first(pe, pred, fmt):
    for u in pe.urls:
        if pred(u):
            return fmt(u)
    return None


def _url_ip(pe):
    return _first(pe, lambda u: D.is_ip(u.domain), lambda u: f"链接直接指向 IP 地址：{u.href}")


def _url_mismatch(pe):
    return _first(
        pe,
        lambda u: u.text_domain and u.domain and D.registrable(u.text_domain) != D.registrable(u.domain),
        lambda u: f"链接显示为 {u.text_domain}，实际跳转到 {u.domain}",
    )


def _url_punycode(pe):
    return _first(pe, lambda u: D.is_punycode(u.domain), lambda u: f"链接域名 {u.domain} 使用国际化编码，可能是形近字仿冒")


def _url_shortener(pe):
    return _first(pe, lambda u: D.registrable(u.domain) in D.SHORTENERS, lambda u: f"使用短链接 {u.href}，无法直接看出真实地址")


def _url_at(pe):
    return _first(pe, lambda u: "@" in u.href.split("//", 1)[-1].split("/", 1)[0], lambda u: f"链接中含 @ 符号，真实地址是 @ 后面的部分：{u.href}")


def _own_link(pe, u) -> bool:
    """链接指向已通过 DMARC 认证的发件人自己的域名（例如阿里云邮件里指向 aliyun.com 的链接）。"""
    return (pe.auth_results.get("dmarc") == "pass" and bool(pe.from_domain) and bool(u.domain)
            and D.registrable(u.domain) == D.registrable(pe.from_domain))


def _url_subdomains(pe):
    # 只数可注册域名之前的层级，避免把 www.cs.waikato.ac.nz 这类正常大学网站误判
    return _first(pe, lambda u: D.subdomain_depth(u.domain) >= 3 and not _own_link(pe, u), lambda u: f"链接子域名层级过多：{u.domain}")


def _url_tld(pe):
    return _first(pe, lambda u: D.tld(u.domain) in D.SUSPICIOUS_TLDS and not _own_link(pe, u),
                  lambda u: f"链接使用高风险顶级域名 .{D.tld(u.domain)}：{u.domain}")


def _url_lookalike(pe):
    for u in pe.urls:
        hit = D.lookalike_brand(u.domain)
        if hit:
            return f"链接域名 {u.domain} 疑似仿冒 {hit[0]}（{hit[1]}）"
    return None


def _url_http_login(pe):
    def is_plain_login(u):
        if not u.href.lower().startswith("http://") or _own_link(pe, u):
            return False
        parts = urlsplit(u.href)
        return bool(LOGIN_PATH.search(parts.path + "?" + parts.query))

    return _first(pe, is_plain_login, lambda u: f"登录/验证类页面未使用 HTTPS 加密：{u.href}")


# ---------------- 正文 ----------------
def _match(regex, label):
    def check(pe):
        m = regex.search(pe.model_input())
        return f"{label}：“{m.group(0)}”" if m else None
    return check


def _form(pe):
    return "邮件正文中嵌入了表单或密码输入框，正规机构不会通过邮件收集密码" if pe.has_form else None


# ---------------- 附件 ----------------
def _att_dangerous(pe):
    for a in pe.attachments:
        exts = _ext(a.filename)
        if exts and exts[-1] in DANGEROUS_EXT:
            return f"附件 {a.filename} 是可执行或脚本类文件，打开后可能直接运行恶意程序"
    return None


def _att_double(pe):
    for a in pe.attachments:
        exts = _ext(a.filename)
        if len(exts) >= 2 and exts[-2] in DOC_EXT and exts[-1] not in DOC_EXT:
            return f"附件 {a.filename} 使用双扩展名伪装成文档"
    return None


def _att_macro(pe):
    for a in pe.attachments:
        exts = _ext(a.filename)
        if exts and exts[-1] in MACRO_EXT:
            return f"附件 {a.filename} 是启用宏的 Office 文档"
    return None


def _att_archive_password(pe):
    has_archive = any((_ext(a.filename) or [""])[-1] in ARCHIVE_EXT for a in pe.attachments)
    if has_archive and re.search(r"解压密码|压缩包密码|密码[是为:：]|\bpassword\s*(is|:)", pe.text, re.I):
        return "附件是压缩包，且正文中给出了解压密码，常用于躲避杀毒软件扫描"
    return None


# ---------------- 组合（关键规则）----------------
def _crit_auth_and_spoof(pe):
    if pe.auth_results.get("dmarc") == "fail" and (D.lookalike_brand(pe.from_domain) or _name_brand_spoof(pe)):
        return "发件人身份认证失败，同时冒充知名品牌或机构"
    return None


RULES: list[Rule] = [
    Rule("AUTH_SPF_FAIL", "SPF 校验失败", "header", 15, _spf),
    Rule("AUTH_DKIM_FAIL", "DKIM 签名校验失败", "header", 10, _dkim),
    Rule("AUTH_DMARC_FAIL", "DMARC 校验失败", "header", 20, _dmarc),
    Rule("REPLY_TO_MISMATCH", "回复地址与发件人不一致", "header", 15, _reply_to),
    Rule("RETURN_PATH_MISMATCH", "退信地址与发件人不一致", "header", 5, _return_path),
    Rule("DISPLAY_NAME_EMAIL", "显示名伪装成其他邮箱", "sender", 15, _name_has_email),
    Rule("DISPLAY_NAME_BRAND", "显示名冒充品牌或机构", "sender", 20, _name_brand_spoof),
    Rule("FREEMAIL_EXEC", "免费邮箱冒充领导或财务", "sender", 15, _freemail_exec),
    Rule("SENDER_LOOKALIKE", "发件域名仿冒", "sender", 30, _sender_lookalike),
    Rule("URL_IP_HOST", "链接直连 IP 地址", "url", 20, _url_ip),
    Rule("URL_TEXT_MISMATCH", "链接显示地址与实际地址不一致", "url", 25, _url_mismatch),
    Rule("URL_PUNYCODE", "链接使用国际化编码域名", "url", 20, _url_punycode),
    Rule("URL_SHORTENER", "使用短链接", "url", 10, _url_shortener),
    Rule("URL_AT_SIGN", "链接含 @ 符号", "url", 15, _url_at),
    Rule("URL_MANY_SUBDOMAINS", "链接子域名层级过多", "url", 5, _url_subdomains),
    Rule("URL_SUSPICIOUS_TLD", "链接使用高风险顶级域名", "url", 10, _url_tld),
    Rule("URL_LOOKALIKE", "链接域名仿冒品牌", "url", 25, _url_lookalike),
    Rule("URL_HTTP_LOGIN", "登录页面未加密", "url", 10, _url_http_login),
    Rule("TEXT_URGENCY", "制造紧迫感", "content", 10, _match(URGENCY, "正文制造紧迫感")),
    Rule("TEXT_CREDENTIAL", "索取账号密码", "content", 15, _match(CREDENTIAL, "正文要求验证或输入账号信息")),
    Rule("TEXT_MONEY", "涉及转账或金钱诱导", "content", 15, _match(MONEY, "正文涉及转账、收款账户或金钱")),
    Rule("TEXT_THREAT", "以账户异常相威胁", "content", 10, _match(THREAT, "正文以账户冻结或异常相威胁")),
    Rule("HTML_FORM", "邮件内嵌表单", "content", 15, _form),
    Rule("ATT_DANGEROUS", "危险类型附件", "attachment", 30, _att_dangerous),
    Rule("ATT_DOUBLE_EXT", "附件双扩展名", "attachment", 30, _att_double),
    Rule("ATT_MACRO", "启用宏的文档附件", "attachment", 20, _att_macro),
    Rule("ATT_ARCHIVE_PASSWORD", "加密压缩包附件", "attachment", 20, _att_archive_password),
    Rule("CRIT_AUTH_SPOOF", "身份认证失败且冒充品牌", "sender", 40, _crit_auth_and_spoof, critical=True),
]


@dataclass
class RuleResult:
    score: int  # 0–100
    critical: bool
    hits: list[RuleHit]
    trusted_sender: bool = False

    def to_dict(self) -> dict:
        return {"score": self.score, "critical": self.critical, "trusted_sender": self.trusted_sender,
                "hits": [asdict(h) for h in self.hits]}


# 发件人身份可信的反证：命中任一条，就不认为发件人可信
_IDENTITY_RED_FLAGS = {"SENDER_LOOKALIKE", "DISPLAY_NAME_BRAND", "DISPLAY_NAME_EMAIL", "REPLY_TO_MISMATCH", "FREEMAIL_EXEC"}
# 认证可信时减半的正文话术规则：真实平台的登录提醒、邮箱确认也会用到这些说法
_WORDING_RULES = {"TEXT_URGENCY", "TEXT_CREDENTIAL", "TEXT_MONEY", "TEXT_THREAT"}
TRUSTED_NOTE = "（发件人已通过 DMARC 身份认证，且不是仿冒域名，此项权重减半）"


def evaluate(pe: ParsedEmail, rules: list[Rule] | None = None) -> RuleResult:
    hits: list[RuleHit] = []
    for r in rules or RULES:
        try:
            ev = r.check(pe)
        except Exception:  # noqa: BLE001 - 单条规则出错不能影响整封邮件的检测
            ev = None
        if ev:
            hits.append(RuleHit(r.rule_id, r.name, r.category, r.weight, ev, r.critical))

    # 发件人身份可信：DMARC 通过（From 中的域名确实发出了这封邮件），且没有任何冒充迹象。
    # 这时"紧迫感""请验证账户"等话术更可能是正常的平台通知，权重减半（实验 8）。
    # 已知代价：真实企业邮箱被盗后发出的钓鱼同样能通过 DMARC，此时依靠模型层和其他规则识别。
    trusted = (pe.auth_results.get("dmarc") == "pass" and bool(pe.from_domain)
               and not any(h.rule_id in _IDENTITY_RED_FLAGS for h in hits))
    if trusted:
        for h in hits:
            if h.rule_id in _WORDING_RULES:
                h.weight = (h.weight + 1) // 2
                h.evidence += TRUSTED_NOTE

    hits.sort(key=lambda h: (-h.critical, -h.weight))
    return RuleResult(score=min(100, sum(h.weight for h in hits)), critical=any(h.critical for h in hits), hits=hits,
                      trusted_sender=trusted)
