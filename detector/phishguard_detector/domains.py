"""域名工具：可注册域名、仿冒域名（形近字 / 编辑距离）、品牌识别。"""
from __future__ import annotations

import ipaddress
import re

# 常见二级公共后缀（够用的近似，不引入完整 Public Suffix List）
_SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "ac", "or", "ne", "go"}

# 品牌 → 官方可注册域名
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com", "office365.com",
                  "microsoftrewards.com", "xbox.com", "bing.com", "skype.com", "azure.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.cn"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "alipay": {"alipay.com"},
    "taobao": {"taobao.com"},
    "tencent": {"qq.com", "tencent.com", "exmail.qq.com", "weixin.qq.com"},
    "aliyun": {"aliyun.com", "alibaba.com"},
    "icbc": {"icbc.com.cn"},
    "ccb": {"ccb.com"},
    "boc": {"boc.cn", "bankofchina.com"},
    "cmbchina": {"cmbchina.com"},
    "chinatax": {"chinatax.gov.cn"},
}
BRAND_DOMAINS = {d for ds in BRANDS.values() for d in ds}
# BRAND_SLDS 在文件末尾计算（依赖 sld 函数）

# 显示名中常被冒充的中文品牌/机构名 → 品牌键
BRAND_ALIASES_ZH = {
    "支付宝": "alipay", "淘宝": "taobao", "腾讯": "tencent", "微信": "tencent", "阿里云": "aliyun",
    "工商银行": "icbc", "建设银行": "ccb", "中国银行": "boc", "招商银行": "cmbchina", "税务": "chinatax",
}

FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "qq.com", "163.com", "126.com", "sina.com", "foxmail.com", "aol.com", "mail.ru"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "t.cn", "dwz.cn", "url.cn", "suo.im"}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "country", "kim", "work", "gq", "tk", "ml", "cf", "ga", "rest", "loan", "mov", "cam", "icu", "buzz"}

_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a"), ("|", "l")]
_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable(host: str | None) -> str:
    """近似的可注册域名：a.b.example.com → example.com，x.example.com.cn → example.com.cn。"""
    if not host or is_ip(host):
        return host or ""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def sld(host: str | None) -> str:
    """可注册域名的主体部分：paypal.com → paypal。"""
    return registrable(host).split(".")[0] if host else ""


def tld(host: str | None) -> str:
    return host.rsplit(".", 1)[-1].lower() if host and "." in host else ""


def is_punycode(host: str | None) -> bool:
    return bool(host) and any(lbl.startswith("xn--") for lbl in host.lower().split("."))


def unhomoglyph(s: str) -> str:
    s = s.lower()
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def official_brand(host: str | None) -> str | None:
    """host 属于某品牌官方域名时返回品牌键。"""
    reg = registrable(host)
    for brand, ds in BRANDS.items():
        if reg in ds or (host or "").lower() in ds:
            return brand
    return None


def lookalike_brand(host: str | None) -> tuple[str, str] | None:
    """判断 host 是否仿冒某品牌，返回 (品牌官方域名, 原因)。官方域名本身返回 None。"""
    if not host or is_ip(host) or official_brand(host):
        return None
    host = host.lower().strip(".")
    reg = registrable(host)
    body = reg.split(".")[0]
    if not _LABEL_RE.match(body) or body in BRAND_SLDS:
        # 主体与品牌同名（google.co.uk、google.fi 等国家域名）视为官方
        return None
    norm = unhomoglyph(body)
    for brand_domain in BRAND_DOMAINS:
        b = sld(brand_domain)  # exmail.qq.com → qq，不能把子域名 exmail 当成品牌名
        if norm == b:
            return brand_domain, "形近字替换"
        # 编辑距离只用于较长的品牌名：gmail/email、apple/ample 这类短词误报太多
        if len(b) >= 6 and levenshtein(norm, b) == 1:
            return brand_domain, "拼写近似"
        # 品牌名是主体的独立片段：paypal-secure.com；避免 pineapple 这类子串误报
        if len(b) >= 4 and b in body.split("-"):
            return brand_domain, "域名中包含品牌名"
        # 在子域名里嵌入完整品牌域名：paypal.com.evil.net
        if host.startswith(brand_domain + ".") or f".{brand_domain}." in host:
            return brand_domain, "在子域名中嵌入品牌域名"
    return None


def subdomain_depth(host: str | None) -> int:
    """可注册域名之前的子域名层数：a.b.example.com → 2。"""
    if not host or is_ip(host):
        return 0
    return max(0, host.strip(".").count(".") - registrable(host).count("."))


BRAND_SLDS = {sld(d) for d in BRAND_DOMAINS}
