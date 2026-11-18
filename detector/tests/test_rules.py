from phishguard_detector import domains as D
from phishguard_detector.parser import Attachment, ParsedEmail, UrlRef, parse_text
from phishguard_detector.rules import RULES, evaluate


def ids(pe):
    return {h.rule_id for h in evaluate(pe).hits}


def test_registrable_and_lookalike():
    assert D.registrable("a.b.paypal.com") == "paypal.com"
    assert D.registrable("www.icbc.com.cn") == "icbc.com.cn"
    assert D.lookalike_brand("paypa1.com")[1] == "形近字替换"
    assert D.lookalike_brand("rnicrosoft.com")[1] == "形近字替换"
    assert D.lookalike_brand("paypal-secure.com")[1] == "域名中包含品牌名"
    assert D.lookalike_brand("paypal.com") is None  # 官方域名
    assert D.lookalike_brand("www.paypal.com") is None
    assert D.lookalike_brand("paypal.com.evil.net")[1] == "在子域名中嵌入品牌域名"
    assert D.lookalike_brand("paypai.com")[1] == "拼写近似"
    assert D.lookalike_brand("pineapple.com") is None  # 不应误报 apple
    assert D.lookalike_brand("example.com") is None
    # 以下来自公开数据集中的真实误报
    assert D.lookalike_brand("www.email.si") is None  # email 与 gmail 只差一个字母
    assert D.lookalike_brand("groups.google.co.uk") is None  # 谷歌的国家域名
    assert D.lookalike_brand("apple.slashdot.org") is None  # 品牌词作为栏目子域名
    assert D.subdomain_depth("www.cs.waikato.ac.nz") == 2
    assert D.subdomain_depth("a.b.c.evil.com") == 3


def test_clean_business_email_has_no_hits():
    pe = parse_text("周五例会纪要", "各位好，附件是本周例会纪要，请查阅。如有补充请回复本邮件。\n详情见 https://wiki.corp.example/meeting", "张三 <zhangsan@corp.example>")
    assert evaluate(pe).score == 0


def test_bec_transfer_email():
    pe = parse_text("紧急付款", "我在开会不方便接电话，请今天之内把货款汇款到新的收款账户，账号如下。", "总经理 王总 <boss.wang@163.com>")
    hit = ids(pe)
    assert {"FREEMAIL_EXEC", "TEXT_MONEY", "TEXT_URGENCY"} <= hit


def test_header_url_attachment_rules():
    pe = ParsedEmail(
        subject="Your account will be suspended",
        from_addr="service@paypa1.com", from_name="PayPal <service@paypal.com>",
        reply_to="x@evil.example", return_path="b@evil.example",
        text="Please verify your account within 24 hours. 解压密码：1234",
        has_form=True,
        auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        urls=[
            UrlRef(href="http://198.51.100.7/login", text="https://www.paypal.com", domain="198.51.100.7", text_domain="www.paypal.com"),
            UrlRef(href="https://bit.ly/abc", domain="bit.ly"),
            UrlRef(href="https://xn--pypal-4ve.com/", domain="xn--pypal-4ve.com"),
            UrlRef(href="https://secure.login.account.verify.example.xyz/", domain="secure.login.account.verify.example.xyz"),
        ],
        attachments=[
            Attachment("invoice.pdf.exe", "application/octet-stream", 10, "0" * 64),
            Attachment("report.xlsm", "application/vnd.ms-excel", 10, "0" * 64),
            Attachment("files.zip", "application/zip", 10, "0" * 64),
        ],
    )
    hit = ids(pe)
    expected = {
        "AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL", "REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH",
        "DISPLAY_NAME_EMAIL", "DISPLAY_NAME_BRAND", "SENDER_LOOKALIKE",
        "URL_IP_HOST", "URL_TEXT_MISMATCH", "URL_PUNYCODE", "URL_SHORTENER", "URL_MANY_SUBDOMAINS", "URL_SUSPICIOUS_TLD", "URL_HTTP_LOGIN",
        "TEXT_URGENCY", "TEXT_CREDENTIAL", "TEXT_THREAT", "HTML_FORM",
        "ATT_DANGEROUS", "ATT_DOUBLE_EXT", "ATT_MACRO", "ATT_ARCHIVE_PASSWORD", "CRIT_AUTH_SPOOF",
    }
    missing = expected - hit
    assert not missing, missing
    res = evaluate(pe)
    assert res.score == 100 and res.critical
    assert res.hits[0].rule_id == "CRIT_AUTH_SPOOF"  # 关键规则排在最前


def test_legit_brand_sender_not_flagged():
    pe = ParsedEmail(from_addr="service@paypal.com", from_name="PayPal", auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
                     urls=[UrlRef(href="https://www.paypal.com/x", domain="www.paypal.com")])
    assert evaluate(pe).score == 0


def test_microsoft_rewards_is_official():
    # 真实邮箱中的误报：微软积分计划使用独立域名
    pe = ParsedEmail(from_addr="news@customeremail.microsoftrewards.com", from_name="Microsoft Rewards")
    assert "DISPLAY_NAME_BRAND" not in ids(pe)


def _weights(res):
    return {h.rule_id: h.weight for h in res.hits}


def test_trusted_sender_halves_wording_rules():
    # 真实邮箱中的误报：Steam 登录提醒，DMARC 通过
    body = "您的账号在新设备上登录，如非本人操作请立即修改密码"
    pe = ParsedEmail(subject="Steam 上有新的登录操作", text=body, from_addr="noreply@steampowered.com",
                     from_name="Steam", auth_results={"dmarc": "pass"})
    res = evaluate(pe)
    assert res.trusted_sender
    assert _weights(res)["TEXT_URGENCY"] == 5  # 10 → 5
    assert "DMARC" in next(h.evidence for h in res.hits if h.rule_id == "TEXT_URGENCY")
    # 同样内容，认证失败：不减半
    pe.auth_results = {"dmarc": "fail"}
    assert _weights(evaluate(pe))["TEXT_URGENCY"] == 10


def test_trusted_does_not_apply_to_impersonation():
    # DMARC 通过但域名仿冒（攻击者自己注册的 paypa1.com 也能配好 DMARC）：不算可信
    pe = ParsedEmail(subject="Account limited", text="Please verify your account immediately",
                     from_addr="service@paypa1.com", from_name="PayPal", auth_results={"dmarc": "pass"})
    res = evaluate(pe)
    assert not res.trusted_sender
    assert _weights(res)["TEXT_CREDENTIAL"] == 15


def test_own_domain_links_skip_url_rules():
    # 真实邮箱中的误报：阿里云邮件里的 http 激活链接指向 aliyun.com
    own = UrlRef(href="http://notice.aliyun.com/verify?code=1", domain="notice.aliyun.com")
    pe = ParsedEmail(from_addr="no-reply@notice.aliyun.com", auth_results={"dmarc": "pass"}, urls=[own])
    assert "URL_HTTP_LOGIN" not in ids(pe)
    pe.auth_results = {}  # 没有认证结果时照常判断
    assert "URL_HTTP_LOGIN" in ids(pe)
    # 认证通过，但链接指向别的域名：照常判断
    other = UrlRef(href="http://login-check.top/verify", domain="login-check.top")
    pe2 = ParsedEmail(from_addr="no-reply@notice.aliyun.com", auth_results={"dmarc": "pass"}, urls=[other])
    assert {"URL_HTTP_LOGIN", "URL_SUSPICIOUS_TLD"} <= ids(pe2)


def test_rule_ids_unique():
    assert len({r.rule_id for r in RULES}) == len(RULES)
