import base64

from phishguard_detector import parse_bytes, parse_text

SUBJECT_B64 = "=?utf-8?b?" + base64.b64encode("账户即将冻结".encode()).decode() + "?="

PHISH_EML = """\
From: "IT Support" <support@paypa1-secure.com>
Reply-To: attacker@evil.example
Return-Path: <bounce@evil.example>
To: alice@corp.example
Subject: {subject}
Date: Tue, 05 Aug 2025 16:31:02 +0800
Message-ID: <abc@paypa1-secure.com>
Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=paypa1-secure.com; dkim=none; dmarc=fail
Received: from a by b
Received: from c by d
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XX"

--XX
Content-Type: text/html; charset=utf-8

<html><head><style>.x{}</style></head><body>
<p>您的账户将在24小时内冻结，请立即验证：</p>
<a href="http://198.51.100.7/login">https://www.paypal.com/verify</a>
<form action="http://198.51.100.7/post"><input type="password" name="p"></form>
</body></html>
--XX
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

TVqQAAMAAAAEAAAA
--XX--
""".replace("{subject}", SUBJECT_B64)


def test_parse_phishing_eml():
    pe = parse_bytes(PHISH_EML.encode("utf-8"))
    assert pe.subject == "账户即将冻结"
    assert pe.from_addr == "support@paypa1-secure.com"
    assert pe.from_name == "IT Support"
    assert pe.from_domain == "paypa1-secure.com"
    assert pe.reply_to_domain == "evil.example"
    assert pe.auth_results == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert pe.received_count == 2
    assert pe.has_html and pe.has_form
    assert "24小时内冻结" in pe.text
    assert ".x{}" not in pe.text  # style 内容不应进入正文

    anchor = next(u for u in pe.urls if u.text)
    assert anchor.domain == "198.51.100.7"
    assert anchor.text_domain == "www.paypal.com"  # 显示地址与实际地址不一致

    assert len(pe.attachments) == 1
    att = pe.attachments[0]
    assert att.filename == "invoice.pdf.exe" and att.size > 0 and len(att.sha256) == 64


def test_parse_plain_and_malformed():
    raw = b"Subject: hi\r\nFrom: bob@x.com\r\nContent-Type: text/plain; charset=unknown-8bit\r\n\r\nvisit www.example.com/a now\r\n"
    pe = parse_bytes(raw)
    assert pe.subject == "hi"
    assert [u.domain for u in pe.urls] == ["www.example.com"]
    assert pe.auth_results == {}


def test_parse_text_for_datasets():
    pe = parse_text("Win", "Click http://bit.ly/x   now\n\n\n\nthanks", "A <a@b.com>")
    assert pe.from_addr == "a@b.com"
    assert pe.urls[0].domain == "bit.ly"
    assert "\n\n\n" not in pe.text
    assert pe.model_input().startswith("Win\n")
