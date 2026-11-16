from tests.helpers import login


def test_login_and_me(client, admin_h):
    r = client.get("/api/v1/auth/me", headers=admin_h)
    assert r.status_code == 200 and r.json()["role"] == "admin"


def test_unauthenticated_and_bad_token(client):
    assert client.get("/api/v1/emails").json()["code"] == "UNAUTHORIZED"
    r = client.get("/api/v1/emails", headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401


def test_refresh_token(client):
    r = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer-pass-123"})
    refresh = r.json()["refresh_token"]
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200 and r2.json()["access_token"]
    # access token 不能当 refresh token 用
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": r.json()["access_token"]}).status_code == 401


def test_lockout_after_failures(client, admin_h):
    client.post("/api/v1/users", headers=admin_h, json={"username": "locky", "password": "locky-pass-123", "role": "viewer"})
    for _ in range(5):
        r = client.post("/api/v1/auth/login", json={"username": "locky", "password": "wrong-password"})
        assert r.status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "locky", "password": "locky-pass-123"})
    assert r.status_code == 423 and r.json()["code"] == "ACCOUNT_LOCKED"
    # 不存在的用户返回同样的错误，不泄露用户名是否存在
    r = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x"})
    assert r.status_code == 401 and r.json()["message"] == "用户名或密码错误"


def test_role_matrix(client, admin_h, operator_h, viewer_h):
    # viewer 只能看
    assert client.get("/api/v1/emails", headers=viewer_h).status_code == 200
    assert client.get("/api/v1/stats/overview", headers=viewer_h).status_code == 200
    assert client.post("/api/v1/detect/text", headers=viewer_h, json={"subject": "a", "body": "b"}).status_code == 403
    assert client.get("/api/v1/users", headers=viewer_h).status_code == 403
    # operator 可以检测、复核，但不能改配置
    assert client.post("/api/v1/detect/text", headers=operator_h, json={"subject": "hi", "body": "hello"}).status_code == 200
    assert client.post("/api/v1/allowlist", headers=operator_h, json={"type": "domain", "value": "x.com"}).status_code == 403
    assert client.put("/api/v1/settings", headers=operator_h, json={"observe_mode": False}).status_code == 403
    assert client.post("/api/v1/quarantine/delete", headers=operator_h, json={"ids": [1]}).status_code == 403
    # admin 全部可以
    assert client.get("/api/v1/users", headers=admin_h).status_code == 200


def test_admin_cannot_demote_self(client, admin_h):
    me = client.get("/api/v1/auth/me", headers=admin_h).json()
    r = client.patch(f"/api/v1/users/{me['id']}", headers=admin_h, json={"role": "viewer"})
    assert r.status_code == 400


def test_manual_detect_phishing_and_safe(client, operator_h):
    raw = (
        "From: \"PayPal\" <service@paypa1.com>\r\nTo: a@corp.test\r\nSubject: Your account is limited\r\n"
        "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<p>Please verify your account within 24 hours.</p><a href=\"http://198.51.100.7/login\">https://www.paypal.com/</a>"
    )
    r = client.post("/api/v1/detect/text", headers=operator_h, json={"raw": raw})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["verdict"] == "phishing"
    assert any(h["rule_id"] == "URL_TEXT_MISMATCH" for h in body["rules"]["hits"])
    assert body["verdict"]["summary"].startswith("判定为钓鱼邮件")

    r = client.post("/api/v1/detect/eml", headers=operator_h,
                    files={"file": ("ok.eml", b"From: tom@corp.test\r\nSubject: lunch\r\n\r\nLunch at noon tomorrow? Thanks, Tom", "message/rfc822")})
    assert r.status_code == 200 and r.json()["verdict"]["verdict"] in ("safe", "suspicious")
    assert client.post("/api/v1/detect/text", headers=operator_h, json={}).json()["code"] == "EMPTY_INPUT"


def test_allowlist_crud_and_validation(client, admin_h):
    r = client.post("/api/v1/allowlist", headers=admin_h, json={"type": "sender", "value": "not-an-email"})
    assert r.status_code == 400
    r = client.post("/api/v1/allowlist", headers=admin_h, json={"type": "domain", "value": "Partner.Example", "reason": "供应商"})
    assert r.status_code == 201 and r.json()["value"] == "partner.example"
    assert client.post("/api/v1/allowlist", headers=admin_h, json={"type": "domain", "value": "partner.example"}).status_code == 409
    eid = r.json()["id"]
    assert client.delete(f"/api/v1/allowlist/{eid}", headers=admin_h).status_code == 204


def test_settings_validation_and_audit(client, admin_h):
    assert client.put("/api/v1/settings", headers=admin_h, json={"suspicious_threshold": 90}).status_code == 400
    assert client.put("/api/v1/settings", headers=admin_h, json={"webhook_url": "http://x"}).status_code == 400
    r = client.put("/api/v1/settings", headers=admin_h, json={"phishing_threshold": 85})
    assert r.status_code == 200 and r.json()["phishing_threshold"] == 85
    client.put("/api/v1/settings", headers=admin_h, json={"phishing_threshold": 80})
    logs = client.get("/api/v1/audit-logs?action=settings.update", headers=admin_h).json()
    assert logs["total"] >= 2


def test_stats_endpoints(client, viewer_h):
    o = client.get("/api/v1/stats/overview", headers=viewer_h).json()
    assert {"today", "quarantined_now", "pending_review", "mailboxes"} <= set(o)
    t = client.get("/api/v1/stats/trend?days=7", headers=viewer_h).json()
    assert len(t) == 7 and set(t[0]) == {"date", "safe", "suspicious", "phishing"}


def test_mailbox_bad_connection_message(client, admin_h):
    r = client.post("/api/v1/mailboxes/test", headers=admin_h, json={
        "address": "x@nonexistent.invalid", "imap_host": "imap.nonexistent.invalid", "password": "x"})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "服务器" in r.json()["message"] or "IMAP" in r.json()["message"]


def test_credentials_never_returned(client, admin_h):
    r = client.get("/api/v1/mailboxes", headers=admin_h)
    for mb in r.json():
        assert "password" not in mb and "credential_enc" not in mb


def test_viewer_login_helper(client):
    assert "Authorization" in login(client, "viewer")
