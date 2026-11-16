def login(client, username: str) -> dict:
    """测试账号的密码统一为 <用户名>-pass-123，见 conftest.client。"""
    r = client.post("/api/v1/auth/login", json={"username": username, "password": f"{username}-pass-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
