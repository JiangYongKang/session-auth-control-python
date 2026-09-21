"""应用装配冒烟测试。"""


def test_app_builds(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
