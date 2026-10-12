"""tests for the flask api."""
from app import app


def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_health():
    res = client().get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_echo_ok():
    res = client().post("/echo", json={"message": "hi"})
    assert res.status_code == 200
    assert res.get_json()["message"] == "hi"


def test_echo_bad_body():
    res = client().post("/echo", json={"nope": 1})
    assert res.status_code == 400


def test_whoami_unauthorized():
    res = client().get("/whoami")
    assert res.status_code == 401
