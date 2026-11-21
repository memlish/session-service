import time

from authlib.jose import JsonWebToken
from fastapi.testclient import TestClient

from session_service.app import app
from session_service.config import settings

client = TestClient(app)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def login(user_id: str = "u-1001") -> str:
    r = client.post("/sessions", json={"user_id": user_id})
    assert r.status_code == 201
    return r.json()["token"]


def signed(claims: dict, key: bytes = settings.signing_key) -> str:
    return JsonWebToken(["HS256"]).encode({"alg": "HS256"}, claims, key).decode()


def base_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": "u-1001",
        "roles": ["user"],
        "iat": now,
        "exp": now + 600,
        "jti": "test-session",
    }
    claims.update(overrides)
    return claims


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_issue_and_resolve_session():
    r = client.get("/me", headers=bearer(login("u-1002")))
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == "u-1002"
    assert body["roles"] == ["user", "support"]


def test_unknown_user_cannot_get_session():
    r = client.post("/sessions", json={"user_id": "u-9999"})
    assert r.status_code == 404


def test_missing_or_malformed_header():
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get("/me", headers=bearer("not-a-jwt")).status_code == 401


def test_wrong_key_rejected():
    token = signed(base_claims(), key=b"some-other-key")
    assert client.get("/me", headers=bearer(token)).status_code == 401


def test_expired_token_rejected():
    token = signed(base_claims(iat=int(time.time()) - 7200, exp=int(time.time()) - 3600))
    assert client.get("/me", headers=bearer(token)).status_code == 401


def test_wrong_audience_rejected():
    token = signed(base_claims(aud="mobile"))
    assert client.get("/me", headers=bearer(token)).status_code == 401


def test_revoked_session_rejected():
    token = login()
    assert client.post("/sessions/revoke", headers=bearer(token)).status_code == 204
    assert client.get("/me", headers=bearer(token)).status_code == 401
