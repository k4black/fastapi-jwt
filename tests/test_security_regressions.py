from datetime import timedelta
from time import time
from typing import Optional

import pytest
from fastapi import FastAPI, Security
from fastapi.responses import Response
from fastapi.testclient import TestClient

from fastapi_jwt import JwtAccessBearer, JwtAccessCookie, JwtAuthorizationCredentials, JwtRefreshBearer
from fastapi_jwt.jwt_backends import AuthlibJWTBackend

KEY = "a" * 64


def client_for(security):
    app = FastAPI()

    @app.get("/")
    def read(credentials: Optional[JwtAuthorizationCredentials] = Security(security)):
        return credentials.subject if credentials else None

    return TestClient(app)


@pytest.mark.parametrize("auto_error", [True, False])
@pytest.mark.parametrize("security_cls", [JwtAccessBearer, JwtRefreshBearer])
def test_reject_other_token_type(auto_error, security_cls):
    security = security_cls(KEY, auto_error=auto_error)
    token = (
        security.create_refresh_token({"name": "test"})
        if security_cls is JwtAccessBearer
        else security.create_access_token({"name": "test"})
    )
    response = client_for(security).get("/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == (401 if auto_error else 200)
    if not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("auto_error", [True, False])
def test_reject_invalid_signature(auto_error):
    security = JwtAccessBearer(KEY, auto_error=auto_error)
    header, payload, signature = security.create_access_token({"name": "test"}).split(".")
    signature = ("a" if signature[0] != "a" else "b") + signature[1:]
    response = client_for(security).get("/", headers={"Authorization": f"Bearer {header}.{payload}.{signature}"})
    assert response.status_code == (401 if auto_error else 200)
    if not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("auto_error", [True, False])
@pytest.mark.parametrize(
    "patch",
    [
        {"subject": None},
        {"subject": []},
        {"subject": "user"},
        {"type": None},
        {"type": []},
        {"type": "unknown"},
        {"exp": None},
        {"exp": True},
        {"exp": float("nan")},
        {"exp": float("inf")},
        {"jti": 123},
    ],
)
def test_reject_invalid_payload(auto_error, patch):
    security = JwtAccessBearer(KEY, auto_error=auto_error)
    payload = {"subject": {"name": "test"}, "type": "access", "exp": int(time()) + 60}
    payload.update(patch)
    token = security.jwt_backend.encode(payload, KEY)
    response = client_for(security).get("/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == (401 if auto_error else 200)
    if not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("claim", ["subject", "type", "exp"])
def test_reject_missing_payload_claim(claim):
    security = JwtAccessBearer(KEY)
    payload = {"subject": {"name": "test"}, "type": "access", "exp": int(time()) + 60}
    del payload[claim]
    token = security.jwt_backend.encode(payload, KEY)
    assert client_for(security).get("/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_from_other_preserves_false():
    security = JwtAccessBearer(KEY, auto_error=True)
    assert JwtRefreshBearer.from_other(security, auto_error=False).auto_error is False
    assert JwtRefreshBearer.from_other(security).auto_error is True


@pytest.mark.parametrize("algorithm", ["none", "unknown"])
def test_reject_unsigned_or_unknown_algorithm(algorithm):
    with pytest.raises(ValueError):
        AuthlibJWTBackend(algorithm)


def test_cookie_defaults_and_logout():
    app = FastAPI()
    security = JwtAccessCookie(KEY)

    @app.post("/auth")
    def auth(response: Response):
        security.set_access_cookie(response, security.create_access_token({"name": "test"}), timedelta(minutes=1))

    @app.delete("/auth")
    def logout(response: Response):
        security.unset_access_cookie(response)

    @app.get("/")
    def read(credentials: JwtAuthorizationCredentials = Security(security)):
        return credentials.subject

    client = TestClient(app, base_url="https://testserver")
    response = client.post("/auth")
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert "Max-Age=60" in response.headers["set-cookie"]
    assert client.get("/").json() == {"name": "test"}
    client.delete("/auth")
    assert client.get("/").status_code == 401


def test_cookie_options_keep_positional_expiration():
    response = Response()
    JwtAccessCookie.set_access_cookie(
        response, "token", timedelta(seconds=30), secure=False, httponly=False, samesite="strict"
    )
    cookie = response.headers["set-cookie"]
    assert "Max-Age=30" in cookie
    assert "SameSite=strict" in cookie
    assert "Secure" not in cookie
    assert "HttpOnly" not in cookie


def test_decode_existing_authlib_token():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWJqZWN0Ijp7Im5hbWUiOiJsZWdhY3kifSwidHlwZSI6ImFjY2VzcyIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiJsZWdhY3kifQ."
        "1Lx16iWmSmjBKMGo3rJTbj51h19R4qz_huvLqWDYfKQ"
    )
    assert client_for(JwtAccessBearer(KEY)).get("/", headers={"Authorization": f"Bearer {token}"}).json() == {
        "name": "legacy"
    }


def test_rsa_private_signing_and_public_verification():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    token = JwtAccessBearer(private_pem, algorithm="RS256").create_access_token({"name": "rsa"})
    response = client_for(JwtAccessBearer(public_pem, algorithm="RS256")).get(
        "/", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"name": "rsa"}
