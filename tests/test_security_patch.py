from time import time
from typing import Optional

import pytest
from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from fastapi_jwt import (
    JwtAccessBearer,
    JwtAccessBearerCookie,
    JwtAccessCookie,
    JwtAuthorizationCredentials,
    JwtRefreshBearer,
    force_jwt_backend,
)

KEY = "security-patch-test-key-" * 3


def patch_client(security):
    app = FastAPI()

    @app.get("/")
    def protected(credentials: Optional[JwtAuthorizationCredentials] = Security(security)):
        return credentials.subject if credentials is not None else None

    return TestClient(app)


@pytest.mark.parametrize("auto_error", [True, False])
@pytest.mark.parametrize("token_type", ["access", "refresh", None])
@pytest.mark.parametrize(
    "security_cls,transport",
    [
        (JwtAccessBearer, "header"),
        (JwtAccessCookie, "cookie"),
        (JwtAccessBearerCookie, "header"),
        (JwtAccessBearerCookie, "cookie"),
    ],
)
def test_access_requires_access_type(jwt_backend, auto_error, token_type, security_cls, transport):
    force_jwt_backend(jwt_backend)
    security = security_cls(KEY, auto_error=auto_error)
    payload = {"subject": {"username": "test"}, "exp": int(time()) + 60, "jti": "test"}
    if token_type is not None:
        payload["type"] = token_type
    token = security.jwt_backend.encode(payload, KEY)
    client = patch_client(security)
    headers = {"Authorization": "Bearer " + token} if transport == "header" else {}
    if transport == "cookie":
        client.cookies.set("access_token_cookie", token)
    response = client.get("/", headers=headers)
    assert response.status_code == (200 if token_type == "access" or not auto_error else 401)
    if token_type == "access":
        assert response.json() == {"username": "test"}
    elif not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("auto_error", [True, False])
def test_invalid_signature_uses_authentication_error(jwt_backend, auto_error):
    force_jwt_backend(jwt_backend)
    security = JwtAccessBearer(KEY, auto_error=auto_error)
    header, payload, signature = security.create_access_token({"username": "test"}).split(".")
    signature = ("a" if signature[0] != "a" else "b") + signature[1:]
    response = patch_client(security).get(
        "/", headers={"Authorization": "Bearer " + ".".join((header, payload, signature))}
    )
    assert response.status_code == (401 if auto_error else 200)
    if not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("subject", [None, [], "test"])
@pytest.mark.parametrize("security_cls,token_type", [(JwtAccessBearer, "access"), (JwtRefreshBearer, "refresh")])
@pytest.mark.parametrize("auto_error", [True, False])
def test_invalid_subject_uses_authentication_error(jwt_backend, subject, security_cls, token_type, auto_error):
    force_jwt_backend(jwt_backend)
    security = security_cls(KEY, auto_error=auto_error)
    payload = {"subject": subject, "type": token_type, "exp": int(time()) + 60, "jti": "test"}
    token = security.jwt_backend.encode(payload, KEY)
    response = patch_client(security).get("/", headers={"Authorization": "Bearer " + token})
    assert response.status_code == (401 if auto_error else 200)
    if not auto_error:
        assert response.json() is None


def test_from_other_honors_optional_authentication(jwt_backend):
    force_jwt_backend(jwt_backend)
    source = JwtAccessBearer(KEY, auto_error=True)
    optional = JwtRefreshBearer.from_other(source, auto_error=False)
    response = patch_client(optional).get("/")
    assert response.status_code == 200
    assert response.json() is None
    assert patch_client(JwtRefreshBearer.from_other(source)).get("/").status_code == 401
