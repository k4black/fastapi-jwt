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
    JwtRefreshBearerCookie,
    JwtRefreshCookie,
)

KEY = "a" * 64


def claims_client(security):
    app = FastAPI()

    @app.get("/")
    def read(credentials: Optional[JwtAuthorizationCredentials] = Security(security)):
        if credentials is None:
            return None
        return {"subject": credentials.subject, "jti": credentials.jti, "exp": credentials.exp}

    return TestClient(app)


def test_expose_verified_expiration():
    security = JwtAccessBearer(KEY)
    token = security.jwt_backend.encode(
        {"subject": {"name": "test"}, "type": "access", "exp": 4102444800, "jti": "test-id"}, KEY
    )
    response = claims_client(security).get("/", headers={"Authorization": f"Bearer {token}"})
    assert response.json() == {"subject": {"name": "test"}, "jti": "test-id", "exp": 4102444800}


@pytest.mark.parametrize(
    "security_cls,token_method",
    [
        (JwtAccessBearer, "create_access_token"),
        (JwtAccessCookie, "create_access_token"),
        (JwtAccessBearerCookie, "create_access_token"),
        (JwtRefreshBearer, "create_refresh_token"),
        (JwtRefreshCookie, "create_refresh_token"),
        (JwtRefreshBearerCookie, "create_refresh_token"),
    ],
)
def test_generate_configured_claims(security_cls, token_method):
    security = security_cls(KEY, audience="api", issuer="issuer")
    token = getattr(security, token_method)({"name": "test"})
    payload = security.jwt_backend.decode(token, KEY)
    assert payload["aud"] == "api"
    assert payload["iss"] == "issuer"


@pytest.mark.parametrize("auto_error", [True, False])
@pytest.mark.parametrize(
    "claims,valid",
    [
        ({"aud": "api", "iss": "issuer"}, True),
        ({"aud": ["another-api", "api"], "iss": "issuer"}, True),
        ({"aud": "wrong", "iss": "issuer"}, False),
        ({"aud": ["wrong"], "iss": "issuer"}, False),
        ({"aud": "api", "iss": "wrong"}, False),
        ({"aud": "api"}, False),
        ({"iss": "issuer"}, False),
        ({}, False),
    ],
)
def test_require_configured_claims(auto_error, claims, valid):
    security = JwtAccessBearer(KEY, auto_error=auto_error, audience="api", issuer="issuer")
    payload = {"subject": {"name": "test"}, "type": "access", "exp": 4102444800, **claims}
    token = security.jwt_backend.encode(payload, KEY)
    response = claims_client(security).get("/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == (200 if valid or not auto_error else 401)
    if not valid and not auto_error:
        assert response.json() is None


@pytest.mark.parametrize("options", [{}, {"audience": "api"}, {"issuer": "issuer"}])
def test_unconfigured_claims_remain_optional(options):
    security = JwtAccessBearer(KEY, **options)
    token = security.create_access_token({"name": "test"})
    assert claims_client(security).get("/", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_from_other_copies_and_overrides_claims():
    security = JwtAccessBearer(KEY, audience="api", issuer="issuer")
    refresh = JwtRefreshBearer.from_other(security)
    token = refresh.create_refresh_token({"name": "test"})
    assert claims_client(refresh).get("/", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    payload = refresh.jwt_backend.decode(token, KEY)
    assert payload["aud"] == "api"
    assert payload["iss"] == "issuer"
    override = JwtRefreshBearer.from_other(security, audience="other-api", issuer="other-issuer")
    payload = override.jwt_backend.decode(override.create_refresh_token({"name": "test"}), KEY)
    assert payload["aud"] == "other-api"
    assert payload["iss"] == "other-issuer"
