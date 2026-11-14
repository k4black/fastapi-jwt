import base64
import json
from datetime import timedelta

import pytest
from fastapi import Response

from fastapi_jwt import JwtAccessBearer

KEY = "a" * 64


@pytest.mark.parametrize("token_type", ["access", "refresh"])
@pytest.mark.parametrize("source", ["constructor", "from_other", "token"])
def test_zero_token_expiration(token_type, source):
    expiration = {f"{token_type}_expires_delta": timedelta(0)}
    security = JwtAccessBearer(KEY)
    if source == "constructor":
        security = JwtAccessBearer(KEY, **expiration)
    elif source == "from_other":
        security = JwtAccessBearer.from_other(security, **expiration)
    options = {"expires_delta": timedelta(0)} if source == "token" else {}
    token = getattr(security, f"create_{token_type}_token")({"name": "test"}, **options)
    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert payload["exp"] == payload["iat"]


@pytest.mark.parametrize("token_type", ["access", "refresh"])
@pytest.mark.parametrize("duration, max_age", [(None, None), (timedelta(0), "0"), (timedelta(seconds=30), "30")])
def test_cookie_expiration(token_type, duration, max_age):
    response = Response()
    getattr(JwtAccessBearer, f"set_{token_type}_cookie")(response, "token", duration)
    cookie = response.headers["set-cookie"]
    if max_age is None:
        assert "Max-Age" not in cookie
    else:
        assert f"Max-Age={max_age};" in cookie
