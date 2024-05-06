import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from fastapi_jwt import (
    AuthlibJWTBackend,
    JwtAccessCookie,
    JwtRefreshCookie,
    PythonJoseJWTBackend,
    define_default_jwt_backend,
)
from fastapi_jwt.jwt_backends import AbstractJWTBackend


def create_example_client(jwt_backend: AbstractJWTBackend):
    define_default_jwt_backend(jwt_backend)
    app = FastAPI()

    access_security = JwtAccessCookie(secret_key="secret_key")
    refresh_security = JwtRefreshCookie(secret_key="secret_key")

    @app.post("/auth")
    def auth(response: Response):
        subject = {"username": "username", "role": "user"}

        access_token = access_security.create_access_token(subject=subject)
        refresh_token = access_security.create_refresh_token(subject=subject)

        access_security.set_access_cookie(response, access_token)
        refresh_security.set_refresh_cookie(response, refresh_token)

        return {"access_token": access_token, "refresh_token": refresh_token}

    @app.delete("/auth")
    def logout(response: Response):
        access_security.unset_access_cookie(response)
        refresh_security.unset_refresh_cookie(response)

        return {"msg": "Successful logout"}

    return TestClient(app)


openapi_schema = {
    "openapi": "3.1.0",
    "info": {"title": "FastAPI", "version": "0.1.0"},
    "paths": {
        "/auth": {
            "post": {
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "summary": "Auth",
                "operationId": "auth_auth_post",
            },
            "delete": {
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "summary": "Logout",
                "operationId": "logout_auth_delete",
            },
        }
    },
}


@pytest.mark.parametrize("jwt_backend", [AuthlibJWTBackend, PythonJoseJWTBackend])
def test_openapi_schema(jwt_backend):
    client = create_example_client(jwt_backend)
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    assert response.json() == openapi_schema


@pytest.mark.parametrize("jwt_backend", [AuthlibJWTBackend, PythonJoseJWTBackend])
def test_security_jwt_auth(jwt_backend):
    client = create_example_client(jwt_backend)
    response = client.post("/auth")
    assert response.status_code == 200, response.text

    assert "access_token_cookie" in response.cookies
    assert response.cookies["access_token_cookie"] == response.json()["access_token"]
    assert "refresh_token_cookie" in response.cookies
    assert response.cookies["refresh_token_cookie"] == response.json()["refresh_token"]


@pytest.mark.parametrize("jwt_backend", [AuthlibJWTBackend, PythonJoseJWTBackend])
def test_security_jwt_logout(jwt_backend):
    client = create_example_client(jwt_backend)
    response = client.delete("/auth")
    assert response.status_code == 200, response.text

    assert "access_token_cookie" in response.headers["set-cookie"]
    assert 'access_token_cookie=""; Max-Age=-1;' in response.headers["set-cookie"]
    assert "refresh_token_cookie" in response.headers["set-cookie"]
    assert 'refresh_token_cookie=""; HttpOnly; Max-Age=-1' in response.headers["set-cookie"]
    # assert "access_token_cookie" not in response.cookies
    # assert response.cookies["access_token_cookie"].max_age == -1
    # assert "refresh_token_cookie" not in response.cookies
    # assert response.cookies["refresh_token_cookie"].max_age == -1
