# fastapi-jwt

[![Test](https://github.com/k4black/fastapi-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/k4black/fastapi-jwt/actions/workflows/test.yml)
[![Publish](https://github.com/k4black/fastapi-jwt/actions/workflows/publish.yml/badge.svg)](https://github.com/k4black/fastapi-jwt/actions/workflows/publish.yml)
[![codecov](https://codecov.io/gh/k4black/fastapi-jwt/branch/main/graph/badge.svg?token=3F9J850FX2)](https://codecov.io/gh/k4black/fastapi-jwt)
[![pypi](https://img.shields.io/pypi/v/fastapi-jwt)](https://pypi.org/project/fastapi-jwt/)

FastAPI native extension, easy and simple JWT auth

---


**Documentation:** [k4black.github.io/fastapi-jwt](https://k4black.github.io/fastapi-jwt/)  
**Source Code:** [github.com/k4black/fastapi-jwt](https://github.com/k4black/fastapi-jwt/)


## Features
* OpenAPI schema generation 
* Native integration with FastAPI
* Access/Refresh JWT
* JTI and expiration metadata
* Optional audience and issuer validation
* Cookie setting


## Installation
You can access package [fastapi-jwt in pypi](https://pypi.org/project/fastapi-jwt/)
```shell
pip install fastapi-jwt[authlib]
```

python-jose support was removed due to [GHSA-3qf3-8w2g-rqmx](https://github.com/advisories/GHSA-3qf3-8w2g-rqmx).

## Usage
This library made in fastapi style, so it can be used as standard security features 

```python
from fastapi import FastAPI, Security, Response
from fastapi_jwt import JwtAuthorizationCredentials, JwtAccessBearer


app = FastAPI()
access_security = JwtAccessBearer(secret_key="secret_key", auto_error=True)


@app.post("/auth")
def auth():
    subject = {"username": "username", "role": "user"}
    return {"access_token": access_security.create_access_token(subject=subject)}

@app.post("/auth_cookie")
def auth(response: Response):
    subject = {"username": "username", "role": "user"}
    access_token = access_security.create_access_token(subject=subject)
    access_security.set_access_cookie(response, access_token)
    return {"access_token": access_token}


@app.get("/users/me")
def read_current_user(
    credentials: JwtAuthorizationCredentials = Security(access_security),
):
    return {"username": credentials["username"], "role": credentials["role"]}
```

For more examples see usage docs


## Alternatives 

* FastAPI docs suggest [writing it manually](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), but
  * code duplication  
  * opportunity for bugs

* There is nice [fastapi-jwt-auth](https://github.com/IndominusByte/fastapi-jwt-auth/), but
  * poorly supported  
  * not "FastAPI-style" (not native functions parameters)

## FastAPI Integration 

[FastAPI PR #3305](https://github.com/fastapi/fastapi/pull/3305) is closed.
FastAPI declined built-in JWT support because token handling belongs in an external package.
The maintainer also declined the additional python-jose dependency.
See the [maintainer response](https://github.com/fastapi/fastapi/pull/3305#issuecomment-3121608562).
This project remains a separate FastAPI extension.

## Requirements 

* Python 3.11 or later
* `fastapi >=0.162.2`
* `joserfc >=1.8.0,<2.0.0`

## Security

Access dependencies reject refresh tokens. Invalid signatures and malformed credential payloads return authentication errors.
`auto_error=False` returns `None` for invalid credentials.
Tokens must contain an object in `subject`, the expected `type`, and a finite numeric `exp`.

Cookie helpers now default to `secure=True`, `httponly=True`, and `samesite="lax"`.
Use HTTPS. For local HTTP development, pass `secure=False` explicitly.
The keyword-only options preserve positional `expires_delta` arguments.
Use the same cookie options when you unset a cookie.
SameSite and HttpOnly do not provide complete CSRF protection.
Applications that accept cookies must validate Origin or use CSRF tokens for state-changing requests.
Do not change state through GET requests.

The `authlib` installation extra and `AuthlibJWTBackend` class now use joserfc.
Their public names remain available for compatibility. The implementation does not import deprecated `authlib.jose`.

## License
This project is licensed under the terms of the MIT license.
