# fastapi-jwt

[![Test](https://github.com/k4black/fastapi-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/k4black/fastapi-jwt/actions/workflows/test.yml)
[![Publish](https://github.com/k4black/fastapi-jwt/actions/workflows/publish.yml/badge.svg)](https://github.com/k4black/fastapi-jwt/actions/workflows/publish.yml)
[![codecov](https://codecov.io/gh/k4black/fastapi-jwt/branch/master/graph/badge.svg?token=3F9J850FX2)](https://codecov.io/gh/k4black/fastapi-jwt)
[![pypi](https://img.shields.io/pypi/v/fastapi-jwt)](https://pypi.org/project/fastapi-jwt/)

FastAPI native extension, easy and simple JWT auth

---


**Documentation:** [k4black.github.io/fastapi-jwt](https://k4black.github.io/fastapi-jwt/)  
**Source Code:** [github.com/k4black/fastapi-jwt](https://github.com/k4black/fastapi-jwt/)


## Features
* OpenAPI schema generation 
* Native integration with FastAPI
* Access/Refresh JWT
* JTI
* Cookie setting


## Installation
You can access package [fastapi-jwt in pypi](https://pypi.org/project/fastapi-jwt/)
```shell
pip install fastapi-jwt
```


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

There it is open and maintained [Pull Request #3305](https://github.com/tiangolo/fastapi/pull/3305) to the `fastapi` repo. Currently, not considered.

## Requirements 

* `fastapi`
* `python-jose[cryptography]`

## License
This project is licensed under the terms of the MIT license.