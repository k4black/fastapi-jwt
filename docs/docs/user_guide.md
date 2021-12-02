# User guide 

This library made in fastapi style, so it can be used as standard security features 


## Example 


```python
from datetime import timedelta

from fastapi import FastAPI, Security, HTTPException
from fastapi_jwt import (
    JwtAccessBearerCookie,
    JwtAuthorizationCredentials,
    JwtRefreshBearer,
)


app = FastAPI()


# Read access token from bearer header and cookie (bearer priority)
access_security = JwtAccessBearerCookie(
    secret_key="secret_key",
    auto_error=False,
    access_expires_delta=timedelta(hours=1)  # change access token validation timedelta
)
# Read refresh token from bearer header only
refresh_security = JwtRefreshBearer(
    secret_key="secret_key", 
    auto_error=True  # automatically raise HTTPException: HTTP_401_UNAUTHORIZED 
)


@app.post("/auth")
def auth():
    # subject (actual payload) is any json-able python dict
    subject = {"username": "username", "role": "user"}
    
    # Create new access/refresh tokens pair
    access_token = access_security.create_access_token(subject=subject)
    refresh_token = refresh_security.create_refresh_token(subject=subject)

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/refresh")
def refresh(
        credentials: JwtAuthorizationCredentials = Security(refresh_security)
):
    # Update access/refresh tokens pair
    # We can customize expires_delta when creating
    access_token = access_security.create_access_token(subject=credentials.subject)
    refresh_token = refresh_security.create_refresh_token(subject=credentials.subject, expires_delta=timedelta(days=2))

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.get("/users/me")
def read_current_user(
        credentials: JwtAuthorizationCredentials = Security(access_security)
):  
    # auto_error=False, fo we should check manually
    if not credentials:
        raise HTTPException(status_code=401, detail='my-custom-details')
    
    # now we can access Credentials object
    return {"username": credentials["username"], "role": credentials["role"]}
```
