# Classes

This library made in fastapi style, so it can be used as standard security features 


## Security classes 

#### Credentials 

* `JwtAuthorizationCredentials` - universal credentials for access and refresh tokens.  
    Provide access to subject and unique token identifier (jti)
    ```python
    def foo(credentials: JwtAuthorizationCredentials = Security(access_security)):
        return credentials["username"], credentials.jti
    ```

#### Access tokens

* `JwtAccessBearer` - read access token from bearer header only
* `JwtAccessCookie` - read access token from cookies only
* `JwtAccessBearerCookie` - read access token from both bearer and cookie

#### Refresh tokens

* `JwtRefreshBearer` - read access token from bearer header only
* `JwtRefreshCookie` - read access token from cookies only
* `JwtRefreshBearerCookie` - read access token from both bearer and cookie


### Create

You can create `access_security` / `refresh_security` in multiple ways 
```python
# Manually
access_security = JwtAccessBearerCookie(
    secret_key="other_secret_key",
    auto_error=True,
    access_expires_delta=timedelta(hours=1),  # custom access token valid timedelta
    refresh_expires_delta=timedelta(days=1),  # custom access token valid timedelta
)

# Create from another object, copy all params
refresh_security = JwtRefreshBearer.from_other(access_security)

# Create from another object, rewrite some params
other_access_security = JwtAccessCookie.from_other(
    access_security, 
    secret_key='!key!', 
    auto_error=False
)
```

For tokens, `None` uses the configured expiration duration, or the duration copied by `from_other`.
`timedelta(0)` creates a token with `exp` equal to `iat`.
Token validation retains its 10-second clock leeway.
For cookie setters, `timedelta(0)` sets `Max-Age=0` to expire the cookie immediately.
Cookie expiration uses only the setter's `expires_delta` argument, independently of the configured token duration.
With `None`, the setter creates a session cookie without `Max-Age`.
