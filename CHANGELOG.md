# Changelog

## [0.4.0](https://github.com/k4black/fastapi-jwt/compare/0.3.1...0.4.0) (2026-11-14)

**Breaking changes**

- Require Python 3.11 or later. CI covers Python 3.11 through 3.15.
- Remove the python-jose backend and extra due to [GHSA-3qf3-8w2g-rqmx](https://github.com/advisories/GHSA-3qf3-8w2g-rqmx). Install `fastapi-jwt[authlib]` instead.
- Replace deprecated `authlib.jose` with joserfc. The `authlib` extra and `AuthlibJWTBackend` class names remain available.
- Default cookies to Secure, HttpOnly, and SameSite=Lax. Use HTTPS, or explicitly set `secure=False` for local HTTP development.

**Authentication fixes**

- Retain the 0.3.1 fixes for refresh-token confusion, invalid signatures, malformed subjects, and `from_other(auto_error=False)`.
- Validate expiration and token identifiers through the authentication error path.
- Preserve `timedelta(0)` in constructors, `from_other`, token creation, and cookie setters. Token validation retains its 10-second clock leeway.

**Features**

- Expose verified expiration through `JwtAuthorizationCredentials.exp`.
- Add optional audience and issuer validation. Revocation storage and checks remain application responsibilities.

**Maintenance**

- Update FastAPI, development dependencies, documentation dependencies, and GitHub Actions.
- Adopt Release Please, Ruff lint and format, and ty.
- Replace the personal email in package metadata with GitHub security reporting links.

Changes: [#63](https://github.com/k4black/fastapi-jwt/pull/63), [#64](https://github.com/k4black/fastapi-jwt/pull/64), [#65](https://github.com/k4black/fastapi-jwt/pull/65), [#66](https://github.com/k4black/fastapi-jwt/pull/66), [#68](https://github.com/k4black/fastapi-jwt/pull/68).

## 0.3.1 (2026-11-14)

- Fix refresh-token confusion, invalid signatures, malformed subjects, and explicit optional-authentication overrides.
- Preserve Python 3.8 support and both JWT backends.
- Credit @ohgoodjay as the original finder of the access-token type issue in [#6](https://github.com/k4black/fastapi-jwt/issues/6).
- See [GHSA-3m23-h9j2-f9xq](https://github.com/k4black/fastapi-jwt/security/advisories/GHSA-3m23-h9j2-f9xq).
