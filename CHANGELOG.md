# Changelog

## [0.4.0](https://github.com/k4black/fastapi-jwt/compare/0.3.1...0.4.0) (2026-11-14)


### ⚠ BREAKING CHANGES

* Require Python 3.11 or later, remove python-jose support, and default cookies to Secure and HttpOnly. The authlib extra and AuthlibJWTBackend class remain available with joserfc.
* **deps:** update versions and drop python-jose support ([#63](https://github.com/k4black/fastapi-jwt/issues/63))

### Features

* jwt_backends - create backend mechanism and add authlib support ([#41](https://github.com/k4black/fastapi-jwt/issues/41)) ([0ea6c04](https://github.com/k4black/fastapi-jwt/commit/0ea6c045ab2821ffa47b4bad15fedb4cebbadab7))


### Bug Fixes

* &lt;3.9 set to tp.Set ([3aa6528](https://github.com/k4black/fastapi-jwt/commit/3aa6528d0eb649631aaec454d230367585d975d9))
* harden JWT validation and cookie authentication ([#64](https://github.com/k4black/fastapi-jwt/issues/64)) ([7d7f97c](https://github.com/k4black/fastapi-jwt/commit/7d7f97ca1f4df1b60c7c89c9536536303462d836))
* use explicit UTC timezone instead of `datetime.utcnow` ([#15](https://github.com/k4black/fastapi-jwt/issues/15)) ([60812d4](https://github.com/k4black/fastapi-jwt/commit/60812d4180d84b5d43f9d778338ba19a6fc7b308))


### Miscellaneous Chores

* **deps:** update versions and drop python-jose support ([#63](https://github.com/k4black/fastapi-jwt/issues/63)) ([0c6a43f](https://github.com/k4black/fastapi-jwt/commit/0c6a43fd2bda894bdd61a3c4c96498409af8e37c))

## Changelog

## Latest Changes

- Use Release Please for version PRs and publish fixed release tags.
- Replace Black, isort, Flake8, and mypy with Ruff lint, Ruff format, and ty.


- Require Python 3.11 or later. Test Python 3.11 through 3.15.
- Update FastAPI, Authlib, development dependencies, documentation dependencies, and GitHub Actions.
- Remove the python-jose backend and extra due to [GHSA-3qf3-8w2g-rqmx](https://github.com/advisories/GHSA-3qf3-8w2g-rqmx). Use `fastapi-jwt[authlib]` instead.
- Correct the status and rationale of the closed FastAPI integration PR.

- Reject refresh tokens on access routes and reject malformed credential payloads.
- Map invalid signatures and JOSE validation errors to the existing authentication error path.
- Preserve explicit `auto_error=False` overrides in `from_other`.
- Default cookies to Secure, HttpOnly, and SameSite=Lax. Preserve positional expiration arguments.
- Replace deprecated `authlib.jose` with joserfc without changing the backend class or installation extra name.

- Expose verified expiration as `JwtAuthorizationCredentials.exp`.
- Add optional audience and issuer requirements, token claims, and `from_other` inheritance.
- Preserve zero expiration durations in constructors, `from_other`, token creation, and cookie setters.
