# Changelog

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
