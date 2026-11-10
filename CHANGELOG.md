# Changelog

## Latest Changes


- Require Python 3.11 or later. Test Python 3.11 through 3.15.
- Update FastAPI, Authlib, development dependencies, documentation dependencies, and GitHub Actions.
- Remove the python-jose backend and extra due to [GHSA-3qf3-8w2g-rqmx](https://github.com/advisories/GHSA-3qf3-8w2g-rqmx). Use `fastapi-jwt[authlib]` instead.
- Correct the status and rationale of the closed FastAPI integration PR.
