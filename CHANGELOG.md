# Changelog

## 0.3.1

- Reject refresh tokens and tokens without the access type at access-protected endpoints.
- Reject missing or invalid subject objects through the authentication error path.
- Handle invalid Authlib signatures through the authentication error path.
- Preserve explicit `auto_error=False` overrides in `from_other`.
- Replace the personal author email with GitHub security reporting links in package metadata.
- Preserve Python 3.8 support, both JWT backends, and existing cookie defaults.

Original report: [issue #6](https://github.com/k4black/fastapi-jwt/issues/6), opened by @ohgoodjay on 9 May 2022.
Security advisory: [GHSA-3m23-h9j2-f9xq](https://github.com/k4black/fastapi-jwt/security/advisories/GHSA-3m23-h9j2-f9xq).
