# Maintenance progress

## Version update PR

- [x] Require Python 3.11 or later and test Python 3.11 through 3.15.
- [x] Update FastAPI, JWT backends, development dependencies, documentation dependencies, and GitHub Actions.
- [x] Update timezone mocks and cookie tests for current dependencies.
- [x] Test all 146 cases on each supported Python version.
- [x] Pass lint, typing, documentation builds, distribution checks, and `py.typed` checks.
- [x] Correct the closed FastAPI integration PR and explain the maintainer decision.
- [x] Add CI for minimum runtime dependencies and package artifacts.
- [ ] Require fresh GitHub checks before merging this PR.
- [ ] Close superseded version PRs #55, #59, #60, and #62 after this PR merges.

## Remaining work, in priority order

1. Reject refresh tokens on access routes: issues #6 and #14.
2. Complete PR #46 with signature regression tests: issue #50.
3. Validate payload fields before constructing credentials.
4. Harden cookie options and define CSRF protection: issue #32.
5. Preserve explicit `False` in `JwtAuthBase.from_other`.
6. Expose expiration metadata from PR #33 and document application revocation: issue #53.
7. Add audience and issuer validation: issue #12. Split the incompatible changes in PR #26.
8. Define standard `sub` compatibility separately: issue #13.
9. Replace deprecated `authlib.jose` before Authlib 2.0. Keep the current dependency below 2.0.
10. Revise cookie customization from PR #47: issue #21. Preserve positional arguments.
11. Publish fixed, tested tags without changing `main` or force-moving release tags.
12. Reproduce the two-cookie report in issue #30. Existing tests cover both cookies.
13. Add an RS256 example and test for issue #61 before adding a key API.
14. Confirm the released Authlib support and close completed issue #40.
15. Answer maintenance issue #3 after the first fixes and release plan are concrete.
16. Defer WebSocket support from issue #48 until authentication fixes pass.
17. Decline incomplete PR #7 and document application exception handlers.
18. Remove duplicate lint tools after identifying their unique checks.
19. Confirm the published package includes `py.typed` for issue #35. Current artifacts contain it.

## Dependency audit limits

The audit reports advisories without published fixes in python-jose 3.5.0 and its ecdsa dependency.
The project retains the deprecated backend for compatibility. New installations must prefer Authlib.

- [python-jose advisory](https://github.com/advisories/GHSA-3qf3-8w2g-rqmx)
- [ecdsa advisory](https://github.com/advisories/GHSA-wj6h-64fc-37mp)

## GitHub project setup

- Changed: enabled auto-merge, disabled Wiki, and resumed paused Dependabot security updates.
- Changed: activated the default-branch ruleset with 0 approvals and a verified admin bypass.
- The ruleset requires a PR, resolved conversations, linear history, and squash merges. It blocks force-pushes and branch deletion.
- Added an advisory PR-title workflow in this PR. Required status checks remain outside the setup scope.
- Already correct: squash-only merges, PR-title commit subjects, branch deletion after merge, and branch update suggestions.
- Already correct: Dependabot alerts, private vulnerability reporting, secret scanning, and push protection.
- Retained Issues only, as requested. Existing weekly pip and github-actions Dependabot entries both use `/`.
- Unavailable on this personal repository: merge queues and Enterprise commit-message rules.
- Organization-only features remain unavailable: generic secret patterns, validity checks, AI detection, and delegated secret workflows.
- Rulesets prevent accidents. Repository admins can change or bypass them.

Manual settings follow-ups at Settings > Security > Advanced Security:

- Check Dependabot malware alerts in the Dependabot section.
- Check grouped security updates in the Dependabot section. The repository toggle has no API.
- Automatic dependency submission is Maven-only and does not apply to this Python project.
- Generic patterns, validity checks, AI detection, and delegated options require an eligible organization plan.
