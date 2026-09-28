# Optional project profiles

ztemplate intentionally does not install a framework, cloud provider, registry or data store automatically. Pick a profile, document an ADR and remove unneeded sample files.

| Profile | First deliverables | Required validation |
| --- | --- | --- |
| API/service | OpenAPI contract, auth model, DB migrations, idempotency and rate limits | contract tests, integration tests with real dependencies, auth negative cases |
| Web app | routing, accessibility, auth/session security, CSP and asset pipeline | unit tests, browser E2E, accessibility scan and production build |
| Worker/automation | queue contracts, deduplication, retry/backoff and dead-letter handling | failure injection, concurrent execution and poison-message tests |
| Library/SDK | public API, supported runtime matrix, SemVer and publish flow | compatibility matrix, package installation and reproducible release |
| CLI/desktop | install/update/uninstall, permissions and platform support | clean-install, offline/error handling, installer signing when required |
| Infrastructure | state ownership, drift handling, least-privilege credentials and DR | plan review, policy scan, staging apply and rollback drill |

Regardless of profile, decide data classification, security boundaries, supply-chain controls, observability, runbooks, cost limits and recovery objectives proportional to the actual system. Optional modules should not become compulsory dependencies for every generated repository.
