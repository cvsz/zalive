# {{PROJECT_NAME}}

{{DESCRIPTION}}

## Status

Project scaffold initialized from ztemplate. Application code, runtime CI, deployment, observability, and recovery must be implemented and validated before a production release.

## Getting started

1. Read [Startup guide](docs/startup.md) and complete [Implementation Checklist](IMPLEMENTATION-CHECKLIST.md).
2. Set language/runtime and package manager. Replace placeholder Makefile and Dockerfile with actual implementation or remove them.
3. Copy .env.example to .env and configure local-only, non-secret settings. Never commit .env.
4. Add application code, tests, CI and security scanners applicable to your stack.
5. Define ownership in .github/CODEOWNERS and SECURITY.md, then configure repository rulesets.

## Architecture and operations

- [Architecture](docs/architecture.md)
- [Development](docs/development.md)
- [Release](docs/release.md)
- [Startup decisions](docs/startup.md)
- [Cloudflare/DNS ownership contract](docs/cloudflare-terraform.md)

## Security

Report vulnerabilities through [GitHub security](https://github.com/{{OWNER}}/{{PROJECT_NAME}}/security) or the private channel documented in [SECURITY.md](SECURITY.md). Never include vulnerabilities or credentials in public issues.

## License

Review LICENSE copyright and choose a license before your first release. Template source retains the original copyright attribution where legally required.
