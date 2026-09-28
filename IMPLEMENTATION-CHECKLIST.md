# Implementation Checklist

Use this checklist after creating a repository from `ztemplate`.

## Bootstrap

- [ ] Generate a new repository using **Use this template**, not a fork when independent history is desired.
- [ ] Preview and apply `scripts/bootstrap.py` with the actual name, owner and description.
- [ ] Review the four changed identity files and commit `.ztemplate-initialized.json` as nonsecret setup evidence.
- [ ] Choose a project profile in `docs/profiles.md` and record non-goals.
- [ ] Confirm README and ABOUT describe the real project rather than the original author.

## Repository identity

- [ ] Replace `ztemplate` references with the real project name.
- [ ] Replace template descriptions and badges.
- [ ] Confirm license choice, retain valid original attribution and add the project's actual copyright holder/year as appropriate.
- [ ] Configure repository topics, description, homepage, and template status.

## Ownership and governance

- [ ] Update `.github/CODEOWNERS`.
- [ ] Review `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
- [ ] Configure branch protection or repository rulesets.
- [ ] Require pull request review where appropriate.
- [ ] Require passing status checks before merge.

## Security

- [ ] Review `SECURITY.md` and configure private vulnerability reporting.
- [ ] Enable Dependabot alerts and security updates.
- [ ] Review CodeQL language detection/support for the actual stack.
- [ ] Keep dependency review enabled for pull requests where supported.
- [ ] Configure secret scanning and push protection where available.
- [ ] Add stack-specific SAST, container, IaC, and SBOM checks as needed.
- [ ] Confirm Actions permissions follow least privilege.

## Development

- [ ] Select the language/runtime and package manager.
- [ ] Add formatter and linter configuration.
- [ ] Add unit, integration, and end-to-end tests as appropriate.
- [ ] Replace placeholder Makefile targets with real commands.
- [ ] Replace or remove the placeholder Dockerfile.
- [ ] Populate `.env.example` with safe non-secret keys only.

## Cloudflare and DNS

- [ ] Read `docs/cloudflare-terraform.md` before adding any hostname.
- [ ] Do not create a per-project `infrastructure/terraform/cloudflare`; public
      DNS records and tunnel ingress are owned by a single designated repository.
- [ ] Confirm the service answers on a loopback port before requesting a
      hostname.
- [ ] Declare the hostname on a feature branch in the owning repository and open
      a pull request from there.
- [ ] Import an existing record rather than creating or deleting it.
- [ ] Verify `terraform plan` reports `0 to destroy` before applying.
- [ ] Wait for that pull request to merge and clear review before applying; the
      shared tunnel also carries unrelated production hostnames.
- [ ] If the owning repository hands out an ingress fragment for a locally
      managed tunnel, confirm it lists the new hostname.
- [ ] Re-check the other hostnames on the shared tunnel for regressions.

## CI/CD

- [ ] Customize CI for the selected stack.
- [ ] Pin runtime versions and define supported-version matrices.
- [ ] Add build and package validation.
- [ ] Add artifact retention settings where needed.
- [ ] Configure environments, approvals, and deployment protections.
- [ ] Verify workflows from forks do not receive unsafe credentials.

## Release

- [ ] Decide on Semantic Versioning or another explicit versioning policy.
- [ ] Configure changelog and release-note generation.
- [ ] Configure package/container publishing only when needed.
- [ ] Add provenance, signing, and attestations for production artifacts where appropriate.
- [ ] Document rollback procedures.

## Documentation

- [ ] Complete `docs/architecture.md`.
- [ ] Complete `docs/development.md`.
- [ ] Complete `docs/release.md`.
- [ ] Add ADRs for material architectural decisions.
- [ ] Document operational ownership and support expectations.

## Final verification

- [ ] Fresh clone works with documented bootstrap steps.
- [ ] CI passes on `main` and pull requests.
- [ ] No secrets or private information are committed.
- [ ] Security checks are enabled and passing.
- [ ] A release can be created and rolled back according to documentation.
