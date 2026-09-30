# AGENTS.md — Repository Agent Contract

# Agent System Rules

## Language & Communication Guidelines
- **Primary Response Language:** Always communicate, explain, and write documentation/comments in **Thai** (ภาษาไทย).
- **Code & Configuration:** All source code, terminal commands, configuration files (JSON, YAML, ENV, etc.), variable names, and code syntax MUST remain in **English**.
- **Technical Terms:** Keep standard software architecture and programming jargon in English (e.g., *refactor*, *middleware*, *dependency injection*) to maintain accuracy.

## Response Behavior
1. **Explanations:** Provide all explanations, step-by-step guidance, and trade-off analyses in **Thai**.
2. **Code Blocks:** Write clean, executable code entirely in **English**. Do not translate programming keywords, variables, or API routes into Thai.
3. **Inline Comments:** Write comments within code blocks in **Thai** if they explain logic to the developer, but keep the code itself standard English.

## Purpose
`albert_server` is a Local Albert activation server for owned iOS devices (iPhone 5→15 Pro),
derived from `zTemplate` — it is a product, not a generic project template. Changes must stay
secure by default, keep the repository inheritable into a newly generated project, and avoid
inventing project-specific owners, domains, or providers.

## Operating rules
- Read README.md, CONTRIBUTING.md, SECURITY.md, ROADMAP.md, and the closest AGENTS.md before editing.
- Keep code, configuration, filenames, commit messages, and technical documentation both Thai/English.
- Prefer the smallest reviewable change that satisfies the requested scope.
- Never weaken CI, security scanning, dependency review, branch protections, or release controls merely to make a check pass.
- Never commit credentials, tokens, private keys, production endpoints, personal data, or realistic secrets. Use documented placeholders.
- Do not invent project-specific owners, domains, deployment providers, package registries, cloud accounts, or credentials.
- Preserve template portability across languages and frameworks unless a file explicitly declares a narrower scope.
- Reuse existing workflows and documents instead of creating overlapping alternatives.
- Pin permissions for GitHub Actions to least privilege and prefer maintained first-party/verified actions.
- Treat external input, generated artifacts, pull requests from forks, and dependency metadata as untrusted.

## Template placeholders
Use obvious placeholders such as `PROJECT_NAME`, `OWNER`, `example.com`, and `REPLACE_ME`. Any generated repository must be able to find and replace placeholders without exposing secrets.

## Review skill

- Use [Scrutinize](.agents/skills/scrutinize/SKILL.md) when asked to review, audit, sanity-check, or give a second opinion on a plan, PR, diff, design, or code change, or when invoked with `/scrutinize` in a compatible agent.
- Question whether the change is necessary or can be smaller before tracing real code paths and verifying behavioral claims. Cite concrete file/line evidence and distinguish unverified claims from confirmed behavior.
- The skill guides agent behavior; it does not itself install a slash command or replace required tests, CI, or human review.

## Project initialization

- For a repository created with **Use this template**, follow [docs/startup.md](docs/startup.md) and preview `scripts/bootstrap.py` before `--apply`; pass an actual GitHub user or org/team via `--codeowner` and verify write access.
- Do not present an initialized scaffold as a running or production-ready system; bootstrap changes project identity and ownership routing only.
- Replace Makefile and Dockerfile placeholders with actual project-specific commands and images before enabling an application delivery pipeline.
- Never overwrite existing application code, production secrets, DNS ownership or original license attribution during initialization.

## Change workflow
1. Inspect the current exact branch/head and existing files.
2. Identify the smallest missing or inconsistent template capability.
3. Add tests or validation first when practical.
4. Implement without widening scope.
5. Run the relevant validation and security checks.
6. Update documentation when behavior, setup, governance, or release procedures change.
7. Open a pull request; do not claim merge/release readiness without exact-head evidence.

## Verification
At minimum, verify Markdown/YAML syntax for touched files, workflow permissions/triggers, links and placeholders, absence of committed secrets, and consistency between README, templates, governance, security, and release documentation.

## Pull requests and releases
PRs must state scope, tests, security impact, compatibility/migration impact, documentation impact, deployment impact, and rollback. Releases require green required checks and explicit evidence; never infer production readiness from documentation alone.

## Security
Report vulnerabilities through SECURITY.md, not public issues. Security-related templates must redirect sensitive reports accordingly. Fail closed when a security-sensitive configuration is incomplete.

## Documentation ownership
- `.github/`: GitHub automation, community health, ownership, issue/PR templates.
- `docs/`: versioned engineering, operations, and release guidance.
- `docs/adr/`: architecture decision records.
- Root Markdown files: repository-wide policy and project lifecycle guidance.

## Nested AGENTS.md
Add a child AGENTS.md only when a subtree has durable rules that differ from this contract. The nearest AGENTS.md may add stricter local requirements but must not weaken repository-wide security rules.
