#!/usr/bin/env python3
"""Configure and verify GitHub repository administration gates for ztemplate.

Dry-run is the default. Use --apply only with an authenticated gh CLI identity
that has repository Administration permission.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

DEFAULT_REPO = "cvsz/ztemplate"
DEFAULT_BRANCH = "main"
REQUIRED_CHECKS = (
    "repository-baseline",
    "Analyze GitHub Actions",
    "dependency-review",
)


def gh_api(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> Any:
    cmd = ["gh", "api", "--method", method, "-H", "Accept: application/vnd.github+json", endpoint]
    if payload is not None:
        cmd += ["--input", "-"]
    proc = subprocess.run(
        cmd,
        input=json.dumps(payload) if payload is not None else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def require_gh() -> None:
    proc = subprocess.run(
        ["gh", "auth", "status"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("GitHub CLI is not authenticated. Run: gh auth login")


def protection_payload() -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": list(REQUIRED_CHECKS),
        },
        "enforce_admins": True,
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "required_approving_review_count": 1,
            "require_last_push_approval": True,
        },
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": False,
        "required_conversation_resolution": True,
        "lock_branch": False,
        "allow_fork_syncing": True,
    }


def print_plan(repo: str, branch: str) -> None:
    print(f"Repository: {repo}")
    print(f"Branch: {branch}")
    print("Planned administration changes:")
    print("- require pull requests with >=1 approval")
    print("- dismiss stale approvals")
    print("- require CODEOWNERS review")
    print("- require approval after the latest push")
    print("- require conversation resolution")
    print("- require branch to be up to date")
    print("- require checks:")
    for check in REQUIRED_CHECKS:
        print(f"  - {check}")
    print("- enforce rules for administrators")
    print("- block force pushes and branch deletion")
    print("- enable Dependabot vulnerability alerts and automated security fixes")
    print("- enable private vulnerability reporting")
    print("- enable secret scanning and push protection where GitHub supports them")
    print("- set default Actions GITHUB_TOKEN permission to read-only")
    print("- prevent Actions from approving pull requests")


def apply(repo: str, branch: str) -> None:
    gh_api("PUT", f"repos/{repo}/branches/{branch}/protection", protection_payload())

    gh_api("PUT", f"repos/{repo}/vulnerability-alerts")
    gh_api("PUT", f"repos/{repo}/automated-security-fixes")
    gh_api("PUT", f"repos/{repo}/private-vulnerability-reporting")

    repo_state = gh_api("GET", f"repos/{repo}")
    security = dict(repo_state.get("security_and_analysis") or {})
    desired_security = {}
    if "secret_scanning" in security:
        desired_security["secret_scanning"] = {"status": "enabled"}
    if "secret_scanning_push_protection" in security:
        desired_security["secret_scanning_push_protection"] = {"status": "enabled"}
    if desired_security:
        gh_api("PATCH", f"repos/{repo}", {"security_and_analysis": desired_security})

    gh_api(
        "PUT",
        f"repos/{repo}/actions/permissions/workflow",
        {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
    )


def verify(repo: str, branch: str) -> list[str]:
    errors: list[str] = []

    protection = gh_api("GET", f"repos/{repo}/branches/{branch}/protection")

    contexts = set(
        (protection.get("required_status_checks") or {}).get("contexts") or []
    )
    missing_checks = sorted(set(REQUIRED_CHECKS) - contexts)
    if missing_checks:
        errors.append(f"missing required status checks: {', '.join(missing_checks)}")

    if not (protection.get("required_status_checks") or {}).get("strict"):
        errors.append("required status checks are not strict/up-to-date")

    reviews = protection.get("required_pull_request_reviews") or {}
    if int(reviews.get("required_approving_review_count") or 0) < 1:
        errors.append("at least one approving review is not required")
    if not reviews.get("dismiss_stale_reviews"):
        errors.append("stale approvals are not dismissed")
    if not reviews.get("require_code_owner_reviews"):
        errors.append("CODEOWNERS review is not required")
    if not reviews.get("require_last_push_approval"):
        errors.append("approval after the latest push is not required")

    if not (protection.get("enforce_admins") or {}).get("enabled"):
        errors.append("branch protection is not enforced for administrators")
    if not (protection.get("required_conversation_resolution") or {}).get("enabled"):
        errors.append("conversation resolution is not required")
    if (protection.get("allow_force_pushes") or {}).get("enabled"):
        errors.append("force pushes are allowed")
    if (protection.get("allow_deletions") or {}).get("enabled"):
        errors.append("branch deletion is allowed")

    actions = gh_api("GET", f"repos/{repo}/actions/permissions/workflow")
    if actions.get("default_workflow_permissions") != "read":
        errors.append("default Actions workflow permission is not read-only")
    if actions.get("can_approve_pull_request_reviews") is not False:
        errors.append("Actions can approve pull requests")

    repo_state = gh_api("GET", f"repos/{repo}")
    security = repo_state.get("security_and_analysis") or {}
    if (security.get("secret_scanning") or {}).get("status") != "enabled":
        errors.append("secret scanning is not enabled")
    if (security.get("secret_scanning_push_protection") or {}).get("status") != "enabled":
        errors.append("secret scanning push protection is not enabled")

    try:
        private_reporting = gh_api("GET", f"repos/{repo}/private-vulnerability-reporting")
        if private_reporting.get("enabled") is not True:
            errors.append("private vulnerability reporting is not enabled")
    except RuntimeError as exc:
        errors.append(f"private vulnerability reporting not verified: {exc}")

    try:
        gh_api("GET", f"repos/{repo}/vulnerability-alerts")
    except RuntimeError as exc:
        errors.append(f"Dependabot vulnerability alerts not verified: {exc}")

    try:
        gh_api("GET", f"repos/{repo}/automated-security-fixes")
    except RuntimeError as exc:
        errors.append(f"Dependabot automated security fixes not verified: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--apply", action="store_true", help="apply administration changes")
    parser.add_argument("--verify", action="store_true", help="verify effective settings")
    args = parser.parse_args()

    require_gh()
    print_plan(args.repo, args.branch)

    if not args.apply and not args.verify:
        print("\nDry-run only. Re-run with --apply to mutate GitHub settings.")
        return 0

    if args.apply:
        apply(args.repo, args.branch)
        print("\nAdministration changes applied.")

    if args.verify or args.apply:
        errors = verify(args.repo, args.branch)
        if errors:
            print("\nVerification failed:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("\nVERIFIED: GitHub repository administration gate is enforced.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
