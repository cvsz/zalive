#!/usr/bin/env python3
"""Validate ztemplate structure and local Markdown links."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = (
    "README.md",
    "ABOUT.md",
    "AGENTS.md",
    "CLAUDE.md",
    "OPENCODE.md",
    "ZEAZ-INTRODUCTION.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "ROADMAP.md",
    "IMPLEMENTATION-CHECKLIST.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/dependabot.yml",
    "docs/ai/README.md",
    "docs/ai/guides",
    "docs/ai/playbooks",
    "docs/ai/prompts",
    "skills/zeaz-skill-finder/SKILL.md",
    "components.d/zeaz-engineering.yml",
    "plugins.d/zeaz-skills.yml",
    "ecc-install.json",
    "scripts/github_admin.py",
    "docs/ai/guides/github-repository-admin.md",
)

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#", "data:")


def validate_required_paths() -> list[str]:
    errors: list[str] = []
    for rel in REQUIRED_PATHS:
        if not (ROOT / rel).exists():
            errors.append(f"missing required path: {rel}")
    return errors


def normalize_link_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    target = target.split("#", 1)[0].split("?", 1)[0]
    return unquote(target)


def validate_markdown_links() -> list[str]:
    errors: list[str] = []
    for md in sorted(ROOT.rglob("*.md")):
        if ".git" in md.parts:
            continue
        text = md.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            raw = match.group(1).strip()
            if not raw or raw.startswith(SKIP_PREFIXES):
                continue
            target = normalize_link_target(raw)
            if not target:
                continue
            link_base = ROOT if md.relative_to(ROOT).as_posix() == "templates/project-readme.md" else md.parent
            resolved = (link_base / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{md.relative_to(ROOT)}: link escapes repository: {raw}")
                continue
            if not resolved.exists():
                errors.append(f"{md.relative_to(ROOT)}: broken local link: {raw}")
    return errors


def main() -> int:
    errors = validate_required_paths() + validate_markdown_links()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Repository structure and local Markdown links are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
