#!/usr/bin/env python3
"""Initialize a repository created from ztemplate. Python 3.10+, stdlib only."""

import argparse
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import date

OWNER_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,39}(?<!-)$")
CODEOWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9][A-Za-z0-9-]{0,99})?$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MARKER = ".ztemplate-initialized.json"
FILES = (
    "README.md",
    "ABOUT.md",
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/config.yml",
)
TEMPLATES = {
    "README.md": "templates/project-readme.md",
    "ABOUT.md": "templates/project-about.md",
}


def safe_file(root: Path, relative: str) -> Path:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Missing or unsafe template file: {relative}")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes repository: {relative}")
    return path


def build_changes(root: Path, name: str, owner: str, codeowner: str, description: str) -> dict:
    if not NAME_RE.fullmatch(name) or name in {".", ".."}:
        raise ValueError("Invalid project name; use letters, digits, dot, hyphen or underscore")
    if not OWNER_RE.fullmatch(owner):
        raise ValueError("Invalid GitHub owner")
    if not CODEOWNER_RE.fullmatch(codeowner):
        raise ValueError("Invalid CODEOWNERS user or org/team; provide --codeowner explicitly")
    if not description.strip() or len(description) > 500 or "\n" in description or "\r" in description:
        raise ValueError("Description must be one nonempty line (max 500 characters)")
    # Escape generated Markdown and YAML contexts independently.
    markdown_description = description.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    markdown_description = markdown_description.replace("\\", "\\\\")
    values = {
        "{{PROJECT_NAME}}": name,
        "{{OWNER}}": owner,
        "{{DESCRIPTION}}": markdown_description,
    }
    changes = {}
    for target, source in TEMPLATES.items():
        raw = safe_file(root, source).read_text(encoding="utf-8")
        for key, replacement in values.items():
            raw = raw.replace(key, replacement)
        if re.search(r"\{\{[A-Z_]+\}\}", raw):
            raise ValueError(f"Unresolved placeholder in {source}")
        changes[target] = raw
    codeowners = safe_file(root, ".github/CODEOWNERS").read_text(encoding="utf-8")
    if "@cvsz" not in codeowners:
        raise ValueError("Unexpected CODEOWNERS template; manual review required")
    changes[".github/CODEOWNERS"] = codeowners.replace("@cvsz", "@" + codeowner)
    issue = safe_file(root, ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
    old_url = "https://github.com/cvsz/ztemplate/security"
    if issue.count(old_url) != 1:
        raise ValueError("Unexpected issue security URL; manual review required")
    changes[".github/ISSUE_TEMPLATE/config.yml"] = issue.replace(
        old_url, f"https://github.com/{owner}/{name}/security"
    )
    for target in FILES:
        safe_file(root, target)
    return changes


def initialize(root: Path, name: str, owner: str, codeowner: str, description: str, apply: bool) -> list[str]:
    root = root.resolve()
    marker = root / MARKER
    args = {"name": name, "owner": owner, "codeowner": codeowner, "description": description.strip()}
    if marker.exists() or marker.is_symlink():
        if marker.is_symlink() or not marker.is_file():
            raise ValueError("Unsafe initialization marker")
        previous = json.loads(marker.read_text(encoding="utf-8"))
        if previous != args:
            raise ValueError("Already initialized with different settings; edit manually")
        return []
    changes = build_changes(root, name, owner, codeowner, description.strip())
    modified = sorted(path for path, data in changes.items() if safe_file(root, path).read_text(encoding="utf-8") != data)
    if apply:
        # All inputs validated before any writes. Keep the branch clean so git can rollback.
        for target in modified:
            path = safe_file(root, target)
            fd, temp_path = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
                    out.write(changes[target])
                os.chmod(temp_path, path.stat().st_mode & 0o777)
                os.replace(temp_path, path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
        marker.write_text(json.dumps(args, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return modified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="Repository name")
    parser.add_argument("--owner", required=True, help="GitHub user or organization")
    parser.add_argument("--codeowner", required=True, help="Existing GitHub username or org/team with write access")
    parser.add_argument("--description", required=True, help="One-line project description")
    parser.add_argument("--apply", action="store_true", help="Write changes; otherwise dry run")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        modified = initialize(args.root, args.name, args.owner, args.codeowner, args.description, args.apply)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"bootstrap: {exc}\n")
    label = "Applied" if args.apply else "Planned"
    print(f"{label}: {', '.join(modified) if modified else 'already initialized / no changes'}")
    if args.apply:
        print("Next: verify CODEOWNERS identity has write access; review LICENSE, SECURITY.md, CI, deployment and IMPLEMENTATION-CHECKLIST.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
