"""Bootstrap startup tests: run with python3 -m unittest discover -s tests -v."""

import json
from pathlib import Path
import tempfile
import unittest

from scripts.bootstrap import initialize


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        samples = {
            "README.md": "# zTemplate\n",
            "ABOUT.md": "# About cvsz\n",
            ".github/CODEOWNERS": "* @cvsz\n/.github/ @cvsz\n",
            ".github/ISSUE_TEMPLATE/config.yml": "url: https://github.com/cvsz/ztemplate/security\n",
            "templates/project-readme.md": "# {{PROJECT_NAME}}\n{{DESCRIPTION}}\n{{OWNER}}\n",
            "templates/project-about.md": "# About {{PROJECT_NAME}}\n{{DESCRIPTION}}\n",
        }
        for path, data in samples.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data, encoding="utf-8")

    def run_init(self, apply=False, **kwargs):
        args = {"name": "example-app", "owner": "example-org", "codeowner": "example-org/maintainers", "description": "Example app"}
        args.update(kwargs)
        return initialize(self.root, apply=apply, **args)

    def test_dry_run_does_not_change_files(self):
        changes = self.run_init()
        self.assertEqual(len(changes), 4)
        self.assertEqual((self.root / "README.md").read_text(), "# zTemplate\n")
        self.assertFalse((self.root / ".ztemplate-initialized.json").exists())

    def test_apply_updates_only_allowlisted_files_and_is_idempotent(self):
        self.assertEqual(len(self.run_init(apply=True)), 4)
        self.assertIn("# example-app", (self.root / "README.md").read_text())
        self.assertIn("@example-org/maintainers", (self.root / ".github/CODEOWNERS").read_text())
        self.assertIn(
            "github.com/example-org/example-app/security",
            (self.root / ".github/ISSUE_TEMPLATE/config.yml").read_text(),
        )
        self.assertEqual(self.run_init(apply=True), [])
        marker = json.loads((self.root / ".ztemplate-initialized.json").read_text())
        self.assertEqual(marker["name"], "example-app")

    def test_refuses_conflicting_reinitialization(self):
        self.run_init(apply=True)
        with self.assertRaisesRegex(ValueError, "different settings"):
            self.run_init(apply=True, name="new-project")

    def test_refuses_invalid_names_and_description(self):
        for name in ("../escape", "-bad", "bad/name"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.run_init(name=name, apply=True)
        with self.assertRaises(ValueError):
            self.run_init(description="bad\nnew-line", apply=True)
        with self.assertRaises(ValueError):
            self.run_init(owner="-invalid", apply=True)
        with self.assertRaises(ValueError):
            self.run_init(codeowner="invalid/team/other", apply=True)
        self.assertFalse((self.root / ".ztemplate-initialized.json").exists())

    def test_refuses_symlink_target(self):
        target = self.root / "README.md"
        target.unlink()
        target.symlink_to(self.root / "ABOUT.md")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.run_init(apply=True)
        self.assertFalse((self.root / ".ztemplate-initialized.json").exists())


if __name__ == "__main__":
    unittest.main()
