from pathlib import Path

import scripts.validate_repo as validate_repo


def test_markdown_link_validation_skips_virtualenv_content(tmp_path, monkeypatch):
    (tmp_path / "README.md").write_text("[local](docs.md)\n", encoding="utf-8")
    (tmp_path / "docs.md").write_text("Valid target.\n", encoding="utf-8")
    dependency_docs = tmp_path / "venv" / "lib" / "package"
    dependency_docs.mkdir(parents=True)
    (dependency_docs / "README.md").write_text(
        "[upstream](missing-upstream-doc.md)\n", encoding="utf-8"
    )
    monkeypatch.setattr(validate_repo, "ROOT", tmp_path)

    assert validate_repo.validate_markdown_links() == []
