from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import pytest

from scripts import validate_markdown_v09 as markdown


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "scripts/supply-chain-requirements.hashes.lock"
RELEASE_DOCUMENTATION = (
    ROOT / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI" / "releases"
)


def test_markdown_preview_engine_is_exactly_hash_locked() -> None:
    source = LOCK.read_text(encoding="utf-8")
    assert re.search(
        r"(?m)^markdown-it-py==4\.2\.0 \\\n+\s+--hash=sha256:9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a$",
        source,
    )
    assert re.search(
        r"(?m)^mdurl==0\.1\.2 \\\n+\s+--hash=sha256:84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8$",
        source,
    )
    assert importlib.metadata.version("markdown-it-py") == "4.2.0"


def test_preview_engine_renders_commonmark_and_gfm_tables() -> None:
    rendered = markdown.preview_engine().render(
        "# Preview\n\n| A | B |\n| --- | --- |\n| one | ~~two~~ |\n"
    )
    assert "<h1>Preview</h1>" in rendered
    assert "<table>" in rendered
    assert "<s>two</s>" in rendered


def test_gitless_qualification_export_has_a_bounded_markdown_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "README.md").write_text("# Root\n", encoding="utf-8")
    nested = tmp_path / "docs"
    nested.mkdir()
    (nested / "Guide.md").write_text("# Guide\n", encoding="utf-8")

    def missing_git(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError("git")

    monkeypatch.setattr(markdown.subprocess, "run", missing_git)
    monkeypatch.delenv("SPELL_QUALIFICATION_SOURCE_ROOT", raising=False)
    with pytest.raises(markdown.MarkdownValidationError, match="cannot enumerate"):
        markdown.tracked_markdown(tmp_path)

    monkeypatch.setenv("SPELL_QUALIFICATION_SOURCE_ROOT", str(tmp_path))
    assert markdown.tracked_markdown(tmp_path) == ("README.md", "docs/Guide.md")


def test_comment_validation_does_not_treat_diagram_arrows_as_comment_ends() -> None:
    assert markdown._comments_are_closed("service ------> database")
    assert markdown._comments_are_closed("<!-- note -->\nservice --> database")
    assert not markdown._comments_are_closed("<!-- unclosed")


def test_every_tracked_markdown_file_renders_in_preview_mode() -> None:
    report = markdown.validate_markdown(ROOT)
    assert report.files == len(markdown.tracked_markdown(ROOT))
    assert report.tables > 0
    prompt = (ROOT / "PROMPT_Instructions.md").read_text(encoding="utf-8")
    history = (ROOT / "PROMPT_History.md").read_text(encoding="utf-8")
    provenance = (ROOT / "PROVENANCE.md").read_text(encoding="utf-8")
    for source in (prompt, history, provenance):
        normalized = " ".join(source.split())
        assert "one-shot transient issuer" in normalized
        assert "loopback-only" in normalized
        assert "finite `exp`" in normalized
        assert "running service" in normalized
        assert "under `var/`" in normalized
        assert "ignored local `.env`" in normalized
    assert "Default and qualification tokens remain short-lived" in " ".join(
        history.split()
    )
    assert "Default and qualification tokens remain short-lived" in " ".join(
        provenance.split()
    )
    assert "Default and qualification tokens must be short-lived" in " ".join(
        prompt.split()
    )


def test_never_versioned_v03_capture_is_not_a_nonportable_link() -> None:
    source = (RELEASE_DOCUMENTATION / "SPELL_v0.3_Release.md").read_text(
        encoding="utf-8"
    )
    assert "[Session access gate](artifacts/v0.3/session-access.png)" not in source
    assert "`artifacts/v0.3/session-access.png`" in source
    assert "never versioned" in source


def test_preview_rejects_a_missing_local_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "broken.md").write_text("[missing](no-such-file.md)\n", encoding="utf-8")
    monkeypatch.setattr(markdown, "tracked_markdown", lambda root: ("broken.md",))
    with pytest.raises(markdown.MarkdownValidationError, match="target is missing"):
        markdown.validate_markdown(tmp_path)


def test_preview_resolves_same_document_and_percent_decoded_heading_fragments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "anchors.md").write_text(
        "# Release Notes\n\n[same](#release-notes)\n"
        "[encoded](#release%2Dnotes)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(markdown, "tracked_markdown", lambda root: ("anchors.md",))
    report = markdown.validate_markdown(tmp_path)
    assert report.links == 2


def test_preview_resolves_duplicate_heading_suffixes_and_explicit_html_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "target.md").write_text(
        "# Repeat\n\n# Repeat\n\n<a id=\"operator-proof\"></a>\n",
        encoding="utf-8",
    )
    (tmp_path / "source.md").write_text(
        "[duplicate](target.md#repeat-1)\n[explicit](target.md#operator-proof)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        markdown, "tracked_markdown", lambda root: ("source.md", "target.md")
    )
    assert markdown.validate_markdown(tmp_path).links == 2


def test_preview_rejects_a_missing_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "broken.md").write_text(
        "# Present\n\n[missing](#absent)\n", encoding="utf-8"
    )
    monkeypatch.setattr(markdown, "tracked_markdown", lambda root: ("broken.md",))
    with pytest.raises(markdown.MarkdownValidationError, match="fragment is missing"):
        markdown.validate_markdown(tmp_path)


def test_preview_allows_parent_segments_that_remain_inside_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "target.md").write_text("# Target\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/source.md").write_text(
        "[target](../target.md#target)\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        markdown, "tracked_markdown", lambda root: ("docs/source.md", "target.md")
    )
    assert markdown.validate_markdown(tmp_path).links == 1
