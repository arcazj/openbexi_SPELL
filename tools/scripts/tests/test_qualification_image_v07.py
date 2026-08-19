from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "scripts/qualification-v07.Dockerfile"
DOCKERIGNORE = ROOT / "scripts/qualification-v07.Dockerfile.dockerignore"


def test_v07_qualification_image_is_pinned_locked_and_non_root() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")

    assert source.startswith(
        "FROM python:3.13-slim@sha256:"
        "eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280\n"
    )
    assert "SPELL_QUALIFICATION_RELEASE=v0.7.0" in source
    assert "python -m pip install --require-hashes" in source
    for lock in (
        "backend/requirements.hashes.lock",
        "driver_host/pki-requirements.hashes.lock",
        "contracts/generator-requirements.hashes.lock",
    ):
        assert f"COPY {lock}" in source
    assert "COPY . /qualification-source" in source
    assert source.rstrip().endswith("USER spell")


def test_v07_qualification_context_is_candidate_bounded_with_v06_baseline() -> None:
    source = DOCKERIGNORE.read_text(encoding="utf-8")
    lines = source.splitlines()

    assert ".git" in lines
    assert lines.count("!artifacts/v0.7/work-package/schema.json") == 1
    assert "!artifacts/v0.7/work-package/qualification.json" not in lines
    assert "!artifacts/v0.6/release-qualification.json" in lines
    for accepted_pair in (
        "!artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz",
        "!artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256",
    ):
        assert lines.count(accepted_pair) == 1
        assert lines.index(accepted_pair) > lines.index("artifacts/**/*.tar.gz")
    assert not any(
        line.startswith("!artifacts/v0.7/work-package/tests") for line in lines
    )


def test_v07_qualification_baseline_inputs_exist_as_regular_files() -> None:
    for relative in (
        "SPELL_v0.6_Release.md",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.6-gate-0b.json",
        "artifacts/v0.6/release-qualification.json",
        "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz",
        "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256",
    ):
        path = ROOT / relative
        assert path.is_file() and not path.is_symlink(), relative
