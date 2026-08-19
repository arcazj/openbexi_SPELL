from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "scripts/qualification-v09.Dockerfile"
DOCKERIGNORE = ROOT / "scripts/qualification-v09.Dockerfile.dockerignore"


V09_RELEASE_SURFACE = tuple(
    sorted(
        {
            *(path.relative_to(ROOT).as_posix() for path in (ROOT / "scripts").glob("*v09*") if path.is_file()),
            *(path.relative_to(ROOT).as_posix() for path in (ROOT / "scripts/tests").glob("*v09*") if path.is_file()),
            "artifacts/v0.9/work-package/schema.json",
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py",
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v09_gate_0b.py",
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.9-gate-0b.json",
            "SPELL_v0.9_Gate_0B.md",
            "SPELL_v0.9_Release.md",
        }
    )
)


def test_v09_qualification_image_is_pinned_locked_and_non_root() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")

    assert source.startswith(
        "FROM python:3.13-slim@sha256:"
        "eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280\n"
    )
    assert "SPELL_QUALIFICATION_RELEASE=v0.9.0" in source
    assert "python -m pip install --require-hashes" in source
    for lock in (
        "backend/requirements.hashes.lock",
        "driver_host/pki-requirements.hashes.lock",
        "contracts/generator-requirements.hashes.lock",
        "scripts/supply-chain-requirements.hashes.lock",
    ):
        assert f"COPY {lock}" in source
    assert "COPY . /qualification-source" in source
    assert source.rstrip().endswith("USER spell")


def test_v09_qualification_context_is_candidate_bounded_with_v08_baseline() -> None:
    source = DOCKERIGNORE.read_text(encoding="utf-8")
    lines = source.splitlines()

    assert ".git" in lines
    assert "artifacts/**/.qualification" in lines
    assert lines.count("!artifacts/v0.9/work-package/schema.json") == 1
    assert "!artifacts/v0.9/work-package/qualification.json" not in lines
    assert "!artifacts/v0.8/release-qualification.json" not in lines
    for accepted_pair in (
        "!artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz",
        "!artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256",
    ):
        assert lines.count(accepted_pair) == 1
        assert lines.index(accepted_pair) > lines.index("artifacts/**/*.tar.gz")
    assert not any(
        line.startswith("!artifacts/v0.9/work-package/tests") for line in lines
    )


def test_v09_qualification_baseline_inputs_exist_as_regular_files() -> None:
    for relative in (
        "SPELL_v0.8_Release.md",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.8-gate-0b.json",
        "artifacts/v0.8/release-qualification.json",
        "artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz",
        "artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256",
    ):
        path = ROOT / relative
        assert path.is_file() and not path.is_symlink(), relative


def test_v09_release_surface_contains_no_mechanical_conversion_stale_constants() -> None:
    forbidden = tuple(
        "".join(parts)
        for parts in (
            ("451c065", "740e7b6501f86094d9be79578b30b1591"),
            ("a2369b9", "1796c7824ae93975420f6ca52060fc34e"),
            ("92f3b4ba7fe", "9c34ffcd94fd29d0d35716a5f9a5f"),
            ("accepted_", "v07_release_v09"),
            ("assert_accepted_", "v07_release_v09"),
            ("test_accepted_", "v07_release_v09"),
            ("seed_observation_", "v08"),
            ("LOCAL_SYNTHETIC_NON_CUI_", "DATA_SERVICE"),
            ("v0_7_", "immutability"),
            ("accepted_v07_", "artifacts_unchanged"),
            ("Assert-", "V07ArtifactsUnchanged"),
        )
    )
    for relative in V09_RELEASE_SURFACE:
        source = (ROOT / relative).read_text(encoding="utf-8")
        for stale in forbidden:
            assert stale not in source, f"{relative}: stale {stale}"

    for required in (
        "scripts/accepted_v08_release_v09.py",
        "scripts/assert_accepted_v08_release_v09.ps1",
        "scripts/tests/test_accepted_v08_release_v09.py",
    ):
        assert (ROOT / required).is_file(), required
    assert "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT" in (
        ROOT / "scripts/audit_supply_chain_v09.ps1"
    ).read_text(encoding="utf-8")


def test_v09_browser_entrypoint_contract_uses_the_built_html_path() -> None:
    declared_surfaces = (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.9-gate-0b.json",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py",
        "SPELL_v0.9_Gate_0B.md",
        "SPELL_v0.9_Release.md",
        "VERSION_TIMELINE.md",
        "PROVENANCE.md",
        "frontend/README.md",
    )
    for relative in declared_surfaces:
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "/development.html" in source, relative
        assert "`/development/`" not in source, relative
