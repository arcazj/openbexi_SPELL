from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import select

from backend import development_analysis
from backend.development_domain import DevelopmentError, DevelopmentLimitError, canonical_json_bytes
from backend.development_models import DevelopmentLibraryCache
from backend.development_service import CATALOG_MEDIA_TYPE
from backend.procedure_parser import MAX_SOURCE_BYTES, ProcedureCatalog
from backend.tests.test_development_authoring_v09 import _catalog, _check, _create_text_resource
from backend.tests.test_development_service_v09 import OPERATOR, _create_project, _service


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_parser_selects_v09_and_preserves_legacy_profiles_deterministically() -> None:
    source = "\n".join(
        (
            "# @procedure local/profile-selection",
            "# @display-name Profile selection",
            "# @description v0.9 authoring profile over the inherited compiler",
            "# @language-profile spell-restricted-ast/0.9",
            '"""Profile selection."""',
            "ARGS(count='int')",
            "DataContainer('LOCAL.PROFILE')",
            "Log('ready')",
            "",
        )
    )
    first = development_analysis.analyze_source(
        source, "procedures/profile.spell.py", workspace_revision=9
    )
    second = development_analysis.analyze_source(
        source, "procedures/profile.spell.py", workspace_revision=9
    )
    assert first == second
    assert first.metadata["language-profile"] == "spell-restricted-ast/0.9"
    assert first.compiled["procedures/profile.spell.py"]["ir_version"] == "0.8"

    parser = ProcedureCatalog.__new__(ProcedureCatalog)
    assert parser.validate_source('Log("legacy")\n', "legacy.spell.py").ir_version == "0.3"
    assert parser.validate_source(
        'Prompt("typed", type="OK")\n', "typed.spell.py"
    ).ir_version == "0.6"
    assert parser.validate_source(
        "DataContainer('LOCAL.LEGACY')\n", "v08.spell.py"
    ).ir_version == "0.8"


def test_language_service_golden_diagnostics_outline_and_completions_are_deterministic() -> None:
    valid = "\n".join(
        (
            "# @procedure local/golden",
            "# @display-name Golden",
            "# @description Golden language-service proof",
            "# @language-profile spell-restricted-ast/0.9",
            "# @dictionary-reference DICT.A",
            "# @tm-reference TM.A",
            "# @tc-reference TC.A",
            '"""Golden."""',
            'ARGS(count="int")',
            'DataContainer("LOCAL.TEST")',
            'Log("ready")',
            "",
        )
    )
    invalid = "\n".join(
        (
            "# @procedure local/invalid",
            "# @language-profile spell-restricted-ast/0.9",
            "Log(",
            "",
        )
    )
    valid_first = development_analysis.analyze_source(
        valid, "procedures/golden.spell.py", workspace_revision=7
    )
    valid_second = development_analysis.analyze_source(
        valid, "procedures/golden.spell.py", workspace_revision=7
    )
    invalid_first = development_analysis.analyze_source(
        invalid, "procedures/invalid.spell.py", workspace_revision=7
    )
    invalid_second = development_analysis.analyze_source(
        invalid, "procedures/invalid.spell.py", workspace_revision=7
    )
    assert canonical_json_bytes(valid_first.__dict__) == canonical_json_bytes(
        valid_second.__dict__
    )
    assert canonical_json_bytes(invalid_first.__dict__) == canonical_json_bytes(
        invalid_second.__dict__
    )
    assert invalid_first.diagnostics == (
        {
            "diagnostic_id": "4f4bfcddcc7e10f5d6fc113fdd9eba9a6767085446143a201da3bc0855adfea5",
            "code": "SPELL001",
            "severity": "ERROR",
            "source_path": "procedures/invalid.spell.py",
            "start_line": 3,
            "start_column": 4,
            "end_line": 3,
            "end_column": 4,
            "language_profile": "spell-restricted-ast/0.9",
            "message": "'(' was never closed",
            "remediation_ref": "spell://diagnostics/SPELL001",
            "tool_version": "spell-development-analysis/0.10",
        },
    )
    assert [
        (item["kind"], item["name"], item["line"], item["column"])
        for item in valid_first.outline
    ] == [
        ("HEADER", "local/golden", 1, 1),
        ("HEADER", "Golden", 2, 1),
        ("HEADER", "Golden language-service proof", 3, 1),
        ("HEADER", "spell-restricted-ast/0.9", 4, 1),
        ("DICTIONARY_REFERENCE", "DICT.A", 5, 1),
        ("TM_REFERENCE", "TM.A", 6, 1),
        ("TC_REFERENCE", "TC.A", 7, 1),
        ("SPELL_CALL", "ARGS", 9, 1),
        ("SPELL_CALL", "DataContainer", 10, 1),
        ("STEP", "data_operation", 10, 1),
        ("SPELL_CALL", "Log", 11, 1),
        ("STEP", "log", 11, 1),
    ]
    labels = [item["label"] for item in valid_first.completions]
    assert labels == sorted(labels)
    assert labels == [
        "ARGS",
        "CloseFile",
        "CreateDictionary",
        "DataContainer",
        "GetSharedData",
        "GetTM",
        "LoadDictionary",
        "Log",
        "OpenFile",
        "Prompt",
        "ReadFile",
        "SaveDictionary",
        "SetSharedData",
        "StartProc",
        "Telemetry",
        "Var",
        "Verify",
        "Wait",
        "WaitFor",
        "WriteFile",
    ]
    assert len(labels) <= development_analysis.MAX_COMPLETION_ITEMS


def test_library_is_non_executing_digest_cached_and_explicitly_reparsed(tmp_path) -> None:
    service = _service(tmp_path)
    project = _create_project(service, "Library cache")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="libraries",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="libraries-folder",
    )
    source = "def bounded_helper(value):\n    return value\n"
    library = _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="libraries/helpers.library.py",
        content=source,
        kind="LIBRARY",
        media_type="text/x-python",
        key="library-source",
    )

    first = _check(
        service,
        project["project_id"],
        3,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="library-first",
    )
    assert first["report"]["outcome"] == "PASS"
    assert first["report"]["library_resource_cache"] == {
        "libraries/helpers.library.py": False
    }
    assert any(item["name"] == "bounded_helper" for item in first["report"]["outline"])

    second = _check(
        service,
        project["project_id"],
        3,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="library-second",
    )
    assert second["report"]["library_resource_cache"] == {
        "libraries/helpers.library.py": True
    }

    with service.factory.begin() as session:
        cache = session.scalar(
            select(DevelopmentLibraryCache).where(
                DevelopmentLibraryCache.project_id == project["project_id"],
                DevelopmentLibraryCache.cache_kind == "LIBRARY_INDEX",
            )
        )
        assert cache is not None
        cache.canonical_result = b"{}"
        cache.result_sha256 = hashlib.sha256(b"{}").hexdigest()
    recovered = _check(
        service,
        project["project_id"],
        3,
        scope="PROJECT",
        path=None,
        reparse=False,
        key="library-recover",
    )
    assert recovered["report"]["library_resource_cache"] == {
        "libraries/helpers.library.py": False
    }
    reparsed = _check(
        service,
        project["project_id"],
        3,
        scope="PROJECT",
        path=None,
        reparse=True,
        key="library-reparse",
    )
    assert reparsed["report"]["library_resource_cache"] == {
        "libraries/helpers.library.py": False
    }

    read = service.get_resource(
        project["project_id"], library["resource_id"], subject="viewer", role="viewer"
    )["resource"]
    assert read["kind"] == "LIBRARY"
    assert read["language"]["diagnostics"] == []


def test_library_limits_and_forbidden_imports_are_checked_before_execution(
    tmp_path, monkeypatch
) -> None:
    called = False

    def forbidden_parse(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("ast.parse must not receive oversized source")

    monkeypatch.setattr(development_analysis.ast, "parse", forbidden_parse)
    result = development_analysis.analyze_library_source(
        "x" * (MAX_SOURCE_BYTES + 1),
        "libraries/oversized.library.py",
        workspace_revision=1,
    )
    assert called is False
    assert [item["code"] for item in result.diagnostics] == ["LIBRARY_SOURCE_LIMIT"]

    service = _service(tmp_path)
    project = _create_project(service, "Library limits")
    _create_text_resource(
        service,
        project["project_id"],
        revision=1,
        path="libraries",
        content="",
        kind="FOLDER",
        media_type="application/x-directory",
        key="library-limit-folder",
    )
    with pytest.raises(DevelopmentLimitError):
        _create_text_resource(
            service,
            project["project_id"],
            revision=2,
            path="libraries/oversized.library.py",
            content="x" * (MAX_SOURCE_BYTES + 1),
            kind="LIBRARY",
            media_type="text/x-python",
            key="library-limit",
        )

    monkeypatch.undo()
    forbidden = "import socket\n"
    _create_text_resource(
        service,
        project["project_id"],
        revision=2,
        path="libraries/forbidden.library.py",
        content=forbidden,
        kind="LIBRARY",
        media_type="text/x-python",
        key="library-forbidden",
    )
    checked = _check(
        service,
        project["project_id"],
        3,
        scope="FILE",
        path="libraries/forbidden.library.py",
        reparse=False,
        key="library-forbidden-check",
    )
    assert [item["code"] for item in checked["report"]["diagnostics"]] == [
        "LIBRARY_IMPORT_FORBIDDEN"
    ]


@pytest.mark.parametrize("invalid_data", [None, "text", 3, [], True])
def test_catalog_snapshot_entry_data_is_a_bounded_object(tmp_path, invalid_data) -> None:
    service = _service(tmp_path)
    project = _create_project(service, f"Catalog data {type(invalid_data).__name__}")
    content, _ = _catalog("STRICT_CATALOG")
    value = json.loads(content)
    value["entries"][0]["data"] = invalid_data
    unsigned = {key: item for key, item in value.items() if key != "content_digest"}
    value["content_digest"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    encoded = canonical_json_bytes(value).decode("utf-8")
    with pytest.raises(DevelopmentError, match="data must be an object"):
        _create_text_resource(
            service,
            project["project_id"],
            revision=1,
            path="strict-catalog.json",
            content=encoded,
            kind="PROJECT_METADATA",
            media_type=CATALOG_MEDIA_TYPE,
            key=f"catalog-invalid-{type(invalid_data).__name__}",
        )
