from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import validate_candidate_evidence_v05 as evidence


def _write_junit(
    path: Path,
    cases: list[tuple[str, str, str]],
    *,
    reported_tests: int | None = None,
) -> None:
    children = []
    skipped = failures = errors = 0
    for classname, name, status in cases:
        child = ""
        if status == "skipped":
            child = '<skipped message="controlled skip" />'
            skipped += 1
        elif status == "failure":
            child = '<failure message="controlled failure" />'
            failures += 1
        elif status == "error":
            child = '<error message="controlled error" />'
            errors += 1
        children.append(
            f'<testcase classname="{classname}" name="{name}">{child}</testcase>'
        )
    count = len(cases) if reported_tests is None else reported_tests
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites name="pytest tests">'
        f'<testsuite name="pytest" tests="{count}" skipped="{skipped}" '
        f'failures="{failures}" errors="{errors}">'
        + "".join(children)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )


def _suite(nodes: list[str], capture: str, result: evidence.JUnitResult) -> dict:
    return {
        "capture": capture,
        "collected_nodes": nodes,
        "inventory_sha256": evidence.inventory_sha256(nodes),
        "test_count": len(nodes),
        "subtest_count": result.subtests,
        "passed_count": result.passed,
        "skipped_count": result.skipped,
        "failure_count": result.failures,
        "error_count": result.errors,
        "network_mode": "internal",
    }


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"one","schema_version":"two"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
    ],
)
def test_strict_json_rejects_duplicate_keys_and_nonfinite_values(
    tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "candidate.json"
    path.write_bytes(raw)

    with pytest.raises(evidence.CandidateEvidenceError):
        evidence.read_strict_json(path, "candidate")


def test_junit_rejects_dtd_before_xml_parsing(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.xml"
    path.write_text(
        '<!DOCTYPE testsuite [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase classname="backend.tests.test_example" name="test_value">'
        "&leak;</testcase></testsuite>",
        encoding="utf-8",
    )

    with pytest.raises(evidence.CandidateEvidenceError, match="DTD"):
        evidence.parse_junit(path, "unsafe JUnit")


def test_junit_rejects_duplicate_testcase_identity(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.xml"
    case = ("backend.tests.test_example", "test_value", "passed")
    _write_junit(path, [case, case])

    with pytest.raises(evidence.CandidateEvidenceError, match="duplicate testcase"):
        evidence.parse_junit(path, "duplicate JUnit")


def test_junit_rejects_false_aggregate(tmp_path: Path) -> None:
    path = tmp_path / "aggregate.xml"
    _write_junit(
        path,
        [("backend.tests.test_example", "test_value", "passed")],
        reported_tests=2,
    )

    with pytest.raises(evidence.CandidateEvidenceError, match="aggregate differs"):
        evidence.parse_junit(path, "aggregate JUnit")


def test_junit_accepts_only_the_exact_declared_subtest_aggregate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "subtests.xml"
    _write_junit(
        path,
        [("scripts.tests.test_example", "test_value", "passed")],
        reported_tests=3,
    )

    result = evidence.parse_junit(
        path,
        "subtest JUnit",
        expected_subtests=2,
    )

    assert result.subtests == 2
    with pytest.raises(evidence.CandidateEvidenceError, match="subtest aggregate differs"):
        evidence.parse_junit(
            path,
            "subtest JUnit",
            expected_subtests=1,
        )


def test_junit_reconstructs_unittest_class_node(tmp_path: Path) -> None:
    path = tmp_path / "class.xml"
    _write_junit(
        path,
        [
            (
                "scripts.tests.test_release_framework_v04.V04ReleaseFrameworkTests",
                "test_exact_evidence",
                "passed",
            )
        ],
    )

    result = evidence.parse_junit(path, "class JUnit")

    assert set(result.statuses) == {
        "scripts/tests/test_release_framework_v04.py::"
        "V04ReleaseFrameworkTests::test_exact_evidence"
    }


def test_junit_and_inventory_preserve_backslashes_in_parameter_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "parameter.xml"
    name = r"test_value[Log('\\ud800')\n]"
    node = f"backend/tests/test_example.py::{name}"
    _write_junit(path, [("backend.tests.test_example", name, "passed")])

    result = evidence.parse_junit(path, "parameter JUnit")

    assert set(result.statuses) == {node}
    assert evidence.inventory_sha256([node]) != evidence.inventory_sha256(
        [node.replace("\\", "/")]
    )


def test_powershell_collector_normalizes_only_the_node_path_prefix() -> None:
    harness = (
        Path(__file__).resolve().parents[1] / "qualify_candidate_v05.ps1"
    ).read_text(encoding="utf-8")

    assert (
        "$line.Substring(0, $separator).Replace('\\', '/') + "
        "$line.Substring($separator)"
    ) in harness
    assert "([string]$_).Replace('\\', '/')" not in harness


def test_postgresql_suite_rejects_a_skip_even_when_manifest_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "postgres.xml"
    node = "backend/tests/test_example.py::test_database"
    _write_junit(path, [("backend.tests.test_example", "test_database", "skipped")])
    result = evidence.parse_junit(path, "PostgreSQL JUnit")
    monkeypatch.setitem(
        evidence.EXPECTED_INVENTORIES,
        "backend_postgresql",
        (1, evidence.inventory_sha256([node])),
    )
    suite = _suite([node], evidence.ARTIFACT_PATHS["backend_postgresql"], result)

    with pytest.raises(evidence.CandidateEvidenceError, match="contains a skip"):
        evidence.validate_suite("backend_postgresql", suite, result)


def test_suite_rejects_a_missing_collected_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "postgres.xml"
    nodes = [
        "backend/tests/test_example.py::test_first",
        "backend/tests/test_example.py::test_second",
    ]
    _write_junit(path, [("backend.tests.test_example", "test_first", "passed")])
    result = evidence.parse_junit(path, "PostgreSQL JUnit")
    monkeypatch.setitem(
        evidence.EXPECTED_INVENTORIES,
        "backend_postgresql",
        (2, evidence.inventory_sha256(nodes)),
    )
    suite = _suite(nodes, evidence.ARTIFACT_PATHS["backend_postgresql"], result)

    with pytest.raises(evidence.CandidateEvidenceError, match="bijection differs"):
        evidence.validate_suite("backend_postgresql", suite, result)


def test_database_rejects_reused_application_and_migration_name() -> None:
    database = {
        "application_name": "spell_test",
        "migration_name": "spell_test",
        "distinct_names": True,
        "both_environment_variables_bound": True,
        "postgresql_zero_skips": True,
        "network_internal": True,
        "host_port_published": False,
        "postgres_image_id": "sha256:" + "a" * 64,
    }
    postgres = evidence.JUnitResult({}, 0, 0, 0, 0)

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="migration qualification database differs|not distinct",
    ):
        evidence.validate_database(database, postgres)


def test_identity_rejects_skip_without_a_waiver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = "V05-IR-001-TEST"
    node = "backend/tests/test_ir_v03.py::test_boundary"
    monkeypatch.setattr(evidence, "IDENTITY_IDS", (identity,))
    monkeypatch.setattr(
        evidence,
        "expected_identity_map",
        lambda _nodes: {identity: [node]},
    )
    identities = {
        identity: {
            "nodes": [node],
            "environments": ["sqlite", "postgresql"],
            "passed_count": 1,
            "skipped_count": 0,
        }
    }
    sqlite = evidence.JUnitResult({node: "passed"}, 1, 0, 0, 0)
    postgres = evidence.JUnitResult({node: "skipped"}, 0, 1, 0, 0)

    with pytest.raises(evidence.CandidateEvidenceError, match="without skips"):
        evidence.validate_identities(identities, [node], sqlite, postgres)


def test_implementation_binding_rejects_wrong_commit_before_git_queries(
    tmp_path: Path,
) -> None:
    candidate = {
        "commit": "0" * 40,
        "tree": evidence.IMPLEMENTATION_TREE,
        "parent": evidence.IMPLEMENTATION_PARENT,
        "changed_paths": [
            {"path": path, "blob": blob}
            for path, blob in evidence.IMPLEMENTATION_BLOBS.items()
        ],
    }

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="implementation candidate commit differs",
    ):
        evidence.validate_implementation_candidate_git(tmp_path, candidate)


def test_qualification_source_rejects_wrong_commit_before_git_queries(
    tmp_path: Path,
) -> None:
    qualification = {
        "commit": "0" * 40,
        "tree": evidence.QUALIFICATION_TREE,
        "parent": evidence.QUALIFICATION_PARENT,
        "correction": dict(evidence.QUALIFICATION_CORRECTION),
    }

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="qualification source commit differs",
    ):
        evidence.validate_qualification_source_git(tmp_path, qualification)


def test_qualification_source_rejects_correction_hash_mutation(
    tmp_path: Path,
) -> None:
    correction = dict(evidence.QUALIFICATION_CORRECTION)
    correction["sha256"] = "0" * 64
    qualification = {
        "commit": evidence.QUALIFICATION_COMMIT,
        "tree": evidence.QUALIFICATION_TREE,
        "parent": evidence.QUALIFICATION_PARENT,
        "correction": correction,
    }

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="qualification correction binding differs",
    ):
        evidence.validate_qualification_source_git(tmp_path, qualification)


def test_toolchain_binding_rejects_python_version_drift(tmp_path: Path) -> None:
    toolchain = {
        "lock_path": evidence.TOOLCHAIN_LOCK_PATH,
        "lock_sha256": evidence.TOOLCHAIN_LOCK_SHA256,
        "python_version": "3.13.13",
        "python_sha256": evidence.PYTHON_SHA256,
        "qualification_dockerfile_path": evidence.QUALIFICATION_DOCKERFILE_PATH,
        "qualification_dockerfile_sha256": evidence.QUALIFICATION_DOCKERFILE_SHA256,
        "qualification_dockerignore_path": evidence.QUALIFICATION_DOCKERIGNORE_PATH,
        "qualification_dockerignore_sha256": evidence.QUALIFICATION_DOCKERIGNORE_SHA256,
        "qualification_image_id": "sha256:" + "a" * 64,
        "external_manuals": {
            "directory": evidence.EXTERNAL_MANUAL_DIRECTORY,
            "ledger_path": evidence.EXTERNAL_MANUAL_LEDGER_PATH,
            "ledger_sha256": evidence.EXTERNAL_MANUAL_LEDGER_SHA256,
            "files": evidence.EXTERNAL_MANUALS,
        },
    }

    with pytest.raises(evidence.CandidateEvidenceError, match="Python version differs"):
        evidence.validate_toolchain(tmp_path, toolchain)


def test_external_manual_ledger_rejects_hash_mutation() -> None:
    lines = []
    for index, (name, digest) in enumerate(evidence.EXTERNAL_MANUALS.items()):
        if index == 0:
            digest = "0" * 64
        lines.append(f"| `{name}` | 1/1 | version | `{digest}` | use | limit |")

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="ledger inventory differs",
    ):
        evidence.parse_external_manual_ledger("\n".join(lines).encode("utf-8"))


def test_external_manual_binding_rejects_manifest_map_mutation(tmp_path: Path) -> None:
    files = dict(evidence.EXTERNAL_MANUALS)
    files[next(iter(files))] = "0" * 64
    external = {
        "directory": evidence.EXTERNAL_MANUAL_DIRECTORY,
        "ledger_path": evidence.EXTERNAL_MANUAL_LEDGER_PATH,
        "ledger_sha256": evidence.EXTERNAL_MANUAL_LEDGER_SHA256,
        "files": files,
    }

    with pytest.raises(
        evidence.CandidateEvidenceError,
        match="manifest map differs",
    ):
        evidence.validate_external_manuals(tmp_path, external)


def test_inherited_v04_cannot_be_claimed_as_direct_v05_proof(tmp_path: Path) -> None:
    inherited = {
        "classification": evidence.INHERITED_CLASSIFICATION,
        "supports": evidence.INHERITED_SUPPORTS,
        "result_path": evidence.INHERITED_RUN_PATH,
        "result_sha256": "a" * 64,
        "source_fingerprint_sha256": evidence.INHERITED_SOURCE_FINGERPRINT,
        "direct_v05_proof": True,
    }

    with pytest.raises(evidence.CandidateEvidenceError, match="misclassified"):
        evidence.validate_inherited_v04(tmp_path, inherited)


def _secret_manifest(nodes: list[str] | None = None, **extra: object) -> bytes:
    manifest = {
        "suites": {
            "tooling": {
                "collected_nodes": list(evidence.TOOLING_SYNTHETIC_NODES)
                if nodes is None
                else nodes
            }
        },
        **extra,
    }
    return json.dumps(manifest, separators=(",", ":")).encode("utf-8")


def _write_synthetic_tooling_xml(
    path: Path,
    nodes: list[str] | None = None,
    *,
    prefix: str = "",
    suffix: str = "",
    comment: str = "",
) -> None:
    cases = []
    for node in list(evidence.TOOLING_SYNTHETIC_NODES) if nodes is None else nodes:
        classname, name = evidence._node_to_case_key(node)
        encoded_name = evidence._xml_attribute_value(name).decode("utf-8")
        cases.append(
            f'<testcase classname="{classname}" name="{prefix}{encoded_name}{suffix}" />'
        )
    path.write_text(
        "<testsuite>" + "".join(cases) + comment + "</testsuite>",
        encoding="utf-8",
    )


def test_secret_material_scan_accepts_only_exact_structured_canaries(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "tooling.xml"
    _write_synthetic_tooling_xml(artifact)

    evidence._validate_no_secret_material(_secret_manifest(), [artifact])


@pytest.mark.parametrize(
    "manifest",
    [
        b"{}",
        _secret_manifest(list(evidence.TOOLING_SYNTHETIC_NODES[:-1])),
        _secret_manifest(
            [*evidence.TOOLING_SYNTHETIC_NODES, evidence.TOOLING_SYNTHETIC_NODES[0]]
        ),
        json.dumps(
            {
                "suites": {"tooling": {"collected_nodes": []}},
                "wrong_path": list(evidence.TOOLING_SYNTHETIC_NODES),
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        _secret_manifest(extra_node=evidence.TOOLING_SYNTHETIC_NODES[0]),
        _secret_manifest(
            [
                evidence.TOOLING_SYNTHETIC_NODES[0] + "-tampered",
                *evidence.TOOLING_SYNTHETIC_NODES[1:],
            ]
        ),
    ],
)
def test_secret_material_scan_rejects_manifest_location_count_and_nearby_mutations(
    tmp_path: Path, manifest: bytes
) -> None:
    artifact = tmp_path / "tooling.xml"
    _write_synthetic_tooling_xml(artifact)

    with pytest.raises(evidence.CandidateEvidenceError):
        evidence._validate_no_secret_material(manifest, [artifact])


def test_secret_material_scan_rejects_tooling_identity_and_nearby_mutations(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "tooling.xml"
    wrong_class_node = evidence.TOOLING_SYNTHETIC_NODES[0].replace(
        "scripts/tests/test_seed_driver_projection_v04.py::",
        "scripts/tests/test_wrong.py::",
        1,
    )
    _write_synthetic_tooling_xml(
        artifact,
        [wrong_class_node, *evidence.TOOLING_SYNTHETIC_NODES[1:]],
    )
    with pytest.raises(evidence.CandidateEvidenceError):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])

    for position in ("prefix", "suffix"):
        _write_synthetic_tooling_xml(
            artifact,
            prefix="tampered-" if position == "prefix" else "",
            suffix="-tampered" if position == "suffix" else "",
        )
        with pytest.raises(evidence.CandidateEvidenceError):
            evidence._validate_no_secret_material(_secret_manifest(), [artifact])

    _write_synthetic_tooling_xml(
        artifact,
        comment="<!-- postgresql+psycopg://spell:secret@comment/spell -->",
    )
    with pytest.raises(evidence.CandidateEvidenceError, match="secret material"):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])


@pytest.mark.parametrize(
    "nodes",
    [
        list(evidence.TOOLING_SYNTHETIC_NODES[:-1]),
        [*evidence.TOOLING_SYNTHETIC_NODES, evidence.TOOLING_SYNTHETIC_NODES[0]],
    ],
)
def test_secret_material_scan_rejects_tooling_missing_or_duplicate_canary(
    tmp_path: Path, nodes: list[str]
) -> None:
    artifact = tmp_path / "tooling.xml"
    _write_synthetic_tooling_xml(artifact, nodes)

    with pytest.raises(evidence.CandidateEvidenceError):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])


def test_secret_material_scan_rejects_database_url_in_other_artifact(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "backend.xml"
    artifact.write_bytes(b"postgresql+psycopg://spell:secret@postgres/spell_test")

    with pytest.raises(evidence.CandidateEvidenceError, match="secret material"):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])


def test_secret_material_scan_rejects_non_key_pem_marker_outside_exact_node(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "test.xml"
    artifact.write_bytes(
        b"-----BEGIN PRIVATE KEY-----\\n"
        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\n"
        b"-----END PRIVATE KEY-----"
    )

    with pytest.raises(evidence.CandidateEvidenceError, match="private-key material"):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])


def test_secret_material_scan_rejects_a_der_private_key_payload(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "test.xml"
    artifact.write_bytes(
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MAMCAQA=\n"
        b"-----END PRIVATE KEY-----"
    )

    with pytest.raises(evidence.CandidateEvidenceError, match="private-key material"):
        evidence._validate_no_secret_material(_secret_manifest(), [artifact])


def test_inventory_digest_is_order_independent_and_duplicate_sensitive() -> None:
    nodes = ["backend/tests/test_b.py::test_b", "backend/tests/test_a.py::test_a"]

    assert evidence.inventory_sha256(nodes) == evidence.inventory_sha256(list(reversed(nodes)))
    assert evidence.inventory_sha256(nodes) != evidence.inventory_sha256([*nodes, nodes[0]])
