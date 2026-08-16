from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import validate_release_evidence_v06 as release


def _write_junit(
    path: Path,
    cases: list[tuple[str, str, str]],
    *,
    reported_tests: int | None = None,
    time: str = "0.01",
) -> None:
    children: list[str] = []
    skipped = failures = errors = 0
    for classname, name, status in cases:
        result = ""
        if status == "skipped":
            result = '<skipped message="controlled skip" />'
            skipped += 1
        elif status == "failure":
            result = '<failure message="controlled failure" />'
            failures += 1
        elif status == "error":
            result = '<error message="controlled error" />'
            errors += 1
        children.append(
            f'<testcase classname="{classname}" name="{name}" time="{time}">'
            f"{result}</testcase>"
        )
    count = len(cases) if reported_tests is None else reported_tests
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites name="qualification">'
        f'<testsuite name="tests" tests="{count}" skipped="{skipped}" '
        f'failures="{failures}" errors="{errors}">'
        + "".join(children)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )


def _vitest_capture() -> dict:
    assertion = {
        "ancestorTitles": ["release"],
        "fullName": "release passes",
        "status": "passed",
        "title": "passes",
        "duration": 1,
        "failureMessages": [],
        "meta": {},
    }
    return {
        "numTotalTestSuites": 1,
        "numPassedTestSuites": 1,
        "numFailedTestSuites": 0,
        "numPendingTestSuites": 0,
        "numTotalTests": 1,
        "numPassedTests": 1,
        "numFailedTests": 0,
        "numPendingTests": 0,
        "numTodoTests": 0,
        "snapshot": {},
        "startTime": 1,
        "success": True,
        "testResults": [
            {
                "assertionResults": [assertion],
                "startTime": 1,
                "endTime": 2,
                "status": "passed",
                "message": "",
                "name": "frontend/src/release.test.ts",
            }
        ],
    }


def _manifest_shape() -> dict:
    return {
        "schema_version": release.SCHEMA_VERSION,
        "product_version": release.PRODUCT_VERSION,
        "scope_profile": release.SCOPE_PROFILE,
        "decision": {
            "owner": "JC Arcaz",
            "release_status": "READY_FOR_ANNOTATED_TAG",
            "accepted_exceptions": [],
            "operational_authorization": False,
            "compliance_determination": False,
            "cryptographic_signature_claimed": False,
        },
        "qualified_source": {},
        "work_package": {},
        "gate_0b": {},
        "toolchain": {},
        "final_qualification": {},
        "final_suites": {},
        "inherited_v05": {},
        "sbom": {},
        "supply_chain": {},
        "evidence": {},
        "teardown": {},
        "tag_policy": {},
        "overall_pass": True,
    }


def _inherited_v05() -> dict:
    return {
        "classification": "ACCEPTED_RELEASE_BASELINE_NOT_DIRECT_V06_PROOF",
        "supports": ["release-lineage", "compatibility", "toolchain"],
        "direct_v06_proof": False,
        "accepted_tag_ref": release.V05_TAG_REF,
        "accepted_tag_object": release.V05_TAG_OBJECT,
        "accepted_commit": release.V05_COMMIT,
        "accepted_artifact_tree": release.V05_ARTIFACT_TREE,
        "accepted_archive_path": release.V05_ARCHIVE_RELATIVE,
        "accepted_archive_sha256": release.V05_ARCHIVE_SHA256,
        "accepted_sidecar_path": release.V05_SIDECAR_RELATIVE,
        "accepted_sidecar_sha256": release.V05_SIDECAR_SHA256,
        "accepted_tag_archive_claim": release.V05_TAG_ARCHIVE_CLAIM,
    }


def test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag() -> None:
    inherited = _inherited_v05()
    release.validate_v05_unchanged(release.ROOT, inherited)

    for key in (
        "accepted_archive_sha256",
        "accepted_sidecar_sha256",
        "accepted_tag_archive_claim",
    ):
        mutation = copy.deepcopy(inherited)
        mutation[key] = "0" * 64
        with pytest.raises(release.ReleaseEvidenceError, match=f"inherited_v05.{key}"):
            release.validate_v05_unchanged(release.ROOT, mutation)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"one","schema_version":"two"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b"\xff",
    ],
)
def test_strict_json_rejects_duplicate_nonfinite_and_non_utf8(raw: bytes) -> None:
    with pytest.raises(release.ReleaseEvidenceError):
        release.parse_strict_json(raw, "release fixture")


def test_validator_direct_path_bootstraps_repo_imports_under_isolated_python(
    tmp_path: Path,
) -> None:
    validator = Path(release.__file__).resolve()
    code = (
        "import runpy;"
        f"module=runpy.run_path({str(validator)!r},run_name='isolated_validator');"
        "import scripts.validate_candidate_evidence_v06 as candidate;"
        "print(module['SCHEMA_VERSION']+' '+candidate.__name__)"
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    direct = subprocess.run(
        [sys.executable, "-I", "-B", str(validator), "--help"],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )
    assert direct.returncode == 0, direct.stderr
    assert direct.stderr == ""
    assert direct.stdout.startswith("usage: validate_release_evidence_v06.py ")
    assert "--require-tag" in direct.stdout

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == (
        "spell.v06.release-qualification/1 "
        "scripts.validate_candidate_evidence_v06"
    )


def test_junit_accepts_and_counts_a_strict_capture(tmp_path: Path) -> None:
    path = tmp_path / "capture.xml"
    _write_junit(
        path,
        [
            ("backend.tests.test_release", "test_pass", "passed"),
            ("backend.tests.test_release", "test_skip", "skipped"),
        ],
    )

    result = release.parse_junit(path, "capture")

    assert result.passed == 1
    assert result.skipped == 1
    assert result.failures == 0
    assert result.subtests == 0
    assert set(result.nodes) == {
        "backend/tests/test_release.py::test_pass",
        "backend/tests/test_release.py::test_skip",
    }


def test_junit_preserves_python_classes_browser_projects_and_subtests(
    tmp_path: Path,
) -> None:
    path = tmp_path / "subtests.xml"
    _write_junit(
        path,
        [
            (
                "scripts.tests.test_release.ReleaseTests",
                "test_python_class",
                "passed",
            ),
            ("browser_desktop.e2e.auth.spec", "opens the console", "passed"),
        ],
        reported_tests=38,
    )

    result = release.parse_junit(path, "subtests", expected_subtests=36)

    assert result.subtests == 36
    assert set(result.nodes) == {
        "scripts/tests/test_release.py::ReleaseTests::test_python_class",
        "browser_desktop.e2e.auth.spec::opens the console",
    }
    with pytest.raises(release.ReleaseEvidenceError, match="subtest aggregate differs"):
        release.parse_junit(path, "subtests")


def test_tooling_suite_requires_the_exact_secret_canary_nodes(tmp_path: Path) -> None:
    path = tmp_path / "artifacts/v0.6/final/tests/tooling.xml"
    cases: list[tuple[str, str, str]] = []
    for node in release.TOOLING_SECRET_CANARY_NODES:
        module, name = node.split("::", 1)
        cases.append((module[:-3].replace("/", "."), name, "passed"))
    _write_junit(path, cases, reported_tests=len(cases) + 36)
    suite = {
        "kind": "junit",
        "capture": "artifacts/v0.6/final/tests/tooling.xml",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "test_count": len(cases),
        "subtest_count": 36,
        "passed_count": len(cases),
        "skipped_count": 0,
        "failure_count": 0,
        "error_count": 0,
        "allowed_skipped_nodes": [],
    }

    result, count = release._validate_suite_manifest(
        "tooling", suite, tmp_path, "a" * 64
    )
    assert result is not None and result.subtests == 36 and count == len(cases)

    _write_junit(path, cases[:-1], reported_tests=len(cases) - 1 + 36)
    suite["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    suite["test_count"] = len(cases) - 1
    suite["passed_count"] = len(cases) - 1
    with pytest.raises(release.ReleaseEvidenceError, match="canary node inventory"):
        release._validate_suite_manifest("tooling", suite, tmp_path, "a" * 64)


def test_junit_rejects_dtd_entity_duplicate_and_false_aggregate(
    tmp_path: Path,
) -> None:
    dtd = tmp_path / "dtd.xml"
    dtd.write_text(
        '<!DOCTYPE testsuite [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase classname="backend.tests.test_release" name="test_value">'
        "&leak;</testcase></testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(release.ReleaseEvidenceError, match="DTD"):
        release.parse_junit(dtd, "unsafe")

    duplicate = tmp_path / "duplicate.xml"
    case = ("backend.tests.test_release", "test_value", "passed")
    _write_junit(duplicate, [case, case])
    with pytest.raises(release.ReleaseEvidenceError, match="duplicate testcase"):
        release.parse_junit(duplicate, "duplicate")

    aggregate = tmp_path / "aggregate.xml"
    _write_junit(aggregate, [case], reported_tests=2)
    with pytest.raises(release.ReleaseEvidenceError, match="aggregate differs"):
        release.parse_junit(aggregate, "aggregate")


@pytest.mark.parametrize("time", ["NaN", "Infinity", "-1", "not-a-number"])
def test_junit_rejects_invalid_testcase_time(tmp_path: Path, time: str) -> None:
    path = tmp_path / "time.xml"
    _write_junit(
        path,
        [("backend.tests.test_release", "test_value", "passed")],
        time=time,
    )

    with pytest.raises(release.ReleaseEvidenceError, match="testcase time"):
        release.parse_junit(path, "time")


def test_vitest_requires_every_suite_and_assertion_to_pass(tmp_path: Path) -> None:
    path = tmp_path / "vitest.json"
    path.write_text(json.dumps(_vitest_capture()), encoding="utf-8")
    result = release.parse_vitest(path, "vitest")
    assert result.passed == 1

    failed = _vitest_capture()
    failed["testResults"][0]["assertionResults"][0]["status"] = "failed"
    path.write_text(json.dumps(failed), encoding="utf-8")
    with pytest.raises(release.ReleaseEvidenceError, match="assertion did not pass"):
        release.parse_vitest(path, "vitest")


def test_frontend_build_capture_is_source_and_dist_bound(tmp_path: Path) -> None:
    source = "a" * 64
    capture_path = tmp_path / "artifacts/v0.6/final/tests/frontend-build.json"
    capture_path.parent.mkdir(parents=True)
    capture = {
        "schema_version": "spell.v06.frontend-build/1",
        "product_version": "0.6.0",
        "source_fingerprint_sha256": source,
        "command": ["npm", "run", "build"],
        "return_code": 0,
        "passed": True,
        "dist_file_count": 12,
        "dist_sha256": "b" * 64,
    }
    capture_path.write_text(json.dumps(capture), encoding="utf-8")
    suite = {
        "kind": "frontend-build",
        "capture": "artifacts/v0.6/final/tests/frontend-build.json",
        "sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
        "passed": True,
        "dist_file_count": 12,
        "dist_sha256": "b" * 64,
    }

    assert release.validate_frontend_build(tmp_path, suite, source) == 0

    suite["dist_sha256"] = "c" * 64
    with pytest.raises(release.ReleaseEvidenceError, match="dist hash differs"):
        release.validate_frontend_build(tmp_path, suite, source)


def test_final_qualification_summary_is_hash_source_suite_and_teardown_bound(
    tmp_path: Path,
) -> None:
    source = "a" * 64
    product = "f" * 64
    commit = "b" * 40
    tree = "c" * 40
    work_package = {"evidence_sha256": "d" * 64}
    gate_0b = {"scope_sha256": "e" * 64}
    toolchain = {"qualification_image_id": "sha256:" + "1" * 64}
    suites = {suite_id: {"capture": suite_id} for suite_id in release.FINAL_SUITE_IDS}
    path = tmp_path / release.FINAL_QUALIFICATION_PATH
    path.parent.mkdir(parents=True)
    summary = {
        "schema_version": "spell.v06.final-qualification/1",
        "product_version": "0.6.0",
        "scope_profile": release.SCOPE_PROFILE,
        "qualified_source": {"commit": commit, "tree": tree},
        "source_fingerprint_sha256": source,
        "product_package_sha256": product,
        "work_package": work_package,
        "gate_0b": gate_0b,
        "toolchain": copy.deepcopy(toolchain),
        "suites": suites,
        "accepted_v05_release": copy.deepcopy(release.V05_EXTERNAL_RELEASE_BINDING),
        "teardown": {
            "qualification_resources_torn_down": True,
            "runtime_test_resources_torn_down": True,
            "temporary_evidence_removed": True,
            "secrets_retained": False,
        },
        "accepted_exceptions": [],
        "overall_pass": True,
    }
    path.write_text(json.dumps(summary), encoding="utf-8")
    binding = {
        "path": release.FINAL_QUALIFICATION_PATH,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }

    release.validate_final_qualification(
        tmp_path,
        binding,
        qualified_source_commit=commit,
        qualified_source_tree=tree,
        source_fingerprint=source,
        product_package_sha256=product,
        work_package=work_package,
        gate_0b=gate_0b,
        toolchain=toolchain,
        final_suites=suites,
    )

    summary["accepted_exceptions"] = ["browser skipped"]
    path.write_text(json.dumps(summary), encoding="utf-8")
    binding["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(release.ReleaseEvidenceError, match="contains an exception"):
        release.validate_final_qualification(
            tmp_path,
            binding,
            qualified_source_commit=commit,
            qualified_source_tree=tree,
            source_fingerprint=source,
            product_package_sha256=product,
            work_package=work_package,
            gate_0b=gate_0b,
            toolchain=toolchain,
            final_suites=suites,
        )

    summary["accepted_exceptions"] = []
    summary["toolchain"]["qualification_image_id"] = "sha256:" + "2" * 64
    path.write_text(json.dumps(summary), encoding="utf-8")
    binding["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(release.ReleaseEvidenceError, match="toolchain binding differs"):
        release.validate_final_qualification(
            tmp_path,
            binding,
            qualified_source_commit=commit,
            qualified_source_tree=tree,
            source_fingerprint=source,
            product_package_sha256=product,
            work_package=work_package,
            gate_0b=gate_0b,
            toolchain=toolchain,
            final_suites=suites,
        )


def _write_version_fixture(root: Path) -> None:
    (root / "backend").mkdir(parents=True)
    (root / "driver_host").mkdir()
    (root / "frontend").mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nversion = "0.6.0"\n'
        '[tool.spell.supply-chain]\nrelease_artifact_root = "artifacts/v0.6"\n'
        'release_toolchain_lock = "scripts/release-toolchain-v04.json"\n',
        encoding="utf-8",
    )
    (root / "frontend/package.json").write_text(
        '{"version":"0.6.0"}', encoding="utf-8"
    )
    (root / "frontend/package-lock.json").write_text(
        '{"version":"0.6.0","packages":{"":{"version":"0.6.0"}}}',
        encoding="utf-8",
    )
    (root / "backend/version.py").write_text(
        'PRODUCT_VERSION = "0.6.0"\n', encoding="utf-8"
    )
    (root / "backend/__init__.py").write_text(
        '__version__ = "0.6.0"\n', encoding="utf-8"
    )
    (root / "driver_host/config.py").write_text(
        'class Config:\n    implementation_version: str = "0.4.0"\n',
        encoding="utf-8",
    )
    (root / "backend/driver_gateway.py").write_text(
        'EXPECTED_IMPLEMENTATION_VERSION = "0.4.0"\n', encoding="utf-8"
    )
    for name in ("Dockerfile", "pki.Dockerfile"):
        (root / "driver_host" / name).write_text(
            "FROM scratch\nARG SPELL_PACKAGE_VERSION=0.4.0\n",
            encoding="utf-8",
        )


def test_version_metadata_advances_product_but_retains_driver_identity(
    tmp_path: Path,
) -> None:
    _write_version_fixture(tmp_path)
    release.validate_version_metadata(tmp_path)

    (tmp_path / "driver_host/config.py").write_text(
        'class Config:\n    implementation_version: str = "0.6.0"\n',
        encoding="utf-8",
    )
    with pytest.raises(release.ReleaseEvidenceError, match="driver host config"):
        release.validate_version_metadata(tmp_path)


def test_candidate_delta_allowlist_excludes_product_and_dependency_changes() -> None:
    assert release._allowed_candidate_path("backend/version.py")
    assert not release._allowed_candidate_path("backend/tests/test_driver_isolation.py")
    assert release._allowed_candidate_path("frontend/README.md")
    assert release._allowed_candidate_path("scripts/package-v04.Dockerfile.dockerignore")
    assert release._allowed_candidate_path("scripts/create_release_qualification_v06.py")
    assert release._allowed_candidate_path("scripts/qualification-v06.Dockerfile.dockerignore")
    assert release._allowed_candidate_path("scripts/tests/test_qualify_release_v06.py")
    assert release._allowed_candidate_path("artifacts/v0.6/work-package/qualification.json")
    assert not release._allowed_candidate_path("backend/supervisor.py")
    assert not release._allowed_candidate_path("backend/requirements.hashes.lock")
    assert not release._allowed_candidate_path("driver_host/config.py")


def test_release_closeout_allows_only_the_complete_canonical_package_pair() -> None:
    evidence = ["artifacts/v0.6/release-qualification.json"]
    release.validate_release_closeout_paths(evidence)
    with pytest.raises(release.ReleaseEvidenceError, match="package and sidecar together"):
        release.validate_release_closeout_paths(evidence, require_package=True)
    release.validate_release_closeout_paths(
        [*evidence, release.RELEASE_PACKAGE_PATH, release.RELEASE_PACKAGE_SIDECAR_PATH],
        require_package=True,
    )

    with pytest.raises(release.ReleaseEvidenceError, match="package and sidecar together"):
        release.validate_release_closeout_paths(
            [*evidence, release.RELEASE_PACKAGE_PATH]
        )
    with pytest.raises(release.ReleaseEvidenceError, match="noncanonical package"):
        release.validate_release_closeout_paths(
            [*evidence, "artifacts/v0.6/unapproved.tar.gz"]
        )
    with pytest.raises(release.ReleaseEvidenceError, match="outside canonical"):
        release.validate_release_closeout_paths([*evidence, "README.md"])
    with pytest.raises(release.ReleaseEvidenceError, match="scratch evidence"):
        release.validate_release_closeout_paths(
            [*evidence, "artifacts/v0.6/.qualification/run.json"]
        )


def test_evidence_inventory_is_exact_hash_bound_and_secret_scanned(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "artifacts/v0.6"
    files: dict[str, Path] = {}
    for index, relative in enumerate(sorted(release.CANONICAL_EVIDENCE_PATHS)):
        artifact = tmp_path / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(f"bounded evidence {index}\n".encode("ascii"))
        files[relative] = artifact
    for relative, nodes in (
        (
            "artifacts/v0.6/work-package/tests/tooling.xml",
            release.FINAL_TOOLING_SECRET_TESTCASE_NODES,
        ),
        (
            "artifacts/v0.6/final/tests/tooling.xml",
            release.FINAL_TOOLING_SECRET_TESTCASE_NODES,
        ),
    ):
        files[relative].write_bytes(_tooling_secret_xml(nodes))
    release_manifest = evidence_root / release.MANIFEST_NAME
    release_manifest.write_text("{}", encoding="utf-8")
    declared = {
        "files": {
            relative: hashlib.sha256(artifact.read_bytes()).hexdigest()
            for relative, artifact in files.items()
        },
        "evidence_fingerprint_sha256": release.evidence_fingerprint_v06(files),
    }

    fingerprint, observed = release.validate_evidence_inventory(
        tmp_path, evidence_root, declared
    )
    assert fingerprint == declared["evidence_fingerprint_sha256"]
    assert observed == files

    extra = evidence_root / "unexpected.txt"
    extra.write_text("extra", encoding="utf-8")
    with pytest.raises(release.ReleaseEvidenceError, match="inventory differs"):
        release.validate_evidence_inventory(tmp_path, evidence_root, declared)
    extra.unlink()
    artifact = files[release.FINAL_QUALIFICATION_PATH]
    artifact.write_bytes(b"postgresql+psycopg://user:secret@postgres/test")
    declared["files"][release.FINAL_QUALIFICATION_PATH] = hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()
    declared["evidence_fingerprint_sha256"] = release.evidence_fingerprint_v06(files)
    with pytest.raises(release.ReleaseEvidenceError, match="secret material"):
        release.validate_evidence_inventory(tmp_path, evidence_root, declared)


def _tooling_secret_xml(
    nodes: tuple[str, ...] | list[str],
    *,
    comment: str | None = None,
    nested_first: bool = False,
    extra_value: str | None = None,
) -> bytes:
    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        tests=str(len(nodes)),
        skipped="0",
        failures="0",
        errors="0",
    )
    wrapper = ET.SubElement(suite, "wrapper") if nested_first else None
    for index, node in enumerate(nodes):
        module, name = node.split(".py::", 1)
        parent = wrapper if index == 0 and wrapper is not None else suite
        ET.SubElement(
            parent,
            "testcase",
            classname=module.replace("/", "."),
            name=name,
        )
    if comment is not None:
        suite.append(ET.Comment(comment))
    if extra_value is not None:
        ET.SubElement(suite, "property", name="probe", value=extra_value)
    return release.CANONICAL_XML_DECLARATION + ET.tostring(
        root, encoding="utf-8"
    )


def test_tooling_secret_testcases_are_exact_structured_exemptions() -> None:
    from scripts.validate_candidate_evidence_v06 import TOOLING_SYNTHETIC_NODES

    assert tuple(TOOLING_SYNTHETIC_NODES) == release.TOOLING_SECRET_CANARY_NODES
    assert len(release.FINAL_TOOLING_SECRET_TESTCASE_NODES) == 8
    for relative, nodes in (
        (
            "artifacts/v0.6/work-package/tests/tooling.xml",
            release.FINAL_TOOLING_SECRET_TESTCASE_NODES,
        ),
        (
            "artifacts/v0.6/final/tests/tooling.xml",
            release.FINAL_TOOLING_SECRET_TESTCASE_NODES,
        ),
    ):
        scanner_input = release._secret_scannable_evidence(
            relative, _tooling_secret_xml(nodes)
        )
        assert scanner_input.startswith(release.CANONICAL_XML_DECLARATION)
        assert scanner_input != b""


def test_tooling_secret_testcases_reject_duplicates_mutations_and_mislocation() -> None:
    relative = "artifacts/v0.6/final/tests/tooling.xml"
    nodes = list(release.FINAL_TOOLING_SECRET_TESTCASE_NODES)
    with pytest.raises(release.ReleaseEvidenceError, match="inventory differs"):
        release._secret_scannable_evidence(
            relative, _tooling_secret_xml([*nodes, nodes[0]])
        )
    with pytest.raises(release.ReleaseEvidenceError, match="inventory differs"):
        release._secret_scannable_evidence(relative, _tooling_secret_xml(nodes[:-1]))

    module, name = nodes[0].split(".py::", 1)
    for mutated_name in ("prefix-" + name, name + "-suffix"):
        mutated = [f"{module}.py::{mutated_name}", *nodes[1:]]
        with pytest.raises(release.ReleaseEvidenceError, match="secret material"):
            release._secret_scannable_evidence(
                relative, _tooling_secret_xml(mutated)
            )

    canary = "postgresql+psycopg://spell:real@postgres/spell"
    for raw, error in (
        (_tooling_secret_xml(nodes, nested_first=True), "secret material"),
        (_tooling_secret_xml(nodes, comment=canary), "comment"),
        (_tooling_secret_xml(nodes, extra_value=canary), "secret material"),
        (
            _tooling_secret_xml(
                nodes,
                extra_value="-----BEGIN " + "PRIVATE KEY-----\nreal payload",
            ),
            "secret material",
        ),
    ):
        with pytest.raises(release.ReleaseEvidenceError, match=error):
            release._secret_scannable_evidence(relative, raw)


def test_tooling_xml_enforces_builder_token_patterns_outside_exempt_names() -> None:
    from scripts import build_reproducible_v06 as builder

    relative = "artifacts/v0.6/final/tests/tooling.xml"
    nodes = release.FINAL_TOOLING_SECRET_TESTCASE_NODES
    tokens = (
        b"AKIA" + b"0123456789ABCDEF",
        b"ghp_" + b"0123456789abcdefghijklmnopqrstuvwxyz",
        b"xoxb-" + b"0123456789abcdefghij",
    )
    assert all(any(pattern.search(token) for pattern in builder.SECRET_PATTERNS) for token in tokens)
    for token in tokens:
        raw = _tooling_secret_xml(nodes, extra_value=token.decode("ascii"))
        with pytest.raises(release.ReleaseEvidenceError, match="secret material"):
            release._secret_scannable_evidence(relative, raw)
        with pytest.raises(release.ReleaseEvidenceError, match="secret material"):
            builder._validate_bytes(Path(relative), raw)

    body = _tooling_secret_xml(nodes).removeprefix(
        release.CANONICAL_XML_DECLARATION
    )
    top_level_comment = (
        release.CANONICAL_XML_DECLARATION
        + b"<!--"
        + tokens[0]
        + b"-->"
        + body
    )
    with pytest.raises(release.ReleaseEvidenceError, match="comment"):
        release._secret_scannable_evidence(relative, top_level_comment)


def test_tooling_xml_rejects_alternate_encoding_before_structured_parse() -> None:
    from scripts import build_reproducible_v06 as builder

    relative = "artifacts/v0.6/final/tests/tooling.xml"
    canonical = _tooling_secret_xml(
        release.FINAL_TOOLING_SECRET_TESTCASE_NODES,
        extra_value=(b"AKIA" + b"0123456789ABCDEF").decode("ascii"),
    )
    text = canonical.decode("utf-8").replace(
        'encoding="utf-8"', 'encoding="utf-16"', 1
    )
    alternate = text.encode("utf-16")
    body = canonical.decode("utf-8").removeprefix(
        release.CANONICAL_XML_DECLARATION.decode("ascii")
    )
    alternate_dtd = (
        '<?xml version="1.0" encoding="utf-16"?>'
        '<!DOCTYPE testsuites [<!ENTITY injected "'
        'postgresql+psycopg://spell:secret@postgres/spell">]>'
        + body
    ).encode("utf-16")
    for validate in (
        lambda: release._secret_scannable_evidence(relative, alternate),
        lambda: builder._validate_bytes(Path(relative), alternate),
        lambda: release._secret_scannable_evidence(relative, alternate_dtd),
        lambda: builder._validate_bytes(Path(relative), alternate_dtd),
    ):
        with pytest.raises(
            release.ReleaseEvidenceError, match="exact UTF-8 XML declaration"
        ):
            validate()

    for mutated in (
        canonical.removeprefix(release.CANONICAL_XML_DECLARATION),
        canonical.replace(b'encoding="utf-8"', b'encoding="UTF-8"', 1),
        canonical.replace(b'"utf-8"', b"'utf-8'", 1),
    ):
        with pytest.raises(
            release.ReleaseEvidenceError, match="exact UTF-8 XML declaration"
        ):
            release._secret_scannable_evidence(relative, mutated)


def test_evidence_fingerprint_is_path_and_byte_sensitive(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    a = release.evidence_fingerprint_v06({"a.txt": first})
    b = release.evidence_fingerprint_v06({"b.txt": second})
    assert a != b
    first.write_bytes(b"changed")
    assert release.evidence_fingerprint_v06({"a.txt": first}) != a


def test_sha256sums_requires_exact_unique_ascii_inventory(tmp_path: Path) -> None:
    manifest = tmp_path / "SHA256SUMS"
    names = set(release.SBOM_FILES)
    manifest.write_text(
        "".join(f"{'a' * 64}  {name}\n" for name in release.SBOM_FILES),
        encoding="ascii",
    )
    assert set(release._parse_sha256sums(manifest, names)) == names

    manifest.write_text(
        f"{'a' * 64}  backend.cdx.json\n{'b' * 64}  backend.cdx.json\n",
        encoding="ascii",
    )
    with pytest.raises(release.ReleaseEvidenceError):
        release._parse_sha256sums(manifest, names)


def _component(name: str) -> dict:
    return {"name": name, "licenses": [{"license": {"id": "MIT"}}]}


def _write_sboms(root: Path, source: str) -> dict:
    directory = root / "artifacts/v0.6/sbom"
    directory.mkdir(parents=True)
    declarations: dict[str, dict] = {}
    lines: list[str] = []
    for index, name in enumerate(release.SBOM_FILES):
        image = "sha256:" + f"{index + 1:x}" * 64
        subject = release.SBOM_SUBJECTS[name]
        inventory = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "component": {"type": "container", "name": subject, "version": image},
                "properties": [
                    {"name": release.SBOM_SOURCE_PROPERTY, "value": source},
                    {"name": release.SBOM_IMAGE_PROPERTY, "value": image},
                ],
            },
            "components": [
                _component(component)
                for component in sorted(release.SBOM_REQUIRED_COMPONENTS[name])
            ],
        }
        path = directory / name
        path.write_text(json.dumps(inventory), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
        declarations[name] = {"sha256": digest, "subject": subject, "image_id": image}
    sums = directory / "SHA256SUMS"
    sums.write_text("".join(lines), encoding="ascii")
    return {
        "directory": "artifacts/v0.6/sbom",
        "checksum_manifest": "artifacts/v0.6/sbom/SHA256SUMS",
        "checksum_manifest_sha256": hashlib.sha256(sums.read_bytes()).hexdigest(),
        "inventories": declarations,
        "source_fingerprint_sha256": source,
    }


def test_sbom_set_is_exact_distinct_checksum_and_source_bound(tmp_path: Path) -> None:
    source = "a" * 64
    declaration = _write_sboms(tmp_path, source)
    image_ids = release.validate_sbom(tmp_path, declaration, source)
    assert len(set(image_ids)) == 4

    backend = tmp_path / "artifacts/v0.6/sbom/backend.cdx.json"
    value = json.loads(backend.read_text(encoding="utf-8"))
    value["metadata"]["properties"][0]["value"] = "b" * 64
    backend.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(release.ReleaseEvidenceError):
        release.validate_sbom(tmp_path, declaration, source)


def _write_supply_capture(root: Path, source: str) -> dict:
    path = root / "artifacts/v0.6/supply-chain.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    capture = {
        "schema_version": "spell.v06.supply-chain/1",
        "product_version": "0.6.0",
        "scope_profile": release.SCOPE_PROFILE,
        "test_id": "V06-SC-001",
        "passed": True,
        "source_fingerprint_sha256": source,
        "inherited_audit_engine": {},
        "assertions": [{"id": "audit", "passed": True}],
        "metrics": {
            "critical_finding_count": 0,
            "high_finding_count": 0,
            "unlocked_input_count": 0,
            "audited_image_count": 4,
            "compose_dependency_audited_image_count": 2,
        },
        "accepted_v05_artifacts_unchanged": True,
        "accepted_v05_release": copy.deepcopy(release.V05_EXTERNAL_RELEASE_BINDING),
    }
    path.write_text(json.dumps(capture), encoding="utf-8")
    return {
        "capture": "artifacts/v0.6/supply-chain.json",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "test_id": "V06-SC-001",
        "passed": True,
        "source_fingerprint_sha256": source,
        "critical_finding_count": 0,
        "high_finding_count": 0,
        "unlocked_input_count": 0,
        "accepted_v05_artifacts_unchanged": True,
        "accepted_v05_release": copy.deepcopy(release.V05_EXTERNAL_RELEASE_BINDING),
    }


def test_supply_chain_requires_zero_high_critical_and_unlocked_inputs(
    tmp_path: Path,
) -> None:
    source = "a" * 64
    declaration = _write_supply_capture(tmp_path, source)
    release.validate_supply_chain(tmp_path, declaration, source)

    declaration["high_finding_count"] = 1
    with pytest.raises(release.ReleaseEvidenceError, match="must be zero"):
        release.validate_supply_chain(tmp_path, declaration, source)

    declaration = _write_supply_capture(tmp_path, source)
    declaration["accepted_v05_release"]["archive_sha256"] = "0" * 64
    with pytest.raises(
        release.ReleaseEvidenceError,
        match="accepted v0.5 release binding differs",
    ):
        release.validate_supply_chain(tmp_path, declaration, source)


def test_teardown_requires_every_cleanup_and_no_retained_secret() -> None:
    teardown = {
        "qualification_resources_torn_down": True,
        "runtime_test_resources_torn_down": True,
        "supply_chain_resources_torn_down": True,
        "sbom_resources_torn_down": True,
        "temporary_evidence_removed": True,
        "secrets_retained": False,
    }
    release.validate_teardown(teardown)

    teardown["secrets_retained"] = True
    with pytest.raises(release.ReleaseEvidenceError, match="must be false"):
        release.validate_teardown(teardown)


def _tag_policy() -> dict:
    return {
        "tag_name": "v0.6.0",
        "tag_ref": "refs/tags/v0.6.0",
        "object_type": "tag",
        "target_policy": "CURRENT_RELEASE_HEAD",
        "package_path": "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz",
        "sidecar_path": "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256",
        "required_static_markers": [
            "Owner: JC Arcaz",
            "Decision: ACCEPTED",
            "Gate 0B: PASS",
            "Accepted exceptions: None",
            "Operational authorization: None",
            "Compliance determination: None",
            "Cryptographic signature: Not claimed",
        ],
        "required_dynamic_fields": list(release.RELEASE_TAG_DYNAMIC_FIELDS),
    }


def test_tag_policy_requires_annotated_semver_tag_and_nonclaims() -> None:
    policy = _tag_policy()
    release.validate_tag_policy(policy)

    mutation = copy.deepcopy(policy)
    mutation["tag_name"] = "v0.6"
    with pytest.raises(release.ReleaseEvidenceError, match="policy differs"):
        release.validate_tag_policy(mutation)


def test_tag_message_producer_is_exact_ordered_and_rejects_any_mutation() -> None:
    policy = _tag_policy()
    values = {
        "release_head": "a" * 40,
        "qualified_source": "b" * 40,
        "candidate_commit": "9" * 40,
        "source_fingerprint": "c" * 64,
        "evidence_fingerprint": "d" * 64,
        "product_package_sha256": "e" * 64,
        "work_package_sha256": "f" * 64,
        "final_archive_sha256": "1" * 64,
    }
    expected = release.create_release_tag_message_v06(policy, **values)
    lines = expected.splitlines()
    assert lines[:2] == [release.RELEASE_TAG_TITLE, ""]
    assert len(lines[2:]) == 15
    assert lines[2:9] == policy["required_static_markers"]
    assert [line.partition(":")[0] for line in lines[9:]] == list(
        release.RELEASE_TAG_DYNAMIC_FIELDS
    )
    release.validate_release_tag_message_v06(expected.encode("utf-8"), expected)

    reordered = lines.copy()
    reordered[2], reordered[3] = reordered[3], reordered[2]
    mutations = (
        expected.replace(release.RELEASE_TAG_TITLE, "SPELL v0.6", 1),
        "\n".join(reordered) + "\n",
        expected + "Unexpected field: value\n",
        expected.replace(lines[2] + "\n", lines[2] + "\n" + lines[2] + "\n", 1),
        expected.replace(lines[10] + "\n", "", 1),
        expected.replace("\n\n", "\n", 1),
    )
    for mutation in mutations:
        with pytest.raises(release.ReleaseEvidenceError, match="exact ordered"):
            release.validate_release_tag_message_v06(
                mutation.encode("utf-8"), expected
            )


def test_tag_object_requires_exact_headers_and_rejects_signature_headers() -> None:
    head = "a" * 40
    required = [
        f"object {head}".encode("ascii"),
        b"type commit",
        b"tag v0.6.0",
        b"tagger Release Test <release-test@example.invalid> 1786665600 -0400",
    ]
    message = b"SPELL v0.6.0\n"

    def tag_object(headers: list[bytes], body: bytes = message) -> bytes:
        return b"\n".join(headers) + b"\n\n" + body

    assert release._release_tag_message_from_object(
        tag_object(required), head
    ) == message

    header_mutations = (
        required[:3],
        [*required, b"unknown release-header"],
        [*required, required[3]],
        [*required[:3], b"tagger malformed"],
        [
            *required[:3],
            b"tagger  <release-test@example.invalid> 1786665600 -0400",
        ],
        [
            *required[:3],
            b"tagger Release Test <invalid> 1786665600 -0400",
        ],
        [required[0], required[1], required[3], required[2]],
    )
    for headers in header_mutations:
        with pytest.raises(release.ReleaseEvidenceError, match="headers differ"):
            release._release_tag_message_from_object(tag_object(headers), head)

    for signature_header in (
        b"gpgsig unclaimed",
        b"gpgsig-sha256 unclaimed",
        b"sshsig unclaimed",
        b"signature unclaimed",
        b"x-header: -----BEGIN PGP SIGNATURE-----",
    ):
        with pytest.raises(
            release.ReleaseEvidenceError,
            match="unclaimed cryptographic signature",
        ):
            release._release_tag_message_from_object(
                tag_object([*required, signature_header]), head
            )


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode("utf-8").strip()


def test_require_tag_validates_real_annotated_object_target_markers_and_sidecar(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Release Test")
    _git(tmp_path, "config", "user.email", "release-test@example.invalid")
    package = tmp_path / "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz"
    package.parent.mkdir(parents=True)
    package.write_bytes(b"deterministic release bytes")
    archive_sha = hashlib.sha256(package.read_bytes()).hexdigest()
    sidecar = package.with_name(package.name + ".sha256")
    sidecar.write_bytes(f"{archive_sha}  {package.name}\n".encode("ascii"))
    tracked = tmp_path / "release.txt"
    tracked.write_text("release\n", encoding="ascii")
    _git(
        tmp_path,
        "add",
        "-f",
        "release.txt",
        release.RELEASE_PACKAGE_PATH,
        release.RELEASE_PACKAGE_SIDECAR_PATH,
    )
    _git(tmp_path, "commit", "-m", "release")
    head = _git(tmp_path, "rev-parse", "HEAD")
    qualified = "b" * 40
    candidate = "9" * 40
    source = "c" * 64
    evidence = "d" * 64
    product = "e" * 64
    work = "f" * 64
    policy = _tag_policy()
    expected_message = release.create_release_tag_message_v06(
        policy,
        release_head=head,
        qualified_source=qualified,
        candidate_commit=candidate,
        source_fingerprint=source,
        evidence_fingerprint=evidence,
        product_package_sha256=product,
        work_package_sha256=work,
        final_archive_sha256=archive_sha,
    )
    message = tmp_path / "tag-message.txt"
    message.write_text(expected_message, encoding="utf-8")
    _git(tmp_path, "tag", "-a", "v0.6.0", "-F", str(message))

    tag_object, tagged = release.validate_release_tag(
        tmp_path,
        policy,
        release_head=head,
        qualified_source=qualified,
        candidate_commit=candidate,
        source_fingerprint=source,
        evidence_fingerprint=evidence,
        product_package_sha256=product,
        work_package_sha256=work,
    )

    assert len(tag_object) == 40
    assert tagged == head

    package.write_bytes(b"mutable filesystem replacement")
    with pytest.raises(
        release.ReleaseEvidenceError, match="differs from the release commit"
    ):
        release.validate_release_tag(
            tmp_path,
            policy,
            release_head=head,
            qualified_source=qualified,
            candidate_commit=candidate,
            source_fingerprint=source,
            evidence_fingerprint=evidence,
            product_package_sha256=product,
            work_package_sha256=work,
        )
    package.write_bytes(b"deterministic release bytes")
    sidecar.write_bytes(b"0" * 64 + f"  {package.name}\n".encode("ascii"))
    with pytest.raises(
        release.ReleaseEvidenceError, match="differs from the release commit"
    ):
        release.validate_release_tag(
            tmp_path,
            policy,
            release_head=head,
            qualified_source=qualified,
            candidate_commit=candidate,
            source_fingerprint=source,
            evidence_fingerprint=evidence,
            product_package_sha256=product,
            work_package_sha256=work,
        )
    sidecar.write_bytes(f"{archive_sha}  {package.name}\n".encode("ascii"))

    _git(tmp_path, "tag", "-d", "v0.6.0")
    message.write_text(
        expected_message
        + "-----BEGIN SSH SIGNATURE-----\n"
        + "unclaimed\n"
        + "-----END SSH SIGNATURE-----\n",
        encoding="utf-8",
    )
    _git(tmp_path, "tag", "-a", "v0.6.0", "-F", str(message))
    with pytest.raises(
        release.ReleaseEvidenceError, match="unclaimed cryptographic signature"
    ):
        release.validate_release_tag(
            tmp_path,
            policy,
            release_head=head,
            qualified_source=qualified,
            candidate_commit=candidate,
            source_fingerprint=source,
            evidence_fingerprint=evidence,
            product_package_sha256=product,
            work_package_sha256=work,
        )
    _git(tmp_path, "tag", "-d", "v0.6.0")
    message.write_text(expected_message, encoding="utf-8")
    _git(tmp_path, "tag", "-a", "v0.6.0", "-F", str(message))

    _git(tmp_path, "tag", "v0.6")
    with pytest.raises(release.ReleaseEvidenceError, match="secondary v0.6 tag"):
        release.validate_release_tag(
            tmp_path,
            policy,
            release_head=head,
            qualified_source=qualified,
            candidate_commit=candidate,
            source_fingerprint=source,
            evidence_fingerprint=evidence,
            product_package_sha256=product,
            work_package_sha256=work,
        )

    mutation = copy.deepcopy(policy)
    mutation["required_static_markers"].remove("Operational authorization: None")
    with pytest.raises(release.ReleaseEvidenceError, match="policy differs"):
        release.validate_tag_policy(mutation)


def test_release_manifest_shape_rejects_exceptions_claims_and_unknown_fields() -> None:
    manifest = _manifest_shape()
    release.validate_release_manifest_shape(manifest)

    manifest["decision"]["accepted_exceptions"] = ["skip PostgreSQL"]
    with pytest.raises(release.ReleaseEvidenceError, match="accepted exception"):
        release.validate_release_manifest_shape(manifest)

    manifest = _manifest_shape()
    manifest["decision"]["operational_authorization"] = True
    with pytest.raises(release.ReleaseEvidenceError, match="must be false"):
        release.validate_release_manifest_shape(manifest)

    manifest = _manifest_shape()
    manifest["broader_v06_scope"] = True
    with pytest.raises(release.ReleaseEvidenceError, match="unauthorized keys"):
        release.validate_release_manifest_shape(manifest)


def test_sqlite_skip_contract_is_exact_and_other_suites_have_no_allowlist() -> None:
    assert len(release.SQLITE_ALLOWED_SKIPS) == 6
    assert sum("test_migrations.py" in node for node in release.SQLITE_ALLOWED_SKIPS) == 4
    assert sum("test_driver_isolation.py" in node for node in release.SQLITE_ALLOWED_SKIPS) == 2
    assert "backend_postgresql" in release.ZERO_SKIP_SUITE_IDS
    assert "driver_host" in release.ZERO_SKIP_SUITE_IDS
    assert release.FINAL_SUBTEST_COUNTS == {
        "backend_sqlite": 0,
        "backend_postgresql": 0,
        "backend_docker_host": 0,
        "driver_host": 0,
        "tooling": 36,
        "frontend_unit": 0,
        "browser_mocked": 0,
        "browser_real": 0,
    }
    assert "tooling" in release.ZERO_SKIP_SUITE_IDS
    assert "frontend_unit" in release.ZERO_SKIP_SUITE_IDS
    assert "browser_mocked" in release.ZERO_SKIP_SUITE_IDS
    assert "browser_real" in release.ZERO_SKIP_SUITE_IDS


def test_builder_compatible_api_returns_versioned_entry_point() -> None:
    assert callable(release.validate_release_evidence)
    assert callable(release.validate_release_evidence_v06)
    assert release.validate_release_evidence_v06.__doc__


def test_builder_is_the_only_explicit_prepublication_package_exception() -> None:
    source = (release.ROOT / "scripts/build_reproducible_v06.py").read_text(
        encoding="utf-8"
    )
    assert source.count("require_package=False") == 2


def test_repository_release_validation_is_positive_or_fails_closed_before_publication() -> None:
    manifest = release.DEFAULT_EVIDENCE_ROOT / release.MANIFEST_NAME
    if not manifest.is_file():
        with pytest.raises(
            release.ReleaseEvidenceError,
            match="release qualification manifest is missing or unsafe",
        ):
            release.validate_release_evidence(release.ROOT)
        return

    result = release.validate_release_evidence(release.ROOT)

    assert result.validated_suite_ids == release.FINAL_SUITE_IDS
    assert result.validated_test_count > 0
    assert len(result.sbom_image_ids) == 4
