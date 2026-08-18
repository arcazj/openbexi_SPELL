from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import create_release_qualification_v08 as producer
from scripts import validate_release_evidence_v08 as release


def _source() -> producer.QualifiedSourceV08:
    return producer.QualifiedSourceV08(
        commit="a" * 40,
        tree="b" * 40,
        parent="c" * 40,
        candidate_commit="d" * 40,
        candidate_delta_paths=(
            "scripts/create_release_qualification_v08.py",
            "scripts/tests/test_create_release_qualification_v08.py",
        ),
    )


def test_generation_paths_require_frozen_work_package_and_exact_final_evidence() -> None:
    producer._validate_generation_paths(
        tracked_evidence=sorted(producer.WORK_PACKAGE_EVIDENCE_PATHS),
        changed_paths=[],
        untracked_paths=sorted(producer.FINAL_EVIDENCE_PATHS),
        candidate_delta_paths=list(_source().candidate_delta_paths),
        manifest_present=False,
    )

    with pytest.raises(
        producer.ReleaseQualificationProductionError,
        match="tracked working-tree",
    ):
        producer._validate_generation_paths(
            tracked_evidence=sorted(producer.WORK_PACKAGE_EVIDENCE_PATHS),
            changed_paths=["backend/version.py"],
            untracked_paths=sorted(producer.FINAL_EVIDENCE_PATHS),
            candidate_delta_paths=list(_source().candidate_delta_paths),
            manifest_present=False,
        )

    missing = sorted(producer.FINAL_EVIDENCE_PATHS)[:-1]
    with pytest.raises(
        producer.ReleaseQualificationProductionError,
        match="untracked inventory",
    ):
        producer._validate_generation_paths(
            tracked_evidence=sorted(producer.WORK_PACKAGE_EVIDENCE_PATHS),
            changed_paths=[],
            untracked_paths=missing,
            candidate_delta_paths=list(_source().candidate_delta_paths),
            manifest_present=False,
        )

    with pytest.raises(
        producer.ReleaseQualificationProductionError,
        match="unauthorized candidate delta",
    ):
        producer._validate_generation_paths(
            tracked_evidence=sorted(producer.WORK_PACKAGE_EVIDENCE_PATHS),
            changed_paths=[],
            untracked_paths=sorted(producer.FINAL_EVIDENCE_PATHS),
            candidate_delta_paths=["backend/supervisor.py"],
            manifest_present=False,
        )


def test_tag_policy_declares_every_static_and_dynamic_message_field() -> None:
    policy = producer._tag_policy()
    release.validate_tag_policy(policy)
    assert policy["required_dynamic_fields"] == list(
        release.RELEASE_TAG_DYNAMIC_FIELDS
    )
    assert policy["required_dynamic_fields"][-1] == "Final archive SHA-256"

    mutation = copy.deepcopy(policy)
    mutation["required_dynamic_fields"].remove("Evidence fingerprint")
    with pytest.raises(release.ReleaseEvidenceError, match="policy differs"):
        release.validate_tag_policy(mutation)


def test_manifest_serialization_is_stable_and_preserves_suite_order() -> None:
    manifest = {
        "final_suites": {suite_id: {} for suite_id in release.FINAL_SUITE_IDS}
    }
    first = producer._manifest_bytes(manifest)
    second = producer._manifest_bytes(copy.deepcopy(manifest))
    assert first == second
    parsed = json.loads(first)
    assert tuple(parsed["final_suites"]) == release.FINAL_SUITE_IDS
    assert first.endswith(b"\n")


def test_sbom_declaration_is_derived_from_checksum_subject_and_image(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "artifacts/v0.8/sbom"
    directory.mkdir(parents=True)
    source = "c" * 64
    checksum_lines: list[str] = []
    expected_images: dict[str, str] = {}
    for index, name in enumerate(release.SBOM_FILES):
        image_id = f"sha256:{index + 1:064x}"
        expected_images[name] = image_id
        inventory = {
            "metadata": {
                "component": {"name": release.SBOM_SUBJECTS[name]},
                "properties": [
                    {"name": release.SBOM_IMAGE_PROPERTY, "value": image_id},
                    {"name": release.SBOM_SOURCE_PROPERTY, "value": source},
                ],
            }
        }
        path = directory / name
        path.write_text(json.dumps(inventory) + "\n", encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksum_lines.append(f"{digest}  {name}\n")
    (directory / "SHA256SUMS").write_text("".join(checksum_lines), encoding="ascii")

    declaration = producer._sbom(tmp_path, source)

    assert tuple(declaration["inventories"]) == release.SBOM_FILES
    assert {
        name: item["image_id"]
        for name, item in declaration["inventories"].items()
    } == expected_images
    assert declaration["source_fingerprint_sha256"] == source


def test_supply_chain_declaration_uses_canonical_capture_metrics(
    tmp_path: Path,
) -> None:
    source = "d" * 64
    path = tmp_path / "artifacts/v0.8/supply-chain.json"
    path.parent.mkdir(parents=True)
    capture = {
        "test_id": "V08-SC-001",
        "passed": True,
        "metrics": {
            "critical_finding_count": 0,
            "high_finding_count": 0,
            "unlocked_input_count": 0,
        },
        "accepted_v07_artifacts_unchanged": True,
    }
    path.write_text(json.dumps(capture) + "\n", encoding="utf-8")

    declaration = producer._supply_chain(tmp_path, source)

    assert declaration["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert declaration["source_fingerprint_sha256"] == source
    assert declaration["critical_finding_count"] == 0


def test_final_toolchain_changes_only_the_current_source_image_identity() -> None:
    candidate = {
        "python": "3.13.14",
        "docker": "28.5.1",
        "node": "24.13.0",
        "npm": "11.6.2",
        "playwright": "1.61.1",
        "chromium": "1234",
        "files_sha256": {"scripts/release-toolchain-v04.json": "1" * 64},
        "qualification_image_id": "sha256:" + "5" * 64,
    }
    final = {
        key: copy.deepcopy(candidate[key])
        for key in ("python", "docker", "node", "npm", "playwright", "chromium", "files_sha256")
    }
    final["candidate_qualification_image_id"] = candidate["qualification_image_id"]
    final["final_qualification_image_id"] = "sha256:" + "6" * 64
    producer._validate_final_toolchain_transition(candidate, final)

    final["python"] = "3.13.15"
    with pytest.raises(
        producer.ReleaseQualificationProductionError,
        match="immutable binding differs",
    ):
        producer._validate_final_toolchain_transition(candidate, final)


def test_manifest_builder_binds_all_release_primitives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source()
    fingerprint = "c" * 64
    product = "d" * 64
    work = {"evidence_sha256": "e" * 64}
    gate = {"scope_sha256": "f" * 64}
    suites = {suite_id: {"capture": suite_id} for suite_id in release.FINAL_SUITE_IDS}
    evidence = {"files": {}, "evidence_fingerprint_sha256": "1" * 64}
    candidate_toolchain = {
        "python": "3.13.14",
        "docker": "28.5.1",
        "node": "24.13.0",
        "npm": "11.6.2",
        "playwright": "1.61.1",
        "chromium": "1234",
        "files_sha256": {"lock": "1" * 64},
        "qualification_image_id": "sha256:" + "5" * 64,
    }
    final_toolchain = {
        key: copy.deepcopy(candidate_toolchain[key])
        for key in ("python", "docker", "node", "npm", "playwright", "chromium", "files_sha256")
    }
    final_toolchain["candidate_qualification_image_id"] = candidate_toolchain["qualification_image_id"]
    final_toolchain["final_qualification_image_id"] = "sha256:" + "6" * 64
    monkeypatch.setattr(
        producer,
        "_assert_generation_git_state",
        lambda root, *, manifest_present: source,
    )
    monkeypatch.setattr(producer, "source_fingerprint_v08", lambda root: fingerprint)
    monkeypatch.setattr(producer, "product_package_sha256_v08", lambda root: product)
    monkeypatch.setattr(
        producer,
        "_work_package_and_toolchain",
        lambda root: (work, candidate_toolchain),
    )
    monkeypatch.setattr(producer, "_gate_0b", lambda root: gate)
    monkeypatch.setattr(
        producer,
        "_final_qualification",
        lambda root: (
            {"path": release.FINAL_QUALIFICATION_PATH, "sha256": "2" * 64},
            suites,
            {
                "work_package": work,
                "gate_0b": gate,
                "toolchain": final_toolchain,
            },
        ),
    )
    monkeypatch.setattr(producer, "_evidence", lambda root: evidence)
    monkeypatch.setattr(
        producer,
        "_sbom",
        lambda root, source_fingerprint: {"source": source_fingerprint},
    )
    monkeypatch.setattr(
        producer,
        "_supply_chain",
        lambda root, source_fingerprint: {"source": source_fingerprint},
    )
    monkeypatch.setattr(producer, "_validate_manifest_components", lambda root, manifest: None)

    manifest = producer.build_release_qualification_v08(tmp_path)

    assert manifest["qualified_source"]["commit"] == source.commit
    assert manifest["qualified_source"]["tree"] == source.tree
    assert manifest["qualified_source"]["parent"] == source.parent
    assert manifest["qualified_source"]["candidate_commit"] == source.candidate_commit
    assert manifest["qualified_source"]["gate_0a_commit"] == release.GATE_0A_COMMIT
    assert manifest["qualified_source"]["source_fingerprint_sha256"] == fingerprint
    assert manifest["qualified_source"]["product_package_sha256"] == product
    assert manifest["work_package"] == work
    assert manifest["gate_0b"] == gate
    assert manifest["toolchain"] == final_toolchain
    assert tuple(manifest["final_suites"]) == release.FINAL_SUITE_IDS
    assert manifest["tag_policy"]["required_dynamic_fields"] == list(
        release.RELEASE_TAG_DYNAMIC_FIELDS
    )


def test_canonical_writer_is_atomic_idempotent_and_refuses_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source()
    manifest = {
        "qualified_source": {
            "commit": source.commit,
            "tree": source.tree,
            "source_fingerprint_sha256": "c" * 64,
            "product_package_sha256": "d" * 64,
        },
        "evidence": {"evidence_fingerprint_sha256": "e" * 64},
    }
    monkeypatch.setattr(
        producer, "build_release_qualification_v08", lambda root: manifest
    )
    monkeypatch.setattr(
        producer,
        "_assert_generation_git_state",
        lambda root, *, manifest_present: source,
    )

    first = producer.create_release_qualification_v08(tmp_path)
    second = producer.create_release_qualification_v08(tmp_path)
    output = tmp_path / producer.MANIFEST_RELATIVE

    assert first == second
    assert output.read_bytes() == producer._manifest_bytes(manifest)
    assert first.tag_message_fields == release.RELEASE_TAG_DYNAMIC_FIELDS
    assert not list(output.parent.glob(".release-qualification.json.tmp-*"))

    output.write_bytes(b"different\n")
    with pytest.raises(
        producer.ReleaseQualificationProductionError,
        match="refusing to replace",
    ):
        producer.create_release_qualification_v08(tmp_path)
