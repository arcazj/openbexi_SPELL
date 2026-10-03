from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scripts import release_next as release


@pytest.mark.parametrize("minor,scope", [
    (16, "LOCAL_SIMULATOR_LANGUAGE_AND_MANUAL_WORKSPACE"),
    (17, "LOCAL_SIMULATOR_DIRECT_LANGUAGE_CONFORMANCE"),
    (18, "LOCAL_SIMULATOR_NATIVE_TELECOMMAND_WORKFLOWS"),
    (19, "LOCAL_SIMULATOR_OBSERVATION_COMMAND_WORKFLOWS"),
])
@pytest.mark.parametrize("tamper", [None, "schema", "owner", "requirements", "predecessor", "authority", "inventory", "source"])
def test_entry_gate_rejects_changed_authority_and_references(tmp_path, monkeypatch, minor, scope, tamper):
    import importlib
    import json
    gate = importlib.import_module(f"scripts.validate_v{minor}_gate")

    references = [{"path": "manual.pdf", "sha256": release.sha(b"reference")}]
    entry = {"schema_version": f"spell.v{minor}.entry-gate/1", "release_tag": f"v0.{minor}.0", "scope": scope,
             "owner_authorized": True, "operational_authorization": False,
             "full_language_compatibility_claim": False, "requirements": sorted(gate.REQUIRED),
             "predecessor_commit": "accepted"}
    policy = {"release_tag": entry["release_tag"], "scope": entry["scope"],
              "predecessor_commit": "accepted", "reference_inputs": references,
              "operational_authorization": False, "legacy_system_qualified": False}
    prior = json.dumps({"reference_inputs": references}).encode()
    monkeypatch.setattr(gate.subprocess, "check_output", lambda args, **kwargs:
                        "accepted\n" if args[1] == "rev-parse" else prior)
    monkeypatch.setattr(gate.subprocess, "run", lambda *args, **kwargs: None)
    (tmp_path / f"contracts/v{minor}").mkdir(parents=True)
    record = tmp_path / f"NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.{minor}_Pre-Implementation.md"
    record.parent.mkdir(parents=True)
    record.write_text("\n".join(gate.REQUIRED))
    (tmp_path / "manual.pdf").write_bytes(b"reference")
    if tamper == "schema": entry["schema_version"] = f"spell.v{minor-1}.entry-gate/1"
    elif tamper == "owner": entry["owner_authorized"] = False
    elif tamper == "requirements": entry["requirements"].pop()
    elif tamper == "predecessor": entry["predecessor_commit"] = "unaccepted"
    elif tamper == "authority": policy["operational_authorization"] = True
    elif tamper == "inventory": policy["reference_inputs"] = []
    elif tamper == "source": (tmp_path / "manual.pdf").write_bytes(b"changed")
    release.write_json(tmp_path / f"contracts/v{minor}/entry_gate.json", entry)
    release.write_json(tmp_path / f"contracts/v{minor}/release_policy.json", policy)
    if tamper:
        with pytest.raises(ValueError):
            gate.validate(tmp_path)
    else:
        assert gate.validate(tmp_path)["decision"] == "PASS"


@pytest.mark.parametrize("tamper", [None, "missing", "extra", "not_png"])
def test_browser_evidence_rechecks_screenshot_inventory_and_format(tmp_path, tamper):
    browser = tmp_path / "browser"
    browser.mkdir()
    screenshot = browser / "session.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic-test-payload")
    if tamper == "missing": screenshot.unlink()
    elif tamper == "extra": (browser / "extra.png").write_bytes(screenshot.read_bytes())
    elif tamper == "not_png": screenshot.write_bytes(b"not screenshot evidence")
    if tamper:
        with pytest.raises(release.ReleaseError):
            release.verify_browser_evidence(tmp_path, {"browser_screenshots": 1})
    else:
        release.verify_browser_evidence(tmp_path, {"browser_screenshots": 1})


@pytest.mark.parametrize("field", [None, "schema_version", "release_tag", "scope", "file_count", "repeated_builds", "repro_schema"])
def test_release_metadata_rejects_tamper_even_when_package_hash_is_unchanged(monkeypatch, field):
    monkeypatch.setattr(release, "package_names", lambda: ["backend/app.py", "README.md"])
    manifest = {"schema_version": f"spell.v{release.MINOR}.release-manifest/1",
                "release_tag": release.TAG, "scope": release.PROFILE,
                "file_count": 2, "repeated_builds": 2, "package_sha256": "unchanged"}
    reproduced = {"schema_version": f"spell.v{release.MINOR}.reproducibility/1"}
    if field == "repro_schema": reproduced["schema_version"] = "old"
    elif field is not None: manifest[field] = 1 if field in {"file_count", "repeated_builds"} else "tampered"
    if field:
        with pytest.raises(release.ReleaseError):
            release.verify_release_metadata(manifest, reproduced)
    else:
        release.verify_release_metadata(manifest, reproduced)


@pytest.mark.parametrize("minor", [16, 17, 18, 19])
@pytest.mark.parametrize("tamper", [None, "missing", "extra", "ir", "cases", "adaptations", "authority", "failure"])
def test_installed_language_runner_proof_is_exact(monkeypatch, minor, tamper):
    monkeypatch.setattr(release, "MINOR", minor)
    result = {"ir_version": "0.16", "steps": 7, "direct_and_boundary_cases": 32,
              "adapted_examples": 195, "adapted_variants": 257,
              "full_compatibility": False, "decision": "PASS"}
    if minor >= 17:
        from importlib import import_module
        result = import_module(f"backend.language_conformance_v{minor}").expected_image_runner_proof()
    if tamper == "extra": result["unbound"] = True
    if tamper == "ir": result["ir_version"] = "0.15"
    elif tamper == "cases": result["direct_and_boundary_cases"] -= 1
    elif tamper == "adaptations": result["adapted_variants"] = 195
    elif tamper == "authority": result["full_compatibility"] = 0
    elif tamper == "failure": result["decision"] = "FAIL"
    probe = {"images": {"backend": {} if tamper == "missing" else {"language_runner": result}}}
    if tamper:
        with pytest.raises(release.ReleaseError):
            release.verify_installed_language_runner(probe)
    else:
        release.verify_installed_language_runner(probe)


def test_junit_retains_exact_identities_and_skips(tmp_path: Path) -> None:
    path = tmp_path / "tests.xml"
    path.write_text('<testsuite><testcase classname="a" name="b" time="0.1"/><testcase classname="a" name="c"><skipped/></testcase></testsuite>')
    assert release.junit(path) == {"tests": 2, "passed": 1, "identities": ["a::b", "a::c"], "skipped": ["a::c"]}


@pytest.mark.parametrize("cases", [
    '', '<testcase name="bad"><failure/></testcase>', '<testcase name="bad"><error/></testcase>',
    '<testcase name="same"/><testcase name="same"/>', '<testcase name="bad" time="NaN"/>',
    '<testcase name="bad" time="Infinity"/>', '<testcase name="bad" time="-1"/>',
])
def test_junit_rejects_invalid_or_failing_evidence(tmp_path: Path, cases: str) -> None:
    path = tmp_path / "tests.xml"
    path.write_text('<testsuite>' + cases + '</testsuite>')
    with pytest.raises(release.ReleaseError):
        release.junit(path)


def test_package_retains_product_images_but_excludes_captures_and_manuals(tmp_path: Path, monkeypatch) -> None:
    names = ['frontend/src/logo.png', 'backend/app.py', 'artifacts/v0.12/screenshot.png',
             'SPELL_DOCUMENTATION/manual.pdf', 'legacy.zip', 'module.pyc']
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'product')
    monkeypatch.setattr(release, 'ROOT', tmp_path)
    monkeypatch.setattr(release, 'git', lambda *args: '\0'.join(names))
    assert release.package_names() == ['backend/app.py', 'frontend/src/logo.png']
    first = release.archive()
    assert first == release.archive()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first))) as archive:
        assert archive.getnames() == release.package_names()


@pytest.mark.parametrize("name", [".env", "backend/private.key", "credentials.json"])
def test_secret_paths_fail_packaging(tmp_path: Path, monkeypatch, name: str) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic-canary")
    monkeypatch.setattr(release, 'ROOT', tmp_path)
    monkeypatch.setattr(release, 'git', lambda *args: name)
    with pytest.raises(release.ReleaseError):
        release.package_names()


def test_json_evidence_has_canonical_lf_bytes(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    release.write_json(path, {"result": "PASS"})
    assert b'\r' not in path.read_bytes()
    assert path.read_bytes().endswith(b'\n')


def test_catalog_preserves_double_colons_inside_parameters(tmp_path: Path) -> None:
    import json
    from types import SimpleNamespace
    from scripts.collect_release_v12 import Catalog
    name = "test_reflection[column::text = ANY (ARRAY['a'::varchar]::text[])]"
    item = SimpleNamespace(nodeid="backend/tests/test_schema.py::" + name, name=name,
                           iter_markers=lambda _: ())
    output = tmp_path / "catalog.json"
    Catalog(output).pytest_collection_finish(SimpleNamespace(items=[item]))
    assert json.loads(output.read_bytes()) == [{"identity": "backend.tests.test_schema::" + name, "skip": False}]


@pytest.mark.parametrize("tamper", [None, "evidence", "source"])
def test_candidate_gate_activates_atomically_only_for_unchanged_proof(tmp_path, monkeypatch, tamper):
    import json
    captures = tmp_path / "captures"
    captures.mkdir()
    (tmp_path / ".qualification").mkdir()
    candidate = tmp_path / "candidate"
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "CANDIDATE", candidate)
    monkeypatch.setattr(release, "fingerprint", lambda: "frozen")
    monkeypatch.setattr(release, "git", lambda *args: "source" if args[0] == "rev-parse" else "")
    monkeypatch.setattr(release, "policy", lambda: {"candidate_identities": ["suite::proof"]})
    (captures / "candidate.xml").write_bytes(b'<testsuite><testcase classname="suite" name="proof"/></testsuite>')
    release.write_json(captures / "candidate.command.json", {"source_commit": "source",
        "source_fingerprint": "frozen", "commands": [{"returncode": 0}]})
    release.candidate_prepare(captures)
    assert not candidate.exists()
    if tamper == "evidence":
        (captures / "candidate.xml").write_bytes(b'<testsuite><testcase classname="suite" name="proof"><failure/></testcase></testsuite>')
    elif tamper == "source":
        monkeypatch.setattr(release, "fingerprint", lambda: "changed")
    if tamper:
        with pytest.raises(release.ReleaseError):
            release.candidate_apply(captures)
        assert not candidate.exists()
    else:
        release.candidate_apply(captures)
        assert release.verify_candidate(release.policy())["decision"] == "PASS"
        assert json.loads((candidate / "gate-0b.json").read_bytes())["tests"] == 1


@pytest.mark.parametrize("tamper", [None, "advisory", "package", "version", "header", "location", "hash", "development"])
def test_gcc_applicability_is_component_and_evidence_bound(tamper):
    from scripts.gcc_header_applicability import ADVISORY, PURL, PACKAGES, LOCATIONS, resolve
    rule = {"id": ADVISORY, "properties": {"security-severity": "7.0", "purls": [PURL]}}
    result = {"ruleId": ADVISORY, "locations": [{"physicalLocation": {"artifactLocation": {"uri": p}}} for p in sorted(LOCATIONS)]}
    evidence = {"packages": dict(PACKAGES), "files": {p: "a" * 64 for p in LOCATIONS - {"/var/lib/dpkg/status"}}, "pb_ds_headers": []}
    if tamper == "advisory":
        rule["id"] = "CVE-unknown"
    elif tamper == "package":
        rule["properties"]["purls"] = ["pkg:deb/debian/gcc-15@other"]
    elif tamper == "version":
        evidence["packages"]["libstdc++6:amd64"] = "unknown"
    elif tamper == "header":
        evidence["pb_ds_headers"] = ["/usr/include/c++/14/ext/pb_ds/priority_queue.hpp"]
    elif tamper == "location":
        result["locations"].append({"physicalLocation": {"artifactLocation": {"uri": "/unknown"}}})
    elif tamper == "hash":
        evidence["files"]["/usr/lib/x86_64-linux-gnu/libgcc_s.so.1"] = "invalid"
    elif tamper == "development":
        evidence["files"]["/usr/include/c++/header.hpp"] = "a" * 64
    scan = {"runs": [{"tool": {"driver": {"rules": [rule]}}, "results": [result]}]}
    if tamper:
        with pytest.raises(AssertionError):
            resolve(scan, {"gcc_header_applicability": evidence})
    else:
        assert resolve(scan, {"gcc_header_applicability": evidence})[0]["status"] == "NOT_AFFECTED"


@pytest.mark.parametrize("tamper", [None, "duration", "nan", "latency", "workload", "source", "failure"])
def test_adapter_soak_rejects_invalid_budget_and_source_proof(tamper):
    from backend.legacy_observation_v12 import load_sources
    report = {"decision": "PASS", "failures": 0, "elapsed_seconds": 60.1, "batches": 128,
              "reads_per_batch": 8, "batch_latency_ms": [0.1] * 128,
              "sources": {key: value.identity() for key, value in load_sources().items()}}
    if tamper == "duration": report["elapsed_seconds"] = 0
    elif tamper == "nan": report["batch_latency_ms"][0] = float("nan")
    elif tamper == "latency": report["batch_latency_ms"][0] = 500
    elif tamper == "workload": report["batches"] = 127
    elif tamper == "source": report["sources"]["reference"]["digest"] = "0" * 64
    elif tamper == "failure": report["failures"] = 1
    if tamper:
        with pytest.raises(release.ReleaseError):
            release.verify_adapter_soak(report)
    else:
        release.verify_adapter_soak(report)


@pytest.mark.parametrize("tamper", [None, "duration", "latency", "event_count", "authority", "source"])
def test_pilot_soak_recomputes_durable_workload_and_authority(tamper):
    from backend.legacy_observation_v12 import load_sources
    report = {"decision": "PASS", "failures": 0, "elapsed_seconds": 60.1, "iterations": 16,
              "batch_seconds": [0.1] * 16, "runs": 32, "events": 80, "operational_authorization": False,
              "source_identities": {key: value.identity() for key, value in load_sources().items()}}
    if tamper == "duration": report["elapsed_seconds"] = 1
    elif tamper == "latency": report["batch_seconds"][0] = float("nan")
    elif tamper == "event_count": report["events"] = 79
    elif tamper == "authority": report["operational_authorization"] = True
    elif tamper == "source": report["source_identities"]["reference"]["digest"] = "0" * 64
    if tamper:
        with pytest.raises(release.ReleaseError):
            release.verify_pilot_soak(report)
    else:
        release.verify_pilot_soak(report)
