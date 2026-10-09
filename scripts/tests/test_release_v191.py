"""Independent entry, image and complete procedure coverage for the patch release."""
from copy import deepcopy
import hashlib
import json

import pytest

from scripts import release_next as release
from scripts import validate_v191_gate as entry
from scripts.qualify_dss_v191 import build_manifest, scenario_definitions
from scripts.validate_dss_delivery import load_manifest, source_inventory, _release_minor


@pytest.mark.parametrize("tamper", [None, "schema", "owner", "scope", "requirements", "predecessor", "authority", "dss", "references", "source"])
def test_patch_entry_rechecks_authority_predecessor_and_reference_bytes(tmp_path, monkeypatch, tamper):
    references = [{"path":"manual.pdf", "sha256":hashlib.sha256(b"reference").hexdigest()}]
    record = {"schema_version":"spell.v191.entry-gate/1", "release_tag":"v0.19.1",
        "scope":"LOCAL_SIMULATOR_PYTHON_RUNTIME_AND_DEBUGGER", "owner_authorized":True,
        "operational_authorization":False, "full_language_compatibility_claim":False,
        "dss_validation_required":True, "predecessor_commit":"accepted", "requirements":sorted(entry.REQUIRED)}
    policy = {key:record[key] for key in ("release_tag", "scope", "operational_authorization", "dss_validation_required", "predecessor_commit")}
    policy.update(product_version="0.19.1", legacy_system_qualified=False, reference_inputs=references)
    monkeypatch.setattr(entry.subprocess, "check_output", lambda args, **kwargs:
        "accepted\n" if args[1] == "rev-parse" else json.dumps({"reference_inputs":references}).encode())
    monkeypatch.setattr(entry.subprocess, "run", lambda *args, **kwargs: None)
    (tmp_path / "contracts/v19.1").mkdir(parents=True)
    docs = tmp_path / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases"
    docs.mkdir(parents=True)
    (docs / "SPELL_v0.19.1_Pre-Implementation.md").write_text("\n".join(entry.REQUIRED))
    (tmp_path / "manual.pdf").write_bytes(b"reference")
    if tamper == "schema": record["schema_version"] = "spell.v19.entry-gate/1"
    elif tamper == "owner": record["owner_authorized"] = False
    elif tamper == "scope": record["scope"] = "different"
    elif tamper == "requirements": record["requirements"].pop()
    elif tamper == "predecessor": record["predecessor_commit"] = "unaccepted"
    elif tamper == "authority": policy["operational_authorization"] = True
    elif tamper == "dss": policy["dss_validation_required"] = False
    elif tamper == "references": policy["reference_inputs"] = []
    elif tamper == "source": (tmp_path / "manual.pdf").write_bytes(b"changed")
    (tmp_path / "contracts/v19.1/entry_gate.json").write_text(json.dumps(record))
    (tmp_path / "contracts/v19.1/release_policy.json").write_text(json.dumps(policy))
    if tamper:
        with pytest.raises(ValueError): entry.validate(tmp_path)
    else:
        assert entry.validate(tmp_path)["decision"] == "PASS"


@pytest.mark.parametrize("tamper", [None, "missing", "wrong-image"])
def test_python_runner_requires_its_own_scanned_running_image(monkeypatch, tamper):
    monkeypatch.setattr(release, "MINOR", 19)
    monkeypatch.setattr(release, "PYTHON_RELEASE", True)
    assert release.image_names() == {"backend", "driver", "frontend", "proxy", "dss", "kafka", "python"}
    images = {name:{"image_id":"sha256:" + f"{i:064x}"} for i, name in enumerate(sorted(release.image_names()), 1)}
    services = {service:deepcopy(images[name]) for service, name in (
        ("backend", "backend"), ("spell-driver", "driver"), ("proxy", "proxy"),
        ("bundle-builder-a", "backend"), ("bundle-builder-b", "backend"),
        ("dss", "dss"), ("kafka", "kafka"), ("python-runtime", "python"))}
    if tamper == "missing": services.pop("python-runtime")
    elif tamper == "wrong-image": services["python-runtime"] = images["backend"]
    if tamper:
        with pytest.raises(ValueError, match="python-runtime"):
            release.verify_running_image_bindings(services, images)
    else:
        release.verify_running_image_bindings(services, images)


def test_patch_inventory_includes_every_python_file_and_retains_all_reference_cases():
    inventory = source_inventory("v0.19.1")
    files = {path.relative_to(release.ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in (release.ROOT / "procedures").rglob("*.py")}
    assert {row["source_path"]:row["source_sha256"] for row in inventory if row["kind"] == "PROCEDURE"} == files
    assert len(files) == 12
    assert len(inventory) == 956
    assert load_manifest("v0.19.1") == build_manifest()
    scenarios = scenario_definitions()
    assert len(scenarios) == 32
    assert {row["subject"].removeprefix("procedure:") for row in scenarios} == set(files)
    assert scenarios[-1]["id"] == "core-tutorial"
    assert next(row for row in scenarios if row["id"] == "native-python-full")["operator_actions"] == [{"action":"run"}]


@pytest.mark.parametrize("version", ["v0.19.2", "v0.20.1", "v0.19", "0.19.1"])
def test_unreviewed_patch_release_cannot_borrow_dss_contract(version):
    with pytest.raises(ValueError): _release_minor(version)


@pytest.mark.parametrize("tamper", [None, "procedure-profile", "tc-stage", "duplicate-checkpoint"])
def test_native_dss_oracle_uses_public_metadata_and_accepts_decoded_telemetry(monkeypatch, tamper):
    from scripts import validate_dss_delivery as validator
    definition = next(row for row in scenario_definitions() if row["id"] == "native-python-full")
    expected = definition["expected"]
    events = [{"event_type":"step.completed", "payload":{}},
              {"event_type":"procedure.python_paused", "payload":{"reason":"entry", "source_sha256":"a"*64}}]
    events += [{"event_type":"procedure.log", "payload":{"message":"runtime output"}} for _ in range(344)]
    events.append({"event_type":"procedure.log", "payload":{"message":expected["summary"][0]}})
    # The execution snapshot deliberately has no ir_version; the public procedure does.
    capture = {"execution":{"state":"completed", "current_step":1, "variables":deepcopy(expected["variables"]), "procedure_hash":"a"*64},
        "procedure":{"ir_version":"python/1"}, "events":events, "typed_prompts":[],
        "operator_audit":[{"event_type":"operator.command_settled"}], "initial_dss_state":{},
        "dss":{"scenario_id":"native-test", "epoch":"test-epoch", "faults":{}}}
    counts = {"tc_stages":0, "executed_commands":0, "loaded_unexecuted_commands":0, "decoded_packets":14}
    monkeypatch.setattr(validator, "validate_execution_spec", lambda *args: None)
    monkeypatch.setattr(validator, "validate_transport_capture", lambda *args, **kwargs: counts)
    if tamper == "procedure-profile": capture["procedure"]["ir_version"] = "0.19"
    elif tamper == "tc-stage": counts["tc_stages"] = 1
    elif tamper == "duplicate-checkpoint": events.append(events[0])
    if tamper:
        with pytest.raises(ValueError): validator.observed_python_procedure(capture, definition)
    else:
        assert validator.observed_python_procedure(capture, definition) == expected
