"""Authoring profile binding through independent build and promotion checks."""
from copy import deepcopy
import base64
import hashlib

import pytest

from backend.development_analysis import analyze_source
from backend.development_domain import DevelopmentCorruptionError, DevelopmentError, canonical_json_bytes
from backend.development_models import DevelopmentBundle
from backend.development_profiles import LEGACY_LANGUAGE_PROFILE, V19_LANGUAGE_PROFILE
from backend.development_service import DevelopmentService
from backend.tests.test_development_service_v09 import ADMIN, OPERATOR, _candidate_bundle, _run_project_check, _service
from backend.tests.test_ir_v07 import _condition


BODY = '''reading: float = 0.0
status: str = ""
GetTM("TM.POWER.BUS_VOLTAGE", target=reading, scalar_type="float")
Verify(condition=CONDITION, target=status, timeout=2)
WaitFor(seconds=0)
answer = Prompt("Send the observed command?", Type=YES_NO)
command = BuildTC("CMDNAME")
if answer == "YES" and reading >= 27.5 and status == "TRUE":
    Send(command=command, Confirm=True)
Display("Observation workflow finished")
'''.replace("CONDITION", repr(_condition()))


def source(body=BODY, profile=V19_LANGUAGE_PROFILE):
    return f"# @procedure local/authoring-v19\n# @language-profile {profile}\n" + body


def project_with_source(service, body=BODY):
    project = service.create_project(
        **OPERATOR, name="V19 authoring", case_policy="CASE_INSENSITIVE",
        manifest={"language_profile": V19_LANGUAGE_PROFILE}, idempotency_key="project-v19",
    )["project"]
    text = source(body)
    created = service.create_resource(
        project["project_id"], **OPERATOR, path="procedures/workflow.spell.py",
        kind="PROCEDURE", media_type="text/x-python", content=text,
        content_sha256=hashlib.sha256(text.encode()).hexdigest(), expected_workspace_revision=1,
        idempotency_key="source-v19",
    )
    return created["project"], created["resource"]


def test_profile_bound_language_service_returns_current_metadata_and_completion(tmp_path):
    service = _service(tmp_path)
    project, resource = project_with_source(service)
    document = service.get_resource(project["project_id"], resource["resource_id"], **OPERATOR)["resource"]
    assert document["metadata"]["language_profile"] == V19_LANGUAGE_PROFILE
    assert document["language"]["diagnostics"] == []
    calls = {item["label"] for item in document["language"]["completions"] if item["kind"] == "SPELL_CALL"}
    assert {"GetTM", "Verify", "WaitFor", "Prompt", "Display", "BuildTC", "Send"} <= calls
    analysis = analyze_source(source(), "procedures/workflow.spell.py", workspace_revision=2, language_profile=V19_LANGUAGE_PROFILE)
    assert analysis.compiled["procedures/workflow.spell.py"]["ir_version"] == "0.19"
    job = _run_project_check(service, project["project_id"], project["workspace_revision"], "profile-report")
    assert job["report"]["language_profile"] == V19_LANGUAGE_PROFILE
    assert job["report"]["outcome"] == "PASS"


@pytest.mark.parametrize("body,version", [
    ('Log("ready")\n', "0.3"),
    ('Prompt("ready", type="OK")\n', "0.6"),
    ('WaitFor(seconds=0)\n', "0.7"),
    ('DataContainer("LOCAL.DATA")\n', "0.8"),
    ('Send(command="CMDNAME")\n', "0.11"),
    ('answer = Prompt("Continue?", YES_NO)\n', "0.17"),
    ('answer = Prompt("Continue?", YES_NO)\nSend(command="CMDNAME")\n', "0.18"),
    (BODY, "0.19"),
])
def test_new_profile_allows_exact_standalone_and_composed_ir(body, version):
    result = analyze_source(source(body), "procedure.spell.py", workspace_revision=1, language_profile=V19_LANGUAGE_PROFILE)
    assert result.diagnostics == ()
    assert result.compiled["procedure.spell.py"]["ir_version"] == version


@pytest.mark.parametrize("header,project,body,code", [
    (V19_LANGUAGE_PROFILE, LEGACY_LANGUAGE_PROFILE, 'Log("x")\n', "AUTHORING_PROFILE_MISMATCH"),
    (LEGACY_LANGUAGE_PROFILE, V19_LANGUAGE_PROFILE, 'Log("x")\n', "AUTHORING_PROFILE_MISMATCH"),
    (LEGACY_LANGUAGE_PROFILE, LEGACY_LANGUAGE_PROFILE, BODY, "AUTHORING_IR_UNSUPPORTED"),
    (V19_LANGUAGE_PROFILE, V19_LANGUAGE_PROFILE, 'result = ""\nLanguageCheck(0, profile="0.19", target=result)\n', "AUTHORING_IR_UNSUPPORTED"),
])
def test_wrong_profile_and_catalog_only_ir_never_produce_authored_artifact(header, project, body, code):
    result = analyze_source(source(body, header), "procedure.spell.py", workspace_revision=1, language_profile=project)
    assert code in {item["code"] for item in result.diagnostics}
    assert all(item["language_profile"] == project for item in result.diagnostics)
    assert result.compiled == {}


@pytest.mark.parametrize("invalid", [[], {}, True, "spell-lrm244-conformance/0.20"])
def test_manifest_rejects_unrecognized_or_unhashable_profile(invalid):
    with pytest.raises(DevelopmentError, match="profile"):
        DevelopmentService._manifest({"language_profile": invalid}, project_id="project", display_name="Profile", case_policy="CASE_SENSITIVE", owner="author")


def test_new_profile_bundle_review_promotion_and_source_identity(tmp_path):
    service = _service(tmp_path)
    project, _ = project_with_source(service)
    bundle = _candidate_bundle(service, project)
    with service.factory() as session:
        stored = session.get(DevelopmentBundle, bundle["bundle_digest"])
        verified = service._verify_bundle_row(stored)
        assert verified["manifest"]["language_profile"] == V19_LANGUAGE_PROFILE
        assert verified["manifest"]["ir_schema_version"] == ["0.19"]
        assert verified["manifest"]["review_subject"] == ADMIN["subject"] != OPERATOR["subject"]
    service.approve_bundle(bundle["bundle_digest"], **ADMIN, expected_state_revision=1, reason="Independent v19 approval", idempotency_key="approve-v19")
    service.catalog_decision("local/authoring-v19", **ADMIN, operation="PROMOTE", bundle_digest=bundle["bundle_digest"], expected_registry_revision=0, reason="Local v19 promotion", idempotency_key="promote-v19")
    procedure = service.get_promoted_procedure("local/authoring-v19")
    assert procedure.ir_version == "0.19"
    assert procedure.bundle_digest == bundle["bundle_digest"]
    assert procedure.source == source()
    assert procedure.sha256 == hashlib.sha256(source().encode()).hexdigest()


@pytest.mark.parametrize("mutation", ["bundle-profile", "project-profile", "compiled", "toolchain"])
def test_stored_bundle_revalidation_rejects_rehashed_profile_ir_and_provenance_tampering(tmp_path, mutation):
    service = _service(tmp_path)
    project, _ = project_with_source(service)
    bundle = _candidate_bundle(service, project)
    with service.factory() as session:
        row = session.get(DevelopmentBundle, bundle["bundle_digest"])
        payload = deepcopy(service._verify_bundle_row(row))
        if mutation == "bundle-profile":
            payload["manifest"]["language_profile"] = LEGACY_LANGUAGE_PROFILE
        elif mutation == "project-profile":
            entry = next(item for item in payload["entries"] if item["path"] == "spell-project.yaml")
            import json
            manifest = json.loads(base64.b64decode(entry["content"]))
            manifest["language_profile"] = LEGACY_LANGUAGE_PROFILE
            content = canonical_json_bytes(manifest)
            entry["content"] = base64.b64encode(content).decode("ascii")
            entry["content_sha256"] = hashlib.sha256(content).hexdigest()
        elif mutation == "compiled":
            entry = next(item for item in payload["entries"] if "compiled" in item)
            entry["compiled"]["steps"][-1]["line"] += 1
        else:
            payload["manifest"]["toolchain_digest"] = "0" * 64
        raw = canonical_json_bytes(payload)
        row.bundle_bytes = raw
        row.byte_length = len(raw)
        row.bundle_digest = hashlib.sha256(raw).hexdigest()
        row.manifest = {**payload["manifest"], "bundle_digest": row.bundle_digest}
        with pytest.raises(DevelopmentCorruptionError):
            service._verify_bundle_row(row)
