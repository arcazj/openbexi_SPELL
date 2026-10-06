"""Continuation boundary proofs; synthetic fixtures never claim full DSS execution."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from scripts import dss_continuation as continuation


def _git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")[:1000]
    return result.stdout.decode().strip()


def _commit(root):
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "test boundary")
    return _git(root, "rev-parse", "HEAD")


def _policy():
    identity = "scripts.tests.test_dss_delivery::test_existing"
    return {"scope":"unchanged", "reference_inputs":[{"sha256":"a"*64}],
        "candidate_deselections":[], "candidate_files":["scripts/tests/test_dss_delivery.py"],
        "candidate_identities":[identity],
        "gates":{"tooling":{"tests":1,"identities":[identity],"skipped":[]}}}


@pytest.fixture
def source_repo(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Continuation Test")
    _git(root, "config", "core.autocrlf", "false")
    files = {"backend/worker.py":"original runtime\n", "procedures/demo.spell.py":"Display('original')\n",
        "contracts/dss/satellite_database.json":"{}\n", "backend/requirements.hashes.lock":"pinned dependency\n",
        "scripts/qualify_dss_v19.py":"original qualification\n",
        "scripts/freeze_next_catalog.py":"tools = ('scripts.tests.test_dss_delivery::',)\n",
        "contracts/v19/release_policy.json":json.dumps(_policy())}
    files.update({name: "original gate source\n" for name in continuation.REVIEWED_GATE_CORRECTIONS})
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    base = _commit(root)
    monkeypatch.setattr(continuation, "BASELINE_SOURCE", base)
    return root, base


def test_continuation_real_git_allows_only_reviewed_qualification_catalog_delta(source_repo):
    root, _ = source_repo
    (root/"scripts/qualify_dss_v19.py").write_text("numeric wire fix\n",encoding="utf-8")
    (root/"scripts/dss_continuation.py").write_text("qualification only\n",encoding="utf-8")
    path = root/"contracts/v19/release_policy.json"
    policy = json.loads(path.read_bytes())
    new_id = "scripts.tests.test_dss_continuation::test_new"
    policy["gates"]["tooling"]["identities"] = sorted(policy["gates"]["tooling"]["identities"]+[new_id])
    policy["gates"]["tooling"]["tests"] = 2
    policy["candidate_identities"] = sorted(policy["candidate_identities"]+[new_id])
    policy["candidate_files"].append("scripts/tests/test_dss_continuation.py")
    path.write_text(json.dumps(policy),encoding="utf-8")
    (root/"scripts/freeze_next_catalog.py").write_text(
        "tools = ('scripts.tests.test_dss_delivery::', 'scripts.tests.test_dss_continuation::')\n",encoding="utf-8")
    (root/"artifacts").mkdir()
    (root/"artifacts/new-proof.json").write_text("{}",encoding="utf-8")
    changed = continuation.verify_source_compatibility(_commit(root),root=root)
    assert set(changed) == {"scripts/qualify_dss_v19.py","scripts/dss_continuation.py",
        "contracts/v19/release_policy.json","scripts/freeze_next_catalog.py"}


@pytest.mark.parametrize("mutation", [None, "changed-ui", "extra-ui", "missing-ui", "different-history"])
def test_continuation_pins_reviewed_ui_bytes_and_ancestry(source_repo, monkeypatch, mutation):
    root, base = source_repo
    names = sorted(continuation.REVIEWED_UI_FILES)
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("reviewed metallic presentation\n", encoding="utf-8")
    reviewed = _commit(root)
    monkeypatch.setattr(continuation, "REVIEWED_UI_SOURCE", reviewed)
    if mutation == "different-history":
        _git(root, "checkout", "-b", "unreviewed", base)
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("reviewed metallic presentation\n", encoding="utf-8")
    elif mutation == "changed-ui":
        (root / names[0]).write_text("unreviewed behavior\n", encoding="utf-8")
    elif mutation == "extra-ui":
        (root / "frontend/src/extra.ts").write_text("unreviewed code\n", encoding="utf-8")
    elif mutation == "missing-ui":
        (root / names[0]).unlink()
    (root / "scripts/qualify_dss_v19.py").write_text("numeric validation correction\n", encoding="utf-8")
    head = _commit(root)
    if mutation:
        with pytest.raises(ValueError):
            continuation.verify_source_compatibility(head, root=root)
    else:
        assert set(continuation.verify_source_compatibility(head, root=root)) == set(names) | {
            "scripts/qualify_dss_v19.py"}


@pytest.mark.parametrize("source_path", sorted(continuation.REVIEWED_GATE_CORRECTIONS))
@pytest.mark.parametrize("mutation", [None, "changed-source", "changed-mode", "runtime-change", "deleted-source", "missing-baseline-source"])
def test_continuation_pins_exact_reviewed_gate_correction_before_copy(source_repo, tmp_path, monkeypatch, source_path, mutation):
    root, _ = source_repo
    path = root / source_path
    if mutation == "missing-baseline-source":
        path.unlink()
        monkeypatch.setattr(continuation, "BASELINE_SOURCE", _commit(root))
    approved = b"reviewed qualification correction\n"
    path.write_bytes(approved)
    hashes = dict(continuation.REVIEWED_GATE_CORRECTIONS)
    hashes[source_path] = continuation.sha256(approved)
    monkeypatch.setattr(continuation, "REVIEWED_GATE_CORRECTIONS", hashes)
    head = _commit(root)
    if mutation == "changed-mode":
        _git(root, "update-index", "--chmod=+x", source_path)
        _git(root, "commit", "-qm", "unreviewed file mode")
        head = _git(root, "rev-parse", "HEAD")
    elif mutation == "changed-source":
        path.write_bytes(approved + b"unreviewed source change\n")
        head = _commit(root)
    elif mutation == "runtime-change":
        (root / "backend/worker.py").write_bytes(b"changed worker\n")
        head = _commit(root)
    elif mutation == "deleted-source":
        path.unlink()
        head = _commit(root)
    if mutation is None:
        assert continuation.verify_source_compatibility(head, root=root) == [source_path]
    else:
        output = tmp_path / "new-final"
        output.mkdir()
        qualifier = SimpleNamespace(bindings={"source_commit": head}, output=output / "dss-validation.json",
                                    results={}, scenarios=[], captures={})
        with pytest.raises(ValueError):
            continuation.restore_prefix(qualifier, tmp_path / "archive-not-read", root=root)
        assert qualifier.results == {} and qualifier.scenarios == [] and qualifier.captures == {}
        assert list(output.iterdir()) == []


@pytest.mark.parametrize("mutation",["backend","procedure","database","dependency","added-runtime","deleted-runtime","nonancestor"])
def test_continuation_real_git_rejects_runtime_changes_before_copy(source_repo,tmp_path,mutation):
    root,base = source_repo
    names = {"backend":"backend/worker.py", "procedure":"procedures/demo.spell.py",
        "database":"contracts/dss/satellite_database.json", "dependency":"backend/requirements.hashes.lock"}
    if mutation in names:(root/names[mutation]).write_text("changed\n",encoding="utf-8")
    elif mutation == "added-runtime":(root/"backend/extra.py").write_text("new runtime\n",encoding="utf-8")
    elif mutation == "deleted-runtime":(root/"backend/worker.py").unlink()
    else:
        _git(root,"checkout","--orphan","unrelated")
        (root/"scripts/qualify_dss_v19.py").write_text("different history\n",encoding="utf-8")
    head = _commit(root)
    output = tmp_path/"new-final"
    output.mkdir()
    q = SimpleNamespace(bindings={"source_commit":head},output=output/"dss-validation.json",
        results={},scenarios=[],captures={})
    with pytest.raises(ValueError):continuation.restore_prefix(q,tmp_path/"archive-not-read",root=root)
    assert q.results == {} and q.scenarios == [] and q.captures == {}
    assert list(output.iterdir()) == [] and _git(root,"rev-parse",base) == base


@pytest.mark.parametrize("mutation",["source-oracle","removed-identity","skip","unrelated-test","deselection","count"])
def test_continuation_frozen_policy_cannot_weaken_prior_requirements(mutation):
    old = _policy()
    new = deepcopy(old)
    if mutation == "source-oracle":new["reference_inputs"][0]["sha256"]="b"*64
    elif mutation == "removed-identity":new["gates"]["tooling"].update(tests=0,identities=[])
    elif mutation == "skip":new["gates"]["tooling"]["skipped"]=new["candidate_identities"][:]
    elif mutation == "unrelated-test":
        new["candidate_identities"].append("unexpected.tests.test_runtime::test_new")
        new["candidate_identities"].sort()
    elif mutation == "deselection":new["candidate_deselections"]=["scripts/tests/test_dss_delivery.py::test_existing"]
    else:new["gates"]["tooling"]["tests"]=2
    with pytest.raises(ValueError):continuation._validate_policy_change(old,new)


def test_continuation_freezer_addition_cannot_hide_executable_changes():
    before = b"tools = ('old-prefix',)\n"
    allowed = b"tools = ('old-prefix', 'scripts.tests.test_dss_continuation::')\n"
    continuation._validate_freezer_change(before,allowed)
    with pytest.raises(ValueError):continuation._validate_freezer_change(before,allowed+b"skip_all = True\n")


@pytest.fixture
def baseline_envelope(monkeypatch):
    """Only the provenance-envelope unit boundary; no executed-case claim."""
    source = continuation.BASELINE_SOURCE
    images = {name:"sha256:"+str(index)*64 for index,name in enumerate(sorted(continuation.IMAGE_NAMES),1)}
    documents = {
        "dss-validation.json":{"decision":"FAIL","failed_identity":continuation.FAILED_IDENTITY,
            "error":"prompt-warning-default: automatic default lacks an actual settlement event"},
        "dss-bindings.json":{"source_commit":source,"image_ids":images},
        "prepare.command.json":{"source_commit":source,"commands":[{"returncode":0,"source_commit":source,"gate":"prepare"} for _ in range(27)]}}
    documents = {name:continuation._document(continuation.canonical(row)) for name,row in documents.items()}
    refs = {f"{index:064x}":{"path":f"{index:064x}.json","size":1} for index in range(1037)}
    logs = {f"case{index:03}.json":continuation._document(b"{}") for index in range(351)}
    monkeypatch.setattr(continuation,"BASELINE_DOCUMENTS",{name:row["sha256"] for name,row in documents.items()})
    monkeypatch.setattr(continuation,"BASELINE_CAPTURES_SHA256",continuation.sha256(continuation.canonical(refs)))
    monkeypatch.setattr(continuation,"BASELINE_LOGS_SHA256",continuation.sha256(continuation.canonical(
        {name:{"sha256":row["sha256"],"size":row["size"]} for name,row in logs.items()})))
    return documents,refs,logs


@pytest.mark.parametrize("mutation",["failure-to-pass","image","prepare-returncode","raw-index","case-log"])
def test_continuation_rejects_rehashed_substitution_of_pinned_baseline(baseline_envelope,mutation):
    documents,refs,logs = baseline_envelope
    failed,_ = continuation._baseline(documents,refs,logs)
    assert failed["decision"] == "FAIL"
    if mutation in {"failure-to-pass","image","prepare-returncode"}:
        name = {"failure-to-pass":"dss-validation.json","image":"dss-bindings.json","prepare-returncode":"prepare.command.json"}[mutation]
        value = json.loads(continuation._document_bytes(documents[name]))
        if mutation == "failure-to-pass":value["decision"]="PASS"
        elif mutation == "image":value["image_ids"]["backend"]="sha256:"+"f"*64
        else:value["commands"][0]["returncode"]=1
        documents[name]=continuation._document(continuation.canonical(value))
    elif mutation == "raw-index":refs[next(iter(refs))]["size"]=2
    else:logs[next(iter(logs))]=continuation._document(b'{"changed":true}')
    with pytest.raises(ValueError):continuation._baseline(documents,refs,logs)


@pytest.mark.parametrize("mutation",[None,"late-capture","late-log","late-failure"])
def test_continuation_copy_is_exact_public_only_and_rechecks_late_changes(tmp_path,mutation):
    archive,out = tmp_path/"old",tmp_path/"new"
    for root in (archive,out):
        (root/"dss-validation-captures").mkdir(parents=True)
        (root/"dss-validation-cases").mkdir()
    raw = b'{"retained":"actual bytes"}'
    digest = continuation.sha256(raw)
    refs = {digest:{"path":digest+".json","size":len(raw)}}
    capture = archive/"dss-validation-captures"/(digest+".json")
    capture.write_bytes(raw)
    log = archive/"dss-validation-cases/menu-000.json"
    log.write_bytes(b'{"identity":"menu:000"}')
    failed = archive/"dss-validation.json"
    failed.write_bytes(b'{"decision":"FAIL"}')
    docs = {failed.name:continuation._document(failed.read_bytes())}
    logs = {log.name:continuation._document(log.read_bytes())}
    (archive/"runtime.env").write_bytes(b"SECRET=never-copy")
    (archive/"dss-gate.token").write_bytes(b"never-copy")
    if mutation == "late-capture":capture.write_bytes(raw.replace(b"actual",b"forged"))
    elif mutation == "late-log":log.write_bytes(b'{"identity":"menu:001"}')
    elif mutation == "late-failure":failed.write_bytes(b'{"decision":"PASS"}')
    if mutation:
        with pytest.raises(ValueError):continuation._copy_public_prefix(archive,out/"dss-validation-captures",out/"dss-validation-cases",docs,refs,logs)
    else:
        continuation._copy_public_prefix(archive,out/"dss-validation-captures",out/"dss-validation-cases",docs,refs,logs)
        assert (out/"dss-validation-captures"/(digest+".json")).read_bytes()==raw
        assert (out/"dss-validation-cases/menu-000.json").read_bytes()==log.read_bytes()
    assert not (out/"runtime.env").exists() and not (out/"dss-gate.token").exists()
    assert not (out/"dss-validation.json").exists()


def test_continuation_evidence_source_cannot_relabel_or_replace_carried_capture():
    proof = {"carried_evidence":{"menu:000":"a"*64}}
    current = "b"*40
    assert continuation.expected_evidence_source(proof,"menu:000","a"*64,current)==continuation.BASELINE_SOURCE
    assert continuation.expected_evidence_source(proof,"prompt-warning-default","c"*64,current)==current
    assert continuation.expected_evidence_source(None,"menu:000","a"*64,current)==current
    with pytest.raises(ValueError):continuation.expected_evidence_source(proof,"menu:000","d"*64,current)


def test_continuation_retained_index_stays_fixed_after_actual_new_capture_storage(source_repo, tmp_path, monkeypatch):
    """Index ownership after envelope/oracle checks; no full delivery PASS is fabricated."""
    from scripts.qualify_dss_v19 import DeliveryQualifier
    root, _ = source_repo
    (root / "scripts/qualify_dss_v19.py").write_text("reviewed qualification fix\n", encoding="utf-8")
    source = _commit(root)
    images = {name: "sha256:" + str(index) * 64
              for index, name in enumerate(sorted(continuation.IMAGE_NAMES), 1)}
    archive, out = tmp_path / "retained-unit-prefix", tmp_path / "new-unit-output"
    for directory in (archive, out):
        (directory / "dss-validation-captures").mkdir(parents=True)
        (directory / "dss-validation-cases").mkdir()
    original = continuation.canonical({"scope": "UNIT_PREFIX_ONLY"})
    digest = continuation.sha256(original)
    (archive / "dss-validation-captures" / (digest + ".json")).write_bytes(original)
    for name in continuation.BASELINE_DOCUMENTS:
        (archive / name).write_bytes(b'{"scope":"UNIT_ENVELOPE_ONLY"}')
    retained = {"unit:retained": {"id": "unit:retained", "evidence": {"raw_capture_sha256": digest}}}
    monkeypatch.setattr(continuation, "_baseline", lambda *args: ({"decision": "FAIL"}, {"image_ids": images}))
    monkeypatch.setattr(continuation, "_reconstruct", lambda *args: (retained, []))
    qualifier = DeliveryQualifier.__new__(DeliveryQualifier)
    qualifier.bindings = {"source_commit": source, "image_ids": images}
    qualifier.output = out / "dss-validation.json"
    qualifier.capture_root, qualifier.logs = out / "dss-validation-captures", out / "dss-validation-cases"
    qualifier.results, qualifier.scenarios, qualifier.captures, qualifier.manifest = {}, [], {}, {}
    proof = continuation.restore_prefix(qualifier, archive, root=root)
    checkpoint = json.loads((out / "dss-continuation-checkpoint.json").read_bytes())
    initial_index = deepcopy(proof["baseline_capture_references"])

    new = {"execution": {"id": "unit-new-execution"},
           "dss": {"scenario_id": "unit-new-scenario", "epoch": "unit-new-epoch"}}
    evidence = qualifier.evidence(new)
    new_digest = evidence["raw_capture_sha256"]
    assert (qualifier.capture_root / (new_digest + ".json")).read_bytes() == continuation.canonical(new)
    serialized = json.loads(continuation.canonical({"continuation": proof, "raw_captures": qualifier.captures}))
    assert new_digest in serialized["raw_captures"] and new_digest not in initial_index
    assert serialized["continuation"]["baseline_capture_references"] == initial_index
    assert serialized["continuation"] == checkpoint
    qualifier.captures[digest]["size"] += 1
    assert proof["baseline_capture_references"] == initial_index
    assert continuation.expected_evidence_source(proof, "unit:retained", digest, source) == continuation.BASELINE_SOURCE
    assert continuation.expected_evidence_source(proof, "unit:new", new_digest, source) == source


@pytest.mark.parametrize("gate", ["candidate", "sqlite", "frontend", "assemble"])
def test_continuation_canonical_cli_rejects_resume_for_other_gates(monkeypatch, gate):
    import sys
    from scripts import qualify_next
    calls = []
    monkeypatch.setattr(qualify_next, "Producer", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(sys, "argv", ["qualify_next", gate, "--resume-from", "retained-failure"])
    with pytest.raises(SystemExit) as error:
        qualify_next.main()
    assert error.value.code == 2 and not calls


def test_continuation_canonical_gate_mounts_archive_read_only_and_records_execution(tmp_path, monkeypatch):
    from scripts import qualify_next
    archive, out = tmp_path / "original-failure", tmp_path / "new-output"
    archive.mkdir()
    out.mkdir()
    original = b'{"decision":"FAIL"}\n'
    (archive / "dss-validation.json").write_bytes(original)
    monkeypatch.setattr(qualify_next, "OUT", out)
    monkeypatch.setattr(qualify_next, "LINUX_SOURCE", {"volume": "unit-qualified-source"})
    producer = qualify_next.Producer.__new__(qualify_next.Producer)
    producer.gate, producer.source, producer.resume_from = "dss-validation", "a" * 40, archive
    commands = []
    def run(command, **kwargs):
        commands.append((command, kwargs))
        if command[:3] == ["docker", "image", "inspect"]:
            index = sorted(qualify_next.IMAGES.values()).index(command[-1]) + 1
            return ("sha256:" + str(index) * 64).encode()
        return b"unit.private.token"
    producer.run = run
    finished = []
    producer.finish = lambda: finished.append(True)
    producer.execute()
    execution = commands[-1][0]
    assert ["--resume-from", "/retained-dss"] == execution[-2:]
    assert f"{archive.as_posix()}:/retained-dss:ro" in execution
    assert "unit-qualified-source:/workspace:ro" in execution
    assert f"{(qualify_next.ROOT / '.git').as_posix()}:/workspace/.git:ro" in execution
    assert finished == [True] and commands[-2][1]["private"] is True
    assert not (out / "dss-gate.token").exists()
    assert (archive / "dss-validation.json").read_bytes() == original


@pytest.mark.parametrize("failure",[None,"restore","remaining"])
def test_continuation_cli_restores_before_execution_and_never_heals_failure(tmp_path,monkeypatch,failure):
    """CLI ordering only; the fake runner emits no acceptance report."""
    import sys
    from scripts import qualify_dss_v19 as producer
    output=tmp_path/"new/dss-validation.json"
    old=tmp_path/"original-failure"
    old.mkdir()
    original=b'{"decision":"FAIL"}\n'
    (old/"dss-validation.json").write_bytes(original)
    bindings=tmp_path/"bindings.json"
    bindings.write_text(json.dumps({"source_commit":"b"*40,"image_ids":{}}),encoding="utf-8")
    calls=[]
    class Qualifier:
        def __init__(self,backend,dss,bindings,path):
            calls.append("construct")
            self.output,self.results,self.current_identity=path,{},"initialization"
        def run(self):
            calls.append("run")
            assert self.results=={"retained-unit-identity":{}}
            self.current_identity=continuation.FAILED_IDENTITY
            if failure=="remaining":raise ValueError("new scenario failed")
    def restore(q,path):
        calls.append("restore")
        assert path==old and not q.results and not output.exists()
        if failure=="restore":raise ValueError("old evidence failed validation")
        q.results={"retained-unit-identity":{}}
    monkeypatch.setattr(producer,"DeliveryQualifier",Qualifier)
    monkeypatch.setattr(producer,"load_manifest",lambda _:None)
    monkeypatch.setattr(continuation,"restore_prefix",restore)
    monkeypatch.setenv("SPELL_DSS_GATE_TOKEN","unit-token-not-used")
    monkeypatch.setattr(sys,"argv",["qualify_dss_v19","--bindings",str(bindings),"--output",str(output),"--resume-from",str(old)])
    if failure:
        with pytest.raises(ValueError):producer.main()
        assert json.loads(output.read_bytes())["decision"]=="FAIL"
    else:
        assert producer.main()==0
        assert not output.exists()
    assert calls==(["construct","restore"] if failure=="restore" else ["construct","restore","run"])
    assert (old/"dss-validation.json").read_bytes()==original


@pytest.mark.parametrize("validated",[False,True])
def test_continuation_producer_requires_validated_prefix_then_starts_failed_scenario(monkeypatch,validated):
    """Stop at first execution; no mocked 954-case PASS report is manufactured."""
    from scripts import qualify_dss_v19 as producer
    from scripts import validate_dss_delivery as validator
    scenarios=producer.scenario_definitions()
    qualifier=producer.DeliveryQualifier.__new__(producer.DeliveryQualifier)
    qualifier.manifest={"scenarios":scenarios}
    qualifier.scenarios=[{"id":row["id"]} for row in scenarios[:8]]
    qualifier.results={"menu:343":{"evidence":{"raw_capture_sha256":"a"*64}}}
    qualifier.continuation={"completed_identities":["menu:343"],
        "completed_scenarios":[row["id"] for row in qualifier.scenarios]}
    if validated:qualifier._continuation_validated=True
    qualifier.dss=SimpleNamespace(call=lambda _: {"transport":{"automatic_interval_ns":1,"physics_ticks_per_frame":1}})
    monkeypatch.setattr(validator,"reproduction_metadata",lambda _: {"runtime_configuration":{"automatic_interval_ns":1,"physics_ticks_per_frame":1}})
    calls=[]
    def execute(identity,procedure,actions,inputs,**kwargs):
        calls.append(identity)
        assert not kwargs and identity=="prompt-warning-default" and procedure=="prompt_workflow_v17"
        assert actions==scenarios[8]["operator_actions"] and inputs==scenarios[8]["inputs"]
        raise LookupError("stop at first new execution")
    qualifier.run_procedure=execute
    with pytest.raises(LookupError if validated else ValueError):qualifier.run()
    assert calls==(["prompt-warning-default"] if validated else [])
