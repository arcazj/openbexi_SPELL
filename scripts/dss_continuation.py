"""Revalidate the exact retained DSS prefix before resuming its failed scenario.

This is qualification evidence reuse, not worker recovery. No command, prompt,
or simulator operation is issued here, and the original report remains FAIL.
"""
from __future__ import annotations

import json
import ast
from pathlib import Path
import re
import subprocess

from scripts.validate_dss_delivery import (
    ROOT, CaptureStore, canonical, load_manifest, observed_procedure, require,
    sha256, _validate_evidence, validate_execution_spec,
)

BASELINE_SOURCE = "3e7d991123034bf6c83408f100bbdb00d7cc78ae"
REVIEWED_GATE_CORRECTIONS = {
    'backend/tests/test_driver_isolation.py': '35c0239459aba455a1ab1fe05293cf4931341a9511135429558e155d63dd3e47',
    'backend/tests/test_observation_websocket_batching_v19.py': 'b66fddeb938c3be4e19d2dc306c97e46f209a66e3985e2a447e4d7c92886651b',
    'backend/tests/test_reference_runner_v10.py': 'c7e578a0c47f702f723a647f3eed537b7a0755aff7dc8ce711523c2a661a69d7',
    'backend/tests/test_shadow_pilot_v15.py': '5f16a0de1bb4124fa1e51fad167bc1f87fe7a99569ac3e308f00aa56e060eb79',
    'backend/tests/test_synthetic_control_v13.py': '5b515513cfd433b40ea63c47b46b480b240647c9f2bf7537aafc5f630b46a8e9',
    'backend/tests/test_v11_operator_integration.py': '21f3e871c2bcba205cd6664dc2db5999f759ae2ae641031218fc5f7b805940a9',
    'scripts/qualify_reference_examples_v10.py': 'cee6d1b6426a613859f96ef7625d76ac1d1a4a032e49b034470ade531e899b94',
}
REVIEWED_UI_SOURCE = "c18614444e918160e8c80fa9cde236db5793da91"
REVIEWED_UI_FILES = frozenset({
    "frontend/src/components/DataDock.tsx", "frontend/src/development/main.tsx",
    "frontend/src/development/styles.css", "frontend/src/dss/dss.css",
    "frontend/src/dss/main.tsx", "frontend/src/main.tsx",
    "frontend/src/manualWorkspace.css", "frontend/src/metallicTheme.css",
    "frontend/src/styles.css",
})
FAILED_IDENTITY = "scenario:prompt-warning-default"
SCHEMA = "spell.dss.qualification-continuation/1"
QUALIFICATION_ONLY = frozenset({
    "scripts/qualify_dss_v19.py", "scripts/validate_dss_delivery.py",
    "scripts/dss_prompt_validation.py", "scripts/dss_continuation.py",
    "scripts/qualify_next.py", "scripts/tests/test_dss_delivery.py",
    "scripts/tests/test_dss_continuation.py", "contracts/v19/release_policy.json",
    "contracts/dss/README.md", "scripts/freeze_next_catalog.py",
    *REVIEWED_GATE_CORRECTIONS,
})
BASELINE_DOCUMENTS = {
    "dss-validation.json": "11f649e8abca49f86ae7e48caa6e7cbacb55ccb916c6905c97cc127bfa653fd6",
    "dss-bindings.json": "da08300320f56316ee974b34ad8faa680f0cf306dd93b40445fd9e946e3ff1b1",
    "prepare.command.json": "1c1ae14f436f0767ea8718c6e92eb63ef007e4f8f21f75bb14679fa6f8b2ea81",
}
BASELINE_CAPTURES_SHA256 = "70fe92b95633657531257b0fad2dc9912ec88bd537949cc69f5cbddfc451365a"
BASELINE_LOGS_SHA256 = "ef796fc77f3db19f84cea08975b46aa70396fb57e493333c001c652d6d38ee87"
IMAGE_NAMES = {"backend", "driver", "dss", "kafka", "frontend", "proxy"}


def _git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=30)
    require(result.returncode == 0, "continuation Git source proof failed")
    return result.stdout


def _tree(root, commit):
    require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit), "invalid continuation commit")
    rows = {}
    for record in _git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        path = name.decode("utf-8")
        if path.startswith("artifacts/"):
            continue
        mode, kind, digest = header.decode("ascii").split()
        require(kind == "blob" and mode in {"100644", "100755"}, "unsafe continuation source entry")
        rows[path] = (mode, digest)
    require(rows, "empty continuation source tree")
    return rows


def verify_source_compatibility(source_commit, *, root=ROOT):
    """Pin runtime bytes, the reviewed UI and exact gate-correction files."""
    require(source_commit != BASELINE_SOURCE, "continuation requires the reviewed qualification fix")
    _git(root, "merge-base", "--is-ancestor", BASELINE_SOURCE, source_commit)
    old, new = _tree(root, BASELINE_SOURCE), _tree(root, source_commit)
    changed = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
    presentation = set(changed) - QUALIFICATION_ONLY
    if presentation:
        require(presentation == REVIEWED_UI_FILES, "continuation changes unreviewed presentation source")
        _git(root, "merge-base", "--is-ancestor", BASELINE_SOURCE, REVIEWED_UI_SOURCE)
        _git(root, "merge-base", "--is-ancestor", REVIEWED_UI_SOURCE, source_commit)
        reviewed = _tree(root, REVIEWED_UI_SOURCE)
        approved = {name for name in old.keys() | reviewed.keys() if old.get(name) != reviewed.get(name)}
        require(approved == REVIEWED_UI_FILES and all(new.get(name) == reviewed.get(name) for name in approved),
                "continuation presentation differs from the reviewed UI commit")
    require(changed and set(changed) <= QUALIFICATION_ONLY | REVIEWED_UI_FILES,
            "continuation changes runtime or unreviewed source: " + ", ".join(changed[:20]))
    require(all(name in new for name in old), "continuation deletes tracked source")
    for name, approved_sha256 in REVIEWED_GATE_CORRECTIONS.items():
        if name in changed:
            # These exact gate corrections do not change the pinned runtime.
            require(name in old and name in new and old[name][0] == new[name][0]
                    and sha256(_git(root, "show", source_commit + ":" + name)) == approved_sha256,
                    "continuation gate correction differs from reviewed bytes or mode: " + name)
    if "contracts/v19/release_policy.json" in changed:
        _validate_policy_change(json.loads(_git(root, "show", BASELINE_SOURCE + ":contracts/v19/release_policy.json")),
            json.loads(_git(root, "show", source_commit + ":contracts/v19/release_policy.json")))
    if "scripts/freeze_next_catalog.py" in changed:
        _validate_freezer_change(_git(root, "show", BASELINE_SOURCE + ":scripts/freeze_next_catalog.py"),
            _git(root, "show", source_commit + ":scripts/freeze_next_catalog.py"))
    return changed


def _validate_policy_change(old, new):
    dynamic = {"gates", "candidate_files", "candidate_identities"}
    require(set(old) == set(new) and canonical({key:value for key,value in old.items() if key not in dynamic})
            == canonical({key:value for key,value in new.items() if key not in dynamic}),
            "continuation changed policy authority or source oracles")
    require(set(old["gates"]) == set(new["gates"]), "continuation changed the mandatory gate set")
    allowed = ("scripts.tests.test_dss_delivery::", "scripts.tests.test_dss_continuation::")
    def identities(before, after):
        require(type(after) is list and after == sorted(set(after)) and set(before) <= set(after)
                and all(value.startswith(allowed) for value in set(after)-set(before)),
                "continuation removed or changed unrelated test identities")
    for name, before in old["gates"].items():
        after = new["gates"][name]
        require(set(after) == {"tests", "identities", "skipped"}
                and type(after["tests"]) is int and after["tests"] == len(after["identities"])
                and after["skipped"] == before["skipped"], "continuation changed test counts or skip resolution")
        identities(before["identities"], after["identities"])
    identities(old["candidate_identities"], new["candidate_identities"])
    files = new["candidate_files"]
    require(type(files) is list and len(files) == len(set(files)) and set(old["candidate_files"]) <= set(files)
            and set(files)-set(old["candidate_files"]) <= {"scripts/tests/test_dss_continuation.py"},
            "continuation changed unrelated candidate test files")


def _validate_freezer_change(old, new):
    before, after = ast.parse(old), ast.parse(new)
    prefix = "scripts.tests.test_dss_continuation::"
    removed = []
    class RemovePrefix(ast.NodeTransformer):
        def visit_Tuple(self, node):
            self.generic_visit(node)
            matches = [item for item in node.elts if isinstance(item, ast.Constant) and item.value == prefix]
            removed.extend(matches)
            node.elts = [item for item in node.elts if item not in matches]
            return node
    after = RemovePrefix().visit(after)
    require(len(removed) == 1 and ast.dump(before) == ast.dump(after),
            "continuation freezer change exceeds the single tooling prefix")


def _images(value):
    require(type(value) is dict and set(value) == IMAGE_NAMES
            and all(type(item) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in value.values())
            and len(set(value.values())) == 6, "continuation requires six exact distinct images")
    return value


def _read(path, *, limit=1_000_000):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
            "continuation public evidence missing, unsafe or oversized")
    data = path.read_bytes()
    require(0 < len(data) <= limit, "continuation evidence changed size")
    return data


def _document(data):
    return {"sha256": sha256(data), "size": len(data), "utf8": data.decode("utf-8")}


def _document_bytes(value):
    require(type(value) is dict and set(value) == {"sha256", "size", "utf8"}
            and type(value["utf8"]) is str and type(value["size"]) is int,
            "continuation document fields differ")
    data = value["utf8"].encode("utf-8")
    require(0 < len(data) == value["size"] <= 1_000_000 and sha256(data) == value["sha256"],
            "continuation document bytes differ")
    return data


def _baseline(documents, references, logs):
    require(type(documents) is dict and set(documents) == set(BASELINE_DOCUMENTS),
            "continuation baseline documents differ")
    decoded = {}
    for name, expected_hash in BASELINE_DOCUMENTS.items():
        data = _document_bytes(documents[name])
        require(sha256(data) == expected_hash, "continuation substitutes the original failed attempt")
        decoded[name] = json.loads(data)
    failed, bindings, prepare = (decoded[name] for name in BASELINE_DOCUMENTS)
    require(failed["decision"] == "FAIL" and failed["failed_identity"] == FAILED_IDENTITY
            and failed["error"] == "prompt-warning-default: automatic default lacks an actual settlement event",
            "continuation baseline is not the reviewed failure")
    require(set(bindings) == {"source_commit", "image_ids"} and bindings["source_commit"] == BASELINE_SOURCE,
            "continuation baseline source differs")
    _images(bindings["image_ids"])
    commands = prepare["commands"]
    require(prepare["source_commit"] == BASELINE_SOURCE and type(commands) is list and len(commands) == 27
            and all(type(row["returncode"]) is int and row["returncode"] == 0
                    and row["source_commit"] == BASELINE_SOURCE and row["gate"] == "prepare" for row in commands),
            "continuation baseline preparation did not succeed")
    require(type(references) is dict and len(references) == 1037
            and sha256(canonical(references)) == BASELINE_CAPTURES_SHA256,
            "continuation baseline raw capture index differs")
    require(type(logs) is dict and len(logs) == 351, "continuation case log inventory differs")
    index = {name: {"sha256": row["sha256"], "size": row["size"]} for name, row in logs.items()}
    require(sha256(canonical(index)) == BASELINE_LOGS_SHA256, "continuation case log bytes differ")
    for name, row in logs.items():
        require(re.fullmatch(r"[a-z0-9-]+\.json", name), "unsafe continuation case log path")
        _document_bytes(row)
    return failed, bindings


def _descriptor(capture, capture_hash):
    if "subject_result" in capture:
        physical = capture["subject_result"]["dss_evidence"]
        mode = "SUPERVISOR_DSS_BROKER"
    elif "broker_result" in capture:
        require(capture["subject_results"], "empty retained runner")
        physical = capture["subject_results"][0]["dss_evidence"]
        mode = "SUPERVISOR_DSS_BROKER"
    else:
        physical, mode = capture["dss"], "PUBLIC_API_DSS"
    return {"mode": mode, "execution_id": capture["execution"]["id"],
        "scenario_id": physical["scenario_id"], "epoch": physical["epoch"],
        "source_commit": BASELINE_SOURCE, "raw_capture_sha256": capture_hash,
        "transport_obligations": [], "transport_results": []}


def _row(definition, observed, evidence):
    return {"id": definition["id"], "definition_sha256": definition["definition_sha256"],
        "status": "PASS", "observed": observed, "evidence": evidence}


def _reconstruct(captures, logs, manifest, failed):
    """Stream real sidecars; observations always come from their executed results."""
    definitions = {row["id"]: row for row in manifest["inventory"]}
    prefix = manifest["scenarios"][:8]
    require(len(manifest["scenarios"]) == 30 and manifest["scenarios"][8]["id"] == FAILED_IDENTITY.split(":", 1)[1]
            and prefix[0]["id"] == "catalog-reference-all", "continuation scenario boundary changed")
    outer = {}
    for capture_hash in captures:
        raw = captures[capture_hash]  # Every raw file is reread/hash/canonical checked.
        if "subject_result" not in raw:
            execution_id = raw["execution"]["id"]
            require(execution_id not in outer, "duplicate retained outer execution")
            outer[execution_id] = capture_hash
        del raw
    require(len(outer) == 351, "continuation retained outer execution count differs")
    results, scenarios, used = {}, [], set()
    menu_ids = [f"menu:{index:03}" for index in range(344)]
    expected_logs = {identity.replace(":", "-") + ".json" for identity in menu_ids}
    expected_logs |= {row["id"] + ".json" for row in prefix[1:]}
    require(set(logs) == expected_logs, "continuation case logs do not prove the exact prefix")

    def get_outer(log_name, identity):
        log = json.loads(_document_bytes(logs[log_name]))
        require(set(log) == {"identity", "execution_id", "terminal", "subjects"} and log["identity"] == identity,
                "continuation case log identity differs")
        require(log["execution_id"] in outer, "continuation case log has no retained execution")
        capture_hash = outer[log["execution_id"]]
        require(capture_hash not in used, "continuation reuses an outer execution")
        used.add(capture_hash)
        capture = captures[capture_hash]
        require(log["terminal"] == capture["execution"]["state"]
                and log["subjects"] == [row["subject"] for row in capture.get("subject_results", [])],
                "continuation case log differs from raw execution")
        return capture, _descriptor(capture, capture_hash)

    all_evidence = None
    for identity in menu_ids:
        definition = definitions[identity]
        capture, evidence = get_outer(identity.replace(":", "-") + ".json", identity)
        require(capture.get("broker_request", {}).get("selection") == definition["selection"]
                and set(capture.get("subject_capture_refs", {})) == set(definition["targets"]),
                "retained menu source selection differs")
        _validate_evidence(evidence, identity, captures, BASELINE_SOURCE)
        validate_execution_spec(capture, definition["execution_spec"], capture["initial_dss_state"])
        results[identity] = _row(definition, {"selection": capture["broker_request"]["selection"],
            "targets": definition["targets"]}, evidence)
        if identity == "menu:343":
            all_evidence = evidence
        else:
            for name, child_hash in capture["subject_capture_refs"].items():
                child = captures[child_hash]
                subject = child["subject_result"]
                require(subject["subject"] == name and canonical(subject["semantic"]) == canonical(definitions[name]["oracle"]),
                        "retained child outcome differs from independent source oracle")
                child_evidence = _descriptor(child, child_hash)
                require(child_evidence["execution_id"] == evidence["execution_id"], "retained child is detached from its menu")
                results[name] = _row(definitions[name], subject["semantic"], child_evidence)
                for variant in definitions.values():
                    if variant.get("parent") == name:
                        proofs = [row for row in subject["semantic"]["variant_proofs"] if "variant:" + row["variant_id"] == variant["id"]]
                        require(len(proofs) == 1 and canonical(proofs[0]) == canonical(variant["oracle"]),
                                "retained variant lacks its exact actual proof")
                        results[variant["id"]] = _row(variant, proofs[0], child_evidence)
                del child, subject
        del capture
    for definition in prefix:
        if definition["id"] == "catalog-reference-all":
            evidence = all_evidence
            capture = captures[evidence["raw_capture_sha256"]]
        else:
            capture, evidence = get_outer(definition["id"] + ".json", definition["id"])
            _validate_evidence(evidence, definition["id"], captures, BASELINE_SOURCE)
        observed = observed_procedure(capture, definition)
        require(canonical(observed) == canonical(definition["expected"]), "retained scenario differs from its source oracle")
        scenarios.append(_row(definition, observed, evidence))
        if definition["subject"] not in results:
            results[definition["subject"]] = _row(definitions[definition["subject"]],
                {"scenario_id": definition["id"], "procedure_sha256": capture["execution"]["procedure_hash"]}, evidence)
        del capture
    require(len(results) == 947 and sorted(results) == failed["completed_identities"]
            and used == set(outer.values()), "continuation completed identity set differs from original failure")
    referenced = {row["evidence"]["raw_capture_sha256"] for row in list(results.values()) + scenarios}
    for capture_hash in outer.values():
        referenced.update(captures[capture_hash].get("subject_capture_refs", {}).values())
    require(referenced == set(captures), "continuation has orphan or missing raw captures")
    return results, scenarios


def _evidence_map(results, scenarios):
    return {row["id"]: row["evidence"]["raw_capture_sha256"] for row in list(results.values()) + scenarios}


def _copy_public_prefix(archive, capture_root, logs_root, documents, refs, logs):
    for capture_hash, reference in refs.items():
        data = _read(archive / "dss-validation-captures" / reference["path"], limit=16_000_000)
        require(len(data) == reference["size"] and sha256(data) == capture_hash, "retained capture changed during copy")
        (capture_root / reference["path"]).write_bytes(data)
    for name, value in logs.items():
        data = _document_bytes(value)
        require(_read(archive / "dss-validation-cases" / name) == data, "retained case log changed during copy")
        (logs_root / name).write_bytes(data)
    for name, value in documents.items():
        require(_read(archive / name) == _document_bytes(value), "retained baseline document changed during copy")


def restore_prefix(qualifier, archive: Path, *, root=ROOT):
    """Populate only an empty new qualifier after independently proving old work."""
    source = qualifier.bindings["source_commit"]
    require(_git(root, "rev-parse", "HEAD").decode().strip() == source, "continuation producer HEAD differs")
    changed = verify_source_compatibility(source, root=root)
    _images(qualifier.bindings["image_ids"])
    require(not qualifier.results and not qualifier.scenarios and not qualifier.captures
            and not any(qualifier.capture_root.iterdir()) and not any(qualifier.logs.iterdir())
            and not qualifier.output.exists(), "continuation destination must be fresh and empty")
    archive = Path(archive)
    require(archive.resolve() != qualifier.output.parent.resolve(), "continuation cannot overwrite its failed attempt")
    documents = {name: _document(_read(archive / name)) for name in BASELINE_DOCUMENTS}
    refs = {path.stem: {"path": path.name, "size": path.stat().st_size}
            for path in (archive / "dss-validation-captures").iterdir()}
    logs = {path.name: _document(_read(path)) for path in (archive / "dss-validation-cases").iterdir()}
    failed, old_bindings = _baseline(documents, refs, logs)
    captures = CaptureStore(archive / "dss-validation-captures", refs)
    results, scenarios = _reconstruct(captures, logs, qualifier.manifest, failed)
    proof = {"schema_version": SCHEMA, "baseline_source": BASELINE_SOURCE, "source_commit": source,
        "baseline_images": old_bindings["image_ids"], "image_ids": qualifier.bindings["image_ids"],
        "source_changes": changed,
        "reviewed_ui_source": REVIEWED_UI_SOURCE if set(changed) & REVIEWED_UI_FILES else None,
        "failed_identity": FAILED_IDENTITY,
        "baseline_documents": documents, "baseline_capture_references": refs,
        "baseline_capture_hashes": sorted(refs), "baseline_case_logs": logs,
        "completed_identities": sorted(results), "completed_scenarios": [row["id"] for row in scenarios],
        "carried_evidence": _evidence_map(results, scenarios),
        "results_sha256": sha256(canonical([results[key] for key in sorted(results)])),
        "scenarios_sha256": sha256(canonical(scenarios))}
    # Copy only named public records; env files, credentials, failures and gate
    # command receipts are never installed as successful current-attempt output.
    _copy_public_prefix(archive, qualifier.capture_root, qualifier.logs, documents, refs, logs)
    # New executions extend the live index. Keep the pinned baseline snapshot
    # independent, including its nested path/size records.
    qualifier.results, qualifier.scenarios, qualifier.captures = results, scenarios, {
        digest: dict(reference) for digest, reference in refs.items()
    }
    qualifier.continuation = proof
    qualifier.output.with_name("dss-continuation-checkpoint.json").write_bytes(canonical(proof) + b"\n")
    qualifier._continuation_validated = True
    return proof


def expected_evidence_source(continuation, identity, capture_hash, current_source):
    """Call only after validate_continuation; never relabel carried executions."""
    if continuation is not None and identity in continuation["carried_evidence"]:
        require(capture_hash == continuation["carried_evidence"][identity], "carried execution capture was replaced")
        return BASELINE_SOURCE
    return current_source


def validate_continuation(report, *, source_commit, image_ids, capture_root, root=ROOT):
    """Independently prove every carried identity; full delivery still runs later."""
    proof = report.get("continuation")
    require(type(proof) is dict and set(proof) == {
        "schema_version", "baseline_source", "source_commit", "baseline_images", "image_ids",
        "source_changes", "reviewed_ui_source", "failed_identity", "baseline_documents", "baseline_capture_references",
        "baseline_capture_hashes", "baseline_case_logs", "completed_identities", "completed_scenarios",
        "carried_evidence", "results_sha256", "scenarios_sha256"}, "continuation proof fields differ")
    require(proof["schema_version"] == SCHEMA and proof["baseline_source"] == BASELINE_SOURCE
            and proof["source_commit"] == source_commit and proof["failed_identity"] == FAILED_IDENTITY,
            "continuation source or resume boundary differs")
    changed = verify_source_compatibility(source_commit, root=root)
    require(proof["source_changes"] == changed
            and proof["reviewed_ui_source"] == (REVIEWED_UI_SOURCE if set(changed) & REVIEWED_UI_FILES else None),
            "continuation source scope differs")
    require(canonical(_images(proof["image_ids"])) == canonical(_images(image_ids)), "continuation current images differ")
    refs, logs = proof["baseline_capture_references"], proof["baseline_case_logs"]
    failed, bindings = _baseline(proof["baseline_documents"], refs, logs)
    require(canonical(proof["baseline_images"]) == canonical(bindings["image_ids"])
            and proof["baseline_capture_hashes"] == sorted(refs), "continuation baseline bindings differ")
    references = report["raw_captures"]
    require(all(references.get(key) == value for key, value in refs.items()), "continuation raw prefix was changed or omitted")
    complete = CaptureStore(capture_root, references)

    class Prefix:
        def __iter__(self): return iter(refs)
        def __getitem__(self, key):
            require(key in refs, "continuation borrowed a later capture")
            return complete[key]
        def get(self, key): return self[key] if key in refs else None

    results, scenarios = _reconstruct(Prefix(), logs, load_manifest(report["release"], root=root), failed)
    require(proof["completed_identities"] == sorted(results)
            and proof["completed_scenarios"] == [row["id"] for row in scenarios]
            and proof["carried_evidence"] == _evidence_map(results, scenarios)
            and proof["results_sha256"] == sha256(canonical([results[key] for key in sorted(results)]))
            and proof["scenarios_sha256"] == sha256(canonical(scenarios)), "continuation reconstructed prefix differs")
    actual = {row["id"]: row for row in report["results"]}
    require(all(canonical(actual.get(key)) == canonical(row) for key, row in results.items())
            and canonical(report["scenarios"][:8]) == canonical(scenarios), "continuation report relabels or replaces carried work")
    return proof
