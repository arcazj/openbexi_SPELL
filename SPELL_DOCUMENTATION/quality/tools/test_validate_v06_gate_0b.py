from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = Path(__file__).with_name("validate_v06_gate_0b.py")
SPEC = importlib.util.spec_from_file_location("validate_v06_gate_0b", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class GateV06ZeroBValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository_scope = gate.read_json(gate.SCOPE_PATH, "test Gate 0B scope")
        self.repository_state = gate.validate_scope(self.repository_scope)
        if self.repository_state == "PASS":
            candidate = self.repository_scope["immutable_inputs"]["candidate"]["commit"]
            relative = gate.SCOPE_PATH.relative_to(ROOT).as_posix()
            result = subprocess.run(
                ["git", "show", f"{candidate}:{relative}"],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            self.scope = gate.strict_json_bytes(result.stdout, "candidate Gate 0B scope")
        else:
            self.scope = copy.deepcopy(self.repository_scope)

    def assert_scope_error(self, scope: object, fragment: str) -> None:
        with self.assertRaisesRegex(gate.GateValidationError, fragment):
            gate.validate_scope(scope)

    def bound_scope(self) -> dict[str, object]:
        scope = copy.deepcopy(self.scope)
        candidate = "1" * 40
        scope["status"] = "PASS"
        scope["decision"]["authorization"] = (
            "V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY"
        )
        scope["immutable_inputs"]["candidate"] = {
            "binding_status": "BOUND",
            "commit": candidate,
            "parent": gate.GATE_0A_COMMIT,
            "tree": "2" * 40,
            "changed_paths": [
                {
                    "path": "backend/ir_v06.py",
                    "status": "A",
                    "blob": "3" * 40,
                    "sha256": "4" * 64,
                }
            ],
        }
        qualification = scope["qualification_contract"]
        qualification["status"] = "PASS"
        qualification["manifest_sha256"] = "5" * 64
        qualification["validator_success_shape"]["source_commit"] = candidate
        for package in scope["qualified_work_packages"]:
            package["status"] = "IMPLEMENTED_AND_QUALIFIED"
        scope["reviewed_surface_delta"]["review_status"] = "REVIEWED_AND_QUALIFIED"
        scope["release_closeout_authorization"]["status"] = "AUTHORIZED"
        for key in (
            "v0_6_work_packages_implemented",
            "v0_6_candidate_qualified",
            "release_closeout_authorized",
        ):
            scope["claims"][key] = True
        return scope

    def evidence_manifest(self) -> dict[str, object]:
        packages: dict[str, object] = {}
        for package, identities in gate.WORK_PACKAGE_TEST_IDS.items():
            packages[package] = {
                "test_ids": {
                    identity: {
                        "proofs": [
                            {
                                "suite": "backend_postgresql",
                                "node": f"backend/tests/test.py::{identity}",
                            }
                        ],
                        "passed_count": 1,
                        "skipped_count": 0,
                    }
                    for identity in identities
                }
            }
        return {
            "schema_version": gate.EVIDENCE_SCHEMA,
            "product_version": "0.6.0-candidate",
            "scope_profile": gate.SCOPE_PROFILE,
            "source": {"commit": "1" * 40},
            "suites": {suite: {} for suite in gate.SUITE_IDS},
            "work_packages": packages,
            "historical_platform_skips": {
                "mapped_test_ids_skipped": [],
                "accepted_failures": [],
            },
            "secret_scan": {"waivers": []},
            "overall_pass": True,
        }

    def test_pending_scope_is_exact_and_has_nine_packages_and_45_ids(self) -> None:
        self.assertEqual(gate.validate_scope(self.scope), "PENDING_CANDIDATE")
        self.assertEqual(len(self.scope["qualified_work_packages"]), 9)
        observed = [
            identity
            for package in self.scope["qualified_work_packages"]
            for identity in package["test_ids"]
        ]
        self.assertEqual(observed, list(gate.TEST_IDS))
        self.assertEqual(len(observed), 45)
        self.assertEqual(len(set(observed)), 45)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_values(self) -> None:
        with self.assertRaisesRegex(gate.GateValidationError, "duplicate JSON key"):
            gate.strict_json_bytes(b'{"status":"PASS","status":"FAIL"}')
        for value in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(value=value):
                with self.assertRaisesRegex(gate.GateValidationError, "non-finite"):
                    gate.strict_json_bytes(value)

    def test_scope_rejects_missing_extra_and_wrongly_typed_fields(self) -> None:
        for mutation, fragment in (
            (lambda value: value.pop("claims"), "scope keys differ"),
            (lambda value: value.__setitem__("unexpected", True), "scope keys differ"),
            (lambda value: value.__setitem__("status", True), "gate status is invalid"),
        ):
            with self.subTest(fragment=fragment):
                value = copy.deepcopy(self.scope)
                mutation(value)
                self.assert_scope_error(value, fragment)

    def test_owner_request_approval_tag_and_nonclaims_are_immutable(self) -> None:
        mutations = (
            ("decision", "owner_request", "finish something else"),
            ("decision", "gate_0a_owner_approval_reaffirmed", False),
            ("decision", "tag_resolution", "LIGHTWEIGHT_TAG"),
            ("claims", "operational_authorization", True),
            ("claims", "broad_language_or_compatibility_claimed", True),
        )
        for section, key, replacement in mutations:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                value[section][key] = replacement
                self.assert_scope_error(value, "differs")

    def test_gate_0a_and_contract_blob_bindings_are_exact(self) -> None:
        for section, key in (
            ("gate_0a", "commit"),
            ("gate_0a", "tree"),
            ("accepted_v0_5_0", "tag_object_id"),
        ):
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                value["immutable_inputs"][section][key] = "0" * 40
                self.assert_scope_error(value, "differs")
        value = copy.deepcopy(self.scope)
        first = next(iter(value["immutable_inputs"]["gate_0a"]["contracts"]))
        value["immutable_inputs"]["gate_0a"]["contracts"][first]["sha256"] = "0" * 64
        self.assert_scope_error(value, "contract bindings")

    def test_all_work_package_ids_suffixes_order_and_status_are_exact(self) -> None:
        mutations = []
        wrong_id = copy.deepcopy(self.scope)
        wrong_id["qualified_work_packages"][0]["work_package_id"] = "V06-OP-010"
        mutations.append(wrong_id)
        missing_test = copy.deepcopy(self.scope)
        missing_test["qualified_work_packages"][4]["test_ids"].pop()
        mutations.append(missing_test)
        duplicate_test = copy.deepcopy(self.scope)
        duplicate_test["qualified_work_packages"][8]["test_ids"][4] = (
            duplicate_test["qualified_work_packages"][8]["test_ids"][3]
        )
        mutations.append(duplicate_test)
        wrong_status = copy.deepcopy(self.scope)
        wrong_status["qualified_work_packages"][2]["status"] = "IMPLEMENTED"
        mutations.append(wrong_status)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(gate.GateValidationError):
                    gate.validate_scope(value)

    def test_pending_state_rejects_candidate_evidence_or_claim_smuggling(self) -> None:
        mutations = (
            ("candidate", "commit", "1" * 40),
            ("qualification", "manifest_sha256", "2" * 64),
            ("claims", "v0_6_candidate_qualified", True),
            ("closeout", "status", "AUTHORIZED"),
        )
        for section, key, replacement in mutations:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                if section == "candidate":
                    value["immutable_inputs"]["candidate"][key] = replacement
                elif section == "qualification":
                    value["qualification_contract"][key] = replacement
                elif section == "claims":
                    value["claims"][key] = replacement
                else:
                    value["release_closeout_authorization"][key] = replacement
                with self.assertRaises(gate.GateValidationError):
                    gate.validate_scope(value)

    def test_structurally_complete_bound_scope_is_the_only_pass_shape(self) -> None:
        value = self.bound_scope()
        self.assertEqual(gate.validate_scope(value), "PASS")
        self.assertEqual(
            gate.marker("PASS"),
            "gate=PASS work_packages=9 identities=45 failed=0 skipped=0 "
            "claimed_constructs=0 claimed_artifacts=0 "
            "release_closeout=AUTHORIZED",
        )

    def test_activation_builder_is_deterministic_and_does_not_mutate_pending_scope(self) -> None:
        original = copy.deepcopy(self.scope)
        changes = [
            {
                "path": "backend/ir_v06.py",
                "status": "A",
                "blob": "3" * 40,
                "sha256": "4" * 64,
            }
        ]
        first = gate.activate_scope_bindings(
            self.scope,
            candidate_commit="1" * 40,
            candidate_tree="2" * 40,
            changed_paths=changes,
            evidence_sha256="5" * 64,
        )
        second = gate.activate_scope_bindings(
            self.scope,
            candidate_commit="1" * 40,
            candidate_tree="2" * 40,
            changed_paths=changes,
            evidence_sha256="5" * 64,
        )
        self.assertEqual(self.scope, original)
        self.assertEqual(first, second)
        self.assertEqual(gate.canonical_scope_bytes(first), gate.canonical_scope_bytes(second))
        self.assertEqual(gate.validate_scope(first), "PASS")

    def test_activation_builder_rejects_unsorted_or_incomplete_git_bindings(self) -> None:
        unsorted = [
            {"path": "z.py", "status": "A", "blob": "3" * 40, "sha256": "4" * 64},
            {"path": "a.py", "status": "M", "blob": "5" * 40, "sha256": "6" * 64},
        ]
        with self.assertRaisesRegex(gate.GateValidationError, "not unique and sorted"):
            gate.activate_scope_bindings(
                self.scope,
                candidate_commit="1" * 40,
                candidate_tree="2" * 40,
                changed_paths=unsorted,
                evidence_sha256="7" * 64,
            )
        with self.assertRaisesRegex(gate.GateValidationError, "evidence hash"):
            gate.activate_scope_bindings(
                self.scope,
                candidate_commit="1" * 40,
                candidate_tree="2" * 40,
                changed_paths=unsorted[:1],
                evidence_sha256="pending",
            )

    def test_activation_documents_render_and_validate_bound_values(self) -> None:
        scope = self.bound_scope()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate_path = root / "SPELL_v0.6_Gate_0B.md"
            release_path = root / "SPELL_v0.6_Release.md"
            gate_path.write_bytes(gate.GATE_DOCUMENT_PATH.read_bytes())
            release_path.write_bytes(gate.RELEASE_DOCUMENT_PATH.read_bytes())
            gate_raw, release_raw = gate.render_activation_documents(
                gate_path, release_path, scope
            )
            gate_path.write_bytes(gate_raw)
            release_path.write_bytes(release_raw)
            gate.validate_gate_document(gate_path, "PASS", scope)
            gate.validate_release_document(release_path, scope)
            self.assertIn(scope["immutable_inputs"]["candidate"]["commit"].encode(), gate_raw)
            self.assertIn(scope["qualification_contract"]["manifest_sha256"].encode(), release_raw)
            normalized_release = release_raw.replace(b"\r\n", b"\n")
            self.assertIn(
                b"| Annotated tag object | `refs/tags/v0.6.0` | Pending |\n\n"
                + gate.RELEASE_EVIDENCE_MARKERS[1].encode(),
                normalized_release,
            )

    def test_atomic_activation_applies_exact_proposal_and_removes_lock(self) -> None:
        scope = self.bound_scope()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / gate.ACTIVATION_LOCK_RELATIVE.parent / "v0.6-gate-0b.json"
            scope_path.parent.mkdir(parents=True)
            gate_path = root / "SPELL_v0.6_Gate_0B.md"
            release_path = root / "SPELL_v0.6_Release.md"
            scope_path.write_bytes(gate.SCOPE_PATH.read_bytes())
            gate_path.write_bytes(gate.GATE_DOCUMENT_PATH.read_bytes())
            release_path.write_bytes(gate.RELEASE_DOCUMENT_PATH.read_bytes())
            proposal_path = root / "proposal.json"
            proposal_path.write_bytes(gate.canonical_scope_bytes(scope))
            committed = {
                scope_path.relative_to(root).as_posix(): scope_path.read_bytes(),
                gate_path.name: gate_path.read_bytes(),
                release_path.name: release_path.read_bytes(),
            }

            def git_blob(_root: Path, _commit: str, path: str) -> tuple[str, bytes]:
                return "a" * 40, committed[path]

            with (
                mock.patch.object(gate, "prepare_activation", return_value=scope),
                mock.patch.object(gate, "_git_blob", side_effect=git_blob),
                mock.patch.object(gate, "validate_repository", return_value=("PASS", scope)),
            ):
                result = gate.apply_activation(root, scope_path, proposal_path)

            self.assertEqual(result["activation"], "APPLIED")
            self.assertEqual(gate.read_json(scope_path, "applied scope"), scope)
            gate.validate_gate_document(gate_path, "PASS", scope)
            gate.validate_release_document(release_path, scope)
            self.assertFalse((root / gate.ACTIVATION_LOCK_RELATIVE).exists())

    def test_atomic_activation_rolls_back_every_target_on_validation_failure(self) -> None:
        scope = self.bound_scope()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_path = root / gate.ACTIVATION_LOCK_RELATIVE.parent / "v0.6-gate-0b.json"
            scope_path.parent.mkdir(parents=True)
            gate_path = root / "SPELL_v0.6_Gate_0B.md"
            release_path = root / "SPELL_v0.6_Release.md"
            scope_path.write_bytes(gate.SCOPE_PATH.read_bytes())
            gate_path.write_bytes(gate.GATE_DOCUMENT_PATH.read_bytes())
            release_path.write_bytes(gate.RELEASE_DOCUMENT_PATH.read_bytes())
            originals = {
                scope_path: scope_path.read_bytes(),
                gate_path: gate_path.read_bytes(),
                release_path: release_path.read_bytes(),
            }
            proposal_path = root / "proposal.json"
            proposal_path.write_bytes(gate.canonical_scope_bytes(scope))
            committed = {
                path.relative_to(root).as_posix(): raw for path, raw in originals.items()
            }

            def git_blob(_root: Path, _commit: str, path: str) -> tuple[str, bytes]:
                return "a" * 40, committed[path]

            with (
                mock.patch.object(gate, "prepare_activation", return_value=scope),
                mock.patch.object(gate, "_git_blob", side_effect=git_blob),
                mock.patch.object(
                    gate,
                    "validate_repository",
                    side_effect=gate.GateValidationError("forced validation failure"),
                ),
            ):
                with self.assertRaisesRegex(gate.GateValidationError, "forced validation"):
                    gate.apply_activation(root, scope_path, proposal_path)

            for path, raw in originals.items():
                self.assertEqual(path.read_bytes(), raw)
            self.assertFalse((root / gate.ACTIVATION_LOCK_RELATIVE).exists())

    def test_pass_shape_rejects_every_unfinished_activation_field(self) -> None:
        mutations = (
            lambda value: value["immutable_inputs"]["candidate"].__setitem__("binding_status", "PENDING_SOURCE_FREEZE"),
            lambda value: value["qualification_contract"].__setitem__("status", "PENDING_CANONICAL_EVIDENCE"),
            lambda value: value["qualification_contract"].__setitem__("manifest_sha256", None),
            lambda value: value["qualified_work_packages"][0].__setitem__("status", "PENDING_QUALIFICATION"),
            lambda value: value["reviewed_surface_delta"].__setitem__("review_status", "PENDING_CANDIDATE_BINDING_AND_QUALIFICATION"),
            lambda value: value["claims"].__setitem__("release_closeout_authorized", False),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                value = self.bound_scope()
                mutation(value)
                with self.assertRaises(gate.GateValidationError):
                    gate.validate_scope(value)

    def test_reviewed_ir_api_migration_dependency_and_compatibility_deltas_are_exact(self) -> None:
        mutations = (
            ("internal_ir", "new_internal_version", "0.7"),
            ("internal_ir", "v0_3_serialized_bytes_must_remain_unchanged", False),
            ("operator_api", "route_families", ["UNBOUNDED_API"] * 10),
            ("database_schema", "new_tables", list(gate.NEW_TABLES[:-1])),
            ("dependencies_and_driver", "new_runtime_dependencies", ["unknown"]),
            ("compatibility_ledger", "broad_compatibility_claimed", True),
        )
        for section, key, replacement in mutations:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                value["reviewed_surface_delta"][section][key] = replacement
                self.assert_scope_error(value, "differs")

    def test_candidate_name_status_parser_is_exact_and_rejects_renames(self) -> None:
        self.assertEqual(
            gate.parse_name_status_z(b"A\0backend/a.py\0M\0frontend/b.ts\0"),
            [("A", "backend/a.py"), ("M", "frontend/b.ts")],
        )
        for raw in (
            b"R100\0backend/old.py\0backend/new.py\0",
            b"M\0frontend/b.ts\0A\0backend/a.py\0",
            b"A\0backend/a.py\0A\0backend/a.py\0",
            b"D\0backend/a.py\0",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(gate.GateValidationError):
                    gate.parse_name_status_z(raw)

    def test_candidate_manifest_contract_requires_all_45_passing_unwaived_ids(self) -> None:
        manifest = self.evidence_manifest()
        gate._validate_manifest_contract(manifest, "1" * 40)
        mutations = []
        skipped = copy.deepcopy(manifest)
        skipped["work_packages"]["V06-OP-002"]["test_ids"]["V06-OP-002-RACE"]["skipped_count"] = 1
        mutations.append(skipped)
        waived = copy.deepcopy(manifest)
        waived["secret_scan"]["waivers"] = ["waiver"]
        mutations.append(waived)
        mapped_skip = copy.deepcopy(manifest)
        mapped_skip["historical_platform_skips"]["mapped_test_ids_skipped"] = ["V06-OP-009-SECURITY"]
        mutations.append(mapped_skip)
        missing = copy.deepcopy(manifest)
        missing["work_packages"]["V06-OP-008"]["test_ids"].pop("V06-OP-008-GRAPH")
        mutations.append(missing)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(gate.GateValidationError):
                    gate._validate_manifest_contract(value, "1" * 40)

    def test_migration_ast_has_exact_20_table_activation_tuple(self) -> None:
        raw = (
            ROOT / "backend/migrations/versions/v0004_operator_workspace.py"
        ).read_bytes()
        self.assertEqual(gate._migration_new_tables(raw), gate.NEW_TABLES)
        changed = raw.replace(
            b"    parent_child_links,\n)",
            b"    parent_child_links,\n    operator_contexts,\n)",
        )
        self.assertNotEqual(gate._migration_new_tables(changed), gate.NEW_TABLES)

    def test_current_operator_api_has_every_reviewed_route_and_strict_schema(self) -> None:
        app = (ROOT / "backend/app.py").read_text(encoding="utf-8")
        for marker in gate.API_ROUTE_MARKERS:
            self.assertIn(marker, app)
        schemas = (ROOT / "backend/schemas.py").read_text(encoding="utf-8")
        self.assertIn("class StrictRequest(BaseModel):", schemas)
        self.assertIn('extra="forbid"', schemas)

    def test_repository_state_verifies_tag_gate_and_document(self) -> None:
        state, scope = gate.validate_repository(gate.SCOPE_PATH, ROOT)
        self.assertEqual(state, self.repository_state)
        self.assertEqual(scope["status"], state)

    def test_command_emits_one_state_marker_and_distinct_exit(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0 if self.repository_state == "PASS" else 2)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout.decode("utf-8").splitlines(),
            [gate.marker(self.repository_state)],
        )

    def test_activation_cli_refuses_to_overwrite_the_canonical_pending_scope(self) -> None:
        before = gate.SCOPE_PATH.read_bytes()
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--prepare-activation",
                str(gate.SCOPE_PATH),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"must not replace the canonical scope", result.stderr)
        self.assertEqual(gate.SCOPE_PATH.read_bytes(), before)

    def test_scope_file_is_strict_json_and_canonical_ascii(self) -> None:
        raw = gate.SCOPE_PATH.read_bytes()
        parsed = gate.strict_json_bytes(raw, "scope")
        self.assertEqual(parsed, self.repository_scope)
        self.assertTrue(raw.endswith(b"\n"))
        raw.decode("ascii")
        self.assertEqual(json.loads(raw), self.repository_scope)


if __name__ == "__main__":
    unittest.main()
