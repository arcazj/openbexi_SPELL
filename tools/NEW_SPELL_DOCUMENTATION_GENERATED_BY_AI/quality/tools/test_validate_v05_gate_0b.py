from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import validate_v05_gate_0b


class GateV05ZeroBValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scope = validate_v05_gate_0b.read_json()

    def validate_scope(self, payload: object | None = None) -> list[str]:
        candidate = copy.deepcopy(self.scope) if payload is None else payload
        return validate_v05_gate_0b.validate_scope(candidate)

    def valid_evidence(self) -> dict[str, object]:
        return {
            "schema_version": "spell.v05.candidate-qualification/1",
            "product_version": "0.5.0-candidate",
            "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
            "implementation_candidate": {
                "commit": validate_v05_gate_0b.CANDIDATE_COMMIT,
                "tree": validate_v05_gate_0b.CANDIDATE_TREE,
                "parent": validate_v05_gate_0b.GATE_0A_COMMIT,
                "changed_paths": [
                    {"path": item["path"], "blob": item["blob"]}
                    for item in validate_v05_gate_0b.CANDIDATE_PATHS
                ],
            },
            "qualification_source": {
                "commit": validate_v05_gate_0b.QUALIFICATION_COMMIT,
                "tree": validate_v05_gate_0b.QUALIFICATION_TREE,
                "parent": validate_v05_gate_0b.QUALIFICATION_PARENT,
                "correction": {
                    "path": validate_v05_gate_0b.QUALIFICATION_CORRECTION["path"],
                    "blob": validate_v05_gate_0b.QUALIFICATION_CORRECTION["blob"],
                    "sha256": validate_v05_gate_0b.QUALIFICATION_CORRECTION["sha256"],
                },
            },
            "toolchain": {
                "lock_path": "scripts/release-toolchain-v04.json",
                "lock_sha256": "0" * 64,
                "python_version": "3.13.14",
                "python_sha256": "1" * 64,
                "qualification_image_id": "sha256:" + "2" * 64,
            },
            "database": {
                "application_name": "spell_candidate_test",
                "migration_name": "spell_migration_test",
                "distinct_names": True,
                "both_environment_variables_bound": True,
                "postgresql_zero_skips": True,
            },
            "suites": {
                "backend_sqlite": {},
                "backend_postgresql": {},
                "driver_host": {},
                "tooling": {},
            },
            "identities": {
                identity: {
                    "nodes": [f"backend/tests/test_ir_v03.py::{identity}"],
                    "environments": ["sqlite", "postgresql"],
                    "passed_count": 2,
                    "skipped_count": 0,
                }
                for identity in validate_v05_gate_0b.IDENTITY_IDS
            },
            "inherited_v04": {},
            "artifacts": {},
            "teardown": {},
            "overall_pass": True,
        }

    def test_scope_is_the_independent_exact_contract(self) -> None:
        self.assertEqual(self.validate_scope(), [])
        self.assertEqual(self.scope, validate_v05_gate_0b.EXPECTED_SCOPE)
        self.assertEqual(
            hashlib.sha256(validate_v05_gate_0b.SCOPE_PATH.read_bytes()).hexdigest(),
            validate_v05_gate_0b.SCOPE_SHA256,
        )

    def test_scope_rejects_missing_extra_and_wrongly_typed_values(self) -> None:
        missing = copy.deepcopy(self.scope)
        missing.pop("explicit_exclusions")
        extra = copy.deepcopy(self.scope)
        extra["second_work_package"] = {}
        bool_for_zero = copy.deepcopy(self.scope)
        bool_for_zero["qualified_work_package"]["compatibility_delta"][
            "compatibility_ledger_rows_added"
        ] = False

        self.assertTrue(any("missing keys" in error for error in self.validate_scope(missing)))
        self.assertTrue(any("unauthorized keys" in error for error in self.validate_scope(extra)))
        self.assertTrue(any("type differs" in error for error in self.validate_scope(bool_for_zero)))

    def test_owner_request_and_tag_resolution_are_immutable(self) -> None:
        mutations = {
            "owner": "automation",
            "owner_request": "release everything",
            "authorization": "ALL_V05_WORK",
            "tag_resolution": "CREATE_LIGHTWEIGHT_V0_5",
            "precondition": "NO_QUALIFICATION_REQUIRED",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["decision"][field] = replacement
                self.assertTrue(self.validate_scope(payload))

    def test_gate_cannot_authorize_broader_product_work(self) -> None:
        payloads = []
        additional = copy.deepcopy(self.scope)
        additional["release_closeout_authorization"]["additional_product_work_authorized"] = True
        payloads.append(additional)
        action = copy.deepcopy(self.scope)
        action["release_closeout_authorization"]["permitted_actions"].append(
            "IMPLEMENT_TIME_AND_NOW"
        )
        payloads.append(action)
        ir = copy.deepcopy(self.scope)
        ir["qualified_work_package"]["accepted_ir_version"] = "0.4"
        payloads.append(ir)
        construct = copy.deepcopy(self.scope)
        construct["qualified_work_package"]["compatibility_delta"][
            "claimed_construct_ids"
        ] = ["TIME"]
        payloads.append(construct)

        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertTrue(self.validate_scope(payload))

    def test_all_six_identity_ids_are_exact_ordered_and_unique(self) -> None:
        self.assertEqual(len(set(validate_v05_gate_0b.IDENTITY_IDS)), 6)
        for operation in ("remove", "duplicate", "replace", "reorder"):
            with self.subTest(operation=operation):
                payload = copy.deepcopy(self.scope)
                identities = payload["qualified_work_package"]["identity_results"]
                if operation == "remove":
                    identities.pop()
                elif operation == "duplicate":
                    identities[-1] = identities[0]
                elif operation == "replace":
                    identities[-1] = "V05-IR-002-UNIT"
                else:
                    identities.reverse()
                self.assertTrue(self.validate_scope(payload))

    def test_release_is_not_accepted_by_this_gate(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["claims"]["v0_5_release_accepted_by_gate"] = True
        self.assertTrue(self.validate_scope(payload))

    def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    validate_v05_gate_0b.strict_json_bytes(raw)

    def test_accepted_tag_payload_and_all_git_bindings_pass(self) -> None:
        tag = validate_v05_gate_0b.run_git(
            ["cat-file", "tag", validate_v05_gate_0b.BASELINE_TAG_OBJECT]
        )
        self.assertEqual(validate_v05_gate_0b.validate_tag_payload(tag), [])
        self.assertEqual(validate_v05_gate_0b.validate_git_bindings(), [])

    def test_tag_byte_and_marker_mutations_fail(self) -> None:
        tag = validate_v05_gate_0b.run_git(
            ["cat-file", "tag", validate_v05_gate_0b.BASELINE_TAG_OBJECT]
        )
        self.assertTrue(validate_v05_gate_0b.validate_tag_payload(tag + b" "))
        errors = validate_v05_gate_0b.validate_tag_payload(
            tag.replace(b"Owner: JC Arcaz", b"Owner: Unknown", 1)
        )
        self.assertTrue(any("Owner: JC Arcaz" in error for error in errors))

    def test_commit_binding_rejects_wrong_tree_and_merge_parent(self) -> None:
        raw = (
            f"tree {validate_v05_gate_0b.CANDIDATE_TREE}\n"
            f"parent {validate_v05_gate_0b.GATE_0A_COMMIT}\n"
            "parent 0000000000000000000000000000000000000000\n\nmessage\n"
        ).encode("ascii")
        errors = validate_v05_gate_0b.validate_commit_payload(
            raw,
            validate_v05_gate_0b.CANDIDATE_TREE,
            validate_v05_gate_0b.GATE_0A_COMMIT,
            "candidate",
        )
        self.assertTrue(any("single parent" in error for error in errors))
        wrong_tree = raw.replace(
            validate_v05_gate_0b.CANDIDATE_TREE.encode("ascii"), b"0" * 40, 1
        )
        self.assertTrue(
            any(
                "tree binding" in error
                for error in validate_v05_gate_0b.validate_commit_payload(
                    wrong_tree,
                    validate_v05_gate_0b.CANDIDATE_TREE,
                    validate_v05_gate_0b.GATE_0A_COMMIT,
                    "candidate",
                )
            )
        )

    def test_candidate_diff_parser_rejects_extra_and_rename_shapes(self) -> None:
        parsed = validate_v05_gate_0b.parse_name_status_z(b"A\0a.py\0M\0b.py\0")
        self.assertEqual(parsed, [{"status": "A", "path": "a.py"}, {"status": "M", "path": "b.py"}])
        with self.assertRaises(ValueError):
            validate_v05_gate_0b.parse_name_status_z(b"A\0a.py")
        with self.assertRaises(ValueError):
            validate_v05_gate_0b.parse_name_status_z(b"R100\0a.py\0")

    def test_qualification_source_is_one_exact_test_compatibility_correction(self) -> None:
        self.assertEqual(validate_v05_gate_0b.validate_git_bindings(), [])
        payload = copy.deepcopy(self.scope)
        qualification = payload["immutable_inputs"]["qualification_source"]
        qualification["correction"]["sha256"] = "0" * 64
        self.assertTrue(self.validate_scope(payload))
        payload = copy.deepcopy(self.scope)
        payload["immutable_inputs"]["qualification_source"][
            "product_behavior_changed"
        ] = True
        self.assertTrue(self.validate_scope(payload))

    def test_committed_gate_0a_scope_is_strict_and_semantically_bound(self) -> None:
        path = (
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
            "scopes/v0.5-gate-0a.json"
        )
        raw = validate_v05_gate_0b.run_git(
            ["cat-file", "blob", f"{validate_v05_gate_0b.GATE_0A_COMMIT}:{path}"]
        )
        self.assertEqual(validate_v05_gate_0b._validate_gate_0a_scope(raw), [])
        payload = json.loads(raw)
        payload["authorized_work_package"]["planned_test_ids"].append("V05-IR-002")
        self.assertTrue(
            validate_v05_gate_0b._validate_gate_0a_scope(
                json.dumps(payload).encode("utf-8")
            )
        )

    def test_valid_evidence_security_bindings_pass(self) -> None:
        self.assertEqual(
            validate_v05_gate_0b.validate_evidence_payload(self.valid_evidence()),
            [],
        )

    def test_evidence_rejects_candidate_toolchain_and_database_substitution(self) -> None:
        mutations = (
            ("implementation_candidate", "commit", "0" * 40),
            ("implementation_candidate", "parent", "0" * 40),
            ("qualification_source", "commit", "0" * 40),
            ("toolchain", "python_version", "3.9.13"),
            ("database", "distinct_names", False),
            ("database", "both_environment_variables_bound", False),
            ("database", "postgresql_zero_skips", False),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                payload = self.valid_evidence()
                payload[section][field] = value
                self.assertTrue(validate_v05_gate_0b.validate_evidence_payload(payload))

    def test_evidence_rejects_missing_extra_skipped_or_empty_identity(self) -> None:
        payloads = []
        missing = self.valid_evidence()
        missing["identities"].pop(validate_v05_gate_0b.IDENTITY_IDS[-1])
        payloads.append(missing)
        extra = self.valid_evidence()
        extra["identities"]["V05-IR-002"] = copy.deepcopy(
            extra["identities"][validate_v05_gate_0b.IDENTITY_IDS[0]]
        )
        payloads.append(extra)
        skipped = self.valid_evidence()
        skipped["identities"][validate_v05_gate_0b.IDENTITY_IDS[0]]["skipped_count"] = 1
        payloads.append(skipped)
        empty = self.valid_evidence()
        empty["identities"][validate_v05_gate_0b.IDENTITY_IDS[0]]["nodes"] = []
        payloads.append(empty)
        duplicate = self.valid_evidence()
        duplicate["identities"][validate_v05_gate_0b.IDENTITY_IDS[0]]["nodes"] = ["node", "node"]
        payloads.append(duplicate)

        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertTrue(validate_v05_gate_0b.validate_evidence_payload(payload))

    def test_evidence_validator_summary_is_exact_and_digest_bound(self) -> None:
        digest = "a" * 64
        summary = {
            "gate": "PASS",
            "candidate_commit": validate_v05_gate_0b.CANDIDATE_COMMIT,
            "suite_count": 4,
            "identity_count": 6,
            "test_count": 100,
            "evidence_sha256": digest,
        }
        self.assertEqual(validate_v05_gate_0b.validate_evidence_summary(summary, digest), [])
        for field, value in (
            ("gate", "FAIL"),
            ("candidate_commit", "0" * 40),
            ("identity_count", 5),
            ("test_count", 0),
            ("evidence_sha256", "b" * 64),
        ):
            with self.subTest(field=field):
                mutation = copy.deepcopy(summary)
                mutation[field] = value
                self.assertTrue(validate_v05_gate_0b.validate_evidence_summary(mutation, digest))

    def _write_evidence_fixture(self, root: Path, noisy: bool = False) -> None:
        evidence_path = root / "artifacts/v0.5/work-package/qualification.json"
        evidence_path.parent.mkdir(parents=True)
        evidence_path.write_text(
            json.dumps(self.valid_evidence(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        validator = root / "scripts/validate_candidate_evidence_v05.py"
        validator.parent.mkdir(parents=True)
        prefix = "print('noise')\n" if noisy else ""
        validator.write_text(
            textwrap.dedent(
                f"""
                import hashlib
                import json
                import sys
                from pathlib import Path
                {prefix.rstrip()}
                root = Path(sys.argv[sys.argv.index('--root') + 1])
                raw = (root / 'artifacts/v0.5/work-package/qualification.json').read_bytes()
                print(json.dumps({{
                    'gate': 'PASS',
                    'candidate_commit': '{validate_v05_gate_0b.CANDIDATE_COMMIT}',
                    'suite_count': 4,
                    'identity_count': 6,
                    'test_count': 100,
                    'evidence_sha256': hashlib.sha256(raw).hexdigest(),
                }}, separators=(',', ':')))
                """
            ).lstrip(),
            encoding="utf-8",
        )

    def test_evidence_validator_subprocess_accepts_one_digest_bound_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_evidence_fixture(root)
            digest = hashlib.sha256(
                (root / "artifacts/v0.5/work-package/qualification.json").read_bytes()
            ).hexdigest()
            with mock.patch.object(validate_v05_gate_0b, "EVIDENCE_SHA256", digest):
                self.assertEqual(validate_v05_gate_0b.run_evidence_validator(root), [])

    def test_evidence_validator_subprocess_rejects_output_noise(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_evidence_fixture(root, noisy=True)
            digest = hashlib.sha256(
                (root / "artifacts/v0.5/work-package/qualification.json").read_bytes()
            ).hexdigest()
            with mock.patch.object(validate_v05_gate_0b, "EVIDENCE_SHA256", digest):
                errors = validate_v05_gate_0b.run_evidence_validator(root)
            self.assertTrue(any("exactly one success line" in error for error in errors))

    def test_canonical_evidence_byte_hash_is_pinned(self) -> None:
        contract = self.scope["qualified_work_package"]["qualification_contract"]
        self.assertEqual(contract["manifest_sha256"], validate_v05_gate_0b.EVIDENCE_SHA256)
        self.assertEqual(
            hashlib.sha256(validate_v05_gate_0b.EVIDENCE_PATH.read_bytes()).hexdigest(),
            validate_v05_gate_0b.EVIDENCE_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_evidence_fixture(root)
            errors = validate_v05_gate_0b.run_evidence_validator(root)
            self.assertTrue(any("byte SHA-256 differs" in error for error in errors))

    def test_gate_document_has_exact_closeout_and_nonclaim_markers(self) -> None:
        self.assertEqual(validate_v05_gate_0b.validate_gate_document(), [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.md"
            lines = validate_v05_gate_0b.GATE_DOCUMENT_PATH.read_text(encoding="utf-8").splitlines()
            lines.remove(validate_v05_gate_0b.DOCUMENT_MARKERS[2])
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertTrue(validate_v05_gate_0b.validate_gate_document(path))

    def test_repository_gate_and_main_marker_when_canonical_evidence_exists(self) -> None:
        if not validate_v05_gate_0b.EVIDENCE_PATH.is_file() or not validate_v05_gate_0b.EVIDENCE_VALIDATOR_PATH.is_file():
            self.skipTest("canonical candidate evidence has not landed yet")
        errors, summary = validate_v05_gate_0b.validate_repository()
        self.assertEqual(errors, [])
        self.assertEqual(summary["gate"], "PASS")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = validate_v05_gate_0b.main()
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(),
            (
                "gate=PASS work_packages=1 identities=6 failed=0 skipped=0 "
                "claimed_constructs=0 claimed_artifacts=0 "
                "release_closeout=AUTHORIZED\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
