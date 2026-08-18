from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("validate_v09_gate_0a.py")
SPEC = importlib.util.spec_from_file_location("validate_v09_gate_0a", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class GateV09ZeroAValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = copy.deepcopy(gate.read_json())

    def assert_scope_error(self, scope: object, fragment: str) -> None:
        errors = gate.validate_scope(scope)
        self.assertTrue(
            any(fragment in error for error in errors),
            f"expected {fragment!r} in {errors!r}",
        )

    def test_repository_scope_has_exact_gate_shape_and_raw_digest(self) -> None:
        raw = gate.SCOPE_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), gate.SCOPE_SHA256)
        errors, summary = gate.validate_scope_payload(self.scope)
        self.assertEqual(errors, [])
        self.assertEqual(
            summary,
            {
                "gate": "PASS",
                "authorized_work_packages": 9,
                "proposed_work_packages": 9,
                "claimed_constructs": 0,
                "claimed_artifacts": 0,
            },
        )

    def test_scope_rejects_missing_extra_and_wrongly_typed_fields(self) -> None:
        missing = copy.deepcopy(self.scope)
        missing.pop("claims")
        self.assert_scope_error(missing, "top-level keys")
        extra = copy.deepcopy(self.scope)
        extra["unexpected"] = True
        self.assert_scope_error(extra, "top-level keys")
        wrong_type = copy.deepcopy(self.scope)
        wrong_type["status"] = True
        self.assert_scope_error(wrong_type, "status type")

    def test_owner_approval_is_explicit_and_cannot_be_inferred(self) -> None:
        replacements = (
            ("decision", "owner_approval_recorded", False),
            ("decision", "owner_request", "all approvals"),
            ("approval_mechanics", "marker_present", False),
            ("approval_mechanics", "automatic_approval_from_request_or_tool_success", True),
            ("approval_mechanics", "required_owner_approval_marker", "APPROVED"),
        )
        for section, key, replacement in replacements:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                value[section][key] = replacement
                self.assertTrue(gate.validate_scope(value))

    def test_scope_binds_exact_accepted_v08_tag_release_and_artifacts(self) -> None:
        baseline = self.scope["accepted_baseline"]
        self.assertEqual(baseline, gate._expected_baseline())
        for key in (
            "tag_object_id",
            "raw_tag_object_sha256",
            "peeled_release_commit",
            "release_tree",
            "artifact_tree",
            "product_package_sha256",
        ):
            with self.subTest(key=key):
                value = copy.deepcopy(self.scope)
                value["accepted_baseline"][key] = "0" * len(str(baseline[key]))
                self.assert_scope_error(value, "baseline binding")

    def test_scope_authorizes_exact_nine_packages_and_45_unique_ids(self) -> None:
        packages = self.scope["proposed_work_packages"]
        self.assertEqual(packages, gate._expected_packages())
        ids = [item["work_package_id"] for item in packages]
        self.assertEqual(ids, [f"V09-DEV-{index:03d}" for index in range(1, 10)])
        test_ids = [value for item in packages for value in item["planned_test_ids"]]
        self.assertEqual(len(test_ids), len(set(test_ids)))
        self.assertEqual(len(test_ids), 45)
        for mutation in (
            lambda value: value["proposed_work_packages"].pop(),
            lambda value: value["proposed_work_packages"][0].__setitem__("status", "IMPLEMENTED"),
            lambda value: value["proposed_work_packages"][4]["planned_test_ids"].pop(),
            lambda value: value["approval_mechanics"]["authorized_work_package_ids"].reverse(),
        ):
            changed = copy.deepcopy(self.scope)
            mutation(changed)
            self.assertTrue(gate.validate_scope(changed))

    def test_gate_claims_no_v09_implementation_release_or_operation(self) -> None:
        self.assertEqual(self.scope["claims"], gate.EXPECTED_CLAIMS)
        for key in (
            "v0_9_implementation_claimed_by_gate",
            "v0_9_release_accepted",
            "development_constructs_implemented",
            "product_artifacts_implemented",
            "new_container_images_implemented",
            "operational_authorization",
            "deployment_approval",
            "compliance_determination",
            "cryptographic_signature_verified",
        ):
            with self.subTest(key=key):
                value = copy.deepcopy(self.scope)
                value["claims"][key] = True
                self.assert_scope_error(value, "claims")
        for key in ("claimed_construct_ids", "claimed_artifact_ids"):
            value = copy.deepcopy(self.scope)
            value["compatibility_authorization"][key] = ["smuggled"]
            self.assertTrue(gate.validate_scope(value))

    def test_dev244_allocation_is_exact_164_reviewed_20_negative_144_authorized(self) -> None:
        compatibility = self.scope["compatibility_authorization"]
        reviewed = gate._flatten_groups(
            compatibility["reviewed_artifact_ids_by_work_package"]
        )
        negative = compatibility["negative_only_artifact_ids"]
        authorized = gate._flatten_groups(
            compatibility["implementation_authorized_artifact_ids_by_work_package"]
        )
        self.assertEqual([len(values) for values in compatibility["reviewed_artifact_ids_by_work_package"].values()], [37, 35, 17, 34, 11, 30])
        self.assertEqual([len(values) for values in compatibility["implementation_authorized_artifact_ids_by_work_package"].values()], [27, 31, 17, 34, 10, 25])
        self.assertEqual((len(reviewed), len(negative), len(authorized)), (164, 20, 144))
        self.assertEqual(set(authorized), set(reviewed) - set(negative))
        self.assertEqual(gate._selection_digest(reviewed), "3de9055f35bffc1f7065f2dad452dcbb32e937a0335bdf6ff129c69869ed738e")
        self.assertEqual(gate._selection_digest(negative), "f1f199ea5a8facbed6bf8226578665c22f6b1de9cfdb4004e72cb167249f7bcb")
        self.assertEqual(gate._selection_digest(authorized), "22138ab7f4895da9a71af310f85722cff200b7b7693b2f3e0833758fa34fa270")

    def test_compatibility_mutations_fail_closed(self) -> None:
        negative = self.scope["compatibility_authorization"]["negative_only_artifact_ids"][0]
        mutations = (
            lambda value: value["compatibility_authorization"]["implementation_authorized_artifact_ids_by_work_package"]["V09-DEV-001"].append(negative),
            lambda value: value["compatibility_authorization"].__setitem__("reviewed_artifact_id_count", 163),
            lambda value: value["compatibility_authorization"].__setitem__("reviewed_artifact_ids_sha256", "0" * 64),
            lambda value: value["compatibility_authorization"].__setitem__("claimed_artifact_ids", ["CMP-DEV244-FAKE"]),
        )
        for mutation in mutations:
            value = copy.deepcopy(self.scope)
            mutation(value)
            self.assertTrue(gate.validate_scope(value))

    def test_four_image_boundary_and_distinct_subject_duties_are_frozen(self) -> None:
        self.assertEqual(self.scope["deployment_matrix"], gate.EXPECTED_DEPLOYMENT_MATRIX)
        value = copy.deepcopy(self.scope)
        value["deployment_matrix"]["sbom_images"].append("development")
        self.assert_scope_error(value, "four-image")
        value = copy.deepcopy(self.scope)
        value["identity_and_duties"][
            "author_subject_must_differ_from_review_approve_promote_subject"
        ] = False
        self.assert_scope_error(value, "separation-of-duties")

    def test_strict_json_rejects_duplicate_nonfinite_oversize_and_invalid_utf8(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            gate.parse_strict_json(b'{"x":1,"x":2}', "test", 100)
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "non-finite"):
                    gate.parse_strict_json(raw, "test", 100)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            gate.parse_strict_json(b"{}", "test", 1)
        with self.assertRaises(UnicodeDecodeError):
            gate.parse_strict_json(b'"\xff"', "test", 100)

    def test_selection_digest_rejects_duplicates_and_non_ascii(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate._selection_digest(["A", "A"])
        with self.assertRaises(UnicodeEncodeError):
            gate._selection_digest(["not-ascii-\N{SNOWMAN}"])

    def test_contract_inventory_and_all_nine_hashes_are_exact(self) -> None:
        self.assertEqual(gate.validate_contract_directory(), [])
        self.assertEqual(
            {path.name for path in (gate.WORKSPACE_ROOT / gate.CONTRACT_DIRECTORY).iterdir()},
            set(gate.CONTRACTS_SHA256),
        )
        for name, digest in gate.CONTRACTS_SHA256.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((gate.WORKSPACE_ROOT / gate.CONTRACT_DIRECTORY / name).read_bytes()).hexdigest(),
                    digest,
                )

    def test_contract_directory_rejects_inventory_hash_and_non_strict_json(self) -> None:
        with tempfile.TemporaryDirectory(dir=gate.WORKSPACE_ROOT) as directory:
            root = Path(directory)
            payloads = {name: b"{}" for name in gate.CONTRACTS_SHA256}
            hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}
            for name, raw in payloads.items():
                (root / name).write_bytes(raw)
            first = next(iter(payloads))
            (root / first).write_bytes(b'{"x":1,"x":2}')
            (root / "unexpected.json").write_text("{}", encoding="ascii")
            with mock.patch.object(gate, "CONTRACTS_SHA256", hashes):
                errors = gate.validate_contract_directory(root)
            self.assertTrue(any("inventory differs" in error for error in errors))
            self.assertTrue(any(first in error and "duplicate" in error for error in errors))

    def test_current_dev244_ledger_satisfies_exact_gate_allocation(self) -> None:
        self.assertEqual(gate.validate_compatibility_selection(), [])

    def test_accepted_v08_baseline_and_source_objects_validate(self) -> None:
        self.assertEqual(gate.validate_git_baseline(), [])

    def test_gate_document_contains_exact_approval_packages_and_hash_bindings(self) -> None:
        self.assertEqual(gate.validate_document(), [])
        lines = (gate.WORKSPACE_ROOT / gate.PROPOSAL_PATH).read_text(encoding="utf-8").splitlines()
        for marker in (gate.OWNER_APPROVAL_MARKER, gate.PASS_MARKER):
            changed = list(lines)
            changed.remove(marker)
            self.assertTrue(gate.validate_document_lines(changed))
        name, digest = next(iter(gate.CONTRACTS_SHA256.items()))
        marker = f"| `contracts/v09/{name}` | `{digest}` |"
        changed = list(lines)
        changed[changed.index(marker)] = f"| `contracts/v09/{name}` | `{'0' * 64}` |"
        self.assertTrue(gate.validate_document_lines(changed))

    def test_scope_raw_mutation_fails_full_repository_validation(self) -> None:
        with tempfile.TemporaryDirectory(dir=gate.WORKSPACE_ROOT) as directory:
            path = Path(directory) / "scope.json"
            changed = copy.deepcopy(self.scope)
            changed["decision"]["owner"] = "different"
            path.write_text(json.dumps(changed), encoding="utf-8")
            errors, summary = gate.validate_repository(scope_path=path)
            self.assertTrue(any("owner decision" in error for error in errors))
            self.assertTrue(any("raw SHA-256" in error for error in errors))
            self.assertEqual(summary["gate"], "FAIL")

    def test_full_repository_validation_passes(self) -> None:
        errors, summary = gate.validate_repository()
        self.assertEqual(errors, [])
        self.assertEqual(summary["gate"], "PASS")

    def test_main_emits_only_exact_pass_marker(self) -> None:
        summary = gate._scope_summary(self.scope, True)
        stdout = io.StringIO()
        with mock.patch.object(gate, "validate_repository", return_value=([], summary)):
            with contextlib.redirect_stdout(stdout):
                result = gate.main()
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), gate.PASS_MARKER + "\n")

    def test_main_failure_is_unambiguously_fail(self) -> None:
        summary = gate._scope_summary(self.scope, False)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(gate, "validate_repository", return_value=(["forced failure"], summary)):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = gate.main()
        self.assertEqual(result, 1)
        self.assertTrue(stdout.getvalue().startswith("gate=FAIL "))
        self.assertNotIn("gate=PASS", stdout.getvalue())
        self.assertIn("ERROR: forced failure", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
