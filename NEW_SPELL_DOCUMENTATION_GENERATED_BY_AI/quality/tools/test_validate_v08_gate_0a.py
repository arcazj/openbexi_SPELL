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


MODULE_PATH = Path(__file__).with_name("validate_v08_gate_0a.py")
SPEC = importlib.util.spec_from_file_location("validate_v08_gate_0a", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class GateV08ZeroAValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = copy.deepcopy(gate.EXPECTED_SCOPE)

    def assert_scope_error(self, scope: object, fragment: str) -> None:
        errors = gate.validate_scope(scope)
        self.assertTrue(
            any(fragment in error for error in errors),
            f"expected {fragment!r} in {errors!r}",
        )

    def test_repository_scope_is_the_exact_compiled_pass_shape(self) -> None:
        payload = gate.read_json()
        errors, summary = gate.validate_scope_payload(payload)
        self.assertEqual(errors, [])
        self.assertEqual(payload, gate.EXPECTED_SCOPE)
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
        mutations = (
            (lambda value: value.pop("claims"), "missing keys"),
            (lambda value: value.__setitem__("unexpected", True), "unauthorized keys"),
            (
                lambda value: value["decision"].__setitem__(
                    "owner_approval_recorded", 1
                ),
                "type differs",
            ),
        )
        for mutate, fragment in mutations:
            with self.subTest(fragment=fragment):
                value = copy.deepcopy(self.scope)
                mutate(value)
                self.assert_scope_error(value, fragment)

    def test_owner_approval_cannot_be_inferred_or_weakened(self) -> None:
        mutations = (
            ("decision", "owner_approval_recorded", False),
            ("decision", "owner_request", "all approvals"),
            ("approval_mechanics", "marker_present", False),
            ("approval_mechanics", "automatic_approval_from_request_or_tool_success", True),
            ("approval_mechanics", "required_owner_approval_marker", "APPROVED"),
        )
        for section, key, replacement in mutations:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.scope)
                value[section][key] = replacement
                self.assert_scope_error(value, "value differs")

    def test_work_package_ids_titles_statuses_and_identity_order_are_exact(self) -> None:
        packages = self.scope["proposed_work_packages"]
        self.assertEqual(
            [package["work_package_id"] for package in packages],
            [f"V08-DATA-{index:03d}" for index in range(1, 10)],
        )
        identities = [
            identity for package in packages for identity in package["planned_test_ids"]
        ]
        self.assertEqual(len(identities), 45)
        self.assertEqual(len(set(identities)), 45)
        self.assertTrue(
            all(package["status"] == "IMPLEMENTATION_AUTHORIZED" for package in packages)
        )

        mutations = []
        wrong_package = copy.deepcopy(self.scope)
        wrong_package["proposed_work_packages"][0]["work_package_id"] = "V08-DATA-010"
        mutations.append(wrong_package)
        wrong_title = copy.deepcopy(self.scope)
        wrong_title["proposed_work_packages"][2]["title"] += " changed"
        mutations.append(wrong_title)
        missing_identity = copy.deepcopy(self.scope)
        missing_identity["proposed_work_packages"][5]["planned_test_ids"].pop()
        mutations.append(missing_identity)
        reordered = copy.deepcopy(self.scope)
        reordered["proposed_work_packages"][8]["planned_test_ids"].reverse()
        mutations.append(reordered)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(gate.validate_scope(value))

    def test_claims_remain_zero_and_release_or_operational_claims_fail(self) -> None:
        for key in (
            "v0_8_implementation_claimed_by_gate",
            "v0_8_release_accepted",
            "data_constructs_implemented",
            "product_artifacts_implemented",
            "operational_authorization",
            "deployment_approval",
            "compliance_determination",
            "cryptographic_signature_verified",
        ):
            with self.subTest(key=key):
                value = copy.deepcopy(self.scope)
                value["claims"][key] = True
                self.assert_scope_error(value, "value differs")
        for key in ("claimed_construct_ids", "claimed_artifact_ids"):
            with self.subTest(key=key):
                value = copy.deepcopy(self.scope)
                value["compatibility_authorization"][key] = ["smuggled"]
                self.assertTrue(gate.validate_scope(value))

    def test_accepted_tag_tree_blob_and_artifact_bindings_are_exact(self) -> None:
        mutations = (
            ("tag_object_id", "0" * 40),
            ("raw_tag_object_sha256", "0" * 64),
            ("peeled_release_commit", "0" * 40),
            ("release_tree", "0" * 40),
            ("artifact_tree", "0" * 40),
        )
        for key, replacement in mutations:
            with self.subTest(key=key):
                value = copy.deepcopy(self.scope)
                value["accepted_baseline"][key] = replacement
                self.assert_scope_error(value, "value differs")

        value = copy.deepcopy(self.scope)
        value["accepted_baseline"]["tagged_blobs"][gate.ARCHIVE_PATH][
            "object_id"
        ] = "0" * 40
        self.assert_scope_error(value, "value differs")

    def test_reviewed_and_authorized_compatibility_sets_are_distinct_and_exact(self) -> None:
        compatibility = self.scope["compatibility_authorization"]
        reviewed = gate._flatten_groups(
            compatibility["reviewed_artifact_ids_by_work_package"]
        )
        authorized = gate._flatten_groups(
            compatibility["implementation_authorized_artifact_ids_by_work_package"]
        )
        singular = "CMP-LRM244-FUNCTION-CANDIDATE-CLEARSHAREDDATASCOPE"
        plural = "CMP-LRM244-FUNCTION-CLEARSHAREDDATASCOPES"
        self.assertEqual(
            [len(values) for values in compatibility["reviewed_artifact_ids_by_work_package"].values()],
            [6, 24, 18, 14, 33, 40],
        )
        self.assertEqual(
            [len(values) for values in compatibility["implementation_authorized_artifact_ids_by_work_package"].values()],
            [6, 24, 18, 14, 32, 40],
        )
        self.assertEqual(len(reviewed), 135)
        self.assertEqual(len(authorized), 134)
        self.assertEqual(compatibility["negative_only_artifact_ids"], [singular])
        self.assertIn(singular, reviewed)
        self.assertNotIn(singular, authorized)
        self.assertIn(plural, authorized)
        self.assertEqual(gate._selection_digest(reviewed), gate.REVIEWED_ARTIFACT_IDS_SHA256)
        self.assertEqual(
            gate._selection_digest(authorized),
            gate.IMPLEMENTATION_AUTHORIZED_ARTIFACT_IDS_SHA256,
        )

    def test_compatibility_selection_mutations_fail_exact_scope_validation(self) -> None:
        mutations = []
        alias_smuggling = copy.deepcopy(self.scope)
        alias_smuggling["compatibility_authorization"][
            "implementation_authorized_artifact_ids_by_work_package"
        ]["V08-DATA-005"].append(gate.NEGATIVE_ONLY_ARTIFACT_IDS[0])
        mutations.append(alias_smuggling)
        wrong_count = copy.deepcopy(self.scope)
        wrong_count["compatibility_authorization"][
            "implementation_authorized_artifact_id_count"
        ] = 135
        mutations.append(wrong_count)
        wrong_hash = copy.deepcopy(self.scope)
        wrong_hash["compatibility_authorization"]["reviewed_artifact_ids_sha256"] = "0" * 64
        mutations.append(wrong_hash)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(gate.validate_scope(value))

    def test_selection_digest_rejects_duplicates_and_non_ascii(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate._selection_digest(["A", "A"])
        with self.assertRaises(UnicodeEncodeError):
            gate._selection_digest(["not-ascii-\N{SNOWMAN}"])

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

    def test_current_annotated_tag_raw_payload_is_exact(self) -> None:
        raw = gate.run_git(["cat-file", "tag", gate.TAG_OBJECT_ID]).stdout
        self.assertEqual(gate.validate_tag_payload(raw), [])
        self.assertEqual(len(raw), gate.RAW_TAG_OBJECT_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), gate.RAW_TAG_OBJECT_SHA256)

    def test_tag_payload_rejects_header_message_and_byte_mutations(self) -> None:
        raw = gate.run_git(["cat-file", "tag", gate.TAG_OBJECT_ID]).stdout
        variants = (
            raw.replace(b"tag v0.7.0", b"tag v0.7.1", 1),
            raw.replace(b"Decision: ACCEPTED", b"Decision: REJECTED", 1),
            raw[:-1],
        )
        for mutated in variants:
            with self.subTest(mutated=mutated[-32:]):
                self.assertTrue(gate.validate_tag_payload(mutated))

    def test_archive_sidecar_requires_exact_raw_pair(self) -> None:
        archive = gate.run_git(
            ["cat-file", "blob", gate.TAGGED_BLOBS[gate.ARCHIVE_PATH]["object_id"]]
        ).stdout
        sidecar = gate.run_git(
            ["cat-file", "blob", gate.TAGGED_BLOBS[gate.SIDECAR_PATH]["object_id"]]
        ).stdout
        self.assertEqual(gate.validate_archive_sidecar(archive, sidecar, "test"), [])
        self.assertTrue(gate.validate_archive_sidecar(archive + b"x", sidecar, "test"))
        self.assertTrue(gate.validate_archive_sidecar(archive, sidecar.rstrip(), "test"))

    def test_contract_directory_accepts_only_exact_strict_json_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payloads = {
                name: json.dumps({"contract": name}, separators=(",", ":")).encode("ascii")
                for name in gate.CONTRACTS_SHA256
            }
            hashes = {
                name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()
            }
            for name, raw in payloads.items():
                (root / name).write_bytes(raw)
            with mock.patch.object(gate, "CONTRACTS_SHA256", hashes):
                self.assertEqual(gate.validate_contract_directory(root), [])
                (root / "unexpected.json").write_text("{}", encoding="ascii")
                errors = gate.validate_contract_directory(root)
                self.assertTrue(any("inventory differs" in error for error in errors))

    def test_contract_directory_rejects_hash_and_json_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = tuple(gate.CONTRACTS_SHA256)
            payloads = {name: b"{}" for name in names}
            hashes = {name: hashlib.sha256(b"{}").hexdigest() for name in names}
            for name, raw in payloads.items():
                (root / name).write_bytes(raw)
            first, second = names[:2]
            (root / first).write_bytes(b'{"x":1,"x":2}')
            (root / second).write_bytes(b'{"x":NaN}')
            with mock.patch.object(gate, "CONTRACTS_SHA256", hashes):
                errors = gate.validate_contract_directory(root)
            self.assertTrue(any(first in error and "duplicate" in error for error in errors))
            self.assertTrue(any(second in error and "non-finite" in error for error in errors))

    def test_current_compatibility_ledger_satisfies_frozen_selection(self) -> None:
        self.assertEqual(gate.validate_compatibility_selection(), [])

    def test_current_git_baseline_satisfies_strict_object_validation(self) -> None:
        self.assertEqual(gate.validate_git_baseline(), [])

    def test_document_contains_each_exact_binding_and_approval_marker(self) -> None:
        self.assertEqual(gate.validate_document(), [])

    def test_document_marker_or_contract_mutation_is_rejected(self) -> None:
        lines = (gate.WORKSPACE_ROOT / gate.PROPOSAL_PATH).read_text(
            encoding="utf-8"
        ).splitlines()
        for marker in (gate.OWNER_APPROVAL_MARKER, gate.PASS_MARKER):
            with self.subTest(marker=marker):
                mutated = list(lines)
                mutated.remove(marker)
                self.assertTrue(gate.validate_document_lines(mutated))
        mutated = list(lines)
        name, digest = next(iter(gate.CONTRACTS_SHA256.items()))
        index = mutated.index(f"| `contracts/v08/{name}` | `{digest}` |")
        mutated[index] = f"| `contracts/v08/{name}` | `{'0' * 64}` |"
        self.assertTrue(gate.validate_document_lines(mutated))

    def test_failed_scope_summary_never_reports_pass(self) -> None:
        value = copy.deepcopy(self.scope)
        value["status"] = "FAIL"
        errors, summary = gate.validate_scope_payload(value)
        self.assertTrue(errors)
        self.assertEqual(summary["gate"], "FAIL")
        self.assertEqual(summary["authorized_work_packages"], 9)

    def test_full_repository_validation_passes(self) -> None:
        errors, summary = gate.validate_repository()
        self.assertEqual(errors, [])
        self.assertEqual(summary["gate"], "PASS")

    def test_main_emits_only_the_exact_pass_marker_on_success(self) -> None:
        summary = gate._scope_summary(self.scope, True)
        stdout = io.StringIO()
        with mock.patch.object(gate, "validate_repository", return_value=([], summary)):
            with contextlib.redirect_stdout(stdout):
                result = gate.main()
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), gate.PASS_MARKER + "\n")

    def test_main_failure_marker_cannot_be_confused_with_pass(self) -> None:
        summary = gate._scope_summary(self.scope, False)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            gate, "validate_repository", return_value=(["forced failure"], summary)
        ):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = gate.main()
        self.assertEqual(result, 1)
        self.assertTrue(stdout.getvalue().startswith("gate=FAIL "))
        self.assertNotIn("gate=PASS", stdout.getvalue())
        self.assertIn("ERROR: forced failure", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
