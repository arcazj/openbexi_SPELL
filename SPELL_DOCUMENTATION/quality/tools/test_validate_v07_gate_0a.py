from __future__ import annotations

import contextlib
import copy
import io
import shutil
import tempfile
import unittest
from pathlib import Path

import validate_v07_gate_0a


class GateV07ZeroAValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scope = validate_v07_gate_0a.read_json()

    def validate(self, payload: object | None = None) -> list[str]:
        candidate = copy.deepcopy(self.scope) if payload is None else payload
        return validate_v07_gate_0a.validate_scope(candidate)

    def test_repository_reports_exact_pass_summary(self) -> None:
        errors, summary = validate_v07_gate_0a.validate_repository()

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

    def test_main_prints_only_exact_pass_marker(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = validate_v07_gate_0a.main()

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(), validate_v07_gate_0a.PASS_MARKER + "\n"
        )

    def test_scope_matches_independently_compiled_contract(self) -> None:
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.scope, validate_v07_gate_0a.EXPECTED_SCOPE)
        self.assertIsNot(
            self.scope["proposed_work_packages"], validate_v07_gate_0a.WORK_PACKAGES
        )
        self.assertIsNot(
            self.scope["accepted_baseline"]["tagged_blobs"],
            validate_v07_gate_0a.TAGGED_BLOBS,
        )
        self.assertIsNot(
            self.scope["authorization_contracts"]["files_sha256"],
            validate_v07_gate_0a.CONTRACTS_SHA256,
        )

    def test_top_level_and_authority_boundary_keys_are_exact(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["implementation_evidence"] = {"status": "PASS"}
        self.assertTrue(any("unauthorized keys" in item for item in self.validate(payload)))

        for section in (
            "decision",
            "approval_mechanics",
            "accepted_baseline",
            "authorization_contracts",
            "compatibility_delta",
            "claims",
        ):
            with self.subTest(section=section):
                payload = copy.deepcopy(self.scope)
                payload[section]["unreviewed_extension"] = True
                self.assertTrue(
                    any(
                        f"scope.{section} has unauthorized keys" in item
                        for item in self.validate(payload)
                    )
                )

    def test_approved_gate_cannot_be_narrowed_redirected_or_auto_approved(self) -> None:
        mutations = (
            ("status", "PENDING_OWNER_APPROVAL"),
            ("decision.approval_date", "2026-08-17"),
            ("decision.authorization", "NONE"),
            ("decision.owner_approval_recorded", False),
            ("approval_mechanics.marker_present", False),
            (
                "approval_mechanics.authorized_work_package_ids",
                ["V07-OBS-001", "V07-OBS-002"],
            ),
            ("approval_mechanics.automatic_approval_from_request_or_tool_success", True),
            ("claims.v0_7_implementation_authorized", False),
        )
        for dotted_path, replacement in mutations:
            with self.subTest(field=dotted_path):
                payload = copy.deepcopy(self.scope)
                target = payload
                parts = dotted_path.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = replacement
                self.assertTrue(self.validate(payload))

    def test_decision_identity_request_date_and_precondition_are_fixed(self) -> None:
        replacements = {
            "owner": "automated-agent",
            "proposal_date": "2026-08-15",
            "approval_date": "2026-08-15",
            "owner_request": "approve all future work",
            "precondition": "UNVERIFIED_BASELINE",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["decision"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_nine_packages_and_45_test_identities_are_exact_ordered_and_unique(self) -> None:
        packages = self.scope["proposed_work_packages"]
        package_ids = [item["work_package_id"] for item in packages]
        test_ids = [
            test_id for item in packages for test_id in item["planned_test_ids"]
        ]

        self.assertEqual(
            package_ids, [f"V07-OBS-{index:03d}" for index in range(1, 10)]
        )
        self.assertEqual(len(package_ids), len(set(package_ids)))
        self.assertEqual(len(test_ids), 45)
        self.assertEqual(len(test_ids), len(set(test_ids)))
        self.assertEqual(
            self.scope["approval_mechanics"]["authorized_work_package_ids"],
            package_ids,
        )
        self.assertTrue(
            all(item["status"] == "IMPLEMENTATION_AUTHORIZED" for item in packages)
        )
        self.assertEqual(packages, validate_v07_gate_0a.WORK_PACKAGES)

    def test_package_boundaries_and_test_identities_cannot_expand(self) -> None:
        for index in range(9):
            for field, replacement in (
                ("title", "Unbounded observation"),
                ("status", "IMPLEMENTED"),
                ("capability_boundary", "ALL_CAPABILITIES"),
            ):
                with self.subTest(index=index, field=field):
                    payload = copy.deepcopy(self.scope)
                    payload["proposed_work_packages"][index][field] = replacement
                    self.assertTrue(self.validate(payload))
            payload = copy.deepcopy(self.scope)
            payload["proposed_work_packages"][index]["planned_test_ids"].append(
                f"V07-OBS-{index + 1:03d}-UNREVIEWED"
            )
            self.assertTrue(self.validate(payload))

    def test_gate_cannot_claim_implemented_constructs_or_artifacts(self) -> None:
        mutations = {
            "accepted_ir_versions": ["0.3", "0.7"],
            "new_ir_versions": ["0.7"],
            "claimed_construct_ids": ["GetTM"],
            "claimed_artifact_ids": ["V07-TM-RUNTIME"],
            "compatibility_ledger_rows_added": 1,
            "v0_6_scope_rows_changed": 1,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["compatibility_delta"][field] = replacement
                self.assertTrue(self.validate(payload))

        for claim in (
            "v0_7_implementation_claimed_by_gate",
            "v0_7_release_accepted",
            "observation_constructs_implemented",
            "product_artifacts_implemented",
            "operational_authorization",
            "deployment_approval",
            "compliance_determination",
            "cryptographic_signature_verified",
        ):
            with self.subTest(claim=claim):
                payload = copy.deepcopy(self.scope)
                payload["claims"][claim] = True
                self.assertTrue(self.validate(payload))

    def test_boolean_cannot_substitute_for_zero_delta(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["compatibility_delta"]["compatibility_ledger_rows_added"] = False
        self.assertTrue(any("type differs" in item for item in self.validate(payload)))

    def test_exclusions_are_closed_and_ordered(self) -> None:
        for operation in ("remove", "replace", "reorder"):
            with self.subTest(operation=operation):
                payload = copy.deepcopy(self.scope)
                exclusions = payload["explicit_exclusions"]
                if operation == "remove":
                    exclusions.pop()
                elif operation == "replace":
                    exclusions[0] = "ALLOW_ALL_V07_SCOPE"
                else:
                    exclusions.reverse()
                self.assertTrue(self.validate(payload))

    def test_baseline_object_blob_and_artifact_bindings_cannot_change(self) -> None:
        mutations = {
            "tag_ref": "refs/tags/v0.7.0",
            "tag_object_type": "commit",
            "tag_object_id": "0" * 40,
            "raw_tag_object_sha256": "0" * 64,
            "peeled_release_commit": "0" * 40,
            "qualified_source_commit": "0" * 40,
            "candidate_commit": "0" * 40,
            "source_fingerprint_sha256": "0" * 64,
            "evidence_fingerprint_sha256": "0" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["accepted_baseline"][field] = replacement
                self.assertTrue(self.validate(payload))

        for section, field in (
            ("tagged_blobs", "SPELL_v0.6_Release.md"),
            ("accepted_artifact_pair", "archive_sha256"),
        ):
            payload = copy.deepcopy(self.scope)
            if section == "tagged_blobs":
                payload["accepted_baseline"][section][field]["sha256"] = "0" * 64
            else:
                payload["accepted_baseline"][section][field] = "0" * 64
            self.assertTrue(self.validate(payload))

    def test_contract_inventory_and_all_seven_hashes_are_exact(self) -> None:
        contracts = self.scope["authorization_contracts"]
        self.assertEqual(contracts["matrix_count"], 6)
        self.assertEqual(contracts["file_count"], 7)
        self.assertEqual(contracts["files_sha256"], validate_v07_gate_0a.CONTRACTS_SHA256)
        self.assertEqual(validate_v07_gate_0a.validate_contract_directory(), [])

        for name in validate_v07_gate_0a.CONTRACTS_SHA256:
            with self.subTest(name=name):
                payload = copy.deepcopy(self.scope)
                payload["authorization_contracts"]["files_sha256"][name] = "0" * 64
                self.assertTrue(self.validate(payload))

    def test_contract_directory_rejects_extra_and_mutated_files(self) -> None:
        source = validate_v07_gate_0a.WORKSPACE_ROOT / "contracts" / "v07"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "v07"
            shutil.copytree(source, target)
            (target / "extra.json").write_text("{}\n", encoding="utf-8")
            errors = validate_v07_gate_0a.validate_contract_directory(target)
            self.assertTrue(any("inventory differs" in item for item in errors))

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "v07"
            shutil.copytree(source, target)
            (target / "condition_engine.json").write_bytes(b'{"x":1,"x":2}\n')
            errors = validate_v07_gate_0a.validate_contract_directory(target)
            self.assertTrue(any("duplicate JSON key" in item for item in errors))

    def test_strict_json_rejects_duplicate_non_finite_and_oversized_input(self) -> None:
        payloads = (
            b'{"status":"PENDING","status":"PASS"}',
            b'{"delta":NaN}',
            b'{"delta":Infinity}',
            b" " * (512 * 1024 + 1),
        )
        for index, raw in enumerate(payloads):
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_v07_gate_0a.parse_strict_json(raw, "test", 512 * 1024)

    def test_accepted_annotated_tag_blobs_ancestry_and_pair_validate(self) -> None:
        raw_tag = validate_v07_gate_0a.run_git(
            ["cat-file", "tag", validate_v07_gate_0a.TAG_OBJECT_ID]
        ).stdout

        self.assertEqual(validate_v07_gate_0a.validate_tag_payload(raw_tag), [])
        self.assertEqual(validate_v07_gate_0a.validate_git_baseline(), [])

    def test_tag_byte_header_and_owner_marker_mutations_are_rejected(self) -> None:
        raw_tag = validate_v07_gate_0a.run_git(
            ["cat-file", "tag", validate_v07_gate_0a.TAG_OBJECT_ID]
        ).stdout
        byte_errors = validate_v07_gate_0a.validate_tag_payload(raw_tag + b" ")
        marker_errors = validate_v07_gate_0a.validate_tag_payload(
            raw_tag.replace(b"Owner: JC Arcaz", b"Owner: Unverified Actor", 1)
        )
        header_errors = validate_v07_gate_0a.validate_tag_payload(
            raw_tag.replace(b"tag v0.6.0", b"tag v0.7.0", 1)
        )

        self.assertTrue(any("SHA-256 differs" in item for item in byte_errors))
        self.assertTrue(any("Owner: JC Arcaz" in item for item in marker_errors))
        self.assertTrue(any("object ID" in item for item in marker_errors))
        self.assertTrue(any("headers differ" in item for item in header_errors))

    def test_wrong_tagged_blob_id_and_digest_are_rejected(self) -> None:
        path = "SPELL_v0.6_Release.md"
        expected = copy.deepcopy(validate_v07_gate_0a.TAGGED_BLOBS[path])
        expected["sha256"] = "0" * 64
        errors, _ = validate_v07_gate_0a._validate_tagged_blob(path, expected)
        self.assertTrue(any("blob SHA-256 differs" in item for item in errors))

        expected = copy.deepcopy(validate_v07_gate_0a.TAGGED_BLOBS[path])
        expected["object_id"] = validate_v07_gate_0a.TAGGED_BLOBS[
            "artifacts/v0.6/release-qualification.json"
        ]["object_id"]
        errors, _ = validate_v07_gate_0a._validate_tagged_blob(path, expected)
        self.assertTrue(any("tree entry differs" in item for item in errors))
        self.assertTrue(any("blob ID differs" in item for item in errors))

    def test_archive_and_sidecar_byte_mutations_are_rejected(self) -> None:
        archive = (validate_v07_gate_0a.WORKSPACE_ROOT / validate_v07_gate_0a.ARCHIVE_PATH).read_bytes()
        sidecar = validate_v07_gate_0a.SIDECAR_BYTES

        archive_errors = validate_v07_gate_0a.validate_archive_sidecar(
            archive + b"x", sidecar, "mutated"
        )
        sidecar_errors = validate_v07_gate_0a.validate_archive_sidecar(
            archive, sidecar.replace(b"  ", b" ", 1), "mutated"
        )

        self.assertTrue(any("archive SHA-256 differs" in item for item in archive_errors))
        self.assertTrue(any("sidecar" in item for item in sidecar_errors))

    def _valid_document_lines(self) -> list[str]:
        return [
            "# SPELL v0.7 Pre-Implementation Gate 0A",
            "| Gate status | `PASS`; `V07-OBS-001` through `V07-OBS-009` are authorized |",
            "| Owner approval date | 2026-08-16 |",
            f"| Owner request | `{validate_v07_gate_0a.OWNER_REQUEST}` |",
            "| Authorized work packages | `V07-OBS-001` through `V07-OBS-009` |",
            "| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |",
            validate_v07_gate_0a.OWNER_APPROVAL_MARKER,
            *[
                f"| `V07-OBS-{index:03d}` | Package | Proof |"
                for index in range(1, 10)
            ],
            *[
                f"| `contracts/v07/{name}` | `{digest}` |"
                for name, digest in validate_v07_gate_0a.CONTRACTS_SHA256.items()
            ],
            validate_v07_gate_0a.PASS_MARKER,
            "`V07-GATE-0A PASS` authorizes implementation of exactly `V07-OBS-001` through",
            "`V07-OBS-009`. It claims zero implemented constructs and zero implemented",
        ]

    def test_accepted_document_markers_validate_exactly(self) -> None:
        self.assertEqual(
            validate_v07_gate_0a.validate_document_lines(self._valid_document_lines()),
            [],
        )
        self.assertEqual(validate_v07_gate_0a.validate_document(), [])

    def test_missing_owner_zero_claim_or_contract_marker_fails_document(self) -> None:
        for marker in (
            validate_v07_gate_0a.OWNER_APPROVAL_MARKER,
            "`V07-OBS-009`. It claims zero implemented constructs and zero implemented",
            (
                "| `contracts/v07/manifest.json` | "
                f"`{validate_v07_gate_0a.CONTRACTS_SHA256['manifest.json']}` |"
            ),
        ):
            with self.subTest(marker=marker):
                lines = self._valid_document_lines()
                lines.remove(marker)
                self.assertTrue(validate_v07_gate_0a.validate_document_lines(lines))

    def test_failed_scope_summary_never_reports_pass(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["approval_mechanics"]["authorized_work_package_ids"].pop()
        errors, summary = validate_v07_gate_0a.validate_scope_payload(payload)

        self.assertTrue(errors)
        self.assertEqual(summary["gate"], "FAIL")
        self.assertEqual(summary["authorized_work_packages"], 8)
        self.assertEqual(summary["proposed_work_packages"], 9)
        self.assertEqual(summary["claimed_constructs"], 0)
        self.assertEqual(summary["claimed_artifacts"], 0)


if __name__ == "__main__":
    unittest.main()
