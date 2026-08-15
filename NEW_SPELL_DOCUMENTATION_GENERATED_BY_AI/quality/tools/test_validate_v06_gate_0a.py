from __future__ import annotations

import contextlib
import copy
import io
import tempfile
import unittest
from pathlib import Path

import validate_v06_gate_0a


class GateV06ZeroAValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scope = validate_v06_gate_0a.read_json()

    def validate(self, payload: object | None = None) -> list[str]:
        candidate = copy.deepcopy(self.scope) if payload is None else payload
        return validate_v06_gate_0a.validate_scope(candidate)

    def test_repository_reports_exact_pass_summary(self) -> None:
        errors, summary = validate_v06_gate_0a.validate_repository()

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
            result = validate_v06_gate_0a.main()

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(), validate_v06_gate_0a.PASS_MARKER + "\n"
        )

    def test_scope_matches_independent_compiled_contract(self) -> None:
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.scope, validate_v06_gate_0a.EXPECTED_SCOPE)
        self.assertIsNot(
            self.scope["proposed_work_packages"],
            validate_v06_gate_0a.WORK_PACKAGES,
        )
        self.assertIsNot(
            self.scope["accepted_baseline"]["tagged_files_sha256"],
            validate_v06_gate_0a.TAGGED_FILES_SHA256,
        )

    def test_top_level_and_authority_boundary_keys_are_exact(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["second_gate_decision"] = {"status": "PASS"}
        self.assertTrue(any("unauthorized keys" in item for item in self.validate(payload)))

        for section in (
            "decision",
            "approval_mechanics",
            "accepted_baseline",
            "compatibility_delta",
            "claims",
        ):
            with self.subTest(section=section):
                payload = copy.deepcopy(self.scope)
                payload[section]["unreviewed_extension"] = True
                errors = self.validate(payload)
                self.assertTrue(
                    any(
                        f"scope.{section} has unauthorized keys" in item
                        for item in errors
                    )
                )

    def test_approved_gate_cannot_be_narrowed_or_redirected(self) -> None:
        mutations = (
            ("status", "PENDING_OWNER_APPROVAL"),
            ("decision.approval_date", "2026-08-16"),
            ("decision.authorization", "NONE"),
            ("decision.owner_approval_recorded", False),
            ("approval_mechanics.marker_present", False),
            (
                "approval_mechanics.authorized_work_package_ids",
                ["V06-OP-001", "V06-OP-002"],
            ),
            ("claims.v0_6_implementation_authorized", False),
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

    def test_decision_identity_request_and_precondition_are_fixed(self) -> None:
        replacements = {
            "owner": "automated-agent",
            "proposal_date": "2026-08-16",
            "owner_request": "approve all product work",
            "precondition": "UNVERIFIED_BASELINE",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["decision"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_nine_package_ids_are_ordered_unique_and_explicitly_authorized(self) -> None:
        packages = self.scope["proposed_work_packages"]
        ids = [item["work_package_id"] for item in packages]

        self.assertEqual(ids, [f"V06-OP-{index:03d}" for index in range(1, 10)])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(
            all(item["status"] == "IMPLEMENTATION_AUTHORIZED" for item in packages)
        )
        self.assertEqual(
            self.scope["approval_mechanics"]["authorized_work_package_ids"], ids
        )

    def test_package_identity_boundary_and_tests_cannot_expand(self) -> None:
        for index in range(9):
            for field, replacement in (
                ("title", "Unbounded operator features"),
                ("status", "PROPOSED_NOT_AUTHORIZED"),
                ("capability_boundary", "ALL_CAPABILITIES"),
            ):
                with self.subTest(index=index, field=field):
                    payload = copy.deepcopy(self.scope)
                    payload["proposed_work_packages"][index][field] = replacement
                    self.assertTrue(self.validate(payload))

            payload = copy.deepcopy(self.scope)
            payload["proposed_work_packages"][index]["planned_test_ids"].append(
                f"V06-OP-{index + 1:03d}-UNREVIEWED"
            )
            self.assertTrue(self.validate(payload))

    def test_compatibility_delta_cannot_claim_new_surface(self) -> None:
        mutations = {
            "accepted_ir_versions": ["0.3", "0.4"],
            "new_ir_versions": ["0.4"],
            "claimed_construct_ids": ["StartProc"],
            "claimed_artifact_ids": ["CMP-V06-STARTPROC"],
            "compatibility_ledger_rows_added": 1,
            "v0_5_scope_rows_changed": 1,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["compatibility_delta"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_boolean_cannot_substitute_for_zero_delta(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["compatibility_delta"]["compatibility_ledger_rows_added"] = False

        self.assertTrue(
            any("type differs" in item for item in self.validate(payload))
        )

    def test_claims_and_exclusions_are_closed_and_ordered(self) -> None:
        for claim, expected in self.scope["claims"].items():
            with self.subTest(claim=claim):
                payload = copy.deepcopy(self.scope)
                payload["claims"][claim] = not expected
                self.assertTrue(self.validate(payload))

        for operation in ("remove", "replace", "reorder"):
            with self.subTest(operation=operation):
                payload = copy.deepcopy(self.scope)
                exclusions = payload["explicit_exclusions"]
                if operation == "remove":
                    exclusions.pop()
                elif operation == "replace":
                    exclusions[0] = "ALLOW_ALL_V06_SCOPE"
                else:
                    exclusions.reverse()
                self.assertTrue(self.validate(payload))

    def test_baseline_bindings_cannot_be_redirected_or_rehashed(self) -> None:
        mutations = {
            "tag_ref": "refs/tags/v0.6.0",
            "tag_object_type": "commit",
            "tag_object_id": "0" * 40,
            "raw_tag_object_sha256": "0" * 64,
            "peeled_release_commit": "0" * 40,
            "qualified_source_commit": "0" * 40,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["accepted_baseline"][field] = replacement
                self.assertTrue(self.validate(payload))

        payload = copy.deepcopy(self.scope)
        first_path = next(iter(validate_v06_gate_0a.TAGGED_FILES_SHA256))
        payload["accepted_baseline"]["tagged_files_sha256"][first_path] = "0" * 64
        self.assertTrue(self.validate(payload))

    def test_strict_json_rejects_duplicate_non_finite_and_oversized_input(self) -> None:
        payloads = (
            b'{"status":"PENDING","status":"PASS"}',
            b'{"delta":NaN}',
            b'{"delta":Infinity}',
            b" " * (512 * 1024 + 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, raw in enumerate(payloads):
                with self.subTest(index=index):
                    path = Path(directory) / f"invalid-{index}.json"
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        validate_v06_gate_0a.read_json(path)

    def test_accepted_annotated_tag_and_tagged_evidence_validate(self) -> None:
        raw_tag = validate_v06_gate_0a.run_git(
            ["cat-file", "tag", validate_v06_gate_0a.TAG_OBJECT_ID]
        ).stdout

        self.assertEqual(validate_v06_gate_0a.validate_tag_payload(raw_tag), [])
        self.assertEqual(validate_v06_gate_0a.validate_git_baseline(), [])

    def test_tag_byte_and_owner_marker_mutations_are_rejected(self) -> None:
        raw_tag = validate_v06_gate_0a.run_git(
            ["cat-file", "tag", validate_v06_gate_0a.TAG_OBJECT_ID]
        ).stdout
        byte_errors = validate_v06_gate_0a.validate_tag_payload(raw_tag + b" ")
        marker_errors = validate_v06_gate_0a.validate_tag_payload(
            raw_tag.replace(b"Owner: JC Arcaz", b"Owner: Unverified Actor", 1)
        )

        self.assertTrue(any("SHA-256 differs" in item for item in byte_errors))
        self.assertTrue(any("Owner: JC Arcaz" in item for item in marker_errors))
        self.assertTrue(any("object ID" in item for item in marker_errors))

    def test_wrong_tagged_file_digest_is_rejected_independently(self) -> None:
        errors = validate_v06_gate_0a._validate_tagged_file(
            "SPELL_v0.5_Release.md",
            "0" * 64,
            validate_v06_gate_0a.WORKSPACE_ROOT,
        )

        self.assertTrue(any("tagged baseline SHA-256 differs" in item for item in errors))

    def _valid_document_lines(self) -> list[str]:
        return [
            "# SPELL v0.6 Pre-Implementation Gate 0A",
            "| Gate status | `PASS`; `V06-OP-001` through `V06-OP-009` are authorized |",
            "| Owner approval date | 2026-08-15 |",
            "| Authorized work packages | `V06-OP-001` through `V06-OP-009` |",
            "| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |",
            validate_v06_gate_0a.OWNER_APPROVAL_MARKER,
            *[
                f"| `V06-OP-{index:03d}` | Package | Proof |"
                for index in range(1, 10)
            ],
            validate_v06_gate_0a.PASS_MARKER,
            "`V06-GATE-0A PASS` authorizes implementation of exactly `V06-OP-001` through",
        ]

    def test_accepted_document_markers_validate_exactly(self) -> None:
        self.assertEqual(
            validate_v06_gate_0a.validate_document_lines(
                self._valid_document_lines()
            ),
            [],
        )
        self.assertEqual(validate_v06_gate_0a.validate_document(), [])

    def test_missing_or_duplicate_owner_approval_marker_fails_gate(self) -> None:
        lines = self._valid_document_lines()
        lines.remove(validate_v06_gate_0a.OWNER_APPROVAL_MARKER)

        errors = validate_v06_gate_0a.validate_document_lines(lines)

        self.assertTrue(any("OWNER-APPROVAL" in item for item in errors))

        duplicated = self._valid_document_lines()
        duplicated.append(validate_v06_gate_0a.OWNER_APPROVAL_MARKER)
        self.assertTrue(validate_v06_gate_0a.validate_document_lines(duplicated))

    def test_missing_pass_marker_or_package_row_is_rejected(self) -> None:
        missing_marker = self._valid_document_lines()
        missing_marker.remove(validate_v06_gate_0a.PASS_MARKER)
        missing_package = self._valid_document_lines()
        missing_package = [
            line
            for line in missing_package
            if not line.startswith("| `V06-OP-009` |")
        ]

        self.assertTrue(validate_v06_gate_0a.validate_document_lines(missing_marker))
        self.assertTrue(validate_v06_gate_0a.validate_document_lines(missing_package))

    def test_failed_scope_summary_never_reports_pass_as_valid(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["approval_mechanics"]["authorized_work_package_ids"].pop()

        errors, summary = validate_v06_gate_0a.validate_scope_payload(payload)

        self.assertTrue(errors)
        self.assertEqual(summary["gate"], "FAIL")
        self.assertEqual(summary["authorized_work_packages"], 8)
        self.assertEqual(summary["proposed_work_packages"], 9)


if __name__ == "__main__":
    unittest.main()
