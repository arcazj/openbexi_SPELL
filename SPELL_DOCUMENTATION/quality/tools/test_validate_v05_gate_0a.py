from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import validate_v05_gate_0a


class GateV05ZeroAValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scope = validate_v05_gate_0a.read_json()

    def validate(self, payload: object | None = None) -> list[str]:
        candidate = copy.deepcopy(self.scope) if payload is None else payload
        return validate_v05_gate_0a.validate_scope(candidate)

    def test_repository_gate_passes_with_exact_summary(self) -> None:
        errors, summary = validate_v05_gate_0a.validate_repository()

        self.assertEqual(errors, [])
        self.assertEqual(
            summary,
            {
                "gate": "PASS",
                "work_packages": 1,
                "claimed_constructs": 0,
                "claimed_artifacts": 0,
            },
        )

    def test_main_prints_only_the_required_success_marker(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = validate_v05_gate_0a.main()

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(),
            "gate=PASS work_packages=1 claimed_constructs=0 claimed_artifacts=0\n",
        )

    def test_scope_matches_an_independent_compiled_in_contract(self) -> None:
        self.assertEqual(self.validate(), [])
        self.assertEqual(self.scope, validate_v05_gate_0a.EXPECTED_SCOPE)
        self.assertIsNot(
            self.scope["accepted_baseline"]["tagged_files_sha256"],
            validate_v05_gate_0a.TAGGED_FILES_SHA256,
        )

    def test_top_level_keys_are_exact(self) -> None:
        missing = copy.deepcopy(self.scope)
        missing.pop("explicit_exclusions")
        extra = copy.deepcopy(self.scope)
        extra["second_authorized_work_package"] = {"id": "V05-IR-002"}

        self.assertTrue(any("missing keys" in error for error in self.validate(missing)))
        self.assertTrue(
            any("unauthorized keys" in error for error in self.validate(extra))
        )

    def test_nested_keys_are_exact_at_every_authority_boundary(self) -> None:
        for section in (
            "decision",
            "accepted_baseline",
            "compatibility_delta",
            "authorized_work_package",
            "claims",
        ):
            with self.subTest(section=section):
                payload = copy.deepcopy(self.scope)
                payload[section]["unreviewed_extension"] = True
                errors = self.validate(payload)
                self.assertTrue(
                    any(
                        f"scope.{section} has unauthorized keys" in error
                        for error in errors
                    )
                )

    def test_decision_identity_and_precondition_cannot_be_forged(self) -> None:
        mutations = {
            "owner": "automated-agent",
            "decision_date": "2026-08-13",
            "authorization": "ALL_V05_WORK",
            "owner_request": "start all of v0.5",
            "precondition": "UNVERIFIED_BASELINE",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["decision"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_only_v05_ir_001_can_be_authorized(self) -> None:
        mutations = {
            "work_package_id": "V05-IR-002",
            "title": "Broader language implementation",
            "status": "IMPLEMENTED",
            "accepted_ir_version": "0.4",
            "failure_boundary": "REJECT_AFTER_WORKER_STARTED",
            "persistence_policy": "MIGRATE_AND_REWRITE_IR",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["authorized_work_package"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_authorized_change_allowlist_is_complete_ordered_and_closed(self) -> None:
        payloads = []
        removed = copy.deepcopy(self.scope)
        removed["authorized_work_package"]["authorized_changes"].pop()
        payloads.append(removed)
        reordered = copy.deepcopy(self.scope)
        reordered["authorized_work_package"]["authorized_changes"].reverse()
        payloads.append(reordered)
        broadened = copy.deepcopy(self.scope)
        broadened["authorized_work_package"]["authorized_changes"].append(
            "SOURCE_TO_IR_REPARSE_OR_INTEGRITY_EXPANSION"
        )
        payloads.append(broadened)

        for payload in payloads:
            with self.subTest(changes=payload["authorized_work_package"]["authorized_changes"]):
                self.assertTrue(self.validate(payload))

    def test_all_six_planned_test_ids_are_exact_and_unique(self) -> None:
        test_ids = self.scope["authorized_work_package"]["planned_test_ids"]
        self.assertEqual(len(test_ids), 6)
        self.assertEqual(len(set(test_ids)), 6)

        for operation in ("remove", "duplicate", "replace"):
            with self.subTest(operation=operation):
                payload = copy.deepcopy(self.scope)
                ids = payload["authorized_work_package"]["planned_test_ids"]
                if operation == "remove":
                    ids.pop()
                elif operation == "duplicate":
                    ids[-1] = ids[0]
                else:
                    ids[-1] = "V05-IR-002-UNIT"
                self.assertTrue(self.validate(payload))

    def test_compatibility_delta_cannot_claim_new_surface(self) -> None:
        mutations = {
            "accepted_ir_versions": ["0.3", "0.4"],
            "new_ir_versions": ["0.4"],
            "claimed_construct_ids": ["TIME"],
            "claimed_artifact_ids": ["CMP-LRM244-TIME"],
            "compatibility_ledger_rows_added": 1,
            "v0_4_scope_rows_changed": 1,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["compatibility_delta"][field] = replacement
                self.assertTrue(self.validate(payload))

    def test_claims_cannot_be_broadened_or_downgraded(self) -> None:
        for claim, expected in self.scope["claims"].items():
            with self.subTest(claim=claim):
                payload = copy.deepcopy(self.scope)
                payload["claims"][claim] = not expected
                errors = self.validate(payload)
                self.assertTrue(any(f"scope.claims.{claim}" in error for error in errors))

    def test_json_boolean_cannot_substitute_for_zero_delta(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["compatibility_delta"]["compatibility_ledger_rows_added"] = False

        errors = self.validate(payload)

        self.assertTrue(any("type differs" in error for error in errors))

    def test_baseline_bindings_cannot_be_redirected_or_rehashed(self) -> None:
        baseline_mutations = {
            "tag_ref": "refs/tags/v0.4.1",
            "tag_object_type": "commit",
            "tag_object_id": "0" * 40,
            "raw_tag_object_sha256": "0" * 64,
            "peeled_commit": "0" * 40,
        }
        for field, replacement in baseline_mutations.items():
            with self.subTest(field=field):
                payload = copy.deepcopy(self.scope)
                payload["accepted_baseline"][field] = replacement
                self.assertTrue(self.validate(payload))

        payload = copy.deepcopy(self.scope)
        first_path = next(iter(validate_v05_gate_0a.TAGGED_FILES_SHA256))
        payload["accepted_baseline"]["tagged_files_sha256"][first_path] = "0" * 64
        self.assertTrue(self.validate(payload))

    def test_every_explicit_exclusion_is_required_in_order(self) -> None:
        for operation in ("remove", "replace", "reorder"):
            with self.subTest(operation=operation):
                payload = copy.deepcopy(self.scope)
                exclusions = payload["explicit_exclusions"]
                if operation == "remove":
                    exclusions.pop()
                elif operation == "replace":
                    exclusions[0] = "ALLOW_ALL_V05_SCOPE"
                else:
                    exclusions.reverse()
                self.assertTrue(self.validate(payload))

    def test_strict_json_rejects_duplicate_keys_and_non_finite_values(self) -> None:
        payloads = (
            '{"schema_version":"one","schema_version":"two"}',
            '{"delta":NaN}',
            '{"delta":Infinity}',
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, text in enumerate(payloads):
                with self.subTest(text=text):
                    path = Path(directory) / f"invalid-{index}.json"
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        validate_v05_gate_0a.read_json(path)

    def test_annotated_tag_raw_bytes_and_required_markers_validate(self) -> None:
        raw_tag = validate_v05_gate_0a.run_git(
            ["cat-file", "tag", validate_v05_gate_0a.TAG_OBJECT_ID]
        ).stdout

        self.assertEqual(validate_v05_gate_0a.validate_tag_payload(raw_tag), [])

    def test_any_tag_byte_or_required_marker_mutation_is_rejected(self) -> None:
        raw_tag = validate_v05_gate_0a.run_git(
            ["cat-file", "tag", validate_v05_gate_0a.TAG_OBJECT_ID]
        ).stdout
        byte_mutation = raw_tag + b" "
        marker_mutation = raw_tag.replace(
            b"Owner: JC Arcaz", b"Owner: Unverified Actor", 1
        )

        self.assertTrue(
            any(
                "raw tag object SHA-256 differs" in error
                for error in validate_v05_gate_0a.validate_tag_payload(byte_mutation)
            )
        )
        marker_errors = validate_v05_gate_0a.validate_tag_payload(marker_mutation)
        self.assertTrue(any("Owner: JC Arcaz" in error for error in marker_errors))
        self.assertTrue(any("tag object ID" in error for error in marker_errors))

    def test_git_baseline_is_annotated_ancestral_and_byte_identical(self) -> None:
        self.assertEqual(validate_v05_gate_0a.validate_git_baseline(), [])

    def test_wrong_tagged_file_digest_is_rejected_independently(self) -> None:
        relative_path = "SPELL_v0.4_Release.md"

        errors = validate_v05_gate_0a._validate_tagged_file(
            relative_path,
            "0" * 64,
            validate_v05_gate_0a.WORKSPACE_ROOT,
        )

        self.assertTrue(any("tagged baseline SHA-256 differs" in error for error in errors))
        self.assertTrue(any("working baseline SHA-256 differs" in error for error in errors))

    def _valid_document_lines(self) -> dict[str, list[str]]:
        return {
            "SPELL_v0.5_Pre-Implementation.md": [
                "# SPELL v0.5 Pre-Implementation Gate 0A"
            ],
            "Test_and_Integration.md": ["## Version 0.5 Gate 0A Test Plan"],
            "PROJECT_ROADMAP.md": [
                "### v0.5 - Core Language And Deterministic Runtime",
                "#### Current Gate 0A Authorization",
                "### v0.6 - Durable Operator Workspace And Procedure Composition",
            ],
            "PROMPT_History.md": [
                "# Prompt History",
                "## 2026-08-12 - v0.4.0 Accepted And v0.5 Gate 0A Opened",
                "## 2026-07-18 - Earlier",
            ],
            "VERSION_TIMELINE.md": [
                "# OpenBEXI SPELL Version Timeline",
                "## 2026-08-12 - v0.5 Gate 0A",
                "## 2026-07-18 - Earlier",
            ],
        }

    def test_document_marker_contract_accepts_exact_placement(self) -> None:
        self.assertEqual(
            validate_v05_gate_0a.validate_document_lines(
                self._valid_document_lines()
            ),
            [],
        )
        self.assertEqual(validate_v05_gate_0a.validate_document_markers(), [])

    def test_missing_or_duplicate_document_marker_is_rejected(self) -> None:
        missing = self._valid_document_lines()
        missing["Test_and_Integration.md"] = []
        duplicated = self._valid_document_lines()
        duplicated["SPELL_v0.5_Pre-Implementation.md"].append(
            "# SPELL v0.5 Pre-Implementation Gate 0A"
        )

        self.assertTrue(validate_v05_gate_0a.validate_document_lines(missing))
        self.assertTrue(validate_v05_gate_0a.validate_document_lines(duplicated))

    def test_gate_heading_outside_v05_roadmap_section_is_rejected(self) -> None:
        documents = self._valid_document_lines()
        documents["PROJECT_ROADMAP.md"] = [
            "#### Current Gate 0A Authorization",
            "### v0.5 - Core Language And Deterministic Runtime",
            "### v0.6 - Durable Operator Workspace And Procedure Composition",
        ]

        errors = validate_v05_gate_0a.validate_document_lines(documents)

        self.assertTrue(any("roadmap v0.5 section" in error for error in errors))

    def test_gate_history_entries_must_be_newest(self) -> None:
        for relative_path in ("PROMPT_History.md", "VERSION_TIMELINE.md"):
            with self.subTest(relative_path=relative_path):
                documents = self._valid_document_lines()
                lines = documents[relative_path]
                lines.insert(1, "## 2026-08-13 - Unauthorized Later Entry")
                errors = validate_v05_gate_0a.validate_document_lines(documents)
                self.assertTrue(
                    any(
                        f"newest dated entry differs in {relative_path}" in error
                        for error in errors
                    )
                )

    def test_failed_scope_summary_does_not_report_gate_pass(self) -> None:
        payload = copy.deepcopy(self.scope)
        payload["compatibility_delta"]["claimed_construct_ids"] = ["TIME"]

        errors, summary = validate_v05_gate_0a.validate_scope_payload(payload)

        self.assertTrue(errors)
        self.assertEqual(summary["gate"], "FAIL")
        self.assertEqual(summary["work_packages"], 1)
        self.assertEqual(summary["claimed_constructs"], 1)
        self.assertEqual(summary["claimed_artifacts"], 0)


if __name__ == "__main__":
    unittest.main()
