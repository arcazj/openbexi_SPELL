from __future__ import annotations

import copy
import unittest
from pathlib import Path

import validate_g0


class GateZeroValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.requirements = validate_g0.parse_requirements()
        cls.rules = validate_g0.load_rules()
        cls.expected = validate_g0.build_expected_allocation(
            cls.requirements,
            cls.rules,
        )

    def gate_inputs(self) -> tuple[list[dict[str, str]], dict, dict, dict]:
        actual, read_errors = validate_g0.read_allocation()
        self.assertEqual(read_errors, [])
        evidence_errors, evidence = validate_g0.validate_approval_evidence(
            validate_g0.load_approval_evidence()
        )
        self.assertEqual(evidence_errors, [])
        compatibility_errors, compatibility = (
            validate_g0.analyze_compatibility_evidence()
        )
        self.assertEqual(compatibility_errors, [])
        gate_errors, gate_input_summary = (
            validate_g0.validate_gate_input_structure(self.rules)
        )
        self.assertEqual(gate_errors, [])
        return actual, evidence, compatibility, gate_input_summary

    def test_central_register_and_rules_are_complete(self) -> None:
        self.assertEqual(len(self.requirements), 366)
        self.assertEqual(validate_g0.validate_rules(self.rules), [])
        self.assertEqual(
            validate_g0.validate_central_register(self.requirements, self.rules),
            [],
        )

    def test_generated_allocation_matches_controlled_rules(self) -> None:
        actual, read_errors = validate_g0.read_allocation()

        self.assertEqual(read_errors, [])
        self.assertEqual(len(actual), 366)
        self.assertEqual(validate_g0.validate_allocation(actual, self.expected), [])
        self.assertEqual(
            {row["approval_status"] for row in actual},
            {"OUTSIDE_LOCAL_V04_GATE"},
        )

    def test_broader_approver_metadata_is_informational_only(self) -> None:
        rows = {row["requirement_id"]: row for row in self.expected}

        self.assertEqual(
            rows["MODE-025"]["required_approvers"], "PO, MO, SA, SY, SO"
        )
        self.assertEqual(
            rows["MODE-027"]["required_approvers"], "MO, SA, SY, SO, CM"
        )
        self.assertTrue(
            all(
                row["approval_status"] == "OUTSIDE_LOCAL_V04_GATE"
                for row in rows.values()
            )
        )
        self.assertEqual(self.rules["g0"]["required_signer_roles"], ["Project owner"])
        self.assertEqual(self.rules["g0"]["required_adrs"], [])
        self.assertEqual(self.rules["g0"]["blocking_decisions"], [])

    def test_requirement_digest_binds_all_normative_fields(self) -> None:
        baseline = validate_g0.Requirement("MODE-999", "Statement", "T", "SO")
        variants = (
            validate_g0.Requirement("MODE-998", "Statement", "T", "SO"),
            validate_g0.Requirement("MODE-999", "Changed", "T", "SO"),
            validate_g0.Requirement("MODE-999", "Statement", "I,T", "SO"),
            validate_g0.Requirement("MODE-999", "Statement", "T", "MO"),
        )
        for variant in variants:
            self.assertNotEqual(baseline.record_digest, variant.record_digest)

    def test_owner_approval_is_exact_and_binds_scope_disposition(self) -> None:
        evidence = copy.deepcopy(validate_g0.load_approval_evidence())
        errors, summary = validate_g0.validate_approval_evidence(evidence)

        self.assertEqual(errors, [])
        self.assertTrue(summary["owner_scope_approval_valid"])
        self.assertTrue(summary["manifest_verified"])
        self.assertTrue(summary["compatibility_scope_approval_verified"])
        self.assertFalse(summary["cryptographic_signature_verified"])
        self.assertFalse(summary["identity_cryptographically_verified"])
        self.assertEqual(summary["records_present"], 1)
        self.assertFalse(
            evidence["compatibility_disposition"]
            ["owner_row_by_row_source_review_claimed"]
        )
        self.assertFalse(evidence["claims"]["operational_authorization"])
        self.assertFalse(evidence["claims"]["compliance_determination"])
        self.assertTrue(evidence["claims"]["implementation_authorized"])
        self.assertFalse(evidence["claims"]["release_accepted"])

    def test_changed_owner_authorization_is_rejected(self) -> None:
        evidence = copy.deepcopy(validate_g0.load_approval_evidence())
        evidence["approval"]["authorization_text"] = "approve everything"
        errors, summary = validate_g0.validate_approval_evidence(evidence)

        self.assertIn(
            "G0 owner approval does not match the recorded instruction",
            errors,
        )
        self.assertFalse(summary["owner_scope_approval_valid"])

    def test_changed_scope_disposition_policy_is_rejected(self) -> None:
        evidence = copy.deepcopy(validate_g0.load_approval_evidence())
        evidence["compatibility_disposition"]["deferred_policy"] = (
            "Advertise every legacy feature"
        )

        errors, summary = validate_g0.validate_approval_evidence(evidence)

        self.assertIn("G0 compatibility scope-disposition policy differs", errors)
        self.assertFalse(summary["compatibility_scope_approval_verified"])

    def test_owner_record_cannot_fabricate_external_claims(self) -> None:
        evidence = copy.deepcopy(validate_g0.load_approval_evidence())
        evidence["approval"]["cryptographic_signature"] = "not-a-signature"
        evidence["claims"]["cryptographic_signature_verified"] = True
        evidence["claims"]["operational_authorization"] = True
        evidence["claims"]["compliance_determination"] = True

        errors, summary = validate_g0.validate_approval_evidence(evidence)

        self.assertIn("G0 owner record claims differ", errors)
        self.assertFalse(summary["cryptographic_signature_verified"])
        self.assertFalse(summary["owner_scope_approval_valid"])

    def test_local_gate_has_no_organization_only_blockers(self) -> None:
        actual, evidence, compatibility, gate_inputs = self.gate_inputs()

        blockers, summary = validate_g0.collect_gate_blockers(
            actual, self.rules, evidence, compatibility, gate_inputs
        )

        self.assertEqual(blockers, [])
        self.assertEqual(summary["broader_spec_rows_outside_local_gate"], 366)
        self.assertEqual(summary["unresolved_local_entry_decisions"], [])

    def test_global_compatibility_failure_remains_a_technical_blocker(self) -> None:
        actual, evidence, compatibility, gate_inputs = self.gate_inputs()
        compatibility = copy.deepcopy(compatibility)
        compatibility["global_reconciled"] = False

        blockers, _ = validate_g0.collect_gate_blockers(
            actual, self.rules, evidence, compatibility, gate_inputs
        )

        self.assertEqual(
            {blocker["code"] for blocker in blockers},
            {"DETAILED_COMPATIBILITY_EVIDENCE_INCOMPLETE"},
        )

    def test_scope_binding_failure_remains_a_technical_blocker(self) -> None:
        actual, evidence, compatibility, gate_inputs = self.gate_inputs()
        evidence = copy.deepcopy(evidence)
        evidence["compatibility_scope_approval_verified"] = False

        blockers, _ = validate_g0.collect_gate_blockers(
            actual, self.rules, evidence, compatibility, gate_inputs
        )

        self.assertEqual(
            {blocker["code"] for blocker in blockers},
            {"DETAILED_COMPATIBILITY_EVIDENCE_INCOMPLETE"},
        )

    def test_owner_record_rejects_changed_baseline_binding(self) -> None:
        evidence = copy.deepcopy(validate_g0.load_approval_evidence())
        first_path = validate_g0.LOCAL_BASELINE_ARTIFACTS[0]
        evidence["baseline_binding"]["artifacts"][first_path] = "0" * 64

        errors, summary = validate_g0.validate_approval_evidence(evidence)

        self.assertTrue(any("artifact changed" in error for error in errors))
        self.assertFalse(summary["owner_scope_approval_valid"])
        self.assertFalse(summary["manifest_verified"])
        self.assertFalse(summary["compatibility_scope_approval_verified"])

    def test_header_only_compatibility_table_does_not_clear_gate(self) -> None:
        header = "| " + " | ".join(validate_g0.COMPATIBILITY_COLUMNS) + " |"
        separator = "| " + " | ".join(
            "---" for _ in validate_g0.COMPATIBILITY_COLUMNS
        ) + " |"

        errors, summary = validate_g0.analyze_compatibility_evidence(
            f"{header}\n{separator}\n"
        )

        self.assertEqual(errors, [])
        self.assertTrue(summary["schema_valid"])
        self.assertEqual(summary["row_count"], 0)
        self.assertFalse(summary["scope_reconciled"])

    def test_gate_exit_codes_are_explicit(self) -> None:
        blockers = [{"code": "TECHNICAL_GATE_FAILED"}]
        self.assertEqual(validate_g0.determine_exit_code([], blockers, False), 2)
        self.assertEqual(validate_g0.determine_exit_code([], blockers, True), 0)
        self.assertEqual(
            validate_g0.determine_exit_code(["invalid"], blockers, True), 1
        )
        self.assertEqual(validate_g0.determine_exit_code([], [], False), 0)

    def test_report_output_cannot_bypass_canonical_freshness(self) -> None:
        with self.assertRaises(ValueError):
            validate_g0.resolve_report_destination(Path("quality/other.json"))
        self.assertEqual(
            validate_g0.resolve_report_destination(
                Path("quality/G0_READINESS_REPORT.json")
            ),
            validate_g0.REPORT_PATH.resolve(),
        )

    def test_qualification_runtime_pin_is_enforced(self) -> None:
        self.assertEqual(validate_g0.validate_runtime(self.rules, "3.13"), [])
        self.assertNotEqual(validate_g0.validate_runtime(self.rules, "3.12"), [])

    def test_source_authority_matches_the_pinned_seven_pdf_set(self) -> None:
        errors, checked = validate_g0.validate_source_hashes()

        self.assertEqual(errors, [])
        self.assertEqual(checked, 7)


if __name__ == "__main__":
    unittest.main()
