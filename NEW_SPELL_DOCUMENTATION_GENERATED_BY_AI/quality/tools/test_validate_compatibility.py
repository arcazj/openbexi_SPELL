from __future__ import annotations

import copy
import unittest

import validate_compatibility


class CompatibilityValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = validate_compatibility.read_json(
            validate_compatibility.INVENTORY_PATH
        )
        cls.ledger = validate_compatibility.read_json(
            validate_compatibility.LEDGER_PATH
        )
        cls.scope = validate_compatibility.read_json(
            validate_compatibility.SCOPE_PATH
        )
        cls.technical_review = validate_compatibility.read_json(
            validate_compatibility.TECHNICAL_REVIEW_PATH
        )

    def validate(
        self,
        inventory: dict | None = None,
        ledger: dict | None = None,
        scope: dict | None = None,
    ) -> tuple[list[str], dict]:
        return validate_compatibility.validate_payloads(
            copy.deepcopy(self.inventory) if inventory is None else inventory,
            copy.deepcopy(self.ledger) if ledger is None else ledger,
            copy.deepcopy(self.scope) if scope is None else scope,
        )

    def test_repository_scope_is_exhaustive_and_reconciled(self) -> None:
        errors, summary = validate_compatibility.validate_repository()

        self.assertEqual(errors, [])
        self.assertEqual(
            summary["row_count"], validate_compatibility.EXPECTED_SCOPE_TOTAL
        )
        self.assertEqual(
            summary["example_count"],
            validate_compatibility.EXPECTED_NORMATIVE_EXAMPLES,
        )
        self.assertEqual(
            summary["v0_4_rows"], validate_compatibility.EXPECTED_V04_ROWS
        )
        self.assertEqual(
            summary["deferred_rows"],
            validate_compatibility.EXPECTED_DEFERRED_ROWS,
        )
        self.assertEqual(summary["source_count"], 7)
        self.assertEqual(summary["approved_rows"], summary["row_count"])
        self.assertEqual(summary["implemented_rows"], 0)
        self.assertEqual(summary["verified_rows"], 0)
        self.assertTrue(summary["scope_reconciled"])
        self.assertTrue(summary["global_reconciled"])
        self.assertTrue(summary["technical_review_verified"])

    def test_technical_review_is_digest_bound_and_has_bounded_claims(self) -> None:
        self.assertEqual(
            validate_compatibility.validate_technical_review(
                self.technical_review,
                self.ledger,
            ),
            [],
        )
        review = copy.deepcopy(self.technical_review)
        review["source_results"][0]["canonical_rows_sha256"] = "0" * 64
        review["claims"]["human_approval"] = True

        errors = validate_compatibility.validate_technical_review(
            review,
            self.ledger,
        )

        self.assertTrue(
            any("canonical rows digest differs" in error for error in errors)
        )
        self.assertIn("compatibility technical review claims differ", errors)

    def test_every_source_has_exact_cardinality_and_complete_pages(self) -> None:
        actual = {
            source["source_code"]: len(source["artifacts"])
            for source in self.inventory["sources"]
        }

        self.assertEqual(actual, validate_compatibility.EXPECTED_SCOPE_COUNTS)
        for source in self.inventory["sources"]:
            self.assertTrue(
                source["inventory_complete_for_local_v0_4_disposition"]
            )
            self.assertEqual(
                source["reviewed_page_slices"],
                [f"1-{source['page_count']}"],
            )

    def test_missing_ledger_row_is_rejected(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"].pop()

        errors, summary = self.validate(ledger=ledger)

        self.assertTrue(errors)
        self.assertFalse(summary["global_reconciled"])
        self.assertTrue(
            any("inventory/ledger mismatch" in error for error in errors)
        )

    def test_duplicate_row_and_test_vector_are_rejected(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"][-1] = copy.deepcopy(ledger["rows"][0])

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("duplicate compatibility ledger row" in error for error in errors)
        )
        self.assertTrue(
            any("duplicate compatibility test vectors" in error for error in errors)
        )

    def test_forged_source_hash_is_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        inventory["sources"][0]["source_hash"] = "0" * 64

        errors, _ = self.validate(inventory=inventory)

        self.assertTrue(any("source hash differs" in error for error in errors))

    def test_out_of_range_page_is_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        source = inventory["sources"][0]
        source["artifacts"][0]["Pages"] = str(source["page_count"] + 1)

        errors, _ = self.validate(inventory=inventory)

        self.assertTrue(any("exceeds 1-" in error for error in errors))

    def test_approval_state_and_row_status_cannot_be_forged(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["approval_state"] = "APPROVED"
        ledger["rows"][0]["Status"] = "Implemented"

        errors, summary = self.validate(ledger=ledger)

        self.assertTrue(
            any("ledger approval state differs" in error for error in errors)
        )
        self.assertTrue(any("status differs" in error for error in errors))
        self.assertEqual(
            summary["approved_rows"],
            validate_compatibility.EXPECTED_SCOPE_TOTAL - 1,
        )
        self.assertFalse(summary["global_reconciled"])

    def test_approval_limit_disclaims_row_by_row_owner_review(self) -> None:
        self.assertIn("personally reviewed", self.ledger["approval_limit"])
        ledger = copy.deepcopy(self.ledger)
        ledger["approval_limit"] = "Candidate A scope disposition only"

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("approval limit omits" in error for error in errors)
        )

    def test_scope_omission_is_rejected(self) -> None:
        scope = copy.deepcopy(self.scope)
        scope["artifact_ids"].pop()

        errors, _ = self.validate(scope=scope)

        self.assertTrue(
            any("does not match inventory and ledger" in error for error in errors)
        )

    def test_coordinated_artifact_replacement_breaks_independent_pins(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        ledger = copy.deepcopy(self.ledger)
        scope = copy.deepcopy(self.scope)
        original = inventory["sources"][0]["artifacts"][0]["ArtifactId"]
        replacement = f"{original}-REPLACED"
        inventory["sources"][0]["artifacts"][0]["ArtifactId"] = replacement
        ledger_row = next(
            row for row in ledger["rows"] if row["ArtifactId"] == original
        )
        ledger_row["ArtifactId"] = replacement
        ledger_row["TestVectors"] = (
            f"NGV-{replacement}{validate_compatibility.PLANNED_TEST_SUFFIX}"
        )
        scope["artifact_ids"][scope["artifact_ids"].index(original)] = replacement
        scope["artifact_ids"].sort()

        errors, _ = self.validate(inventory, ledger, scope)

        self.assertTrue(
            any("artifact manifest differs" in error for error in errors)
        )
        self.assertTrue(any("ledger rows differ" in error for error in errors))

    def test_whitespace_only_semantic_field_is_rejected(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"][0]["LegacyResult"] = "   "

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("empty or non-string fields" in error for error in errors)
        )

    def test_reviewed_slices_must_cover_full_source(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        inventory["sources"][0]["reviewed_page_slices"] = ["1-117"]

        errors, _ = self.validate(inventory=inventory)

        self.assertTrue(
            any("do not cover the full source" in error for error in errors)
        )

    def test_duplicate_source_record_is_rejected(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        inventory["sources"].append(copy.deepcopy(inventory["sources"][0]))

        errors, _ = self.validate(inventory=inventory)

        self.assertTrue(
            any("source record cardinality" in error for error in errors)
        )
        self.assertTrue(
            any("duplicate compatibility source code" in error for error in errors)
        )

    def test_deferred_row_must_be_excluded_and_not_advertised(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        row = next(
            item for item in ledger["rows"]
            if item["TargetIncrement"] == "Deferred"
        )
        row["Disposition"] = "SAFE"
        row["DriverCapability"] = "ADVERTISED"

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(any("deferred row must be EXCLUDE" in e for e in errors))
        self.assertTrue(any("deferred capability differs" in e for e in errors))

    def test_v0_4_row_cannot_have_unresolved_disposition(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        row = next(
            item for item in ledger["rows"] if item["TargetIncrement"] == "v0.4"
        )
        row["Disposition"] = "AMBIG"

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("in-scope row has unresolved disposition" in e for e in errors)
        )

    def test_planned_test_identity_is_unique_and_derived(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"][1]["TestVectors"] = ledger["rows"][0]["TestVectors"]

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(any("test-vector identity differs" in e for e in errors))
        self.assertTrue(
            any("duplicate compatibility test vectors" in e for e in errors)
        )

    def test_owner_scope_reference_cannot_erase_technical_rationale(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"][0]["Decision"] = "V04-OWNER-20260718"

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("technical rationale differs" in error for error in errors)
        )

    def test_scope_cannot_make_implementation_or_external_claims(self) -> None:
        scope = copy.deepcopy(self.scope)
        scope["implementation_claim"] = True
        scope["operational_authorization"] = True
        scope["compliance_determination"] = True

        errors, _ = self.validate(scope=scope)

        self.assertTrue(
            any("implementation_claim differs" in error for error in errors)
        )
        self.assertTrue(
            any("operational_authorization differs" in error for error in errors)
        )
        self.assertTrue(
            any("compliance_determination differs" in error for error in errors)
        )

    def test_every_row_has_an_explicit_error_or_errata_disposition(self) -> None:
        self.assertTrue(
            all(row["LegacyErrors"].strip() for row in self.ledger["rows"])
        )
        ledger = copy.deepcopy(self.ledger)
        ledger["rows"][0]["LegacyErrors"] = " "

        errors, _ = self.validate(ledger=ledger)

        self.assertTrue(
            any("empty or non-string fields" in error for error in errors)
        )

    def test_reconciliation_is_digest_bound_and_globally_complete(self) -> None:
        digests = {
            "ledger": validate_compatibility.sha256_file(
                validate_compatibility.LEDGER_PATH
            ),
            "scope": validate_compatibility.sha256_file(
                validate_compatibility.SCOPE_PATH
            ),
            "source_inventory": validate_compatibility.sha256_file(
                validate_compatibility.INVENTORY_PATH
            ),
        }
        expected = validate_compatibility.build_reconciliation(
            self.inventory,
            self.ledger,
            self.scope,
            digests,
        )
        actual = validate_compatibility.read_json(
            validate_compatibility.RECONCILIATION_PATH
        )

        self.assertEqual(actual, expected)
        self.assertTrue(actual["scope_reconciled"])
        self.assertTrue(actual["global_reconciled"])
        self.assertTrue(actual["local_v0_4_disposition_complete"])
        self.assertEqual(actual["blocking_gaps"], [])
        self.assertEqual(actual["counts"]["implemented_rows"], 0)
        self.assertEqual(actual["counts"]["verified_rows"], 0)
        self.assertTrue(actual["deferred_non_claims"])


if __name__ == "__main__":
    unittest.main()
