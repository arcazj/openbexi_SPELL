#!/usr/bin/env python3
"""Execute and assemble fail-closed SPELL v0.4 Gate 1-5 evidence.

Repository-local acceptance checks have fixed command recipes. Checks that
need a composed runtime, browser, packet capture, performance harness, image
scanner, or platform installer require a collector command. A collector must
exit successfully and print a source-bound JSON result as its final non-empty
stdout line. Partial results stay below ``artifacts/v0.4/.qualification`` and
cannot be mistaken for release evidence.

Examples::

    python scripts/qualify_v04.py plan
    python scripts/qualify_v04.py run --gate 1
    python scripts/qualify_v04.py collect --test-id V04-PERF-001 -- command ...
    python scripts/qualify_v04.py status
    python scripts/qualify_v04.py publish
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.supply_provenance_v04 import (
    SUPPORTED_TEST_IDS as SUPPLY_PROVENANCE_TEST_IDS,
    canonical_directory as canonical_supply_directory,
    copy_validated_corpus as copy_validated_supply_corpus,
    staged_directory as staged_supply_directory,
    validate_supply_corpus,
)
from scripts.validate_release_evidence_v04 import (
    EVIDENCE_DIRECTORY,
    EVIDENCE_SCHEMA_VERSION,
    EXPECTED_TEST_IDS,
    GATE_REPORTS,
    GATE_TEST_IDS,
    PRODUCT_VERSION,
    SBOM_DIRECTORY,
    SCOPE_PROFILE,
    SEMANTIC_VALIDATORS,
    TEST_EVIDENCE_DIRECTORY,
    TEST_EVIDENCE_SCHEMA_VERSION,
    validate_release_evidence_v04,
    validate_product_package_binding_v04,
    validate_sboms_v04,
)


COLLECTOR_MAP_SCHEMA_VERSION = "spell.v04.collector-map/1"
STAGING_DIRECTORY = EVIDENCE_DIRECTORY / ".qualification"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 3600.0
PROCESS_TERMINATION_GRACE_SECONDS = 2.0
PROCESS_TERMINATION_FORCE_SECONDS = 10.0
PROCESS_TERMINATION_POLL_SECONDS = 0.05
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PYTEST_PASSED_PATTERN = re.compile(r"(?m)(\d+) passed")
PYTEST_SKIPPED_PATTERN = re.compile(r"(?m)(\d+) skipped")
UNSAFE_ARG_PATTERN = re.compile(
    r"(?i)(?:authorization:\s*bearer\s+|(?:password|private[-_]?key|secret|token)=.+)"
)
FORBIDDEN_ACCEPTANCE_CLAIMS = {
    "release_accepted",
    "acceptance_recorded",
    "operationally_approved",
    "compliance_approved",
}


class QualificationError(RuntimeError):
    """A command or evidence input failed a v0.4 qualification invariant."""


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    assertion_id: str
    structured: bool = False
    require_pytest_pass: bool = False


@dataclass(frozen=True)
class Recipe:
    commands: tuple[CommandSpec, ...]
    reason: str

    @property
    def collector_required(self) -> bool:
        return not self.commands


def _pytest(reason: str, *nodes: str) -> Recipe:
    return Recipe(
        commands=(
            CommandSpec(
                argv=("{python}", "-m", "pytest", "-q", *nodes),
                assertion_id="targeted-pytest-suite-passed-without-skips",
                require_pytest_pass=True,
            ),
        ),
        reason=reason,
    )


def _command(reason: str, *argv: str) -> Recipe:
    return Recipe(
        commands=(CommandSpec(tuple(argv), "command-completed-successfully"),),
        reason=reason,
    )


def _external(reason: str) -> Recipe:
    return Recipe(commands=(), reason=reason)


def _scope_recipe() -> Recipe:
    return Recipe(
        commands=(
            CommandSpec(
                (
                    "{python}",
                    "-m",
                    "pytest",
                    "-q",
                    "driver_host/tests/test_service.py::test_protobuf_exposes_exactly_one_nine_method_unary_infrastructure_service",
                ),
                "wire-service-test-passed-without-skips",
                require_pytest_pass=True,
            ),
            CommandSpec(
                ("{python}", "scripts/qualify_v04.py", "--root", "{root}", "_probe-scope-001"),
                "descriptor-probe-passed",
                structured=True,
            ),
        ),
        reason="Exact descriptor surface, unary shape, and typed payload inspection.",
    )


RECIPES: dict[str, Recipe] = {
    # Gate 1: controlled scope, contract, state, configuration, and migration.
    "V04-DOC-001": _command(
        "Gate 0 approval, traceability, and controlled-input freshness.",
        "{python}",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
    ),
    "V04-DOC-002": _command(
        "Controlled source inventory, hashes, page accounting, and review metadata.",
        "{python}",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
    ),
    "V04-DOC-003": _command(
        "Exhaustive compatibility ledger and reconciliation.",
        "{python}",
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py",
    ),
    "V04-BOUND-001": _pytest(
        "Configuration rejects ambiguous or non-simulator driver selection.",
        "backend/tests/test_config.py::test_settings_from_env_rejects_ambiguous_driver_enablement",
        "driver_host/tests/test_config.py::test_host_config_rejects_malformed_or_out_of_bounds_input",
    ),
    "V04-SCOPE-001": _scope_recipe(),
    "V04-SCOPE-002": _external(
        "Requires an accepted v0.3 Telemetry run with a live driver and before/after RPC, context, binding, operation, and journal counters."
    ),
    "V04-CON-001": _external(
        "Requires two offline protobuf generations using the hash-locked generator toolchain installed in the qualification image."
    ),
    "V04-CON-002": _external(
        "Requires the complete major/minor, field reuse, enum, semantic-change, and untyped-payload compatibility matrix using the hash-locked generator toolchain installed in the qualification image."
    ),
    "V04-CON-003": _external(
        "Requires bounded wire fuzzing for malformed, truncated, oversized, nested, conflicting, and unsafe-error payloads."
    ),
    "V04-CON-004": _pytest(
        "Handshake binds the exact contract, host identity, capabilities, and capacity.",
        "driver_host/tests/test_service.py::test_handshake_reports_exact_identity_capabilities_capacity_and_typed_mismatch",
        "backend/tests/test_driver_gateway.py::test_start_uses_exact_factory_arguments_and_persists_the_exact_handshake",
    ),
    "V04-CON-005": _pytest(
        "Contract and lifecycle identity mismatches fail before effect.",
        "backend/tests/test_driver_gateway.py::test_handshake_mismatch_fails_closed_and_closes_the_client",
        "backend/tests/test_driver_gateway.py::test_context_tuple_mismatch_fails_before_acceptance_or_rpc",
        "driver_host/tests/test_service.py::test_stale_wire_identity_is_typed_and_never_dispatched",
    ),
    "V04-CTX-001": _pytest(
        "Stable layered identities and generation fences are persisted and enforced.",
        "backend/tests/test_driver_persistence.py::test_operation_history_is_idempotent_fenced_and_retries_only_after_no_effect",
        "driver_host/tests/test_service.py::test_stale_wire_identity_is_typed_and_never_dispatched",
    ),
    "V04-CTX-002": _pytest(
        "Context, attachment, operation, and procedure states remain distinct through reload.",
        "driver_host/tests/test_lifecycle.py::test_happy_path_reload_and_reverse_cleanup_order",
        "backend/tests/test_driver_persistence.py::test_context_binding_generations_release_capacity_only_after_cleanup",
    ),
    "V04-CFG-001": _pytest(
        "Canonical typed host, context, and attachment digests are deterministic.",
        "driver_host/tests/test_config.py::test_host_config_loads_only_typed_allowlisted_values",
        "backend/tests/test_driver_persistence.py::test_default_profile_is_disabled_and_bound_to_canonical_typed_configuration",
    ),
    "V04-CFG-002": _pytest(
        "Unknown, malformed, unsafe, and out-of-bounds configuration fails closed.",
        "driver_host/tests/test_config.py::test_host_config_rejects_malformed_or_out_of_bounds_input",
        "driver_host/tests/test_config.py::test_nested_config_bounds_are_enforced",
        "driver_host/tests/test_config.py::test_host_config_requires_a_regular_file",
    ),
    "V04-CFG-003": _pytest(
        "Host restart and child reopen/reload generation transitions are deterministic.",
        "driver_host/tests/test_config.py::test_default_host_generations_are_unique",
        "driver_host/tests/test_lifecycle.py::test_happy_path_reload_and_reverse_cleanup_order",
        "driver_host/tests/test_journal.py::test_one_ledger_retains_attempts_across_host_generations",
    ),
    "V04-CFG-004": _pytest(
        "Credential epochs and the complete configuration identity tuple are fenced.",
        "backend/tests/test_driver_mtls.py::test_stale_credential_epoch_fails_before_dispatch",
        "backend/tests/test_driver_persistence.py::test_operation_history_is_idempotent_fenced_and_retries_only_after_no_effect",
    ),
    "V04-CAP-001": _pytest(
        "Capabilities are granular and match the exact infrastructure service.",
        "driver_host/tests/test_service.py::test_handshake_reports_exact_identity_capabilities_capacity_and_typed_mismatch",
        "backend/tests/test_driver_persistence.py::test_host_requires_enabled_profile_and_exact_nine_rpc_capabilities",
    ),
    "V04-CAP-002": _pytest(
        "Named capacities reject before effect and release exactly once at cleanup or reconciliation.",
        "driver_host/tests/test_lifecycle.py::test_in_flight_and_journal_capacity_fail_before_a_second_effect",
        "driver_host/tests/test_journal.py::test_entry_capacity_rejects_without_evicting_evidence",
        "backend/tests/test_driver_persistence.py::test_host_lifecycle_capacity_fails_closed_before_acceptance",
        "backend/tests/test_driver_persistence.py::test_failed_binding_releases_capacity_once_and_retains_reload_fence",
        "backend/tests/test_driver_persistence.py::test_reconciliation_releases_operation_capacity_exactly_once",
    ),
    "V04-LIFE-001": _pytest(
        "The host, context, and attachment state tables follow approved transitions.",
        "driver_host/tests/test_lifecycle.py::test_visible_intermediate_states_and_drain_transition",
        "driver_host/tests/test_lifecycle.py::test_happy_path_reload_and_reverse_cleanup_order",
    ),
    "V04-LIFE-002": _pytest(
        "Lifecycle mutation, cancellation, and settled-race idempotency.",
        "driver_host/tests/test_lifecycle.py::test_deadline_cancellation_and_already_settled_race",
        "driver_host/tests/test_service.py::test_wire_mutation_health_reconciliation_duplicate_and_digest_conflict",
    ),
    "V04-LIFE-003": _pytest(
        "Partial failure, Health admission, repeated cleanup, drain, and restart remain bounded and visible.",
        "driver_host/tests/test_lifecycle.py::test_duplicate_replay_after_restart_has_no_second_effect_and_conflict_is_safe",
        "driver_host/tests/test_lifecycle.py::test_drain_grace_expiry_leaves_uncertain_evidence_and_failed_host",
        "backend/tests/test_driver_gateway.py::test_handshake_without_health_denies_mutation_and_pending_reconciliation",
        "backend/tests/test_driver_gateway.py::test_rejected_health_immediately_denies_mutation_and_reconciliation",
        "backend/tests/test_driver_gateway.py::test_health_persistence_failure_revokes_admission_until_valid_refresh",
    ),
    "V04-LIFE-004": _pytest(
        "Hook ordering, reverse cleanup, compensation, and cleanup failure are explicit.",
        "driver_host/tests/test_lifecycle.py::test_happy_path_reload_and_reverse_cleanup_order",
        "driver_host/tests/test_lifecycle.py::test_setup_failure_compensates_completed_context_hooks_in_reverse",
        "driver_host/tests/test_lifecycle.py::test_attachment_failure_compensates_and_cleanup_failure_does_not_short_circuit",
    ),
    "V04-MIG-001": _pytest(
        "Fresh SQLite/PostgreSQL schemas are equivalent and disabled by default.",
        "backend/tests/test_migrations.py::test_migrations_create_fresh_schema_and_are_idempotent",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
    ),
    "V04-MIG-002": _external(
        "Requires populated accepted-v0.3 SQLite and PostgreSQL fixtures and full record comparison."
    ),
    "V04-MIG-003": _pytest(
        "Repeated migration is a no-op and an injected failure rolls back.",
        "backend/tests/test_migrations.py::test_migrations_create_fresh_schema_and_are_idempotent",
        "backend/tests/test_migrations.py::test_failed_migration_rolls_back_and_remains_pending",
        "backend/tests/test_migrations.py::test_migrations_reject_unknown_or_gapped_history",
    ),
    "V04-MIG-004": _external(
        "Requires backup, restore, rollback, unsafe-state refusal, tombstone retention, and restored-v0.3 behavior across both databases."
    ),
    "V04-SEC-004": _external(
        "Requires composed reflection, proxy-route, JWT-as-service-identity, unauthorized-metadata, and direct-administration probes with audit inspection."
    ),

    # Gate 2: isolation, security, deadlines, journal, and recovery faults.
    "V04-BOUND-002": _external(
        "Requires packet capture and connection-log analysis across nominal and fault runs."
    ),
    "V04-ISO-001": _pytest(
        "A created driver container has the approved runtime isolation controls.",
        "backend/tests/test_driver_isolation.py::test_compose_statically_isolates_and_hardens_the_driver",
        "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    ),
    "V04-ISO-002": _pytest(
        "Workers have no product call path or usable credential and identities fail closed.",
        "backend/tests/test_driver_isolation.py::test_gateway_consumes_credentials_before_the_application_accepts_work",
        "backend/tests/test_driver_isolation.py::test_spawned_worker_has_no_driver_product_call_path_or_credential_argument",
        "backend/tests/test_driver_mtls.py::test_missing_client_identity_and_wrong_client_ca_fail_before_dispatch",
    ),
    "V04-ISO-003": _external(
        "Requires composed driver kill/wedge injection while proxy, API, worker, and database liveness and stale projection are observed."
    ),
    "V04-ISO-004": _external(
        "Requires network-namespace reachability and DNS probes from the driver container."
    ),
    "V04-SEC-001": _pytest(
        "Current mutual identity succeeds and invalid trust, role, revocation, expiry, and epoch fail before dispatch.",
        "backend/tests/test_driver_mtls.py",
    ),
    "V04-SEC-002": _external(
        "Requires live certificate/secret rotation, audited epoch increment, old-credential rejection, and trust-set comparison."
    ),
    "V04-SEC-003": _external(
        "Requires a canary scan over worker, browser, bundle, API, logs, events, reports, screenshots, SBOMs, and package, returning required leak metrics."
    ),
    "V04-DEAD-001": _pytest(
        "Already-expired lifecycle requests reject before dispatch with authoritative no effect.",
        "backend/tests/test_driver_gateway.py::test_expired_deadline_settles_no_effect_without_dispatch",
        "driver_host/tests/test_lifecycle.py::test_deadline_cancellation_and_already_settled_race",
    ),
    "V04-DEAD-002": _pytest(
        "Deadline expiry during setup and cleanup follows the certainty table.",
        "driver_host/tests/test_lifecycle.py::test_deadline_during_setup_compensates_completed_hooks_with_no_effect",
        "driver_host/tests/test_lifecycle.py::test_deadline_during_cleanup_completes_with_confirmed_effect",
    ),
    "V04-DEAD-003": _pytest(
        "Transport cancellation and lifecycle cancellation preserve target certainty.",
        "driver_host/tests/test_lifecycle.py::test_deadline_cancellation_and_already_settled_race",
        "driver_host/tests/test_service.py::test_wire_mutation_health_reconciliation_duplicate_and_digest_conflict",
    ),
    "V04-DEAD-004": _external(
        "Requires process-level forced termination after grace and reconciliation of every accepted operation."
    ),
    "V04-OP-001": _pytest(
        "Acceptance stores stable operation identity before dispatch and database failure dispatches nothing.",
        "backend/tests/test_driver_gateway.py::test_lifecycle_persists_dispatch_before_rpc_and_records_settled_result",
        "backend/tests/test_driver_persistence.py::test_transition_and_outbox_are_atomic_on_persistence_failure",
    ),
    "V04-OP-002": _pytest(
        "Sequential and concurrent retry deduplicate one attempt and one simulator effect.",
        "driver_host/tests/test_lifecycle.py::test_duplicate_replay_after_restart_has_no_second_effect_and_conflict_is_safe",
        "backend/tests/test_driver_gateway.py::test_lost_response_latches_reconciliation_and_repeat_never_resends",
    ),
    "V04-OP-003": _pytest(
        "Private-journal restart replay deduplicates exact identity and rejects conflicts.",
        "driver_host/tests/test_journal.py::test_accept_is_idempotent_and_conflicting_digest_is_rejected",
        "driver_host/tests/test_journal.py::test_new_attempt_requires_durable_no_effect_proof",
        "driver_host/tests/test_lifecycle.py::test_duplicate_replay_after_restart_has_no_second_effect_and_conflict_is_safe",
    ),
    "V04-OP-004": _pytest(
        "Stage and certainty histories cover terminal, timeout, cancellation, and stale cases.",
        "driver_host/tests/test_journal.py::test_transition_history_and_terminal_disposition_survive_reopen",
        "driver_host/tests/test_lifecycle.py::test_deadline_cancellation_and_already_settled_race",
        "backend/tests/test_driver_gateway.py::test_mismatched_lifecycle_result_becomes_effect_unknown",
        "backend/tests/test_driver_gateway.py::test_reconciliation_normalizes_invalid_driver_stage_certainty_pairs",
    ),
    "V04-OP-005": _pytest(
        "Regressive, duplicate, conflicting, late, and competing outcomes cannot overwrite authority.",
        "backend/tests/test_driver_persistence.py::test_operation_history_is_idempotent_fenced_and_retries_only_after_no_effect",
        "backend/tests/test_driver_gateway.py::test_reconciliation_uses_only_get_operation_and_settles_same_attempt",
    ),
    "V04-OP-006": _pytest(
        "Possible or unknown effect remains latched and is never automatically resent.",
        "backend/tests/test_driver_gateway.py::test_lost_response_latches_reconciliation_and_repeat_never_resends",
        "backend/tests/test_driver_gateway.py::test_startup_reconciles_all_unresolved_operations_without_resending_mutations",
        "backend/tests/test_driver_gateway.py::test_reconciliation_normalizes_invalid_driver_stage_certainty_pairs",
        "driver_host/tests/test_lifecycle.py::test_drain_grace_expiry_leaves_uncertain_evidence_and_failed_host",
    ),
    "V04-JRN-001": _external(
        "Requires process crash injection at every intent/effect/result/reply/project-commit boundary."
    ),
    "V04-JRN-002": _pytest(
        "Journal quota and integrity failures fail closed without redispatch.",
        "driver_host/tests/test_journal.py::test_entry_capacity_rejects_without_evicting_evidence",
        "driver_host/tests/test_journal.py::test_missing_symlinked_truncated_and_checksum_invalid_storage_fails_closed",
        "driver_host/tests/test_lifecycle.py::test_in_flight_and_journal_capacity_fail_before_a_second_effect",
    ),
    "V04-JRN-003": _pytest(
        "Generation fencing, retirement witnesses, and no-ID-reuse evidence survive.",
        "driver_host/tests/test_journal.py::test_one_ledger_retains_attempts_across_host_generations",
        "driver_host/tests/test_journal.py::test_active_generation_witnesses_only_exact_covered_fenced_generation",
        "driver_host/tests/test_journal.py::test_retirement_rejects_fenced_generation_with_unlatched_acceptance",
        "driver_host/tests/test_journal.py::test_retirement_witness_cryptographically_binds_the_fenced_generation",
    ),
    "V04-REC-001": _pytest(
        "Operation, transition, audit, and outbox state commit atomically.",
        "backend/tests/test_driver_persistence.py::test_transition_and_outbox_are_atomic_on_persistence_failure",
    ),
    "V04-REC-002": _pytest(
        "Committed outbox events retain stable sequence and retry after publish failure.",
        "backend/tests/test_driver_gateway.py::test_outbox_relay_retries_stable_committed_sequence_and_closes_task",
        "backend/tests/test_driver_api.py::test_app_relays_only_committed_driver_outbox_events_on_fixed_hub_topic",
    ),
    "V04-REC-003": _external(
        "Requires API and driver process crash injection before/after dispatch/effect."
    ),
    "V04-REC-004": _pytest(
        "Lost acknowledgement reconciles by original operation ID without resend.",
        "backend/tests/test_driver_gateway.py::test_lost_response_latches_reconciliation_and_repeat_never_resends",
        "backend/tests/test_driver_gateway.py::test_reconciliation_uses_only_get_operation_and_settles_same_attempt",
    ),
    "V04-REC-005": _external(
        "Requires PostgreSQL outage injection before, during, and after driver response."
    ),
    "V04-REC-006": _pytest(
        "Startup and transport recovery reconcile only after same-generation Health admission.",
        "backend/tests/test_driver_gateway.py::test_startup_reconciles_all_unresolved_operations_without_resending_mutations",
        "backend/tests/test_driver_gateway.py::test_transport_recovery_handshake_automatically_reconciles_pending_operation",
        "backend/tests/test_driver_gateway.py::test_generation_change_waits_for_same_generation_health_before_reconcile",
    ),
    "V04-REC-007": _pytest(
        "Late or mismatched generation results remain evidence but cannot mutate current state.",
        "backend/tests/test_driver_gateway.py::test_mismatched_lifecycle_result_becomes_effect_unknown",
        "backend/tests/test_driver_gateway.py::test_reconciliation_normalizes_invalid_driver_stage_certainty_pairs",
        "driver_host/tests/test_service.py::test_new_host_generation_can_get_old_generation_operation_evidence",
    ),

    # Gate 3: authoritative read projection and real-browser behavior.
    "V04-API-001": _pytest(
        "Read-only authenticated driver resources are typed and bounded.",
        "backend/tests/test_driver_api.py::test_driver_projection_is_authenticated_read_only_and_disabled_by_default",
        "backend/tests/test_driver_api.py::test_driver_projection_has_exact_get_surface_and_bounded_queries",
        "backend/tests/test_driver_persistence.py::test_read_projection_cursor_is_typed_bounded_and_non_secret",
    ),
    "V04-API-002": _external(
        "Requires real REST/WebSocket downstream-only projection, endpoint/secret scan, and no synchronous browser-to-driver proxy."
    ),
    "V04-API-003": _external(
        "Requires the complete v0.3 replay/auth/expiry/revision/idempotency browser matrix plus competing reconciliation."
    ),
    "V04-UI-001": _external(
        "Requires desktop/mobile screenshots and assertions against a real backend/driver projection."
    ),
    "V04-UI-002": _external(
        "Requires real-backend degraded, disconnected, unsupported, stale, failed, and uncertain visual-state coverage."
    ),
    "V04-UI-003": _external(
        "Requires desktop/mobile Axe, keyboard, accessible-name, live-region, and overflow metrics."
    ),
    "V04-UI-004": _external(
        "Requires a browser network trace proving only approved loopback HTTP/WebSocket requests and no direct driver connection."
    ),
    "V04-REG-001": _external(
        "Requires structured accounting for all accepted-v0.3 SQLite, PostgreSQL, parser, worker, REST/WebSocket, auth, isolation, recovery, browser, accessibility, performance, audit, SBOM, and reproducibility suites."
    ),

    # Gate 4: measured composed-runtime budgets.
    "V04-PERF-001": _external(
        "Requires 1,000 measured health/status RPCs paced at 100/s."
    ),
    "V04-PERF-002": _external(
        "Requires 1,000 measured zero-delay lifecycle operations paced at 20/s."
    ),
    "V04-PERF-003": _external(
        "Requires 100 cancellation measurements and 25 process restart/reconciliation measurements."
    ),
    "V04-PERF-004": _external(
        "Requires the full ten-minute 20/s mixed-operation soak and memory sampling."
    ),

    # Gate 5: immutable images, inventories, reproducibility, and lifecycle.
    "V04-SC-001": _external(
        "Requires locked-input inspection and current Python, Node, image, and other approved audit tools."
    ),
    "V04-SC-002": _external(
        "Requires four current immutable images and their distinct CycloneDX inventories."
    ),
    "V04-SC-003": _external(
        "Requires image/source/package scanning for secrets, manuals, archives, journals, and hardening controls."
    ),
    "V04-SC-004": _external(
        "Requires two offline contract generations and two independent immutable-input package builds with shared evidence binding."
    ),
    "V04-SC-005": _external(
        "Requires v0.3/v0.4 path isolation and final package-manifest asset accounting."
    ),
    "V04-SC-006": _external(
        "Requires install, disabled-default, enable, upgrade, rollback, uninstall, and unsafe-state handling on every declared platform profile."
    ),
}


if set(RECIPES) != set(EXPECTED_TEST_IDS):
    missing = sorted(set(EXPECTED_TEST_IDS) - set(RECIPES))
    unexpected = sorted(set(RECIPES) - set(EXPECTED_TEST_IDS))
    raise RuntimeError(
        f"v0.4 recipe catalog mismatch; missing={missing!r} unexpected={unexpected!r}"
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _parse_json_strict(text: str, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise QualificationError(f"{label} contains duplicate object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise QualificationError(f"{label} contains non-finite number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise QualificationError(f"{label} is not strict JSON") from exc


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise QualificationError(f"refusing unsafe evidence output path: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()


def _reject_forbidden_claims(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_ACCEPTANCE_CLAIMS and item is True:
                raise QualificationError(f"{label} makes forbidden claim {key}")
            _reject_forbidden_claims(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_claims(item, label)
    elif isinstance(value, str) and "artifacts/v0.3" in value.replace("\\", "/").casefold():
        raise QualificationError(f"{label} references forbidden v0.3 evidence")


def _safe_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv or any(not isinstance(item, str) or not item or len(item) > 1024 for item in argv):
        raise QualificationError("collector argv must contain bounded non-empty strings")
    if any(UNSAFE_ARG_PATTERN.search(item) for item in argv):
        raise QualificationError("credential-like material is forbidden in recorded argv")
    return tuple(argv)


def _expand_argv(spec: CommandSpec, root: Path) -> tuple[str, ...]:
    substitutions = {"{python}": sys.executable, "{root}": str(root)}
    return _safe_argv(tuple(substitutions.get(item, item) for item in spec.argv))


def _staging_tests(root: Path, source: str) -> Path:
    return root / STAGING_DIRECTORY / source / "tests"


def _record_path(root: Path, source: str, test_id: str) -> Path:
    return _staging_tests(root, source) / f"{test_id}.json"


def _parse_structured_stdout(
    stdout: bytes, test_id: str, source: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QualificationError(f"{test_id} collector stdout is not UTF-8") from exc
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise QualificationError(f"{test_id} collector did not emit JSON")
    payload = _parse_json_strict(lines[-1], f"{test_id} collector final stdout line")
    if not isinstance(payload, dict):
        raise QualificationError(f"{test_id} collector result must be an object")
    _reject_forbidden_claims(payload, f"{test_id} collector")
    if payload.get("test_id") != test_id:
        raise QualificationError(f"{test_id} collector result has the wrong test_id")
    if payload.get("source_fingerprint_sha256") != source:
        raise QualificationError(f"{test_id} collector result has a stale source fingerprint")
    assertions_value = payload.get("assertions")
    if not isinstance(assertions_value, list) or not assertions_value:
        raise QualificationError(f"{test_id} collector assertions are empty")
    assertions: list[dict[str, Any]] = []
    observed_ids: set[str] = set()
    for value in assertions_value:
        if not isinstance(value, dict):
            raise QualificationError(f"{test_id} collector assertion is not an object")
        assertion_id = value.get("id")
        if not isinstance(assertion_id, str) or not assertion_id or len(assertion_id) > 256:
            raise QualificationError(f"{test_id} collector assertion id is invalid")
        if assertion_id in observed_ids:
            raise QualificationError(f"{test_id} collector assertion ids are not unique")
        if value.get("passed") is not True:
            raise QualificationError(f"{test_id} collector assertion did not pass: {assertion_id}")
        observed_ids.add(assertion_id)
        assertions.append({"id": assertion_id, "passed": True})
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise QualificationError(f"{test_id} collector metrics must be an object")
    try:
        _json_bytes(metrics)
    except (TypeError, ValueError) as exc:
        raise QualificationError(f"{test_id} collector metrics are not finite JSON") from exc
    validator = SEMANTIC_VALIDATORS.get(test_id)
    if validator is not None:
        try:
            validator(metrics, f"{test_id}.metrics", source)
        except ValueError as exc:
            raise QualificationError(str(exc)) from exc
    return assertions, metrics


def _run_command(
    argv: tuple[str, ...], root: Path, timeout_seconds: float
) -> tuple[subprocess.CompletedProcess[bytes], str, str]:
    process: subprocess.Popen[bytes] | None = None
    windows_job: _WindowsJob | None = None
    try:
        if os.name == "nt":
            windows_job = _WindowsJob()
            worker_argv = (
                sys.executable,
                str(Path(__file__).resolve()),
                "_windows-job-worker",
                "--",
                *argv,
            )
            process = subprocess.Popen(
                worker_argv,
                cwd=root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            windows_job.assign(process)
            if process.stdin is None:
                raise QualificationError("Windows command worker has no start pipe")
            process.stdin.write(b"\0")
            process.stdin.close()
            process.stdin = None
        else:
            process = subprocess.Popen(
                argv,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise QualificationError(
            f"command timed out after {timeout_seconds:g}s: {argv!r}"
        ) from exc
    except OSError as exc:
        raise QualificationError(f"cannot execute command: {argv!r}: {exc}") from exc
    finally:
        if process is not None:
            _terminate_process_tree(process, windows_job)
        elif windows_job is not None:
            windows_job.close()
    if process is None:
        raise QualificationError(f"cannot execute command: {argv!r}")
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    if len(result.stdout) > MAX_CAPTURE_BYTES or len(result.stderr) > MAX_CAPTURE_BYTES:
        raise QualificationError(f"command output exceeds {MAX_CAPTURE_BYTES} bytes: {argv!r}")
    return result, _sha256(result.stdout), _sha256(result.stderr)


class _WindowsJob:
    """A non-breakaway Windows Job Object owned by the qualifier process."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION = 9
    _BASIC_ACCOUNTING_INFORMATION = 1

    def __init__(self) -> None:
        if os.name != "nt":
            raise QualificationError("Windows Job Objects are unavailable on this platform")
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        )
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise QualificationError(f"cannot create Windows command job: {ctypes.WinError(ctypes.get_last_error())}")
        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle,
            self._EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel32.CloseHandle(handle)
            raise QualificationError(f"cannot configure Windows command job: {error}")
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self._accounting_type = BasicAccountingInformation
        self._handle: Any = handle

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if self._handle is None or not self._kernel32.AssignProcessToJobObject(
            self._handle, int(process._handle)  # type: ignore[attr-defined]
        ):
            error = self._ctypes.WinError(self._ctypes.get_last_error())
            raise QualificationError(f"cannot contain Windows command process: {error}")

    def _active_processes(self) -> int:
        if self._handle is None:
            return 0
        accounting = self._accounting_type()
        if not self._kernel32.QueryInformationJobObject(
            self._handle,
            self._BASIC_ACCOUNTING_INFORMATION,
            self._ctypes.byref(accounting),
            self._ctypes.sizeof(accounting),
            None,
        ):
            error = self._ctypes.WinError(self._ctypes.get_last_error())
            raise QualificationError(f"cannot inspect Windows command job: {error}")
        return int(accounting.ActiveProcesses)

    def terminate_remaining(self) -> None:
        if self._handle is None or self._active_processes() == 0:
            return
        if not self._kernel32.TerminateJobObject(self._handle, 1):
            error = self._ctypes.WinError(self._ctypes.get_last_error())
            raise QualificationError(f"cannot terminate Windows command job: {error}")
        deadline = time.monotonic() + PROCESS_TERMINATION_FORCE_SECONDS
        while self._active_processes() and time.monotonic() < deadline:
            time.sleep(PROCESS_TERMINATION_POLL_SECONDS)
        if self._active_processes():
            raise QualificationError("Windows command job still contains active processes")

    def close(self) -> None:
        if self._handle is None:
            return
        handle, self._handle = self._handle, None
        if not self._kernel32.CloseHandle(handle):
            error = self._ctypes.WinError(self._ctypes.get_last_error())
            raise QualificationError(f"cannot close Windows command job: {error}")


def _linux_process_group_members(process_group_id: int) -> tuple[set[int], set[int]] | None:
    """Return live and zombie members, or None when procfs cannot prove membership."""

    if not sys.platform.startswith("linux"):
        return None
    live: set[int] = set()
    zombies: set[int] = set()
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except OSError:
            return None
        closing_parenthesis = stat.rfind(")")
        fields = stat[closing_parenthesis + 2 :].split() if closing_parenthesis >= 0 else []
        if len(fields) < 3:
            return None
        if int(fields[2]) != process_group_id:
            continue
        pid = int(entry.name)
        (zombies if fields[0] == "Z" else live).add(pid)
    return live, zombies


def _posix_process_group_has_live_members(process_group_id: int) -> bool:
    members = _linux_process_group_members(process_group_id)
    if members is not None:
        return bool(members[0])
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_posix_process_group(process_group_id: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _posix_process_group_has_live_members(process_group_id):
        if time.monotonic() >= deadline:
            return False
        time.sleep(PROCESS_TERMINATION_POLL_SECONDS)
    return True


def _terminate_process_tree(
    process: subprocess.Popen[bytes], windows_job: _WindowsJob | None = None
) -> None:
    """Terminate and verify only the isolated tree for one qualification command."""

    if os.name == "nt":
        if windows_job is None:
            raise QualificationError("Windows command process has no containment job")
        try:
            if process.poll() is None:
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                    process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            windows_job.terminate_remaining()
            try:
                process.communicate(timeout=PROCESS_TERMINATION_FORCE_SECONDS)
            except subprocess.TimeoutExpired as exc:
                raise QualificationError(
                    f"command worker PID {process.pid} did not terminate"
                ) from exc
        finally:
            windows_job.close()
        return

    process_group_id = process.pid
    if _posix_process_group_has_live_members(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise QualificationError(
                f"cannot terminate command process group {process_group_id}"
            ) from exc
        if not _wait_for_posix_process_group(
            process_group_id, PROCESS_TERMINATION_GRACE_SECONDS
        ):
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise QualificationError(
                    f"cannot kill command process group {process_group_id}"
                ) from exc
    if not _wait_for_posix_process_group(
        process_group_id, PROCESS_TERMINATION_FORCE_SECONDS
    ):
        raise QualificationError(
            f"command process group {process_group_id} still has live members"
        )
    try:
        process.communicate(timeout=PROCESS_TERMINATION_FORCE_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise QualificationError(
            f"command process PID {process.pid} could not be reaped"
        ) from exc


def _windows_job_worker(argv: Sequence[str]) -> int:
    """Wait for Job assignment, then run the real command inside that Job."""

    if os.name != "nt" or not argv:
        return 125
    if sys.stdin.buffer.read(1) != b"\0":
        print("ERROR: Windows command worker was not assigned to its job", file=sys.stderr)
        return 125
    try:
        return subprocess.run(
            tuple(argv),
            stdin=subprocess.DEVNULL,
            check=False,
        ).returncode
    except OSError as exc:
        print(f"ERROR: cannot execute contained command: {exc}", file=sys.stderr)
        return 127


def execute_test(
    root: Path,
    test_id: str,
    specs: Sequence[CommandSpec],
    *,
    timeout_seconds: float,
    replace: bool,
) -> Path:
    """Execute command specs and write one staged record only after complete pass."""

    if test_id not in EXPECTED_TEST_IDS:
        raise QualificationError(f"unknown v0.4 acceptance ID: {test_id}")
    if not specs:
        raise QualificationError(f"{test_id} has no executable command")
    source = source_fingerprint_v04(root)
    destination = _record_path(root, source, test_id)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise QualificationError(f"unsafe staged evidence path: {destination}")
        if not replace:
            raise QualificationError(
                f"staged evidence already exists for {test_id}; pass --replace to rerun"
            )
        destination.unlink()

    started = _utc_now()
    commands: list[dict[str, Any]] = []
    assertions: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    structured_count = 0
    for index, spec in enumerate(specs):
        argv = _expand_argv(spec, root)
        result, stdout_sha, stderr_sha = _run_command(argv, root, timeout_seconds)
        commands.append(
            {
                "argv": list(argv),
                "return_code": result.returncode,
                "stdout_sha256": stdout_sha,
                "stderr_sha256": stderr_sha,
            }
        )
        if result.returncode != 0:
            raise QualificationError(
                f"{test_id} command {index + 1} failed rc={result.returncode} "
                f"stdout_sha256={stdout_sha} stderr_sha256={stderr_sha}"
            )
        if spec.require_pytest_pass:
            combined = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
            passed = sum(int(match) for match in PYTEST_PASSED_PATTERN.findall(combined))
            skipped = sum(int(match) for match in PYTEST_SKIPPED_PATTERN.findall(combined))
            if passed < 1 or skipped:
                raise QualificationError(
                    f"{test_id} targeted pytest accounting is incomplete: passed={passed} skipped={skipped}"
                )
        if spec.structured:
            structured_count += 1
            observed_assertions, observed_metrics = _parse_structured_stdout(
                result.stdout, test_id, source
            )
            assertions.extend(observed_assertions)
            metrics = observed_metrics
        else:
            assertion_id = spec.assertion_id
            if len(specs) > 1:
                assertion_id = f"{assertion_id}-{index + 1}"
            assertions.append({"id": assertion_id, "passed": True})

    if structured_count > 1:
        raise QualificationError(f"{test_id} recipe emitted more than one metric result")
    if test_id in SEMANTIC_VALIDATORS and structured_count != 1:
        raise QualificationError(f"{test_id} requires a structured metric collector")
    assertion_ids = [item["id"] for item in assertions]
    if not assertions or len(assertion_ids) != len(set(assertion_ids)):
        raise QualificationError(f"{test_id} produced empty or duplicate assertions")
    if source_fingerprint_v04(root) != source:
        raise QualificationError(f"source changed while {test_id} was executing")

    evidence = {
        "schema_version": TEST_EVIDENCE_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "test_id": test_id,
        "source": {"fingerprint_sha256": source},
        "started_at": started,
        "finished_at": _utc_now(),
        "executed": True,
        "passed": True,
        "environment": {
            "runner": "scripts/qualify_v04.py",
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "commands": commands,
        "assertions": assertions,
        "metrics": metrics,
    }
    _reject_forbidden_claims(evidence, test_id)
    _write_atomic(destination, _json_bytes(evidence))
    return destination


def _load_collector_map(path: Path | None) -> dict[str, tuple[str, ...]]:
    if path is None:
        return {}
    try:
        value = _parse_json_strict(path.read_text(encoding="utf-8"), "collector map")
    except (OSError, UnicodeDecodeError) as exc:
        raise QualificationError(f"cannot load collector map: {path}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != COLLECTOR_MAP_SCHEMA_VERSION:
        raise QualificationError("collector map schema version differs")
    collectors = value.get("collectors")
    if not isinstance(collectors, dict):
        raise QualificationError("collector map collectors must be an object")
    result: dict[str, tuple[str, ...]] = {}
    for test_id, argv in collectors.items():
        if test_id not in EXPECTED_TEST_IDS:
            raise QualificationError(f"collector map contains unknown ID: {test_id}")
        if not isinstance(argv, list):
            raise QualificationError(f"collector argv must be an array: {test_id}")
        result[test_id] = _safe_argv(argv)
    return result


def _selected_test_ids(gates: Sequence[int], requested: Sequence[str]) -> list[str]:
    selected: set[str] = set()
    for gate in gates:
        gate_id = f"V04-GATE-{gate}"
        if gate_id not in GATE_TEST_IDS:
            raise QualificationError(f"unknown gate number: {gate}")
        selected.update(GATE_TEST_IDS[gate_id])
    for test_id in requested:
        if test_id not in EXPECTED_TEST_IDS:
            raise QualificationError(f"unknown v0.4 acceptance ID: {test_id}")
        selected.add(test_id)
    return sorted(selected or EXPECTED_TEST_IDS)


def _load_staged_record(path: Path, test_id: str, source: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise QualificationError(f"missing or unsafe staged evidence: {test_id}")
    try:
        evidence = _parse_json_strict(path.read_text(encoding="utf-8"), test_id)
    except UnicodeDecodeError as exc:
        raise QualificationError(f"staged evidence is invalid JSON: {test_id}") from exc
    if not isinstance(evidence, dict):
        raise QualificationError(f"staged evidence is not an object: {test_id}")
    _reject_forbidden_claims(evidence, test_id)
    required = {
        "schema_version": TEST_EVIDENCE_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "test_id": test_id,
        "executed": True,
        "passed": True,
    }
    for key, expected in required.items():
        if evidence.get(key) != expected:
            raise QualificationError(f"staged {test_id}.{key} differs")
    source_value = evidence.get("source")
    if not isinstance(source_value, dict) or source_value.get("fingerprint_sha256") != source:
        raise QualificationError(f"staged evidence has a stale source: {test_id}")
    commands = evidence.get("commands")
    if not isinstance(commands, list) or not commands:
        raise QualificationError(f"staged evidence has no commands: {test_id}")
    for command in commands:
        if not isinstance(command, dict) or command.get("return_code") != 0:
            raise QualificationError(f"staged evidence has a failed command: {test_id}")
        _safe_argv(command.get("argv", []))
        if not isinstance(command.get("stdout_sha256"), str) or not SHA256_PATTERN.fullmatch(command["stdout_sha256"]):
            raise QualificationError(f"staged evidence has an invalid stdout hash: {test_id}")
        if not isinstance(command.get("stderr_sha256"), str) or not SHA256_PATTERN.fullmatch(command["stderr_sha256"]):
            raise QualificationError(f"staged evidence has an invalid stderr hash: {test_id}")
    assertions = evidence.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise QualificationError(f"staged evidence has no assertions: {test_id}")
    assertion_ids: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict) or assertion.get("passed") is not True:
            raise QualificationError(f"staged evidence has a failed assertion: {test_id}")
        assertion_id = assertion.get("id")
        if not isinstance(assertion_id, str) or not assertion_id or assertion_id in assertion_ids:
            raise QualificationError(f"staged evidence has invalid assertion IDs: {test_id}")
        assertion_ids.add(assertion_id)
    metrics = evidence.get("metrics")
    if not isinstance(metrics, dict):
        raise QualificationError(f"staged evidence metrics are invalid: {test_id}")
    validator = SEMANTIC_VALIDATORS.get(test_id)
    if validator is not None:
        try:
            validator(metrics, f"{test_id}.metrics", source)
        except ValueError as exc:
            raise QualificationError(str(exc)) from exc
    return evidence


def _gate_report(
    gate_id: str, source: str, evidence_bytes: dict[str, bytes], records: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    tests: list[dict[str, Any]] = []
    for test_id in sorted(GATE_TEST_IDS[gate_id]):
        record = records[test_id]
        assertion_count = len(record["assertions"])
        tests.append(
            {
                "test_id": test_id,
                "passed": True,
                "evidence_path": (TEST_EVIDENCE_DIRECTORY / f"{test_id}.json").as_posix(),
                "evidence_sha256": _sha256(evidence_bytes[test_id]),
                "assertions": {
                    "total": assertion_count,
                    "passed": assertion_count,
                    "failed": 0,
                    "skipped": 0,
                    "errors": 0,
                },
                "metrics": record["metrics"],
            }
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "gate_id": gate_id,
        "source": {"fingerprint_sha256": source},
        "overall_pass": True,
        "acceptance_complete": False,
        "waivers": [],
        "open_findings": {"critical": 0, "high": 0},
        "tests": tests,
    }


def publish(root: Path, *, replace: bool, preliminary: bool = False) -> None:
    """Publish the exact complete staged set and verify release evidence."""

    source = source_fingerprint_v04(root)
    staging = _staging_tests(root, source)
    discovered = {path.name for path in staging.glob("*.json")} if staging.is_dir() else set()
    expected_names = {f"{test_id}.json" for test_id in EXPECTED_TEST_IDS}
    if discovered != expected_names:
        missing = sorted(expected_names - discovered)
        unexpected = sorted(discovered - expected_names)
        raise QualificationError(
            f"cannot publish incomplete staged evidence; missing={missing!r} unexpected={unexpected!r}"
        )

    records: dict[str, dict[str, Any]] = {}
    evidence_bytes: dict[str, bytes] = {}
    for test_id in sorted(EXPECTED_TEST_IDS):
        path = staging / f"{test_id}.json"
        records[test_id] = _load_staged_record(path, test_id, source)
        evidence_bytes[test_id] = path.read_bytes()
    supply_corpora: dict[str, Path] = {}
    for test_id in sorted(SUPPLY_PROVENANCE_TEST_IDS):
        record = records[test_id]
        metrics = record["metrics"]
        run_id = metrics.get("supply_provenance_run_id")
        if not isinstance(run_id, str):
            raise QualificationError(f"staged {test_id} has no supply provenance run ID")
        corpus = staged_supply_directory(root, source, test_id, run_id)
        collector_result = {
            "test_id": test_id,
            "source_fingerprint_sha256": source,
            "assertions": record["assertions"],
            "metrics": metrics,
        }
        try:
            validate_supply_corpus(
                root,
                corpus,
                expected_test_id=test_id,
                expected_source=source,
                expected_result=collector_result,
                expected_run_id=run_id,
            )
        except (OSError, ValueError, TypeError) as exc:
            raise QualificationError(f"staged {test_id} supply provenance is invalid: {exc}") from exc
        supply_corpora[test_id] = corpus
    try:
        validate_product_package_binding_v04(
            root,
            records["V04-SC-004"]["metrics"].get("package_sha256"),
            "staged V04-SC-004",
        )
    except (FileNotFoundError, ValueError) as exc:
        raise QualificationError(str(exc)) from exc
    if source_fingerprint_v04(root) != source:
        raise QualificationError("source changed while staged evidence was being validated")

    # Gate 5 cannot pass without the exact current four-image inventory set.
    try:
        validate_sboms_v04(root, source)
    except (FileNotFoundError, ValueError) as exc:
        raise QualificationError(str(exc)) from exc

    destination = root / TEST_EVIDENCE_DIRECTORY
    supply_destination = root / EVIDENCE_DIRECTORY / "provenance" / "supply"
    existing_reports = [
        root / relative for relative in GATE_REPORTS.values() if (root / relative).exists()
    ]
    if (destination.exists() or supply_destination.exists() or existing_reports) and not replace:
        raise QualificationError("canonical v0.4 evidence exists; pass --replace to republish")
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise QualificationError(f"unsafe canonical test evidence path: {destination}")
    if supply_destination.is_symlink() or (
        supply_destination.exists() and not supply_destination.is_dir()
    ):
        raise QualificationError(f"unsafe canonical supply provenance path: {supply_destination}")
    if supply_destination.parent.is_symlink() or (
        supply_destination.parent.exists() and not supply_destination.parent.is_dir()
    ):
        raise QualificationError(
            f"unsafe canonical provenance parent path: {supply_destination.parent}"
        )

    publication_root = root / STAGING_DIRECTORY / f"publish-{uuid.uuid4().hex}"
    publication_tests = publication_root / "tests"
    publication_tests.mkdir(parents=True)
    for test_id, data in evidence_bytes.items():
        _write_atomic(publication_tests / f"{test_id}.json", data)
    publication_supply = publication_root / "supply"
    publication_supply.mkdir()
    for test_id, corpus in sorted(supply_corpora.items()):
        copy_validated_supply_corpus(
            corpus,
            publication_supply / canonical_supply_directory(root, test_id).name,
        )
    publication_reports: dict[str, Path] = {}
    for gate_id in GATE_REPORTS:
        path = publication_root / f"gate-{gate_id.rsplit('-', 1)[1]}.json"
        _write_atomic(path, _json_bytes(_gate_report(gate_id, source, evidence_bytes, records)))
        publication_reports[gate_id] = path

    backup: Path | None = None
    supply_backup: Path | None = None
    supply_published = False
    previous_reports: dict[Path, bytes | None] = {}
    for relative in GATE_REPORTS.values():
        target = root / relative
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise QualificationError(f"unsafe canonical gate report path: {target}")
        previous_reports[target] = target.read_bytes() if target.is_file() else None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            backup = publication_root / "previous-tests"
            os.replace(destination, backup)
        os.replace(publication_tests, destination)
        supply_destination.parent.mkdir(parents=True, exist_ok=True)
        if supply_destination.exists():
            supply_backup = publication_root / "previous-supply"
            os.replace(supply_destination, supply_backup)
        os.replace(publication_supply, supply_destination)
        supply_published = True
        for gate_id, relative in GATE_REPORTS.items():
            target = root / relative
            _write_atomic(target, publication_reports[gate_id].read_bytes())
        if source_fingerprint_v04(root) != source:
            raise QualificationError("source changed while canonical evidence was published")
        try:
            result = validate_release_evidence_v04(root, preliminary=preliminary)
        except (FileNotFoundError, ValueError) as exc:
            raise QualificationError(str(exc)) from exc
        if len(result.validated_test_ids) != len(EXPECTED_TEST_IDS):
            raise QualificationError("release validator did not confirm all v0.4 IDs")
    except Exception:
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        if backup is not None and backup.is_dir() and not backup.is_symlink():
            os.replace(backup, destination)
        if supply_published or supply_backup is not None:
            if supply_destination.is_dir() and not supply_destination.is_symlink():
                shutil.rmtree(supply_destination)
            if (
                supply_backup is not None
                and supply_backup.is_dir()
                and not supply_backup.is_symlink()
            ):
                os.replace(supply_backup, supply_destination)
        for target, previous in previous_reports.items():
            if previous is None:
                if target.is_file() and not target.is_symlink():
                    target.unlink()
            else:
                _write_atomic(target, previous)
        raise
    finally:
        if publication_root.is_dir() and not publication_root.is_symlink():
            shutil.rmtree(publication_root)


def _probe_scope_001(root: Path) -> dict[str, Any]:
    from google.protobuf import descriptor_pb2

    expected_service = "spell.driver.v1.DriverInfrastructureService"
    expected_methods = (
        "Handshake",
        "Health",
        "OpenContext",
        "CloseContext",
        "AttachExecution",
        "DetachExecution",
        "CancelLifecycleOperation",
        "DrainHost",
        "GetOperation",
    )

    descriptor_path = root / "contracts/spell_driver_v1.pb"
    descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(descriptor_path.read_bytes())
    services: list[tuple[str, tuple[str, ...], tuple[bool, ...]]] = []
    untyped_payload_count = 0
    for file_descriptor in descriptor_set.file:
        package = file_descriptor.package
        for service in file_descriptor.service:
            qualified = f"{package}.{service.name}" if package else service.name
            services.append(
                (
                    qualified,
                    tuple(method.name for method in service.method),
                    tuple(method.client_streaming or method.server_streaming for method in service.method),
                )
            )
        pending = list(file_descriptor.message_type)
        while pending:
            message = pending.pop()
            pending.extend(message.nested_type)
            for field in message.field:
                if field.type_name in {
                    ".google.protobuf.Any",
                    ".google.protobuf.Struct",
                    ".google.protobuf.Value",
                }:
                    untyped_payload_count += 1
            if message.options.map_entry:
                untyped_payload_count += 1
    exact_service = services == [(expected_service, expected_methods, (False,) * 9)]
    if not exact_service or untyped_payload_count:
        raise QualificationError(
            f"descriptor differs: services={services!r} untyped={untyped_payload_count}"
        )
    return {
        "test_id": "V04-SCOPE-001",
        "source_fingerprint_sha256": source_fingerprint_v04(root),
        "assertions": [
            {"id": "exact-single-infrastructure-service", "passed": True},
            {"id": "exact-nine-approved-unary-rpcs", "passed": True},
            {"id": "no-untyped-protobuf-escape-hatch", "passed": True},
        ],
        "metrics": {
            "rpc_count": 9,
            "future_service_count": 0,
            "untyped_payload_count": 0,
        },
    }


def _plan() -> dict[str, Any]:
    gates: dict[str, list[dict[str, Any]]] = {}
    for gate_id, ids in GATE_TEST_IDS.items():
        gates[gate_id] = []
        for test_id in sorted(ids):
            recipe = RECIPES[test_id]
            gates[gate_id].append(
                {
                    "test_id": test_id,
                    "mode": "collector" if recipe.collector_required else "builtin",
                    "reason": recipe.reason,
                    "commands": [list(spec.argv) for spec in recipe.commands],
                }
            )
    return {
        "schema_version": "spell.v04.qualification-plan/1",
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "test_count": len(RECIPES),
        "collector_required_count": sum(
            recipe.collector_required for recipe in RECIPES.values()
        ),
        "collector_map_contract": {
            "schema_version": COLLECTOR_MAP_SCHEMA_VERSION,
            "shape": {"collectors": {"V04-TEST-ID": ["executable", "argument"]}},
        },
        "collector_stdout_contract": {
            "final_nonempty_line": "strict JSON",
            "required_fields": [
                "test_id",
                "source_fingerprint_sha256",
                "assertions",
                "metrics",
            ],
            "assertion_shape": {"id": "non-empty unique string", "passed": True},
            "source_binding": "must equal scripts/source_fingerprint_v04.py output for the tested tree",
        },
        "gates": gates,
    }


def _status(root: Path) -> dict[str, Any]:
    source = source_fingerprint_v04(root)
    staging = _staging_tests(root, source)
    valid: list[str] = []
    invalid: dict[str, str] = {}
    for test_id in sorted(EXPECTED_TEST_IDS):
        path = staging / f"{test_id}.json"
        if not path.exists():
            continue
        try:
            _load_staged_record(path, test_id, source)
        except QualificationError as exc:
            invalid[test_id] = str(exc)
        else:
            valid.append(test_id)
    missing = sorted(set(EXPECTED_TEST_IDS) - set(valid) - set(invalid))
    return {
        "source_fingerprint_sha256": source,
        "valid_count": len(valid),
        "invalid_count": len(invalid),
        "missing_count": len(missing),
        "valid_test_ids": valid,
        "invalid": invalid,
        "missing_test_ids": missing,
        "publish_ready": not invalid and not missing,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print the exact 74-ID execution plan")

    run = subparsers.add_parser("run", help="execute built-ins and supplied collectors")
    run.add_argument("--gate", type=int, action="append", default=[])
    run.add_argument("--test-id", action="append", default=[])
    run.add_argument("--collector-map", type=Path)
    run.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    run.add_argument("--replace", action="store_true")

    collect = subparsers.add_parser(
        "collect", help="execute one structured environment-bound collector"
    )
    collect.add_argument("--test-id", required=True)
    collect.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    collect.add_argument("--replace", action="store_true")
    collect.add_argument("argv", nargs=argparse.REMAINDER)

    subparsers.add_parser("status", help="validate and summarize current staged evidence")
    publish_parser = subparsers.add_parser(
        "publish", help="atomically assemble and validate canonical Gate 1-5 evidence"
    )
    publish_parser.add_argument("--replace", action="store_true")
    publish_parser.add_argument(
        "--preliminary",
        action="store_true",
        help="publish gate evidence before retained final fault provenance exists",
    )
    subparsers.add_parser("_probe-scope-001", help=argparse.SUPPRESS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    argument_list = list(argv) if argv is not None else sys.argv[1:]
    if argument_list and argument_list[0] == "_windows-job-worker":
        worker_argv = argument_list[1:]
        if worker_argv and worker_argv[0] == "--":
            worker_argv = worker_argv[1:]
        return _windows_job_worker(worker_argv)
    parser = _build_parser()
    args = parser.parse_args(argument_list)
    root = args.root.resolve()
    try:
        if args.command == "plan":
            print(json.dumps(_plan(), sort_keys=True))
            return 0
        if args.command == "_probe-scope-001":
            print(json.dumps(_probe_scope_001(root), sort_keys=True, allow_nan=False))
            return 0
        if args.command == "status":
            status = _status(root)
            print(json.dumps(status, sort_keys=True))
            return 0 if status["publish_ready"] else 2
        if args.command == "publish":
            publish(root, replace=args.replace, preliminary=args.preliminary)
            print(
                json.dumps(
                    {
                        "published": True,
                        "preliminary": args.preliminary,
                        "test_count": len(EXPECTED_TEST_IDS),
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.timeout_seconds <= 0 or not math.isfinite(args.timeout_seconds):
            raise QualificationError("timeout must be a positive finite number")
        if args.command == "collect":
            collector_argv = list(args.argv)
            if collector_argv and collector_argv[0] == "--":
                collector_argv = collector_argv[1:]
            spec = CommandSpec(
                _safe_argv(collector_argv),
                "structured-collector-passed",
                structured=True,
            )
            path = execute_test(
                root,
                args.test_id,
                (spec,),
                timeout_seconds=args.timeout_seconds,
                replace=args.replace,
            )
            print(json.dumps({"staged": path.relative_to(root).as_posix()}, sort_keys=True))
            return 0
        if args.command == "run":
            selected = _selected_test_ids(args.gate, args.test_id)
            collector_map = args.collector_map
            if collector_map is not None and not collector_map.is_absolute():
                collector_map = root / collector_map
            collectors = _load_collector_map(collector_map)
            blocked: dict[str, str] = {}
            failed: dict[str, str] = {}
            staged: list[str] = []
            for test_id in selected:
                recipe = RECIPES[test_id]
                argv_value = collectors.get(test_id)
                if argv_value is not None:
                    specs = (
                        CommandSpec(
                            argv_value,
                            "structured-collector-passed",
                            structured=True,
                        ),
                    )
                elif recipe.collector_required:
                    if argv_value is None:
                        blocked[test_id] = recipe.reason
                        continue
                else:
                    specs = recipe.commands
                try:
                    execute_test(
                        root,
                        test_id,
                        specs,
                        timeout_seconds=args.timeout_seconds,
                        replace=args.replace,
                    )
                except QualificationError as exc:
                    failed[test_id] = str(exc)
                else:
                    staged.append(test_id)
            result = {"staged_test_ids": staged, "blocked": blocked, "failed": failed}
            print(json.dumps(result, sort_keys=True))
            return 0 if not blocked and not failed else 2
        raise QualificationError(f"unsupported command: {args.command}")
    except (QualificationError, FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
