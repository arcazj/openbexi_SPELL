# Next-Generation SPELL Documentation

## Purpose

This directory is the controlled, derived design specification for planning and
implementing the next generation of SPELL. Every document under the parent
repository's `SPELL_DOCUMENTATION/` directory is a mandatory source-reference
input. This specification preserves and traces the language, driver, server,
operator, and development concepts that define SPELL while replacing obsolete
implementation, desktop, deployment, security, and operational assumptions
with a blueprint intended to become implementation-ready after Gate G0 entry
decisions and human approval.

Generated content does not independently supersede the source manuals. Any
clarification, safety strengthening, unsupported behavior, or migration must be
recorded through source authority, compatibility disposition, requirements,
decisions, and verification evidence.

The specification describes a Python-based execution platform, a responsive
web application, one logical satellite control domain per satellite, concurrent
procedure execution, multiple independently scalable domains, Git-managed
procedure development, reliable real-time state distribution, and security
capabilities intended to support an organization's NIST SP 800-171 Rev. 3
obligations.

This documentation does not authorize connection to a spacecraft or production
Ground Control System (GCS). It becomes an approved baseline only after the
accountable human roles in [DOCUMENT_CONTROL.md](DOCUMENT_CONTROL.md) accept it.

## Status

| Field | Value |
| --- | --- |
| Specification version | `0.1.0-draft.1` |
| Prepared | 2026-07-18 |
| Source review | 304 of 304 supplied pages reviewed |
| Project-declared AI assistance tool | ChatGPT 5.6 SOL |
| Product implementation change | None |
| Operational authorization | None |
| Approval state | Draft; multidisciplinary review required |
| Local v0.4 Gate G0 readiness | `PASS`; Candidate A scope, exclusions, budgets, and test plan project-owner approved; exhaustive seven-source compatibility review passed for 1,682 rows, including 125 v0.4 and 1,557 Deferred rows; exact manifest and pinned Python 3.13 qualification verified |

Derived design authority does not mean approved implementation or operational
authorization: this baseline remains Draft until the accountable human roles
accept it. It also cannot silently override a source reference under
`../SPELL_DOCUMENTATION/`. Normative words `shall`, `shall not`, `should`, and
`may` have the meanings defined in
[DOCUMENT_CONTROL.md](DOCUMENT_CONTROL.md). Open values are never silently
invented: they are assigned an owner and gate in
[quality/OPEN_DECISIONS.md](quality/OPEN_DECISIONS.md).

## Start Here

Before using this map, inventory and read the applicable source manuals under
[`../SPELL_DOCUMENTATION/`](../SPELL_DOCUMENTATION/) and confirm their identity
in [SOURCE_AUTHORITY.md](SOURCE_AUTHORITY.md).

1. Read [DOCUMENT_CONTROL.md](DOCUMENT_CONTROL.md) for authority and approval.
2. Read [SOURCE_AUTHORITY.md](SOURCE_AUTHORITY.md) for source precedence and
   exact evidence hashes.
3. Read [requirements/SYSTEM_REQUIREMENTS.md](requirements/SYSTEM_REQUIREMENTS.md)
   for the normative system contract.
4. Check [requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md](requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md)
   for the allocation of detailed normative clauses.
5. Review [requirements/COMPATIBILITY_LEDGER.md](requirements/COMPATIBILITY_LEDGER.md)
   and the exhaustive local v0.4 machine-readable disposition catalog before
   proposing a product scope.
6. Review [quality/G0_READINESS_PACKAGE.md](quality/G0_READINESS_PACKAGE.md)
   and its machine-readable report before proposing implementation.
7. Read [architecture/LOGICAL_ARCHITECTURE.md](architecture/LOGICAL_ARCHITECTURE.md)
   and [architecture/SERVER_AND_EXECUTION.md](architecture/SERVER_AND_EXECUTION.md)
   for the implementation shape.
8. Read [security/NIST_SP_800_171_ALIGNMENT.md](security/NIST_SP_800_171_ALIGNMENT.md)
   before defining a CUI boundary or claiming compliance.
9. Use [requirements/TRACEABILITY_MATRIX.md](requirements/TRACEABILITY_MATRIX.md)
   and [quality/VERIFICATION_AND_VALIDATION.md](quality/VERIFICATION_AND_VALIDATION.md)
   to evaluate completeness.
10. Use [releases/README.md](releases/README.md) to locate version-specific
    planning, gate, implementation, and release records.

## Repository Map

### Control And Authority

- [DOCUMENT_CONTROL.md](DOCUMENT_CONTROL.md): lifecycle, approval, change, and
  normative-language rules.
- [SOURCE_AUTHORITY.md](SOURCE_AUTHORITY.md): evidence inventory, integrity, and
  conflict precedence.
- [GLOSSARY.md](GLOSSARY.md): shared vocabulary and identifier definitions.
- [CHANGELOG.md](CHANGELOG.md): controlled specification history.
- [preserved/LANGUAGE_REFERENCE_AUTHORITY.md](preserved/LANGUAGE_REFERENCE_AUTHORITY.md):
  immutable Language Reference authority record.
- [preserved/DRIVER_MANUAL_AUTHORITY.md](preserved/DRIVER_MANUAL_AUTHORITY.md):
  immutable Driver Development Manual authority record.

### Requirements And Traceability

- [requirements/SYSTEM_REQUIREMENTS.md](requirements/SYSTEM_REQUIREMENTS.md)
- [requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md](requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md)
- [requirements/TRACEABILITY_MATRIX.md](requirements/TRACEABILITY_MATRIX.md)
- [requirements/COMPATIBILITY_LEDGER.md](requirements/COMPATIBILITY_LEDGER.md)
- [requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json](requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json),
  [canonical detailed ledger](requirements/compatibility/COMPATIBILITY_LEDGER.json),
  [v0.4 partial scope](requirements/compatibility/scopes/v0.4.json), and
  [digest reconciliation](requirements/compatibility/COMPATIBILITY_RECONCILIATION.json):
  62 decomposed Driver/Server assertions; exhaustive coverage and approval are
  still pending.
- [requirements/IMPLEMENTATION_ALLOCATION_RULES.json](requirements/IMPLEMENTATION_ALLOCATION_RULES.json):
  controlled candidate rules for primary per-ID implementation allocation.
- [requirements/IMPLEMENTATION_ALLOCATION.csv](requirements/IMPLEMENTATION_ALLOCATION.csv):
  generated 366-row allocation and planned evidence relation; not approval or
  implementation evidence.

### Release Records

- [releases/README.md](releases/README.md): index of the version-specific
  planning, gate, implementation, and release records moved from the repository
  root into this documentation tree.

### Architecture

- [architecture/SYSTEM_CONTEXT.md](architecture/SYSTEM_CONTEXT.md)
- [architecture/LOGICAL_ARCHITECTURE.md](architecture/LOGICAL_ARCHITECTURE.md)
- [architecture/SERVER_AND_EXECUTION.md](architecture/SERVER_AND_EXECUTION.md)
- [architecture/STATE_MACHINES.md](architecture/STATE_MACHINES.md)
- [architecture/state-machines.json](architecture/state-machines.json)
- [architecture/REAL_TIME_COMMUNICATIONS.md](architecture/REAL_TIME_COMMUNICATIONS.md)
- [architecture/DATA_ARCHITECTURE.md](architecture/DATA_ARCHITECTURE.md)
- [architecture/RELIABILITY_AND_RECOVERY.md](architecture/RELIABILITY_AND_RECOVERY.md)
- [architecture/DEPLOYMENT_AND_SCALABILITY.md](architecture/DEPLOYMENT_AND_SCALABILITY.md)
- [architecture/SATELLITE_ASSIGNMENT_AUTHORITY.md](architecture/SATELLITE_ASSIGNMENT_AUTHORITY.md)
- [architecture/decisions/README.md](architecture/decisions/README.md): proposed architecture
  decisions with consequences; none is accepted before baseline approval.

### Web And Procedures

- [web/WEB_APPLICATION.md](web/WEB_APPLICATION.md)
- [web/OPERATING_MODES.md](web/OPERATING_MODES.md)
- [web/PROCEDURE_NAVIGATION.md](web/PROCEDURE_NAVIGATION.md)
- [web/REAL_TIME_STATE.md](web/REAL_TIME_STATE.md)
- [web/SPELL_GUI_USER_MANUAL.md](web/SPELL_GUI_USER_MANUAL.md): controlled
  source for the next-generation GUI User Manual.
- [web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf](web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf):
  versioned, outlined Draft PDF candidate; final build binding, validation, and
  human acceptance remain pending.
- [web/assets/gui-manual-mockups.html](web/assets/gui-manual-mockups.html),
  [fleet overview](web/assets/fleet-overview.png),
  [Execution workspace](web/assets/execution-workspace.png),
  [Monitoring and handover](web/assets/monitor-handover.png), and
  [Edit workspace](web/assets/edit-workspace.png): concept-figure source and
  rendered assets.
- [web/assets/gui-manual-print.css](web/assets/gui-manual-print.css),
  [web/tools/render_gui_user_manual.py](web/tools/render_gui_user_manual.py),
  [web/tools/print_gui_user_manual.cjs](web/tools/print_gui_user_manual.cjs), and
  [web/tools/requirements.txt](web/tools/requirements.txt): reproducible manual
  publication pipeline.
- [procedures/AUTHORING_AND_GIT.md](procedures/AUTHORING_AND_GIT.md)
- [procedures/COMPATIBILITY_AND_MIGRATION.md](procedures/COMPATIBILITY_AND_MIGRATION.md)

### Security And Operations

- [security/SECURITY_ARCHITECTURE.md](security/SECURITY_ARCHITECTURE.md)
- [security/NIST_SP_800_171_ALIGNMENT.md](security/NIST_SP_800_171_ALIGNMENT.md)
- [security/NIST_REQUIREMENT_ASSESSMENT_MATRIX.md](security/NIST_REQUIREMENT_ASSESSMENT_MATRIX.md)
- [security/THREAT_MODEL.md](security/THREAT_MODEL.md)
- [security/SECURE_SDLC_AND_SUPPLY_CHAIN.md](security/SECURE_SDLC_AND_SUPPLY_CHAIN.md)
- [operations/OPERATIONS_AND_OBSERVABILITY.md](operations/OPERATIONS_AND_OBSERVABILITY.md)
- [operations/BACKUP_RESTORE_AND_DR.md](operations/BACKUP_RESTORE_AND_DR.md)

### Delivery And Assurance

- [quality/VERIFICATION_AND_VALIDATION.md](quality/VERIFICATION_AND_VALIDATION.md)
- [quality/IMPLEMENTATION_ROADMAP.md](quality/IMPLEMENTATION_ROADMAP.md)
- [quality/G0_READINESS_PACKAGE.md](quality/G0_READINESS_PACKAGE.md):
  structured decision inputs and the truthful current `BLOCKED` disposition.
- [quality/G0_READINESS_REPORT.json](quality/G0_READINESS_REPORT.json):
  deterministic digest-bound structural results and authorization blockers.
- [quality/G0_HUMAN_APPROVAL_LEDGER.json](quality/G0_HUMAN_APPROVAL_LEDGER.json):
  recorded JC Arcaz project-owner approval of Candidate A, its exclusions,
  local budgets, and test plan, with bounded nonclaims and an exact SHA-256
  local-gate manifest still to be finalized.
- [quality/OPEN_DECISIONS.md](quality/OPEN_DECISIONS.md)
- [quality/DOCUMENT_ACCEPTANCE_CHECKLIST.md](quality/DOCUMENT_ACCEPTANCE_CHECKLIST.md)
- [quality/tools/validate_g0.py](quality/tools/validate_g0.py) and
  [quality/tools/test_validate_g0.py](quality/tools/test_validate_g0.py):
  allocation generation, document/source checks, blocked-gate enforcement, and
  unit coverage.
- [quality/tools/validate_compatibility.py](quality/tools/validate_compatibility.py)
  and
  [quality/tools/test_validate_compatibility.py](quality/tools/test_validate_compatibility.py):
  exhaustive seven-source page/schema/count/disposition reconciliation,
  planned-only test identities, technical-review pins, and bounded nonclaims.
  These tools provide technical evidence; they do not claim implementation,
  runtime semantic conformance, operational authorization, or compliance.

## Architectural Position In One Page

- A Satellite Control Domain is the unit of control, failure isolation, audit,
  and scaling. It controls exactly one satellite. A mission deploys one or more
  domains.
- A domain executes multiple procedures concurrently within configured resource,
  conflict, and safety constraints.
- Exactly one valid controller lease may authorize interactive execution control
  for a domain. The lease carries a monotonically increasing
  `control_fencing_token` and a tab-local client proof binding.
- Monitoring is server-enforced read-only. There is no product-imposed monitor
  count, but every deployment has measured and published capacity; no design can
  promise physically unlimited clients.
- Procedure source is managed in Git. Only validated, reviewed, immutable,
  content-addressed bundles may be promoted to a runtime catalog. Editing never
  changes an active execution.
- Browsers use HTTPS REST for authenticated commands and snapshots and WebSocket
  for ordered committed events. Internal typed service boundaries use gRPC over
  mutually authenticated channels.
- PostgreSQL remains the authoritative transactional store. Object storage holds
  immutable bundles, reports, and backup artifacts. Brokers, caches, and
  analytical stores may scale delivery but are never control authority.
- A single fenced writer controls each domain. High availability is active-passive
  for command authority; uncertain external effects are reconciled, never blindly
  resent.
- A mission-wide Satellite Assignment Authority prevents independent clusters,
  disaster sites, or legacy/new systems from activating command paths for the
  same satellite. Every activation uses a fresh authority incarnation and a
  generation receipt from an external non-rollback anchor; pre-SAA paths require
  complete legacy adoption and independent fencing.
- One Effect Authorization Point exclusively holds each effect credential and
  egress route. Immediately before effect, it consumes a one-use SAA attempt
  permit while transactionally locking and validating current PostgreSQL
  assignment, leader, controller, attempt, and integration fences; it commits
  the permit receipt and journal intent before send without claiming a
  cross-system ACID transaction.
- Procedure source is parsed into a bounded, versioned, data-only intermediate
  representation. Arbitrary Python, imports, shell access, and direct driver
  credentials are outside the execution contract.
- Security documentation supports NIST SP 800-171 Rev. 3 implementation and
  assessment. Compliance is an organizational and contractual determination,
  not a property this software can claim by itself.

## Change Rule

No requirement is removed, weakened, or reinterpreted by editing a descriptive
document alone. The change must update its requirement row, affected decision,
traceability, verification evidence, document version, and approval record.
