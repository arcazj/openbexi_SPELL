# Documentation Acceptance Checklist

## Baseline Completeness

This checklist is a superset for the broader next-generation program. For the
local-only synthetic non-CUI v0.4 gate, the controlling subset is the exact
seven-source inventory, Candidate A/Deferred compatibility dispositions,
testable local requirements, secret/CUI exclusion, owner-record manifest, and
the engineering checks incorporated by `V04-GATE-0`. Proposed ADR acceptance,
organization role assignment, connected-system review, GUI-manual publication,
and other broader unchecked items do not block the local gate.

### Mutable v0.10/v0.11 Application Check

This bounded application note does not change the Draft baseline or the
accepted v0.9.0 product release.

- [x] The v0.10 traceability records distinguish 195 numbered example outcomes
  from 257 independently asserted variant subcases.
- [x] Raw malformed, pseudocode, output-only, placeholder, negative, and
  intentionally invalid reference snippets are labeled as hash-bound semantic
  adaptations, not verbatim executable source.
- [x] The implemented v0.11 boundary is simulator-only and separates
  confirmation, timing, transport, loading, release, acknowledgement, onboard
  execution, verification, disposition, certainty, cancellation, recovery, and
  reconciliation.
- [x] Record exact commands and results from one consistent final working-tree
  state in `../releases/SPELL_v0.11_Implementation.md`.
- [x] Confirm direct public telecommand API extreme numeric inputs fail with
  bounded typed diagnostics and no raw exception.
- [x] Confirm the full v0.10 195-example/257-variant gate, v0.11 command corpus,
  current product regression, frontend/build/browser, and product-image checks;
  record every platform selection and historical release-only exclusion.
- [x] Do not claim a v0.10 or v0.11 candidate, accepted release, package, tag,
  deployment, compliance result, or operational authorization from mutable
  working-tree evidence.

- [ ] Repository version, source revision, status, approvers and effective date are fixed.
- [x] All 304 reviewed source pages and seven file hashes reconcile.
- [ ] The Language Reference and Driver Manual authority records match their exact bytes.
- [ ] Every requirement ID is unique and bidirectionally traced.
- [ ] Every ADR has an explicit status, alternatives, consequences and approvers.
- [ ] Every relative Markdown link resolves.
- [ ] Every safety/security/interoperability TBD is either closed or blocks its gate.
- [x] The detailed compatibility rows for the next increment reconcile to source catalogs/examples.
- [x] `V04_COMPATIBILITY_TECHNICAL_REVIEW.json` binds every final per-source
  row digest and records zero blocking/high source-review findings without
  claiming human approval or runtime conformance.
- [ ] Diagrams and schemas use consistent identifiers and have text equivalents.
- [ ] No secret, credential, CUI, proprietary code or unapproved artifact is committed.
- [ ] Normative language is testable and no descriptive text weakens a requirement.
- [x] The local scope manifest and exact owner-approval record are generated and
  retained; their SHA-256 digests are integrity evidence, not signatures.
- [ ] `web/SPELL_GUI_USER_MANUAL.md` and its rendered PDF cover every `DOC-011`
  topic, identify their specification/build scope, pass link/accessibility and
  secret/CUI checks, and have a recorded page-by-page visual review.

## Architecture Review

The Architecture, Product and Mission Operations, Security, and Quality and
Operations sections below are retained for later or expanded scopes. Their
organization, mission, protected-data, assessment, deployment, and operational
sign-offs are not local v0.4 Gate 0 requirements. Only the Candidate A checks
incorporated by `V04-GATE-0` and its engineering test plan apply to this gate.

- [ ] One satellite/domain, multiple-domain isolation and multi-procedure concurrency are coherent.
- [ ] Controller lease, fence, leader epoch, revision and idempotency invariants are complete.
- [ ] Satellite Assignment Authority prevents simultaneous effect-enabled paths across active, draining, restored, and legacy/new systems; `OD-024` is closed before any real command path.
- [ ] Non-rollback generation-anchor receipts prevent reuse after total SAA restore, and a missing or ambiguous receipt blocks issuance.
- [ ] Every cutover, failover, restore, and failback reserves a fresh externally anchored, effect-disabled target tuple before final fence evidence is collected; every evidence item binds that target, and activation/credentials follow fencing, reconciliation, local authority, and readiness.
- [ ] Every pre-SAA legacy path has a complete adoption inventory and independent per-path fence evidence bound to the reserved replacement tuple before activation.
- [ ] One Effect Authorization Point exclusively owns each effect credential/egress route and implements the two ordered linearization points: one-use SAA permit consume, then transactional PostgreSQL permit/journal commit before send, with no cross-system ACID claim.
- [ ] Controller leases are session/client-proof bound and ownership-fence versus lease-revision behavior is unambiguous.
- [ ] Machine-readable state models validate, cover every transition/rejection, and match the human-readable contract.
- [ ] One execution per sandbox, worker identity, storage, resource, and crash isolation are explicit.
- [ ] Every service, trust, process, data and failure boundary has one accountable owner.
- [ ] REST, WebSocket, gRPC and driver contracts define ordering, failure and compatibility.
- [ ] Stream-epoch positions and opaque authorization-projection sequence/cursor behavior pass delayed-transaction, restore, privacy, and scope-change review.
- [ ] PostgreSQL and optional storage/transport roles have no conflicting authority.
- [ ] Degraded behavior, uncertain effects, recovery and HA cannot create duplicate command authority.
- [ ] Operation/attempt identity, read-only certainty applicability, schedule restart, and controller-reacquisition behavior are deterministic.
- [ ] Deployment and capacity statements are measurable and do not promise infinite scale.

## Product And Mission Operations Review

- [ ] Execution, Monitoring and Edit permissions and workflows are accepted.
- [ ] Control acquisition, handover, loss, revocation and failover are accepted.
- [ ] Critical actions, prompts, alarms, stale state and historical/live distinctions are accepted.
- [ ] Procedure organization, search, favorites, recents and Git workflows are accepted.
- [ ] Human factors, accessibility, supported displays and workflow budgets are assigned.
- [ ] Representative Controller, Monitoring, and Developer users validate the
  GUI User Manual against the exact accepted interface build and record findings.
- [ ] Simulator, shadow, effect-lab and operational boundaries are understood.

## Security Review

- [ ] Governing applicability and operated-on-behalf determinations are recorded; CUI boundary, contracts, information flows and connected systems are approved.
- [ ] SSP, ODP, control owner, assessment and POA&M processes are assigned.
- [ ] All 17 NIST SP 800-171 Rev. 3 families have capability/evidence ownership, and the deployment template accounts for every official requirement and SP 800-171A determination statement.
- [ ] Threat model covers browser, identity, Git, procedure, runtime, driver, data and operations.
- [ ] Cryptography, keys, secrets, audit, segmentation, integrity and supply chain are approved.
- [ ] Organizational controls outside software have accountable evidence owners.
- [ ] No software-only compliance or certification claim is present.

## Quality And Operations Review

- [ ] Test environments, fixtures, models, workload and evidence format are approved.
- [ ] Fault, failover, backup, restore, DR, security and operator exercises are defined.
- [ ] SLOs, SLIs, alerts, runbooks, escalation, retention and support are assigned.
- [ ] Release gates and exception authority are accepted.
- [ ] Migration, rollback and legacy-retirement decisions are explicit and independent.

## Required Sign-Off

For the local-only, synthetic, non-CUI v0.4 engineering gate, the project owner
is the only required approval role. Organization, mission, assessment,
authorizing-official, and operational roles are outside this gate. Any future
connected, protected-data, compliance, or operational scope requires a separate
applicability decision and approval record.

| Role | Name | Decision | Date | Baseline/tag | Findings reference |
| --- | --- | --- | --- | --- | --- |
| Project owner | JC Arcaz | Candidate A scope approved; local Gate G0 passed; bounded implementation authorized | 2026-07-18 | SHA-256 file manifest; no tag/signature claim | `G0_HUMAN_APPROVAL_LEDGER.json`; `G0_READINESS_REPORT.json` |
