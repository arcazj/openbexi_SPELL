# Implementation Roadmap

## Roadmap Rule

This is a capability and evidence roadmap, not an authorization schedule. A phase
starts only after its entry gate is approved and ends only when its evidence is
accepted. Parallel work is allowed only when it cannot bypass a dependency or
combine read-only and effect-bearing risk.

The existing OpenBEXI SPELL v0.1 through v0.3 history is not renumbered by this
repository. The current project roadmap identifies a candidate v0.4 typed
simulator driver/context foundation. `OD-001` requires the product owner to map
the phases below to release numbers after this specification gate is accepted.

This repository is the authoritative design source for next-generation scope.
Its current status remains Draft: authority here means that implementation
planning shall trace to this specification, not that a phase, product release,
deployment, compliance assertion, or operational connection is approved.

The local-only synthetic non-CUI v0.4 Candidate A gate is a bounded profile of
this roadmap. JC Arcaz is its sole required approval role. The organization,
mission, protected-data, deployment, proposed-ADR, and other named-role
dependencies below remain applicable to their broader work packages but do not
block local v0.4 Gate 0.

## Governed Work Packages

The work packages below allocate implementation and evidence work to the
existing requirement register. They do not create product requirements. Before
work starts, `NG-WP-00` shall verify that the new `MODE-023..MODE-027` startup
and handover requirements are fully allocated and approved, and shall confirm
that registered `DOC-011`, its allocation, and its Draft manual artifact set
remain consistent. Every delta updates allocation, traceability, verification,
migration, and approval records under `DOC-002`, `DOC-006`, and `DOC-009`.

| ID | Work package | Primary coverage | Entry dependencies | Measurable package gate |
| --- | --- | --- | --- | --- |
| `NG-WP-00` | Specification and complete traceability | All current `DOC`, `ARC`, `SRV`, `EXEC`, `COM`, `DATA`, `WEB`, `MODE`, `GIT`, `REL`, `SEC`, `OPS`, `COMP`, `DEP`, and `VNV` families | Named approval roles, closed phase-entry decisions, approved requirement deltas | Reconcile the exact central-ID count by family; assign 100 percent of IDs to an owner, design, work package, phase, verification method, test/result target, and gate; report zero duplicate, orphan, missing, or unapproved normative rows; sign the G0 baseline. |
| `NG-WP-01` | RBAC role-based startup | `MODE-001`, `MODE-013`, `MODE-023` through `MODE-024`, `MODE-027`, `SEC-003` through `SEC-006`, `SEC-010`, `WEB-002`, `WEB-005`, `WEB-013` | `NG-WP-00`; approved identity provider, role/attribute matrix, domain/environment scopes, session and reauthentication policy | A server-signed bootstrap result identifies subject, session expiry, effective capabilities, scopes, permitted modes, selected/required initial mode, policy revision, and reauthentication needs without granting a controller lease. Test every approved single-role and multi-role role/attribute/domain/environment/mode row and negative row; prove the baseline single-role mapping opens Controller in Execution, Monitoring in Monitoring, and Developer in Edit, while Controller without a valid lease remains visibly non-authorizing. Prove no browser-inferred or client-selected role elevates access, excluded capabilities do not merge, revocation takes effect, and every allow/deny/startup-mode decision is audited. |
| `NG-WP-02` | Python backend and data modernization | `ARC`, `SRV`, `EXEC`, `COM`, `DATA`, applicable `SEC`, `OPS`, and `DEP` requirements | `NG-WP-00`; approved service boundaries, state models, schemas, migration/rollback design, identity and secrets | Versioned REST, WebSocket, and internal typed RPC contracts pass schema/compatibility tests; PostgreSQL state/event/audit transactions and migrations pass fresh, upgrade, rollback, restart, and contention tests; browsers and workers have no direct database/driver/GCS path; every mutation is authorized, revision guarded, idempotent, durable, and correlated. |
| `NG-WP-03` | Web UI and Edit Mode modernization | `WEB-001` through `WEB-037`, `MODE-001` through `MODE-027`, `GIT-001` through `GIT-024`, applicable `COM` requirements | `NG-WP-01`, `NG-WP-02`; approved information architecture, API/event schemas, workflow and accessibility criteria | Execution, Monitoring, Edit, and Replay workflows pass the supported browser/viewport matrix, WCAG 2.2 AA checks, authorization and stale-state negative tests, snapshot/cursor recovery, qualified fan-out/load, Git promotion/rollback, and mission-operator workflow acceptance with no direct driver or database access. |
| `NG-WP-04` | Secure two-party controller handover and audit | `SRV-005` through `SRV-009`, `SRV-014` through `SRV-017`, `SRV-021`, `MODE-013` through `MODE-017`, `MODE-021` through `MODE-022`, `MODE-025` through `MODE-027`, `SEC-007`, `SEC-010` through `SEC-011`, `SEC-019` | `NG-WP-01`, `NG-WP-02`; approved `MODE-025..MODE-027` baseline, lease state model, client proof, step-up policy, audit sink | Normal handover requires two distinct authenticated principals and sessions: current holder approval and subsequent request-bound responsibility acknowledgement by the named eligible requester. The transfer atomically terminalizes the old grant, creates and installs a new active lease and higher fence, changes authoritative modes, preserves unresolved-effect visibility, and rejects stale/replayed/expired decisions. Model, race, failover, cancellation, revocation, and negative tests pass; 100 percent of attempts produce a correlated append-only audit chain containing both actors, roles/policy/reason, request/approval/acknowledgement identities, old/new lease revisions and fences, trusted timestamps, and outcome. Forced takeover remains a separately authorized and audited break-glass path. |
| `NG-WP-05` | Final GUI User Manual acceptance and publication | Approved `WEB`, `MODE`, `GIT`, `DOC`, and operator-facing `REL` behavior | Produced `DOC-011` Draft artifacts; stable accepted UI workflows from `NG-WP-03` and `NG-WP-04`; approved publication path, audience, classification, and build identity | Finalize the controlled source and `SPELL_GUI_USER_MANUAL.pdf`, bound to the exact accepted product/specification versions and digests. A coverage matrix accounts for 100 percent of approved critical workflows, including RBAC startup, modes, control acquisition/handover/loss, procedure execution, monitoring, editing/Git, prompts, alarms, degraded/offline/recovery, and support. Automated link/metadata/accessibility checks, page render review, secret/CUI scan, screenshot-to-build verification, and representative operator sign-off pass with no unresolved critical documentation defect. |
| `NG-WP-06` | NIST SP 800-171 Rev. 3 implementation evidence | `SEC-001` through `SEC-023`, `VNV-007`, `VNV-012`, supporting architecture/operations requirements | Governing applicability and operated-on-behalf decisions; approved CUI boundary/flows, SSP, ODP register, responsibility model, assessor plan, exact deployed baseline | Account for all 17 Rev. 3 families, every requirement in the pinned SP 800-171 catalog, and every applicable SP 800-171A Rev. 3 determination statement. Each applicable row has implementation, owner/custodian, method, evidence digest, result, finding/POA&M/risk disposition, and assessed artifact identity; zero unassigned ODPs or unresolved applicability rows remain for the asserted scope. SP 800-172 Rev. 3 is included only when selected by the governing authority. Evidence supports, but does not itself create, compliance or authorization. |
| `NG-WP-07` | Reliability, recovery, and operational resilience | `REL-001` through `REL-029`, `OPS-001` through `OPS-010`, reliability-related `ARC`, `SRV`, `EXEC`, `DATA`, and `DEP` requirements | `NG-WP-02`; approved workload, `REL-PAR-*` values, topology, failure domains, RPO/RTO, capacity and degradation policy | Execute the approved failure matrix across process, host, network, identity, clock, storage, database, site, restore, upgrade, and effect-uncertainty boundaries. All safety invariants hold; measured availability/freshness/latency/capacity and recovery meet the approved profile; backup/restore, failover/failback, audit continuity, graceful degradation, watchdog, and runbook exercises have evidence-bound results and no unresolved mandatory failure. |
| `NG-WP-08` | Integrated test, V&V, documentation acceptance, and release decision | `VNV-001` through `VNV-012` and every requirement under test | All package-specific entry criteria; approved fixtures, environments, workload, evidence schema, acceptance roles | Bidirectional traceability covers 100 percent of the approved scope from requirement through design, implementation, test, result, finding, and approval. Required unit, contract, integration, property/model, fault, security, browser, accessibility, performance, recovery, manual, and operator-validation suites pass against exact artifact digests. Gates G0 through G9 record explicit pass, block, or authorized time-bounded exception; all required acceptance-checklist roles sign the exact baseline. |

### NG-WP-00 Current Readiness

The Draft contains controlled allocation rules, a 366-row broader-spec registry
bound to canonical requirement-record digests, stable planned test/result
identifiers, a local project-owner record, a G0 validator with adversarial unit
tests, and a validated exhaustive seven-source compatibility catalog. All 366
broader-spec rows are generated as `OUTSIDE_LOCAL_V04_GATE`. The catalog covers
all 304 pages and all 195 Language Reference examples and assigns each row to
Candidate A or Deferred/`EXCLUDE`; excluded rows are not implementation or
executed-fixture claims.

The exhaustive compatibility catalog, fresh independent review, final
count/digest reconciliation, exact owner-record manifest binding, and pinned
Python 3.13 qualification pass. Local Gate G0 is `PASS` for 1,682 rows: 125
v0.4 and 1,557 Deferred. The ten broader Phase-entry
decisions, composite owners, organization signers, and proposed ADR approvals
remain future-program inputs and are not local blockers. No trusted signature
or signed tag is claimed or required for this working-tree gate record. The
exact disposition and evidence inputs are in
[`G0_READINESS_PACKAGE.md`](G0_READINESS_PACKAGE.md).

Package work may overlap only after shared prerequisites are accepted. Package
completion never inherits to a later environment, adapter, satellite, effect
class, or release; each claim is limited to its recorded evidence scope.

The `DOC-011` Draft deliverable is already produced as controlled
`web/SPELL_GUI_USER_MANUAL.md`, a versioned
`web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf`, four
concept figures, print CSS, and reproducible renderer tools. This artifact set
does not close `NG-WP-05`: final build binding, accepted-workflow reconciliation,
publication verification, and representative operator acceptance remain later
package gates.

## Phase 0 - Authoritative Specification Gate

**Deliver:** approved source authorities, requirements, ADRs, domain model,
protocol/data/security/operations designs, complete feature-level compatibility
rows for the next implementation scope, threat model, SSP plan, test architecture,
workload profile, open-decision closure, the governed work-package register,
complete allocation and approval of `MODE-023..MODE-027`, approval of registered
and allocated `DOC-011` and its Draft artifact disposition, a complete
requirement-family allocation report, and a signed documentation baseline
(`NG-WP-00`).

**Exit:** G0 passes; no safety, security, state, protocol, or compatibility value
needed by the next phase remains implicit. The exact requirement count is
reconciled by family and every approved ID has one work package, phase, owner,
verification method, and acceptance target.

## Phase 1 - Secure Platform Spine

**Deliver:** identity integration, deny-by-default server-side authorization,
the signed role/attribute/domain/environment startup bootstrap from `NG-WP-01`, domain registry,
PostgreSQL migrations/invariants, append-only committed events, audit export,
object artifact boundary, configuration validation, service identity, secrets,
health/readiness, release provenance, Satellite Assignment Authority contracts
and a non-operational emulator, non-rollback generation-anchor and Effect
Authorization Point contracts/emulators, the backend modernization foundation
from `NG-WP-02`, and local deterministic deployment.

No procedure language or GCS effect is required to prove this spine.

**Exit:** the complete startup authorization matrix and revocation tests pass;
domain isolation, state/event/audit atomicity, fencing primitives, signed build,
schema migration/rollback, backup/restore, security baseline, and observability
pass their tests.

## Phase 2 - Bounded Runtime And Deterministic Simulator

**Deliver:** non-executing parser/semantic analyzer, versioned data-only IR,
immutable bundles, one isolated sandbox per execution, machine-readable state
machines and exhaustive transition tests, variables,
conditions, timers, waits, prompts, checkpoints, as-run record, parent-child
execution foundation, and deterministic simulator driver lifecycle.

Only compatibility rows approved for this phase may be implemented.

**Exit:** language and driver conformance, state/property tests, crash recovery,
prompt races, resource bounds, deterministic replay, and as-run reconstruction
pass with no arbitrary code path.

## Phase 3 - Web Execution And Monitoring

**Deliver:** responsive web shell, domain/execution workspaces, controller lease
and fencing workflow, the normal two-party handover and correlated audit path in
`NG-WP-04`, Execution and Monitoring modes, hierarchical catalog,
snapshot/cursor WebSocket projections, logs/events/variables/telemetry/prompts/
alarms/notifications, connection freshness, degraded state, accessibility, and
reconciliation of the produced `DOC-011` Draft manual with the implemented
workflows in preparation for `NG-WP-05`.

**Exit:** one-controller and two-party handover invariants, complete lease/audit
transition coverage, read-only negative tests, gap/reconnect/failover tests,
critical operator workflows, accessibility, and qualified monitor fan-out pass.

## Phase 4 - Git-Backed Edit And Promotion

**Deliver:** Edit Mode, repository/project browsing, safe editor/language services,
diagnostics, dependency analysis, review checks, protected promotion, signed
content-addressed bundles, catalog activation, deletion/retention, rollback, and
the Edit/Git procedures and validated screenshots required by the GUI User
Manual coverage matrix.

**Exit:** deterministic rebuild, provenance/signature verification, policy and
separation-of-duty tests, malicious repository corpus, promotion/rollback, and
active-execution pinning pass.

## Phase 5 - Read-Only Driver Services

**Deliver:** approved time, telemetry, event/resource read, limits/alarm state,
lookup, and other read-only capabilities through typed isolated adapters. Begin
with the simulator; optionally add one structurally read-only legacy observation
adapter after independent review.

**Exit:** capability negotiation, schema/quality/time semantics, stream loss and
backpressure, adapter failure/restart, cross-comparison, and read-only enforcement
pass.

## Phase 6 - Controlled Effect Services

**Deliver:** one approved effect class per tranche, such as simulator event or
resource mutation, then telecommand construction and dispatch. Include policy,
dual control where assigned, stages, acknowledgment, effect certainty,
reconciliation, cancellation, limits, audit, and rollback. All effect paths use
the sole credentialed Effect Authorization Point and database-serialized
one-use permit/lease race semantics.

**Exit:** hazard analysis and independent conformance/fault testing prove partial,
duplicate, timeout, disconnect, and uncertain-effect behavior. Passing one effect
class does not authorize another.

## Phase 7 - High Availability And Operational Resilience

**Deliver:** `NG-WP-07`: production topology, highly available mission-wide Satellite
Assignment Authority, grant-bound effect credentials, fenced active-passive domain authority,
mandatory non-rollback generation anchor, highly available Effect Authorization
Point, horizontally scaled read/API/event projection, PostgreSQL HA/PITR, cross-site
backup and recovery, capacity protection, rolling upgrade, security monitoring,
incident response, runbooks, and exercises.

**Exit:** the approved failure matrix and `REL-PAR-*` profile pass with evidence-
bound availability/freshness/latency/capacity, failover, RPO/RTO, site recovery,
audit continuity, security assessment, graceful-degradation, and operator
exercise results.

## Phase 8 - Migration And Operational Readiness

**Deliver:** inventory and convert candidate procedures, simulator qualification,
read-only shadow comparison, operator training, parallel run, cutover/rollback
plan, mission-specific SSP/assessment evidence, support model, and capability-
scoped authorization package. A pre-SAA source requires a complete legacy
adoption inventory and independently verified fence evidence for every command
credential, session, endpoint, egress route, interlock, and operator path. The
target generation and incarnation are externally anchored and reserved as
effect-disabled before final evidence collection; every evidence item binds
that target, and activation plus effect credentials follow fencing,
reconciliation, local-authority establishment, and readiness approval.

Finalize `NG-WP-05` from the accepted product workflows and exact candidate
build, complete the objective-level SP 800-171/171A evidence package in
`NG-WP-06`, and run the integrated `NG-WP-08` V&V and acceptance decision. The
GUI User Manual PDF, security evidence, test results, and acceptance signatures
shall all identify the same candidate artifact and configuration digests.

**Exit:** the designated operational authority accepts the exact mission,
satellite, environment, adapter capabilities, procedure set, residual risk,
monitoring, support window, and rollback. Every applicable security objective
and approved product requirement has an evidence disposition, the user manual
has no unresolved critical defect, all mandatory gates are closed, and legacy
retirement remains a separate decision.

## Requirement-Family Coverage Gate

This table is a planning allocation, not evidence that any requirement is
implemented. `NG-WP-00` shall regenerate the exact ID ranges and counts from the
approved central register whenever a requirement changes.

| Central family | Primary work packages | Principal phases | Completion rule |
| --- | --- | --- | --- |
| `DOC-001..DOC-011` | `NG-WP-00`, `NG-WP-05`, `NG-WP-08` | 0, 3, 4, 8 | Baseline control, manual source/PDF, allocation, CI, evidence, and approvals reconcile. |
| `ARC-001..ARC-040` | `NG-WP-02`, `NG-WP-07`, `NG-WP-08` | 1, 2, 7, 8 | Every trust, authority, effect, scale, and isolation boundary has implementation and invariant evidence. |
| `SRV-001..SRV-022` | `NG-WP-02`, `NG-WP-04`, `NG-WP-07`, `NG-WP-08` | 1, 3, 7, 8 | Domain, leader, controller, concurrency, lifecycle, handover, and assignment states are exhaustively verified. |
| `EXEC-001..EXEC-028` | `NG-WP-02`, `NG-WP-03`, `NG-WP-07`, `NG-WP-08` | 2, 3, 5, 6, 8 | Each implemented language/runtime/effect row has conformance, state, recovery, and certainty evidence. |
| `COM-001..COM-027` | `NG-WP-02`, `NG-WP-03`, `NG-WP-07`, `NG-WP-08` | 1, 3, 5, 7, 8 | REST, WebSocket, typed RPC, cursor/privacy, retry, capacity, and failure contracts pass. |
| `DATA-001..DATA-029` | `NG-WP-02`, `NG-WP-07`, `NG-WP-08` | 1, 2, 4, 7, 8 | Ownership, schema, transaction, retention, migration, backup, and decision-evidence rules pass. |
| `WEB-001..WEB-037` | `NG-WP-01`, `NG-WP-03`, `NG-WP-05`, `NG-WP-08` | 3, 4, 8 | All approved workflows pass browser, accessibility, security, freshness, load, and documented-use acceptance. |
| `MODE-001..MODE-027` | `NG-WP-01`, `NG-WP-03`, `NG-WP-04`, `NG-WP-05`, `NG-WP-08` | 1, 3, 8 | Role, mode, lease, startup, handover, takeover, and read-only matrices have positive and negative evidence. |
| `GIT-001..GIT-024` | `NG-WP-03`, `NG-WP-05`, `NG-WP-08` | 4, 8 | Authoring, review, validation, promotion, rollback, retention, and user guidance pass. |
| `REL-001..REL-029` | `NG-WP-07`, `NG-WP-08` | 1, 7, 8 | Every approved reliability parameter and failure/recovery scenario has a measured disposition. |
| `SEC-001..SEC-023` | `NG-WP-01`, `NG-WP-02`, `NG-WP-04`, `NG-WP-06`, `NG-WP-08` | 0, 1, 3, 7, 8 | Technical and organizational responsibility, NIST objective, audit, assessment, and evidence rows reconcile. |
| `OPS-001..OPS-010` | `NG-WP-02`, `NG-WP-07`, `NG-WP-08` | 1, 7, 8 | Observability, runbook, incident, capacity, time, maintenance, and exercise evidence passes. |
| `COMP-001..COMP-022` | `NG-WP-00`, `NG-WP-02`, `NG-WP-03`, `NG-WP-08` | 0, 2 through 6, 8 | Every claimed manual construct, workflow, service, example, and deviation has an approved disposition and oracle. |
| `DEP-001..DEP-025` | `NG-WP-02`, `NG-WP-07`, `NG-WP-08` | 1, 7, 8 | Build, topology, environment, upgrade, rollback, integrity, and operational-profile evidence passes. |
| `VNV-001..VNV-012` | `NG-WP-08` | 0 through 8 | Every claim is evidence-bound and bidirectionally traced; mandatory gates and required signatures close. |

The coverage report fails G0 or the affected later gate when a central ID is
unallocated, mapped only to prose, missing an owner/test/result target, or
linked to evidence from a different artifact, configuration, or environment.

## Critical Dependencies

| Dependency | Must precede |
| --- | --- |
| Approved `MODE-023..MODE-027` and complete `NG-WP-00` family allocation | Any implementation of role-based startup or two-party handover |
| CUI boundary, identity, authorization, audit and environment separation | Any protected-data or multi-user deployment |
| Approved IdP/session policy and role/attribute/domain/environment/mode matrix | RBAC startup qualification |
| RBAC bootstrap, client proof, lease/fence state model, step-up policy and durable audit admission | Two-party controller handover implementation |
| Versioned backend REST/WebSocket/RPC/state contracts | Integrated web UI implementation and browser acceptance |
| Accepted critical UI workflows and exact releasable build | Final screenshots, procedures, and publication of `SPELL_GUI_USER_MANUAL.pdf` |
| Source authority and detailed compatibility rows | Each language/driver feature implementation |
| Immutable bundles and exact source identity | Runtime catalog and operational execution |
| Transactional events, revisions, leases and fencing | Real-time UI and HA |
| Simulator conformance | Any legacy/operational adapter |
| Read-only adapter proof | Controlled legacy procedure-control consideration |
| Effect certainty and reconciliation | Any externally effectful capability |
| Non-rollback assignment anchor, legacy adoption, and final Effect Authorization Point | Any real command-path activation or migration |
| Mission-wide satellite assignment and independently proven old-path fencing | Any real command-path activation, cutover, restore, failover, or failback |
| Workload, RPO/RTO and topology decisions | HA/performance qualification |
| Governing applicability, CUI boundary, SSP, ODPs, assessment plan and evidence ownership | SP 800-171 Rev. 3 assessment or compliance assertion |
| Package-specific results and zero unresolved mandatory gate failures | Integrated `NG-WP-08` acceptance and any release decision |

## Increment Definition Of Done

An increment is done only when requirements and compatibility rows are approved,
implementation and schemas are reviewed, tests and evidence bind to exact
artifacts, threat/hazard/operations documents are current, migrations and rollback
are exercised, all mandatory gates pass, residual findings are dispositioned, and
the accountable owner approves the intended environment. The requirement-family
coverage report shall show no orphan or evidence-free ID for the increment, and
user-facing changes shall update and verify the GUI User Manual source and PDF
before the documentation gate closes. Merge, deployment, demonstration, a PDF,
or a control mapping alone does not establish completion.
