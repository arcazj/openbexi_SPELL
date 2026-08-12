# Prompt History

This document records approved project requests, planning decisions, delivery
status, and unresolved issues by OpenBEXI SPELL version. The current version is
inserted at the top so it is visible first; earlier entries retain their original
delivery order. Later versions may supersede a decision but must not rewrite an
earlier request or result.

## 2026-07-18 - v0.4 Gate 0 Pass And Implementation Start

### Gate Result

The final local `G0` / `V04-GATE-0` record passed under the digest-pinned
Python 3.13 image after exact owner-manifest binding. The exhaustive
compatibility catalog reconciles 1,682 approved disposition rows across all
seven sources and 304 pages, with 125 rows in the Candidate A slice and 1,557
Deferred/`EXCLUDE` rows. The compatibility and Gate 0 suites report 21 and 17
passing tests respectively, with zero structural errors or technical blockers.

### Implementation Status

Bounded Candidate A product engineering is authorized and has started. Work is
limited to the exact nine-RPC typed simulator lifecycle boundary, separate
driver host and private journal, mutual service identity, canonical persistence,
and authenticated read-only projection. Existing v0.3 procedure semantics are
not routed through the driver. Candidate B and all telemetry data-plane,
telecommand, operational, connected, mission, broader language, and broader GUI
behavior remain excluded.

This is an implementation-start record, not v0.4 acceptance. Gates 1-5 remain
mandatory, and no release, operational authorization, deployment approval, or
compliance determination is recorded.

## 2026-07-18 - Local v0.4 Candidate A Gate Approval

### Owner Request

JC Arcaz stated: "Revise v0.4 to a local-only, synthetic non-CUI simulator
engineering gate. I, JC Arcaz, am the project owner and approve Candidate A,
its exclusions, budgets, and test plan. Remove organization-only approval
requirements without making operational or compliance claims."

### Gate Revision

The v0.4 gate now requires the project-owner record plus bounded engineering
evidence for Candidate A. Candidate B remains deferred. Organization, mission,
protected-data, assessment, deployment, authorizing-official, proposed-ADR, and
other role-based approvals remain in the broader next-generation records but
are not local v0.4 entry requirements.

The approved worker boundary is bounded non-executing IR plus strict mTLS
credential separation and fail-closed driver authentication. A route may exist
on the shared local development network, but the procedure worker may have no
product call path or usable driver credential. This is a bounded local
engineering decision, not a deployment or isolation claim for another scope.

Gate 0 requires exhaustive source identity/span, classification, Candidate A or
Deferred/`EXCLUDE` disposition, target phase, a unique planned test identity,
errata handling, and reconciled counts. Deferred rows require static source and
negative-scope evidence; they do not require executable fixtures, semantic
oracles, or results and do not claim implementation. In-scope v0.4 fixtures
execute at the applicable later release gates.

### Current Disposition

The owner scope decision is recorded. Product edits remain blocked until the
candidate exhaustive seven-source catalog passes deterministic validation and
fresh independent source review and the exact local gate files are bound by the
owner-record SHA-256 manifest. The manifest is change-detection evidence, not a
signature. No release acceptance, operational authorization, deployment
approval, or compliance determination is recorded by this entry.

## 2026-07-18 - Complete v0.4 Before Beginning v0.5

**Superseded gate note:** The later owner instruction recorded above preserves
the required v0.4-before-v0.5 sequence but replaces this entry's organization-
approval blockers with the local Candidate A owner record and technical Gate 0.
The partial-catalog facts below remain historical checkpoints.

### Owner Request

The owner requested: "so complete V 0.4 and start implementing v 0.5 once V
0.4 done".

This request establishes the required order: Candidate v0.4 must pass its entry
gate, implementation, complete qualification, release decision, commit, and tag
before a separately gated v0.5 implementation may begin. It does not identify
the owner or the other named approval-role holders, sign the exact Draft
baseline, close the ten G0 phase-entry decisions, approve the 366 normative
allocations, or supply the remaining compatibility dispositions. Those actions
cannot be inferred or performed by the project-declared AI assistance tool.

### Current Disposition

Gate G0 and `V04-GATE-0` remain blocked. The next permitted work is the
source-grounded completion of the seven-manual compatibility inventory and
preparation of the exact approval inputs. No v0.4 product runtime, API, schema,
dependency, deployment, or operational change is authorized until the required
named human decisions and signatures are verified. After v0.4 is accepted,
v0.5 requires its own pre-implementation scope, compatibility/errata approval,
requirements, acceptance tests, and entry decision before product edits.

### Bounded Progress

The permitted documentation-conformance increment now represents all seven
authoritative source records and reconciles 257 rows: 195 exact Language
Reference example number/title/page indexes, 40 prior Driver Manual assertions,
and 22 prior Server Manual assertions. The example bodies and oracles are not
decomposed, no fixture or result evidence exists, and their target increment is
unassigned pending `OD-008`. The four GUI, Development Environment, Build, and
GUI 4.0.2 source catalogs still have zero detailed rows; the non-example
Language Reference catalog and the complete Driver and Server catalogs also
remain open. The record contains 195 `Indexed` and 62 `Decomposed` rows, all
`PENDING_HUMAN_APPROVAL`. Focused compatibility and G0 validator tests pass
structurally, while the default G0 decision remains `BLOCKED` as required.

## 2026-07-18 - Roadmap-Directed NG-WP-00 Continuation

**Superseded gate note:** The later local v0.4 revision recorded above removes
the organization-only approvals and signed-baseline conditions described here
from Candidate A Gate 0. This entry remains the factual record of the earlier
bounded increment.

### Owner Request

The owner requested: "move forward according `PROJECT_ROADMAP.md`".

The roadmap keeps Gate G0 blocked and prohibits starting `NG-WP-01` or wiring
the experimental startup modules into the product before named human decisions,
approvals, and a signed baseline. This request therefore authorizes the next
machine-actionable `NG-WP-00` documentation-conformance increment; it is not a
substitute for `OD-023`, per-decision approval, per-requirement signatures, or
the explicit v0.4 product gate.

### Bounded Outcome

A partial Candidate v0.4 compatibility seed was prepared from selected Driver
Development Manual and Server Manual source assertions:

- 62 unique source-bound rows with all 25 required compatibility fields;
- 40 Driver Manual and 22 Server Manual assertions;
- an explicit partial v0.4 scope and digest-pinned reconciliation record;
- a validator and adversarial tests for identity, hashes, pages, schema,
  counts, membership, approval spoofing, and reconciliation freshness; and
- no product runtime, API, schema, dependency, deployment, or operational
  change.

Every row remains `Decomposed` and `PENDING_HUMAN_APPROVAL`. The other five
sources, full Driver and Server catalogs, and all normative examples remain
open. The result does not complete `COMP-001`, `NG-WP-00`, `V04-GATE-0`, or G0
and does not authorize `NG-WP-01`.

## 2026-07-17 - SPELL v0.4 Gate Draft

### Release Identity

| Field | Value |
| --- | --- |
| Version target | 0.4.0 |
| Release name | Typed Simulator Driver and Context Foundation |
| Request type | Next-step planning and pre-implementation gate |
| Status | Gate revised after complete supplied-manual review; owner approval pending |
| Accepted product baseline | Commit `7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`, tag `v0.3.0` |
| Product implementation | Not authorized |
| Operational authorization | None |

### Owner Request

After creating the v0.3.1 roadmap and version timeline, the owner requested:
"implement next step". The roadmap identifies two possible v0.4 foundations
and requires one to be selected through a new pre-implementation gate.

This request is recorded as authorization to draft the next required planning
gate, not as unambiguous approval to change product behavior. Candidate A was
selected for the draft because v0.3 explicitly carries driver-host contracts
forward to v0.4 and it is the prerequisite for documented simulator service
conformance and eventual read-only legacy observation. Candidate B remains
deferred from v0.4.

The owner then requested a complete review of the SPELL documentation under
`SPELL-DOCUMENTATION/`, a roadmap revision, and a check that future development
follows the documentation closely. Seven PDFs totaling 304 pages were reviewed
page by page on 2026-07-17. That request authorizes documentation-conformance
and planning corrections only; it does not approve v0.4 product implementation.

### Consolidated Version 0.4 Gate Prompt

Before any v0.4 product edit, propose one bounded, simulator-only Typed
Simulator Driver and Context Foundation release based on the accepted v0.3.0
tag and the complete supplied-manual review.

The proposal must:

- Define a versioned protobuf/gRPC contract with bounded typed messages,
  deterministic generated code, explicit compatibility rules, and a
  capability/version/identity/configuration/generation handshake.
- Separate host, context-binding, execution-attachment, capability lifecycle,
  and operation state; carry stable server-profile, context, execution,
  driver-binding, and operation identity.
- Define typed host-profile, context-binding, and execution-attachment
  configuration with separate generations/digests, explicit precedence,
  out-of-band secret references, granular capabilities, setup/cleanup order,
  and named host/per-context capacity.
- Add exactly one bundled deterministic simulator driver in a separate
  non-root, read-only host with no published port, database route, public route,
  mission route, or arbitrary endpoint configuration.
- Limit the driver surface to the nine infrastructure methods `Handshake`,
  `Health`, `OpenContext`, `CloseContext`, `AttachExecution`,
  `DetachExecution`, `CancelLifecycleOperation`, `DrainHost`, and
  `GetOperation`.
- Keep the control-plane supervisor as the sole gateway and owner of canonical
  project-database, audit, and event persistence. Give the driver only a
  private bounded idempotency journal for restart reconciliation; neither the
  browser nor the procedure worker may hold a usable driver credential or
  invoke the host directly under the approved threat model.
- Use mutual service authentication independent of browser JWTs, with no
  insecure fallback and no credential leakage into workers, clients, logs,
  events, reports, images, SBOMs, or packages.
- Persist a stable operation ID before dispatch, deduplicate retries by that
  identity, separate lifecycle stage from effect certainty, fence stale
  generations, and latch uncertain outcomes for reconciliation without
  automatic resend.
- Add only authenticated read-only driver snapshots and console projection; no
  browser driver-control mutation is allowed.
- Define fresh/populated SQLite and PostgreSQL migrations, rollback, failure
  injection, compatibility regression, local performance budgets, dependency
  locks, audits, driver SBOM, and reproducible v0.4 evidence.
- Parameterize release evidence so v0.4 cannot overwrite or satisfy itself with
  retained v0.3 artifacts.
- Record a populated compatibility disposition and errata process for every
  documented language artifact, server/configuration item, driver contract,
  operator/development workflow or view, build/deployment concept, and example
  without implementing later language, UI, development, telemetry, or command
  phases in v0.4.

Do not add telemetry or telecommand driver services, route existing procedures
through the host, add new procedure syntax, implement prompt-result binding,
connect to a live or legacy GCS or spacecraft, permit arbitrary endpoints, add
externally effective behavior, or claim operational authorization.

### Unresolved Entry Decisions

The owner must explicitly resolve or approve:

1. Candidate A as the sole v0.4 product scope and Candidate B as deferred.
2. Worker-to-driver network and credential isolation. Workers currently share
   the backend container network namespace, so route isolation is not yet a
   supported claim.
3. Contract namespace, compatibility rules, bounded messages, lifecycle
   methods, context/execution identity, configuration precedence, capabilities,
   capacity, errors, stages, certainty values, and deterministic simulator
   fixture.
4. Local mutual-authentication identity issuance, rotation, expiry, revocation,
   storage, and redaction.
5. Migration, canonical operation-ledger, private driver-journal
   retention/corruption/fail-closed behavior, read-only API/event, rollback,
   performance, and release-evidence designs.
6. The intended clean repository change set, excluding unrelated staged,
   modified, untracked, and potentially credential-bearing artifacts.
7. A populated exhaustive cross-manual compatibility ledger, reconciled
   per-manual artifact counts, errata decisions, and any
   licensing/publication boundary for the external PDFs.

### Entry Decision

**Pending.** [`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md)
and the v0.4 section of [`Test_and_Integration.md`](Test_and_Integration.md) are
draft proposals. Their creation does not approve the release or authorize
implementation. Product code, schemas, dependencies, services, and deployment
configuration must remain unchanged until the owner explicitly approves or
revises the complete gate.

### Gate Draft Outcome

The v0.4 scope, exclusions, trust boundary, operation-certainty model,
requirements, planned tests, local budgets, rollback, risks, and entry/exit
criteria were documented on 2026-07-17. The later page-complete manual review
revised the gate to include context/execution binding, typed configuration,
granular capability/capacity, lifecycle ordering, documentation traceability,
and package lifecycle tests. It also reordered future work so documented
simulator language, operator, telemetry, data, development, auxiliary service,
and telecommand conformance precedes legacy observation. No v0.4 product
implementation, qualification result, release commit, tag, or operational
authorization is claimed. The required populated compatibility ledger and
owner gate decision remain incomplete.

## 2026-07-16 - SPELL v0.3

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.3 |
| Release name | Simulator Hardening and Language Foundation |
| Request type | Hardening, restricted-language expansion, and validation workflow |
| Status | Delivered and accepted as a local simulator engineering release |
| Baseline | Commit `7df7743`, tag `v0.2.0` |
| License | Apache License 2.0 |
| Operational authorization | None |

### Owner Request

Execute all recommendations required before v0.3, show the newest version at
the top of this history, license the new implementation under Apache License
2.0, and then deliver SPELL v0.3.

### Consolidated Version 0.3 Prompt

Freeze the verified v0.2 simulator baseline in source control without
committing IDE metadata or legacy reference archives. Add the official Apache
License 2.0 text and project notice, preserve the v0.2 evidence, and tag the
baseline `v0.2.0`.

Before v0.3 implementation, define its exact requirements, exclusions,
acceptance tests, performance budgets, security dispositions, and evidence
rules in `SPELL_v0.3_Pre-Implementation.md`, `PROMPT_History.md`, and
`Test_and_Integration.md`.

Then implement one simulator-only v0.3 release that:

- Uses versioned migrations for fresh and existing SQLite/PostgreSQL stores.
- Uses signed JWT claims and server-enforced roles, with an explicitly gated
  loopback development issuer for the local console.
- Removes general backend outbound networking through the Compose topology.
- Produces hash-locked Python dependencies, reproducible packages, SBOMs, and
  zero unreviewed dependency advisories.
- Expands the non-executing procedure IR with typed variables, safe
  expressions, conditions, bounded loops, reusable local calls, and durable
  variable checkpoints.
- Adds validation-only REST and 2D console workflows without persistent
  authoring or Python source execution.
- Exercises concurrency, faults, migrations, restart/recovery, 10,000-event
  replay, accessibility, performance, and a sustained local soak.

Do not add Java, Three.js, arbitrary Python execution, drivers, GCS or
spacecraft connections, operational commanding, high availability, or
operational authorization.

### Entry Decision

The owner explicitly authorized this bounded v0.3 work. The v0.2 baseline was
committed and tagged before v0.3 product edits. Implementation may begin only
after the v0.3 test section in `Test_and_Integration.md` is present. Release
acceptance requires actual evidence or an explicit non-safety exception for
every v0.3 test.

### Version 0.3 Implementation Outcome

Version 0.3 was finalized on 2026-07-16 under Apache License 2.0. It delivered
versioned SQLite/PostgreSQL migrations, strict signed JWT identity and roles,
internal-only backend/database networking, hash-locked dependencies, SBOMs,
reproducible packaging, the typed restricted language and variable recovery,
and transient API/console validation.

Final verification passed 112 backend tests with one PostgreSQL-only skip under
network-disabled SQLite, all 113 tests on PostgreSQL, 13 frontend unit tests, a
strict production build, 16 desktop/mobile browser tests, and 26 release-tooling
tests. The 100-command latency and 10,000-event replay gates passed. Two
independent Chromium processes each received all 6,002 sequences at 100.022
events/second after an explicit subscription-readiness handshake, and the
10-minute soak persisted 12,001 exact events at 20.002 events/second with
bounded scheduling lag and memory growth. Dependency audits reported no known
product dependency vulnerabilities; separate backend, proxy, and frontend SBOMs
and their checksum manifest were generated.

The release is recorded in `SPELL_v0.3_Release.md` and tagged `v0.3.0`. No GCS,
spacecraft, driver, Java, arbitrary Python execution, Three.js, or operational
authorization was added.

## 2026-07-12 - SPELL v0.1

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.1 |
| Release name | Pre-Implementation Baseline |
| Request type | Documentation, research, and architecture only |
| Status | Delivered; awaiting review and approval |
| Product implementation | Not authorized |
| Operational authorization | None |

### Prompt Lineage

The v0.1 request was developed through the following user decisions:

1. Replace inherited OpenBEXI Earth Orbit instructions with project-specific
   SPELL guidance.
2. Use the supplied legacy SPELL Core, COTS, and GUI archives as references.
3. Read the Server, GUI, Language, Driver Development, Development Environment,
   and Build manuals before implementation.
4. Plan a new Python implementation with no Java components.
5. Replace the Eclipse GUI with a real-time 2D web interface.
6. Revisit the SPELL APIs and real-time execution architecture.
7. Deliver every pre-implementation artifact together as SPELL v0.1 before any
   implementation begins.
8. Create `PROMPT_History.md`, `Test_and_Integration.md`, and `README.md`, and
   make the test plan a prerequisite for every later version.
9. Treat v0.1 as the approved behavioral and architectural contract and reserve
   the first simulator-only implementation slice for v0.2.

### Consolidated Version 0.1 Prompt

Produce a complete planning baseline for a modern replacement of SPELL using the
supplied legacy archives, embedded manuals, version-specific source behavior,
and reproducible legacy traces as the compatibility reference.

This is a documentation-only release. Do not create backend, frontend, procedure
engine, driver, database, deployment, or integration code. Do not modify the
legacy archives or connect to a live Ground Control System or spacecraft.

The planned target must:

- Use Python 3 for the backend, execution engine, services, and procedure SDK.
- Contain no Java or Eclipse RCP/SWT components.
- Provide a real-time 2D browser-based operator interface.
- Preserve readable, sequential SPELL procedure behavior where practical.
- Keep spacecraft and Ground Control System behavior behind typed drivers.
- Preserve execution control, monitoring, prompts, telemetry, telecommands,
  variables, resources, logs, recovery, replay, and as-run evidence.
- Redesign the legacy client/server API into versioned REST commands and
  snapshots, ordered WebSocket events, internal typed gRPC services, and a
  versioned Python procedure SDK.
- Use isolated procedure workers and separate driver hosts so that neither the
  API server nor browser directly executes or accesses operational integrations.
- Persist authoritative command, event, prompt, state, checkpoint, and audit
  data before projecting real-time updates.
- Treat an uncertain telecommand result as reconciliation-required and never
  repeat it automatically.
- Migrate incrementally using simulators, legacy adapters, golden traces,
  differential execution, parallel operation, and rollback.

Before defining the target, locate and review:

- SPELL Server Manual.
- SPELL GUI User Manual.
- SPELL Language Reference.
- SPELL Driver Development Manual.
- SPELL Development Environment Manual.
- SPELL Build Manual.
- All relevant material in `SPELL2.6.10-src.zip`,
  `SPELL-COTS-2.6.10.zip`, and
  `SPELL_GUI_4.0.12-win32.win32.x86.zip`.

Record versions, applicable components, behavior to preserve, obsolete
technology, compatibility-sensitive interfaces, safety/recovery behavior,
missing information, and conflicts. Do not invent behavior when evidence is
missing.

Deliver one coordinated v0.1 package containing:

1. Manual and source review.
2. Legacy component and capability inventory.
3. State-transition and command matrix.
4. Documented-versus-implemented comparison.
5. Stable, traceable requirements.
6. Target architecture and legacy-to-new mapping.
7. REST, WebSocket, gRPC, event, command, and procedure SDK direction.
8. Procedure-language and configuration migration strategy.
9. Ground Control System driver architecture.
10. Real-time 2D operator-interface specification.
11. Persistence, checkpoint, recovery, and as-run strategy.
12. Security, safety, licensing, and supply-chain assessment.
13. Test, simulation, replay, fault-injection, accessibility, and performance
    strategy.
14. Phased implementation, parallel validation, cutover, and rollback plan.
15. Architecture decisions, risks, assumptions, missing information, and
    unresolved decisions.

Create the v0.1 test plan before the master deliverable. Update and approve the
test plan before implementation of every later version. Do not begin v0.2 until
the complete v0.1 package is reviewed and explicitly approved.

### Inputs Reviewed

| Input | Result |
| --- | --- |
| `SPELL2.6.10-src.zip` | Core C++/Python source, interfaces, configuration, build, deployment, and sparse tests inventoried |
| `SPELL-COTS-2.6.10.zip` | Obsolete/mixed dependency bundle inventoried; not accepted for target reuse |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | Binary Eclipse GUI, plug-in capabilities, and embedded manuals inventoried |
| Server Manual 2.4.4 | Reviewed as older configuration/startup evidence |
| GUI User Manual 2.4.4 | Reviewed for operator workflows and execution control |
| Language Reference 2.4.4 | Reviewed for procedure and service semantics |
| Driver Development Manual 2.4.4 | Reviewed for GCS abstraction and service contracts |
| Build Manual 2.4.4 | Reviewed for legacy build/component context |
| Server Communication ICD draft | Reviewed as historical API evidence only |
| Development Environment Manual | Not found; recorded as an open gap |

### Decisions

| Decision | Status in v0.1 |
| --- | --- |
| New implementation with legacy behavioral compatibility | Accepted direction |
| Python 3 backend and engine | Accepted direction |
| No Java in target product | Accepted direction |
| Real-time 2D web interface | Accepted direction |
| No Three.js in 2D baseline | Proposed |
| Modular control plane before microservices | Proposed |
| Isolated procedure workers | Proposed |
| Out-of-process typed driver hosts | Proposed |
| REST commands, WebSocket events, internal gRPC | Proposed |
| PostgreSQL authoritative store | Proposed |
| React and strict TypeScript console | Proposed |
| Simulator-only v0.2 vertical slice | Proposed for approval |

### Delivered Documents

- `SPELL_v0.1_Pre-Implementation.md`
- `Test_and_Integration.md`
- `README.md`
- `PROMPT_History.md`

`PROMPT_Instructions.md` remains the durable project-wide execution reference.

### Important Findings

- Manual content is 2.4.4 while the source and GUI packages identify as 2.6.10
  and 4.0.12 respectively.
- The required Development Environment manual was absent from the evidence
  supplied for v0.1. It was supplied and reviewed later on 2026-07-17.
- Core release notes stop before the archive version and GUI release notes stop
  before the product version.
- The core has dual Python 2/3 executors, while the target will be Python 3 only.
- Legacy GUI/client IPC is custom socket messaging; driver gRPC is separate and
  contains weakly typed payloads and insecure defaults.
- The source includes no substantive core automated test suite.
- Optional/proprietary drivers referenced by build metadata are absent.
- The COTS bundle is obsolete, duplicated, mixed-license, and not reproducible
  as supplied.
- Legacy material includes internal infrastructure references and a draft ICD
  with a confidentiality marking; publication boundaries require review.

### Approval Status

The v0.1 documentation package is delivered as a draft for review. Approval is
not inferred from delivery. Product implementation remains blocked until the
project owner approves or revises the architecture, requirements, safety model,
test plan, unresolved issues, and v0.2 entry scope.

This was the status at v0.1 delivery. The explicit bounded approval recorded in
the v0.2 entry below supersedes this implementation block for that scope only.

## 2026-07-12 - SPELL v0.2

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.2 |
| Release name | Simulator Vertical Slice |
| Request type | First bounded implementation release |
| Status | Approved to begin; v0.2 pre-implementation test plan recorded |
| Product implementation | Authorized only for the scope below |
| Operational authorization | None |

### Approval Record

The project owner asked whether v0.2 could proceed, accepted the recommended
conditional gate, and then requested v0.2 incorporating all recommendations.
This records approval of the v0.1 baseline for this bounded implementation
slice. It does not approve live Ground Control System (GCS), spacecraft,
production, or operational use.

At the time of the v0.2 gate, the missing SPELL Development Environment manual
was waived for v0.2 only because this release did not implement the full
authoring environment. The manual was later supplied and reviewed on
2026-07-17. Operational workload profiles and service-level objectives were
also deferred; v0.2 used provisional local engineering targets only.

### Consolidated Version 0.2 Prompt

Implement one clean-room, simulator-only vertical slice of the new SPELL
architecture. Do not copy legacy implementation code. Legacy manuals, archives,
source inspection, and reproducible behavior may be used to define compatibility
requirements and tests, subject to the unresolved legal and publication review.

Before implementation, update `PROMPT_History.md` and
`Test_and_Integration.md`. Then implement only the following capabilities:

- A Python 3 modular control plane.
- Procedure execution in an isolated operating-system worker process, never in
  the API process.
- A small, explicitly documented and restricted procedure subset parsed into a
  validated AST or intermediate representation; arbitrary legacy Python is out
  of scope.
- Versioned REST resources for snapshots and durable start, pause, resume,
  prompt-response, and abort commands.
- Idempotency keys and expected execution revisions for every state-changing
  request.
- Ordered downstream WebSocket events with event identity, per-execution
  sequence, schema version, timestamps, and correlation metadata.
- Snapshot-plus-cursor resynchronization after a client reconnect or detected
  sequence gap.
- PostgreSQL as the target authoritative store, accessed behind a persistence
  boundary. SQLite is permitted as a fast local development and unit-test
  fallback. PostgreSQL integration verification will be attempted using the
  project Docker Compose environment.
- A React and strict TypeScript real-time 2D operator console with no Java and
  no Three.js dependency.
- One-procedure load, validation, execution, current-line display, pause,
  resume, durable prompt, safe abort, controlled worker-crash recovery, and an
  auditable as-run report.

Use deterministic simulator inputs, an injectable clock where required, and
versioned procedure/configuration identities. Persist authoritative command,
event, prompt, state, checkpoint, and audit changes before projecting them to
the browser. A command or prompt response must have one durable outcome even
when the client retries or reconnects.

### Scope Boundaries

Version 0.2 must not include:

- A live, legacy, or non-operational GCS connection.
- A spacecraft connection or operational telecommand capability.
- Production deployment, high availability, or operational authorization.
- Full legacy procedure-language or Python 2 compatibility.
- Java, Eclipse RCP/SWT, Three.js, or a complete development environment.
- Proprietary driver implementation or reuse of the legacy COTS bundle.
- Automatic retry of an externally effective or outcome-uncertain action.

The simulator interface must be incapable of resolving to an operational
endpoint through normal v0.2 configuration. Tests and demonstrations must use
only synthetic, recorded, or deterministic simulated data.

### Accepted And Deferred Decisions

| Decision | v0.2 disposition |
| --- | --- |
| Clean-room implementation | Accepted for v0.2 |
| Python 3 control plane and isolated worker | Accepted |
| Restricted AST/IR procedure subset | Accepted |
| REST commands and ordered WebSocket events | Accepted |
| Idempotency and optimistic revision checks | Accepted |
| PostgreSQL target persistence | Accepted direction |
| SQLite fast local and unit-test fallback | Accepted; does not replace PostgreSQL integration evidence |
| PostgreSQL Docker Compose integration run | Planned for v0.2 verification |
| React with strict TypeScript 2D console | Accepted |
| Simulator-only safety boundary | Mandatory |
| Operational latency, load, availability, and retention SLOs | Deferred pending workload evidence |
| Full Python 2 and legacy language compatibility | Deferred |
| Internal gRPC worker/driver boundary | Target direction; not required unless the v0.2 slice needs it |
| Production authentication, HA, deployment, and live GCS drivers | Deferred and not authorized |

### Version 0.2 Deliverables

1. The updated history and approved v0.2 test and integration plan.
2. The bounded Python 3 control plane and isolated worker vertical slice.
3. The restricted procedure-subset definition and validation behavior.
4. Versioned REST and WebSocket contracts for the v0.2 workflows.
5. The simulator and deterministic scenario used for acceptance.
6. The React/TypeScript 2D operator workflow.
7. Durable persistence, recovery, and as-run evidence for the slice.
8. Test results, limitations, skipped or blocked evidence, and release decision.

### Approval Conditions

Implementation may start only after the v0.2 section of
`Test_and_Integration.md` is complete. Release acceptance requires all mandatory
v0.2 tests to pass or have an explicit written disposition. Passing v0.2 grants
no authority to connect to a live GCS or spacecraft. PostgreSQL integration
verification must be attempted for v0.2 and its actual result recorded. SQLite
results must not be presented as proof of PostgreSQL production readiness.

### Version 0.2 Implementation Outcome

The approved slice was implemented on 2026-07-12 and accepted as a local,
simulator-only developer release with documented exceptions. This outcome
supersedes the entry status above without changing the historically approved
prompt.

- The isolated Python worker, restricted AST subset, durable REST and WebSocket
  contracts, SQLite/PostgreSQL persistence, crash recovery, 2D web console, and
  as-run report were delivered.
- The backend suite passed 18 tests with SQLite and Docker networking disabled,
  then the same 18 tests against PostgreSQL 18 using `spell_test`.
- Seven frontend component/store tests, the strict production build, and eight
  real-backend desktop/mobile Playwright scenarios passed.
- The performance and soak plan, a separate manual keyboard-only review, and a
  single outbound-disabled full browser workflow remain accepted exceptions.
- Five Starlette advisories, Python artifact hash locking, project licensing,
  production authentication, and the then-missing Development Environment
  manual remained open at v0.2 acceptance.
- Full language compatibility, authoring, driver/GCS, spacecraft, high
  availability, and operational workload qualification remain deferred.

The detailed evidence and release restrictions are recorded in
`SPELL_v0.2_Release.md`. No operational authorization was granted.

### Version 0.2 Freeze Note

Before the v0.3 entry gate opened, the owner selected the Apache License,
Version 2.0 for the new OpenBEXI SPELL implementation. `LICENSE` and `NOTICE`
were added, the v0.2 provenance and release records were updated, and the
legacy reference archives were explicitly excluded from the source release.
This supersedes the earlier open project-license item without changing the
licenses or distribution restrictions of legacy or third-party material.
