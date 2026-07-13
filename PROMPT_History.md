# Prompt History

This document records approved project requests, planning decisions, delivery
status, and unresolved issues by OpenBEXI SPELL version. New version entries
are inserted at the top so the current version is visible first. Later versions
may supersede a decision but must not rewrite an earlier request or result.

## 2026-07-12 - SPELL v0.3

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.3 |
| Release name | Simulator Hardening and Language Foundation |
| Request type | Hardening, restricted-language expansion, and validation workflow |
| Status | Approved to implement after the recorded v0.3 test gate |
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
- The required Development Environment manual is absent.
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

The missing SPELL Development Environment manual is waived for v0.2 only
because this release does not implement the full authoring environment. The gap
remains open for any later authoring-tool scope. Operational workload profiles
and service-level objectives are also deferred; v0.2 uses provisional local
engineering targets only.

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
  production authentication, and the missing Development Environment manual
  remain open.
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
