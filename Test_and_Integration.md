# Test and Integration Plan

## Document Control

| Field | Value |
| --- | --- |
| Project | OpenBEXI SPELL |
| Current release | SPELL v0.3 |
| Status | v0.3 local simulator engineering release accepted |
| Date | 2026-07-16 |
| Applies to | v0.1 documentation baseline and every product version from v0.2 onward |
| Operational authorization | None |

## Version 0.3 Pre-Implementation Test Plan

### Requirements And Traceability

| Requirement ID | Requirement | Primary tests |
| --- | --- | --- |
| `V03-REQ-LIC-001` | The new implementation is Apache-2.0 licensed and legacy evidence is excluded | `V03-LIC-001` |
| `V03-REQ-MIG-001` | Versioned migrations preserve fresh and existing SQLite/PostgreSQL data | `V03-MIG-001` through `003` |
| `V03-REQ-AUTH-001` | Signed identity claims and server-enforced roles replace caller-asserted role headers | `V03-AUTH-001` through `004` |
| `V03-REQ-ISO-001` | The backend has no general outbound route and still reaches only required internal services | `V03-ISO-001`, `002` |
| `V03-REQ-SUP-001` | Dependencies are reproducible, inventoried, and have zero unreviewed advisories | `V03-SUP-001` through `003` |
| `V03-REQ-LANG-001` | Typed variables and safe expressions execute only through data IR | `V03-LANG-001`, `002` |
| `V03-REQ-LANG-002` | Conditions, bounded loops, and reusable local calls are deterministic and checkpointable | `V03-LANG-003` through `005` |
| `V03-REQ-REC-001` | Variables, effects, and control position recover atomically without duplication | `V03-REC-001`, `002` |
| `V03-REQ-VAL-001` | Validation returns diagnostics/IR/hash without saving or executing source | `V03-VAL-001` through `003` |
| `V03-REQ-UI-001` | The console exposes an accessible validation workflow and preserves execution interlocks | `V03-UI-001` through `003` |
| `V03-REQ-PERF-001` | Local command, replay, concurrency, throughput, and soak budgets are measured | `V03-PERF-001` through `004` |

### Acceptance Tests

| Test ID | Expected result | Environment | Final result |
| --- | --- | --- | --- |
| `V03-LIC-001` | Official Apache-2.0 text matches upstream; NOTICE exists; legacy ZIPs are absent from commits/packages | `DOC`, `DEV` | Pass |
| `V03-MIG-001` | A fresh SQLite and PostgreSQL database upgrades from zero to the v0.3 head | `DEV`, `SIM` | Pass |
| `V03-MIG-002` | A populated v0.2 schema upgrades without losing executions, events, prompts, commands, or hashes | `DEV`, `SIM` | Pass |
| `V03-MIG-003` | Re-running upgrade is idempotent and a failed migration rolls back visibly | `DEV`, `SIM` | Pass |
| `V03-AUTH-001` | Valid JWT issuer, audience, expiry, subject, and role claims authenticate REST and WebSocket | `DEV`, `SIM` | Pass |
| `V03-AUTH-002` | Missing, expired, malformed, wrong-issuer, wrong-audience, and unsigned tokens are rejected | `DEV` | Pass |
| `V03-AUTH-003` | Viewer/operator/admin permissions are enforced only from signed claims; spoofed role headers have no effect | `DEV`, `SIM` | Pass |
| `V03-AUTH-004` | Development token issuance is disabled by default outside the explicit local profile | `DEV`, `SIM` | Pass |
| `V03-ISO-001` | Backend and database attach only to an internal network; the loopback proxy is the sole API ingress | `SIM` | Pass |
| `V03-ISO-002` | Full browser acceptance passes while a backend internet-connect probe fails and PostgreSQL remains reachable | `SIM` | Pass |
| `V03-SUP-001` | Python installation succeeds with exact versions and required hashes; Node uses `npm ci` integrity data | `DEV` | Pass |
| `V03-SUP-002` | Backend/frontend packages rebuild twice with identical content hashes after normalized metadata | `DEV` | Pass |
| `V03-SUP-003` | CycloneDX inventories and audit policy report zero unreviewed advisories | `DEV` | Pass |
| `V03-LANG-001` | Typed declarations and assignments produce normalized expression IR without executing source | `DEV` | Pass |
| `V03-LANG-002` | Arithmetic, comparison, and boolean expression types are checked; unsafe syntax is rejected | `DEV` | Pass |
| `V03-LANG-003` | If/else selects one deterministic branch and emits ordered checkpoints/effects | `DEV`, `SIM` | Pass |
| `V03-LANG-004` | A bounded `range` loop executes the exact approved count and rejects excessive/dynamic bounds | `DEV`, `SIM` | Pass |
| `V03-LANG-005` | Reusable zero-argument local calls expand with bounded depth and recursion is rejected | `DEV`, `SIM` | Pass |
| `V03-REC-001` | Crash/recovery after variable and control-flow checkpoints restores values and emits no duplicate effect | `SIM` | Pass |
| `V03-REC-002` | Concurrent commands/prompts, late worker states, database failure, and restart retain one durable outcome | `DEV`, `SIM` | Pass |
| `V03-VAL-001` | Valid source returns subset version, SHA-256, normalized IR, variables, and no diagnostics | `DEV` | Pass |
| `V03-VAL-002` | Invalid/unsafe source returns stable line/column/code/severity diagnostics and creates no execution | `DEV` | Pass |
| `V03-VAL-003` | Validation input size, complexity, nesting, call depth, and loop bounds are enforced | `DEV` | Pass |
| `V03-UI-001` | Selected source can be validated without execution and results are visible and keyboard reachable | `SIM` | Pass |
| `V03-UI-002` | Desktop/mobile Axe scan has no serious/critical issue and controls/text fit their containers | `SIM` | Pass |
| `V03-UI-003` | Existing pause, prompt, abort, crash/recovery, report, stale, and reconnect workflows remain correct | `SIM` | Pass |
| `V03-PERF-001` | At least 100 REST mutations meet 250 ms local p95 without duplicate outcomes | `SIM` | Pass |
| `V03-PERF-002` | A 10,000-event snapshot/cursor replay completes in 3 seconds with exact canonical order | `SIM` | Pass |
| `V03-PERF-003` | One execution and two browser clients sustain at least 100 events/s for 60 seconds without loss | `SIM` | Pass with two independent Chromium processes using native WebSocket |
| `V03-PERF-003A` | The supporting in-process EventHub boundary sustains the same fan-out load without queue overflow | `SIM` | Pass; supporting evidence only |
| `V03-PERF-004` | A 10-minute 20 events/s soak has no crash, loss, stuck control, or sustained memory-growth trend | `SIM` | Pass |

### Performance Qualification Command

Run `./scripts/qualify_release.ps1` for the release-grade performance gate. It
builds one immutable qualification image, runs the quick and soak components
with outbound networking disabled, runs the real browser component against an
ephemeral loopback Uvicorn server, and independently composes the evidence.

- `qualification-quick.json` contains `V03-PERF-001`, `002`, and supporting
  EventHub gate `003A`.
- `qualification-soak.json` contains the full 600-second `V03-PERF-004` run.
- `qualification-browser-stream.json` contains `V03-PERF-003` from two
  independent Chromium processes using native WebSocket connections.
- `qualification.json` is composer-owned release evidence. It is accepted only
  when all components pass, their identities and metrics are internally
  consistent, and all source fingerprints match.

The REST measurement uses 50 acknowledged pause/resume pairs against one
long-running simulated execution; state polling and idempotent retries are
outside the primary latency timer. Browser cadence is measured independently in
each Chromium process from first to last data event. Both browsers must first
receive the server keepalive emitted after subscription and replay, and the
composer verifies that this readiness timestamp precedes first data. Only then
does the harness start production. The sentinel is checked separately for
completeness. `V03-PERF-003A` exercises two bounded production EventHub
subscriptions, but it is supporting evidence and cannot substitute for the
native browser gate.

### Release Gate

Every test is mandatory unless the final release record gives a concrete
non-safety exception. Migration, authentication, isolation, language safety,
durability, recovery, and canonical event-loss tests cannot be waived. The
release remains simulator-only and grants no authority to add a GCS or
spacecraft endpoint.

### Version 0.3 Executed Evidence

Final verification ran from 2026-07-13 through 2026-07-16 EDT (the final
qualification reports were generated on 2026-07-17 UTC) from Windows 11 Pro
build 26200 on an Intel Core i7-9700 with 31.8 GiB RAM. Docker 26.1.1 ran Python
3.13.14 Linux containers and PostgreSQL 18.4. Frontend verification used Node
24.13.0, npm 11.6.2, Playwright 1.61.1, and desktop/mobile Chromium projects.

| Gate | Actual result |
| --- | --- |
| Backend, SQLite, Docker network disabled | 112 passed, 1 PostgreSQL-only skip |
| Backend, PostgreSQL, including populated v0.2 migration | 113 passed |
| Frontend Vitest | 13 passed |
| Strict TypeScript and Vite production build | Pass |
| Mocked and real Playwright, desktop and mobile | 16 passed: 8 mocked and 8 signed-token real-backend |
| Release composer and reproducible-package tooling | 26 passed |
| Real-flow Axe serious/critical findings | 0 after correcting focusability, names, and contrast |
| Browser requests outside loopback | 0 |
| Backend internet probe | Blocked as required; PostgreSQL probe remained reachable |
| Compose ingress | Only Nginx published, at `127.0.0.1:8080` |
| Authenticated REST mutations | 100 pause/resume commands plus 100 idempotent retries; 12.452 ms primary p95; 0 duplicate outcomes |
| Canonical replay | 10,000 events in 0.13462 s; no gap, duplicate, or payload mismatch |
| Native browser real-time stream | Two ready-before-production Chromium processes each received all 6,002 sequences; 100.022 events/s over 59.9967 s; no gap or duplicate |
| Browser producer scheduling | 100.012 events/s for 60.002974 s; 0.91 ms p95 and 7.336 ms maximum lag |
| Supporting EventHub fan-out | Two bounded clients at 100.013 events/s for 60.003304 s; no loss, duplicate, or overflow |
| Sustained soak | 12,001 exact events at 20.002 events/s for 600.001721 s; no control or producer failure |
| Soak scheduling and memory | 0.548 ms p95/2.653 ms max lag; 1.375 MiB post-warmup growth; 0.188 MiB/min slope |
| Python and Node dependency audits | 0 known vulnerabilities; Starlette exposure policy passed |
| CycloneDX image inventories | Separate backend, proxy, and frontend inventories with `SHA256SUMS`; conversion warnings recorded in `PROVENANCE.md` |
| Reproducible package | Two immutable-input builds and a third current-context drift build produced an identical SHA-256; checksum sidecar retained with the archive |

Focused safety and release-integrity evidence also passed:

- Source byte, Unicode, AST node/depth, expanded-step, prompt-width, and
  serialized-IR byte limits reject oversized input before worker handoff or
  persistence. Invalid UTF-8, unpaired surrogates, and NULs return stable,
  non-echoing diagnostics. Accepted source and its SHA-256 use the exact same
  text.
- Definite assignment is enforced across branches, loops, and calls; reserved
  compiler/runtime names cannot be declared, assigned, or used as loop targets.
- Chained comparisons short-circuit in the data interpreter. Empty or excessive
  ranges, recursion, unsafe syntax, and unbounded call expansion are rejected.
- Worker terminal messages, consumer failure, bounded shutdown, and restart
  recovery settle every accepted command durably; stale generations and late
  messages cannot overwrite the authoritative result.
- Established WebSockets close when their JWT expires. Logout and close code
  `4401` both close the client socket, erase the session token, and return the
  console to the access gate.
- Migration `v0001` is immutable static schema code rather than live ORM
  metadata. Fresh, populated-v0.2, repeated, failure, SQLite, and PostgreSQL
  paths passed.
- Qualification and packaging reject missing, failed, mixed-fingerprint, or
  stale reports. Packaging excludes only generated screenshots under
  `artifacts/v0.3`, retaining legitimate product PNG assets.

Machine-readable performance evidence is in
`artifacts/v0.3/qualification.json` (schema `1.1`, `overall_pass: true`,
`acceptance_complete: true`, fingerprint
`454d79fdbadc6d5076f415fa9bc1d03dd12552511e58c59330ad5315d50eb734`).
The quick, soak, and browser-stream component reports are retained beside it.
Browser screenshots are under `artifacts/v0.3/`; backend, proxy, and frontend
CycloneDX inventories plus their checksum manifest are under `artifacts/sbom/`.

No v0.3 acceptance test has a safety exception. SPELL v0.3 is accepted only as
a local simulator engineering release. It remains unapproved for shared,
operational, GCS, spacecraft, or telecommand use.

## Purpose

This document is the authoritative test-planning reference for OpenBEXI SPELL.
It defines the verification work that must be planned before implementation and
executed before release. Every new version must update this document before its
implementation begins.

SPELL v0.1 contains documentation only. Its executable verification was limited
to archive integrity, evidence review, documentation consistency, and
requirements traceability. SPELL v0.2 is the first implementation release and
is restricted to the simulator-only vertical slice defined below. Its tests
were specified here before implementation. The executed v0.2 evidence and
release decision are recorded at the end of this document.

## Safety Boundary

- No v0.2 component or test may connect to a live Ground Control System or
  spacecraft.
- Development defaults to simulators, stubs, recorded data, and isolated test
  drivers.
- A passing software test does not authorize operational use.
- Simulator approval, non-operational integration approval, staging approval,
  and operational approval are separate gates.
- No test may silently retry a telecommand or interpret an uncertain external
  result as success or failure.
- Test evidence must not contain credentials, private certificates, internal
  endpoints, spacecraft secrets, or proprietary driver data.

## Reference Baseline

The following inputs were inventoried without modifying the archives:

| Artifact | Role | SHA-256 |
| --- | --- | --- |
| `SPELL2.6.10-src.zip` | Legacy core source reference | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` |
| `SPELL-COTS-2.6.10.zip` | Legacy dependency reference | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | Legacy GUI behavioral reference | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` |

The GUI archive embeds Server, GUI, Language, Driver Development, and Build
manuals labeled SPELL 2.4.4, plus a draft Server Communication ICD for SPELL
2.4. The required SPELL Development Environment manual was not found. This gap
must remain visible in requirements and acceptance reviews.

## Source Precedence

When sources disagree, tests must use this precedence and record the conflict:

1. Reproducible behavior observed in an isolated legacy environment.
2. Version-specific source and configuration.
3. Version-specific manuals.
4. General upstream documentation.
5. Explicitly labeled assumptions.

No undocumented behavior may be accepted solely because it appears convenient
for the new implementation.

## Per-Version Test Gate

Before implementation of every version:

1. Assign stable requirement identifiers.
2. Define the exact feature and failure scope.
3. Select approved test environments and data.
4. Map each requirement to one or more planned test cases.
5. Define measurable expected results and acceptance thresholds.
6. Identify safety-critical tests and independent review needs.
7. Define migration, rollback, and evidence-retention expectations.
8. Review and approve this plan update.

Before release of every version:

1. Run the approved tests in the required environments.
2. Preserve commands, versions, configuration hashes, results, logs, and
   timestamps needed to reproduce the run.
3. Explain every skipped, blocked, flaky, or failed test.
4. Close or explicitly accept all release-blocking defects.
5. Audit requirements-to-test and test-to-evidence traceability.
6. Record the release decision and remaining operational restrictions.

## Test Environments

| Environment | Purpose | Commanding permission |
| --- | --- | --- |
| `DOC` | Documentation and static evidence review | None |
| `LEGACY-REF` | Isolated legacy behavioral capture | Simulator or stub only |
| `SIM` | New system with deterministic spacecraft/GCS simulation | Simulated only |
| `DEV` | Developer unit and component testing | Mocked or simulated only |
| `INT-NONOP` | Approved non-operational GCS integration | Explicitly constrained |
| `STAGING` | Release-candidate validation | Per approved safety plan |
| `OPERATIONAL` | Live deployment acceptance | Outside v0.2 and separately authorized |

Every evidence record must name the environment. Tests that omit the environment
are not acceptable release evidence.

## Test Data Rules

- Version and hash all procedure bundles, configurations, schemas, driver
  capabilities, simulation scenarios, and recorded traces used by tests.
- Use synthetic or sanitized telemetry and command data unless a separate data
  handling approval exists.
- Provide deterministic clocks and random seeds where applicable.
- Preserve original legacy traces and normalized comparison traces separately.
- Cover nominal, boundary, malformed, stale, duplicate, reordered, missing,
  delayed, and disconnected inputs.
- Do not use a production credential or production endpoint as test data.

## Evidence Requirements

Each executed test record must contain:

- Test identifier and requirement identifiers.
- Product, API, procedure SDK, driver, schema, and configuration versions.
- Environment and dependency inventory.
- Input data and procedure bundle hashes.
- Preconditions and safety controls.
- Execution steps or automated test reference.
- Expected and actual results.
- Ordered event and audit evidence where applicable.
- Pass, fail, blocked, or skipped result with reason.
- Reviewer and execution timestamp.

## Version 0.1 Verification Matrix

| Test ID | Verification | Expected result | Status |
| --- | --- | --- | --- |
| `V01-DOC-001` | Required v0.1 documents exist | Four coordinated Markdown documents exist | Pass |
| `V01-DOC-002` | Release identity | All documents identify v0.1 as pre-implementation | Pass |
| `V01-DOC-003` | Archive integrity | Three SHA-256 hashes are recorded | Pass |
| `V01-DOC-004` | Manual inventory | Available manuals, versions, paths, and missing DEV manual are recorded | Pass |
| `V01-DOC-005` | Version separation | Project v0.1, Core/COTS 2.6.10, GUI 4.0.12, manuals 2.4.4 remain distinct | Pass |
| `V01-DOC-006` | Legacy capability coverage | Server, executor, procedure, driver, GUI, data, and build behavior are inventoried | Pass |
| `V01-DOC-007` | Architecture definition | Proposed Python, worker, driver, API, persistence, and web boundaries are defined | Pass |
| `V01-DOC-008` | Requirements traceability | Stable requirement families map to evidence and planned tests | Pass |
| `V01-DOC-009` | Safety coverage | Live-system prohibition, uncertain-command handling, audit, and stale-client behavior are defined | Pass |
| `V01-DOC-010` | Future test coverage | Engine, API, driver, UI, recovery, security, performance, and migration suites are planned | Pass |
| `V01-DOC-011` | Implementation exclusion | No new executable product code is included in v0.1 | Pass |
| `V01-DOC-012` | Approval state | Documents state that architecture and v0.2 entry require approval | Pass |

The matrix statuses above are documentation review results, not product runtime
results.

## Version 0.2 Pre-Implementation Test Plan

### Release Scope

SPELL v0.2 is a clean-room, simulator-only vertical slice. It may implement a
Python 3 control plane, an isolated execution worker, a restricted AST/IR
procedure subset, durable REST commands, ordered WebSocket events, persistence,
and a React/TypeScript 2D console. The complete workflow is limited to loading
and validating one procedure, executing it, pausing and resuming it, resolving
one durable prompt, aborting safely, recovering from a controlled worker crash,
and generating an auditable as-run report.

No v0.2 test or demonstration may connect to a live or legacy GCS, spacecraft,
or operational endpoint. There is no operational telecommand capability in
this release.

### Version 0.2 Requirements

| Requirement ID | Requirement | Primary verification |
| --- | --- | --- |
| `V02-REQ-BOUND-001` | All execution uses a deterministic simulator and cannot resolve an operational endpoint | `V02-BOUND-001`, `V02-BOUND-002` |
| `V02-REQ-ARCH-001` | The control plane uses Python 3 and contains no Java runtime component | `V02-ARCH-001` |
| `V02-REQ-ARCH-002` | Procedure execution occurs in a separate OS process and a worker failure cannot terminate the API process | `V02-ARCH-002`, `V02-REC-001` |
| `V02-REQ-PROC-001` | Procedures are parsed into a documented, validated AST/IR subset | `V02-PROC-001`, `V02-PROC-002` |
| `V02-REQ-API-001` | State-changing REST requests require an idempotency key and expected revision | `V02-API-001`, `V02-API-002` |
| `V02-REQ-API-002` | WebSocket output is downstream-only, ordered per execution, replayable, and schema-versioned | `V02-WS-001`, `V02-WS-002` |
| `V02-REQ-DATA-001` | Authoritative state, commands, prompts, events, checkpoints, and audit data are persisted before publication | `V02-DATA-001`, `V02-DATA-002` |
| `V02-REQ-EXEC-001` | The slice supports load, validate, run, pause, resume, prompt response, abort, and terminal completion with guarded transitions | `V02-EXEC-001` through `V02-EXEC-004` |
| `V02-REQ-REC-001` | A controlled worker crash has an explicit state and can recover from a safe checkpoint without duplicate simulated effects | `V02-REC-001`, `V02-REC-002` |
| `V02-REQ-UI-001` | The 2D web console displays authoritative execution state, current source line, prompt, controls, connection state, and event history | `V02-UI-001` through `V02-UI-003` |
| `V02-REQ-AUD-001` | An as-run report reconstructs the execution with identities, hashes, actors, commands, prompts, state changes, recovery, and results | `V02-AUD-001` |
| `V02-REQ-PROV-001` | New implementation provenance is recorded and legacy implementation code is not copied | `V02-PROV-001` |

### Acceptance Tests

All tests below are mandatory for the v0.2 release unless the release decision
records an explicit exception. An exception to a safety-boundary, isolation,
idempotency, ordering, prompt, abort, recovery, or audit test blocks release.

| Test ID | Test and expected result | Environment | Pre-implementation status |
| --- | --- | --- | --- |
| `V02-DOC-001` | v0.2 scope, approval, tests, targets, restrictions, and deferred decisions are recorded before product implementation | `DOC` | Pass |
| `V02-BOUND-001` | Default and test configurations expose only the approved simulator; configuration containing a non-simulator or non-loopback operational endpoint is rejected before any connection attempt | `DEV`, `SIM` | Planned |
| `V02-BOUND-002` | With outbound network access denied, the complete acceptance workflow still passes and logs contain no attempted GCS or spacecraft connection | `SIM` | Planned |
| `V02-ARCH-001` | Runtime/dependency inventory shows Python 3 backend and TypeScript frontend with no Java, Eclipse, SWT, or Three.js runtime dependency | `DEV` | Planned |
| `V02-ARCH-002` | The worker PID differs from the API PID; force-terminating the worker leaves the API health and authoritative execution record available | `SIM` | Planned |
| `V02-PROC-001` | A versioned valid sample procedure is parsed and validated to the documented AST/IR; its content hash and subset version are stored | `DEV` | Planned |
| `V02-PROC-002` | Syntax outside the subset and attempts to import modules or access filesystem, network, subprocess, database, driver, or secrets are rejected before execution with typed diagnostics | `DEV` | Planned |
| `V02-API-001` | Repeating the same mutation with the same idempotency key and identical body returns the same command identity and creates one command, transition, and effect; reuse with a different body is rejected | `DEV`, `SIM` | Planned |
| `V02-API-002` | A mutation with a stale expected revision is rejected as a conflict and produces no execution-state or simulator-effect change | `DEV`, `SIM` | Planned |
| `V02-WS-001` | Each event has an ID, schema version, execution ID, strictly increasing execution sequence, timestamps, type, and correlation metadata; a complete run has no missing or repeated canonical sequence | `SIM` | Planned |
| `V02-WS-002` | Disconnect after sequence N and reconnect from N yields the remaining ordered events without duplicate UI projection; an invalid or unavailable cursor forces an authoritative snapshot and visible resynchronization | `SIM` | Planned |
| `V02-DATA-001` | Stop and restart the control plane after committed commands/events; the execution snapshot, revision, event sequence, prompt, and audit history remain consistent | `SIM` | Planned |
| `V02-DATA-002` | Prevent a persistence commit and verify the corresponding event is not published and the operation fails visibly without a partial authoritative transition | `DEV`, `SIM` | Planned |
| `V02-EXEC-001` | A valid procedure follows the defined created/validated/ready/running/terminal state path; invalid commands in every tested state are rejected without mutation | `SIM` | Planned |
| `V02-EXEC-002` | Pause reaches a safe boundary, executes no later procedure step while paused, and resume continues once from the recorded location | `SIM` | Planned |
| `V02-EXEC-003` | A prompt is persisted before display, survives browser reconnect and control-plane restart, accepts one authorized response, and rejects or deduplicates repeated/competing responses without advancing twice | `SIM` | Planned |
| `V02-EXEC-004` | Abort enters an explicit aborting state, terminates the worker, reaches aborted, and produces no procedure-step or simulator-effect event after the terminal transition | `SIM` | Planned |
| `V02-REC-001` | Kill the worker at each documented safe boundary; execution enters an explicit recovery state and the API remains responsive | `SIM` | Planned |
| `V02-REC-002` | Controlled recovery uses the same procedure/configuration identities, restores the last committed checkpoint, preserves event order, and neither loses nor duplicates a committed simulated effect | `SIM` | Planned |
| `V02-UI-001` | Browser workflow loads the sample, starts it, shows current line and state, pauses, resumes, answers the prompt, and reaches the correct terminal result | `SIM` | Planned |
| `V02-UI-002` | Connection loss shows a persistent reconnecting/stale state and disables mutations until snapshot/replay resynchronization completes | `SIM` | Planned |
| `V02-UI-003` | Keyboard-only workflow is usable; controls have accessible names and focus states; status is not conveyed by color alone; automated accessibility scan has no serious or critical finding | `SIM` | Planned |
| `V02-AUD-001` | Generated as-run data reconstructs ordered states, source locations, commands, prompt and response, actor, timestamps, procedure/configuration hashes, worker crash/recovery, and final result | `SIM` | Planned |
| `V02-PROV-001` | Review new source provenance, notices, and dependency inventory; no legacy archive content or implementation code is present in new source directories | `DOC`, `DEV` | Planned |
| `V02-PERF-001` | The defined local latency, throughput, reconnect, recovery, and soak scenarios meet every provisional target below | `SIM` | Planned |

### Persistence Test Boundary

PostgreSQL remains the target authoritative database. The v0.2 persistence API,
transactions, schema behavior, and tests must be designed for that target.
SQLite is approved as a fast local development and unit-test fallback.
PostgreSQL integration verification will be attempted through the project
Docker Compose environment and its actual result will be recorded.

The same behavioral persistence contract must be reusable against PostgreSQL.
A PostgreSQL-backed integration run is planned for v0.2. If the attempt is
blocked by the environment, record the exact failure and keep PostgreSQL
readiness unverified. SQLite evidence does not prove PostgreSQL concurrency,
isolation, locking, failover, performance, or deployment behavior.

| Test ID | Test and expected result | v0.2 treatment |
| --- | --- | --- |
| `V02-DB-SQLITE-001` | Run all v0.2 persistence, restart, conflict, rollback, recovery, and as-run cases against a fresh SQLite database | Required |
| `V02-DB-PORT-001` | Storage code is behind an explicit persistence boundary; no procedure, worker, REST, WebSocket, or UI logic depends on SQLite-specific behavior | Required review |
| `V02-DB-PG-001` | Run the shared persistence contract suite against the Docker Compose PostgreSQL service | Planned v0.2 integration verification; record Pass, Fail, or Blocked with actual evidence |

### Provisional Local Engineering Targets

These targets make v0.2 locally testable; they are not operational SLOs. Record
the CPU, memory, OS, browser, Python and Node versions, database mode, test data,
sample count, and measurement method with the results. Latency is measured on
one local host using a monotonic clock after warm-up.

| Measure | Provisional v0.2 target |
| --- | --- |
| REST command acceptance | p95 at or below 250 ms over at least 100 local requests |
| Persisted event to visible browser update | p95 at or below 500 ms over at least 1,000 events |
| Prompt persisted to visible browser prompt | p95 at or below 500 ms over at least 100 prompts |
| Pause or resume accepted to observed state | p95 at or below 1 second over at least 50 cycles |
| Abort accepted to worker termination and `aborted` | p95 at or below 2 seconds over at least 25 runs without an uninterruptible simulated operation |
| Worker start | p95 at or below 2 seconds over at least 50 starts |
| Controlled worker recovery | p95 at or below 5 seconds over at least 25 recoveries |
| WebSocket reconnect/resync | at or below 3 seconds with a 10,000-event execution history |
| Event throughput | 100 events/second for 10 minutes and 500 events/second for 10 seconds, with zero missing canonical events or sequence gaps |
| Supported v0.2 load | One active procedure and two simultaneous browser clients |
| Local soak | Two hours at 20 events/second with no crash, no missing canonical event, usable controls, and no sustained post-warm-up memory growth trend |

All safety-critical command, state, prompt, checkpoint, recovery, and audit
events have a zero-loss acceptance target. Delivery replay may repeat transport
frames, but canonical storage and final UI projection must not duplicate the
logical event.

Operational latency, throughput, concurrency, availability, recovery,
retention, deployment, and long-duration SLOs remain **TBD** pending representative
mission workloads, hardware, network topology, GCS characteristics, and owner
approval. Meeting these local targets does not imply operational suitability.

### Version 0.2 Release Gate

The v0.2 release decision requires:

1. Every mandatory test above has reproducible evidence and a traceable result.
2. No Critical or High defect remains open.
3. The no-live-system boundary, process isolation, idempotency, ordering,
   prompt, abort, recovery, and audit cases pass without waiver.
4. SQLite use and the actual PostgreSQL integration result are disclosed in the
   release notes and README.
5. Dependency versions, licenses, hashes, and clean-room provenance are
   reviewed.
6. The as-run report and test evidence contain no secret or internal endpoint.
7. The release is labeled simulator-only and not approved for operational use.

Failure to meet a provisional performance target must be investigated and
recorded. It blocks v0.2 acceptance only when it breaks the vertical-slice
workflow, causes data/event loss, violates a safety invariant, or is explicitly
classified as release-blocking in the test result.

## Planned Verification Catalog

### Legacy Compatibility

| Test family | Required coverage |
| --- | --- |
| `LGC-STATE` | Legacy states, transition guards, terminal-state behavior, and invalid commands |
| `LGC-CMD` | Run, pause, step, step-over, skip, goto, interrupt, abort, finish, reload, recover, and close |
| `LGC-PROMPT` | Prompt types, defaults, scope, answer, cancel, timeout, error, and no-controller outcomes |
| `LGC-PROC` | Procedure headers, arguments, IVARS, child procedures, libraries, files, and databases |
| `LGC-SVC` | TM, TC, events, resources, tasks, time, users, ranging, memory, PCS, and configuration |
| `LGC-GUI` | Control, monitor, background, takeover, scheduling, replay, variables, logs, and as-run workflows |

Golden traces must compare ordered state changes, source locations, prompts,
telemetry/command outcomes, messages, errors, and as-run records. Differences
must be classified as compatible, intentionally changed, defect, or unresolved.

### Procedure Engine

| Test family | Required coverage |
| --- | --- |
| `ENG-LOAD` | Package identity, metadata, validation, imports, arguments, and rejected content |
| `ENG-EXEC` | Sequential execution, calls, returns, steps, breakpoints, goto, waits, and conditions |
| `ENG-CTRL` | Valid and invalid command/state combinations with one serialized owner |
| `ENG-PROMPT` | Durable prompts, ownership, response races, timeout, cancel, and reconnect |
| `ENG-CHILD` | Blocking, non-blocking, background, hidden, and failure propagation behavior |
| `ENG-ISOL` | Worker process isolation, resource limits, forbidden capabilities, and forced termination |
| `ENG-CHECK` | Safe checkpoint boundaries, artifact compatibility, and state restoration |

### REST And Real-Time APIs

| Test family | Required coverage |
| --- | --- |
| `API-REST` | Resource schemas, validation, authentication, authorization, errors, and versioning |
| `API-CMD` | Durable command lifecycle, idempotency, expected revision, audit, and conflicts |
| `API-WS` | Ordered delivery, authentication, subscription, heartbeat, bounded queues, and shutdown |
| `API-REPLAY` | Snapshot plus cursor, reconnect, gap replay, gap detection, and forced resynchronization |
| `API-SCHEMA` | Additive evolution, unknown fields, deprecated fields, and consumer contract tests |
| `API-LOAD` | Concurrent clients, slow consumers, backpressure, and non-droppable event classes |

Safety-critical commands must use the authoritative command API. WebSocket tests
must prove that a reconnect cannot duplicate an operator action.

### Driver Conformance

| Test family | Required coverage |
| --- | --- |
| `DRV-LIFE` | Capability handshake, setup, health, deadlines, cleanup, interrupt, and close |
| `DRV-TM` | Snapshot and stream values, raw/engineering data, quality, validity, time, limits, and staleness |
| `DRV-TC` | Stable operation identity, acceptance, release, stages, acknowledgement, rejection, and uncertainty |
| `DRV-SVC` | Events, resources, tasks, users, time, ranging, memory, PCS, and optional capabilities |
| `DRV-FAIL` | Timeout, disconnect, malformed response, partial service, restart, and reconciliation |
| `DRV-SEC` | Mutual authentication, authorization, credential isolation, and secret redaction |

No conformance case may automatically repeat a non-idempotent external action.

### Persistence, Audit, And Recovery

| Test family | Required coverage |
| --- | --- |
| `REC-EVENT` | Persist-before-publish, immutable identity, per-execution order, and duplicate rejection |
| `REC-DB` | Transaction rollback, serialization conflict, database outage, and restart |
| `REC-WORKER` | Worker crash before and after command dispatch, event commit, and checkpoint |
| `REC-UNCERTAIN` | Unknown telecommand outcome enters reconciliation-required state without resend |
| `REC-CLIENT` | Controller loss, monitor continuity, lease expiry, takeover, and prompt ownership |
| `REC-ASRUN` | Complete chronological reconstruction with actor, source, procedure, and configuration hashes |
| `REC-RETENTION` | Retention, archival, export, restore, and tamper-evidence checks |

### Real-Time 2D Web Interface

| Test family | Required coverage |
| --- | --- |
| `UI-CONTEXT` | Server/context identity, health, spacecraft, GCS, UTC, and role visibility |
| `UI-PROC` | Catalog, source, current line, coverage, call stack, state, and execution controls |
| `UI-DATA` | Telemetry, commands, events, variables, resources, logs, and history tables |
| `UI-PROMPT` | Latched prompt, keyboard/focus behavior, validation, commit, cancel, and races |
| `UI-STALE` | Connected, reconnecting, resynchronizing, stale, and control-disabled behavior |
| `UI-A11Y` | Keyboard-only use, focus, labels, contrast, status messages, and reduced motion |
| `UI-BROWSER` | Supported desktop browsers, viewport constraints, and long-session behavior |
| `UI-PERF` | High-rate updates, virtualization, charts, memory, responsiveness, and replay |

Color alone must never communicate safety state. Alarms, prompts, failed commands,
connection loss, and uncertainty must remain visible until resolved or
acknowledged according to policy.

### Security And Supply Chain

| Test family | Required coverage |
| --- | --- |
| `SEC-AUTHN` | User authentication, expiration, reauthentication, and service identity |
| `SEC-AUTHZ` | Viewer, operator, supervisor, and administrator permissions and escalation denial |
| `SEC-WEB` | Origin, CSRF, injection, content security, session, and WebSocket protections |
| `SEC-SECRETS` | No secret in logs, events, exports, images, packages, or client payloads |
| `SEC-SBOM` | Dependency inventory, licenses, hashes, vulnerabilities, and policy enforcement |
| `SEC-ARTIFACT` | Reproducible package metadata, signatures, provenance, and verification |
| `SEC-PROC` | Procedure capability restrictions and attempted isolation escapes |

The legacy COTS bundle is evidence only. It is not an approved dependency lock
for the new product.

### Performance And Reliability

The provisional v0.2 local budgets are defined above. Every later integration
or operational candidate must separately approve measurable budgets for:

- Telemetry source-to-server and server-to-display latency.
- Operator-command acceptance and completion reporting latency.
- Prompt display and response processing latency.
- Sustainable and burst event throughput.
- Browser reconnect, replay, and resynchronization time.
- Worker startup, checkpoint, and recovery time.
- Supported concurrent contexts, executions, drivers, and clients.
- Multi-hour memory, CPU, storage, and UI responsiveness limits.
- Maximum event backlog and retention volume.

Operational numeric targets are not asserted because representative workloads
and required service levels have not yet been supplied. The v0.2 local targets
must not be reused as operational commitments.

### Migration And Rollback

| Test family | Required coverage |
| --- | --- |
| `MIG-ADAPT` | Legacy adapter mappings, unsupported fields, errors, and connection recovery |
| `MIG-DIFF` | Same procedure and inputs produce classified legacy/new trace differences |
| `MIG-DATA` | Procedure, configuration, database, audit, and as-run import/export |
| `MIG-SHADOW` | Read-only shadow operation without effects on legacy control |
| `MIG-PILOT` | Supervised non-commanding and later approved commanding workflows |
| `MIG-ROLL` | Defined rollback restores legacy authority without lost or duplicated actions |

## Defect Severity

| Severity | Meaning | Release treatment |
| --- | --- | --- |
| Critical | Could cause unauthorized, duplicated, misdirected, or unrecoverable spacecraft/GCS action | Blocks release |
| High | Breaks execution control, audit, recovery, authorization, or required compatibility | Blocks release |
| Medium | Degrades a supported workflow with a documented safe workaround | Requires explicit disposition |
| Low | Cosmetic or documentation issue without operational ambiguity | May defer with owner |

Flaky safety-critical tests are failures, not acceptable intermittent results.

## Traceability Audit

Every requirement must map to at least one test family and acceptance criterion.
Every executed test must map back to a requirement. Orphan requirements and
orphan tests block the version gate until corrected or explicitly removed.

The v0.1 traceability families are:

| Requirement prefix | Primary planned tests |
| --- | --- |
| `REQ-SAFE` | `ENG-CTRL`, `DRV-TC`, `REC-UNCERTAIN`, `SEC-AUTHZ` |
| `REQ-COMP` | `LGC-*`, `MIG-DIFF`, `API-SCHEMA` |
| `REQ-ARCH` | `ENG-ISOL`, `DRV-LIFE`, `REC-DB` |
| `REQ-API` | `API-*`, `REC-EVENT` |
| `REQ-PROC` | `LGC-PROC`, `ENG-*` |
| `REQ-DRV` | `DRV-*` |
| `REQ-UI` | `UI-*` |
| `REQ-DATA` | `REC-*`, `MIG-DATA` |
| `REQ-SEC` | `SEC-*` |
| `REQ-PERF` | `API-LOAD`, `UI-PERF`, performance budgets |
| `REQ-MIG` | `MIG-*` |

## Version 0.1 Verification Log

On 2026-07-12 the following planning verification was completed:

- Computed and recorded SHA-256 hashes for all three supplied archives.
- Inventoried 716 core-source entries and 2,322 GUI-distribution entries.
- Located and reviewed the embedded 2.4.4 Server, GUI, Language, Driver
  Development, and Build manuals.
- Reviewed the embedded draft Server Communication ICD as historical evidence.
- Confirmed that the required Development Environment manual is absent.
- Compared manual behavior with the 2.6.10 source, current GUI plug-ins, release
  notes, configuration, protobuf interfaces, build metadata, and tests.
- Confirmed that the supplied legacy test coverage is insufficient for a safe
  rewrite and defined specification-derived test families above.

No legacy build, GUI launch, procedure execution, driver connection, browser
test, or operational integration test was performed for v0.1.

## Version 0.1 Exit Decision

This test plan was completed as the planning baseline. On 2026-07-12 the project
owner approved proceeding to the bounded v0.2 simulator vertical slice. The
missing Development Environment manual is waived only for this slice; all other
recorded v0.1 gaps remain open unless explicitly resolved.

## Version 0.2 Executed Results

The final verification run completed on 2026-07-12. Tests used Windows build
26200, an Intel Core i7-9700, 31.8 GiB RAM, Docker 26.1.1, Python 3.13,
PostgreSQL 18, Node 24.13.0, npm 11.6.2, and Playwright Chromium desktop and
mobile projects. Procedures and telemetry were deterministic simulator data.

| Test ID | Result | Evidence and disposition |
| --- | --- | --- |
| `V02-DOC-001` | Pass | v0.2 scope and test gate were recorded before implementation |
| `V02-BOUND-001` | Pass | API rejects every context other than literal `simulator`; no driver or endpoint configuration exists |
| `V02-BOUND-002` | Accepted exception | All 18 backend tests passed with Docker networking disabled and real browser requests were loopback-only; one combined outbound-disabled browser workflow was not run |
| `V02-ARCH-001` | Pass | Python/TypeScript dependency review found no Java, Eclipse, SWT, or Three.js runtime |
| `V02-ARCH-002` | Pass | Worker PID isolation, crash, API health, and durable recovery assertions passed |
| `V02-PROC-001` | Pass | Valid subset parse, ordered IR, procedure hash, subset version, and literal-only behavior passed |
| `V02-PROC-002` | Pass | Imports, assignment, arbitrary/nested calls, unknown calls, and unsupported arguments were rejected without execution |
| `V02-API-001` | Pass | Start, command, and prompt retry identity, atomic prompt reservation, competing-response rejection, and conflicting-body rejection passed |
| `V02-API-002` | Pass | Stale revisions returned conflict without mutation |
| `V02-WS-001` | Pass | Authentication, schema version, contiguous sequences, keepalive, and canonical ordering passed |
| `V02-WS-002` | Pass | Cursor replay, unavailable-cursor resync, real offline reconnect, and UI projection passed |
| `V02-DATA-001` | Pass | Atomic create/auto-start, serialized snapshots, restart durability, prompt, cursor, audit, and explicit recovery state passed |
| `V02-DATA-002` | Pass | Forced transactional failure rolled back effects, checkpoint, sequence, and publication |
| `V02-EXEC-001` | Pass | Creation through terminal execution and guarded command transitions passed |
| `V02-EXEC-002` | Pass | Worker-acknowledged pause/resume and browser keyboard activation passed |
| `V02-EXEC-003` | Pass | Durable prompt restart, reconnect, revision, retry, and single-response behavior passed |
| `V02-EXEC-004` | Pass | Abort cancelled the prompt, terminated the worker, and emitted no later simulated effect |
| `V02-REC-001` | Pass | Controlled crashes passed in every supported crashable state; start/recover spawn failures and late terminal/control races reached durable outcomes |
| `V02-REC-002` | Pass | Recovery retained hashes/order/checkpoints and did not duplicate committed logs |
| `V02-UI-001` | Pass | Real browser load, line, pause, resume, prompt, recovery, completion, abort, and report flows passed |
| `V02-UI-002` | Pass | Desktop/mobile offline tests latched stale state, disabled mutations, resynced, and re-enabled controls |
| `V02-UI-003` | Accepted exception | Axe found no serious/critical issue in either viewport; labels, focus styling, overflow, status text, and keyboard pause/resume passed; no separate manual keyboard-only review was recorded |
| `V02-AUD-001` | Pass | As-run report included ordered evidence, actors, sources, hashes, commands, prompt, recovery, result, and digest |
| `V02-PROV-001` | Pass with gap | Source/archive comparison, Apache-2.0 licensing, and SBOM review passed; Python artifact hashes remain unresolved |
| `V02-PERF-001` | Accepted exception | Provisional latency, throughput, 10,000-event resync, and two-hour soak targets were not executed |
| `V02-DB-SQLITE-001` | Pass | 18 tests passed in 15.07 s using a fresh SQLite database with Docker networking disabled |
| `V02-DB-PORT-001` | Pass | Shared SQLAlchemy persistence boundary and identical suite reviewed for both databases |
| `V02-DB-PG-001` | Pass | 18 tests passed in 15.73 s against the dedicated PostgreSQL `spell_test` database |

Frontend verification also recorded seven passing Vitest tests, a passing
strict TypeScript/Vite production build, and eight passing real-backend
Playwright tests in 18.6 seconds. `npm audit --audit-level=low` found zero known
vulnerabilities. Exact-pinned Python audit found five accepted Starlette
residuals documented in `PROVENANCE.md` and `SPELL_v0.2_Release.md`.

Evidence images and CycloneDX inventories are retained under `artifacts/v0.2/`.
The first offline/reconnect run exposed a stale-socket reconnect defect; it was
fixed and both the focused two-project rerun and final eight-test suite passed.
Final concurrency review also exposed prompt-reservation, worker-dispatch, and
atomic create/start races. Those paths were corrected, covered by new failure
and competing-action tests on both databases, and independently re-reviewed
with no remaining release-blocking finding.
No Critical or High defect remains open for the bounded simulator workflow.

## Version 0.2 Exit Decision

SPELL v0.2 is accepted as a local simulator-only developer release with the
explicit exceptions above. The unexecuted performance targets did not expose a
workflow failure or safety invariant violation and are nonblocking under the
approved v0.2 gate. The security, artifact-hash, manual keyboard,
and outbound-isolation limitations block any claim of shared, production, or
operational readiness.

The release carries no authorization to connect to a live or legacy GCS or
spacecraft. Full language support, drivers, authoring, production identity,
high availability, and operational use require a new approved plan update.
