# SPELL v0.1 Pre-Implementation Baseline

## Document Control

| Field | Value |
| --- | --- |
| Project | OpenBEXI SPELL |
| Project version | 0.1 |
| Release name | Pre-Implementation Baseline |
| Date | 2026-07-12 |
| Status | Draft for review |
| Product code | None |
| Operational authorization | None |

## Executive Decision

SPELL v0.1 defines the behavioral, architectural, interface, safety, migration,
and verification contract for a new SPELL implementation. It does not contain an
implementation.

The target is a Python 3 execution platform with a real-time 2D web operator
interface and no Java components. The codebase may be new, but the behavior may
not be reinvented without evidence. Legacy manuals, source, artifacts, and
reproducible traces form the compatibility reference.

The recommended delivery strategy is incremental. A compatibility boundary and
simulator-led vertical slices replace a big-bang cutover. Operational authority
remains with the legacy system until the new system passes documented safety,
compatibility, integration, and operational acceptance gates.

## Scope

Version 0.1 includes:

- Manual and archive review.
- Legacy capability and state/command inventory.
- Documented-versus-implemented comparison.
- Target architecture and component boundaries.
- REST, WebSocket, gRPC, and Python procedure SDK direction.
- Event, command, prompt, telemetry, audit, and recovery models.
- Procedure and configuration migration strategy.
- Real-time 2D operator-interface specification.
- Security, licensing, supply-chain, and operational-safety analysis.
- Test, integration, simulation, replay, performance, and fault strategy.
- Phased implementation and rollback plan.

Version 0.1 excludes:

- Backend, frontend, procedure-engine, driver, or deployment code.
- Dependency installation for the future product.
- Modification of legacy archives, binaries, or vendored dependencies.
- Connection to a live Ground Control System or spacecraft.
- An assertion that the proposed architecture is already operational.
- Final operational performance targets without workload evidence.

## Version Identity

The project version is independent of all imported versions:

| Item | Verified version | Meaning |
| --- | --- | --- |
| OpenBEXI SPELL | 0.1 | New project planning release |
| Core archive | 2.6.10 | Filename and Helm application version |
| COTS archive | 2.6.10 | Dependency-bundle label |
| GUI distribution | 4.0.12 | Eclipse product version |
| Embedded primary manuals | 2.4.4 | Manual content baseline |
| Server Communication ICD | Draft 0.1 for SPELL 2.4 | Historical interface evidence |

These versions must never be collapsed into one release number.

## Evidence Inventory

### Supplied Archives

| Artifact | Entries | SHA-256 | Assessment |
| --- | ---: | --- | --- |
| `SPELL2.6.10-src.zip` | 716 | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` | Core C++/Python source and deployment reference |
| `SPELL-COTS-2.6.10.zip` | Not used as a source tree | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` | Legacy vendored dependency/build bundle |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | 2,322 | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` | Prebuilt Windows x86 Eclipse RCP GUI |

The archives remain read-only project inputs.

### Manual Review

The manuals are embedded in
`SPELL_GUI/plugins/com.astra.ses.spell.gui.documentation_4.0.12.202410020907.jar`.

| Manual | Version/pages | Verified coverage | Result |
| --- | --- | --- | --- |
| SPELL Server Manual | 2.4.4 / 11 | Linux execution environment, XML configuration, listener, context, executor, drivers, databases, startup | Reviewed; older than core source |
| SPELL GUI User Manual | 2.4.4 / 54 | Context and procedure lifecycle, control/monitor/background modes, source and data views, prompts, scheduling, variables, as-run and logs | Reviewed; older than GUI binary |
| SPELL Language Reference | 2.4.4 / 118 | Python base, modifiers, errors, TM, TC, waits, prompts, limits, resources, tasks, subprocedures, data and files | Reviewed; requires source comparison |
| SPELL Driver Development Manual | 2.4.4 / 45 | GCS abstraction, Python connection layer, service groups, models, exceptions, configuration and deployment | Reviewed; legacy inheritance design will not be retained |
| SPELL Build Manual | 2.4.4 / 16 | GNU/Linux Autotools and legacy Eclipse/Java build | Reviewed; tool versions are obsolete |
| Server Communication ICD | Draft 0.1 / 52 | Listener/context/executor TCP message model and control/monitor concepts | Historical evidence only; draft contains a confidentiality marking |
| SPELL Development Environment Manual | Not found | Required procedure-development and maintenance workflows | Open documentation gap |

The development documentation plug-in contains another GUI manual and the
Language Reference, not the required Development Environment manual. Eclipse
plug-ins prove that development features exist, but they are not a substitute
for the missing manual.

### Evidence Precedence

When evidence conflicts, the project will use:

1. Reproducible behavior observed in an isolated legacy environment.
2. Version-specific source and configuration.
3. Version-specific manuals.
4. General upstream documentation.
5. Explicitly labeled assumptions.

## Legacy Capability Inventory

### Execution Environment

The legacy execution environment is process-oriented:

- `SPELL-Listener` is the initial client entry point and manages available
  contexts.
- `SPELL-Context` owns client sessions, procedure discovery, shared data,
  executor/service managers, context configuration, and recovery registration.
- Each active procedure has its own native executor process.
- The context selects a Python 2 or Python 3 executor from procedure metadata;
  an absent Python-version header defaults to Python 2.
- The C++ executor embeds CPython and supplies tracing, source-line control,
  call stacks, breakpoints, goto, stepping, scheduling, variables, resources,
  as-run recording, and warm-start state.
- Control, monitor, and background client modes are distinct. Control can be
  transferred or removed while monitors continue to receive execution data.

The core archive also includes command-line executors, services, shell tooling,
ping/health support, XML configuration, protobuf/gRPC driver contracts,
containers, Helm, Kubernetes, and CI material.

### Legacy Execution States

| State | Verified meaning |
| --- | --- |
| `UNINIT` | Executor not initialized or state unknown |
| `LOADED` | Procedure loaded; foreground execution normally pauses at its first line |
| `PAUSED` | Execution paused at a controllable point |
| `RUNNING` | Procedure executing continuously |
| `FINISHED` | Successful terminal completion |
| `ABORTED` | Terminal user or system abort after cleanup |
| `ERROR` | Load, syntax, runtime, system, or unrecovered error |
| `WAITING` | Execution held for time, telemetry, event, or other condition |
| `PROMPT` | Execution waiting for operator input |
| `INTERRUPTED` | Driver operation or wait interrupted and execution stopped |
| `RELOADING` | Procedure reload in progress |
| `UNKNOWN` | Unrecognized or unavailable status |

Terminal states reject normal later status changes. Abort reporting occurs after
driver cleanup, which is an important observable ordering requirement.

### Legacy Command And State Matrix

| Command | Verified allowed source state or condition |
| --- | --- |
| Run | `PAUSED` or `INTERRUPTED` |
| Step | `PAUSED` or `INTERRUPTED` |
| Step over | `PAUSED` or `INTERRUPTED` |
| Skip | `PAUSED` or `INTERRUPTED` |
| Goto | `PAUSED` |
| Pause | `RUNNING`, `PROMPT`, or `WAITING` |
| Interrupt | Active driver operation/wait while `RUNNING`, `PAUSED`, or `WAITING` |
| Abort | Active non-terminal execution states |
| Finish | `RUNNING`, `PAUSED`, `WAITING`, or `PROMPT` |
| Reload | `FINISHED`, `ABORTED`, or `ERROR` |
| Recover | `ERROR` |
| Execute script | `PAUSED`, `WAITING`, `PROMPT`, or `INTERRUPTED` |
| Close | Context/executor lifecycle rules apply |

The new state machine must formally specify every allowed and rejected
transition. It may add validation, aborting, resynchronization, or recovery
states, but it must expose a documented compatibility mapping.

### Prompts And Failure Handling

Legacy prompts carry message, options, expected values, default, scope, type,
and timeout. Types include OK/cancel, yes/no, numeric, alphanumeric, date,
password, list, and combo input.

Distinct terminal prompt outcomes include cancel, timeout, error, and no
controlling client. Prompt start and end notifications are sent to monitoring
clients. Legacy cancellation and timeout can abort execution; absence of a
controller warns and pauses.

Legacy failure actions include abort, repeat, resend, recheck, skip, cancel,
handle, and no-action. Because resend can repeat an external effect, the new
system must classify command certainty before offering or applying any retry.

### Procedure Language And SDK Families

Legacy procedures are sequential Python with SPELL functions injected into the
runtime. They are not sandboxed. Verified capability families include:

- Procedure lifecycle, steps, goto, pause, finish, abort, user actions, and
  configuration.
- Time and interval management.
- Telemetry acquisition, raw and engineering values, validity, timestamps,
  limits, injection, and verification.
- Telecommand construction, arguments, groups, sequences, release/time tags,
  confirmation, verification, and failure actions.
- Events, resources, tasks, users, displays, prompts, messages, and logs.
- Child procedures, procedure libraries, arguments, IVARS, and shared data.
- Spacecraft, ground, manoeuvre, user, and procedure databases.
- Files, dictionaries, data containers, memory, ranging, PCS, and TM/TC
  database access.

The new SDK must keep operator-facing procedure intent sequential and readable,
even if the runtime uses asynchronous I/O internally.

### Driver Model

Legacy drivers translate common SPELL services into GCS-specific behavior. The
manual describes an in-process Python inheritance boundary; the 2.6.10 source
also contains protobuf/gRPC services.

Verified service groups include TM, TC, events, resources, tasks, time, users,
ranging, memory, PCS, configuration, and database management. Legacy protobuf
contracts use generic payloads and boolean results in several places. Some
driver channels are insecure and optional HiFly/Scorpio implementations
referenced by the build are absent from the archive.

The GCS abstraction is a behavior to preserve. The in-process inheritance and
legacy wire details are not target constraints.

### GUI And Operator Workflows

The GUI archive is a prebuilt Windows 32-bit Eclipse RCP/SWT application. It is
compiled Java/OSGi content and contains no editable GUI source. Verified
operator capabilities include:

- Server connect, disconnect, restart, and context lifecycle.
- Procedure catalog refresh, properties, open, open with arguments, background
  execution, scheduling, close, release, kill, and recovery.
- Run, pause, step, step-over, skip, goto, interrupt, abort, reload, breakpoints,
  run-into, and by-step modes.
- Separate control and monitor sessions and control handover.
- Source/current-line, text, shell, prototype flow, call-stack, outline,
  variable, shared-data, resource, history, and replay views.
- Telecommand and prompt confirmation modes.
- Calling-argument, internal-variable, dictionary, and shared-data editing.
- Logs, as-run files, export, printing, input-file viewing, status, and clock.

The new 2D web interface must preserve the supported workflows, not the Eclipse
window model or visual styling.

### Configuration, Data, And Audit

Legacy XML configures server/listener ports, contexts, spacecraft and GCS
identity, procedure and user-library paths, drivers, databases, executor
defaults, language modifiers, as-run locations, and warm-start locations. No XML
schema is supplied.

Legacy as-run output is a flushed, ordered record of state, display, prompt,
answer, child, item, source line, call, return, error, and user-action data.
Warm-start modes include online, on-step, on-demand, and disabled behavior.

The new design must retain reconstructable as-run evidence while replacing
ad-hoc formats with versioned typed models and explicit retention.

### Build, Deployment, And Dependencies

The core build is GNU Autotools on POSIX/Linux and uses C++, Python 2, Python 3,
protobuf, POSIX services, Xerces-C, log4cplus, and optional integration
dependencies. There is no verified native Windows core build.

The COTS archive mixes 32-bit and 64-bit assumptions, Python 2.7 and Python 3.7,
duplicated dependency versions, obsolete packages, incomplete build inputs,
mixed licenses, and internal infrastructure references. It is not an acceptable
dependency lock for the new product.

The GUI requires an external Java runtime and bundles an Eclipse 4.6-era stack.
No Java or Eclipse dependency will be carried into the target product.

## Documented Versus Implemented Comparison

| Area | Documentation | Supplied implementation | v0.1 disposition |
| --- | --- | --- | --- |
| Core version | Manuals describe 2.4.4 | Archive and Helm say 2.6.10; release notes stop at 2.6.8.4 | Capture behavior; do not infer from labels |
| GUI version | Manual describes 2.4.4 | Product is 4.0.12; release notes stop at 4.0.9 | Treat plug-ins and later traces as evidence |
| Development manual | Required by project input | Not found; dev plug-in embeds GUI and language manuals | Open blocker for workflow parity |
| Python | Manual assumes old Python 2 | Core has Python 2/3 executors and Python 3 fixes | Migrate to Python 3 with compatibility tests |
| GUI | Java/Eclipse RCP | Prebuilt Java/OSGi binary only | Replace with 2D web application |
| Client API | Draft custom TCP ICD and Java/C++ clients | Custom IPC remains; separate gRPC driver API added | New REST/WebSocket/gRPC model |
| Driver boundary | In-process Python inheritance | Python adapters plus protobuf/gRPC service driver | Out-of-process typed driver host |
| Driver services | TM/TC/EV/RSC/TIME/TASK emphasized | Adds USER/RNG/MEM/PCS/config/database services | Capability-based contract |
| Configuration | XML examples and defaults | Source XML contains mojibake and default conflicts | Typed schema and migration tooling required |
| Testing | Build mentions optional CppUnit | No substantive core test suite included | Specification-derived suite required |
| Build completeness | Manual describes full framework | Optional driver source/submodules are absent | Record unsupported components |
| Security | Legacy docs focus on connectivity | Unencrypted IPC, insecure gRPC, internal endpoints, weak scan gates | New security baseline required |
| Licensing | Component-level open-source claims | GPL/LGPL and mixed COTS licenses | Legal/SBOM review before reuse |

## Target Architecture

### Architectural Shape

The recommended first implementation is a modular Python control plane with
strong process boundaries, not an initial microservice estate.

The proposed components are:

1. **Web Operator Console**: React and strict TypeScript desktop-class SPA.
2. **Control API**: authenticated REST commands and snapshots plus a downstream
   WebSocket event stream.
3. **Execution Supervisor**: owns the formal lifecycle, control lease, worker
   fencing, prompts, commands, deadlines, checkpoints, and recovery.
4. **Procedure Worker**: one isolated Python process or container per execution.
5. **Driver Host**: separate process for each configured GCS/spacecraft adapter.
6. **Driver Gateway**: typed, versioned protobuf/gRPC capability contracts.
7. **Persistence Layer**: PostgreSQL system of record for command, state, event,
   prompt, checkpoint, procedure, configuration, and audit data.
8. **Telemetry Projection**: bounded current values and time-series retention
   separated from the non-droppable execution/audit event stream.
9. **Compatibility Adapter**: temporary legacy IPC boundary used only where
   migration evidence justifies it.
10. **Optional Event Transport**: added only when multi-node fan-out or
    high-availability needs exceed the transactional outbox design.

### Non-Negotiable Boundaries

- The browser never communicates directly with a driver or GCS.
- Procedure code never runs inside the API process.
- A procedure worker has no direct GCS credentials or unrestricted network,
  database, filesystem, or secret access.
- One serialized state-machine owner controls an execution.
- Driver-specific and spacecraft-specific behavior remains outside common
  execution and procedure semantics.
- Events are persisted before they are published to clients.
- WebSocket delivery is a projection, not the source of truth.
- Operational commands are durable API resources, not transient socket
  messages.

## Legacy-To-New Component Mapping

| Legacy component | Target responsibility | Migration treatment |
| --- | --- | --- |
| Listener | Control API entry, authentication, context catalog | Replace protocol; preserve discovery behavior |
| Context | Context service and execution supervisor | Preserve isolation and shared-data scope |
| Executor | Isolated Python procedure worker | Reimplement against compatibility traces |
| C++ embedded CPython engine | Python runtime plus validated execution model | Replace; preserve visible semantics |
| In-process driver | Out-of-process driver host | Replace boundary; preserve service capabilities |
| Custom TCP IPC | REST commands, WebSocket events, internal gRPC | Compatibility adapter only during migration |
| SPELL Library | Versioned Python procedure SDK | Preserve recognizable names/semantics selectively |
| SPELL Shell | Administrative/API client | Reassess after API stabilization |
| Eclipse GUI | Real-time 2D web operator console | Replace completely |
| SPELL DEV | Web or editor-integrated authoring workflow | Blocked pending workflow/manual inventory |
| XML configuration | Validated typed configuration with import/export | Provide migration and compatibility reports |
| ASRUN text files | Versioned append-only audit and export | Preserve ordered reconstruction and export |
| Warmstart | Versioned safe checkpoints and reconciliation | Redesign; never resume uncertain effects blindly |

## API Specification Direction

### Browser-Facing REST API

The candidate API prefix is `/api/v1`. Candidate resources are contexts,
procedure definitions and versions, executions, commands, prompts, drivers,
snapshots, events, reports, users, roles, and approvals.

State-changing operations create durable commands. A request returns a command
identifier and an accepted status; execution of the request is observed through
the command resource and ordered event stream.

Every mutation must include:

- Idempotency key.
- Expected execution revision.
- Authenticated actor and role.
- Context and execution identity.
- Reason where policy requires it.
- Correlation identifier.
- Optional approval reference for critical actions.

Duplicate idempotency keys return the original command result. A stale expected
revision is rejected as a conflict. Safety-critical commands are never queued or
retried invisibly by the browser.

### Real-Time WebSocket API

One authenticated event stream provides ordered downstream updates. A client
starts from an authoritative REST snapshot and subscribes after the snapshot's
sequence. On reconnect, it supplies the last applied sequence. The server replays
the gap or directs the client to obtain a new snapshot.

The protocol must include heartbeat, bounded queues, slow-consumer policy, gap
detection, replay limits, and explicit connected, reconnecting, resynchronizing,
stale, and closed states.

Lifecycle, prompt, command, approval, error, security, and audit events are never
silently dropped or coalesced. High-rate telemetry display samples may be
downsampled only under a declared policy; authoritative telemetry retention is a
separate concern.

### Internal gRPC Driver API

Driver hosts use typed protobuf services with:

- Version and capability handshake.
- Health, setup, cleanup, interrupt, and close lifecycle.
- Explicit deadlines and cancellation.
- Mutual service authentication.
- Stable operation identifiers.
- Structured errors and external-effect certainty.
- Snapshot plus subscription models where applicable.

Capabilities cover TM, TC, events, resources, tasks/displays, time, users,
ranging, memory, PCS, configuration, and databases as supported. Unsupported
capabilities are explicit.

Telecommand submission returns an operation identity and reports distinct
acceptance, release, acknowledgement, verification, rejection, timeout,
cancellation, and unknown stages. An unknown outcome cannot be resent without
reconciliation and an authorized decision.

### Procedure SDK

The target SDK is versioned Python 3. Procedure authors retain deterministic,
sequential constructs while the runtime performs asynchronous I/O behind typed
services.

Procedure bundles declare metadata, target applicability, SDK version,
capabilities, configuration dependencies, and content hashes. Runtime services,
clock, data, and drivers are injected. Direct access to server internals is not
part of the SDK.

Legacy Python 2 procedures are inventoried, parsed, and classified as directly
compatible, adapter-compatible, mechanically migratable, manually migratable,
or unsupported. The target runtime does not embed Python 2.

## Canonical Data Models

### Execution

An execution records identity, context, immutable procedure version/hash,
runtime/SDK/driver/configuration versions, state, revision, control lease,
timestamps, checkpoint reference, terminal outcome, and audit correlation.

### Command

A command records identity, type, target, idempotency key, expected revision,
actor, role, reason, approval, request time, accepted/rejected state, execution
time, result, external-effect certainty, and correlation/causation chain.

### Event Envelope

Every canonical event contains:

- Envelope and payload schema versions.
- Globally unique event identifier.
- Namespace-qualified event type.
- Monotonic sequence within the execution.
- Context, execution, command, prompt, and operation identities as applicable.
- Occurrence and persistence timestamps.
- Correlation and causation identifiers.
- Actor/source, severity, and typed payload.

### Prompt

A prompt records type, message, options, validation, default, scope, timeout,
controller, state, response, actor, timestamps, and terminal outcome. Answer,
cancel, timeout, error, no-controller, and superseded/race outcomes remain
distinct.

### Telemetry

A telemetry observation records parameter identity, source and receive time,
raw and engineering value, units, validity, quality, staleness, limits, source,
and sequence. The UI must not treat a missing quality field as valid data.

### Telecommand Operation

A telecommand operation records command identity and arguments, source
procedure/line, approvals, release options, external operation identity, each
stage and acknowledgement, timestamps, verification, final certainty, and
reconciliation state.

### As-Run Record

An as-run report is a reproducible projection of immutable events and includes
the procedure, runtime, driver, configuration, user, command, prompt, data, and
source-location evidence required to reconstruct the execution.

## Target Execution State Model

The proposed target model adds explicit safety and recovery states while
retaining a compatibility mapping:

| Target state | Legacy relationship | Meaning |
| --- | --- | --- |
| `CREATED` | Before `UNINIT` | Execution identity allocated |
| `VALIDATING` | Load preparation | Package, metadata, dependencies, and policy validation |
| `READY` | `LOADED` | Validated and ready at initial control point |
| `RUNNING` | `RUNNING` | Procedure actively executing |
| `PAUSED` | `PAUSED` | Stopped at safe operator-controlled point |
| `WAITING` | `WAITING` | Waiting on time/data/event condition |
| `PROMPTING` | `PROMPT` | Durable operator input required |
| `INTERRUPTED` | `INTERRUPTED` | Driver operation or wait interrupted |
| `RELOADING` | `RELOADING` | Approved reload/migration in progress |
| `ABORTING` | Legacy cleanup interval | Abort requested; effects and cleanup unresolved |
| `COMPLETED` | `FINISHED` | Successful terminal state |
| `ABORTED` | `ABORTED` | Clean terminal abort |
| `FAILED` | `ERROR` | Terminal failure not eligible for automatic continuation |
| `RECOVERY_REQUIRED` | Partial `ERROR`/warmstart behavior | State or external effects require reconciliation |
| `TERMINATED_UNCLEAN` | No safe direct equivalent | Forced termination with uncertain cleanup/effects |

A detailed transition table and executable state-machine tests are required
before engine implementation.

## Real-Time 2D Web Interface

### Product Direction

The interface is a desktop-class operational console, not a marketing site. It
uses dense, resizable panes and stable controls. The proposed stack is React with
strict TypeScript. DOM/CSS provides controls, SVG provides moderate-size flow and
synoptic views, and a chart library provides telemetry plots and timelines.
Accelerated 2D rendering is added only if measured high-density synoptic needs
justify it. Three.js is not part of the 2D baseline.

### Primary Layout

- Persistent header: server, context, spacecraft, GCS, UTC/mission time, link
  health, authenticated role, controller identity, and alarm count.
- Left pane: contexts, procedure catalog, active executions, filters, and
  lifecycle state.
- Center pane: procedure source, current line, executed coverage, call stack,
  child-procedure navigation, item values/status, and optional 2D flow.
- Right pane: durable prompts, variables, arguments, resources, shared data,
  approvals, and execution configuration.
- Bottom workspace: telemetry, telecommands, acknowledgements, events, logs,
  audit timeline, replay, and as-run history.

### Operator Behavior

- Controls are enabled only when the authoritative state, user role, control
  lease, and expected revision allow the action.
- Monitor clients remain read-only. Control acquisition, release, expiry, and
  takeover are explicit and audited.
- Prompts, alarms, failed commands, uncertain effects, and connection loss are
  latched states, not transient notifications.
- Color is always paired with text and iconography.
- A stale or resynchronizing client cannot issue operational commands.
- Keyboard use, visible focus, accessible names, high contrast, reduced motion,
  and screen-reader status are required.
- High-rate values update without rerendering the full interface; tables are
  virtualized and charts use measured downsampling.

## Persistence, Checkpoint, And Recovery

PostgreSQL is the proposed system of record. Execution state, commands, prompts,
events, checkpoints, audit fields, and a transactional outbox are committed
atomically where required.

Only defined safe points may produce resumable checkpoints. A checkpoint records
the instruction/call location, procedure variables and data containers, pending
wait/prompt, runtime and configuration identity, resource ownership, and last
committed event sequence.

Recovery rehydrates from the latest compatible checkpoint and subsequent
events. It must reconcile external effects before continuation. A telecommand
accepted by a driver but lacking a known result enters `RECOVERY_REQUIRED` and is
never sent again automatically.

Cooperative cancellation precedes forced termination. A forced kill produces an
unclean state and an explicit recovery workflow.

## Security, Safety, And Licensing

### Security Baseline

- Use centralized user authentication and short-lived sessions.
- Enforce viewer, operator, supervisor, and administrator roles.
- Use service identity and mutually authenticated encrypted internal channels.
- Protect REST and WebSocket origins, sessions, and state-changing requests.
- Store driver credentials outside procedure workers and browser payloads.
- Redact secrets from events, logs, errors, exports, and as-run reports.
- Record user, role, lease, reason, approvals, request, pre/post revision,
  outcome, and correlation for every operational action.
- Require stronger approval, including optional two-person control, for policy-
  classified critical operations.

### Operational Safety Baseline

- Default every new environment to non-operational simulators.
- Validate telemetry identity, time, units, quality, validity, limits, and
  freshness before decisions.
- Make timeout, cancel, abort, retry, and recovery semantics explicit.
- Never interpret transport success as spacecraft-command success.
- Never automatically retry a telecommand with an uncertain outcome.
- Preserve complete, chronologically reconstructable audit evidence.
- Separate software release approval from operational deployment approval.

### Licensing And Supply Chain

The core archive contains GPL-3.0-or-later native code and LGPL-3.0-or-later
Python files; the COTS and Eclipse distributions contain mixed licenses. A legal
review is required before copying source or linking implementation content into
the new product.

The new implementation must generate a dependency lock, SBOM, license report,
vulnerability report, provenance, hashes, and signed release artifacts. The
legacy COTS archive is not reusable as a modern lockfile. Internal endpoints and
credentials found in legacy build/deployment material must not be reproduced.

## Requirements Registry

Evidence codes: `USER` is an explicit project request; `MAN-*` is an embedded
manual; `SRC` is the core source; `GUI` is the GUI artifact; `COTS` is the
legacy dependency bundle; `REC` is the v0.1 architecture recommendation.

| ID | Requirement | Priority / safety | Evidence | Planned verification |
| --- | --- | --- | --- | --- |
| `REQ-GOV-001` | v0.1 contains documentation only | Must / High | USER | `V01-DOC-011` |
| `REQ-GOV-002` | Every version updates test plans before implementation | Must / High | USER | Version gate audit |
| `REQ-ARCH-001` | Target backend and engine use Python 3 | Must / High | USER | Architecture and runtime tests |
| `REQ-ARCH-002` | Target product contains no Java components | Must / Normal | USER | Dependency/SBOM audit |
| `REQ-ARCH-003` | Procedure execution is isolated from the API process | Must / Critical | SRC, REC | `ENG-ISOL`, fault tests |
| `REQ-ARCH-004` | GCS drivers run behind a typed process boundary | Must / Critical | MAN-DRV, REC | `DRV-*` |
| `REQ-ARCH-005` | Browser cannot access drivers/GCS directly | Must / Critical | REC | Network and authorization tests |
| `REQ-ARCH-006` | One serialized owner controls each execution | Must / Critical | SRC, REC | `ENG-CTRL`, stale-owner tests |
| `REQ-COMP-001` | Preserve GCS independence in common procedure semantics | Must / Critical | MAN-LANG, MAN-DRV | Driver conformance and golden traces |
| `REQ-COMP-002` | Preserve spacecraft-family independence through data/config | Must / High | MAN-SRV, MAN-LANG | Migration and multi-context tests |
| `REQ-COMP-003` | Map every legacy state and command outcome | Must / High | MAN-GUI, SRC | `LGC-STATE`, `LGC-CMD` |
| `REQ-COMP-004` | Preserve control, monitor, and background semantics | Must / High | MAN-GUI, SRC, GUI | `LGC-GUI`, `REC-CLIENT` |
| `REQ-PROC-001` | Provide a versioned, readable sequential Python SDK | Must / High | USER, MAN-LANG | Procedure compatibility suite |
| `REQ-PROC-002` | Cover verified legacy language service families | Must / High | MAN-LANG, SRC | `LGC-SVC`, SDK contract tests |
| `REQ-PROC-003` | Version and hash every executed procedure bundle | Must / High | REC | `ENG-LOAD`, `REC-ASRUN` |
| `REQ-PROC-004` | Restrict procedure filesystem/network/secret capabilities | Must / Critical | SRC, REC | `SEC-PROC`, `ENG-ISOL` |
| `REQ-PROC-005` | Classify and migrate Python 2 procedures | Must / High | SRC | `MIG-DIFF`, compatibility corpus |
| `REQ-API-001` | REST is authoritative for queries and commands | Must / High | REC | `API-REST`, `API-CMD` |
| `REQ-API-002` | WebSocket carries ordered downstream events only | Must / Critical | REC | `API-WS`, reconnect tests |
| `REQ-API-003` | Every mutation is idempotent and revision-checked | Must / Critical | REC | Duplicate/conflict fault tests |
| `REQ-API-004` | Canonical events have identity, sequence, versions, time, and causality | Must / High | SRC, REC | `API-SCHEMA`, `REC-EVENT` |
| `REQ-API-005` | Reconnect uses snapshot plus cursor/replay or explicit resync | Must / High | REC | `API-REPLAY`, `UI-STALE` |
| `REQ-API-006` | Driver RPCs use typed errors, deadlines, and capabilities | Must / Critical | SRC, REC | `DRV-LIFE`, schema contracts |
| `REQ-DRV-001` | TM includes raw/engineering value, units, time, quality, validity, and limits | Must / Critical | MAN-DRV, SRC | `DRV-TM` |
| `REQ-DRV-002` | TC has stable operation identity and explicit stages/certainty | Must / Critical | MAN-LANG, SRC, REC | `DRV-TC`, `REC-UNCERTAIN` |
| `REQ-DRV-003` | Unsupported driver services are explicit | Must / High | MAN-DRV, SRC | Capability conformance tests |
| `REQ-SAFE-001` | Development cannot connect to live systems by default | Must / Critical | USER, REC | Environment/network policy tests |
| `REQ-SAFE-002` | Uncertain telecommands are never automatically repeated | Must / Critical | SRC, REC | Crash-at-every-boundary tests |
| `REQ-SAFE-003` | Prompt cancel, timeout, error, and no-controller stay distinct | Must / Critical | SRC | `LGC-PROMPT`, `ENG-PROMPT` |
| `REQ-SAFE-004` | Operational controls require current state, role, lease, and revision | Must / Critical | GUI, REC | `SEC-AUTHZ`, `UI-STALE` |
| `REQ-SAFE-005` | Critical actions support reason and approval policy | Should / Critical | REC | Approval and audit tests |
| `REQ-DATA-001` | Persist canonical execution events before broadcasting | Must / Critical | REC | `REC-EVENT`, outage tests |
| `REQ-DATA-002` | Preserve reconstructable as-run history | Must / Critical | MAN-GUI, SRC | `REC-ASRUN`, golden trace |
| `REQ-DATA-003` | Checkpoints occur only at documented safe points | Must / Critical | SRC, REC | `ENG-CHECK`, worker crash tests |
| `REQ-DATA-004` | Separate droppable UI samples from non-droppable audit events | Must / High | REC | Backpressure and gap tests |
| `REQ-UI-001` | Provide a real-time 2D web operator console | Must / High | USER | End-to-end UI workflows |
| `REQ-UI-002` | Preserve source/current-line, call-stack, data, prompt, log, replay, and history workflows | Must / High | MAN-GUI, GUI | `LGC-GUI`, `UI-*` |
| `REQ-UI-003` | Display stale/reconnecting/resync states and disable controls | Must / Critical | REC | `UI-STALE` |
| `REQ-UI-004` | Alarms, prompts, failures, and uncertainty are latched | Must / Critical | MAN-GUI, REC | `UI-PROMPT`, `UI-DATA` |
| `REQ-UI-005` | UI is keyboard-accessible and does not rely on color alone | Must / High | REC | `UI-A11Y` |
| `REQ-SEC-001` | Authenticate users/services and enforce least-privilege roles | Must / Critical | REC | `SEC-AUTHN`, `SEC-AUTHZ` |
| `REQ-SEC-002` | Secrets never enter procedure, client, log, event, or report payloads | Must / Critical | SRC, GUI, REC | `SEC-SECRETS` |
| `REQ-SEC-003` | Produce SBOM, license, vulnerability, provenance, and signature evidence | Must / High | COTS, GUI | `SEC-SBOM`, `SEC-ARTIFACT` |
| `REQ-PERF-001` | Approve measurable real-time budgets before implementation | Must / High | USER, REC | Performance gate |
| `REQ-TEST-001` | Build a deterministic simulator and golden legacy trace corpus | Must / Critical | SRC, REC | `LGC-*`, `MIG-DIFF` |
| `REQ-TEST-002` | Inject crashes, duplicates, gaps, partitions, stale leases, and outages | Must / Critical | REC | `REC-*`, `API-*` |
| `REQ-MIG-001` | Replace legacy behavior incrementally with rollback | Must / Critical | REC | `MIG-*` |
| `REQ-MIG-002` | Retain legacy IDs and report mappings where audit requires | Must / High | SRC, REC | Migration reconciliation tests |

## Architecture Decisions

| Decision | Status | Rationale |
| --- | --- | --- |
| New implementation with behavior compatibility | Accepted direction | User request plus risk reduction |
| Python 3 backend and execution engine | Accepted direction | User requirement; removes dual Python runtime |
| No Java in target product | Accepted direction | User requirement; retires Eclipse RCP/JVM stack |
| Real-time 2D web interface | Accepted direction | User requirement |
| No Three.js in 2D baseline | Proposed | DOM/SVG/charts are better suited; accelerated 2D only when measured |
| Modular control plane before microservices | Proposed | Fewer distributed failure modes during domain stabilization |
| Process-isolated procedure workers | Proposed | Fault containment and explicit lifecycle ownership |
| Out-of-process typed driver hosts | Proposed | GCS isolation, deadlines, capability contracts, and independent recovery |
| REST commands plus WebSocket events | Proposed | Clear mutation/audit and reconnect semantics |
| Protobuf/gRPC internal boundaries | Proposed | Typed service contracts and streaming support |
| PostgreSQL system of record | Proposed | Transactional state, event, command, and outbox consistency |
| React and strict TypeScript SPA | Proposed | Desktop-class component model and browser ecosystem |

Proposed decisions require v0.1 approval and may change through a documented
decision without changing the accepted product goals.

## Test And Integration Strategy

`Test_and_Integration.md` is the authoritative plan. Before every version, its
requirements, cases, expected results, environments, dependencies, safety
controls, and acceptance criteria must be updated and approved.

The minimum strategy includes:

- Legacy state, command, prompt, procedure, service, and GUI golden traces.
- Unit and property tests for state and schema invariants.
- Contract tests for REST, WebSocket, gRPC, and the procedure SDK.
- Driver conformance suites using simulators and recorded data.
- Crash-at-every-boundary and uncertain-effect tests.
- Browser workflow, accessibility, reconnection, replay, and long-soak tests.
- Authentication, authorization, secret, dependency, and supply-chain tests.
- Differential legacy/new execution and rollback exercises.

The supplied archives do not contain an adequate core unit-test suite. New
coverage must be derived from the manuals, source, release defects, and observed
behavior.

## Migration And Rollback Plan

### Phase 0: v0.1 Contract

Approve requirements, architecture, interfaces, test strategy, risks, and the
first vertical slice. Resolve or assign every open question.

### Phase 1: Simulator-Only Vertical Slice

Load and validate one procedure, execute it in an isolated worker, stream ordered
events, show current source state in the 2D UI, pause/resume, answer one prompt,
abort safely, recover from a controlled worker restart, and produce an as-run
report. No live or legacy GCS connection is allowed.

### Phase 2: Read-Only Legacy Adapter

Connect the new API/UI to an isolated legacy environment for catalogs, snapshots,
monitoring, events, logs, replay, and as-run comparison. The adapter has no
command authority.

### Phase 3: Controlled Legacy Commands

Add audited procedure-control commands through the compatibility adapter in a
non-operational environment. Validate idempotency, control lease, prompt races,
reconnect, and rollback.

### Phase 4: New Executor Compatibility

Implement language/engine capability groups incrementally and compare each
against golden traces. Migrate procedure corpora by compatibility class.

### Phase 5: Driver Migration

Implement simulator and then approved GCS drivers one capability at a time.
Require conformance, failure, reconciliation, security, and load evidence.

### Phase 6: Parallel Pilot And Cutover

Run read-only shadow, supervised non-commanding, then separately authorized
commanding pilots. Preserve rapid rollback to legacy authority until operational
acceptance is complete.

The legacy adapter is retired only after procedure, driver, data, audit,
recovery, and operator parity are accepted.

## Risks And Open Issues

| ID | Risk | Severity | Required resolution |
| --- | --- | --- | --- |
| `RISK-001` | Development Environment manual is missing | High | Obtain manual or formally reconstruct/approve workflows before authoring-tool work |
| `RISK-002` | Manual, source, GUI, release-note, and image versions conflict | High | Build a reproducible legacy reference and behavior manifest |
| `RISK-003` | Core archive lacks substantive automated tests | Critical | Create specification-derived golden and fault suites before porting |
| `RISK-004` | Legacy procedures are unrestricted Python | Critical | Decide compatibility versus restricted SDK and isolation policy |
| `RISK-005` | Legacy resend/recheck behavior can repeat external effects | Critical | Define certainty and reconciliation model with operators/GCS owners |
| `RISK-006` | COTS dependencies are obsolete, duplicated, and incompletely reproducible | Critical | Select supported dependencies; generate lock, SBOM, license and vulnerability gates |
| `RISK-007` | GPL/LGPL and mixed third-party licenses affect clean-room reuse | High | Complete legal review before copying source or linking components |
| `RISK-008` | Archives contain internal infrastructure and draft confidential-marked material | High | Sanitize evidence; define publication boundary |
| `RISK-009` | Optional/proprietary driver sources are absent | High | Obtain contracts/owners or scope them out explicitly |
| `RISK-010` | GUI is binary-only and manuals are older | High | Capture workflows and traces from an isolated runnable GUI |
| `RISK-011` | Real-time load and latency requirements are unknown | High | Obtain operational workload profiles and approve budgets before v0.2 |
| `RISK-012` | Legacy XML has no schema and contains default/encoding conflicts | High | Create corpus, parser behavior tests, and migration rules |

## Decisions Required Before v0.2

1. Approve or revise the proposed target architecture and technologies.
2. Define the Python 2 procedure compatibility commitment.
3. Define which language functions and optional services enter the first
   compatibility target.
4. Supply real-time latency, throughput, concurrency, retention, and availability
   requirements.
5. Define authentication provider, roles, approval policy, and control-handover
   policy.
6. Define deployment targets and required high-availability model.
7. Resolve licensing strategy and clean-room constraints.
8. Decide whether the draft ICD may be used beyond internal compatibility
   analysis.
9. Obtain or waive the Development Environment manual.
10. Approve the simulator-only v0.2 vertical slice and its acceptance tests.

## v0.1 Approval Criteria

Version 0.1 can be approved when:

- The manual and archive inventory is accepted with documented gaps.
- Requirements and planned tests are traceable.
- Architecture and API boundaries are accepted or revised.
- State, command, prompt, audit, and uncertain-effect rules are accepted.
- The security, licensing, and supply-chain work has assigned owners.
- Performance budgets have a named decision path.
- The v0.2 scope and no-live-system restriction are accepted.
- `README.md`, `PROMPT_History.md`, `Test_and_Integration.md`, and this document
  are consistent.

Until that approval is recorded, OpenBEXI SPELL remains a planning project and
no implementation phase is authorized.

## Authoritative References

- Local legacy archives listed in the Evidence Inventory.
- SourceForge SPELL Wiki: `https://sourceforge.net/p/spell-sat/wiki/Home/`
- SourceForge project summary: `https://sourceforge.net/projects/spell-sat/`
- SourceForge getting started: `https://sourceforge.net/p/spell-sat/wiki/Start%20using%20SPELL/`
- SourceForge licensing overview: `https://sourceforge.net/p/spell-sat/wiki/Licensing/`

Local version-specific behavior takes precedence over general website content,
subject to the evidence hierarchy above.
