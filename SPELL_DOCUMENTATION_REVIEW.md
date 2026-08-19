# SPELL Documentation Conformance Review

## Document Control

| Field | Value |
| --- | --- |
| Review date | 2026-07-17 |
| Evidence location | `SPELL-DOCUMENTATION/` |
| Coverage | Seven PDF files; 304 of 304 pages reviewed |
| Review purpose | Rebaseline the OpenBEXI SPELL roadmap against documented SPELL behavior |
| Current product baseline | SPELL v0.3.0, tag `v0.3.0` |
| Product implementation change | None |
| Operational authorization | None |
| Distribution decision | Not made; the supplied PDFs remain external read-only evidence unless separately cleared |

This record documents a page-complete review of the material currently under
`SPELL-DOCUMENTATION/`. It is a clean-room behavioral input and roadmap record,
not permission to copy legacy implementation code, package the PDFs, connect to
a Ground Control System (GCS), or reproduce unsafe legacy behavior.

## v0.10 And v0.11 Application Note

The 2026-08-19 mutable-worktree increments apply this review without changing
the original 2026-07-17 evidence inventory. v0.10 maps all 195 numbered Language
Reference examples to 257 hash-bound variant subcases and independently authored
semantic oracles. v0.11 implements the command corpus in Examples 57 through 77
as closed, deterministic simulator `BuildTC`/`Send` behavior. The Language
Reference owns documented syntax and procedure-visible intent; the Driver
Development Manual owns stage and provider concepts. Where legacy prose
conflicts with typed certainty, no-resend, or supervisor-owned confirmation,
the bounded decisions in
`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.11_Pre-Implementation.md`
apply, the mutable
implementation and local qualification boundary is recorded in
`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.11_Implementation.md`,
and
the conflict remains documented rather than guessed.

These applications do not copy manual bodies into runtime source and do not
create a live GCS adapter, driver credential, spacecraft connection, operational
authorization, general SPELL 2.4.4 conformance claim, or accepted release.

## Evidence Inventory

| Document | Pages reviewed | Stated version | SHA-256 | Principal use | Evidence limitation |
| --- | ---: | --- | --- | --- | --- |
| `SPELL - Build Manual - 2.4.4.pdf` | 16/16 | 2.4.4 | `6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6` | Component, build, install, and packaging concepts | Obsolete autotools, GCC, Python 2, Java, and Eclipse details |
| `SPELL - Development Environment Manual - 2.4.4.pdf` | 57/57 | 2.4.4 | `cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81` | Projects, editors, dictionaries, semantic checks, and collaboration | Eclipse, CVS, SVN, and Python 2 workflows are historical |
| `SPELL - Driver Development Manual - 2.4.4.pdf` | 45/45 | 2.4.4 | `057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5` | GCS-independent services, lifecycle, configuration, TM, TC, events, resources, and time | Weak typing, in-process inheritance, security, recovery, and concurrency gaps |
| `SPELL - GUI User Manual - 2.4.4.pdf` | 54/54 | 2.4.4 | `1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6` | Context, catalog, operator control, prompts, monitoring, source, and logs | Direct endpoints, arbitrary shell/evaluation, and unsafe kill behavior require redesign |
| `SPELL - Language Reference - 2.4.4.pdf` | 118/118 | 2.4.4 | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` | Public language, functions, modifiers, results, failure actions, and data services | Contains ambiguities, errata, Python 2 syntax, and unrestricted-code assumptions |
| `SPELL - Server Manual - 2.4.4.pdf` | 11/11 | 2.4.4 | `ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9` | Listener, context, executor, driver selection, paths, and configuration | Very small manual; broken contents/header metadata; no modern security model |
| `SPELL-GUI-4.0.2-Build-Instructions.pdf` | 3/3 | GUI 4.0.2 | `5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6` | Windows/Linux GUI build and package evidence | Conflicts with older Java/Eclipse build versions and is not a behavior specification |
| **Total** | **304/304** | Mixed | - | Complete supplied-document review | Manuals are not an executable or version-exact oracle |

The manuals are labeled 2.4.4, the previously inventoried Core archive is
2.6.10, the supplied GUI binary is 4.0.12, and the separate GUI build note is
4.0.2. The manuals therefore define important observable behavior, vocabulary,
and workflows, but they do not prove the exact behavior of every later binary.
Where they conflict, approved observed traces and version-specific source
evidence take precedence, followed by the manuals and then explicit modern
design decisions. Ambiguity must be recorded rather than guessed.

## Compatibility Policy

Close compatibility means preserving documented operator-visible and
procedure-visible behavior where it is safe, while using a modern bounded
implementation. Every documented language construct/syntax/operator, public
function, modifier, constant, type, outcome/action, state/control,
server/configuration field, driver service/method/result/status, operator or
development workflow/view, build/install/deployment concept, and example must
have one populated ledger entry before the v0.4 product gate can be approved,
with one of these dispositions:

| Disposition | Meaning |
| --- | --- |
| Exact observable compatibility | The documented name and externally visible result can be preserved without weakening safety or determinism. |
| Equivalent with safety strengthening | The intent and visible result are preserved while identity, authorization, typing, persistence, or recovery is strengthened. |
| Legacy syntax translated | A compatibility parser accepts the documented source form and lowers it to bounded, versioned data-only IR. |
| Optional adapter capability | The behavior depends on a driver or environment and must be negotiated explicitly. |
| Deliberately unsupported | The behavior conflicts with isolation, determinism, security, or product direction and fails with a stable diagnostic. |
| Documentation ambiguity | The manuals conflict or omit necessary semantics; record the ambiguity explicitly and defer/exclude it. A technical decision and executable oracle are required before any future implementation, not for the static excluded Gate 0 row. |

The required machine-readable compatibility ledger must record at least:
source manual/version/hash, reference pages, artifact kind and stable identity,
public name or example identity, signature/result, legacy behavior, effect
class, modern behavior, disposition, driver capability, persistence and
recovery rule, target version, a unique planned test identity, and scope
disposition. Per-manual source
inventories and counts must reconcile to populated rows. This family-level
review defines the complete gate schema and source inventory. Earlier 62-row
and 257-row records were partial checkpoints. The validated exhaustive catalog
covers all seven sources, all 304 pages, and all 195 Language Reference examples
and assigns 125 rows to Candidate A and 1,557 to Deferred/`EXCLUDE`. Excluded
rows require source-grounded static and negative-scope evidence, not executable
fixtures or results. Deterministic validation, independent source review, exact
owner-record manifest binding, and pinned Python 3.13 qualification pass for all
1,682 rows. Gate 0 authorizes the bounded product-engineering slice only.

## Target Architecture Mapping

The documented product separates execution, operator control, development, and
GCS abstraction. The modernization should retain those responsibilities:

```text
browser operator workspace -> authenticated control plane/listener
                                      |
                                      v
                              context supervisor
                                      |
                                      v
                           isolated executor/worker
                                      |
                                      v
                           typed driver gateway
                                      |
                                      v
                    isolated simulator or approved adapter

browser development workspace -> non-executing language services
                               -> immutable validated procedure bundle
                               -> simulator catalog/promotion workflow
```

| Documented concept | Modern target | Required rule |
| --- | --- | --- |
| Server listener | Authenticated REST/WebSocket control plane | No arbitrary browser-selected host or port in normal/test configuration |
| Spacecraft context | Versioned context resource and supervisor | Stable context identity, generation, configuration digest, capacity, and isolation |
| Executor/procedure instance | Isolated worker execution | Stable execution and instance identity; bounded IR only |
| Per-context driver binding | Supervisor-owned typed driver binding | Worker and browser receive no driver address or credential |
| Driver service registry | Typed granular capability descriptors | Service, method, modifier, mutability, format, streaming, and capacity are explicit |
| GUI | Accessible 2D operator workspace | Preserve states, ownership, monitoring, prompts, source identity, logs, and recovery semantics |
| Development Environment | Separate web development workspace | Parsing and semantic checking never execute procedure source or require a GCS |
| Project files and dictionaries | Versioned project and catalog resources | Safe import/export, immutable bundle digest, provenance, approval, and rollback |
| As-run and support logs | Canonical append-only audit projections | Persist before publish; gap-detectable cursor replay |

## Driver, Server, And Lifecycle Contract

The manuals make the server-context-executor-driver relationship a core SPELL
behavior. The v0.4 boundary must anticipate it even though v0.4 implements only
one simulator and no telemetry or telecommand service.

Required foundation:

- Separate driver-host lifecycle from context binding, execution attachment,
  and individual operation lifecycle (Driver pp. 24-25; Server pp. 5-10).
- Carry stable `ServerProfileId`, `DriverHostGeneration`, `ContextId`,
  `ContextGeneration`, `ExecutionId`, `ExecutionAttachmentGeneration`,
  `DriverBindingId`, and `OperationId` values.
- Use typed, versioned host-profile, context-binding, and
  execution-attachment configuration with separate immutable
  digests/generations, explicit precedence, schema versions, and secret
  references outside the payload.
- Bind shared context configuration first and clean it last at context
  open/close. For each procedure load/reload attachment, run its configuration
  interface setup first and cleanup last; detach on `FINISHED`, `ABORTED`,
  reload, or unload (Driver pp. 24-25, 37-38).
- Make cleanup best effort but return a typed, audited disposition. A legacy
  instruction not to throw must not silently hide a cleanup failure.
- Replace ambiguous `maxproc` with host and per-context capacity, maximum
  contexts, attachments, and in-flight lifecycle operations, serialization
  keys, deadlines, and typed `RESOURCE_EXHAUSTED` behavior (Driver p. 40;
  Server p. 8).
- Make partial services explicit. Unsupported methods or modifiers return
  typed capability results; they never silently do nothing and warn.
- Reserve snapshot/cursor/sequence/gap/backpressure/cancellation/restart rules
  for future streams. A driver never invokes an arbitrary UI callback.

Documented driver service groups include telemetry (`TM`), telecommand (`TC`),
event (`EV`), time (`TIME`), resources (`RSC`), configuration (`CIF`), memory
(`MEM`), context (`CTX`), and executor (`EXEC`). `TASK`, ranging, PCS, database,
and general subscription behavior are incomplete or inconsistent in the
reviewed manuals (Driver pp. 9-10; Server p. 8) and remain unverified until
another source or approved design defines them.

The manual describes `CIF`, `CTX`, and `EXEC` as always available. The target
preserves their infrastructure responsibilities, but a driver may not use
`CIF` to invoke an arbitrary UI prompt or write directly to a browser; prompts,
authorization, persistence, and publication remain supervisor-owned.

## Language Capability Map

The target should preserve the documented names and source concepts where safe,
but must not execute unrestricted Python or arbitrary imported modules.

| Capability family | Reference pages | Documented surface | Required modern behavior |
| --- | --- | --- | --- |
| Safe Python-shaped source | Language 14-26 | Indentation, expressions, lists/dictionaries, branches, loops, functions, imports | Parse a declared Python 3 compatibility profile into bounded IR; reject unsupported syntax with exact source diagnostics |
| Common configuration and outcomes | Language 26-31, 108-117 | `ChangeLanguageConfig`, modifiers, `OnFailure`, `OnTrue`, `OnFalse`, `PromptFailure`, `PromptUser`, `HandleError`, `DriverException`, and actions `ABORT`, `REPEAT`, `RESEND`, `RECHECK`, `SKIP`, `CANCEL`, `HANDLE`, `RESUME` | Pin defaults per execution and distinguish operation failure, valid false, operator override, and execution-control outcome |
| Time | Language 32-35 | `TIME`, `NOW`, `TODAY`, `TOMORROW`, `YESTERDAY`, `HOUR`, `MINUTE`, `SECOND` | Typed instant/duration, canonical UTC, explicit clock source and uncertainty, restart-safe timers |
| Telemetry acquisition | Language 36-38; Driver 12-13, 17-19 | `GetTM`, current/next sample, raw/engineering, extended item | Typed value, description, units, source, acquisition/receive time, validity, quality, freshness, sequence, and cursor |
| Conditions | Language 39-47 | `Verify`, `AND`, `OR`, comparison operators, tolerance, delay, timeout, retries | Deterministic condition engine with atomic sampling policy and golden semantic tests |
| Command construction and dispatch | Language 47-55; Driver 13-16, 26-30 | `BuildTC`, `Send`, arguments, sequences, groups, blocks, time tags, load-only, confirmation, verification | Simulator first; separate construction, authorization, dispatch, per-element stage, effect certainty, and reconciliation |
| Waits | Language 55-59 | `WaitFor` with relative, absolute, or telemetry condition | Durable target and cursor; interrupt/resume/skip without losing the original result |
| Limits and alarms | Language 59-68; Driver 19-24 | `GetLimits`, `SetLimits`, `AdjustLimits`, `LoadLimits`, `RestoreNormalLimits`, `EnableAlarm`, `DisableAlarm`, `IsAlarmed` | Separate reads from mutations; each mutation gets an explicit capability and effect gate |
| Operator output | Language 68-69; Driver 31-32 | `Display`, `Notify`, `Event` | Preserve client messages/status; treat `Event` as an external GCS write; audit even when presentation is suppressed |
| Resources | Language 69; Driver 33-35 | `GetResource`, `SetResource` | Catalog-backed typed reads and separately authorized writes |
| Prompts | Language 70-72; GUI 19-20, 39-40 | `Prompt` types `OK`, `CANCEL`, `OK_CANCEL`, `YES`, `NO`, `YES_NO`, `ALPHA`, `NUM`, `DATE`, and `LIST` modes | One durable validated result across timeout, restart, disconnect, and competing response |
| Display intent | Language 72-74 | `OpenDisplay`, `OpenWorkspace`, `PrintDisplay`, `CloseDisplay`, `CloseWorkspace` | Optional logical UI adapter; remote workstation and printer control are not core behavior |
| Flow control | Language 75-77 | `Step`, `Goto`, `DisplayStep`, `Pause`, `Abort`, `Finish` | Statically resolved steps and control-flow graph, durable checkpoints, scope-safe legacy `Goto` |
| User actions | Language 77-78 | `SetUserAction`, enable, disable, dismiss | Durable named allowlisted actions settled at safe execution points |
| Databases and containers | Language 78-86 | `SCDB`, `GDB`, `PROC`, user dictionaries, `DataContainer`, `Var`, `ARGS`, `IVARS` | Versioned typed stores and catalog mappings, safe URI resolution, immutable schema/config identity, no text evaluation or implicit live resource access |
| Procedure composition | Language 86-89 | Imports and `StartProc` | Immutable dependency resolution, depth/cycle bounds, durable parent-child identity and recovery |
| Files | Language 90-92 | `OpenFile`, `CloseFile`, `ReadFile`, `WriteFile`, `ReadDirectory`, `File`, `DeleteFile` | Virtual input/output roots, traversal/symlink protection, quota, encoding, atomic write, and audit |
| Shared data | Language 95-99 | Shared scopes, get/set, enumeration, clearing, test-and-set | Durable transactional compare-and-set with revisions and namespace authorization |
| Specialized adapters | Language 93-103 | Ranging, memory reports/images/lookups, `TMTCLookup` | Optional typed capabilities after core simulator conformance |

The validated compatibility catalog represents the complete function and
modifier catalogs on Language Reference pages 104-117 and all 195 manual
examples. Their source identity, classification, disposition, errata handling,
and planned test identities pass the exhaustive validator and independent
review. Deferred examples are not executable test data or semantic-conformance
claims.

## Operator Workspace Contract

The GUI manual describes compatibility behavior, not merely visual styling.
Later phases must cover:

- Logical server/context selection, attach/start lifecycle, procedure catalog,
  metadata, arguments, scheduling, refresh, and history (GUI pp. 5, 7-9,
  28-29, 37, 41-42).
- Multiple instances of one procedure with stable independent identities
  (GUI pp. 9-10).
- Source-line identity, current-line and executed-line presentation, compound
  values, nested subprocedure navigation, scoped timestamped messages, and
  distinct as-run/support logs (GUI pp. 11-16, 43-45).
- Procedure states `UNINIT`, `LOADED`, `RUNNING`, `WAITING`, `PROMPT`, `PAUSED`,
  `ERROR`, `ABORTED`, `FINISHED`, `RELOADING`, `INTERRUPTED`, and `UNKNOWN`,
  mapped explicitly to the modern execution state machine (GUI pp. 38-39).
- Run, step, step-over, pause, skip, goto, reload, abort, recover, take/release
  control, monitor, background, stop, and kill dispositions. Unsafe operations
  may be redesigned or rejected, but cannot be silently omitted (GUI pp. 18,
  21-23, 38-40).
- Controller/monitor/background (`C/M/B`) ownership, strictly read-only
  monitoring, durable control leases, controller-loss pause, and authenticated
  reacquisition (GUI pp. 17, 48-50).
- Full prompt validation, commit/reset/abort, warning delay, accessible
  escalation, default precedence, and context-versus-execution settings
  (GUI pp. 19-20, 39-40).
- Relative, absolute, and telemetry-condition scheduling with durable identity,
  canonical time, recovery, and telemetry-quality rules (GUI pp. 41-42).
- Outline, search, breakpoints, run-to-line, variables, `ARGS`/`IVARS`, shared
  data, and a bounded inspection console replacing arbitrary procedure-scope
  shell execution (GUI pp. 14-16, 24-26, 43-47, 51-53).

Driver health states such as `READY` and `FAILED` are infrastructure state and
must never be presented as procedure execution states.

The GUI manual names a Call-stack view but does not define its behavior (GUI
p. 6). It remains an unresolved compatibility row rather than an inferred
parity claim.

## Development Environment Contract

The recovered 57-page Development Environment manual closes the earlier
document-availability gap. It establishes a separate authoring surface with:

- Project explorer, procedure and dictionary editors, outline, TM/TC catalogs,
  Problems view, and a central editor workspace (Development pp. 6, 11-17).
- Projects, source packages/folders, procedure headers and metadata, DB/IMP
  compatibility, and database association (Development pp. 18-23, 29-30).
- Syntax highlighting, folding, rectangular selection, snippets, droplets,
  and template-based TM/TC code generation (Development pp. 23-28, 36-42).
- External-change detection, safe import/export, case-collision handling, and
  VCS-aware moves/deletes (Development pp. 30-35).
- Parser-based offline semantic checks for steps/gotos, functions, arguments,
  headers, modifiers, SPELL arguments, and TM/TC references (Development
  pp. 52-53).
- Procedure/folder/project checks, cancellable progress, reports, library
  reparsing, check-on-save, and stable warning/error markers (Development
  pp. 53-56).
- Checkout/update/commit/revert/add/lock/history/diff/conflict workflow intent,
  implemented with Git or provider-neutral APIs rather than CVS/SVN coupling
  (Development pp. 43-51).

The modern development workspace must use pinned Python 3 language profiles,
must not execute procedure source, and must not require a GCS. Promotion to the
simulator catalog should use immutable validated bundles with digest,
provenance, approval, and rollback rather than editing runtime files directly.

## Build And Deployment Contract

Preserve separate execution and development products, explicit component
profiles, preparation/configuration/build/install/cleanup stages, out-of-tree
builds, cohesive install roots, configuration/data/document packaging,
predictable archives (Build pp. 4-16), and declared Windows/Linux/browser
support (GUI Build pp. 2-3). Replace the
legacy autotools, GCC 4, Python 2, Java 6/8, Eclipse/RCP, Orbit, mutable paths,
and dynamic plug-ins with pinned Python/Node/container inputs, offline builds,
signed artifacts, SBOMs, checksums, install/upgrade/disable/rollback tests, and
version-specific release evidence.

## Safety Strengthening And Rejected Legacy Behavior

The modernization must be behaviorally close without reproducing unsafe
mechanisms:

- Never execute arbitrary Python, arbitrary imports, procedure-scope shell
  commands, or function-evaluated variable edits.
- Never treat unsupported driver behavior as success or merely ignore an
  unsupported modifier.
- Never let `SKIP` erase the original failure/false result from audit.
- Never automatically `RESEND` or repeat an operation after a possible effect.
  Recheck observation separately; resend only after confirmed no-effect and a
  separately authorized operation.
- Never treat transport success, `LoadOnly`, or GCS loading as spacecraft
  execution success.
- Never suppress canonical audit because `Notify=False` or verbosity hides a
  presentation event.
- Never use plaintext passwords, browser-selected arbitrary endpoints, direct
  SCP, dynamic in-process plug-ins, or direct GCS messages from background UI
  code.
- Never use color alone for status or make a casual kill action imply a clean
  external state.
- Never reproduce Python 2, Eclipse, Java, CVS/SVN, PostScript printing, or old
  octal/dictionary syntax as canonical implementation technology.

## Material Ambiguities

The Language Reference contains conflicts including `HandleError` defaulting
to both true and false, `Notify` prose versus appendix defaults,
`PromptFailure`/`OnFailure` behavior, `OnFailure` versus `OnFalse` for
verification, `WaitFor` delay wording, omitted `DATE` appendix values,
`AdjustLimits`/`SetLimits` naming, singular/plural memory-image names, `ARGS`
versus `PROC["ARGS"]`, and an `INPUT_DATA` path typo. The manuals also omit
atomic sampling, coercion and unit conversion, NaN, encoding, leap seconds,
prompt ownership, authentication, authorization, audit, crash recovery,
deduplication, fencing, stream backpressure, and command uncertainty.

These items require explicit errata decisions and tests. They must not be
silently resolved by whichever implementation is easiest.

## Roadmap Consequence

The previous roadmap put legacy observation before simulator language and
service conformance. The proposed rebaseline reverses that order:

1. Build the typed simulator driver, context-binding, lifecycle, and exhaustive
   compatibility-baseline foundation.
2. Implement documented language/runtime and operator behavior in bounded
   simulator-only tranches.
3. Implement documented telemetry, conditions, data, authoring, auxiliary
   services, and telecommands against deterministic simulators first.
4. Introduce isolated read-only legacy observation only after equivalent typed
   simulator schemas and golden tests exist.
5. Add non-operational control or adapter effects only through separate
   capability-specific gates; keep operational authorization independent.

The detailed candidate versions are maintained in
[`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md). No phase may claim full SPELL
compatibility until the exhaustive ledger, approved errata, documented state
and command matrices, simulator conformance, golden traces, and migration
guidance cover the claimed surface.

## v0.4 Readiness Assessment

The lifecycle-only v0.4 boundary is the project-owner-approved next product
gate. The revised plan incorporates requirements and tests for:

1. Host, context-binding, execution-attachment, capability, and operation
   lifecycle separation.
2. Stable host/context/execution-attachment/binding/operation identities and
   generations.
3. Typed configuration layers, precedence, separate immutable digests, secret
   references, and named host/per-context capacity.
4. Granular service/method/modifier/mutability/streaming capability descriptors.
5. The exhaustive documentation compatibility ledger and errata process.
6. Separate infrastructure-state and procedure-state vocabularies.
7. Install, disable, upgrade, rollback, and supported-platform verification for
   the separately packaged simulator driver.

JC Arcaz's project-owner approval is recorded, and the populated row-by-row
compatibility ledger, errata dispositions, deterministic validation, independent
review, exact owner-record manifest binding, and pinned Python 3.13
qualification pass. Gate 0 authorizes bounded v0.4 product engineering; it is
not an implementation, release, operational, or compliance claim.

These corrections do not authorize or add telemetry, telecommands, a legacy
adapter, arbitrary Python, persistent authoring, GCS connectivity, spacecraft
connectivity, or operational use in v0.4.
