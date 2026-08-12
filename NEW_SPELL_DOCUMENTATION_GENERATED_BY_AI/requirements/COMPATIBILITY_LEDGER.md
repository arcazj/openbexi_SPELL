# Compatibility Ledger

## Purpose And Gate

This ledger controls how documented SPELL behavior enters the modern product.
The two core manuals remain unchanged authorities; this file records the target
disposition without rewriting their text.

The tables below are the complete **capability-family index** derived from the
304-page review. The candidate machine-readable catalog represents all seven
authoritative sources and assigns each detailed artifact either to the exact
Candidate A v0.4 driver/context slice or to Deferred/`EXCLUDE`. Before a family
enters implementation, its row requires executable semantic fixtures and
results. Deferred rows instead require exact static source identity, explicit
negative scope, errata handling, and a unique planned test identity. Counts
shall reconcile to the source catalogs. This is a mandatory `COMP-001` gate,
not deferred cleanup.

## Dispositions

| Code | Disposition | Meaning |
| --- | --- | --- |
| `EXACT` | Exact observable compatibility | Name, accepted input, result, ordering, and visible behavior are preserved. |
| `SAFE` | Equivalent with safety strengthening | Intent is preserved while typing, identity, authorization, isolation, persistence, or recovery is strengthened. |
| `TRANS` | Legacy syntax translated | Legacy source is accepted by a compatibility parser and lowered to bounded IR. |
| `ADAPT` | Optional adapter capability | Behavior exists only when a negotiated driver/UI/environment capability supports it. |
| `UNSUP` | Deliberately unsupported | Unsafe or non-deterministic behavior is rejected with stable diagnostic and migration guidance. |
| `AMBIG` | Documentation ambiguity | The row remains Deferred/`EXCLUDE`; no behavior is implemented until a future technical decision and executable oracle resolve the ambiguity. |
| `EXCLUDE` | Outside Candidate A | The source artifact is deliberately not advertised or implemented by v0.4 and is retained as negative-scope evidence. |

Canonical rows use `DispositionApproved` to mean only that their Candidate A or
Deferred/`EXCLUDE` scope assignment follows the project-owner-approved policy.
It does not claim row-by-row owner source review, implementation, executed
semantic conformance, operational authorization, or compliance determination.

## Required Detailed Row Schema

Each detailed row shall contain:

`ArtifactId`, `Kind`, `PublicName`, `SourceTitle`, `SourceVersion`, `SourceHash`,
`Pages`, `SignatureOrGrammar`, `LegacyInputs`, `LegacyResult`, `LegacyOrdering`,
`LegacyErrors`, `EffectClass`, `ModernBehavior`, `Disposition`, `Diagnostic`,
`DriverCapability`, `Persistence`, `Recovery`, `SecurityConstraints`,
`TargetIncrement`, `TestVectors`, `Decision`, `Approvers`, and `Status`.

## Detailed Registry Status

The canonical detailed data is JSON rather than a 25-column Markdown table:

| Artifact | Current bounded result |
| --- | --- |
| [`compatibility/COMPATIBILITY_SOURCE_INVENTORY.json`](compatibility/COMPATIBILITY_SOURCE_INVENTORY.json) | Seven authoritative source records, all 304 reviewed pages, all 195 exact Language Reference example identities, and the exhaustive candidate artifact membership |
| [`compatibility/COMPATIBILITY_LEDGER.json`](compatibility/COMPATIBILITY_LEDGER.json) | Exhaustive unique rows with all 25 required fields and exact Candidate A or Deferred/`EXCLUDE` disposition |
| [`compatibility/scopes/v0.4.json`](compatibility/scopes/v0.4.json) | Exact seven-source membership and v0.4/deferred counts; no row makes an implementation claim |
| [`compatibility/COMPATIBILITY_RECONCILIATION.json`](compatibility/COMPATIBILITY_RECONCILIATION.json) | Digest-bound equality of inventory, ledger, and scope |
| [`../quality/V04_COMPATIBILITY_TECHNICAL_REVIEW.json`](../quality/V04_COMPATIBILITY_TECHNICAL_REVIEW.json) | Per-source independent technical review result and canonical subset digest; no human-approval or runtime-conformance claim |

The candidate catalog includes language constructs and examples, driver and
server contracts/configuration, GUI and development workflows/views, build and
installation concepts, source errata, and explicit evidence limitations.
All rows have source pages, classifications, target increments, dispositions,
and planned test identities. Deferred rows have no fixture or executed result
because they are not implemented. `COMP-001` and `V04-GATE-0` remain blocked
until deterministic validation, independent technical source review, and exact
owner-record manifest binding pass.

## Language Capability Index

Source authority: Language Reference 2.4.4, SHA-256
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`.

| Family ID | Pages | Surface | Proposed disposition | Modern contract | Detailed gate |
| --- | ---: | --- | --- | --- | --- |
| LNG-001 | 14-26 | Python-shaped syntax, indentation, literals, expressions, collections, branches, loops, functions, imports | `TRANS`, `UNSUP` | Approved Python 3-shaped subset becomes bounded data-only IR; arbitrary import/evaluation is rejected. | Grammar, operator, scope, type, bound, and diagnostic vectors |
| LNG-002 | 26-31, 108-117 | Common configuration, modifiers, results, `OnFailure`, `OnTrue`, `OnFalse`, prompt/error actions | `SAFE`, `AMBIG` | Defaults are pinned per bundle/execution; valid false, operation failure, override, and control outcome are distinct. | Every modifier/default/action and precedence combination |
| LNG-003 | 32-35 | `TIME`, `NOW`, calendar/time constants and arithmetic | `SAFE` | Typed UTC instant/duration with declared clock and uncertainty; persistent timers. | Clock, zone, precision, rollover, restart, and formatting vectors |
| LNG-004 | 36-38 | `GetTM`, current/next sample, raw/engineering and extended values | `SAFE`, `ADAPT` | Typed sample with source, acquisition/receive time, sequence, units, quality, validity, freshness, and cursor. | Every argument/modifier/result type and capability failure |
| LNG-005 | 39-47 | `Verify`, comparison operators, `AND`, `OR`, tolerance, delay, timeout, retries | `SAFE`, `AMBIG` | Deterministic condition plan and declared atomic sampling policy. | Truth tables, sample timing, tolerance boundaries, failure actions |
| LNG-006 | 47-55 | `BuildTC`, `Send`, arguments, sequences, groups, blocks, tags, load, confirm, verify | `SAFE`, `ADAPT` | Separate construction, authorization, dispatch, stages, certainty, confirmation, and reconciliation. | Per modifier plus partial, timeout, duplicate, uncertain-effect vectors |
| LNG-007 | 55-59 | `WaitFor` relative, absolute, and telemetry conditions | `SAFE` | Durable target/cursor with interrupt and recovery preserving the original result. | Clock/condition races, timeout, cancel, restart, gap vectors |
| LNG-008 | 59-68 | Limit and alarm query/mutation functions | `SAFE`, `ADAPT` | Reads and mutations are separate capabilities; mutations require effect authorization and audit. | Every state, threshold, persistence, rollback, and unsupported case |
| LNG-009 | 68-69 | `Display`, `Notify`, `Event` | `SAFE`, `ADAPT` | Display/notify are durable presentation intents; external event writes are separately authorized driver effects. | Suppression, reconnect, formatting, event acknowledgment and failure |
| LNG-010 | 69 | Resource get/set | `SAFE`, `ADAPT` | Typed catalog-backed reads and separately authorized writes with revisions. | Type, namespace, conflict, authorization, driver failure |
| LNG-011 | 70-72 | Prompt types and list/input modes | `SAFE` | Durable, typed, validated, single-settlement prompt across timeout/restart/disconnect. | Each type/option/default plus response/timeout/cancel races |
| LNG-012 | 72-74 | Display/workspace open, close, and print intents | `ADAPT`, `UNSUP` | Optional logical web presentation adapter; remote workstation/printer control is not a core side effect. | Capability negotiation and migration diagnostics |
| LNG-013 | 75-77 | Step labels, goto, display step, pause, abort, finish | `SAFE`, `TRANS` | Statically resolved control-flow graph and durable safe-point transitions. | Scope, nested calls, invalid target, recovery, controller race |
| LNG-014 | 77-78 | Named user actions and enable/disable/dismiss | `SAFE` | Allowlisted durable actions settle at safe points under current controller authorization. | Naming, visibility, races, expiry, recovery, permissions |
| LNG-015 | 78-86 | `SCDB`, `GDB`, `PROC`, dictionaries, `DataContainer`, `Var`, `ARGS`, `IVARS` | `SAFE`, `ADAPT` | Typed versioned stores and catalog mappings; no text evaluation or implicit live resource access. | URI/schema, type, revision, missing/stale, mutation and recovery |
| LNG-016 | 86-89 | Procedure imports and `StartProc` | `SAFE`, `TRANS` | Immutable dependency closure, bounded graph, stable parent-child state. | Resolution, cycles, depth, arguments, cancellation, restart |
| LNG-017 | 90-92 | File and directory operations | `SAFE` | Virtual roots, path/symlink controls, encoding, quota, atomic writes, audit. | Traversal, quota, partial write, encoding, restart, deletion |
| LNG-018 | 93-103 | Shared data, memory, ranging, lookup, and specialized services | `SAFE`, `ADAPT`, `AMBIG` | Typed capability-specific APIs, transactional shared data, simulator-first qualification. | One detailed row per function and documented ambiguity |
| LNG-019 | 104-117 | Function, modifier, constant, type, result, and action catalogs | Per detailed row | Catalog pages are the count reconciliation oracle. | Reconciled inventory and one conformance suite per implemented row |
| LNG-020 | Entire manual | Documented examples | `EXACT`, `TRANS`, `UNSUP`, or `AMBIG` per example | Every example is preserved as a named conformance/diagnostic vector with errata separated from original text. | Source page/example identity, expected parse/behavior/diagnostic |

## Driver Capability Index

Source authority: Driver Development Manual 2.4.4, SHA-256
`057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5`.

| Family ID | Pages | Surface | Proposed disposition | Modern contract | Detailed gate |
| --- | ---: | --- | --- | --- | --- |
| DRV-001 | 9-10, 24-25, 37-40 | Host, context, execution attachment, operation, configuration and cleanup lifecycle | `SAFE` | Independent versioned lifecycles with stable generations, deadlines, typed cleanup and capacity. | Every hook, ordering, partial failure, concurrency and restart path |
| DRV-002 | 11-13, 17-24 | `TM` acquisition, injection, validity, limits, alarms and monitoring | `SAFE`, `ADAPT` | Typed loss-detectable samples/streams, explicit quality and separately gated mutations. | Method/modifier schemas, stream gaps, backpressure, restart |
| DRV-003 | 13-16, 26-30 | `TC` construction, send, sequence/group/block, load/tag/confirm/verify | `SAFE`, `ADAPT` | Durable operation stages, external correlation, effect certainty and reconciliation. | Every stage, partial result, duplicate, cancel, timeout, reconnect |
| DRV-004 | 31-32 | Event read/write services | `SAFE`, `ADAPT` | Typed reads and separately authorized writes; durable correlation and acknowledgment. | Schema, direction, authorization, delivery and failure vectors |
| DRV-005 | 33-35 | Resource services | `SAFE`, `ADAPT` | Namespaced typed resources, revision-aware writes, explicit unsupported behavior. | Type, conflict, permission, persistence and adapter errors |
| DRV-006 | Manual service model | Time service | `SAFE` | Approved clock identity, UTC representation, uncertainty and health. | Drift, loss, failover, formatting and deadline vectors |
| DRV-007 | 24-25, 37-38 | Configuration interface (`CIF`) | `SAFE` | Versioned configuration references and supervisor-owned prompt/audit behavior. | Precedence, secret reference, apply/cleanup, rollback, invalid config |
| DRV-008 | Manual service model | Context (`CTX`) and executor (`EXEC`) services | `SAFE` | Infrastructure capabilities remain mandatory but are typed, authenticated and fenced. | Lifecycle, identity, concurrency, stale generation and cleanup |
| DRV-009 | Manual service model | Memory (`MEM`) | `SAFE`, `ADAPT` | Optional typed memory report/image/lookup capability with bounds and provenance. | Size, format, partial data, authorization, integrity and timeout |
| DRV-010 | 9-10 and incomplete references | Task, ranging, PCS, database and subscription-related behavior | `ADAPT`, `AMBIG` | No implicit support; each service needs an approved contract and source oracle. | Additional evidence or explicit new design decision |
| DRV-011 | Entire manual | In-process Python inheritance, generic payloads and UI callback mechanisms | `UNSUP`, `SAFE` | Functional intent is retained through isolated typed RPC; legacy mechanics are rejected. | Adapter SDK migration guide and conformance harness |

## Operator And Development Workflow Index

| Family ID | Primary source | Legacy intent | Target disposition | Modern target |
| --- | --- | --- | --- | --- |
| UX-001 | GUI 2.4.4 pp. 7-15 | Server/context connection and status | `SAFE` | Authenticated domain selection; no arbitrary browser-selected production endpoint. |
| UX-002 | GUI 2.4.4 pp. 15-18 | Procedure catalog and properties | `SAFE` | Permission-aware hierarchical catalog backed by promoted Git bundles. |
| UX-003 | GUI 2.4.4 pp. 18-38 | Load/run/pause/step/skip/goto/interrupt/abort/reload/recover | `SAFE` | Formal server state matrix, durable controls, revision/fence checks. |
| UX-004 | GUI 2.4.4 pp. 19-20, 39-40 | Prompts and operator input | `SAFE` | Durable single-settlement prompts with controller ownership and monitoring visibility. |
| UX-005 | GUI 2.4.4 | Control/monitor/background modes and handover | `SAFE` | Role-authorized Execution, Monitoring, and Edit startup; one controller lease per domain; named requester, current-holder approval, requester responsibility acknowledgement, atomic higher-fence transfer, and automatic post-transfer mode projection. |
| UX-006 | GUI 2.4.4 | Source, variables, logs, notifications and as-run | `SAFE` | Real-time projections plus exact source identity and canonical as-run evidence. |
| UX-007 | GUI 2.4.4 | Execute script, force kill, direct endpoints and shell-like actions | `UNSUP`, `SAFE` | Replace with allowlisted controls, bounded IR, supervised termination and managed endpoints. |
| DEV-001 | Development Environment 2.4.4 | Projects and hierarchical procedure organization | `SAFE` | Git repository, manifest-defined folders/categories and web catalog. |
| DEV-002 | Development Environment 2.4.4 | Source editor, outlines, dictionaries and problems | `SAFE` | Non-executing web language services with exact diagnostics and dependency analysis. |
| DEV-003 | Development Environment 2.4.4 | CVS/SVN collaboration and history | `SAFE` | Protected Git branches, code review, signatures, promotion and rollback. |
| DEV-004 | Development Environment 2.4.4 | Launch/debug against environments | `SAFE` | Simulator-only validation first; environment/capability authorization is separate. |
| BLD-001 | Build manuals | Autotools, GCC/Python 2, Eclipse/Java packaging | `UNSUP`, `SAFE` | Reproducible signed Python/web/container build with locked dependencies and SBOM. |
| SRV-LEG-001 | Server Manual 2.4.4 | Listener, context, executor, per-context driver and configuration | `SAFE` | Authenticated control plane, Satellite Control Domain, isolated workers, typed driver gateway. |

## Deviation Approval Record

No detailed deviation is approved in `0.1.0-draft.1`. A deviation record shall
include the affected IDs, rationale, operator and procedure impact, security and
hazard analysis, replacement behavior, stable diagnostic, migration, tests,
rollback, approvers, acceptance date, expiry/review date, and exact baseline tag.
