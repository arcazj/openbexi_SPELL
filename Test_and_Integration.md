# Test and Integration Plan

## Document Control

| Field | Value |
| --- | --- |
| Project | OpenBEXI SPELL |
| Current accepted product release | SPELL v0.4.0, tag `v0.4.0`, release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Planning target | SPELL v0.5.0 Gate 0A - existing IR 0.3 fail-closed validation hardening |
| Status | v0.4 accepted; `V05-GATE-0A PASS`; only `V05-IR-001` implementation authorized and not yet claimed |
| Date | Updated 2026-08-12 |
| Applies to | v0.1 documentation baseline and every product version from v0.2 onward |
| Operational authorization | None |

## Version 0.5 Gate 0A Test Plan

### Gate Status And Scope

This section is the acceptance contract for the single work package authorized
by [`SPELL_v0.5_Pre-Implementation.md`](SPELL_v0.5_Pre-Implementation.md).
`V05-GATE-0A PASS` authorizes implementation of `V05-IR-001` only. Every
product-test result below is `Planned`; the gate does not claim the code or its
evidence exists.

The increment adds strict independent validation and canonicalization of the
existing `spell-restricted-ast/0.3` payload at parser, persisted supervisor,
and worker boundaries. Invalid IR must be rejected and audited before process
creation when detected by the supervisor, and always before `worker.started`
or any procedure effect. Valid accepted IR 0.3 behavior and persisted bytes
remain unchanged.

No new syntax, construct, IR version, API, schema, migration, frontend,
dependency, package, driver, source-to-IR reparse/integrity feature, or
operational behavior is in scope.

### Requirements And Traceability

| Requirement ID | Requirement | Severity | Primary tests |
| --- | --- | --- | --- |
| `V05-REQ-IR-001` | One independent validator/canonicalizer accepts only the exact existing IR 0.3 structural and semantic contract with deterministic bounded diagnostics | Critical | `V05-IR-001-UNIT`, `V05-IR-001-ADVERSARIAL` |
| `V05-REQ-IR-002` | Newly compiled parser output is postvalidated before an accepted `Procedure` is returned | Critical | `V05-IR-001-PARSER` |
| `V05-REQ-IR-003` | Stored version, steps, start position, prompt resume, and checkpoint variables are validated before worker generation changes or process creation | Critical | `V05-IR-001-SUPERVISOR`, `V05-IR-001-ADVERSARIAL` |
| `V05-REQ-IR-004` | The worker independently validates explicit IR version and the complete payload before `worker.started`, state acknowledgement, prompt, checkpoint, or effect | Critical | `V05-IR-001-WORKER`, `V05-IR-001-ADVERSARIAL` |
| `V05-REQ-IR-005` | Valid accepted v0.3/v0.4 IR behavior and stored IR bytes remain unchanged without migration or public-contract expansion | Critical | `V05-IR-001-COMPAT` |

### Planned Environments

| Code | Environment | Purpose |
| --- | --- | --- |
| `DEV` | Pinned Python 3.13 local test environment | Validator, parser, worker, and mutation corpus |
| `SQLITE` | Fresh and populated accepted-baseline SQLite stores | Stored-row and recovery preflight without migration |
| `PG` | Fresh and populated accepted-baseline PostgreSQL stores | Dialect-independent stored-row and recovery preflight |
| `FLT` | Deterministic tamper/fault fixtures | Boundary ordering, invalid payloads, and negative audit paths |

### Planned Acceptance Tests

| Test ID | Expected result | Environment | Final result |
| --- | --- | --- | --- |
| `V05-IR-001-UNIT` | The validator accepts the complete canonical IR 0.3 golden corpus and rejects unknown/missing/extra fields, exact-type violations including Boolean-as-integer, non-finite or oversized values, invalid indexes, malformed expressions, bad variable flow/types, invalid prompts, start positions, and checkpoint state with bounded deterministic diagnostics | `DEV` | Planned |
| `V05-IR-001-PARSER` | Every compiler result is postvalidated; accepted golden IR, source identity, step ordering, and IR version are unchanged, while injected invalid compiler output cannot produce an accepted `Procedure` | `DEV` | Planned |
| `V05-IR-001-SUPERVISOR` | Initial start and recovery reject tampered stored IR/version/start/prompt/checkpoint state with bounded durable failure/audit evidence before worker-generation increment or process creation | `DEV`, `SQLITE`, `PG`, `FLT` | Planned |
| `V05-IR-001-WORKER` | Directly supplied invalid version, IR, start position, or checkpoint state is rejected by worker preflight before `worker.started`, running-state acknowledgement, prompt, checkpoint, or effect | `DEV`, `FLT` | Planned |
| `V05-IR-001-COMPAT` | Accepted v0.3/v0.4 parser, execution, recovery, audit, SQLite, and PostgreSQL golden cases remain behaviorally identical; stored valid IR bytes are not rewritten and no schema/API/dependency/driver/frontend delta exists | `DEV`, `SQLITE`, `PG` | Planned |
| `V05-IR-001-ADVERSARIAL` | Cross-boundary mutation covers unsupported versions, field/type/size/depth/index/operator/name/flow/prompt/checkpoint faults, persisted-row substitution between create/start/recovery, and malformed audit inputs; every case fails closed without process/effect leakage or unsafe echo | `DEV`, `SQLITE`, `PG`, `FLT` | Planned |

### Non-Waivable Ordering And Compatibility

- Supervisor validation precedes any worker-generation mutation and process
  creation.
- Worker validation precedes `worker.started`, state acknowledgement, prompt,
  checkpoint, and effect output.
- A failed validation cannot be silently normalized, retried with different
  bytes, or converted to an accepted execution.
- Existing valid persisted IR 0.3 rows are not rewritten or migrated.
- The implementation may not claim a new language construct or artifact to
  satisfy this gate.

### Gate 0A Disposition

The machine scope and validator are:

- [`v0.5-gate-0a.json`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.5-gate-0a.json)
- [`validate_v05_gate_0a.py`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v05_gate_0a.py)
- [`test_validate_v05_gate_0a.py`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v05_gate_0a.py)

The gate binds the annotated `v0.4.0` tag object and raw hash, peeled release
commit, tagged baseline file hashes, required acceptance/non-claim markers,
the one authorized work package, and all six planned test IDs. Its required
success marker is
`gate=PASS work_packages=1 claimed_constructs=0 claimed_artifacts=0`.

`V05-GATE-0A PASS` is implementation authorization for `V05-IR-001`, not an
executed product-test result or v0.5 acceptance. Any broader v0.5 work requires
a later gate. No Critical failure in validation ordering, persisted-byte
compatibility, deterministic rejection, audit safety, or no-effect behavior is
waivable.

## Version 0.4 Pre-Implementation Test Plan

### Gate Status And Scope

This section preserves the owner-approved acceptance contract for the
local-only, synthetic non-CUI Candidate A scope in
[`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md). Every
`Planned` result below records the pre-implementation state. v0.4 subsequently
passed its complete Final qualification and was accepted at tag `v0.4.0`; the
executed release disposition is recorded in
[`SPELL_v0.4_Release.md`](SPELL_v0.4_Release.md).

The planned product slice is one typed, mutually authenticated, out-of-process
deterministic simulator driver supporting host/context/execution lifecycle,
configuration, capability, capacity, and operation reconciliation only.
Existing procedure and simulated `Telemetry` behavior remains on the v0.3
path. No live/legacy GCS, spacecraft, mission network, arbitrary endpoint,
telemetry data plane, telecommand service, or externally effective capability
is allowed.

### Requirements And Traceability

| Requirement ID | Requirement | Severity | Primary tests |
| --- | --- | --- | --- |
| `V04-REQ-GOV-001` | The approved scope, threat model, network matrix, certainty model, budgets, exclusions, rollback, and test mapping precede product edits | Critical | `V04-DOC-001` |
| `V04-REQ-DOC-001` | All seven supplied PDFs and 304 pages are inventoried and reviewed; before gate approval, a populated exhaustive cross-manual artifact ledger, reconciled source counts, and approved errata replace unsupported inference | High | `V04-DOC-002`, `V04-DOC-003` |
| `V04-REQ-BOUND-001` | Normal and test configuration can resolve only the bundled deterministic simulator; arbitrary, legacy, GCS, spacecraft, mission, and externally effective modes are rejected | Critical | `V04-BOUND-001`, `V04-BOUND-002` |
| `V04-REQ-SCOPE-001` | The v0.4 descriptor and handshake expose exactly nine infrastructure lifecycle RPCs and no future service; procedure source/IR cannot enter the driver and accepted v0.3 `Telemetry` produces zero execution-correlated driver call/binding/journal delta | Critical | `V04-SCOPE-001`, `V04-SCOPE-002` |
| `V04-REQ-CON-001` | Protobuf/gRPC messages are typed, versioned, bounded, deterministically generated, and use structured errors without untyped escape hatches | Critical | `V04-CON-001`, `V04-CON-002`, `V04-CON-003` |
| `V04-REQ-CON-002` | Handshake identifies contract, implementation, logical host, simulator marker, driver-host generation/profile digest, explicit capabilities, and named capacity; mismatch fails closed | Critical | `V04-CON-004`, `V04-CON-005` |
| `V04-REQ-CTX-001` | Stable server-profile, driver-host-generation, context-generation, execution, execution-attachment-generation, driver-binding, and operation identities separate host, context, attachment, and operation lifecycles | Critical | `V04-CTX-001`, `V04-CTX-002` |
| `V04-REQ-CFG-001` | Typed versioned host-profile, context-binding, and allowlisted execution-attachment configuration has approved precedence, separate immutable non-secret digests/generations, credential epochs, and out-of-band secret references; operation/journal evidence binds the full applicable tuple | Critical | `V04-CFG-001`, `V04-CFG-002`, `V04-CFG-003`, `V04-CFG-004` |
| `V04-REQ-CAP-001` | Capability negotiation is granular by service, method, modifier/format, mutability, stream support, and capacity; absent behavior is explicitly unsupported | Critical | `V04-CAP-001`, `V04-CAP-002` |
| `V04-REQ-ARCH-001` | The driver runs as a separate non-root, read-only host whose failure cannot terminate the API, worker, or database | Critical | `V04-ISO-001`, `V04-ISO-003` |
| `V04-REQ-ARCH-002` | The browser has no driver route; procedure workers have no driver product call path or usable service credential and cannot authenticate even when a shared local development-network route exists | Critical | `V04-ISO-002`, `V04-ISO-004` |
| `V04-REQ-SEC-001` | Gateway and driver use mutually authenticated encrypted service identities with no insecure fallback | Critical | `V04-SEC-001`, `V04-SEC-002` |
| `V04-REQ-SEC-002` | Driver private keys and service credentials never reach workers, clients, API payloads, logs, events, reports, images, SBOMs, or packages | Critical | `V04-SEC-003`, `V04-SEC-004` |
| `V04-REQ-LIFE-001` | Handshake, health, context open/active/degraded/close, execution attach/detach, host drain/close, failed, and unsupported behavior is explicit and deterministic | High | `V04-LIFE-001`, `V04-LIFE-002`, `V04-LIFE-003` |
| `V04-REQ-LIFE-002` | Lifecycle mutations require explicit deadlines, cooperative cancellation, and bounded forced termination | Critical | `V04-DEAD-001`, `V04-DEAD-002`, `V04-DEAD-003`, `V04-DEAD-004` |
| `V04-REQ-LIFE-003` | A per-RPC hook matrix makes configuration setup first and cleanup last; execution attach/detach covers load/reload and finish/abort with compensation, cleanup is best effort with typed audited outcomes, and infrastructure state remains distinct from procedure state | Critical | `V04-LIFE-004`, `V04-CTX-002` |
| `V04-REQ-OP-001` | One stable operation ID and request digest persist before dispatch; every retry retains that identity | Critical | `V04-OP-001`, `V04-OP-002` |
| `V04-REQ-OP-002` | A private bounded driver journal lets the host deduplicate an `OperationId`/`AttemptId` pair across transport retry/restart and reject a conflicting request digest without accessing the project database | Critical | `V04-OP-003` |
| `V04-REQ-JRN-001` | The driver journal persists identity before effect and result before reply, never reuses/unsafely evicts an ID, and fails closed without resend on full, missing, truncated, corrupt, or failed storage | Critical | `V04-JRN-001`, `V04-JRN-002`, `V04-JRN-003` |
| `V04-REQ-OP-003` | Operation-attempt history is append-only; progress is ordered by `(AttemptNumber, per-attempt stage)`; certainty refinements retain prior evidence; and one durable terminal disposition settles the operation | Critical | `V04-OP-004`, `V04-OP-005` |
| `V04-REQ-SAFE-001` | `EFFECT_POSSIBLE` and `EFFECT_UNKNOWN` operations remain reconciliation-required and can never trigger automatic resend or an invented success/failure | Critical | `V04-OP-006`, `V04-REC-004` |
| `V04-REQ-DATA-001` | Within the canonical project database, driver identity, operation, stage, certainty, audit, and outbox changes commit atomically before projection | Critical | `V04-REC-001`, `V04-REC-002` |
| `V04-REQ-REC-001` | API/driver crash, timeout, partition, cancellation, stale response, database failure, and restart reconcile by operation ID without duplicate simulator effect | Critical | `V04-REC-003`, `V04-REC-004`, `V04-REC-005`, `V04-REC-006`, `V04-REC-007` |
| `V04-REQ-MIG-001` | Static ordered migrations support fresh and populated-v0.3 SQLite/PostgreSQL stores, repeat safely, and roll back cleanly | Critical | `V04-MIG-001`, `V04-MIG-002`, `V04-MIG-003`, `V04-MIG-004` |
| `V04-REQ-API-001` | REST is authoritative, WebSocket downstream-only, driver/context/binding/operation additions are authenticated/read-only/versioned, and endpoint or secret data is not exposed | High | `V04-API-001`, `V04-API-002`, `V04-API-003` |
| `V04-REQ-UI-001` | The 2D UI clearly exposes simulator identity, context/binding, capacity, infrastructure health, capability, stage, certainty, staleness, and disconnected/degraded state without a driver mutation control | High | `V04-UI-001`, `V04-UI-002`, `V04-UI-003`, `V04-UI-004` |
| `V04-REQ-PERF-001` | The approved local lifecycle latency, cancellation, restart, concurrency, memory, and soak budgets pass without duplicate or stuck operations | High | `V04-PERF-001`, `V04-PERF-002`, `V04-PERF-003`, `V04-PERF-004` |
| `V04-REQ-SC-001` | New schemas, dependencies, generated code, images, evidence, and packages are locked, audited, inventoried, secret-free, version-isolated, and reproducible | High | `V04-SC-001`, `V04-SC-002`, `V04-SC-003`, `V04-SC-004`, `V04-SC-005` |
| `V04-REQ-SC-002` | The separate driver package has declared platform support and verified install, disabled-default, upgrade, rollback, and uninstall behavior | High | `V04-SC-006` |
| `V04-REQ-REG-001` | Complete accepted-v0.3 backend, PostgreSQL, browser, security, recovery, qualification, and package behavior remains compatible | Critical | `V04-REG-001` |

### Planned Environments

| Code | Environment |
| --- | --- |
| `DOC` | Static documentation, schema, source, and traceability review |
| `DEV` | Network-disabled backend tests with SQLite and deterministic simulator fixtures |
| `PG` | Target PostgreSQL version with fresh and populated-v0.3 databases |
| `CMP` | Production-shape Compose topology with proxy, backend, worker boundary, database, and driver host |
| `BR` | Desktop and mobile Chromium against the real loopback backend |
| `FLT` | Deterministic process, RPC, network, database, clock, cancellation, and late-message fault injection |
| `PKG` | Offline dependency, code-generation, SBOM, qualification, package, and reproducibility environment |

No v0.4 environment may contain a GCS, spacecraft, mission endpoint,
operational credential, arbitrary driver address, or externally effective
command target.

### Planned Acceptance Tests

| Test ID | Acceptance test | Environment | Result |
| --- | --- | --- | --- |
| `V04-DOC-001` | Gate review proves scope, exclusions, threat model, network matrix, certainty table, budgets, rollback, ownership, and requirement/test traceability are explicitly owner-approved before product edits | `DOC` | Planned |
| `V04-DOC-002` | Inventory verifies seven PDFs, 304/304 reviewed pages, exact file hashes, mixed 2.4.4/4.0.2 evidence versions, version limitations, and external-evidence packaging restrictions recorded in `SPELL_DOCUMENTATION_REVIEW.md` | `DOC` | Planned |
| `V04-DOC-003` | A populated ledger has one uniquely counted row for every language construct/syntax/operator, function, modifier, constant, type, outcome/action, state/control, server/configuration field, driver service/method/result/status, operator/development workflow/view, build/install/deployment concept, and all 195 examples; manual/version/hash/page provenance, effect class, safe behavior, disposition, phase, test, and errata status are present and per-manual inventories reconcile with no omission | `DOC` | Planned |
| `V04-BOUND-001` | Static and runtime configuration accepts only the bundled simulator identity and rejects arbitrary URLs, IPs, DNS names, legacy/GCS/spacecraft modes, and operational identifiers | `DEV`, `CMP` | Planned |
| `V04-BOUND-002` | Packet capture and connection logs show zero traffic to public, host, GCS, spacecraft, mission, or unapproved networks through nominal and fault runs | `CMP`, `FLT` | Planned |
| `V04-SCOPE-001` | Descriptor and handshake golden evidence exposes exactly `Handshake`, `Health`, `OpenContext`, `CloseContext`, `AttachExecution`, `DetachExecution`, `CancelLifecycleOperation`, `DrainHost`, and `GetOperation`; TM, TC, event, resource, task, time, ranging, memory, PCS, database, subscription, and procedure-service RPCs/capabilities are absent, and unknown RPCs fail bounded/audited before dispatch | `DEV`, `CMP`, `PKG` | Planned |
| `V04-SCOPE-002` | With the v0.4 host active and background health/lifecycle traffic baselined, proto/schema/static analysis proves no procedure source, AST, IR, variable, prompt, TM, or TC payload can enter the driver; an accepted-v0.3 simulated `Telemetry` execution creates zero execution-correlated driver RPC, context, binding, operation, or journal delta and does not alter the unrelated baseline | `DEV`, `PG`, `CMP` | Planned |
| `V04-CON-001` | Golden descriptor, field numbers, enum values, generated-source hashes, and two offline generations are byte-for-byte deterministic | `DEV`, `PKG` | Planned |
| `V04-CON-002` | Major/minor compatibility matrix proves approved additive behavior and rejection of incompatible versions, reused fields, changed semantics, unknown enums, and untyped payloads | `DEV` | Planned |
| `V04-CON-003` | Malformed, truncated, oversized, deeply nested, duplicate-conflicting, and unsafe-error payloads fail closed within bounded memory and do not echo input or secrets | `DEV`, `FLT` | Planned |
| `V04-CON-004` | Handshake binds schema, implementation, logical identity, simulator marker, driver-host generation/profile digest, exact infrastructure-only capabilities, and named capacity | `DEV`, `CMP` | Planned |
| `V04-CON-005` | Contract, host identity/generation/profile, context/attachment digest, or lifecycle-capability mismatch rejects at its applicable boundary; a known unsupported lifecycle option returns typed `UNSUPPORTED` and no absent future service can dispatch | `DEV`, `FLT` | Planned |
| `V04-CTX-001` | Contract and persistence require stable server-profile, driver-host-generation, context-generation, execution, execution-attachment-generation, driver-binding, request-operation, and target-operation IDs; missing, stale, cross-context, or conflicting identity fails closed and is audited | `DEV`, `PG`, `FLT` | Planned |
| `V04-CTX-002` | Host, context, execution-attachment, operation, and documented procedure state machines are distinct; initial load attaches once, reload durably detaches/cleans the prior generation then sets up a new generation, finish/abort detaches once, and stale generations cannot cross-bind | `DEV`, `PG`, `FLT` | Planned |
| `V04-CFG-001` | Contract/server/driver precedence resolves a deterministic host-profile digest; host plus context resolves a separate context-binding digest; context plus allowlisted execution inputs resolves a separate attachment digest; each is schema-versioned and stable across restart/offline rebuild | `DEV`, `CMP`, `PKG` | Planned |
| `V04-CFG-002` | Unknown host fields and hidden overrides reject before host readiness; invalid context data rejects `OpenContext`; invalid execution data rejects `AttachExecution`; changed/stale parent digest, inline secret, or unsafe path/endpoint fails at its own boundary without echoing sensitive data | `DEV`, `CMP`, `FLT` | Planned |
| `V04-CFG-003` | Transition matrix proves unchanged host restart gives new host generation/same digest; changed host profile gives new generation/digest after drain/fence; context reopen and execution reload always give new child generations/bindings while same inputs retain and changed inputs replace their layer digest | `DEV`, `PG`, `CMP`, `FLT` | Planned |
| `V04-CFG-004` | Secret-value rotation under one reference retains configuration digests, increments audited credential epoch, and rejects the old value; secret-reference change transitions the owning layer; canonical request digest, operation row, and journal bind identical explicit host/context/attachment generation, binding, and configuration-digest tuples | `DEV`, `PG`, `CMP`, `FLT` | Planned |
| `V04-CAP-001` | Handshake descriptors independently negotiate infrastructure service, method, modifier/format, mutability, stream support, and host/per-context capacity; coarse interface names cannot imply an absent capability | `DEV`, `CMP` | Planned |
| `V04-CAP-002` | Exhausting `MaxContextsPerHost`, `MaxAttachmentsPerContext`, `MaxLifecycleOperationsPerHost`, or `MaxLifecycleOperationsPerContext` rejects before the relevant hook/dispatch with typed no-effect; reservation/release traces remain bounded under races and unsupported behavior never silently queues or executes | `DEV`, `CMP`, `FLT` | Planned |
| `V04-ISO-001` | Container inspection proves a separate PID namespace, non-root identity, read-only root filesystem, dropped capabilities, bounded resources, one private journal mount, and no published host port | `CMP` | Planned |
| `V04-ISO-002` | Browser probes prove no driver route; worker probes may observe the accepted shared local route but prove no product dispatch path, no usable driver credential, and fail-closed authentication for missing, wrong-role, wrong-CA, expired, revoked, and stale identities | `CMP`, `FLT` | Planned |
| `V04-ISO-003` | Killing or wedging the driver cannot terminate the proxy, API, worker, or database; the persisted state becomes visibly degraded/stale | `CMP`, `FLT` | Planned |
| `V04-ISO-004` | Driver probes cannot reach the database, proxy, host services, or any external/internet target; DNS resolution cannot create an unapproved route and only the gateway path appears in the network matrix | `CMP`, `FLT` | Planned |
| `V04-SEC-001` | Valid current gateway/driver mutual identity succeeds; missing, wrong-role, wrong-CA, expired, revoked, or stale identity fails before method dispatch | `DEV`, `CMP` | Planned |
| `V04-SEC-002` | Identity/secret-value rotation increments the audited credential epoch and rejects old credentials without insecure fallback, mixed generation, configuration-digest drift, silent trust expansion, or indefinitely accepted expired credentials | `CMP`, `FLT` | Planned |
| `V04-SEC-003` | Canary service secrets are absent from worker environment/files, browser storage, frontend bundles, REST/WebSocket data, logs, errors, events, reports, screenshots, SBOMs, and package | `DEV`, `BR`, `PKG` | Planned |
| `V04-SEC-004` | gRPC reflection, proxy routing, browser JWT use as service identity, unauthorized metadata, and direct driver administration are rejected and audited safely | `DEV`, `CMP` | Planned |
| `V04-LIFE-001` | Handshake, health, context open/active/degraded/close, execution attach/detach, host drain/close, and failed transitions follow the approved distinct state tables | `DEV`, `CMP` | Planned |
| `V04-LIFE-002` | Open/close, attach/detach, lifecycle-operation cancellation, and drain are idempotent by request operation ID; cancellation requires a target operation ID, is allowed only for accepted/dispatched targets, distinguishes transport cancellation, and settles completion races without changing target certainty | `DEV`, `FLT` | Planned |
| `V04-LIFE-003` | Partial open/attach, repeated detach/close/drain, unhealthy readiness, stale generation, and 25 repeated restarts leave bounded visible host, context, and attachment states | `DEV`, `CMP`, `FLT` | Planned |
| `V04-LIFE-004` | Per-RPC ordered traces prove context and per-execution configuration hooks run first on open/attach and last on reverse detach/close cleanup, plus reload sequence, quota reservation/release, and compensating cleanup after failure at every hook; one cleanup failure is typed/audited and does not suppress later hooks | `DEV`, `CMP`, `FLT` | Planned |
| `V04-DEAD-001` | A request whose deadline is already expired is rejected before dispatch with authoritative `NO_EFFECT` when effect-bearing; a request with `effect_class=NONE` omits effect certainty | `DEV`, `FLT` | Planned |
| `V04-DEAD-002` | Deadline expiry during dispatch settles according to the approved stage/certainty truth table and initiates reconciliation without resend | `DEV`, `FLT` | Planned |
| `V04-DEAD-003` | Transport cancellation and `CancelLifecycleOperation` before effect versus after possible effect remain distinct; caller disconnect does not create a cancel mutation, and cancel acknowledgement cannot invent or overwrite target certainty | `DEV`, `FLT` | Planned |
| `V04-DEAD-004` | An unresponsive host is force-terminated after the approved grace period; all accepted operations settle or remain explicitly reconciliation-required | `CMP`, `FLT` | Planned |
| `V04-OP-001` | Supervisor acceptance durably stores one stable operation ID and request digest before any dispatch; database failure dispatches nothing | `DEV`, `PG`, `FLT` | Planned |
| `V04-OP-002` | Sequential/concurrent transport retries retain the same `OperationId`, `AttemptId`, and request digest and produce one accepted attempt, at most one simulator effect, and one durable attempt disposition | `DEV`, `FLT` | Planned |
| `V04-OP-003` | Private-journal replay after driver restart retains deduplication; the same `OperationId`/`AttemptId` and digest returns the recorded attempt result, while a conflicting digest is rejected and audited; a new `AttemptId` under the same `OperationId` is admitted only after authorized retry from authoritative `NO_EFFECT` and only when the complete generation, binding, and covered-configuration tuple still equals the tuple bound by the retained digest | `DEV`, `CMP`, `FLT` | Planned |
| `V04-JRN-001` | Crash injection before/after journal intent, simulator effect, journal result, driver reply, and project commit proves the persist-before-effect/result-before-reply protocol without distributed-atomicity claims | `DEV`, `PG`, `CMP`, `FLT` | Planned |
| `V04-JRN-002` | Full quota, reservation failure, I/O error, missing file, truncation, checksum mismatch, corruption, and failed fsync reject with `NO_EFFECT` when absence is authoritative or latch `EFFECT_UNKNOWN` when evidence is missing, contradictory, or integrity-invalid; the generation degrades/fails and never redispatches | `DEV`, `CMP`, `FLT` | Planned |
| `V04-JRN-003` | Retention, compaction, backup/restore, generation fencing/retirement, and secure removal preserve no-ID-reuse/no-reexecution evidence; capacity exhaustion stops new driver-effect acceptance before unsafe eviction | `DEV`, `CMP`, `FLT` | Planned |
| `V04-OP-004` | Complete stage/certainty truth table covers success, rejection, failure, timeout, cancellation, crash, lost response, reconciliation, and stale generation | `DEV`, `FLT` | Planned |
| `V04-OP-005` | Out-of-order, duplicate, conflicting, regressive, late, and competing reconciliation transitions cannot overwrite the one authoritative outcome | `DEV`, `PG`, `FLT` | Planned |
| `V04-OP-006` | An `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` operation remains latched across restart and cannot automatically reexecute the same logical open/close/attach/detach/cancel/drain effect under any ID; a separately authorized containment drain/fence may use a new ID only when it cannot repeat or resolve the original effect and preserves its certainty, journal, and tombstone | `DEV`, `CMP`, `FLT` | Planned |
| `V04-REC-001` | Operation, transition, certainty, audit, and outbox write atomically within the canonical project-database transaction; injected failure publishes nothing and leaves no partial canonical state | `DEV`, `PG`, `FLT` | Planned |
| `V04-REC-002` | Every downstream event is published only after commit and preserves exact sequence, cursor replay, snapshot consistency, and gap resynchronization | `DEV`, `PG`, `BR` | Planned |
| `V04-REC-003` | API crash before dispatch and after dispatch, plus driver crash before effect and after effect, yields no lost acceptance or duplicate effect | `DEV`, `CMP`, `FLT` | Planned |
| `V04-REC-004` | Lost acknowledgement and network partition reconcile only by original operation ID; uncertainty never becomes implicit success/failure and never causes resend | `CMP`, `FLT` | Planned |
| `V04-REC-005` | Database outage before, during, and after driver response preserves commit-before-publish and one reconstructable operation disposition | `DEV`, `PG`, `FLT` | Planned |
| `V04-REC-006` | Supervisor/driver/database restart reconciles every accepted operation within the approved bound and leaves none indefinitely pending | `DEV`, `PG`, `CMP`, `FLT` | Planned |
| `V04-REC-007` | Late responses stale at any host, context, or attachment generation are retained as audit evidence but cannot mutate current lifecycle, binding, operation, or certainty state | `DEV`, `FLT` | Planned |
| `V04-MIG-001` | Fresh SQLite and PostgreSQL migrations produce equivalent expected driver schemas, constraints, indexes, defaults, and disabled profile state | `DEV`, `PG` | Planned |
| `V04-MIG-002` | Populated v0.3 SQLite/PostgreSQL upgrade preserves all procedures, executions, events, prompts, variables, checkpoints, audits, reports, and recovery | `DEV`, `PG` | Planned |
| `V04-MIG-003` | Repeated upgrade is a no-op; injected migration failure rolls back schema/data/revision without partial driver records | `DEV`, `PG`, `FLT` | Planned |
| `V04-MIG-004` | Project backup/restore and rollback with terminal, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, `EFFECT_POSSIBLE`, and `EFFECT_UNKNOWN` operations retain identities, attempt history, audit, fences, and no-reexecution tombstones; unsafe rollback refuses or drains/fences without erasing certainty evidence, then restores v0.3 simulator behavior with the driver profile disabled | `DEV`, `PG`, `CMP`, `FLT` | Planned |
| `V04-API-001` | Read-only driver, context-generation, driver-binding, and operation REST schemas enforce signed identity/roles, stable versioning, bounded pagination, safe errors, and no mutation side effect; binding ID or context ID/generation keys distinguish current/history and execution ID alone cannot select an ambiguous reload attachment | `DEV`, `PG` | Planned |
| `V04-API-002` | Driver REST/WebSocket payloads expose no endpoint or secret and never synchronously proxy a browser request; WebSocket remains downstream-only | `DEV`, `BR`, `CMP` | Planned |
| `V04-API-003` | Existing v0.3 replay, reconnect, role-spoofing, token-expiry, stale-revision, and duplicate-request behavior remains unchanged; read-only driver views show one authoritative result during competing internal reconciliation | `DEV`, `BR`, `FLT` | Planned |
| `V04-UI-001` | Real-backend desktop/mobile UI visibly labels the driver as simulator-only and shows driver/context/binding identity, capacity, infrastructure health, generation, capabilities, staleness, stage, and certainty accurately | `BR` | Planned |
| `V04-UI-002` | Degraded, disconnected, unsupported, stale, failed, and uncertain states remain distinguishable without color alone and expose no driver mutation control | `BR`, `FLT` | Planned |
| `V04-UI-003` | Keyboard traversal, focus, accessible names, live-state announcements, responsive containment, and desktop/mobile Axe scans have no serious/critical finding | `BR` | Planned |
| `V04-UI-004` | Browser network trace contains only approved loopback HTTP/WebSocket requests and never attempts a direct driver connection | `BR`, `CMP` | Planned |
| `V04-PERF-001` | 1,000 health/status RPCs at 100/s have p95 at most 50 ms, maximum at most 250 ms, and zero errors | `CMP` | Planned |
| `V04-PERF-002` | 1,000 zero-delay simulator lifecycle operations at 20/s have durable acceptance p95 at most 250 ms, terminal p95 at most 500 ms, and zero duplicate effects | `CMP` | Planned |
| `V04-PERF-003` | 100 pre-effect `CancelLifecycleOperation` requests settle at p95 at most 500 ms/max 1 s without changing target certainty; 25 host restarts become ready and reconcile accepted work within 5 s each | `CMP`, `FLT` | Planned |
| `V04-PERF-004` | Ten minutes at 20 mixed lifecycle/status operations/s has no loss, duplicate, stuck operation, or crash, at most 32 MiB post-warmup growth, and at most 2 MiB/min slope | `CMP` | Planned |
| `V04-SC-001` | Python, Node, protobuf, gRPC, TLS, generator, and image inputs are version/hash locked; audits have no unresolved Critical/High finding | `PKG` | Planned |
| `V04-SC-002` | Backend, proxy, frontend, and driver images have distinct CycloneDX inventories, image/source digests, licenses, and a checksum manifest | `PKG` | Planned |
| `V04-SC-003` | Image/source/package inspection proves non-root/read-only/capability-drop/network policy, no runtime generator or embedded journal, no legacy archive, no supplied PDF bytes or extracted manual text; only the allowlisted review metadata (filenames, page counts, hashes) may remain unless separate clearance exists, and no secret is present | `PKG`, `CMP` | Planned |
| `V04-SC-004` | Two offline generations and two immutable-input package builds are byte-identical and bound to the same source/descriptor/evidence fingerprint | `PKG` | Planned |
| `V04-SC-005` | v0.4 qualification/package paths cannot overwrite, import, or pass using v0.3 evidence; package manifest excludes only generated evidence and retains product assets | `PKG` | Planned |
| `V04-SC-006` | On every declared platform profile, install starts disabled and enable starts only the bundled simulator; upgrade/rollback/uninstall under terminal, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, `EFFECT_POSSIBLE`, and `EFFECT_UNKNOWN` work must refuse, drain, or fence exactly as approved, preserve required journal/tombstones and certainty evidence, restore the prior disabled profile, retain canonical audit, and remove secrets only when safe | `PKG`, `CMP`, `FLT` | Planned |
| `V04-REG-001` | Full accepted-v0.3 SQLite/PostgreSQL, parser, worker, REST/WebSocket, auth, isolation, recovery, browser, accessibility, performance, audit, SBOM, and reproducibility suites pass unchanged | `DEV`, `PG`, `CMP`, `BR`, `PKG` | Planned |

### Certainty Contract

For `effect_class` other than `NONE`, the canonical certainty values are
`NO_EFFECT`, `EFFECT_CONFIRMED`, `EFFECT_POSSIBLE`, and `EFFECT_UNKNOWN`.
Requests with `effect_class=NONE` omit certainty; they do not invent a fifth
value. `REQUESTED`, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, and `SETTLED` are
operation stages. `FAILED`, `TIMED_OUT`, and `CANCELLED` are result or
disposition codes, not stages or certainty values.

Simulator dispatch authorization commits before send and sets
`EFFECT_POSSIBLE`, because the boundary may then be crossed and an effect may
occur before further evidence is durable. A transport acknowledgement never
proves the simulator effect. Reconciliation queries the same `OperationId` and
`AttemptId`, retains every prior classification and evidence record, and may
refine certainty to `NO_EFFECT`, `EFFECT_CONFIRMED`, or `EFFECT_UNKNOWN`. It may
not resubmit `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` work, allocate a successor
operation to evade uncertainty, or convert missing evidence into a terminal
claim. Only an explicitly authorized retry after authoritative `NO_EFFECT`
retains `OperationId` and request digest, increments `AttemptNumber`, and
allocates a new opaque `AttemptId`. The then-current generation, binding, and
covered-configuration tuple must exactly match the immutable tuple covered by
that digest; tuple drift refuses the retry instead of reusing the digest for a
different intent.

### Approved v0.4 Release Gates

| Gate | Required disposition |
| --- | --- |
| `V04-GATE-0` | The project-owner record approves and manifest-binds the bounded scope, exclusions, context/configuration/capability/lifecycle and certainty models, accepted shared-route worker residual risk, simulator fixture, migrations, rollback, budgets, and this test plan. The exhaustive documentation-conformance ledger must contain exact source identity/span, effect class or explicit excluded ambiguity, safe behavior and disposition, target phase, a unique planned test identity, errata disposition, and reconciled counts for every row. Deferred/`EXCLUDE` rows require static source and negative-scope evidence, not executable fixtures, semantic oracles, or results. In-scope v0.4 fixtures are planned at Gate 0 and executed at the applicable Gates 1-5. No organization-only approval is required for this local gate. |
| `V04-GATE-1` | Documentation, contract, context/configuration/capability/lifecycle, migration, and static security tests pass |
| `V04-GATE-2` | Isolation, mutual identity, secret, journal safety, crash-boundary, certainty, persistence, and recovery matrices pass; no waiver is permitted |
| `V04-GATE-3` | SQLite/PostgreSQL, API, real-browser UI, accessibility, and complete v0.3 regression pass |
| `V04-GATE-4` | Driver latency, cancellation, restart, and soak qualification passes with fingerprint-bound evidence |
| `V04-GATE-5` | Audits, distinct SBOMs, deterministic generation, install/disable/upgrade/rollback/uninstall, reproducible package, manifest inspection, and independent traceability review pass |

JC Arcaz approved the Candidate A scope, exclusions, budgets, and this test
plan on 2026-07-18. Exhaustive compatibility validation, independent source
review, exact manifest binding, and pinned Python 3.13 qualification pass, so
`V04-GATE-0` authorizes the bounded product implementation. Gates 1-5 remain
mandatory before v0.4 acceptance.
Any unresolved Critical or High issue in
scope enforcement, documentation traceability, isolation, identity,
configuration, capability/capacity, lifecycle ordering, secret handling,
operation identity, certainty, persistence, recovery, migration, source
non-execution, or no-resend behavior blocks release. These boundaries cannot be
waived by a local software test result.

The Gate 0 compatibility evidence model is deliberately static for excluded
behavior. Every authoritative page and public artifact must be represented,
classified, assigned either to the exact Candidate A slice or to its approved
exclusions, and bound to a unique future test identity. A Deferred/`EXCLUDE`
row is not an implementation, semantic-conformance, fixture-execution, or
verification claim. Executable fixtures and results are mandatory for the
implemented v0.4 rows at the applicable later gate. Deterministic source-count,
page-coverage, identity, disposition, errata, and manifest checks remain
mandatory for `V04-GATE-0`.

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
2.4. The required SPELL Development Environment manual was not present in that
original v0.1 evidence. A separate copy and six related PDFs were supplied
under `SPELL-DOCUMENTATION/` and all 304 pages were reviewed on 2026-07-17; the
inventory and hashes are in
[`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md). This later
evidence closes document availability, not every behavioral ambiguity or
authoring implementation decision.

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
| `V01-DOC-004` | Manual inventory | Manuals available to v0.1, versions, paths, and the then-missing DEV manual are recorded | Pass |
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
- Confirmed that the required Development Environment manual was absent from
  the v0.1 evidence. It was supplied and reviewed later on 2026-07-17.
- Compared manual behavior with the 2.6.10 source, current GUI plug-ins, release
  notes, configuration, protobuf interfaces, build metadata, and tests.
- Confirmed that the supplied legacy test coverage is insufficient for a safe
  rewrite and defined specification-derived test families above.

No legacy build, GUI launch, procedure execution, driver connection, browser
test, or operational integration test was performed for v0.1.

## Version 0.1 Exit Decision

This test plan was completed as the planning baseline. On 2026-07-12 the project
owner approved proceeding to the bounded v0.2 simulator vertical slice. At that
time, the missing Development Environment manual was waived only for this
slice; all other recorded v0.1 gaps remain open unless explicitly resolved.

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
