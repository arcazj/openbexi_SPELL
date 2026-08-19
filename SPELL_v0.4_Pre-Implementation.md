# SPELL v0.4 Pre-Implementation Gate

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.4.0 |
| Release name | Typed Simulator Driver and Context Foundation |
| Gate status | `V04-GATE-0 PASS`; bounded Candidate A product engineering authorized |
| Drafted and revised | 2026-07-17; local gate disposition recorded 2026-07-18 |
| Accepted product baseline | Commit `7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`, tag `v0.3.0` |
| Product implementation | Authorized to begin; not yet delivered or accepted |
| Operational authorization | None |
| Scope profile | Local-only, synthetic non-CUI simulator engineering |
| Project owner | JC Arcaz |

JC Arcaz approved Candidate A, its exclusions, local engineering budgets, and
the test plan for the scope profile above. The exact instruction and file
manifest are recorded in
[`G0_HUMAN_APPROVAL_LEDGER.json`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_HUMAN_APPROVAL_LEDGER.json).
The SHA-256 bindings are integrity evidence, not a cryptographic signature.
Scope approval does not bypass the remaining technical entry criterion, accept
a release, make a compliance claim, or permit connection to a GCS, spacecraft,
mission network, or externally effective system.

## Release Objective

SPELL v0.4 defines the first typed, authenticated, out-of-process driver
boundary using exactly one bundled deterministic simulator driver. It is a
host/context/execution lifecycle, configuration, capability, capacity, and
reconciliation foundation only. Existing v0.3 procedure semantics, including
the existing simulated `Telemetry` step, remain unchanged and are not routed
through the new host.

This scope follows the v0.3 decision that the driver-host boundary remained
v0.4 work. GCS service contracts remain later capability work; v0.4 deliberately
stops before any telemetry data plane, telecommand service, legacy adapter, or
operational integration.

## Approved Scope

1. Define a versioned protobuf/gRPC contract with typed, bounded messages and
   deterministic generated code. Generic `Any`, arbitrary maps, and untyped
   payload escape hatches are forbidden.
2. Add stable server-profile, driver-host-generation, context,
   context-generation, execution, execution-attachment-generation,
   driver-binding, and operation identity to the contract.
3. Add a handshake that reports contract version, implementation version,
   logical driver identity, simulator marker, driver-host generation and host
   configuration schema/digest, explicit granular capabilities, and host plus
   per-context capacity. Incompatible versions and unsupported capabilities
   fail closed.
4. Define typed server/driver host configuration, context-binding
   configuration, and allowlisted execution-attachment configuration. Each
   layer has explicit precedence, its own immutable digest/generation, and
   out-of-band secret references. Arbitrary maps and hidden environment
   overrides are forbidden.
5. Implement only handshake, health, context open/close, execution
   attach/detach, ordered lifecycle setup/cleanup, explicit lifecycle-operation
   cancellation, host drain, and operation-status/reconciliation behavior.
   v0.4 advertises no telemetry, telecommand, event, resource, task, time,
   ranging, memory, database, subscription, or procedure-facing driver
   capability.
6. Run one deterministic simulator driver in a separate non-root, read-only
   container. The host has no published port, no project-database access,
   no proxy route, and no public or mission-network route.
7. Keep the control-plane supervisor as the sole gateway and owner of the
   canonical project database, audit, and event stream. The driver never
   receives procedure source, browser JWT signing material, project-database
   credentials, or direct browser requests.
8. Mutually authenticate and encrypt gateway-to-driver traffic with
   driver-specific service identities independent of browser JWTs. There is no
   insecure fallback.
9. Give every lifecycle mutation one stable `OperationId`, immutable
   `AttemptId`, idempotent duplicate handling, explicit stage, structured error,
   generation fence, effect class, and separate canonical effect-certainty
   value. Lost responses reconcile by the original operation/attempt identity
   and are never invisibly resent.
10. Persist canonical driver identity, layer-specific configuration
   digests/generations, contract/capability/capacity state, lifecycle
   operations, transitions, certainty, and audit events before downstream
   publication. Give the simulator host a
   private bounded durable idempotency journal so it can deduplicate and answer
   `GetOperation` after restart without accessing the project database.
11. Add authenticated read-only REST snapshots and a read-only console
   projection for simulator identity, health, generation, capabilities,
   staleness, lifecycle stage, and certainty. No browser driver-control
   mutation is in scope.
12. Establish the documentation-conformance baseline in
    [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md) and require
    a populated exhaustive ledger before v0.4 gate approval. It must count and
    classify language constructs/public names/types/outcomes, server
    configuration, driver contracts, operator/development workflows and views,
    build/deployment concepts, and every example. This is classification and
    traceability work, not service implementation.
13. Add ordered, rollback-tested migrations for fresh and populated v0.3
    SQLite and PostgreSQL stores, deterministic conformance/fault fixtures, and
    version-parameterized qualification and packaging evidence.

## Architecture And Trust Boundaries

The approved local call path is:

```text
browser -> loopback proxy -> authenticated REST/WebSocket control plane
                                      |
                                      v
                         context/attachment supervisor
                                      |
                                      v
                         supervisor-owned gRPC gateway
                                      |
                                      v
                     isolated deterministic simulator driver
```

- REST and the database remain authoritative. WebSocket remains a
  downstream-only projection of committed canonical events.
- The backend initiates driver RPCs. The driver cannot initiate database,
  proxy, browser, host, DNS-dependent external, or internet activity.
- The proxy has no driver route. The browser receives neither an endpoint nor a
  service credential.
- The driver is isolated from the project-database network and runs non-root
  with a read-only root filesystem, dropped Linux capabilities, bounded
  resources, and one private writable journal volume. The journal contains only
  simulator operation identity, request digest, lifecycle effect, and result;
  it contains no procedure, actor credential, project audit, or browser data.
- A driver-host generation is bound to one host-profile digest. Each context
  binding and execution attachment has its own generation and digest derived
  from its parent identity. A response stale at any layer cannot mutate current
  authoritative state.
- The first v0.4 implementation may support one context and one execution
  attachment at a time, but those identities and capacity limits are explicit
  contract data rather than implicit singleton state.
- Driver code and generated contract artifacts are distinct from the procedure
  worker and cannot execute procedure source.

### Approved Worker-Isolation Decision

The current procedure worker is spawned inside the backend container and
therefore shares its network namespace. Candidate A selects the narrower local
threat model: the worker receives only bounded non-executing IR, has no product
call path or usable driver credential, and cannot authenticate to a driver that
fails closed under strict mTLS service-identity checks. A network route may
exist in the shared local development namespace, so the gate and tests do not
claim physical route isolation.

JC Arcaz accepts that residual routing risk only for this local, synthetic,
non-CUI simulator scope. Browser-to-driver routing remains absent. Worker and
browser negative probes must prove that neither can authenticate or dispatch a
driver RPC and that no procedure source, AST, arbitrary Python, or future
service payload enters the driver. A connected, protected-data, or operational
scope requires a new gate and a separately approved stronger isolation model.

## Contract Boundary

### Approved RPC Surface

| Method | Purpose | Mutation |
| --- | --- | --- |
| `Handshake` | Negotiate contract, host identity/generation/profile digest, capabilities, and capacity | No |
| `Health` | Return bounded host and context health/readiness | No |
| `OpenContext` | Bind one typed context configuration and initialize lifecycle infrastructure in approved order | Yes |
| `CloseContext` | Drain a context and clean lifecycle infrastructure in reverse order, with configuration last | Yes |
| `AttachExecution` | Attach a stable execution identity and attachment generation/digest for a load/reload lifecycle without routing procedure services | Yes |
| `DetachExecution` | Detach a finished, aborted, or explicitly unloaded execution and audit cleanup disposition | Yes |
| `CancelLifecycleOperation` | Request cooperative cancellation of one accepted in-progress lifecycle operation by target operation ID | Yes |
| `DrainHost` | Reject new contexts, attachments, and lifecycle operations; drain bounded work; close the simulator host | Yes |
| `GetOperation` | Reconcile one previously accepted operation by stable ID | No |

All calls have explicit deadlines, bounded request and response sizes,
structured error codes, correlation identifiers, and contract-version
metadata. A transport retry retains the same `OperationId` and `AttemptId`; an
authorized new effect attempt retains `OperationId` and request digest but may
allocate a new `AttemptId` only after authoritative `NO_EFFECT` proof. A known
lifecycle method's unsupported option/capability returns a typed unsupported
result rather than empty success. Future service methods are absent from the v0.4
descriptor; an unknown RPC is rejected at the protocol boundary with bounded
`UNIMPLEMENTED` behavior and cannot dispatch a placeholder service.
Lifecycle mutations are initiated only by supervisor-owned service management;
there is no REST, browser, procedure, or worker path that can request them.
The v0.4 conformance harness uses synthetic context/execution identities to
exercise open/attach/detach/close. Existing v0.3 procedure loads do not create a
driver binding and remain completely outside this host.

Every request carries the applicable `ServerProfileId`,
`DriverHostGeneration`, `ContextId`, `ContextGeneration`, `ExecutionId`,
`ExecutionAttachmentGeneration`, `DriverBindingId`, request `OperationId`,
`AttemptId`, and any method-specific target identity rather than depending on
process-global implicit context. Capability descriptors are typed by service, method,
supported modifier/format, mutability, stream support, and capacity. v0.4
advertises only infrastructure/context/execution lifecycle capabilities; all
future service families are explicitly absent.

Configuration is resolved and fingerprinted at three boundaries:

1. Host profile: contract defaults, server profile, and driver profile produce
   the host schema version/digest bound to `DriverHostGeneration`.
2. Context binding: the immutable parent host identity/digest plus the context
   profile produce the context digest bound to `ContextGeneration`.
3. Execution attachment: the immutable parent context identity/digest plus
   narrowly allowlisted execution inputs produce the attachment digest bound to
   `ExecutionAttachmentGeneration`.

An approved reload detaches and cleans the prior attachment, then creates a new
attachment generation and runs setup; it cannot mutate an attached generation
in place. Secret values are resolved only by the supervisor and never included
in a digest payload, procedure state, browser projection, or generic driver
configuration map. The precedence, secret-reference fingerprinting, and
redaction boundaries in this gate are the approved local implementation rules.

Per-execution setup receives typed immutable projections of the bound host
driver profile, context binding, and attachment inputs with all three parent
identities/digests. This preserves the documented context-plus-driver setup
intent without passing arbitrary maps or allowing an attachment to rewrite its
parent configuration.

Generation and fingerprint transitions are explicit:

| Trigger | Required transition |
| --- | --- |
| Host restart with unchanged resolved host profile | Allocate a new `DriverHostGeneration`; retain the same host-profile digest; fence every response from the prior generation |
| Host-profile change | Drain/fence the old host generation; allocate a new host generation and digest; never mutate the active generation in place |
| Context close/reopen with unchanged profile | Allocate a new `ContextGeneration` under the current host generation; retain the same context-binding digest |
| Context profile change | Close/fence the prior context generation; allocate a new context generation and digest |
| Execution reload with unchanged inputs | Detach/clean the prior binding; allocate a new `ExecutionAttachmentGeneration` and `DriverBindingId`; retain the same attachment digest |
| Execution reload with changed inputs | Detach/clean the prior binding; allocate a new attachment generation, binding ID, and digest |
| Secret value rotation under the same reference | Keep configuration digests unchanged; increment a separately audited `CredentialEpoch` and prove reauthentication/old-value rejection |
| Secret-reference identity change | Treat it as a configuration change at the owning host, context, or attachment layer and apply that layer's generation transition |

The canonical request digest covers the method, bounded payload, operation ID,
target operation ID when present, full applicable host/context/attachment
generation tuple, driver binding, and all applicable configuration digests. The
project operation record and private journal persist that same tuple plus the
attempt ID and attempt number. A host operation uses explicit null
context/attachment values; identity is never inferred from current process
state.

### Lifecycle Hook Ownership

| RPC | Setup/cleanup ownership | Capacity transition | Partial-failure rule |
| --- | --- | --- | --- |
| `OpenContext` | Validate resolved context configuration; initialize configuration first, then declared context infrastructure hooks in order | Reserve context quota before first hook; publish active use only after success | Run compensating cleanup for every completed hook in reverse order, configuration last; release the reservation after audited settlement |
| `AttachExecution` | On initial load or reload, run the per-execution configuration-attachment hook first, then declared lifecycle fixture hooks in order under a new attachment generation | Reserve attachment and in-flight quota before first hook; publish attachment only after success | Run reverse compensating cleanup for every completed hook, configuration attachment last, and retain the failed attachment disposition |
| `DetachExecution` | On finish, abort, reload, or explicit unload, run all per-execution cleanup hooks in reverse order and the configuration-attachment cleanup last | Stop new work first; release attachment quota only after every cleanup result is durably recorded | One failure does not suppress later hooks; aggregate typed results and degrade/fail according to the approved table |
| `CloseContext` | Require attachments to be settled or explicitly detach them, then clean context hooks in reverse order and configuration last | Reject new attachments when closing; release context quota only after audited cleanup | Preserve every cleanup result; uncertainty cannot be erased by closing the context |
| `DrainHost` | Reject new contexts/attachments, settle or fence existing work, close contexts, then close host infrastructure | Enter draining before rejecting new reservations; release host resources only after settlement/fencing | Timeout or failure leaves a typed degraded/failed host with original operation certainty intact |

Every hook emits an ordered trace containing hook identity, owner layer,
generation, operation and attempt IDs, start/result time, stage, certainty, and
safe error.
The v0.4 simulator provides deterministic hooks and fault points solely to prove
this lifecycle contract; they are not telemetry, telecommand, or other future
driver services.

The v0.4 capability contract names four independent runtime quotas:
`MaxContextsPerHost`, `MaxAttachmentsPerContext`,
`MaxLifecycleOperationsPerHost`, and `MaxLifecycleOperationsPerContext`.
Journal byte/entry quota is a separate storage-safety limit. Reservation occurs
durably before the first relevant hook or dispatch; a rejected reservation has
`NO_EFFECT` certainty. Context/attachment quota is released only after the
corresponding cleanup disposition is durable. In-flight operation quota is
released only after the operation is terminal or durably latched
reconciliation-required. Draining admits no new reservation, and no quota uses
the ambiguous term `session`.

`CancelLifecycleOperation` is itself a mutation with a new request
`OperationId` and `AttemptId` and required `TargetOperationId` and
`TargetAttemptId`. It is allowed only while the target is `ACCEPTED` or
`DISPATCHED`. If the target has already settled, the
cancel request returns typed `ALREADY_SETTLED` with no effect. A completion race
is settled by the original target's authoritative stage; the cancel request can
report only whether cancellation was requested/observed, never the target's
effect certainty. Transport-level RPC cancellation merely stops the caller's
wait and does not create `CancelLifecycleOperation` or a procedure
`INTERRUPTED` transition.

### Approved Compatibility Policy

- Contract package namespace: `spell.driver.v1`.
- Major-version mismatch: reject the connection.
- Minor/additive evolution: preserve field numbers, tolerate known additive
  fields only under a recorded compatibility rule, and never reinterpret an
  existing enum or field.
- Unknown enum values, malformed messages, duplicate conflicting operation
  IDs, and oversized payloads: reject safely and audit without echoing secret or
  unbounded content.
- Generated source and the descriptor set are reproducible and fingerprinted.
  Runtime schema generation and network-fetched generators are forbidden.
- Granular capability evolution is additive only. A service, method, modifier,
  format, mutation class, stream feature, or capacity absent from the handshake
  is unsupported and cannot be inferred from a coarse interface name.

## Lifecycle, Operation, And Certainty Model

The following state and certainty model is approved for the bounded local
implementation. It retains immutable operation-attempt history and a separate evidence-based
certainty classification. Within one attempt, stage progress is forward-only.
An authorized retry after authoritative `NO_EFFECT` increments `AttemptNumber`,
allocates a new `AttemptId`, and can move the operation projection from
`RECONCILING` to `ACCEPTED`; progress is therefore ordered lexicographically by
`(AttemptNumber, per-attempt stage)`, not by one scalar stage value. Certainty can
refine as evidence arrives, but earlier classifications and evidence remain in
the append-only history.

Approved host lifecycle states:

`STARTING`, `READY`, `DEGRADED`, `DRAINING`, `CLOSED`, and `FAILED`.

Approved context-binding states:

`OPENING`, `ACTIVE`, `DEGRADED`, `CLOSING`, `CLOSED`, and `FAILED`.

Approved execution-attachment states:

`ATTACHING`, `ATTACHED`, `DETACHING`, `DETACHED`, and `FAILED`.

Open, attach, detach, cleanup, lifecycle-operation cancellation, and drain are
lifecycle actions, not host or procedure states. Health reports each applicable
state plus readiness, its layer-specific generation/configuration digest,
capacity use, and last-observed time.
Documented procedure states such as `LOADED`, `RUNNING`, `PROMPT`, `PAUSED`, and
`INTERRUPTED` remain execution-domain states outside this driver state machine.

The configuration lifecycle initializes first and cleans last. Context and
execution setup proceeds in declared capability order; cleanup is reversed.
Cleanup is best effort and must not prevent later cleanup hooks from running,
but every hook produces a typed audited disposition. Capacity exhaustion is an
explicit non-effecting rejection and never causes unbounded queuing.

Approved stages:

`REQUESTED`, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, and terminal `SETTLED`.

Approved certainty values:

| Certainty | Meaning |
| --- | --- |
| `NO_EFFECT` | Authoritative evidence confirms that this attempt produced no simulator effect. |
| `EFFECT_CONFIRMED` | The simulator confirms the original operation ID produced its defined effect. |
| `EFFECT_POSSIBLE` | Simulator dispatch authorization committed before send, so the effect boundary may have been crossed and an effect may have occurred; final proof is absent or incomplete. |
| `EFFECT_UNKNOWN` | Missing, contradictory, or integrity-invalid evidence prevents determining whether an effect occurred. |

`FAILED`, `TIMED_OUT`, and `CANCELLED` are result or disposition codes, not
stages or certainty values. Read-only calls declare `effect_class=NONE` and do
not fabricate a fifth certainty value. Lifecycle mutations declare an explicit
simulator lifecycle effect class. Transport success does not prove effect. A
failure after possible dispatch is `EFFECT_POSSIBLE`, or `EFFECT_UNKNOWN` when
evidence is missing, contradictory, or integrity-invalid, unless the same
operation/attempt identity can authoritatively prove otherwise. Such an
operation is latched in `RECONCILING` and cannot trigger an automatic resend.
An explicitly authorized retry is legal only after authoritative `NO_EFFECT`;
it retains `OperationId` and request digest, increments `AttemptNumber`, creates
a new opaque `AttemptId`, and binds that attempt to the then-current host,
context, attachment, and driver generations while preserving prior-attempt
history. Because the retained request digest covers that complete tuple, the
then-current tuple and every covered configuration digest must exactly equal
the prior immutable intent. Generation, binding, or covered-configuration
drift refuses the retry; it cannot be hidden beneath the retained digest and
requires a separately authorized operation with a new identity.

This no-reexecution rule does not prohibit a separately authorized containment
operation with its own ID that only drains or fences the affected generation.
Containment cannot repeat the original logical effect, clear its journal or
tombstone, rewrite its certainty, or claim to reconcile it; the original
operation remains latched until evidence for that same ID resolves it.

## Persistence And Projection

The approved local persistence ownership model requires:

- Versioned server-profile, driver-host-generation, context,
  context-generation, execution, execution-attachment-generation, and
  driver-binding identities.
- Separate immutable host-profile, context-binding, and execution-attachment
  schema/digests plus non-secret resolution provenance and parent identity.
- A logical simulator-driver identity, audited credential epoch, and immutable
  host-profile digest.
- A driver-host generation, negotiated contract version, implementation version,
  granular capabilities, host/per-context capacity and use, distinct lifecycle
  health, and last-observed timestamp.
- A durable operation ledger with a project-wide unique stable `OperationId`,
  immutable per-try `AttemptId` and attempt number, request digest, effect class,
  applicable host/context/attachment generation tuple, and driver binding.
- Append-only stage/certainty transitions with actor, correlation ID, safe
  structured error, and accepted/dispatched/terminal timestamps.
- A private driver-host idempotency journal, durably written around simulator
  effects and replayed on restart. It is a reconciliation witness, not the
  canonical project audit or an alternate API database.
- Within the project database, an outbox/canonical event written in the same
  transaction as each authoritative state transition.
- Revision checks so competing or late reconciliation cannot create two final
  outcomes.
- As-run evidence sufficient to reconstruct the driver identity, contract,
  configuration, operation, transition, certainty, and responsible actor.

There is no distributed transaction between the project database and the
private driver journal. The approved protocol makes every crash window
reconcilable:

1. The supervisor commits `ACCEPTED`, the stable operation and attempt IDs,
   request digest, audit, and outbox in one project-database transaction before
   dispatch.
2. The driver durably journals the operation and attempt IDs, full applicable
   generation tuple/binding, and request digest before applying a simulator
   lifecycle effect.
3. The driver durably journals the effect/result before replying.
4. The supervisor commits the returned stage, certainty, audit, and outbox in
   one project-database transaction before projection.

A crash or I/O failure between those points is resolved by querying the same
operation and attempt IDs. Missing proof after possible dispatch is
`EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` according to evidence integrity; it is
never converted to `NO_EFFECT`, success, or a new dispatch without proof.

### Private Journal Safety Rules

- Each attempt ID is bound to one operation ID, request digest, explicit
  host/context/attachment generation tuple, and driver binding and can never be
  reused. The operation ID persists across an authorized retry only as defined
  above.
- No active-generation entry or no-reexecution tombstone may be evicted. A
  generation may retire its journal only after the supervisor fences that
  generation and every accepted operation is canonically terminal or latched
  `EFFECT_POSSIBLE`/`EFFECT_UNKNOWN` in `RECONCILING`.
- Capacity is reserved before accepting a new mutation. A full journal or a
  pre-effect write failure rejects the new operation before effect with
  `NO_EFFECT` certainty and moves health to `DEGRADED`.
- A missing, truncated, checksum-invalid, corrupt, or post-dispatch write-failed
  journal never permits another effect. The generation fails closed, reports
  `DEGRADED` or `FAILED`, and affected operations remain `EFFECT_UNKNOWN`. The
  generation cannot resume and may only be retired after an explicit supervisor
  fence; retirement does not rewrite certainty.
- Compaction may change representation but must preserve operation and attempt
  IDs, generation, request digest, effect/result witness, and no-reexecution
  property. A replacement host, context, or attachment generation rejects every
  operation bound to an old tuple.
- Journal quota, retention horizon, fsync behavior, integrity checks, backup,
  corruption recovery, and secure removal are approved configuration, not
  implementation defaults inferred later.

Approved external additions are read-only and versioned:

- `GET /api/v1/drivers`
- `GET /api/v1/drivers/{driver_id}`
- `GET /api/v1/driver-contexts`
- `GET /api/v1/driver-contexts/{context_id}/generations/{context_generation}`
- `GET /api/v1/driver-bindings`
- `GET /api/v1/driver-bindings/{driver_binding_id}`
- `GET /api/v1/driver-operations/{operation_id}`

These resources read persisted state; they do not synchronously proxy browser
requests to the driver. They expose no internal endpoint, certificate, secret,
private key, or unsafe raw error. Any WebSocket additions are projections of
already committed events and preserve cursor replay and gap resynchronization.
An execution ID may have multiple reload attachments, so it is a list filter,
not a singular attachment key. Current and historical context generations and
driver bindings remain distinguishable; stale records are immutable evidence.
The packaged Compose topology may contain the single allowlisted non-secret
driver service name needed for runtime discovery; it is not an API field or a
credential and does not create a host-published route.

## Security And Supply-Chain Constraints

- Use mutually authenticated service identity, with a local test CA only. This
  release makes no production PKI or identity-provider claim.
- Keep gateway and driver credentials in separate least-privilege mounts. Do
  not place them in worker messages, inherited worker environment, browser
  storage, REST/WebSocket payloads, logs, events, reports, screenshots, SBOMs,
  or release archives.
- Reject missing, wrong, expired, revoked, or stale-generation identities.
- Track service-secret rotation with a monotonic audited `CredentialEpoch`;
  reject the prior value after cutover without changing unrelated configuration
  digests or accepting a mixed epoch.
- Disable gRPC reflection and unplanned health/admin surfaces at the proxy and
  host boundary.
- Hash-lock protobuf, gRPC, TLS, generator, and runtime dependencies; record
  licenses and audits; produce a distinct driver-image SBOM and checksum.
- Build generated code without network access from pinned tools, and prove the
  same source produces the same descriptor and package bytes twice.
- Retain legacy archives and the supplied PDFs as read-only external evidence.
  Use the page-complete review in
  [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md), but do not
  copy legacy code, package uncleared PDFs, or reproduce weakly typed/insecure
  wire contracts in the Apache-2.0 implementation.

## Data Migration And Rollback

- Migrations are immutable, ordered, and static; runtime ORM metadata cannot
  redefine an applied revision.
- Fresh and populated-v0.3 SQLite and PostgreSQL stores must produce equivalent
  schemas and preserve all existing procedures, executions, events, prompts,
  variables, checkpoints, audits, and reports.
- Repeated upgrade is a no-op. An injected failure rolls back without a partial
  driver ledger or changed migration revision.
- The driver profile is disabled by default during upgrade and rollback. The
  private journal has an explicit version, upgrade/replay test, corruption
  behavior, size bound, and backup/removal rule.
- Rollback disables/removes the v0.4 driver service and read-only projection
  while retaining auditable v0.4 records. Existing v0.3 simulator procedures
  continue with their original semantics and data.

## Explicit Exclusions

- Roadmap Candidate B: prompt-result binding, prompt timeout/cancellation
  semantics, and long-procedure prompt-flow redesign.
- Telemetry, telecommand, event, resource, task, time, ranging, memory, PCS,
  database, subscription, or high-rate driver data services.
- Routing any current procedure step through the driver or adding procedure
  syntax, SDK calls, arbitrary Python, third-party imports, or persistent
  authoring.
- Implementation of the later roadmap's language, operator workspace,
  telemetry/condition, data service, development environment, auxiliary
  mutation, telecommand, or legacy-observation phases. v0.4 records their
  compatibility disposition only.
- Live, legacy, test-range, non-operational, or operational GCS adapters;
  spacecraft connectivity; mission networks; arbitrary configured endpoints;
  operational identifiers; or externally effective commands.
- Browser driver mutations, dynamic plug-in loading, legacy protobuf wire
  compatibility, or reuse of legacy implementation code.
- Production PKI, enterprise identity, HA, Kubernetes, multi-node transport,
  operational SLOs, accreditation, deployment approval, or mission authority.
- Java, Eclipse, Three.js, or replacement of the accessible 2D console.

## Requirements And Acceptance Authority

The detailed `V04-REQ-*` to `V04-*` mapping, planned environments, performance
budgets, and release gates are authoritative in
[`Test_and_Integration.md`](Test_and_Integration.md). All v0.4 results remain
`Planned` until implementation is authorized and the tests are actually run.

The following properties are non-waivable:

- Simulator-only endpoint allowlisting and absence of operational capability.
- Populated exhaustive documentation ledger, source-count reconciliation, and
  approved errata dispositions before gate approval.
- Exact nine-RPC infrastructure descriptor, absence of future service/source/IR
  payloads, and zero execution-correlated driver activity from existing v0.3
  procedure behavior while unrelated health traffic remains distinguishable.
- Typed contract compatibility and explicit unsupported behavior.
- Stable host/context/execution-attachment/binding identity, separate
  configuration generations/digests, per-RPC lifecycle ordering/compensation,
  targeted cancellation, granular capabilities, and named capacity.
- Service identity, secret isolation, and failure-closed authentication.
- Stable operation intent and immutable attempt history, lexicographic
  `(AttemptNumber, per-attempt stage)` progress, retained certainty evidence,
  and no automatic resend from `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN`.
- Fail-closed driver-journal capacity, integrity, retention, generation
  retirement, and no-ID-reuse behavior.
- Persist-before-publish ordering, generation fencing, crash reconciliation,
  and one durable disposition.
- Fresh/populated SQLite and PostgreSQL migration integrity.
- Worker/browser driver isolation under the threat model approved at entry.

## Approved Engineering Budgets

These are local qualification budgets, not operational SLOs:

| Test | Approved local budget |
| --- | --- |
| Health/status | 1,000 RPCs at 100/s; p95 at most 50 ms, maximum at most 250 ms, zero errors |
| Lifecycle operations | 1,000 zero-delay simulator operations at 20/s; durable acceptance p95 at most 250 ms and terminal result p95 at most 500 ms; zero duplicate effects |
| Lifecycle cancellation and restart | 100 pre-effect `CancelLifecycleOperation` requests settle at p95 at most 500 ms and maximum at most 1 s; 25 host restarts become ready and reconcile accepted work within 5 s each |
| Sustained operation | Ten minutes at 20 mixed lifecycle/status operations per second; no lost or duplicate disposition, no stuck operation, at most 32 MiB post-warmup growth, and at most 2 MiB/min growth slope |

JC Arcaz approved these values for the local engineering gate. They may be
revised before implementation only with a recorded rationale and corresponding
test update.

## Entry Risks And Decisions

| Decision or risk | Recorded local disposition or retained technical condition |
| --- | --- |
| Scope authorization | Resolved: Candidate A alone is selected and Candidate B is deferred. |
| Worker isolation | Resolved: bounded non-executing IR, strict mTLS credential separation, fail-closed authentication, and the recorded local shared-route residual risk. |
| Contract policy | Resolved by this gate: package namespace, version negotiation, field/enum compatibility, stable identities, size limits, errors, and generation rules are fixed above. |
| Context and lifecycle | Resolved by this gate: host/context/execution-attachment separation, binding transitions, hook/compensation order, cleanup disposition, capacity, and cancellation races are fixed above. |
| Configuration | Resolved by this gate: typed host/context/attachment layers, precedence, generations/digests, allowlisted inputs, secret references, redaction, reload, and profile versioning are fixed above. |
| Capability model | Resolved by this gate: typed service/method/modifier/format/mutability/stream/capacity descriptors and explicit unsupported behavior are fixed above. |
| Identity lifecycle | Resolved for the local test boundary: local mTLS issuance, separate credential mounts, epoch rotation, expiry/revocation rejection, restart, and redaction are required. No production PKI claim is made. |
| Simulator fixture | Resolved for local qualification: deterministic synthetic identity, configuration, lifecycle effects, fault controls, and operation truth table. |
| Persistence/API | Resolved by this gate: canonical ledger, private journal protocol and safety rules, migration/rollback behavior, revision controls, read-only REST schemas, and committed-event projection are fixed above. |
| Performance | Resolved: the local qualification budgets above are approved; they are not operational SLOs. |
| Release tooling | Parameterize v0.4 evidence/package paths so v0.4 cannot overwrite, satisfy itself with, or mutate retained v0.3 evidence. |
| Documentation conformance | Complete the supplied-manual review and populated exhaustive cross-manual compatibility ledger with per-manual artifact counts, source spans, classifications, Candidate A or exclusion dispositions, planned test identities, and errata handling without treating excluded behavior as implemented or the manuals as a version-exact executable oracle. |
| Next-generation design baseline | Validate the Candidate A-applicable typed contract, trust boundary, lifecycle/restart, security, failure, migration, rollback, and verification inputs in `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`. Broader proposed ADR acceptance, externally effective architecture, and organization/mission open decisions remain future design dependencies outside local v0.4 Gate 0. |
| Clean-room boundary | Resolve any publication/licensing boundary for supplied PDFs without importing legacy code or external evidence into product packages. |
| Repository baseline | Separate intended gate files from unrelated staged, modified, and untracked workspace content before any release commit. |

The owner approval resolves the bounded Candidate A scope, its exclusions, the
worker-isolation choice, encoded contract/lifecycle/configuration/capability/
identity/simulator/persistence design, budgets, and test plan. Organization-only
next-generation decisions, per-role sign-offs, and proposed ADR approvals are
outside the local gate. Documentation conformance remains an independently
validated technical criterion; clean-room packaging, dependency locking, and
repository-change-set checks remain mandatory evidence work and cannot be
waived at release.

### Dependency And Generator Feasibility

The Gate 0 feasibility check resolved `grpcio==1.82.1`,
`grpcio-tools==1.82.1`, and `protobuf==7.35.1` under the pinned Python 3.13
qualification image. Two isolated `protoc` generations from the same candidate
contract produced byte-identical descriptors and generated sources. This
confirms that exact locks and offline deterministic generation are feasible; it
does not add a product dependency, close the later audit/SBOM/reproducibility
gates, or claim that the v0.4 contract has been implemented.

## Entry Criteria

Implementation remains blocked until all of the following are recorded:

1. Recorded owner approval of this bounded Candidate A scope and exclusions.
2. Resolution of every local Candidate A design decision in the table above.
3. Completion of the v0.4 history entry and deterministic baseline manifest under
   [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md),
   documentation-conformance baseline, context/configuration/capability
   contract, requirements, test matrix, threat model, rollback, and
   non-waivable gates, bound to the recorded project-owner decision.
4. Completion of populated compatibility-ledger rows and reconciled per-manual
   counts for every language construct/public name/type/outcome,
   server/configuration item, driver contract/status, operator/development
   workflow/view, build/deployment concept, and example, with no unresolved
   omission and an explicit exclusion disposition for each unresolved source
   ambiguity.
5. Confirmation that Deferred/`EXCLUDE` rows have static source and negative
   scope evidence and a unique planned test identity. They do not require an
   executable fixture, semantic oracle, or result at Gate 0; in-scope v0.4
   fixtures execute at the applicable Gates 1-5.
6. Confirmation that protobuf/gRPC/TLS dependencies and generators can be
   hash-locked, audited, SBOM-inventoried, and run deterministically offline.
7. Confirmation of the exact v0.3.0 baseline and an intended clean change set
   that excludes unrelated workspace files and credential-bearing artifacts.

## Exit Criteria

If implementation is later authorized, v0.4 cannot be accepted until:

1. Every mandatory documentation, contract, isolation, identity, secret,
   context/configuration/capability/lifecycle, deadline, operation, certainty,
   persistence, recovery, migration, API, UI,
   accessibility, performance, supply-chain, and regression test is executed
   and recorded.
2. Fault injection covers pre-dispatch, accepted/no-response,
   persisted/pre-publication, stale-generation, database rollback, driver/API
   restart, partition, late response, cancellation, and shutdown boundaries.
3. Network and credential probes prove the approved browser/worker/driver
   boundaries: no browser route, no worker product call path or usable driver
   credential, fail-closed driver authentication, and no public, GCS,
   spacecraft, mission, or internet egress from the driver.
4. Fresh, populated-v0.3, repeated, failed-upgrade, backup/restore, and rollback
   paths pass on SQLite and PostgreSQL.
5. Complete v0.3 backend, browser, security, recovery, audit, performance,
   package, and reproducibility regression remains green.
6. Fingerprint-bound v0.4 evidence, distinct SBOMs, dependency audits, source
   package inspection, and two-build reproducibility pass without using or
   overwriting v0.3 evidence.
7. Driver install, disable, upgrade, rollback, and declared platform-profile
   verification pass for the separately packaged simulator host.
8. A new release record states exact evidence and limitations. No unresolved
   Critical or High defect exists in safety, identity, isolation, persistence,
   recovery, migration, or no-resend behavior.

## Gate Decision

The documentation-conformance catalog is exhaustive across all seven
authoritative sources, all 304 pages, and all 195 Language Reference examples.
Deterministic validation and fresh independent review pass for all 1,682 rows:
125 rows are assigned to the exact Candidate A slice and 1,557 rows to the
approved Deferred/`EXCLUDE` boundary. Each row has a unique planned test
identity. Gate 0 does not treat excluded semantics as executable oracles or
require fixture results for them. Exact owner-record manifest binding and the
full Gate 0 suite pass under the digest-pinned Python 3.13 image.

| Field | Current value |
| --- | --- |
| Candidate selected | Candidate A - Typed Simulator Driver and Context Foundation; Candidate B deferred |
| Owner approval | JC Arcaz, recorded 2026-07-18; exact instruction in `G0_HUMAN_APPROVAL_LEDGER.json` |
| Architecture decisions complete | Yes for the bounded local Candidate A design; broader next-generation decisions are outside this gate |
| Worker isolation | Bounded non-executing IR plus strict mTLS credential separation; local shared-route residual risk accepted |
| Test plan approved | Yes, for the local synthetic non-CUI scope |
| Implementation authorized | Yes, for this bounded local engineering scope only |
| Earliest permitted next action | Implement Candidate A and execute approved Gates 1-5; do not record v0.4 acceptance unless every gate passes |
