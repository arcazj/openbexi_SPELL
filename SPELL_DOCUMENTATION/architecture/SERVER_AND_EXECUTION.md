# Server And Execution Architecture

## Purpose

This document defines domain leadership, controller ownership, execution
identity and state, concurrent scheduling, worker isolation, driver attachment,
command settlement, and crash recovery. It preserves the documented SPELL
context, executor, procedure-instance, controller, monitor, and driver concepts
without retaining unsafe in-process or unrestricted-code assumptions.

The Effect Authorization Point (EAP) is the sole holder of the GCS effect
credential and effect-capable egress used by this execution architecture.

## Stable Identities

| Identity | Scope and lifetime |
| --- | --- |
| `domain_id` | Immutable logical Satellite Control Domain |
| `satellite_id` | Immutable satellite identity assigned one-to-one to a domain |
| `authority_incarnation_id` | Globally unique command-authority activation; restored evidence never reactivates it and the value is never reused |
| `assignment_generation` | Monotonic mission-wide assignment generation for the satellite |
| `leader_epoch` | Monotonic domain service-leadership term; changes at every takeover |
| `control_lease_id` | One grant of human execution control |
| `control_fencing_token` | Monotonic token allocated on every new control grant |
| `control_lease_revision` | Revision of lease state, holder, renewal, or expiry facts |
| `server_profile_id` | Versioned server policy and capacity profile |
| `context_id` | Stable logical spacecraft context within the domain |
| `context_generation` | One immutable resolved context configuration and lifecycle |
| `driver_binding_id` | Exact context-generation to driver-host-generation binding |
| `execution_id` | One independent procedure instance |
| `execution_attachment_generation` | One execution-to-context attachment, renewed on approved reload |
| `bundle_digest` | Immutable validated procedure bundle identity |
| `command_id` | One accepted runtime mutation and its durable disposition |
| `operation_id` | One typed driver operation and its effect-certainty record |
| `attempt_id` | One dispatch attempt within an effecting operation; never reused |
| `saa_attempt_permit_id` | One-use SAA authorization consumed for one attempt |
| `dispatch_permit_id` | One primary-PostgreSQL permit consumed by the EAP before effect |
| `prompt_id` | One durable operator question with at most one settlement |

IDs are opaque, globally unique values. Human-readable names are metadata and
are never used for fencing, deduplication, or authorization.

## Domain Lifecycle

| State | Meaning | Permitted control behavior |
| --- | --- | --- |
| `STARTING` | Configuration, schema, dependency, clock, and leadership checks are running | No execution mutation |
| `STANDBY` | Instance is healthy but is not the domain leader | Read-only observation and takeover candidacy |
| `ACTIVE` | Instance holds the current leader epoch and a valid Satellite Assignment Authority grant for its authority incarnation; all required control dependencies are healthy | Policy-authorized mutations permitted |
| `DEGRADED` | Leader is present but a required capability is impaired | Only operations explicitly permitted by the degradation policy |
| `DRAINING` | SAA has committed `effect_enabled=false`; new admission and EAP permit consumption are closed while work is settled, reconciled, checkpointed, or fenced | No new execution starts, driver attachments, or effects |
| `STOPPED` | This authority incarnation completed an orderly shutdown and is terminal | No control mutation; a later activation uses a new incarnation |
| `FAILED` | Safety or integrity preconditions are not met | No control mutation; recovery or administrative disposition only |

Leadership uses a durable lease or consensus-backed lease plus a PostgreSQL
epoch row. Before final fence evidence is collected, the SAA reserves a fresh
anchored assignment and `AuthorityIncarnationId` with `effect_enabled=false`;
the candidate records that target identity but receives no effect authority.
The candidate becomes active only after it proves the prior command path fenced
with evidence bound to that target; establishes a fresh local leadership epoch;
invalidates prior controller authority; reconciles durable work; and passes
database, integration, and safety readiness while non-active. The SAA then
activates the reserved grant and issues fresh EAP authorization, after which the
domain conditionally transitions to `ACTIVE`. The previous leader cannot commit
after the epoch changes and its dispatch credentials are revoked, even if it
remains alive.

Each generation allocation includes a signed receipt from the mandatory
non-rollback generation anchor. Anchor unavailability or ambiguous lineage
prevents reservation and activation. Apparent loss of the previous leader,
site, EAP, or GCS session never substitutes for external fence proof.

## Human Controller Lease

The controller lease is independent from service leadership. It is scoped to
the entire Satellite Control Domain because the user requirement permits one
execution controller per SPELL server, not one per procedure.

A lease record contains domain, authority incarnation, lease ID, holder subject,
authenticated session, tab-local client-instance identity and proof-key
thumbprint, issued time, expiry time, last renewal time, lease revision,
`control_fencing_token`, acquisition reason, and release or revocation
disposition. Database time determines expiry.

Acquisition rules:

1. The caller must be authenticated and authorized for domain control.
2. The domain must be `ACTIVE` or in an explicitly controllable degraded state.
3. An unexpired lease cannot be displaced by routine acquisition.
4. A new grant atomically increments `control_fencing_token`.
5. Renewal retains the token, advances lease revision, and is accepted only
   from the same authorized holder/session/client proof before the policy
   deadline.
6. Release is explicit and audited. Expiry, administrative revocation, or
   identity/session invalidation also ends the grant.
7. Forced takeover requires a separate privilege, a reason, and policy-defined
   safeguards. It issues a new token and fences every command from the old one.

Authority-incarnation replacement is a terminal controller event, not a benign
lease renewal. In one PostgreSQL transition the server revokes or invalidates
the old lease with reason `AUTHORITY_REPLACED`, increments its lease revision,
clears the current-lease pointer, and moves affected executions to `SUSPENDED`
with `hold_reason=CONTROL_LOST` and saved resume targets. The new incarnation
starts with no controller. Reacquisition allocates a new lease ID and higher
`control_fencing_token` and requires acknowledgement of active executions,
prompts, alarms, and uncertain effects before explicit resume.

Controller loss follows a domain policy selected before operations. The safe
default is to prevent new interactive decisions and pause affected executions
at their next safe point. Already dispatched external operations are reconciled
rather than cancelled or resent by assumption.

## Execution State Model

The complete canonical execution, domain, command, prompt, and driver-operation
machines are defined in [Canonical State Machines](STATE_MACHINES.md) and the
checked-in [machine-readable model](state-machines.json). The execution path
uses `REQUESTED`, `VALIDATING`, `ADMISSION_PENDING`, `LOADING`, `PAUSED`,
`RUNNING`, `WAITING`, `PROMPT`, `INTERRUPTED`, `SUSPENDED`, `RECOVERING`, and
`STOPPING`; terminal states are `FINISHED`, `ABORTED`, and `ERROR`.

Every transition is a compare-and-set against `execution_revision`, is tied to
the current authority incarnation and leader epoch, and appends audit and outbox
records in the same transaction. `CONTROL_HOLD` and `UNKNOWN` are not execution
states. Controller loss uses `SUSPENDED` with
`hold_reason=CONTROL_LOST` and a saved resume target. `UNKNOWN` describes
insufficient observation or unresolved imported evidence. Driver health such as
`READY`, `DEGRADED`, or `FAILED` is separately namespaced and cannot be
presented as execution state.

## Admission And Concurrent Execution

The scheduler admits multiple executions for the same satellite only when all
of these checks succeed:

- the domain and context generation accept new work;
- the immutable bundle is approved for the domain and its dependencies resolve;
- the procedure's declared capabilities are supported by the driver binding;
- domain, context, worker, attachment, and in-flight operation quotas have room;
- declared exclusive resources and driver serialization keys do not conflict;
- scheduling, priority, and separation-of-duty policy permit admission; and
- required time, telemetry quality, and external dependencies are healthy.

Admission reserves capacity transactionally before worker dispatch. A queued
execution has an immutable admission request, priority class, enqueue time, and
reason for every deferral. Priority does not preempt an externally effective
operation. Starvation bounds and operator-visible queue ordering are deployment
parameters and shall be qualified.

Concurrency is explicit at four layers:

1. **Domain:** maximum active executions and aggregate resource budget.
2. **Context:** attachment and lifecycle operation limits for one satellite.
3. **Driver capability:** maximum in-flight calls and named serialization keys.
4. **Procedure:** declared exclusive resources, child-procedure limits, and
   safe-point behavior.

An exceeded limit returns or records typed `RESOURCE_EXHAUSTED` or remains in a
visible queue. It never silently oversubscribes the driver.

## Bundle Load And Worker Isolation

The loader verifies bundle digest, signature or integrity evidence, approval,
language profile, dependency lock, and compatibility profile. It translates
approved source to a versioned data-only IR before runtime. Unsupported Python
syntax, dynamic import, code generation, native extension, shell access, and
unbounded reflection fail validation with stable source diagnostics.

Each admitted execution runs in exactly one dedicated low-privilege process or
container sandbox with its own workload identity, crash domain, writable root,
and bounded CPU, memory, file descriptors, wall time, and output. A worker
manager may create many sandboxes but cannot evaluate multiple executions in
one sandbox or share their memory, identity, writable storage, or credentials.
Network is denied except for the narrow supervisor runtime channel. Sandboxes
cannot read service credentials or write PostgreSQL. They emit checkpoint
proposals and typed operation requests; the supervisor commits them.

## Context And Driver Attachment

Lifecycle ordering preserves the documented context and per-execution setup
intent:

1. Start a driver host with one immutable host profile and new host generation.
2. Open a context generation, applying configuration setup first and declared
   context hooks in order.
3. Bind the context generation to the exact host generation and negotiated
   capability set.
4. Attach an execution, applying procedure configuration first and attachment
   hooks in order.
5. Bind effecting capabilities to the current EAP identity and effect boundary.
   The driver host receives only typed EAP access and no GCS effect credential
   or route.
6. Permit typed runtime operations only after the attachment commits active.
7. On finish, abort, reload, or unload, stop new work, settle operations, run
   attachment cleanup in reverse order, and clean configuration last.
8. Close the context only after attachments settle or are explicitly fenced;
   run context cleanup in reverse order and configuration cleanup last.

Every cleanup result is typed and audited. One cleanup failure does not suppress
later cleanup. A failed or timed-out cleanup leaves a visible degraded or
uncertain disposition and does not erase prior operation certainty.

## Command And Operation Settlement

Internal control commands have these canonical states:

`RECEIVED`, `VALIDATING`, `ACCEPTED`, `WAITING_SAFE_POINT`, `APPLYING`, and
`RECONCILING`; terminal states are `SETTLED`, `REJECTED`, `CANCELLED`,
`SUPERSEDED`, and `FAILED`. An HTTP success for acceptance does not claim that
asynchronous work has applied. External effect operations use the separate
`REQUESTED`, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, and terminal `SETTLED`
stage model.

Every effecting attempt separately records one of exactly four certainty values:

| Certainty | Meaning | Retry rule |
| --- | --- | --- |
| `NO_EFFECT` | EAP and integration evidence durably prove the attempt produced no external effect | Retry may be authorized by capability policy with a new `AttemptId` |
| `EFFECT_CONFIRMED` | Effect and result are durably known | Return recorded result; never repeat |
| `EFFECT_POSSIBLE` | Effect may have occurred but acknowledgement is absent or incomplete | No automatic retry; reconcile or require authorized settlement |
| `EFFECT_UNKNOWN` | Integrity or adapter evidence cannot determine effect | Fail closed; no automatic retry; escalate and reconcile |

`NOT_ATTEMPTED` may be retained as a pre-dispatch disposition fact; it is not an
operation stage or effect-certainty value. Read-only operations declare a
separate `effect_class=NONE` and do not fabricate an
effect-certainty result. Absence is not a fifth certainty enum.

`OperationId` identifies one logical effect intent and one canonical request
digest. `AttemptId` identifies one dispatch attempt, is globally unique, and is
bound to exactly one operation. A retry is permitted only after authoritative
evidence sets the prior attempt to `NO_EFFECT`; it retains `OperationId` and
digest, increments `AttemptNumber`, creates a new opaque `AttemptId`, and binds
that attempt to the then-current assignment, authority, leader, controller,
driver, and execution tuple. Each prior attempt and its historical tuple remain
immutable. A successor `OperationId` represents new intent and cannot be used as
a retry or to bypass a possible or unknown effect. A duplicate `OperationId`
plus `AttemptId` returns the recorded disposition and never dispatches again.

The gateway, driver host, and EAP carry `OperationId`, `AttemptId`, `SatelliteId`,
`DomainId`, `AuthorityIncarnationId`, assignment generation and grant revision,
leader epoch, controller lease/session/client proof and
`control_fencing_token` when human authority is required, host/context/
attachment generations, driver binding, canonical request digest, evidence
revision/digest, and deadline. The driver host calls the EAP and has no GCS
effect credential or route.

The EAP opens a primary-PostgreSQL transaction and locks the assignment, local
domain state, leadership, current lease, operation, attempt, local permit,
binding, and execution rows. The local domain must be `ACTIVE` or effect-capable
`DEGRADED`, never `DRAINING`. With those locks held, it consumes a linearizable
signed one-use SAA attempt permit
for the current effect-enabled grant and full tuple. SAA rejection or ambiguity
rolls back with no local permit. The EAP then revalidates database-time guards
and commits the local dispatch-permit receipt, SAA receipt, complete journal,
audit/outbox evidence, and `EFFECT_POSSIBLE` by compare-and-set. A local
transaction proven not to commit abandons the SAA permit permanently; an
indeterminate commit blocks send and every new attempt pending reconciliation.
After a proven commit the EAP sends immediately using its exclusive GCS
credential.

Assignment changes serialize against the SAA consume; leader and controller
terminal changes serialize against the local row locks. If both consumes and
the local commit win, later authority loss cannot erase the in-flight attempt
and it must settle or reconcile. If either authority change wins, dispatch is
rejected before effect. A crash or timeout after local commit remains
`EFFECT_POSSIBLE`; there is no automatic retry.

## Safe Points And Interactive Control

Pause, abort, skip, goto, reload, user actions, and prompt settlement apply only
at defined interpreter safe points. Each accepted request records whether it is
pending, applied, rejected, superseded, or made impossible by a terminal state.
An attempt whose EAP dispatch permit committed is conservatively classified
`EFFECT_POSSIBLE`: send may follow immediately or may already have occurred, so
the boundary and effect cannot be assumed untouched. The attempt is allowed to
settle or reconcile and is not erased or presumed cancelled by later lease,
authority, or presentation changes.

`kill` from the legacy UI is not a routine runtime transition. An administrative
worker termination produces an audited crash/recovery disposition and cannot be
reported as a clean abort. Reload creates a new attachment generation and may
reuse only state explicitly declared compatible by the language profile.

## Recovery Algorithm

On domain-leader replacement or authority-bearing supervisor restart:

1. Reserve a newly anchored satellite assignment and authority incarnation as
   an effect-disabled target; issue no effect credential, route, permit, or
   controller authority.
2. Prove the prior EAP/GCS or inventoried legacy effect path externally fenced
   with evidence bound to that reserved target. Apparent process, host, or site
   loss is insufficient.
3. Acquire leadership under the reserved identity, increment the domain epoch,
   and mark prior-incarnation and prior-epoch work fenced from new writes and
   effects.
4. In PostgreSQL, revoke or invalidate the prior-incarnation controller lease,
   increment its revision, clear the current pointer, and move affected
   executions to `SUSPENDED` with `hold_reason=CONTROL_LOST`.
5. Read executions, commands, prompts, reservations, checkpoints, operations,
   attempts, and both SAA/local permit receipts from PostgreSQL.
6. Query EAP, driver, and GCS reconciliation journals by stable `OperationId`,
   `AttemptId`, and the full authority/generation tuple.
7. Abandon but never reuse an SAA attempt permit whose local transaction is
   proven absent. Treat an uncertain local commit as reconciliation work.
8. Release reservations only after associated work has a durable disposition.
9. Validate and stage the latest compatible atomic checkpoint without executing
   or resuming procedure work. For an uncertain external effect, retain
   `SUSPENDED` with `hold_reason=EFFECT_RECONCILIATION`; do not re-evaluate the
   effecting step.
10. Publish committed recovery transitions and pass local safety-readiness while
    the incarnation remains non-active and without a controller.
11. Only after the SAA verifies fence, epoch, reconciliation, and readiness
    evidence does it activate the reserved grant and issue fresh EAP dispatch
    credentials; driver hosts receive no GCS credential. The domain then enters
    `ACTIVE` without a controller. New-lease acquisition, required
    acknowledgement, and explicit resume are separate actions.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| SRV-013 | Each server domain shall bind exactly one immutable satellite identity and one current server-profile revision. |
| SRV-014 | Service leadership and human execution control shall use separate leases and separate monotonic fencing values. |
| SRV-015 | The leader shall use authoritative database time for lease expiry and shall reject a stale leader epoch or stale `control_fencing_token`. |
| SRV-016 | A domain shall expose its state, leader epoch, configuration digest, dependency health, degradation policy, and admission capacity. |
| SRV-017 | Forced control takeover shall require dedicated authorization, a recorded reason, a new `control_fencing_token`, and operator-visible notification. |
| SRV-018 | Context, host, binding, and attachment configuration shall be immutable within a generation and identified by schema version and digest. |
| SRV-019 | Cleanup shall be best effort across all registered hooks but shall preserve each typed result and any uncertainty. |
| SRV-020 | Stale host, context, binding, attachment, leader, and controller generations shall be rejected before any external effect. |
| SRV-021 | Domain and controller-lease behavior shall be defined by checked-in machine-readable state models whose legal transitions, guards, effects, and rejection outcomes match the normative human-readable contract. |
| SRV-022 | A domain shall become command-active only while holding a valid mission-wide satellite assignment grant for its `DomainId`, `SatelliteId`, `AuthorityIncarnationId`, and assignment generation. |
| EXEC-015 | Every execution shall reference one immutable bundle digest, language profile, context generation, and independent execution ID. |
| EXEC-016 | Execution transitions shall be durable compare-and-set operations with revision, actor or service identity, reason, timestamp, leader epoch, audit, and outbox event. |
| EXEC-017 | The scheduler shall enforce named domain, context, worker, driver, and procedure constraints before admission. |
| EXEC-018 | A worker shall have no general network, database, shell, host filesystem, or service-credential access. |
| EXEC-019 | A public mutation shall have a stable command ID and idempotency key and shall expose acceptance separately from application and settlement. |
| EXEC-020 | Externally effective operations shall have stable operation IDs, generation fences, effect-certainty states, and adapter reconciliation where supported. |
| EXEC-021 | An operation in `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` shall never be automatically resent. |
| EXEC-022 | A durable prompt shall settle at most once by compare-and-set and shall retain timeout, controller, validation, and response evidence. |
| EXEC-023 | Controller loss shall follow a preconfigured, tested policy and shall default to preventing new interactive decisions and pausing at safe points. |
| EXEC-024 | Runtime recovery shall not release quota, repeat an effect, or resume beyond a checkpoint until associated commands and operations are durably reconciled. |
| EXEC-025 | Multiple instances of the same procedure shall retain independent IDs, variables, control state, logs, checkpoints, and terminal outcomes. |
| EXEC-026 | Administrative worker termination shall be represented as failure and recovery evidence, not a successful procedure abort. |
| EXEC-027 | Execution, command, prompt, driver-operation, and effect-certainty state machines shall be versioned, machine-readable, exhaustively transition-tested, and rejected on unspecified states or transitions. |
| EXEC-028 | Each admitted execution shall run in exactly one isolated process or container sandbox with its own identity, limits, writable storage, and crash domain; a worker manager shall not co-host multiple executions in one sandbox. |

## Verification Hooks

- Race tests renew, expire, release, revoke, and forcibly replace control leases
  while old commands remain in flight.
- State-machine property tests generate all command/state races and prove that
  no illegal transition commits and each command reaches one durable outcome.
- Scheduler tests exercise every quota and serialization key, including crash
  recovery before and after reservation.
- Worker escape tests probe network, filesystem, process, import, native-code,
  resource-exhaustion, and credential boundaries.
- Driver fault tests terminate gateway and host processes before journal intent,
  after intent, after effect, after result, and before acknowledgement.
- EAP tests terminate before and after SAA permit consume, local transaction
  commit, GCS send, and acknowledgement. They prove abandoned SAA permits are
  never reused and a crash after local commit remains `EFFECT_POSSIBLE`.
- Race tests serialize the SAA consume against assignment transitions and the
  local consume against lease/leader transitions, proving either a rejected
  `NO_EFFECT` attempt or one retained in-flight attempt, never both.
- Retry tests retain `OperationId` and digest, allocate a unique `AttemptId` only
  after `NO_EFFECT`, and reject successor IDs used to evade uncertainty.
- Recovery tests compare final state and audit evidence across clean execution,
  process restart, leader failover, and database failover.
