# Canonical State Machines

## Purpose And Authority

This document explains the versioned state models in
[`state-machines.json`](state-machines.json). The JSON file is the canonical
input for generated enums, guards, persistence constraints, API and event
schemas, diagrams, and exhaustive transition tests. This Markdown file defines
the interpretation and operational intent of that model. A generator or runtime
must not infer a transition that is absent from the JSON.

The repository and JSON `status` are `draft`. Canonical means there is one
unambiguous source for implementation and review within this draft; it does not
mean the design has passed its acceptance gates or become an authorized
operational baseline.

The model implements the state-contract portions of `SRV-021` and `EXEC-027`.
It also provides concrete guards for the allocated fencing, execution,
operating-mode, reliability, and verification requirements. The schema version
describes this model format; it is independent of product, API, event, language,
or driver-contract versions.

If generated output, prose, or implementation differs from the checked-in JSON,
the discrepancy is an architecture defect. Implementation stops until the model
and affected requirement or decision record are reviewed together. Unknown
states and unspecified transitions are rejected, preserved as bounded evidence,
and surfaced as an integrity alarm; they are never coerced to a convenient
state.

## Model Scope

The file defines six machines:

| Machine | Durable entity | Initial state | Terminal states |
| --- | --- | --- | --- |
| Domain | `DomainId` plus `AuthorityIncarnationId` | `STARTING` | `STOPPED`, `FAILED` |
| Controller lease | `ControllerLeaseId` | `ACTIVE` on atomic creation | `RELEASED`, `EXPIRED`, `REVOKED`, `TRANSFERRED` |
| Execution | `ExecutionId` | `REQUESTED` | `FINISHED`, `ABORTED`, `ERROR` |
| Internal control command | `CommandId` | `RECEIVED` | `SETTLED`, `REJECTED`, `CANCELLED`, `SUPERSEDED`, `FAILED` |
| Durable prompt | `PromptId` | `CREATED` | `SETTLED` |
| External effect operation | `OperationId` | `REQUESTED` | `SETTLED` |

Every state entry has an explicit terminal flag. Every transition declares its
source, destination, trigger, participating actor set, preconditions, durable
effects, timeout behavior, recovery behavior, and stable rejection outcome.
The `from` field is an array so generators can expand one independently tested
edge for each source state.

Terminal means immutable for that entity identity. A terminal entity can still
receive reads, duplicate requests, audit annotations, or links from later work,
but it cannot transition. A restart creates a new `AuthorityIncarnationId`; a
rerun, reload, or recovery after terminal execution creates a new `ExecutionId`.

## Shared Mutation Envelope

Every authoritative transition uses one transaction to:

1. Validate the current Satellite Assignment Authority signature and its
   `DomainId`, `SatelliteId`, `AssignmentGeneration`, and
   `AuthorityIncarnationId` tuple.
2. Verify that `AssignmentGeneration`, `AuthorityIncarnationId`, and
   `LeaderEpoch` are current.
3. Verify the entity ID and expected revision.
4. For interactive mutations, verify `ControlLeaseRevision`, the unexpired
   controller lease, `ControlFencingToken`, and the session-bound
   `ClientInstanceProof` for its non-exportable proof-of-possession key.
5. Verify applicable `DriverHostGeneration`, `ContextGeneration`,
   `ExecutionAttachmentGeneration`, and `DriverBindingId` fences.
6. Evaluate every declared precondition against authoritative state.
7. Compare-and-set the state and increment the entity revision.
8. Append the audit event and transactional outbox event.
9. Commit before acknowledging application or publishing a projection.

An acceptance response does not claim application. A rejection never increments
the target revision. An idempotency replay returns the original command or
operation resource rather than applying another mutation.

Exact expected `ControlLeaseRevision` is checked when a command or human lease
mutation is accepted. It is not frozen through a later effect boundary: a
benign renewal or non-authorizing handover-request metadata transition may
increment the revision without changing the active controller grant.
Immediately before an external effect, `EFFECT_AUTHORIZATION_POINT`
opens a primary-PostgreSQL transaction and locks the current authority, domain,
leader, lease, operation, driver/execution, and local `EffectPermitId` records.
While
holding those locks, it asks SAA to linearly consume the one-use
`SaaAttemptPermitId` for the current `effect_enabled` grant. After a successful
SAA consume, it commits the local permit, signed SAA receipt, complete fence
evidence, and `EFFECT_POSSIBLE` before send. The accepted and current lease
revisions are both retained as evidence; revision inequality alone does not
reject the effect.

PostgreSQL lease changes serialize at PostgreSQL, and SAA revocation serializes
with permit consumption at SAA. If loss wins at its authority, dispatch rejects.
If consume and local commit win, later loss cannot erase the in-flight attempt.
The ordered protocol is recoverable but is not a distributed ACID transaction.

Only the Effect Authorization Point holds the satellite or GCS effect credential
and effect-capable egress. Loss of primary-database quorum, authoritative
freshness, online assignment validation, or sole-egress ownership rejects before
effect.

`MONITOR` is read-only. `EDITOR` changes procedure source through the Git
workflow and cannot mutate an active execution by an edit action. Neither actor
appears on a mutating transition. `CONTROL_REQUESTER` is a separate actor used
only by the dedicated handover-request contract for a controller-eligible human
currently in a non-control workspace. It has no execution, prompt, lease, or
effect authority until atomic transfer creates a grant for that subject,
session, and client key.

## Domain Authority

The domain machine applies to one authority incarnation of one Satellite
Control Domain. The logical domain and satellite identity outlive an
incarnation. Only the Satellite Assignment Authority allocates and advances
`AssignmentGeneration` and `AuthorityIncarnationId`, in a signed assignment that
binds the domain to one satellite. The incarnation progresses through startup,
standby, fenced active authority, explicit degradation, and drain. `FAILED` and
`STOPPED` close that incarnation permanently.

```text
STARTING -> STANDBY -> ACTIVE <-> DEGRADED
   |                     |           |
   |                     +-----------+-> FAILED  authority lost
   |                     |           |
   +-> FAILED             +-> DRAINING -> STOPPED
                              |
                              +-> FAILED
```

`ACTIVE` and effect-capable `DEGRADED` are the only states from which new
policy-authorized operational mutations may be admitted. `DRAINING` is
effect-disabled and permits
only settlement, reconciliation, cleanup, and its terminal domain transition.
`DEGRADED` is not a general warning state: it names a versioned reduced
capability set. Missing or unclassified safety prerequisites fail closed. The
only activation transition requires a never-before-active,
fresh SAA assignment and authority incarnation allocated outside restored
history, proof that every prior effect path is externally fenced, reconciliation
or durable hold of unresolved effects, and a fresh short-lived dispatch
authority. `HasEverBeenActive` then latches true.

A higher `AssignmentGeneration` or `LeaderEpoch`, assignment revocation,
expired leader lease, or inability to prove the current assignment or lease
immediately fences writes and external dispatch and terminally fails that
incarnation. It cannot return to `STANDBY`. Planned deactivation enters
`DRAINING` and ends `STOPPED`; reactivation always uses a new assignment
generation, `AuthorityIncarnationId`, and dispatch authority.

`DOM-007` enters local `DRAINING` only after the SAA linearly commits the same
grant to `DRAINING` with `effect_enabled=false` and returns signed proof. The EAP
also locks and checks that the local domain is `ACTIVE` or effect-capable
`DEGRADED`. If an earlier permit consume won, that one in-flight attempt settles
or reconciles; after SAA drain wins, no queued or delayed attempt can obtain a
new permit.

Service leadership and human execution control remain separate authorities.
The domain machine consumes controller-lease evidence but does not merge the
controller identity or fence into `LeaderEpoch`.

## Controller Lease State Model

The machine models each durable control grant as a separate
`ControllerLeaseId`. `AVAILABLE` is the derived domain projection when no
current unexpired grant exists; it is not a lease state and cannot be
reactivated. The domain current-lease pointer and each grant creation or
replacement commit atomically.

| State | Terminal | Meaning |
| --- | --- | --- |
| `ACTIVE` | No | Current unexpired grant; control is possible only while every session, client-proof, assignment, authority, revision, fence, and policy guard passes. One non-authorizing `REQUESTED` handover may coexist. |
| `HANDOVER_PENDING` | No | The current holder approved one named request; the requester must acknowledge responsibility before the deadline, and new external effects are blocked. |
| `RELEASED` | Yes | Holder voluntarily ended this grant. |
| `EXPIRED` | Yes | Database time reached the grant expiry before renewal committed. |
| `REVOKED` | Yes | Administrative, identity, assignment, authority, or integrity policy ended the grant. |
| `TRANSFERRED` | Yes | Atomic handover or forced takeover replaced the grant. |

```text
domain AVAILABLE projection -- acquire/reacquire --> new lease ACTIVE
                                                     |  |  |  |
                                renew, same ID/fence --+  |  |  +-> RELEASED
                                                         |  +----> EXPIRED
                                                         +-------> REVOKED
                                                         |
                    requester creates metadata only --+-> ACTIVE + REQUESTED
                                                         |       |
                    cancel/withdraw/decline/timeout --+       +-> holder approval
                                                                    |
                                                                    v
                                                             HANDOVER_PENDING
                                                                  |  |  |
                               cancel/withdraw/decline/timeout --+  |  +-> terminal loss
                                                                     +----> requester acknowledgement
                                                                            + atomic old TRANSFERRED
                                                                            + new ACTIVE lease

ACTIVE or HANDOVER_PENDING -- forced takeover --> old TRANSFERRED
                                                   + new ACTIVE lease
```

### Grant Creation

Acquisition and reacquisition create a new grant directly in `ACTIVE`; there is
no reusable `AVAILABLE` lease record. Creation requires:

- the current signed satellite assignment, `AssignmentGeneration`,
  `AuthorityIncarnationId`, and `LeaderEpoch`;
- an authorized holder subject and live session;
- a request-bound proof from the session's non-exportable
  `ClientInstanceKeyId`;
- trusted database time and a policy-valid lease term;
- acknowledgement of active executions, prompts, alarms, and uncertain effects
  on reacquisition; and
- an idempotency key reconciled before any repeat attempt.

The transaction allocates a new `ControllerLeaseId`, strictly increments
`ControlFencingToken`, initializes `ControlLeaseRevision` to 1, binds the holder
subject/session/client key, and installs the domain current-lease pointer.

### Renewal And Terminal Loss

Renewal retains `ControllerLeaseId` and `ControlFencingToken`, increments
`ControlLeaseRevision`, and calculates expiry from database time. Release,
expiry, and revocation also retain the fence, increment the revision, clear the
current pointer, and terminally close that grant. Voluntary release is distinct
from policy revocation so audit and operator projections do not conflate them.

Clock, identity, assignment, and authority events carry mutually authenticated
service evidence. Human lease actions carry an authorized session and
request-bound `ClientInstanceProof`; a service event cannot manufacture a
holder proof. Every expiry race uses the original database deadline. Restart
never extends the lease implicitly.

### Handover And Takeover

A controller-eligible user in Monitoring Mode acts as `CONTROL_REQUESTER` to
create one named request. Request creation validates that actor's session,
client key, proof, effective Controller capability, selected mode, expected
lease revision, reason, and deadline. It retains the old grant in `ACTIVE`,
increments its revision, and grants the requester no runtime or lease authority.
The current holder remains fully responsible and effect-capable.

The current holder then approves the exact request using a separate holder
proof. Approval records holder identity and trusted database time and moves the
grant to `HANDOVER_PENDING`. While pending, neither party can initiate a new
external effect. The requester must subsequently acknowledge the current
server, domain, satellite, executions, prompts, alarms, commands, unresolved
effects, and controller responsibility. An acknowledgement submitted before
holder approval or against a different projection digest is rejected.

The acknowledgement and transfer are one transaction. It records the
acknowledgement, marks the old grant `TRANSFERRED`, increments its revision
without changing its fence, creates a new `ACTIVE` grant with a new ID and
higher fence, binds the requester, replaces the current pointer, and appends
audit, outbox, and correlated mode-projection events. The new holder is projected
into Execution Mode; the former holder is projected into Monitoring Mode or an
authorized non-control fallback. Server fencing is effective at commit, before
browser delivery. Cancellation, requester withdrawal before approval, requester
decline after approval, request expiry, lease loss, revocation, or forced
takeover settles the request without creating a normal-handover successor.

A forced takeover uses the same atomic grant-replacement shape but additionally
requires dedicated privilege, configured separation of duty, reason, and
acknowledgement of active executions, prompts, alarms, and uncertain effects.
No timeout or retry can create a second successor.

Request, approval, acknowledgement, withdrawal, decline, cancellation, expiry,
and transfer source events include trusted event time; applicable human
subject/session/client-key identities; role attributes and policy revision;
server, domain, and satellite; request/approval/acknowledgement IDs; old and new
lease revisions and fences; reason, outcome, and correlation. A linked
independent-sink receipt binds the source event ID/digest and ingestion time.
Sensitive context is retained through safe digests and protected evidence
references.

### Final Effect Guard

Command and lease-mutation acceptance checks the exact expected
`ControlLeaseRevision`. Final effect validation deliberately does not compare
the current revision for equality with that accepted revision, because a benign
renewal may have advanced it. Instead, immediately before effect the Effect
Authorization Point starts a writable-primary transaction and locks the current
assignment projection, leader, lease pointer and grant, driver binding,
execution, operation, and local permit records. This serializes the local effect
decision with release, expiry, revocation, handover, and takeover. It requires:

- the same `ControllerLeaseId` recorded at acceptance;
- state `ACTIVE` and database time before `ExpiresAtDatabaseTime`;
- the same holder subject, session, and `ClientInstanceKeyId`;
- current `ControlFencingToken`, assignment generation, and authority
  incarnation; and
- an unconsumed one-use SAA attempt permit bound to the current `effect_enabled`
  grant, current assignment and authority incarnation, and fresh dispatch
  authority;
- an online SAA, current leader, current driver/execution generation tuple,
  writable primary database, and required synchronous quorum; and
- a request-bound `ClientInstanceProof` that validates for this effect.

While retaining the PostgreSQL locks, EAP asks SAA to linearly consume that
attempt permit. A failed SAA consume rolls the local transaction back. A
successful consume allows EAP to commit the local permit, SAA receipt, both
accepted and current lease revisions, and `EFFECT_POSSIBLE`; only then may it
send. If SAA consume succeeds but local commit fails, no send occurs and that SAA
permit is abandoned forever. A crash after local commit recovers as
`EFFECT_POSSIBLE`, never as permission to resend.

SAA consumption and PostgreSQL commit are ordered independent authority
decisions, not distributed ACID. Lease loss or SAA revocation that wins first
rejects dispatch; a later loss does not erase an already committed in-flight
attempt. Invalid control drives the affected execution to `SUSPENDED` with
`hold_reason = CONTROL_LOST`; `CONTROL_HOLD` is never a state. Browser, worker,
driver gateway, and driver host have no alternate effect credential or egress.

## Execution State Model

The execution states are fixed for schema version `1.0.0`:

| State | Terminal | Meaning |
| --- | --- | --- |
| `REQUESTED` | No | A new immutable run request and `ExecutionId` exist. |
| `VALIDATING` | No | Bundle, dependencies, policy, and compatibility are checked. |
| `ADMISSION_PENDING` | No | Validation passed; capacity and resource admission are pending. |
| `LOADING` | No | Worker, approved IR, context attachment, and initial checkpoint are loading. |
| `PAUSED` | No | Execution is at a committed operator-safe point. |
| `RUNNING` | No | Approved IR is executing between safe points. |
| `WAITING` | No | A durable time, telemetry, event, or child condition is pending. |
| `PROMPT` | No | The correlated durable prompt is open. |
| `INTERRUPTED` | No | A wait or operation was proved interrupted at a safe point. |
| `SUSPENDED` | No | A safety hold records `hold_reason` and `saved_resume_target`. |
| `RECOVERING` | No | Durable execution and effect evidence are being reconciled. |
| `STOPPING` | No | New work is closed while effects settle and cleanup runs. |
| `FINISHED` | Yes | Normal completion and required cleanup are committed. |
| `ABORTED` | Yes | Abort and required cleanup are committed. |
| `ERROR` | Yes | This run cannot safely continue. |

Every execution record carries machine-readable `State`, `ContextGeneration`,
`SourcePosition`, bounded `Variables`, `CallStack`,
`OutstandingOperationIds`, `ControllerRelationship`, and
`TerminalDisposition` in addition to its identity, revision, bundle, language,
assignment, authority, and leader fields. Nonterminal records retain a typed
not-terminal disposition rather than omitting the field.

A durable wait carries immutable `OriginalTarget`,
`AuthoritativeClockSource`, `UncertaintyPolicy`, and `ResumptionCondition`, plus
`WaitId`, revision, deadline, settlement identity, and
`ConsumedSequenceCursor`. Restart rebuilds observation from that cursor and
never substitutes restart time for the original target. Excess clock
uncertainty prevents settlement or resumption until authoritative time returns
or the pinned failure behavior settles the wait exactly once.

The normal path is intentionally not the only path:

```text
REQUESTED -> VALIDATING -> ADMISSION_PENDING -> LOADING -> PAUSED
                                                         |   ^
                                                         v   |
                                                       RUNNING
                                                        | | |
                                                        | | +-> WAITING
                                                        | +----> PROMPT
                                                        +------> INTERRUPTED

active nonterminal state -> SUSPENDED -> saved safe target
active nonterminal state -> RECOVERING -> reconciled safe target
active nonterminal state -> STOPPING -> FINISHED | ABORTED | ERROR
STOPPING -> SUSPENDED when cleanup or effect certainty is unresolved
```

### Control Loss

`CONTROL_HOLD` is not a state. Controller loss, expiry, revocation, or takeover
uses `SUSPENDED` with:

- `hold_reason = CONTROL_LOST`;
- the prior state in `saved_resume_target`;
- the last compatible checkpoint;
- the active prompt, wait, command, and operation references; and
- the controller, leader, and execution revisions that caused the hold.

Reacquisition does not itself resume execution. The new controller acknowledges
current executions, prompts, alarms, and uncertain effects. The hold cause must
be cleared, `ControlLeaseRevision`, `ControlFencingToken`, client-instance proof,
and all other fences must match, and the corresponding explicit transition must
restore `PAUSED`, `RUNNING`, `WAITING`, `PROMPT`, `INTERRUPTED`, or `STOPPING`.
Restoring `RUNNING` requires explicit resume unless an approved and tested policy
permits automatic resumption of pure computation.

### Pause While Waiting Or Prompting

Legacy behavior permits Pause from `WAITING` and `PROMPT`. The canonical model
preserves that behavior without discarding durable work:

- Pause from `WAITING` enters `PAUSED`, records
  `paused_resume_target = WAITING`, and retains the wait definition and cursor.
- Pause from `PROMPT` enters `PAUSED`, records
  `paused_resume_target = PROMPT`, and leaves the same prompt open but
  temporarily non-answerable.
- Original wait and prompt deadlines continue unless the pinned language
  profile explicitly says otherwise.
- A wait or prompt that settles during the pause updates the paused checkpoint
  by compare-and-set and changes `paused_resume_target` to `RUNNING`; the
  execution remains `PAUSED` until an explicit Run command.
- Run from that paused state restores the preserved `WAITING` or `PROMPT`
  entity. It does not create another wait or prompt.

### Safe Points

The model declares these safe points: `BEFORE_STATEMENT`,
`AFTER_PURE_STATEMENT`, `WAIT_BOUNDARY`, `PROMPT_BOUNDARY`,
`DRIVER_OPERATION_SETTLED`, `CHILD_JOIN_SETTLED`, and `CLEANUP_BOUNDARY`.
A safe point is a committed fact, not a source-line guess. The state, source
location, variables, call stack, wait or prompt correlation, consumed event
cursor, resource ownership, and last event sequence must agree.

No checkpoint can cross an operation in `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN`.
`CLEANUP_BOUNDARY` records cleanup progress but is not a general resumable
procedure checkpoint.

## Legacy Compatibility Mapping

The web projection may show legacy labels, but the authoritative store uses the
canonical states. The compatibility adapter uses this mapping:

| Legacy state | Canonical mapping | Compatibility rule |
| --- | --- | --- |
| `UNINIT` | `REQUESTED`, `VALIDATING`, `ADMISSION_PENDING`, or `LOADING` | Select by committed phase; never guess. |
| `LOADED` | `PAUSED` | `hold_reason` metadata identifies initial load and the first executable location. |
| `PAUSED` | `PAUSED` | Direct mapping. |
| `RUNNING` | `RUNNING` | Direct mapping. |
| `WAITING` | `WAITING` | Direct mapping with durable wait metadata. |
| `PROMPT` | `PROMPT` | Direct mapping with one open `PromptId`. |
| `INTERRUPTED` | `INTERRUPTED` | Claimed only after interruption is proved. |
| `RELOADING` | New execution in `LOADING` | The prior terminal execution remains unchanged and is linked as predecessor. |
| `FINISHED` | `FINISHED` | Terminal. |
| `ABORTED` | `ABORTED` | Terminal and published after cleanup. |
| `ERROR` | `SUSPENDED`, `RECOVERING`, `STOPPING`, or terminal `ERROR` | Recoverable detail is explicit; projected `ERROR` is terminal. |
| `UNKNOWN` | Observation quality, not execution state | Show stale, gapped, or unreconciled projection without mutating the execution. |

Legacy Reload and Recover appear to reactivate a terminal executor. The modern
contract instead allocates a new `ExecutionId`, pins a new attachment generation,
and links `predecessor_execution_id`. This preserves history, terminal
immutability, audit attribution, and idempotency.

## Allowed Command And State Matrix

The complete command policy is machine-readable. This compact table is the
operator-facing contract:

| Command | Allowed source | Result | Safe point |
| --- | --- | --- | --- |
| Start new | Domain controllable; no prior execution required | New `ExecutionId` in `REQUESTED` | No |
| Run | `PAUSED`, `INTERRUPTED` | `RUNNING`, or preserved `WAITING`/`PROMPT` | Yes |
| Pause | `RUNNING`, `WAITING`, `PROMPT` | `PAUSED`; preserve underlying wait or prompt | Yes |
| Step | `PAUSED`, `INTERRUPTED` | `PAUSED` at next statement boundary | Yes |
| Step over | `PAUSED`, `INTERRUPTED` | `PAUSED` after current call boundary | Yes |
| Skip | `PAUSED`, `INTERRUPTED` | `PAUSED` at validated successor | Yes |
| Goto | `PAUSED` | `PAUSED` at validated target | Yes |
| Interrupt | `RUNNING`, `WAITING`, `PAUSED` with interruptible target | `INTERRUPTED` only after confirmed interruption | Yes |
| Abort | Any nonterminal state except `STOPPING` | `STOPPING`, then `ABORTED` or visible `ERROR` | Yes |
| Finish | `RUNNING`, `PAUSED`, `WAITING`, `PROMPT` | `STOPPING`, then `FINISHED` if cleanup settles | Yes |
| Execute fragment | `PAUSED`, `WAITING`, `PROMPT`, `INTERRUPTED` | Approved bounded IR only; waiting/prompt use a child execution | Yes |
| Respond prompt | `PROMPT` and matching open `PromptId` | One prompt settlement | Prompt boundary |
| Acknowledge hold | `SUSPENDED` | Restore saved target only after reconciliation | Yes |
| Reload | `FINISHED`, `ABORTED`, `ERROR` predecessor | New `ExecutionId` in `REQUESTED` | No |
| Recover | `ERROR` predecessor and compatible checkpoint | New `ExecutionId` in `REQUESTED` | No |

There is no ambiguous generic Stop transition. An API or UI must request Abort
or Finish explicitly and display the resulting cleanup and terminal semantics.
Arbitrary Python entered through legacy Execute Script is rejected. The modern
compatibility action accepts only signed, allowlisted, bounded IR. From
`WAITING` or `PROMPT`, that action creates a separately admitted child
`ExecutionId` so the parent's durable condition is not overwritten.

## Internal Control Commands

A public mutation is a durable command resource, not a synchronous state flip:

```text
RECEIVED -> VALIDATING -> ACCEPTED -> WAITING_SAFE_POINT -> APPLYING -> SETTLED
                |            |              |                 |
                v            +-> CANCELLED  +-> SUPERSEDED    +-> RECONCILING
             REJECTED                                           |  |  |
                                                                |  |  +-> SUPERSEDED
                                                                |  +----> ACCEPTED
                                                                +-------> SETTLED
```

`ACCEPTED` means only that authorization, lease, fence, schema, target revision,
and command policy passed. It never means the execution changed. `APPLYING`
outcome uncertainty enters `RECONCILING`, which examines the target event and
revision by `CommandId`. A target transition found during recovery yields
`SETTLED`; proof that no application occurred can requeue the same command only
while its original guards remain true. Blind retry is prohibited.

Each command reaches one terminal disposition. A later, different operator
intent uses a new `CommandId`. The original idempotency key always returns the
original resource, including rejection or supersession.

The command record includes principal, session, client key, domain, assignment,
authority, leader, controller lease and accepted lease revision, fence, target,
expected target revision, reason, request digest, and exact rejection or result
fields. Validation selects exactly one stable public code from the JSON
taxonomy. It never exposes generic `COMMAND_GUARD_FAILED`.

The taxonomy distinguishes authentication, unauthorized role, expired session,
wrong domain, invalid client proof, inactive or expired lease, stale lease ID,
stale lease revision, stale fence, stale assignment, stale authority, stale
leader, duplicate conflict, idempotency conflict, resource revision conflict,
invalid schema, disallowed state, missing reason, terminal target, safety-policy
denial, capacity exhaustion, and timeout before acceptance. A same-key,
same-digest replay returns the existing command; a conflicting digest is a typed
conflict.

## Durable Prompts

The prompt machine deliberately has one terminal state:

```text
CREATED -> OPEN -> SETTLED
```

One compare-and-set from `OPEN` to `SETTLED` wins across validated answer,
cancellation, timeout, no-controller policy, execution termination, restart,
and failover. The settlement stores exactly one outcome:

- `ANSWERED`
- `CANCELLED`
- `TIMED_OUT`
- `NO_CONTROLLER`
- `EXECUTION_TERMINATED`
- `ERROR`

The unique `PromptId` and `SettlementId`, expected `PromptRevision`, current
execution correlation, database deadline, actor assurance, and controller fence
are retained as evidence. A losing responder receives the winning settlement
metadata, not permission to retry. Invalid values create a bounded separate
attempt record, do not change `PromptRevision`, and do not reset the deadline by
default.

Password and secret values never enter prompt plaintext events, logs, audit
payloads, browser persistence, or generic as-run exports. The settlement stores
only the protected result or secret reference permitted by the data policy.

## External Effect Operations

The operation state machine applies only when `EffectClass != NONE`. A typed
read-only request with `EffectClass = NONE` uses a separate bounded request and
result contract; `EffectCertainty` is absent and not applicable. `NONE` is not a
fifth certainty value.

An external effect operation has two independent dimensions:

1. **Stage:** `REQUESTED`, `ACCEPTED`, `DISPATCHED`, `RECONCILING`, or
   terminal `SETTLED`.
2. **Effect certainty:** `NO_EFFECT`, `EFFECT_CONFIRMED`, `EFFECT_POSSIBLE`,
   or `EFFECT_UNKNOWN`.

Stage never implies certainty. Transport success does not prove an effect, and
transport timeout or cancellation does not prove no effect.

The durable operation record includes the immutable `OperationId` and
`RequestDigest`, operation revision, deadline, effect class, current stage and
certainty, settlement data, and an append-only attempt history. Each attempt
record includes its `AttemptNumber`, opaque globally unique `AttemptId`, local
`EffectPermitId`, `SaaEffectEnabledGrantId`, one-use `SaaAttemptPermitId`,
conditional `SaaPermitConsumeReceiptDigest`, journal intent, evidence digests,
and its complete accepted authority and fence tuple. That tuple comprises the
SAA assignment observation, domain and satellite, assignment generation,
authority incarnation, dispatch authority, leader epoch, controller grant and
accepted revision, control fence and holder binding, driver-host generation,
context generation, execution-attachment generation, driver binding, execution
identity, and execution revision.

The accepted tuple is populated exactly once when its `AttemptId` enters
`ACCEPTED` and is immutable for that attempt. A later final-guard observation,
such as `CurrentControlLeaseRevision`, is retained as additional evidence and
does not rewrite the accepted tuple. No authority, generation, or fence field is
an immutable property of `OperationId`. `OperationId` and `RequestDigest` remain
unchanged across retry, while each attempt retains its own tuple and evidence.

| Certainty | Required evidence | Automatic resend |
| --- | --- | --- |
| `NO_EFFECT` | Authoritative proof that no external effect occurred | Only when capability policy, retry budget, and all fences permit it |
| `EFFECT_CONFIRMED` | Authoritative proof of the defined effect | Never |
| `EFFECT_POSSIBLE` | Dispatch authorization, the SAA receipt, and the local permit commit are durable before send; the boundary may have been crossed and an effect may have occurred | Never |
| `EFFECT_UNKNOWN` | Missing, contradictory, or integrity-invalid evidence | Never |

Before dispatch, the gateway journals the operation, attempt, request digest,
deadline, effect class, local and SAA permits, and complete authority, execution,
host, context, attachment, and driver-binding tuple. EAP then executes this
ordered protocol:

1. Open a primary-PostgreSQL transaction, acquire the current authority, domain,
   leader, controller lease, operation, driver/execution, and local-permit locks,
   and validate every local guard, including an effect-capable local domain
   state.
2. While retaining those locks, linearly consume `SaaAttemptPermitId` at SAA for
   the current `effect_enabled` grant.
3. Persist `SaaPermitConsumeReceiptDigest`, consume the local permit, record all
   accepted and current fence evidence, set `Stage = DISPATCHED` and
   `EffectCertainty = EFFECT_POSSIBLE`, and commit.
4. Only after confirmed commit, send through the EAP sole credential and egress.

A failed SAA consume rolls the local transaction back and sends nothing. If SAA
consume succeeds but the local commit fails, EAP sends nothing, abandons the
consumed SAA permit permanently, and reconciles before admitting a fresh attempt.
A crash after local commit remains `EFFECT_POSSIBLE`. SAA revocation and lease
changes serialize at their own authorities: a loss that wins first rejects, while
a later loss cannot erase an in-flight attempt. There is no distributed ACID
claim between SAA and PostgreSQL. A revision-only renewal or handover-request
metadata transition does not reject when every final lease guard still passes;
holder approval still rejects because it changes state to `HANDOVER_PENDING`.
Both accepted and current revisions are recorded.

Loss of an acknowledgment enters `RECONCILING`. The driver gateway queries the
private journal and any typed external reconciliation interface using the same
`OperationId` and `AttemptId`. It may settle as confirmed effect, proved no
effect, or remain possible/unknown. A retry is legal only after authoritative
`NO_EFFECT` proof under the declared capability policy. It retains the same
`OperationId` and `RequestDigest`, increments `AttemptNumber`, allocates a new
opaque `AttemptId` and new local/SAA permits, and binds that attempt to the
then-current authority, generation, leader, controller, driver, and execution
tuple. The new tuple may legitimately differ from the prior attempt's tuple;
the prior attempt, permits, receipts, tuple, and reconciliation evidence remain
unchanged in history.

Any transition to `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` without a confirmed
result moves the owning execution to `SUSPENDED` with
`hold_reason = EFFECT_RECONCILIATION` and a saved pre-operation target, or
`STOPPING` when cleanup had already begun. There is no uncertainty path that
merely says the execution is held without committing that hold.

An authorized unresolved disposition closes engine action without changing
`EFFECT_POSSIBLE` or `EFFECT_UNKNOWN`. It requires dedicated mission authority,
reason and impact evidence, and routes the owning execution to safe cleanup or
terminal error. It is not a successful operation and never permits automatic
continuation across the uncertain effect.

## Deterministic Restart Registry

The JSON restart registry is normative for every durable nonterminal resource:

| Resource | Stable recovery identity | Restart rule |
| --- | --- | --- |
| Command | `CommandId`, revision, idempotency key, target revision | Find target event, settle, safely requeue the same ID, supersede, or retain reconciliation. |
| Prompt | `PromptId`, revision, execution, deadline, settlement | Republish the same prompt or return its single winning settlement. |
| Reservation | `ReservationId`, execution, constraint digest, revision | Reconcile owner and hooks; never infer capacity acquisition or release. |
| Checkpoint | `CheckpointId`, execution, sequence, compatibility digest | Discard uncommitted proposals and resume only from compatible committed state before any uncertain effect. |
| Schedule | `ScheduleId`, occurrence, original target, clock, policy | Recompute the same occurrence and apply bounded misfire behavior. |
| Driver effect operation | Operation, attempt, request digest, local permit, SAA permit/receipt | Reconcile the same attempt and never resend without `NO_EFFECT`. |

A schedule preserves `OriginalTarget`, `AuthoritativeClockSource`,
`UncertaintyPolicy`, `ResumptionCondition`, and its pinned `MisfirePolicy`.
`OccurrenceId` is derived stably from schedule identity and scheduled target and
has one idempotency key. `SKIP`, `FIRE_ONCE`, and `CATCH_UP_BOUNDED` are the only
misfire policies; catch-up cannot exceed `MaximumCatchUpOccurrences`. A schedule
never fires while clock uncertainty exceeds policy, SAA or leader authority is
stale or unavailable, or a prior occurrence remains unresolved.

## Timers And Races

All operational deadlines use authoritative database time and are durable data.
Browser clocks, worker clocks, and transport deadlines may improve user
experience but cannot settle a state machine. Every non-null `timeout.timer`
value in the canonical JSON is one exact ID declared by that same machine; prose,
alternatives, and cross-machine timer names are invalid. A `null` timer means
that the transition has no timer and therefore requires `on_expiry = NONE`.

| Machine | Canonical timer IDs |
| --- | --- |
| Domain | `DOMAIN_START_DEADLINE`, `LEADER_LEASE_DEADLINE`, `DEGRADATION_DEADLINE`, `DOMAIN_DRAIN_DEADLINE` |
| Controller lease | `LEASE_MUTATION_DEADLINE`, `LEASE_RENEWAL_CUTOFF`, `LEASE_EXPIRY`, `HANDOVER_DEADLINE` |
| Execution | `VALIDATION_DEADLINE`, `ADMISSION_DEADLINE`, `LOAD_DEADLINE`, `SAFE_POINT_DEADLINE`, `WAIT_DEADLINE`, `EXECUTION_PROMPT_DEADLINE`, `HOLD_DEADLINE`, `RECOVERY_DEADLINE`, `STOPPING_DEADLINE`, `ERROR_CLOSURE_DEADLINE` |
| Internal command | `COMMAND_VALIDATION_DEADLINE`, `COMMAND_SAFE_POINT_DEADLINE`, `COMMAND_APPLY_DEADLINE` |
| Durable prompt | `PROMPT_OPEN_DEADLINE`, `PROMPT_RESPONSE_DEADLINE`, `NO_CONTROLLER_GRACE` |
| External effect operation | `OPERATION_ACCEPT_DEADLINE`, `OPERATION_RESULT_DEADLINE`, `OPERATION_RECONCILIATION_DEADLINE` |

`DEGRADATION_DEADLINE` is selected from the classified dependency and pinned
degradation policy; recovery does not extend it implicitly. `WAIT_DEADLINE` is
the original immutable deadline on the current `WaitId`.
`EXECUTION_PROMPT_DEADLINE` references the same durable database-time target as
the correlated prompt's `PROMPT_RESPONSE_DEADLINE`; it does not create another
clock or settlement authority. `HOLD_DEADLINE` is persisted from the hold reason
and pinned policy revision and cannot erase uncertainty or resume work.
`ERROR_CLOSURE_DEADLINE` is the single execution timer for terminal-error
closure from either `STOPPING` or `RECOVERING`; expiry permits closure only when
the required cleanup and visible-uncertainty evidence is already sufficient.

Every expiry is processed as another fenced compare-and-set transition. This
gives concurrent operator response and timeout, command application and cancel,
driver result and timeout, or leadership and drain exactly one durable winner.
Losing actors read the winner; they do not compensate by guessing.

Deadline recovery preserves the original target time. Restart does not extend a
prompt, recreate a wait, reset command order, reset an operation attempt, or
convert uncertainty to no effect.

## Cleanup And Recovery

Recovery first establishes a new authority fence, then prevents writes from all
older authorities, workers, and driver hosts. It reads the execution, command,
prompt, reservation, checkpoint, cleanup cursor, and operation journal before
choosing a destination.

Pure computation can resume only from a compatible atomic checkpoint. A wait is
rebuilt from its original target, authoritative clock, uncertainty policy,
resumption condition, deadline, and consumed-sequence cursor. An open prompt is
republished with the same `PromptId`. An internal command is reconciled against
the target revision and event. A schedule uses the same occurrence identity and
bounded misfire policy. An external operation is queried by the original
`OperationId`, `AttemptId`, local permit, SAA permit and receipt, and generation
tuple.

`STOPPING` closes new work and performs cleanup in reverse registration order,
with configuration cleanup last. Each hook has a bounded typed result. One hook
failure does not suppress later hooks. `FINISHED` and `ABORTED` are published
only after required cleanup dispositions are durable. An uncertain operation or
cleanup owner moves `STOPPING` to `SUSPENDED` with
`hold_reason = EFFECT_RECONCILIATION` and
`saved_resume_target = STOPPING`; it never manufactures a clean abort.

## Generated Code And Tests

The checked-in generator consumes `state-machines.json` in this order:

1. Parse strict JSON and reject duplicate keys, unknown top-level fields for the
   active schema, invalid UTF-8, and non-canonical enum spelling.
2. Verify that every actor, source state, destination state, timer, certainty,
   creation rule, command-policy reference, rejection code, restart-registry
   identity, and effect-permit field resolves.
3. Verify unique machine, state, transition, actor, and timer IDs.
4. Verify that initial states exist, all states have terminal flags, terminal
   states have no outgoing edge, and nonterminal states are reachable or have an
   explicit recovery-only rationale.
5. Generate enums, transition dispatch tables, guard interfaces, stable
   rejection codes, restart handlers, effect-permit transactions, database check
   constraints, OpenAPI/event fragments, diagrams, and test cases.
6. Compare generated output with committed golden files; any drift fails CI.

For every transition, tests generate at least these cases:

| Test class | Required assertion |
| --- | --- |
| Positive edge | All guards true commits exactly the declared destination, effects, audit, and outbox event. |
| Negative edge | Each guard false returns the stable rejection and leaves state/revision unchanged. |
| Unspecified edge | Every unlisted source/trigger pair is rejected. |
| Terminal property | No trigger can change a terminal entity. |
| Revision race | One expected-revision compare-and-set wins; losers observe the winner. |
| Authority race | Stale incarnation, leader, controller, host, context, attachment, and binding fences fail before effect. |
| Attempt binding property | Every accepted `AttemptId` has one immutable authority, generation, leader, controller, driver, and execution tuple; a retry binds a new attempt to current values without rewriting prior-attempt history. |
| Activation property | One authority incarnation enters the active/degraded envelope at most once; every later activation uses fresh SAA and dispatch authority. |
| Lease race | Renew, release, expiry, revoke, request/approve/acknowledge/withdraw/cancel/decline handover, takeover, and effect dispatch produce one current grant and a strictly monotonic fence. |
| Lease-metadata/effect race | A benign renewal or non-authorizing request-metadata revision advance preserves effect eligibility only for the same active, unexpired lease ID, holder binding, fence, authority, and valid request proof; holder approval wins by changing state and blocking effect. |
| Permit race | PostgreSQL local commit serializes with lease change, SAA consume serializes with SAA revocation, loss-first rejects, authorization-first remains one in-flight attempt, and no path sends before local permit plus SAA receipt commit. |
| Permit failure window | Failed SAA consume rolls back locally; SAA success plus local commit failure sends nothing and abandons the permit; crash after local commit remains `EFFECT_POSSIBLE`. |
| Idempotency race | Duplicate keys and IDs cause at most one target mutation or external effect. |
| Deadline race | Response/result and timeout produce exactly one settlement. |
| Restart race | Failure before and after intent, target commit, audit, outbox, effect, result, and acknowledgment reaches the declared recovery disposition. |
| Schedule restart | Original target, clock, policy, occurrence ID, and bounded misfire behavior are unchanged across every restart point. |
| Certainty property | `EFFECT_POSSIBLE` and `EFFECT_UNKNOWN` never dispatch a retry. |
| Cleanup property | All registered cleanup hooks run best effort in reverse order and terminal success is not published early. |

Model/property tests must walk every legal path and sample all interleavings of
commands, controller loss, leader replacement, prompt settlement, worker crash,
driver timeout, and cleanup failure. Production code cannot add an emergency
transition behind a feature flag; the state model, requirements trace, tests,
and migration plan change first.

## Versioning And Migration

A compatible model revision may add explanatory metadata, stable rejection
detail, or a transition whose old readers safely reject it. Adding or removing a
state, changing terminal status, widening an actor or source-state set, changing
an effect-certainty rule, or changing terminal behavior is a semantic change.
It requires:

- a new model schema or model semantic version as applicable;
- a data migration and rollback or forward-only plan;
- API and event compatibility analysis;
- web projection and operator-procedure review;
- legacy compatibility-ledger update;
- exhaustive old/new mixed-version tests; and
- approval before any rolling deployment.

Persisted state records carry the model schema version. A binary that does not
support that version refuses mutation while retaining read-only evidence. It
does not map an unknown value to `ERROR`, `UNKNOWN`, or another known state.
