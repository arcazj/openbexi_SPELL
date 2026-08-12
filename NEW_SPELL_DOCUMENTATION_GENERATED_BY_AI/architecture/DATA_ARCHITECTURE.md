# Data Architecture

## Decision Summary

PostgreSQL remains the transactional system of record for next-generation
SPELL. It provides the consistency, constraints, concurrency control, mature
high-availability tooling, and operational familiarity required for domain
leadership, controller leases, execution state, command disposition, prompts,
driver-operation certainty, audit, and transactional publication.

The architecture is deliberately not database-only:

- Git is the source authority for editable procedure text and review history.
- Object storage holds immutable promoted bundles, large reports, exported logs,
  and backup objects by digest.
- An optional broker accelerates event fan-out but is not authoritative.
- An optional time-series or analytics platform holds high-rate history and
  search projections but cannot authorize or settle a control action.
- A secrets service owns credentials and keys; PostgreSQL stores opaque
  references, not secret values.

The binding rationale and reconsideration criteria are recorded in
`decisions/ADR-001-postgresql-as-system-of-record.md`.

## Data Classes And Authorities

| Data class | Authority | Derived copies | Required consistency |
| --- | --- | --- | --- |
| Domain configuration and current revision | PostgreSQL, referencing approved configuration artifact | API caches | Serializable or compare-and-set updates |
| Service leader epoch and human controller lease | PostgreSQL | In-process read cache with short expiry only | Primary-consistent; database time |
| Mission-wide satellite assignment and authority incarnation | Signed Satellite Assignment Authority grant; locally recorded in PostgreSQL | Read-only deployment inventory | One active assignment per satellite across clusters; non-rollback incarnation |
| Execution, schedule, checkpoint, variables, and prompt state | PostgreSQL | REST and WebSocket projections | Transactional per state transition |
| Command and driver-operation disposition | PostgreSQL plus driver private effect journal where external atomicity is impossible | Operator projections and reports | Stable intent ID; immutable attempt history; progress ordered by `AttemptNumber` and per-attempt stage; explicit evidence refinement and reconciliation |
| Effect dispatch authorization | PostgreSQL attempt record plus the consumed one-use SAA permit receipt | Driver private effect journal and operator projections | One permit per immutable operation attempt; local authorization commits before send |
| Audit and transactional outbox | Append-only PostgreSQL records, with immutable archive export | Search index, SIEM, reports | Persisted in the same transaction as the represented change |
| Procedure source and review | Git | Developer working copies | Commit identity and protected promotion policy |
| Catalog promotion decisions | PostgreSQL promotion registry referencing Git and immutable bundle digests | Runtime catalog/search projection | Revisioned, idempotent, audited, outbox-published, HA-restored |
| Promoted bundle and validation evidence | Object storage by digest, with PostgreSQL metadata and approval | Integrity-checked runtime cache | Immutable content and digest verification |
| Current operational telemetry subset | PostgreSQL projection or bounded in-memory cache according to profile | WebSocket and UI | Source time, receive time, sequence, quality, validity, freshness |
| Procedure-consumed telemetry and alarm transitions | PostgreSQL execution evidence; bulk artifact as needed | Reports and analytics | Durable before dependent progress settles and before any influenced external effect is authorized |
| Full-rate telemetry history | Approved external source or optional time-series store | Aggregations | Source-defined ordering and retention; not control authority |
| Bulk as-run/support logs | PostgreSQL index and integrity manifest plus immutable object segments | Search index | Essential transition/audit rows remain transactional |
| Credentials and cryptographic keys | Approved secrets/key service | Short-lived process memory | Never in bundles, events, logs, configuration digests, or database fields |

## Logical PostgreSQL Model

The physical schema may evolve through migrations, but shall preserve these
bounded aggregates and constraints:

| Aggregate or table family | Key fields and constraints |
| --- | --- |
| `domains` | Unique `domain_id`, unique active `satellite_id`, current profile revision, state, leader epoch, health revision |
| `authority_incarnations` | Domain, satellite, globally unique `authority_incarnation_id`, signed assignment generation/grant digest, state, activation/deactivation time, external fence evidence |
| `domain_journal_heads` | Compound key (`domain_id`, `domain_stream_epoch`), where `domain_stream_epoch` equals the fresh `AuthorityIncarnationId`; last committed domain event position, initialized so the first committed position is 1; locked for commit-ordered range allocation within that epoch |
| `domain_leadership` | One current row per domain, epoch, holder workload identity, lease timing based on database time |
| `control_leases` | One `ACTIVE` unexpired grant per domain, authority incarnation, lease ID/revision, monotonic control fence, holder session/client proof-key binding, issue/renewal/expiry, state, disposition |
| `control_handover_requests` | At most one nonterminal request per current lease; request ID/revision/deadline, requester subject/session/client key and proof digest, current-holder approval identity/time, requester responsibility-acknowledgement identity/time/context digest, policy revision, reason, outcome, predecessor/successor lease IDs, and audit/outbox references |
| `contexts` and `context_generations` | Domain-scoped identity, immutable generation number, configuration schema and digest, lifecycle state |
| `driver_hosts` and `driver_bindings` | Host generation, implementation and contract versions, capability digest, exact context generation, lifecycle state |
| `procedure_bundles` | Digest, Git commit, language profile, dependency lock, validation evidence, approval and revocation state, object reference |
| `catalog_entries` and `promotion_decisions` | Stable procedure/catalog/environment identity, revision, prior/new immutable bundle digest, schedule policy, actor, reason, approval, idempotency, audit/outbox reference |
| `executions` | Domain, independent execution ID, bundle digest, context/attachment generation, canonical state, revision, position, terminal result |
| `execution_checkpoints` | Execution and monotonically increasing checkpoint revision, IR location, durable variables, pending interactions, evidence references |
| `schedules` and `reservations` | Canonical target time/condition, pinned bundle digest at schedule creation, catalog revision, clock metadata, priority, admission constraints, reservation ownership and settlement |
| `commands` | Domain-scoped command ID and idempotency scope, canonical request digest, expected revision, authority incarnation, assignment generation, leader/control fences, lease/client proof binding, stages and result |
| `prompts` and `prompt_responses` | Prompt schema, validation, deadline, defaults, warning policy, exactly one accepted settlement, actor evidence |
| `driver_operations` | Stable logical-intent operation ID, immutable request digest and effect class, current projection, reconciliation policy, settlement and result; it does not overwrite attempt history |
| `effect_dispatch_attempts` | Unique (`operation_id`, `attempt_id`) plus monotonic `attempt_number`; immutable request/evidence digest, effect class, SAA permit ID and signed consume receipt, attempt-specific authority incarnation and assignment generation, leader/controller/driver/execution fences, deadline, pre-effect journal intent, authorization state, dispatch time, certainty and reconciliation evidence; retry creates a new row bound to the then-current tuple, while every prior row remains immutable; a permit ID is globally unique and one-use |
| `variables` and `shared_values` | Typed value envelope, namespace, revision, classification, compare-and-set and authorization metadata |
| `telemetry_evidence` and `alarms` | Item identity, source/sample/receive time, sequence, raw/engineering typed value, quality, validity, freshness, consumed-by reference |
| `audit_records` | Immutable identity, actor/workload, action, target, before/after digest or safe delta, outcome, time, request/trace, classification |
| `outbox_events` | Unique compound event namespace (`domain_id`, `domain_stream_epoch`, `domain_event_position`), where the epoch equals `AuthorityIncarnationId`; event ID, aggregate and revision, schema, safe payload, commit time, and relay state independent of event retention |
| `authorization_projection_heads` | Opaque projection-scope ID, `ProjectionEpoch`, source `domain_stream_epoch`, authorization/policy/redaction and subscriber-filter digests, last contiguous projection sequence initialized so the first projected event is 1, retention, and freshness; any scope or digest change creates a new epoch |
| `authorization_projection_events` | Unique (`projection_scope_id`, `ProjectionEpoch`, `projection_sequence`), safe event identity and payload, aggregate revision, commit time, and cursor material; contains only events authorized for that scope and exposes no base-domain position |
| `artifact_manifests` | Object digest, size, media type, classification, retention, encryption metadata, creator and references |

Foreign keys, check constraints, unique partial indexes, and enum or reference
tables enforce invariants in addition to application validation. Every mutable
domain record includes `domain_id`. Row-level access policy or equivalent
database grants add defense in depth but do not replace application policy.

## Transaction Patterns

### State Change And Publish

The leader locks or compare-and-sets the aggregate revision, validates its
epoch and any controller fence, writes the new aggregate state, command/audit
evidence, and outbox event in one transaction. A relay publishes only committed
outbox rows. Relay duplication is harmless because event IDs are stable.

The base journal event namespace is the tuple (`DomainId`,
`DomainStreamEpoch`, `domain_event_position`). `DomainStreamEpoch` is exactly
the fresh `AuthorityIncarnationId` issued for that activation. Position 1 is the
first committed event in an epoch, and the compound tuple is unique. A numeric
position is commit-total only among events with the same domain and stream
epoch; it has no ordering or equality meaning across epochs.

Event positions shall follow commit visibility, not allocation time. The write
transaction locks the `domain_journal_heads` row for the exact (`DomainId`,
`DomainStreamEpoch`) with `SELECT FOR UPDATE`, allocates one contiguous range
for all events in that transaction, inserts those rows, and advances
`last_committed_event_position` in the same transaction. A later transaction in
that epoch cannot allocate or commit a higher position until the earlier lock
holder commits or rolls back. Rollback removes both the events and head advance.
PostgreSQL sequences, timestamps, broker offsets, event IDs, and positions from
another epoch shall not define journal order.

An internal base-journal snapshot reads `DomainStreamEpoch`, domain state, and
that epoch's `last_committed_event_position` from the same repeatable-read view.
Its internal cursor is a visibility watermark only for that exact epoch: replay
from positions greater than the watermark contains every later committed
matching event in the epoch. One transaction may emit zero, one, or multiple
events; only committed positions are observable. A cursor naming another epoch
is not compared numerically and receives `STREAM_EPOCH_CHANGED` with a mandatory
snapshot/reset disposition.

### Authorization Projection And Public Replay

A browser does not replay the base domain journal. A durable projector evaluates
authorization, redaction, classification, and policy before an event receives a
public projection position. It writes only authorized safe events into an
opaque per-authorization-scope projection and assigns a contiguous
`projection_sequence`, beginning at 1, under that scope's `ProjectionEpoch`.
The sequence is comparable only inside that epoch. An unauthorized base event
creates no projection row, sequence gap, cursor-advance frame, count, or timing
signal.

The projection scope binds the domain stream epoch, authorized subject/scope,
policy and redaction revisions, schema, and canonical subscriber-filter digest.
A change to authorization, policy, redaction, or filter digest creates a new
opaque projection scope and `ProjectionEpoch`; old cursors require a fresh
snapshot and cannot be translated by comparing sequence numbers. A public
snapshot reads the authorized materialized view and its projection head from one
repeatable-read view. Browser events and cursors carry projection identity and
sequence but omit `domain_event_position`.

A subscriber-selected filter is evaluated only over the already authorized
projection. When replay must cross authorized projection entries excluded by
that filter, a signed cursor-advance frame may cover a range of
`projection_sequence` values in the same `ProjectionEpoch`. It shall never name
or count base-domain positions. A heartbeat is liveness metadata and cannot
advance either journal or projection state.

### Idempotent Command

The idempotency scope and canonical request digest have a unique constraint. A
duplicate with the same digest returns the existing command. A duplicate with a
different digest is a conflict. Idempotency retention is longer than the
maximum client retry and audit correlation window and is never shortened by a
WebSocket acknowledgement.

### Controller And Leader Fencing

A new human control grant obtains the next `control_fencing_token` in the same
transaction that deactivates or supersedes the prior grant. A new service
leader obtains the next leader epoch only after its durable leadership
preconditions succeed. Every controlled write compares both applicable values.

A handover request alone leaves the old grant `ACTIVE`. Current-holder approval
changes it to `HANDOVER_PENDING`; requester responsibility acknowledgement then
participates in the single transfer transaction that terminalizes the old
grant, inserts the new higher-fence grant, replaces the domain current-lease
pointer, settles the handover request, appends audit and outbox evidence, and
records both affected authoritative session-mode projections. External
publication occurs from the committed outbox only after commit. Unique pointer
and nonterminal request constraints prevent a second controller or parallel successor.
Database counters alone cannot prevent reuse after point-in-time restore.
Every active authority also carries a globally unique
`AuthorityIncarnationId` obtained through the mission-wide Satellite Assignment
Authority after the restored history. That value is also the new
`DomainStreamEpoch`; activation creates a fresh journal-head row whose first
committed position is 1. Commands, events, cursors, worker and driver requests,
private journals, and reconciliation keys include the authority incarnation or
its exact stream-epoch alias. Positions from restored or prior incarnations are
retained only with their old compound namespace and are never compared with the
new epoch. A stale cursor receives `STREAM_EPOCH_CHANGED` and cannot authorize
replay, resume, or command activity.

### Effect Authorization And Dispatch

The approved Effect Authorization Point is the only component that holds the
external effect credential and network route. For each immutable
(`OperationId`, `AttemptId`), it starts a primary PostgreSQL transaction and
locks the current domain assignment/state, leader, applicable controller lease,
driver/execution fences, and operation, attempt, and local-permit rows. While
those locks remain held, it performs a linearizable SAA operation
that consumes one one-use attempt permit for the current effect-enabled
assignment generation. The SAA response binds the permit, satellite, authority
incarnation, assignment generation, operation attempt, request digest, and
expiry in a signed receipt.

If SAA permit consumption fails or any tuple, proof, policy, deadline, quorum,
or trusted-time check is invalid, the local transaction rolls back and no
effect is sent. If the SAA permit is consumed but the local transaction is
proven not to commit, the permit is abandoned and is never reused; no send is
allowed. An indeterminate local outcome blocks send and every new attempt until
reconciliation determines whether the commit occurred. On proven success, the
local transaction commits the consumed receipt, local permit, current fences,
pre-effect journal intent, command/audit evidence, outbox event, and
`EFFECT_POSSIBLE` before the Effect Authorization Point sends the request.
Later integrity loss may require `EFFECT_UNKNOWN`; stronger durable evidence may
settle the attempt as `NO_EFFECT` or `EFFECT_CONFIRMED`.

This protocol gives SAA revocation and PostgreSQL lease or leader changes an
explicit linearization order without asserting a cross-system ACID transaction.
The SAA and PostgreSQL records retain every consumed or abandoned permit and
attempt identity for reconciliation. Driver hosts, workers, browsers, and
public services have neither direct mission-link egress nor access to the effect
credential.

### Checkpoint And External Effect

Pure execution progress and variables commit atomically as a checkpoint. An
external effect cannot share the PostgreSQL transaction. A transport retry uses
the same operation and attempt IDs. An authorized effect retry is permitted only
after `NO_EFFECT`; it retains the stable operation ID and request digest and
creates a new immutable attempt ID under the authorization protocol above. The
integration boundary uses a write-ahead/after-effect journal. The execution
checkpoint records the canonical operation certainty and never advances past an
uncertain effect as if it were absent.

### Prompt Settlement

Prompt response validation and settlement use a unique accepted-response
constraint and expected prompt revision. Competing responses produce exactly
one accepted result; rejected attempts remain audit evidence without changing
the procedure result.

## Telemetry Strategy

Telemetry has different scale and authority characteristics from control state.
The platform shall not force every raw high-rate sample into the transactional
control schema. Instead:

1. The driver supplies typed item identity, source timestamp, receive timestamp,
   raw or engineering value, units, sequence, validity, quality, freshness, and
   clock uncertainty.
2. A bounded current-value projection supports UI snapshots and conditions.
3. Every sample actually used by a procedure decision, wait, verification,
   alarm transition, or report is durably associated with that execution or
   event before dependent progress settles. If it influences an external
   operation, the evidence IDs/revisions and decision digest commit atomically
   with the operation intent before dispatch authorization; the driver request
   references that evidence digest.
4. The full-rate stream may go to a qualified time-series or mission archive
   with explicit retention, replay, and gap contracts.
5. WebSocket telemetry may be sampled or coalesced only with visible source
   sequence and gap metadata.

The optional telemetry store cannot become the sole evidence for an execution
decision unless its integrity, availability, time, and replay contract is
explicitly promoted into the system authorization boundary.

## Object Storage And Git

Promoted procedure bundles, validation reports, dependency manifests, as-run
artifacts, and backup objects use content digests. PostgreSQL metadata records
size, media type, classification, encryption/key reference, retention class,
creator, creation time, and allowed domain. The bundle loader verifies bytes
against the digest before use and fails closed on mismatch or missing content.

Bucket versioning, retention lock where required, lifecycle policy, and denied
anonymous access are deployment requirements. Object storage availability is
not required to continue an already loaded execution when the approved bundle
and required artifacts are locally integrity-checked, but new loads fail if
their bytes cannot be verified.

Git branches are mutable collaboration state. Runtime metadata references an
immutable commit and promoted bundle digest. Deleting or rewriting a branch
does not rewrite historical as-run evidence.

## Optional Broker And Caches

A broker may carry outbox projections and high-rate observation streams. It
uses stable event IDs and domain partitions. Database replay repairs broker
loss. Broker acknowledgement never deletes authoritative outbox or audit data.

Caches may hold immutable bundles by digest, authorization inputs for a bounded
time, and read projections with explicit revision/freshness. Lease, leader,
prompt-settlement, command-certainty, and execution-transition decisions always
return to the authoritative write path. Cache failure is a performance event,
not a state-loss event.

## Partitioning, Indexing, And Retention

- High-growth outbox, audit, log index, telemetry evidence, and command-history
  tables are partitioned by approved time interval and, when necessary, hashed
  domain key.
- Current aggregates remain compact; history is append-only and moves to
  integrity-protected archives under an approved retention schedule.
- Primary indexes serve domain plus state/revision, idempotency lookup, pending
  work, time-based schedules, prompt deadlines, operation reconciliation, and
  event cursor scans.
- Index count and JSONB use are controlled by measured queries. Frequently
  constrained or joined fields are typed columns, not opaque JSON documents.
- Retention never deletes an object still referenced by a legal hold, active
  execution, unresolved operation, audit requirement, or retained as-run
  manifest.
- Purge jobs are authorized, bounded, resumable, audited, and tested against
  referential and archive integrity.

Exact storage, event, and retention budgets are deployment parameters. They
shall be set before qualification from mission procedure rates, telemetry
rates, concurrent users, audit requirements, and recovery windows.

## Encryption, Classification, And Data Minimization

Every schema and event field has an owner, purpose, classification, retention,
and redaction rule. Sensitive values are minimized and encrypted in transit and
at rest according to the deployed security profile. Field-level protection is
used where database or storage administrators must not see a value. Encryption
metadata refers to keys by managed identifier and epoch.

Logs and error records use allowlisted structured fields. Procedure values,
telemetry, source, prompts, and operator input are classified before export.
Secrets are never accepted in ordinary configuration payloads; secret-reference
fields are type-distinct and excluded from digests shown to unprivileged users.

## Schema Evolution

- All database changes use ordered, immutable, checksummed migrations.
- Expansion is deployed before code that writes new fields; contraction occurs
  only after every supported binary stops reading old fields and rollback
  windows close.
- Migrations are tested on empty, representative populated, maximum-size, and
  previous-release databases.
- Long-running changes use online patterns, bounded batches, progress markers,
  pause/resume, and measured lock budgets.
- Event and artifact schemas have independent versions and backward-compatible
  readers for the declared retention and rollback window.
- Backup restore is tested both before and after migration. Rollback never
  erases a command, effect-certainty, audit, or fencing record created by the
  newer version.
- Restore, failover, cutover, and failback retain historical journal tuples but
  create a new `DomainStreamEpoch`, a new head with no committed event so its
  first allocation is position 1, and new authorization `ProjectionEpoch`
  values. They never continue, offset, or numerically compare a restored journal
  or projection head.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| DATA-013 | PostgreSQL shall be authoritative for committed domain control, execution, command, prompt, driver-operation, audit, and outbox state. |
| DATA-014 | A state change, its command/audit evidence, and its publishable outbox event shall commit atomically. |
| DATA-015 | The schema shall enforce one active controller lease per domain, monotonic fencing and leader values, idempotency uniqueness, valid state transitions, and domain-scoped referential integrity. |
| DATA-016 | Every mutable record shall carry a revision and domain scope; every historical record shall carry immutable identity and authoritative timestamp. |
| DATA-017 | Git source, promoted bundle, runtime execution, and as-run evidence shall be linked by commit identity, dependency lock, language profile, validation result, and content digest. |
| DATA-018 | Object content shall be verified by digest before use and shall have classification, retention, encryption, and ownership metadata. |
| DATA-019 | Brokers, caches, replicas, search indexes, and analytics stores shall be replaceable derived systems and shall expose freshness and gap state. |
| DATA-020 | Procedure-consumed telemetry and alarm transitions shall be durable evidence with item, value, units, source/sample/receive time, sequence, quality, validity, freshness, and execution reference. |
| DATA-021 | Secrets and private keys shall be stored in an approved secrets/key service and shall not appear in general database fields, objects, events, logs, or bundle payloads. |
| DATA-022 | Retention and purge shall preserve active references, unresolved effects, audit obligations, legal holds, and as-run integrity. |
| DATA-023 | Migrations shall be ordered, checksummed, restartable where long-running, tested on populated data, and compatible with the approved rollback window. |
| DATA-024 | Database roles and network policy shall grant each service only its required schemas and operations; worker, browser, and driver-host identities shall have no database route. |
| DATA-025 | Backup and restore shall preserve immutable IDs, event positions, operation certainty, and artifact references; restored local fencing values shall remain subordinate to a newly allocated `AuthorityIncarnationId` and shall never authorize reuse. |
| DATA-026 | Storage and query capacity shall be measured against declared domain, execution, telemetry, audit, retention, and monitoring envelopes before production qualification. |
| DATA-027 | Event positions shall be unique and commit-ordered within `(DomainId, DomainStreamEpoch)`, allocated under that stream's journal-head lock in the same transaction as state, audit, outbox rows, and head advance; a snapshot cursor shall contain the epoch and head visible in the same repeatable-read view. |
| DATA-028 | The runtime catalog and promotion registry shall be authoritative PostgreSQL state with revision, idempotency, approval, immutable digest pinning, audit/outbox publication, HA, restore, and schedule references. |
| DATA-029 | Telemetry or alarm evidence influencing an external operation shall commit with the decision and operation intent before dispatch, and the driver request shall reference its evidence revision or digest. |

## Verification Hooks

- Property and database tests race lease acquisition, prompt settlement,
  idempotency reuse, revisions, admission reservations, and leader takeover
  against schema constraints.
- Outbox tests crash writers and relays at every transaction boundary and prove
  no committed state lacks an event and no event represents uncommitted state.
- Outbox ordering tests pause the transaction holding position `N` in one
  (`DomainId`, `DomainStreamEpoch`), attempt a competing commit in that epoch,
  then release or roll back `N`; snapshot plus replay shall neither skip the
  delayed transaction nor expose a higher same-epoch position first.
- Epoch tests activate, fail over, restore, cut over, and fail back, prove each
  new `DomainStreamEpoch` equals its fresh `AuthorityIncarnationId` and starts at
  position 1, and prove an old cursor receives `STREAM_EPOCH_CHANGED` without a
  numeric comparison.
- Authorization-projection tests interleave identical authorized events with
  varying unauthorized event counts and timing and prove public projection
  sequences, cursor frames, payloads, and observable progress disclose no
  unauthorized base position, count, or timing. Subscriber-filter advance
  frames may cover only authorized projection positions in one epoch.
- Effect-authorization tests race SAA revocation, leader takeover, controller
  expiry or replacement, operation retries, transaction rollback, and crashes
  before and after local commit. They prove no direct driver egress, no reused
  permit or attempt, no send before committed journal intent, and a conservative
  canonical certainty whenever outcome evidence is incomplete.
- Telemetry tests inject out-of-order, duplicate, stale, invalid, clock-uncertain,
  and gapped samples and verify procedure evidence and UI freshness.
- Migration tests cover clean install, representative production-like volume,
  interrupted migration, mixed binary window, backup restore, and rollback.
- Storage tests corrupt, replace, delete, and misclassify objects and prove
  integrity checks and retention prevent unsafe execution or evidence loss.
- Load tests measure primary write latency, lock contention, replica lag, outbox
  backlog, partition maintenance, and recovery under the qualified envelope.
