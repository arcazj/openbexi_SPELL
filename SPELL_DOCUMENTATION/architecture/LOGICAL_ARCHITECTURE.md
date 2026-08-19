# Logical Architecture

## Design Shape

The platform separates authoring, public access, domain control, execution,
integration, persistence, and observation. These are logical boundaries. A
small engineering deployment may co-locate compatible services, while a
high-availability deployment isolates and scales them independently. Co-location
does not weaken identity, authorization, transaction, or network rules.

## Component Model

| Component | Responsibility | Authoritative data | Scaling rule |
| --- | --- | --- | --- |
| Access edge | TLS termination, request bounds, origin policy, routing, and coarse abuse protection | None | Stateless horizontal replicas |
| Identity and policy adapter | Validates identity claims and evaluates roles, attributes, domain policy, and separation of duties | Policy versions and decisions are recorded; source policy may be external | Replicated read path; fail closed for mutations |
| Satellite Assignment Authority | Issues the sole signed command-authority grant for a satellite across clusters, sites, and legacy/new systems | Mission-wide assignment state; generation allocations carry signed non-rollback-anchor receipts | Linearizable quorum; unavailable authority prevents activation and new effects, not read-only observation |
| Public API | REST snapshots, queries, command acceptance, edit and promotion APIs | None outside database transactions | Stateless horizontal replicas |
| Stream gateway | Authorized WebSocket subscriptions, cursor replay, filtering, and backpressure | None; reads committed outbox/projections | Horizontal replicas partitioned by subscription load |
| Domain supervisor | Domain leadership, lifecycle, controller lease, health aggregation, and recovery coordination | Domain row, leader epoch, lease, recovery decisions | One authoritative leader plus passive candidates per domain |
| Execution scheduler | Admission, priorities, dependency checks, resource reservations, and worker assignment | Queues, reservations, schedules, and transitions | Partition by domain; only the domain leader commits decisions |
| Procedure sandbox | Evaluates exactly one admitted bounded-IR execution in an isolated process or container | No independent authority; checkpoint proposals become authoritative only when committed | One sandbox per execution; scale through a sandbox manager within quotas |
| Prompt service | Durable prompt creation, validation, timeout, and single settlement | Prompt state and settlement | Replicated API; settlement serialized by database revision |
| Driver gateway | Enforces typed capabilities, generation fences, deadlines, idempotency, and service identity | Operation ledger is in PostgreSQL; gateway memory is disposable | Partition by domain or driver binding |
| Driver host | Adapts typed driver calls and submits them to the EAP | Private protocol/idempotency journal where required; no GCS effect authority | Isolated by adapter and safety boundary; no GCS credential or route |
| Effect Authorization Point | While holding local authority rows, consumes one linearizable SAA attempt permit and one primary-PostgreSQL dispatch permit, then alone uses GCS effect credential and egress | Both permit receipts, attempt certainty, complete authority tuple, and reconciliation evidence | Partition by satellite/effect boundary with passive candidates; one effect-enabled path |
| Bundle service | Resolves approved immutable procedure bundles and dependencies | Metadata in PostgreSQL; content in object storage | Stateless reads with integrity verification |
| Projection and outbox relay | Converts committed state changes into ordered stream and audit projections | PostgreSQL outbox cursor | Multiple consumers with partition ownership; never controls runtime |
| PostgreSQL | Transactional system of record | Operational state, revisions, commands, effects, audit, outbox | HA primary with synchronous or policy-approved replication |
| Object storage | Immutable bundle payloads, reports, large log artifacts, and backup objects | Content bytes by digest; not live control state | Replicated according to deployment recovery class |
| Optional broker | Efficient event transport and fan-out | None | May be clustered; loss falls back to database replay |
| Optional telemetry/analytics store | High-rate history, search, and trends | Derived or adapter-origin telemetry history under explicit retention policy | Independent horizontal scale; cannot authorize commands |
| Observability stack | Metrics, service logs, traces, alerts, and audit export | Derived operational evidence | Independent; local safety does not depend on dashboard availability |

## Dependency Direction

```text
browser
  -> access edge
    -> public API ---------------------------> PostgreSQL
    -> stream gateway -> outbox relay ------> PostgreSQL

Git -> validation/promotion -> bundle service -> object storage
                                      |              |
                                      +----------> PostgreSQL metadata

non-rollback generation anchor <-> Satellite Assignment Authority
                                      |
                                      +-> signed activation grant -> domain supervisor

domain supervisor -> scheduler -> isolated execution sandbox
        |               |              |
        +---------------+--------------+
                        v
                  driver gateway -> driver host -> Effect Authorization Point
                        |                                  |              |
                        +----------> PostgreSQL <----------+              v
                                                                simulator/GCS adapter
```

The worker requests language operations from the supervisor-owned runtime
interface. It does not call the database or driver host directly. The gateway
accepts only internal workload identities, never browser tokens. A driver host
cannot initiate browser callbacks or database writes and cannot reach a GCS.
It calls the EAP over a typed, mutually authenticated interface. Only the EAP
holds the GCS effect credential and effect-capable egress.

## Control And Observation Planes

The **control plane** comprises API command acceptance, domain leadership,
controller leasing, scheduling, worker control, driver operations, and
authoritative persistence. It is conservative under uncertainty and has a
single writer per domain.

The **observation plane** comprises snapshots, real-time projections, read
replicas where permitted, log/search/analytics views, and external monitoring.
It can scale horizontally and degrade without granting control authority. A
projection carries freshness, source revision, and gap state so an operator can
distinguish current, stale, and incomplete information.

The **authoring plane** comprises Git integration, editors, parsers, dependency
analysis, validation, review, and bundle promotion. It never executes source as
general Python and cannot directly modify an active runtime catalog entry.

## Domain Partition

Every domain is keyed by immutable `domain_id` and `satellite_id`. An active
domain also carries the mission-wide `authority_incarnation_id` and
`assignment_generation` that permit its command path. All mutable
records include `domain_id`; globally shared tables contain only immutable
schemas, product metadata, or explicitly mission-wide policy. Database access
is constrained so a service assigned to one domain cannot accidentally update
another.

Within a domain:

- a monotonic `leader_epoch` fences service leaders;
- a monotonic `control_fencing_token` fences people holding execution control;
- a non-restorable `authority_incarnation_id` and mission-wide assignment
  generation, backed by a synchronous non-rollback-anchor receipt, fence other
  clusters, sites, restores, and legacy systems;
- an immutable `bundle_digest` identifies procedure behavior;
- `execution_id` identifies each independent instance, even when instances use
  the same procedure bundle;
- a `context_generation` and `driver_binding_id` identify the exact integration
  attachment; and
- every accepted mutation has `command_id`, idempotency key, actor, policy
  version, expected revision, and durable disposition.

The SAA ledger permits at most one `effect_enabled=true` record per satellite.
That record may represent an active SPELL assignment or an adopted pre-SAA
legacy path. `DRAINING` is always effect-disabled and permits settlement and
reconciliation only.

Replacing an authority incarnation atomically revokes or invalidates the old
controller lease, increments its revision, clears the current-lease pointer,
and suspends affected executions with `hold_reason=CONTROL_LOST`. The new
incarnation starts without a controller. Reacquisition creates a new lease and
higher fence and requires acknowledgement of active executions, prompts,
alarms, and uncertain effects before explicit resume.

## Write Path

1. Validate schema, authentication, domain scope, request size, and media type.
2. Authorize the operation against the current policy version.
3. Lock or compare the target revision and verify the satellite assignment,
   `authority_incarnation_id`, and domain `leader_epoch`.
4. For execution control, verify lease ID/revision, active state, expiry,
   `control_fencing_token`, and client-instance proof using database time.
5. Insert or resolve the idempotency record.
6. Apply the state transition and append audit and outbox rows in one database
   transaction.
7. Return the committed resource revision and command disposition.
8. Perform asynchronous work using the committed command identity. Later stages
   are also persisted before they are published.

No component acknowledges an authoritative state transition before its
transaction commits. A driver effect that cannot share this transaction uses a
durable operation journal and explicit certainty states rather than pretending
to be atomic.

## Effect Dispatch Path

1. The gateway creates or loads one `OperationId` and canonical request digest.
   Each admitted effect attempt has a new `AttemptId` and attempt number;
   transport retry of that attempt reuses both identifiers.
2. The driver host translates the typed adapter request and sends it to the EAP.
   It cannot contact the GCS directly.
3. The EAP locks the primary PostgreSQL assignment, leadership, current lease,
   binding, execution, operation, and attempt rows in canonical order.
4. While those rows are locked, the EAP calls a linearizable SAA operation that
   consumes one signed, one-use attempt permit for the current effect-enabled
   grant, grant revision, request nonce, full tuple, digest, and deadline. SAA
   rejection or ambiguity rolls back with no local effect.
5. The EAP revalidates leader, controller session/client proof/fence, integration
   generations, operation/attempt/digest, policy, database time, and deadline,
   then commits one local permit, both permit receipts, audit/outbox evidence,
   and `EFFECT_POSSIBLE` by compare-and-set.
6. If local commit fails, the SAA permit is abandoned and never reused. After a
   proven local commit, the EAP sends immediately using its assignment-bound GCS
   credential. Result and reconciliation evidence update the same attempt.

Lease release, expiry, revocation, handover, takeover, and leader replacement
serialize against the local consume on the same PostgreSQL rows. Assignment
disable/revocation serializes against the SAA consume. These are two ordered
linearization points, not a distributed transaction. If both consumes and the
local commit win, the attempt is authorized and in flight; a later authority
change cannot erase it and it must settle or reconcile. If either authority
transition wins, the corresponding consume rejects before effect. Loss of
primary write quorum, SAA permit service, trusted time, EAP credential, nonce,
or deadline rejects the attempt. A delayed request is never authorized by an
earlier API, gateway, or driver-host check.

Retry after authoritative `NO_EFFECT` evidence retains `OperationId` and the
request digest, increments `AttemptNumber`, and allocates a new opaque
`AttemptId` bound to the then-current assignment, authority, leader, controller,
driver, and execution tuple. The prior attempt and tuple remain immutable. A new
`OperationId` is new intent, not a retry. An operation with `effect_class=NONE`
uses a read-only EAP capability and has no effect-certainty value.

## Read And Stream Path

Snapshots may use a primary or a replica that satisfies the endpoint's declared
freshness requirement. Control screens default to primary-consistent reads.
Monitoring screens may use bounded-staleness replicas if the response exposes
the source revision, observed timestamp, and staleness status.

Stream gateways read committed outbox records directly or through an optional
broker. The broker is an accelerator. The canonical replay cursor remains tied
to the PostgreSQL outbox. A broker offset alone is not a public cursor.

## Failure Containment

- A worker crash affects its assigned executions, not the supervisor or other
  workers. Each affected execution moves to a durable recovery disposition.
- A driver-host failure degrades only its bindings and dependent operations.
- An EAP, SAA, generation-anchor, or primary-write failure blocks new effects;
  consumed attempts remain settlement/reconciliation work and other domains are
  isolated by their own authority and permit rows.
- A stream-gateway overload disconnects or coalesces qualified observation
  streams; it does not block control transactions.
- An authoring or Git outage prevents new promotions but does not invalidate
  already approved bundles in the runtime cache and object store.
- A domain leadership failure triggers passive takeover with a new epoch. It
  does not cause another domain to stop.
- Loss of PostgreSQL write quorum makes control mutations unavailable and
  fail-closed. Existing workers enter the configured safe-hold behavior and do
  not create unrecorded effects.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| ARC-011 | Each logical service shall have a documented owner, input contract, output contract, identity, timeout, retry rule, health signal, and data-access grant. |
| ARC-012 | Public API replicas shall not retain unique runtime state required to recover a command or subscription. |
| ARC-013 | Only the elected leader for a domain shall commit scheduler, execution, prompt, lease, or driver-operation transitions for that domain. |
| ARC-014 | Procedure workers shall operate on bounded IR and shall access runtime capabilities only through a supervisor-owned typed interface. |
| ARC-015 | Driver gateways shall reject browser identities, stale host/context generations, unsupported capabilities, and operations lacking a stable operation ID. |
| ARC-016 | Every authoritative state change and corresponding publishable event shall be committed atomically through a transactional outbox. |
| ARC-017 | Optional caches, brokers, replicas, indexes, and analytics stores shall expose freshness and shall not decide control authorization or state transitions. |
| ARC-018 | Domain-specific failures and resource saturation shall be contained by quotas, process boundaries, credentials, and queue partitions. |
| ARC-019 | Authoring and promotion services shall not obtain execution-control leases or driver credentials. |
| ARC-020 | A promoted bundle shall be immutable and verified by digest before load and after retrieval from object storage. |
| ARC-021 | Internal calls shall use workload identity, mutual authentication where the security profile requires it, explicit deadlines, bounded messages, and structured errors. |
| ARC-022 | A service shall not retry a non-idempotent or externally effective operation unless the contract proves the original attempt had no effect. |
| ARC-023 | Every projection used for operations shall carry enough revision, cursor, timestamp, and health information to identify stale or incomplete state. |
| ARC-024 | Cross-domain orchestration shall call each domain's public authorized contract and shall not write domain tables or reuse a control token across domains. |
| ARC-025 | Co-locating logical components shall not merge their service identities, authorization grants, audit responsibilities, or failure semantics. |

## Verification Hooks

- Dependency tests reject direct worker-to-driver, browser-to-driver,
  browser-to-database, driver-to-database, and driver-host-to-GCS traffic; only
  the EAP identity and egress path can reach the effect endpoint.
- Transaction tests inject process termination after each write-path step and
  prove that the returned disposition matches committed state.
- EAP race tests contend the SAA consume with assignment transitions and the
  local consume with leader/controller transitions, proving both ordering
  points, abandonment after local rollback, one `AttemptId`, and preserved
  certainty after every crash boundary.
- Assignment tests prove one effect-enabled SPELL or adopted legacy path per
  satellite and deny allocation when the non-rollback anchor is unavailable or
  ambiguous.
- Isolation tests saturate one domain's workers, driver queue, and streams and
  measure unaffected admission and latency in another domain.
- Consistency tests compare snapshots reconstructed from event replay with
  primary database projections at the same cursor.
- Promotion tests mutate or substitute object content and prove digest
  verification fails before execution admission.
