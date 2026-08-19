# ADR-004: REST For Commands, WebSocket For Projections, gRPC Internally

## Status

Proposed for the next-generation design baseline. It becomes accepted only when
the repository baseline is approved.

## Context

The web client needs snapshots, commands, procedure status, logs, variables,
telemetry, acknowledgements, alarms, prompts, and notifications in real time.
Internal workers and drivers need strict typed contracts, deadlines,
capabilities, identity, and bounded streaming. The legacy direct listener and UI
callback patterns do not provide modern authorization, replay, backpressure, or
effect-certainty semantics.

Using one bidirectional socket for everything would make mutation acceptance,
CSRF/origin policy, idempotency, revision checks, audit, retry behavior, and
recovery harder to reason about. Exposing an internal driver protocol to a
browser would also leak integration details and expand the attack surface.

## Decision

Use three deliberately separate protocol roles:

1. **HTTPS REST/JSON** for public snapshots, queries, controller lease actions,
   command acceptance, prompt response, authoring, validation, and promotion.
2. **Secure WebSocket** for server-to-client projections of committed events and
   qualified telemetry. Client frames only authenticate/renew a stream session
   or manage subscriptions; they cannot mutate runtime state.
3. **Protobuf/gRPC with workload identity and mutual authentication** for
   internal supervisor-worker and gateway-driver calls. These endpoints are not
   public routes.

OpenAPI, JSON Schema where needed, Protobuf schemas, error catalogs, and
compatibility tests are version-controlled release artifacts.

## Public Mutation Semantics

REST mutations require a stable idempotency key and expected revision. Execution
control also requires current lease ID and fencing token. The API commits an
accepted command, audit record, and outbox event transactionally and returns a
stable command resource. `202 Accepted` distinguishes acceptance from later
application and settlement.

A timeout or lost HTTP response is resolved by querying the idempotency key or
command resource. It is never grounds for blindly repeating an externally
effective action.

## Real-Time Semantics

A client first obtains a coherent snapshot and signed scoped cursor, then
subscribes from the cursor. Events are at-least-once committed projections with
stable event ID, contiguous per-subscription delivery sequence, aggregate
revision, cursor chain, commit time, domain, schema, and leader epoch. Base
journal order is unique within `(DomainId, DomainStreamEpoch)`; a new authority
incarnation creates a new stream epoch and stale-epoch cursors require snapshot
resynchronization.

Authorization filtering produces an opaque durable projection with its own
`ProjectionEpoch` and contiguous `projection_sequence`. It does not reveal
excluded base-journal positions, counts, or timing. Subscriber-selected filters
may advance only across positions in that already authorized projection.
Heartbeat frames never advance replay. The database outbox and authorized
projection checkpoint are replay authority; an optional broker is an
accelerator.

Canonical events are never silently dropped. A slow client is warned and
disconnected with a recoverable cursor. Qualified telemetry views may coalesce
or sample only when source sequences and gaps remain explicit. Cursor expiry or
continuity failure requires a new snapshot.

## Internal RPC Semantics

Every gRPC method declares:

- request/response schema and maximum size;
- caller and callee workload identities and authorization;
- deadline and cancellation behavior;
- idempotency and whether an external effect is possible;
- operation and generation identities;
- capability and version prerequisites;
- concurrency, serialization, and backpressure limits;
- structured error/result and effect certainty; and
- reconciliation after transport loss.

RPC cancellation only means the caller stopped waiting. It does not undo an
external effect. Reflection, generic invocation, public proxying, and arbitrary
driver-to-UI callbacks are disabled.

## Alternatives Considered

### WebSocket For Commands And Events

Rejected. It creates connection-coupled command identity and ambiguous retry,
complicates uniform policy/audit, and risks granting mutation through a monitor
subscription. REST plus command resources is easier to recover and test.

### REST Polling Only

Rejected as the primary observation mechanism because it produces unnecessary
latency and load for prompts, status, telemetry, alarms, and logs. REST remains
the recovery and snapshot path.

### Server-Sent Events

Viable for one-way events, but not selected as the primary transport because
the product needs bounded subscription changes, application cursor
acknowledgement, binary-capable future streams, and explicit bidirectional
session control. SSE could be added as a derived read-only adapter without
changing authority.

### Public gRPC Or gRPC-Web For Everything

Rejected. Browser/proxy support and enterprise inspection are less uniform,
driver contracts would become exposed, and public resource semantics are better
represented by REST. Internal gRPC remains appropriate for strict typed RPC.

### Broker Topics Exposed Directly To Browsers

Rejected. It leaks topology and credentials, weakens per-resource
authorization, and makes broker retention/offsets a public contract.

## Consequences

Positive:

- one clear, auditable mutation boundary;
- monitoring is structurally read-only;
- real-time views recover through snapshot plus cursor replay;
- internal contracts are typed and capability-aware; and
- public clients never learn driver endpoints or credentials.

Costs:

- clients implement both REST and WebSocket state synchronization;
- the platform maintains OpenAPI and Protobuf compatibility programs;
- outbox replay, cursor retention, and backpressure need operational capacity;
  and
- a command resource adds stages that the UI must present accurately.

## Guardrails

- WebSocket handlers have no call path to runtime mutation services.
- The browser cannot supply a driver host, topic, database query, or internal
  RPC method.
- Public and internal errors are allowlisted and redact sensitive detail.
- No transport-level success is treated as proof of external effect.
- The optional broker can be rebuilt from committed data and its offset is not a
  public cursor.
- API, event, and RPC version changes pass machine-readable backward-
  compatibility and mixed-version tests.

## Affected Requirements (Non-Normative Traceability)

This relationship list identifies central requirements potentially affected by
the decision; it does not allocate normative authority to this ADR. The
authoritative allocation is `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`.

`COM-001` through `COM-027`, `WEB-002` through `WEB-007`, `WEB-029` through
`WEB-037`, `MODE-004` through `MODE-005`, and `SEC-001` through `SEC-020`.

## Migration And Rollback

Version REST, event, cursor, and Protobuf contracts in parallel; old clients
remain on a bounded compatibility endpoint and cannot consume a cursor under
new stream-epoch or authorization-projection semantics. Rollback retains
committed outbox history and uses an explicit cursor reset when the older reader
cannot prove continuity without exposing unauthorized journal metadata.

## Approval

Pending Gate G0 approval under `OD-023` by the System Architect, Mission
Operations Authority, System Owner, Security Officer, Driver Authority, and
Quality Lead.

## Verification

- Static dependency and network tests prove WebSocket and browser identities
  cannot reach mutation or driver endpoints.
- Snapshot/event race tests prove replay yields the primary projection.
- Contract tests inject duplicates, gaps, reordering, slow consumers, cursor
  expiry, stream-epoch changes, authorization-scope changes, schema changes, and
  reconnect storms. Privacy tests prove authorization projections expose no
  excluded position, count, or timing metadata.
- Mutation tests terminate REST and gRPC connections at every stage and prove
  stable command/operation lookup prevents blind retries.
- Load tests qualify monitor scale while preserving control transaction and
  leader-fencing objectives.
