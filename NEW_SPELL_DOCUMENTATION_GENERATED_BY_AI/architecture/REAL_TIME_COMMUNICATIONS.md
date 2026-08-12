# Real-Time Communications

## Purpose

This document specifies the public REST and WebSocket contracts and the
internal gRPC boundary. The design supports procedure state, logs, events,
variables, telemetry, acknowledgements, alarms, prompts, and notifications
without making a transient connection authoritative.

## Protocol Allocation

| Protocol | Use | Prohibited use |
| --- | --- | --- |
| HTTPS REST/JSON | Resource snapshots, queries, command acceptance, lease operations, authoring, promotion, and recovery | Direct driver calls, unbounded downloads, or claiming asynchronous completion from request acceptance |
| Secure WebSocket | Server-to-client delivery from durable, already committed authorization projections and qualified telemetry streams | Client control commands, prompt responses, lease renewal, or any mutation |
| Protobuf/gRPC over mutually authenticated transport | Internal supervisor-to-worker and gateway-to-driver typed calls | Browser access, generic object invocation, arbitrary callbacks, or exposing driver reflection at the public edge |

REST remains available when WebSocket is impaired. Every control action is sent
through REST so authentication, authorization, idempotency, revision checks,
lease fencing, and audit occur at one acceptance boundary.

## Public API Conventions

- Base path: `/api/v1`.
- Content type: `application/json`; schemas are published in version-controlled
  OpenAPI and reject unknown security-sensitive fields.
- Timestamps: RFC 3339 UTC with explicit `Z` and sufficient precision for the
  source clock. Durations use ISO 8601 or a schema-defined integer unit, never
  an unlabelled number.
- IDs are opaque strings. Clients shall not infer type, order, or identity from
  formatting.
- Every response includes `request_id`; mutable resources include `revision`
  and `ETag`.
- Mutations require `Idempotency-Key`, `If-Match` or explicit
  `expected_revision`, and the active controller lease fields when they affect
  execution.
- Errors use a stable problem document with `code`, `title`, `status`,
  `request_id`, optional safe `detail`, `retryable`, and field violations.
- Pagination uses opaque cursors and fixed server-side maximum page sizes.
- Clients cannot select backend hostnames, ports, driver endpoints, database
  queries, filesystem paths, or arbitrary event topics.

## Principal Resources

The minimum runtime surface includes:

```text
GET  /api/v1/domains
GET  /api/v1/domains/{domain_id}
GET  /api/v1/domains/{domain_id}/snapshot
POST /api/v1/domains/{domain_id}/control-leases
POST /api/v1/domains/{domain_id}/control-leases/{lease_id}/renew
DELETE /api/v1/domains/{domain_id}/control-leases/{lease_id}

GET  /api/v1/domains/{domain_id}/executions
POST /api/v1/domains/{domain_id}/executions
GET  /api/v1/domains/{domain_id}/executions/{execution_id}
POST /api/v1/domains/{domain_id}/executions/{execution_id}/commands
GET  /api/v1/domains/{domain_id}/commands/{command_id}

GET  /api/v1/domains/{domain_id}/prompts
POST /api/v1/domains/{domain_id}/prompts/{prompt_id}/responses
GET  /api/v1/domains/{domain_id}/events
GET  /api/v1/domains/{domain_id}/logs
GET  /api/v1/domains/{domain_id}/telemetry
GET  /api/v1/domains/{domain_id}/alarms
GET  /api/v1/domains/{domain_id}/driver-bindings
GET  /api/v1/domains/{domain_id}/driver-operations/{operation_id}
```

The exact authoring and administrative surfaces are specified in their owning
documents. All resources use the same identity, revision, pagination, and
problem conventions.

## Mutation Acceptance

A mutation request contains at least:

```json
{
  "expected_revision": 42,
  "authority_incarnation_id": "opaque-incarnation-id",
  "control_lease_id": "opaque-lease-id",
  "control_lease_revision": 8,
  "control_fencing_token": 17,
  "action": "pause",
  "reason": "operator requested safe hold"
}
```

Interactive mutations also carry the client-instance ID and a proof signature
over method, resource, canonical body digest, idempotency key, server nonce, and
issued time. Proof material belongs in dedicated headers and is never accepted
from a different session, tab-local key, domain, or authority incarnation.

The `Idempotency-Key` is carried as an HTTP header and is scoped to authenticated
subject, domain, operation family, and a policy-defined retention period. Reuse
with the same canonical request returns the original command resource. Reuse
with different content returns `IDEMPOTENCY_CONFLICT`.

An asynchronously applied mutation returns `202 Accepted` and a command
resource. A synchronous compare-and-set, such as settling a prompt after all
validation succeeds, may return the updated resource, but still creates durable
command and audit evidence. HTTP timeout or connection loss never tells the
caller whether the request committed; the caller queries by idempotency key or
stable command ID before attempting anything else.

## Snapshot And Cursor Contract

`GET /domains/{domain_id}/snapshot` returns a coherent operational projection
and a cursor obtained from the same repeatable-read database view:

```json
{
  "schema_version": "spell.snapshot.v1",
  "stream_id": "opaque-subscription-incarnation",
  "domain_id": "opaque-domain-id",
  "domain_stream_epoch": "opaque-authority-incarnation-id",
  "snapshot_revision": 28419,
  "projection_scope_id": "opaque-authorization-projection-id",
  "projection_epoch": "opaque-projection-epoch",
  "projection_sequence": 1842,
  "authorization_policy_revision": 73,
  "authorization_scope_digest": "sha256:opaque-authorization-scope",
  "subscriber_filter_digest": "sha256:opaque-filter-digest",
  "snapshot_cursor": "opaque-signed-cursor",
  "generated_at": "2026-07-18T04:00:00.000Z",
  "freshness": "current",
  "resource_revisions": {
    "domain": 103,
    "executions": 991,
    "control_lease": 8
  },
  "domain": {},
  "control_lease": {},
  "executions": [],
  "commands": [],
  "prompts": [],
  "alarms": [],
  "driver_health": []
}
```

The server first selects an opaque durable projection for the authenticated
authorization scope. Authorization and redaction are evaluated before sequence
allocation: a denied base-domain event creates no projection entry, gap, count,
cursor frame, or timing signal. The snapshot request also declares the
projection classes and subscriber-selected filters. The server canonicalizes
the authorization, policy, redaction, and filter inputs and binds their digests
to a fresh projection scope and `ProjectionEpoch`.

The cursor encodes or references `stream_id`, `DomainId`, `DomainStreamEpoch`
(equal to the fresh `AuthorityIncarnationId`), opaque projection-scope ID,
`ProjectionEpoch`, last authorized `projection_sequence`, schema version,
policy and scope revisions/digests, subscriber-filter digest, and expiry. It is integrity
protected, conveys no authority, and exposes no `domain_event_position`. A
changed authorization, policy, redaction, or filter digest creates a new
projection scope and epoch and requires a fresh snapshot. Large collections may
be represented by consistent authorized collection revisions and fetched
through paged endpoints before subscription.

The base journal namespace is (`DomainId`, `DomainStreamEpoch`,
`domain_event_position`). Its position starts at 1 and is commit-total only
inside that exact epoch. Base positions are an internal persistence contract,
not a browser continuity field. A cursor from an earlier restore, failover,
cutover, failback, or other authority incarnation receives the typed
`STREAM_EPOCH_CHANGED` reset response. Neither server nor client compares its
numeric position with the new epoch. The response marks reset as mandatory and
directs the client to obtain a fresh snapshot; it does not return a translated
position or resume cursor.

The race-free client sequence is:

1. Fetch a snapshot and retain its cursor.
2. Open the WebSocket and subscribe from that cursor.
3. Buffer stream events while rendering the snapshot.
4. Apply events in cursor order.
5. On cursor expiry, `STREAM_EPOCH_CHANGED`, projection-scope or schema
   incompatibility, explicit gap, or authorization/policy/filter change,
   discard derived state and obtain a new snapshot.

## WebSocket Session

The endpoint is `/api/v1/stream`. Authentication uses the deployment's approved
short-lived browser credential mechanism. Credentials are not placed in query
strings. Origin checks, session binding, maximum message size, idle timeouts,
and reauthentication policy are enforced.

After connection, the client sends a bounded subscription request containing a
domain ID, snapshot cursor, and the same projection classes and approved
filters used for the snapshot. This subscription message changes only delivery,
never runtime state. A scope, policy, or filter mismatch is rejected with
`RESYNC_REQUIRED`; a base stream-epoch mismatch returns
`STREAM_EPOCH_CHANGED`.

Each canonical envelope contains:

```json
{
  "schema_version": "spell.event.v1",
  "event_id": "opaque-event-id",
  "stream_id": "opaque-subscription-incarnation",
  "domain_id": "opaque-domain-id",
  "domain_stream_epoch": "opaque-authority-incarnation-id",
  "projection_scope_id": "opaque-authorization-projection-id",
  "projection_epoch": "opaque-projection-epoch",
  "event_type": "execution.state.changed",
  "aggregate_type": "execution",
  "aggregate_id": "opaque-execution-id",
  "aggregate_revision": 43,
  "projection_sequence": 1843,
  "delivery_sequence": 918,
  "cursor": "opaque-next-cursor",
  "previous_cursor": "opaque-previous-cursor",
  "committed_at": "2026-07-18T04:00:01.120Z",
  "occurred_at": "2026-07-18T04:00:01.018Z",
  "correlation_id": "opaque-correlation-id",
  "causation_id": "opaque-command-id",
  "classification": "deployment-defined-label",
  "leader_epoch": 29,
  "payload": {}
}
```

`projection_sequence` starts at 1 and is contiguous in the durable authorized
projection for one `ProjectionEpoch`; numbering occurs only after authorization
and redaction.
`delivery_sequence` is contiguous within one subscription incarnation.
`previous_cursor` and `cursor` form the signed continuity chain. Event IDs
deduplicate delivery. Re-delivery is permitted; reordering within an aggregate
is not. Cross-aggregate replay order is available through projection sequence
within that epoch, while clients use aggregate revision when updating one
resource. Numeric projection sequences are never compared across epochs.

Unauthorized base-domain events produce no public frame and do not advance the
authorized projection. A subscriber-selected filter may exclude entries that
are already present in that authorized projection. To cross such entries, the
gateway may emit a signed `stream.cursor_advanced` frame carrying the next
contiguous `delivery_sequence`, a covered range of authorized
`projection_sequence` values in the same `ProjectionEpoch`, previous and next
cursors, and no excluded event metadata or source timestamps. It shall never
name, count, time, or advance across unauthorized base-domain positions. The
frame is derived from committed authorization-projection state and participates
in the same cursor chain.

Canonical event classes include:

- domain state, health, leader epoch, and control-lease changes;
- execution admission, state, position, checkpoint, variable, and terminal
  result changes;
- command acceptance, dispatch, application, rejection, and settlement;
- prompt creation, warning, validation, response, timeout, and settlement;
- driver binding, capability, health, operation stage, and certainty changes;
- audit-safe procedure messages, logs, mission events, notifications, and alarm
  changes; and
- telemetry snapshot or sample notices with source, sample sequence, time,
  quality, validity, and gap metadata.

Secrets, raw credentials, private keys, unrestricted exception text, sensitive
headers, and data outside the authorization projection are never event
payloads. Public envelopes and cursor-advance frames disclose no unauthorized
base-domain position, count, or timing.

## Delivery, Replay, And Backpressure

The database outbox is the canonical source for the internal epoch-bound domain
journal. The durable authorization projection is the browser replay source. A
broker may fan out its safe events, but broker offsets and base journal positions
are internal and cannot replace public cursors. Projection retention shall
exceed the approved maximum disconnection window. A cursor older than retained
projection history receives `CURSOR_EXPIRED` and requires a snapshot.

Delivery is at least once. Consumers deduplicate by `event_id` and apply only a
newer aggregate revision. The gateway sends periodic heartbeats containing
observed server time and liveness metadata. A heartbeat is not domain state,
does not carry a new cursor, and cannot advance replay position.

Each connection has bounded queues, byte rate, event rate, and subscription
count. For canonical control, audit, prompt, command, and alarm events, a slow
consumer receives a warning and is then disconnected with its last confirmed
cursor. Those events are never silently dropped. A qualified high-rate
telemetry view may sample or coalesce only when the envelope reports original
sample sequence, delivered sequence, coalescing mode, and every gap. Procedure-
consumed telemetry and alarm transitions remain durable evidence.

Clients may periodically acknowledge the last applied cursor for diagnostics
and queue management. Such acknowledgement is not an authorization or deletion
instruction. It does not shorten authoritative retention.

## Gap And Reconnection Behavior

A client shall resynchronize when:

- `delivery_sequence` is not the last applied value plus one;
- `previous_cursor` does not match its last applied cursor;
- the server emits `stream.resync_required`;
- the cursor is expired, invalid, for another domain, projection scope, or
  schema;
- `ProjectionEpoch` changes or a projected sequence discontinuity is not
  covered by a valid cursor-advance frame;
- `DomainStreamEpoch` changes and the server returns
  `STREAM_EPOCH_CHANGED`;
- aggregate revision moves backward or skips without an event type documented
  as a compacted projection; or
- authorization, policy, redaction, or filter digest changes and the gateway
  closes the subscription.

The browser never uses domain-position adjacency because an authorization
projection does not expose base positions. A subscriber-filter cursor-advance
frame may cover only committed authorized projection positions. Any
authorization, policy, or filter change creates a new projection scope/epoch
and requires a snapshot; a client cannot reuse or translate the old cursor.

Automatic reconnect uses bounded exponential delay with jitter and the last
applied cursor. It never retries a REST mutation. The UI presents a stale or
disconnected state until a snapshot and replay restore continuity.

## Internal gRPC Contract

Internal APIs use versioned Protobuf packages, initially a stable namespace
such as `spell.driver.v1` and separate worker-runtime packages. Contracts shall:

- use bounded messages, explicit enums with `UNSPECIFIED`, stable field numbers,
  and wrapper/optional semantics where absence matters;
- carry operation ID, deadline, trace ID, satellite/domain,
  `AuthorityIncarnationId`, assignment generation, leader epoch, controller
  lease and control fence when human authority is required, server profile,
  host generation, context generation, execution attachment generation, driver
  binding, and committed decision-evidence digest as applicable;
- negotiate granular capabilities and limits before use;
- authenticate both workloads and authorize each RPC method;
- disable public routing and unapproved reflection or generic health/admin
  methods;
- use structured status details rather than raw stack traces;
- specify idempotency and effect certainty for every method;
- enforce maximum request, response, stream window, and concurrent-call bounds;
  and
- preserve unknown fields and follow published backward-compatibility rules.

RPC deadline expiry or cancellation means the caller stopped waiting. It does
not prove that an external effect did not occur. The stable operation resource
is reconciled before any retry.

## Error Codes

At minimum, public and internal mappings cover:

`AUTHENTICATION_REQUIRED`, `FORBIDDEN`, `DOMAIN_MISMATCH`,
`CONTROL_LEASE_REQUIRED`, `CONTROL_LEASE_EXPIRED`, `STALE_FENCING_TOKEN`,
`STALE_LEADER_EPOCH`, `REVISION_CONFLICT`, `IDEMPOTENCY_CONFLICT`,
`INVALID_TRANSITION`, `CAPABILITY_UNSUPPORTED`, `RESOURCE_EXHAUSTED`,
`DEPENDENCY_UNAVAILABLE`, `DEADLINE_EXCEEDED`, `CURSOR_INVALID`,
`CURSOR_EXPIRED`, `STREAM_EPOCH_CHANGED`, `RESYNC_REQUIRED`, `EFFECT_UNKNOWN`,
and `INTERNAL_ERROR`.

Whether a code is retryable is part of its operation-specific contract. Clients
never infer retry safety solely from HTTP 5xx or gRPC `UNAVAILABLE`.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| COM-013 | All browser traffic shall use approved HTTPS and authenticated, authorized API or stream endpoints. |
| COM-014 | Every public mutation shall use REST, a stable idempotency key, expected revision, and controller fencing fields where execution control is affected. |
| COM-015 | A WebSocket shall accept subscription management only and shall provide no runtime mutation route. |
| COM-016 | Every WebSocket domain event shall correspond to committed state and carry event identity, aggregate identity and revision, domain scope, cursor continuity, commit time, schema, and leader epoch. |
| COM-017 | Snapshot and cursor shall represent one coherent database view, and cursor replay shall include every later committed matching event. |
| COM-018 | Delivery shall be at least once; clients shall deduplicate and reject stale aggregate revisions. |
| COM-019 | Canonical operational events shall not be silently dropped for slow consumers; the gateway shall bound memory and force explicit reconnect/resynchronization. |
| COM-020 | Telemetry sampling or coalescing shall expose source sequence and every gap and shall not remove samples consumed by a procedure or used for alarm transitions. |
| COM-021 | Cursor scope and integrity shall be validated, cursor retention shall be configured and monitored, and expired cursors shall force a fresh snapshot. |
| COM-022 | Internal driver and worker protocols shall be versioned, typed, bounded, authenticated, authorized, deadline-limited, and inaccessible from the public edge. |
| COM-023 | Timeout, disconnect, cancellation, or transport failure shall not be interpreted as proof that a mutation or external effect failed. |
| COM-024 | API and event payloads shall exclude secrets and shall use redacted, stable error details suitable for the caller's authorization. |
| COM-025 | Every protocol limit and compatibility rule shall be represented in machine-readable contract tests. |
| COM-026 | Monitoring load shall be horizontally scalable with no product-imposed fixed user cap, but every deployment shall publish and qualify finite connection and event-rate capacity. |
| COM-027 | A filtered subscription shall use a contiguous `delivery_sequence` and signed cursor chain; authorization filtering shall use an opaque per-scope projection that exposes no excluded domain position, count, or timing metadata, cursor-advance frames shall cover only already authorized projection positions, heartbeats shall not advance cursors, and a filter or authorization-scope change shall require a new projection epoch or resynchronization. |

## Verification Hooks

- Generate REST and gRPC clients from the checked-in contracts and run backward-
  compatibility checks on every change.
- Commit events concurrently with authorized snapshot reads and prove
  snapshot-plus-projection replay yields the same authorized state as a later
  consistent projection read.
- Delay a transaction holding position `N` within one (`DomainId`,
  `DomainStreamEpoch`), race a competing writer, and prove base journal
  positions still follow database commit serialization in that epoch.
- Create a fresh authority incarnation through restore and failover, prove the
  new domain stream starts at position 1, and verify every old cursor receives
  `STREAM_EPOCH_CHANGED` without numeric position comparison.
- Interleave identical authorized events with varied unauthorized counts and
  timing and prove public sequences, cursor bytes, frame counts, and progress
  reveal no unauthorized base position, count, or timing.
- Exercise subscriber filters that exclude long and interleaved authorized
  projection ranges and prove contiguous delivery sequence, cursor-advance
  coverage only over projection positions, cursor-chain validation, and
  deterministic new-epoch resynchronization on filter change.
- Inject duplicate, delayed, reordered, corrupt, expired, cross-domain, and
  unauthorized cursors and verify deterministic rejection or resynchronization.
- Saturate connection queues and telemetry rates and prove bounded memory,
  explicit gaps, retained canonical events, and unaffected control commits.
- Terminate connections at each mutation and driver-operation stage and prove
  that clients recover by querying stable resources without blind retry.
