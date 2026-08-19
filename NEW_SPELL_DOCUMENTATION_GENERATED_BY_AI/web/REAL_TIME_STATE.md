# Real-Time State and Synchronization

## 1. Purpose

This document defines how the web client receives procedure status, logs,
events, variables, telemetry, command acknowledgments, alarms, prompts, and
operator notifications in real time. It specifies an authoritative
snapshot-plus-cursor protocol rather than treating a WebSocket connection as
the source of truth.

## 2. Protocol Separation

| Channel | Purpose | Direction |
| --- | --- | --- |
| HTTPS REST | Authentication/session, snapshots, queries, command submission, prompt response, lease operations, history, and gap recovery | Request/response |
| WebSocket over TLS | Ordered committed event delivery and subscription control | Server events downstream; client subscription/heartbeat control only |

State-changing business commands shall not be carried as WebSocket messages.
The WebSocket may accept protocol-level subscribe, unsubscribe, heartbeat, and
flow-control frames; these do not mutate an execution.

The browser never connects to a worker, driver, database, message broker, or
GCS. This implements `WEB-029` and `WEB-030`.

## 3. Authoritative Event Model

An event is committed to authoritative persistence before it is eligible for
publication. The common envelope shall include:

| Field | Rule |
| --- | --- |
| `event_id` | Globally unique and immutable |
| `stream_id` | Unique subscription incarnation for one opaque authorization-projection and subscriber-filter scope |
| `domain_id` | Authorized Satellite Control Domain scope; never inferred from client state |
| `domain_stream_epoch` | Equal to the fresh non-restorable `AuthorityIncarnationId`; a changed value forces reset rather than numeric position comparison |
| `projection_scope_id` | Opaque identifier for the durable authorization scope; reveals no base-domain position or population |
| `projection_epoch` | Fresh `ProjectionEpoch` bound to authorization, policy/redaction, schema, and filter digests; sequences are comparable only within this epoch |
| `projection_sequence` | Starts at 1 and is contiguous within one authorized `ProjectionEpoch`; subscriber filtering may cross it only through a signed cursor-advance frame |
| `delivery_sequence` | Contiguous per subscription, including cursor-advance frames; no reuse |
| `previous_cursor` and `cursor` | Integrity-protected continuity chain scoped to domain stream epoch, projection scope/epoch, policy and authorization revisions, filter digest, schema, and expiry |
| `event_type` | Versioned registered name |
| `schema_version` | Event payload schema version |
| `committed_at` | Authoritative UTC commit time |
| `occurred_at` | Source occurrence time when trustworthy; never substitutes for commit ordering |
| `aggregate_type` and `aggregate_id` | Resource changed by the event |
| `aggregate_revision` | Revision after the change |
| `leader_epoch` | Current committed leader fence associated with the event |
| `correlation_id` and `causation_id` | Trace command and causal chain |
| `classification` | Server-provided data-handling label |
| `payload` | Typed schema; server-authorized and redacted |

High-rate source time, acquisition time, quality, validity, and sample sequence
belong in telemetry payloads. Browser receipt time is presentation metadata
only. Browser envelopes and cursors omit `domain_event_position`. Authorization
is evaluated before projection numbering, so an unauthorized base-domain event
creates no visible sequence gap, frame, count, or timing signal.

## 4. Initial Synchronization

The client shall:

1. Authenticate and select an authorized mission, satellite, and server.
2. Request a consistent snapshot containing `schema_version`, `stream_id`,
   `snapshot_revision`, `snapshot_cursor`, generated time, resource
   revisions, effective mode authorization, control lease, active executions,
   prompts, alarms, commands, and projection metadata permitted to the subject. The request includes the exact
   projection/filter scope, and the response includes opaque projection-scope
   ID, `ProjectionEpoch`, authorized projection head, canonical authorization,
   policy/redaction and filter digests, and `DomainStreamEpoch`.
3. Open the event stream from `snapshot_cursor`.
4. Buffer later events while applying the snapshot.
5. Apply only schema-valid frames with contiguous `delivery_sequence` and a
   matching cursor chain for the same subscription incarnation.
6. Mark the view `Live` only after every authorized projection entry through the
   advertised projection head is applied or covered by a valid cursor-advance
   frame.

Snapshot generation and stream retention shall guarantee a usable overlap. If
the cursor expires, the server returns a typed `CURSOR_EXPIRED` result and the
client obtains a new snapshot. If restore, failover, cutover, or failback creates
a new authority incarnation, the server returns `STREAM_EPOCH_CHANGED`; the
client discards derived state and snapshots again without comparing numeric
positions from the two epochs.

## 5. Reconnect and Gap Recovery

The client persists only the last fully applied cursor and non-sensitive
presentation state. On reconnect it presents that cursor with fresh
authentication. It shall not claim live status until continuity is proven.

A gap exists when:

- the next `delivery_sequence` is not the previous value plus one;
- `previous_cursor` does not match the last fully applied cursor;
- stream identity, projection scope, or `ProjectionEpoch` changes;
- `projection_sequence` skips without a valid cursor-advance frame covering
  only authorized projection positions;
- `DomainStreamEpoch` changes or the server reports
  `STREAM_EPOCH_CHANGED`;
- an aggregate revision skips without an event type that explicitly permits a
  compacted projection;
- an event fails schema or integrity validation;
- the server reports cursor expiry or retention loss.

On a gap, the client immediately disables mutations, displays `Gap detected`,
stops applying dependent deltas, and requests replay or a replacement
snapshot. It shall not fill a gap using cached logs, inferred state, or later
events.

Duplicates with the same event identity and content are ignored
idempotently. Reuse of an event identity with different content is an integrity
failure and terminates the stream.

The durable authorization projection is numbered only after access policy and
redaction, so unauthorized base-domain activity cannot create a browser-visible
gap or cursor movement. A subscriber-selected filter may omit entries from that
already authorized projection. The server may emit a signed
`stream.cursor_advanced` frame whose covered range names only committed
`projection_sequence` values in the current `ProjectionEpoch`. The frame carries
a contiguous delivery sequence and cursor chain but no excluded event metadata,
source timestamps, base positions, or unauthorized counts. Heartbeats report
liveness and server time only and cannot advance the cursor. Changing
authorization, policy/redaction, or filter digest creates a new opaque
projection scope and epoch and requires a replacement snapshot.

## 6. Event Families

The event registry shall include, at minimum:

| Family | Examples | Delivery rule |
| --- | --- | --- |
| Execution | created, loaded, state changed, checkpointed, parent/child linked, finished | Never sampled or silently coalesced |
| Source position | current span, executed span, breakpoint or safe-point outcome | May coalesce only when history remains queryable and no semantic transition is lost |
| Log and event | as-run entry, support log, display, notification, external event | Ordered; retained and pageable |
| Variable and shared data | created, changed, deleted, compare-and-set outcome | Include revision; sensitive values redacted server-side |
| Telemetry | sample, quality change, freshness change, subscription status | Bounded batching allowed with sample sequence and explicit dropped-count/gap facts |
| Command | submitted, authorized, accepted, dispatched, acknowledged, reconciled, failed, uncertain | Never sampled or silently coalesced |
| Alarm | raised, changed, acknowledged, shelved/suppressed, cleared | Never sampled; state remains latched until terminal disposition |
| Prompt | opened, response accepted/rejected, timed out, canceled, settled | Never sampled or silently coalesced |
| Control | lease acquired; handover requested, holder-approved, responsibility-acknowledged, transferred, withdrawn, declined, canceled, or expired; fence or authoritative mode projection changed; lease expired or revoked | Never sampled; transfer and both affected session-mode projections share one committed correlation |
| Security | startup mode decision, access denied, reauthentication, policy or redaction change | Never sampled; visibility follows policy |

Transport batching shall not change event order or erase individual event
identities.

## 7. Prompt Durability and Races

A prompt is a server resource with:

- `prompt_id`, `execution_id`, source span, type, message, options and
  validation schema;
- state and revision;
- open, deadline, and settle times;
- default and precedence policy;
- eligible responder policy and required control lease;
- accepted response value, actor, lease fence, and idempotency key when
  settled;
- terminal reason such as responded, timed out, canceled, aborted, or failed.

Responses use REST with expected prompt revision, idempotency key, active
fencing token, and typed value. Exactly one terminal outcome wins in the
authoritative transaction. Competing responses, timeout, abort, and controller
loss return the already committed terminal outcome rather than producing a
second result.

A disconnected client may rediscover an open prompt from the snapshot. It
cannot submit a response after losing its lease or after the prompt settles.

## 8. Command and Acknowledgment Correlation

Command submission returns a durable `command_id` before the UI reports
acceptance. Events for authorization, dispatch, driver acknowledgment,
completion, rejection, cancellation, timeout, and reconciliation carry that
ID. Procedure commands and external telecommands are distinct resource types.

An HTTP timeout does not authorize automatic resubmission with a new
idempotency key. The client queries by original key or command ID and displays
the server's outcome. Unknown external effect is a first-class state and blocks
conflicting effects according to policy.

## 9. Freshness, Staleness, and Clocks

The UI computes presentation age from server-provided commit time using an
estimated clock offset, but server policy determines whether a mutation is
allowed. It shall display:

- stream connection and synchronization state;
- last contiguous delivery sequence, authorized projection sequence/epoch, and
  last visible committed event time;
- snapshot age, projection-scope identity, and `DomainStreamEpoch`;
- telemetry sample acquisition time, receive time, quality, validity, and
  freshness;
- source clock uncertainty when provided.

`No change`, `no sample`, `invalid`, `stale`, `stream delayed`, and
`client offline` are distinct states.

## 10. Backpressure and Capacity

The server shall enforce per-session subscription, bandwidth, event-rate,
buffer, and replay limits. Priority is:

1. control ownership, security, alarms, prompts, execution transitions, and
   command/effect certainty;
2. logs, operator notifications, and variable changes;
3. telemetry and other high-rate observational projections.

Under pressure, the server may batch or downsample only event families whose
schema explicitly defines it. It reports original count, delivered count,
method, interval, and any sample gap within the already authorized projection.
Those fields shall not count or time unauthorized base-domain events. The server
shall close a client with a typed retryable reason before unbounded buffering
threatens execution reliability.

Monitoring fan-out may use horizontally scaled gateways and read models.
Gateways cannot originate operational state, grant leases, or reorder the
durable authorization projection.

## 11. Schema Evolution

Event types and REST resources use explicit versions. Additive optional fields
may be introduced within a compatible version. Removing fields, changing
meaning, enum narrowing, ordering, or settlement semantics requires a new
version and a compatibility period.

Unknown critical event types cause resynchronization or client upgrade, not
silent ignore. Unknown non-critical extension events already authorized for the
projection may be retained in the cursor while omitted from presentation only
when the registry marks them safe to ignore; cursor progress never represents
an unauthorized base-domain event.

## 12. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `WEB-029` | Runtime mutations use authenticated REST resources; WebSocket business events are downstream-only and committed before publication. |
| `WEB-030` | Browser network policy and tests prove no direct worker, driver, broker, database, or GCS access. |
| `WEB-031` | Snapshot plus cursor converges within one projection epoch under reconnect, duplicate delivery, and batching; a failover-created stream epoch forces a typed reset and fresh snapshot. |
| `WEB-032` | A sequence, revision, schema, or integrity gap disables mutation until replay or snapshot resynchronization succeeds. |
| `WEB-033` | Command, prompt, alarm, lease, and effect-certainty events cannot be sampled or silently coalesced. |
| `WEB-034` | Concurrent prompt response, timeout, abort, and lease-loss tests produce exactly one durable terminal outcome. |
| `WEB-035` | The UI distinguishes live, delayed, stale, invalid, gap, offline, and reauthorization conditions using server facts. |
| `WEB-036` | Load tests enforce bounded buffers and preserve critical event ordering during telemetry bursts and reconnect storms. |
| `WEB-037` | Incompatible schemas fail visibly and cannot silently corrupt the client projection. |
| `COM-027` | Filtered streams prove contiguous delivery and cursor-chain coverage over authorized projection positions without exposing base-domain positions or unauthorized counts, timing, or metadata. |
