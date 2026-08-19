# System Requirements

## Contract

These requirements define the minimum target behavior of the next-generation
SPELL platform. Architecture documents explain how the requirements are
satisfied; they do not weaken them.

Verification codes are:

| Code | Method |
| --- | --- |
| `I` | Inspection of configuration, design, source, records, or generated evidence |
| `A` | Analysis, including model, threat, capacity, timing, or failure analysis |
| `T` | Repeatable automated or instrumented test |
| `D` | End-to-end demonstration with recorded evidence |
| `E` | Operational, recovery, incident, or assessment exercise |

Owner abbreviations are `PO` product owner, `MO` mission operations authority,
`SA` system architect, `LA` language authority, `DA` driver authority, `SO`
security officer, `QL` quality lead, `CM` configuration manager, `GA` governing
agency/contract/program authority, `SY` System Owner, `RO` authorized Risk Owner
or Authorizing Official, and `AS` assessment sponsor/customer. Approval of an
owner-defined value is tracked in `quality/OPEN_DECISIONS.md`.

## Documentation And Authority

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| DOC-001 | The approved specification shall identify its version, status, source revision, approvers, effective date, and superseded baseline. | I | CM |
| DOC-002 | `SYSTEM_REQUIREMENTS.md` shall be the sole register of atomic product requirements; every requirement shall have a stable identifier, owner role, verification method, and trace target. | I | QL |
| DOC-003 | The Language Reference 2.4.4 bytes identified in `SOURCE_AUTHORITY.md` shall remain the authority for language semantics unless a controlled compatibility disposition explicitly overrides one behavior. | I,T | LA |
| DOC-004 | The Driver Development Manual 2.4.4 bytes identified in `SOURCE_AUTHORITY.md` shall remain the authority for functional driver intent unless a controlled compatibility disposition explicitly overrides one behavior. | I,T | DA |
| DOC-005 | A source digest mismatch shall invalidate dependent review evidence until the changed artifact is re-inventoried and reviewed. | T | CM |
| DOC-006 | A requirement change shall update affected ADRs, compatibility rows, traceability, tests, migration, rollback, and approvals in the same controlled change. | I | CM |
| DOC-007 | AI-generated content shall not be treated as human approval, risk acceptance, compliance certification, or operational authorization. | I | PO |
| DOC-008 | Secrets, production access tokens, CUI, proprietary implementation code, and unapproved source artifacts shall not be committed to the documentation repository. | I,T | SO |
| DOC-009 | Every normative document shall be listed in `DOCUMENT_REQUIREMENT_ALLOCATION.md`; detailed `shall` clauses shall elaborate allocated central IDs and shall not create an unregistered obligation. | I | QL |
| DOC-010 | Documentation CI shall validate links, identifiers, requirement ranges, allocations, machine-readable artifacts, source hashes, ASCII policy, headings, and fenced examples before a baseline can be approved. | T | QL |
| DOC-011 | The documentation baseline shall include a source-controlled next-generation GUI User Manual and a rendered PDF covering interface architecture and navigation, role-based startup, permitted modes, dashboards, procedure browsing, execution, monitoring, controller handover, editing and Git, real-time state, alarms and notifications, search and filtering, multi-domain operation, permissions, degraded behavior, and operator/developer practices, with accessible concept visuals where they improve comprehension. | I,T,D | QL |

## System And Mission Architecture

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| ARC-001 | A Satellite Control Domain shall be bound to exactly one `SatelliteId` for its entire configured lifetime. | I,T | SA |
| ARC-002 | The platform shall support multiple independently operated Satellite Control Domains in one mission infrastructure. | D,T | SA |
| ARC-003 | A domain shall isolate command authority, execution state, driver bindings, audit, failure, capacity, and recovery from every other domain. | A,T | SA |
| ARC-004 | Browser, control plane, execution, driver, persistence, artifact, identity, and observability trust boundaries shall be explicit and independently enforceable. | I,A | SO |
| ARC-005 | No browser or procedure worker shall receive a driver endpoint credential, database owner credential, or unrestricted artifact-store credential. | I,T | SO |
| ARC-006 | Services shall use stable identities and versioned contracts; network location and process identity shall not be used as domain identity. | I,T | SA |
| ARC-007 | Components shall be replaceable or scalable without changing authoritative language semantics or procedure source identity. | A,T | SA |
| ARC-008 | Simulator, test, staging, and operational environments shall use distinct identities, trust roots, secrets, data, endpoints, and authorization policy. | I,T | SO |
| ARC-009 | An operational adapter or satellite connection shall require explicit environment and capability authorization independent of software deployment. | I,D | MO |
| ARC-010 | Safety-critical decisions shall remain server enforced; a browser display or disabled control shall not be the only enforcement point. | I,T | MO |
| ARC-011 | Each logical service shall have a documented owner, input contract, output contract, identity, timeout, retry rule, health signal, and data-access grant. | I,T | SA |
| ARC-012 | Public API replicas shall not retain unique runtime state required to recover a command or subscription. | I,T | SA |
| ARC-013 | Only the elected leader for a domain shall commit scheduler, execution, prompt, lease, or driver-operation transitions for that domain. | T,A | SA |
| ARC-014 | Procedure workers shall operate on bounded IR and shall access runtime capabilities only through a supervisor-owned typed interface. | I,T | SA |
| ARC-015 | Driver gateways shall reject browser identities, stale host/context generations, unsupported capabilities, and operations lacking a stable operation ID. | T | DA |
| ARC-016 | Every authoritative state change and corresponding publishable event shall be committed atomically through a transactional outbox. | T | SA |
| ARC-017 | Optional caches, brokers, replicas, indexes, and analytics stores shall expose freshness and shall not decide control authorization or state transitions. | A,T | SA |
| ARC-018 | Domain-specific failures and resource saturation shall be contained by quotas, process boundaries, credentials, and queue partitions. | A,T | SA |
| ARC-019 | Authoring and promotion services shall not obtain execution-control leases or driver credentials. | I,T | SO |
| ARC-020 | A promoted bundle shall be immutable and verified by digest before load and after retrieval from object storage. | T | CM |
| ARC-021 | Internal calls shall use workload identity, mutual authentication where the security profile requires it, explicit deadlines, bounded messages, and structured errors. | I,T | SO |
| ARC-022 | A service shall not retry a non-idempotent or externally effective operation unless the contract proves the original attempt had no effect. | T | MO |
| ARC-023 | Every projection used for operations shall carry enough revision, cursor, timestamp, and health information to identify stale or incomplete state. | T,D | MO |
| ARC-024 | Cross-domain orchestration shall call each domain's public authorized contract and shall not write domain tables or reuse a control token across domains. | I,T | SO |
| ARC-025 | Co-locating logical components shall not merge their service identities, authorization grants, audit responsibilities, or failure semantics. | I,T | SO |
| ARC-026 | A Satellite Control Domain shall have exactly one `SatelliteId` and shall not route a procedure operation to another satellite. | T | SA |
| ARC-027 | A deployment shall support multiple independent domains without sharing controller leases, leader epochs, driver credentials, or mutable runtime state. | T,A | SA |
| ARC-028 | A domain may run multiple executions concurrently only after admission control evaluates domain, driver, procedure, and serialization constraints. | T | MO |
| ARC-029 | At most one service leader shall have write authority for a domain at a time; every authoritative mutation shall carry the current monotonically increasing leader epoch. | T,A | SA |
| ARC-030 | At most one person shall hold a domain's execution-control lease at a time; control commands shall carry the current monotonically increasing `control_fencing_token`. | T | MO |
| ARC-031 | PostgreSQL shall be the authoritative source for committed control state, execution state, command disposition, prompts, and audit/outbox records. | I,T | SA |
| ARC-032 | A real-time message shall be a projection of committed state and shall never become authoritative merely because a client received it. | T | SA |
| ARC-033 | Browsers and procedure workers shall receive no driver endpoint, private key, GCS credential, or general route to a driver host. | I,T | SO |
| ARC-034 | Runtime execution shall consume an immutable, validated procedure bundle identified by digest; editing shall not mutate an active bundle. | T | LA |
| ARC-035 | Loss of certainty about an externally effective operation shall never trigger an automatic resend; the operation shall be reconciled or settled by an explicitly authorized decision. | T | MO |
| ARC-036 | A mission-wide Satellite Assignment Authority shall permit at most one effect-enabled command-authority path for a `SatelliteId` across every cluster, site, and legacy or replacement system, including a path in drain or transition. | T,A | SA |
| ARC-037 | Every activation, cutover, restore, or failback shall use a newly allocated `AuthorityIncarnationId` and assignment generation, externally fence the prior effect path, and issue fresh short-lived dispatch authority before control becomes active. | T,E | MO |
| ARC-038 | Every externally effectful integration shall pass through one approved Effect Authorization Point that exclusively owns the effect credential and egress path and, immediately before effect, uses a fail-closed one-use permit protocol that linearly orders current assignment at the SAA and current leader, controller when required, operation attempt, and integration fences at primary PostgreSQL before journaled dispatch. | T,A | SA |
| ARC-039 | Each assignment generation shall be reserved through a non-rollback authority outside the SAA recovery set; its signed reservation receipt shall commit before the generation or grant becomes observable, and loss or ambiguity of that proof shall block issuance. | T,E | SA |
| ARC-040 | A pre-SAA legacy command path shall have an externally identified adoption record and complete credential, session, endpoint, egress, interlock, and operator inventory; a replacement shall remain non-effecting until every inventoried path is independently fenced. | I,T,E | MO |

## Server, Control, And Concurrency

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| SRV-001 | Each domain shall expose a stable `DomainId`, bound `SatelliteId`, configuration version and digest, health state, leader epoch, and capability profile. | T | SA |
| SRV-002 | A domain shall execute multiple procedures concurrently up to approved resource, driver, conflict, and safety constraints. | T,A | MO |
| SRV-003 | Admission control shall reject or queue an execution deterministically when capacity, exclusive resource, dependency, or safety constraints are not satisfied. | T | SA |
| SRV-004 | Concurrency constraints shall be versioned configuration with declared scope, precedence, rationale, and audit history. | I,T | MO |
| SRV-005 | Exactly one `ACTIVE`, non-expired controller lease with the current `control_fencing_token` shall authorize interactive execution-control mutations in a domain. | T | SA |
| SRV-006 | Every control mutation shall carry the authenticated principal, session and client-instance proof, controller lease, lease revision, `control_fencing_token`, `AuthorityIncarnationId`, idempotency key, expected resource revision, and reason where policy requires one. | T | SO |
| SRV-007 | The server shall reject stale lease, stale fence, wrong domain, expired session, unauthorized role, duplicate-conflict, and revision-conflict mutations with stable typed responses. | T | SA |
| SRV-008 | Controller acquisition, renewal, release, expiry, explicit handover, emergency revocation, and reacquisition shall be durable and audited state transitions; ownership grants shall advance `control_fencing_token`, while renewal and terminal lease-state changes shall advance lease revision without reusing or decreasing the fence. | T,D | MO |
| SRV-009 | Loss of a browser, API replica, or network path shall not silently transfer control to another user. | T | MO |
| SRV-010 | A leader epoch shall fence stale domain writers after failover; at most one writer may commit authoritative control state for a domain. | T,A | SA |
| SRV-011 | Domain and execution APIs shall expose health separately from readiness, leadership, dependency health, and operational authorization. | T | SA |
| SRV-012 | Configuration activation shall validate schema, references, signatures, compatibility, and rollback availability before changing a domain. | T,D | CM |
| SRV-013 | Each server domain shall bind exactly one immutable satellite identity and one current server-profile revision. | I,T | SA |
| SRV-014 | Service leadership and human execution control shall use separate leases and separate monotonic fencing values. | T,A | SA |
| SRV-015 | The leader shall use authoritative database time for lease expiry and shall reject a stale leader epoch or stale `control_fencing_token`. | T | SA |
| SRV-016 | A domain shall expose its state, leader epoch, configuration digest, dependency health, degradation policy, and admission capacity. | T | SA |
| SRV-017 | Forced control takeover shall require dedicated authorization, a recorded reason, a new `control_fencing_token`, and operator-visible notification. | T,D | MO |
| SRV-018 | Context, host, binding, and attachment configuration shall be immutable within a generation and identified by schema version and digest. | I,T | DA |
| SRV-019 | Cleanup shall be best effort across all registered hooks but shall preserve each typed result and any uncertainty. | T | DA |
| SRV-020 | Stale host, context, binding, attachment, leader, and controller generations shall be rejected before any external effect. | T | DA |
| SRV-021 | Domain and controller-lease behavior shall be defined by checked-in machine-readable state models whose legal transitions, guards, effects, and rejection outcomes match the normative human-readable contract. | I,T | SA |
| SRV-022 | A domain shall become command-active only while holding a valid mission-wide satellite assignment grant for its `DomainId`, `SatelliteId`, `AuthorityIncarnationId`, and assignment generation. | T,A | SA |

## Procedure Execution

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| EXEC-001 | Each execution shall reference one immutable bundle digest, exact dependency closure, language profile, IR schema, compiler version, configuration digest, principal, and start request. | T | LA |
| EXEC-002 | Procedure source shall be parsed and semantically validated without executing source code. | T,A | LA |
| EXEC-003 | Runtime execution shall consume bounded, versioned, data-only IR and shall reject arbitrary imports, dynamic evaluation, shell access, unrestricted filesystem access, and direct network access. | T | SO |
| EXEC-004 | Each execution shall have a stable identifier, monotonically increasing revision, state, source position, variables, call stack, outstanding operations, controller relationship, and terminal disposition. | T | SA |
| EXEC-005 | The state machine shall define every allowed and rejected transition, actor, precondition, durable event, side effect, timeout, and recovery rule. | I,T | LA |
| EXEC-006 | Pause, resume, step, stop/abort, finish, interrupt, prompt response, and other controls shall be settled exactly once at a declared safe execution point. | T | MO |
| EXEC-007 | A prompt shall be a durable operation with one winning validated settlement across concurrent responses, timeout, cancellation, disconnect, restart, and failover. | T | MO |
| EXEC-008 | A wait or timer shall persist its original target, clock source, uncertainty policy, and resumption condition across restart. | T | LA |
| EXEC-009 | External operations shall have a stable `OperationId`, request digest, deadline, attempt identity, effect class, and reconciliation state; an effect-bearing operation shall use the canonical effect-certainty enum, while `effect_class=NONE` shall mark certainty not applicable without adding another enum value. | T | DA |
| EXEC-010 | The runtime shall not automatically resend an operation whose external effect is uncertain. | T | MO |
| EXEC-011 | Worker failure shall be isolated to affected executions unless an explicitly modeled shared dependency fails. | T,A | SA |
| EXEC-012 | Cleanup shall be best effort, bounded, typed, and audited; cleanup failure shall not be silently discarded or misreported as successful completion. | T | DA |
| EXEC-013 | Parent-child procedure relationships shall use immutable dependency resolution, bounded depth, cycle detection, stable identity, cancellation propagation, and recovery rules. | T | LA |
| EXEC-014 | The runtime shall produce a canonical as-run record sufficient to reconstruct source identity, inputs, state changes, operations, prompts, actor actions, outputs, failures, and final disposition. | T,D | QL |
| EXEC-015 | Every execution shall reference one immutable bundle digest, language profile, context generation, and independent execution ID. | T | LA |
| EXEC-016 | Execution transitions shall be durable compare-and-set operations with revision, actor or service identity, reason, timestamp, leader epoch, audit, and outbox event. | T | SA |
| EXEC-017 | The scheduler shall enforce named domain, context, worker, driver, and procedure constraints before admission. | T | SA |
| EXEC-018 | A worker shall have no general network, database, shell, host filesystem, or service-credential access. | I,T | SO |
| EXEC-019 | A public mutation shall have a stable command ID and idempotency key and shall expose acceptance separately from application and settlement. | T | SA |
| EXEC-020 | Externally effective operations shall have stable operation IDs, generation fences, effect-certainty states, and adapter reconciliation where supported. | T | DA |
| EXEC-021 | An operation in `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` shall never be automatically resent. | T | MO |
| EXEC-022 | A durable prompt shall settle at most once by compare-and-set and shall retain timeout, controller, validation, and response evidence. | T | MO |
| EXEC-023 | Controller loss shall follow a preconfigured, tested policy and shall default to preventing new interactive decisions and pausing at safe points. | T,D | MO |
| EXEC-024 | Runtime recovery shall not release quota, repeat an effect, or resume beyond a checkpoint until associated commands and operations are durably reconciled. | T | MO |
| EXEC-025 | Multiple instances of the same procedure shall retain independent IDs, variables, control state, logs, checkpoints, and terminal outcomes. | T | QL |
| EXEC-026 | Administrative worker termination shall be represented as failure and recovery evidence, not a successful procedure abort. | T | MO |
| EXEC-027 | Execution, command, prompt, driver-operation, and effect-certainty state machines shall be versioned, machine-readable, exhaustively transition-tested, and rejected on unspecified states or transitions. | I,T | QL |
| EXEC-028 | Each admitted execution shall run in exactly one isolated process or container sandbox with its own identity, limits, writable storage, and crash domain; a worker manager shall not co-host multiple executions in one sandbox. | I,T,A | SO |

## Communications And Real-Time State

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| COM-001 | All external network communication shall be authenticated, authorized, encrypted, integrity protected, and restricted to approved protocols and endpoints. | I,T | SO |
| COM-002 | Browsers shall use HTTPS REST for authenticated commands, queries, and consistent snapshots. | I,T | SA |
| COM-003 | Browsers shall receive committed real-time projections through an authenticated WebSocket protocol with heartbeat, sequence, cursor, and schema version. | T | SA |
| COM-004 | An event shall not be published as authoritative before the corresponding state transition is durably committed. | T | SA |
| COM-005 | A client shall obtain a revisioned snapshot and resume from an associated cursor without an unobservable gap. | T | SA |
| COM-006 | The client shall detect sequence gaps, cursor expiry, authorization changes, stale freshness, schema incompatibility, and heartbeat loss and shall resynchronize before presenting state as current. | T,D | QL |
| COM-007 | Stream delivery shall define per-topic ordering, duplicate handling, retention, cursor expiry, maximum lag, backpressure, slow-consumer, and reconnect behavior. | I,T | SA |
| COM-008 | Commands shall use idempotency and optimistic concurrency; transport retry shall not imply external-effect retry. | T | SA |
| COM-009 | Internal service-to-service RPC shall use versioned typed schemas, mutual authentication, bounded deadlines, cancellation, authorization, and correlation identifiers. | I,T | SO |
| COM-010 | Driver streams shall use snapshot/cursor/sequence semantics or a documented loss-detectable equivalent; drivers shall not invoke arbitrary browser callbacks. | T | DA |
| COM-011 | Logs, events, variables, telemetry, command acknowledgments, alarms, prompts, operator notifications, and execution status shall each have an explicit schema and authorization scope. | I,T | SA |
| COM-012 | Protocol compatibility shall be negotiated by version and capability; unknown required fields or unsupported behavior shall fail explicitly. | T | SA |
| COM-013 | All browser traffic shall use approved HTTPS and authenticated, authorized API or stream endpoints. | I,T | SO |
| COM-014 | Every public mutation shall use REST, a stable idempotency key, expected revision, and controller fencing fields where execution control is affected. | T | SA |
| COM-015 | A WebSocket shall accept subscription management only and shall provide no runtime mutation route. | T | SO |
| COM-016 | Every WebSocket domain event shall correspond to committed state and carry event identity, aggregate identity and revision, domain scope, cursor continuity, commit time, schema, and leader epoch. | T | SA |
| COM-017 | Snapshot and cursor shall represent one coherent database view, and cursor replay shall include every later committed matching event. | T | SA |
| COM-018 | Delivery shall be at least once; clients shall deduplicate and reject stale aggregate revisions. | T | SA |
| COM-019 | Canonical operational events shall not be silently dropped for slow consumers; the gateway shall bound memory and force explicit reconnect/resynchronization. | T,A | SA |
| COM-020 | Telemetry sampling or coalescing shall expose source sequence and every gap and shall not remove samples consumed by a procedure or used for alarm transitions. | T | DA |
| COM-021 | Cursor scope and integrity shall be validated, cursor retention shall be configured and monitored, and expired cursors shall force a fresh snapshot. | T | SA |
| COM-022 | Internal driver and worker protocols shall be versioned, typed, bounded, authenticated, authorized, deadline-limited, and inaccessible from the public edge. | I,T | SO |
| COM-023 | Timeout, disconnect, cancellation, or transport failure shall not be interpreted as proof that a mutation or external effect failed. | T | DA |
| COM-024 | API and event payloads shall exclude secrets and shall use redacted, stable error details suitable for the caller's authorization. | T | SO |
| COM-025 | Every protocol limit and compatibility rule shall be represented in machine-readable contract tests. | I,T | QL |
| COM-026 | Monitoring load shall be horizontally scalable with no product-imposed fixed user cap, but every deployment shall publish and qualify finite connection and event-rate capacity. | A,T | SA |
| COM-027 | A filtered subscription shall use a contiguous `delivery_sequence` and signed cursor chain; authorization filtering shall use an opaque per-scope projection that exposes no excluded domain position, count, or timing metadata, cursor-advance frames shall cover only already authorized projection positions, heartbeats shall not advance cursors, and a filter or authorization-scope change shall require a new projection epoch or resynchronization. | T | SA |

## Data And Storage

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| DATA-001 | PostgreSQL shall be the authoritative transactional store for domain configuration state, leases, executions, operations, prompts, committed events, and audit references. | I,T | SA |
| DATA-002 | Database transactions shall preserve state/event atomicity and enforce uniqueness, fencing, revision, referential, and lifecycle invariants. | T | SA |
| DATA-003 | Schema changes shall be ordered, forward tested, rollback or roll-forward planned, backed up, and exercised against representative data before promotion. | T,D | CM |
| DATA-004 | Immutable procedure bundles, large reports, exports, and backup artifacts shall use content-addressed object storage with integrity, retention, encryption, and access controls. | T | SO |
| DATA-005 | A broker, cache, search index, time-series store, or analytical store may be used only as a rebuildable projection or transport and shall not become command or lease authority. | A,T | SA |
| DATA-006 | Procedure-consumed telemetry evidence and values affecting control decisions shall be retained with source, acquisition time, receive time, sequence, quality, validity, units, freshness, and correlation. | T | DA |
| DATA-007 | Data classification, retention, legal hold, deletion, export, and archive policy shall be defined per data class and environment. | I,T | SO |
| DATA-008 | Encryption keys and secrets shall be stored outside application data and configuration payloads using an approved managed secret/key service. | I,T | SO |
| DATA-009 | Database service accounts shall be component-specific and least privileged; applications shall not use a database owner or shared administrator credential. | I,T | SO |
| DATA-010 | Backups shall be encrypted, integrity checked, access logged, restorable without the failed primary environment, and tested to approved RPO/RTO values. | T,E | CM |
| DATA-011 | Shared procedure data shall use authorized namespaces, typed schemas, revisions, and transactional compare-and-set where atomic coordination is required. | T | LA |
| DATA-012 | File language services shall use virtual roots, traversal and symlink protection, explicit encoding, quotas, atomic write rules, malware/content policy, and audit. | T | SO |
| DATA-013 | PostgreSQL shall be authoritative for committed domain control, execution, command, prompt, driver-operation, audit, and outbox state. | I,T | SA |
| DATA-014 | A state change, its command/audit evidence, and its publishable outbox event shall commit atomically. | T | SA |
| DATA-015 | The schema shall enforce one active controller lease per domain, monotonic fencing and leader values, idempotency uniqueness, valid state transitions, and domain-scoped referential integrity. | T | SA |
| DATA-016 | Every mutable record shall carry a revision and domain scope; every historical record shall carry immutable identity and authoritative timestamp. | T | SA |
| DATA-017 | Git source, promoted bundle, runtime execution, and as-run evidence shall be linked by commit identity, dependency lock, language profile, validation result, and content digest. | T | CM |
| DATA-018 | Object content shall be verified by digest before use and shall have classification, retention, encryption, and ownership metadata. | T | SO |
| DATA-019 | Brokers, caches, replicas, search indexes, and analytics stores shall be replaceable derived systems and shall expose freshness and gap state. | A,T | SA |
| DATA-020 | Procedure-consumed telemetry and alarm transitions shall be durable evidence with item, value, units, source/sample/receive time, sequence, quality, validity, freshness, and execution reference. | T | DA |
| DATA-021 | Secrets and private keys shall be stored in an approved secrets/key service and shall not appear in general database fields, objects, events, logs, or bundle payloads. | I,T | SO |
| DATA-022 | Retention and purge shall preserve active references, unresolved effects, audit obligations, legal holds, and as-run integrity. | T | SO |
| DATA-023 | Migrations shall be ordered, checksummed, restartable where long-running, tested on populated data, and compatible with the approved rollback window. | T,D | CM |
| DATA-024 | Database roles and network policy shall grant each service only its required schemas and operations; worker, browser, and driver-host identities shall have no database route. | I,T | SO |
| DATA-025 | Backup and restore shall preserve immutable IDs, event positions, operation certainty, and artifact references; restored local fencing values shall remain subordinate to a newly allocated `AuthorityIncarnationId` and shall never authorize reuse. | T,E | CM |
| DATA-026 | Storage and query capacity shall be measured against declared domain, execution, telemetry, audit, retention, and monitoring envelopes before production qualification. | A,T | SA |
| DATA-027 | Event positions shall be unique and commit-ordered within `(DomainId, DomainStreamEpoch)`, allocated under that stream's journal-head lock in the same transaction as state, audit, outbox rows, and head advance; a snapshot cursor shall contain the epoch and head visible in the same repeatable-read view. | T | SA |
| DATA-028 | The runtime catalog and promotion registry shall be authoritative PostgreSQL state with revision, idempotency, approval, immutable digest pinning, audit/outbox publication, HA, restore, and schedule references. | T,E | CM |
| DATA-029 | Telemetry or alarm evidence influencing an external operation shall commit with the decision and operation intent before dispatch, and the driver request shall reference its evidence revision or digest. | T | DA |

## Web Application And Operator Experience

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| WEB-001 | The product shall provide a responsive web application supporting Execution, Monitoring, and Edit modes without a required desktop client. | D,T | PO |
| WEB-002 | The interface shall expose current satellite/domain identity, environment, authorization mode, controller identity/state, connection freshness, leader epoch, and configuration version without ambiguity. | D,T | MO |
| WEB-003 | Execution status, logs, events, variables, telemetry, command acknowledgments, alarms, prompts, and notifications shall update in real time and expose snapshot time and freshness. | D,T | MO |
| WEB-004 | The interface shall visibly distinguish current, stale, resynchronizing, disconnected, degraded, replayed, and authorization-lost state. | D,T | MO |
| WEB-005 | A control shall be shown or enabled only when the server reports the action is authorized and valid for the current revision; the server shall independently revalidate it. | T,D | MO |
| WEB-006 | Destructive, irreversible, safety-sensitive, or uncertain-effect actions shall use policy-driven confirmation that states target, consequence, and required reason or second approval. | D,T | MO |
| WEB-007 | Prompt presentation shall preserve exact execution, source, request, expected type/options, timeout, default, and settlement state and shall prevent stale or duplicate response. | T,D | MO |
| WEB-008 | The application shall meet the approved accessibility baseline for keyboard operation, focus, semantics, contrast, text scaling, motion, and non-color status cues. | T,D | QL |
| WEB-009 | Common critical workflows shall meet owner-approved latency, action-count, error-recovery, and viewport acceptance criteria under the qualified workload. | D,A | MO |
| WEB-010 | The browser shall not persist bearer credentials, procedure secrets, or CUI in insecure storage and shall clear protected state on logout or authorization loss. | I,T | SO |
| WEB-011 | Browser security policy shall restrict content sources, framing, cross-origin access, insecure transport, and untrusted rendered content. | I,T | SO |
| WEB-012 | Historical/replay content shall be visually and semantically distinct from live operational state. | D,T | MO |
| WEB-013 | A user shall always be able to identify mission, satellite, server, environment, identity, mode, control owner, connection state, and data age. | D,T | MO |
| WEB-014 | Execution, Monitoring, Edit, and Replay views shall never conflate authoritative runtime state with editor or cached state. | D,T | MO |
| WEB-015 | Multiple executions of one definition shall remain independently selectable and carry stable identities. | D,T | MO |
| WEB-016 | Each mutation shall display durable submission and terminal settlement, including an explicit unknown outcome. | D,T | MO |
| WEB-017 | Critical actions shall name their target and consequence, collect required reasons or approvals, and be audited. | D,T | MO |
| WEB-018 | Offline, stale, delayed, synchronizing, gap, and reauthorization states shall be visually and programmatically distinct. | D,T | QL |
| WEB-019 | Desktop, tablet, and mobile test matrices shall complete without overlap, loss of critical state, or changed command semantics. | D,T | QL |
| WEB-020 | The approved WCAG 2.2 AA automated and manual checks shall pass for every critical workflow. | T,D | QL |
| WEB-021 | Security tests shall prove that browser content cannot reach a driver directly and that untrusted text is not executable markup. | T | SO |
| WEB-022 | Replay shall reconstruct an as-run view from persistence while all operational commands remain disabled. | T,D | MO |
| WEB-023 | Nested default and user-defined categories shall render with stable IDs, accessible keyboard behavior, and deterministic ordering. | T,D | PO |
| WEB-024 | Rename and move shall preserve procedure identity; historical and running versions shall remain resolvable by digest. | T | CM |
| WEB-025 | Search, filters, favorites, and recent views shall not reveal unauthorized metadata or mutate runtime state. | T | SO |
| WEB-026 | Definition selection and execution selection shall be unambiguous, and no navigation gesture shall start a procedure. | D,T | MO |
| WEB-027 | Edit operations shall produce validated Git diffs; delete shall not remove required history, promoted artifacts, or active instances. | T | CM |
| WEB-028 | Start shall reject a stale catalog revision and shall always pin an immutable bundle digest. | T | CM |
| WEB-029 | Runtime mutations shall use authenticated REST resources; WebSocket business events shall be downstream-only and committed before publication. | T | SA |
| WEB-030 | Browser network policy and tests shall prove no direct worker, driver, broker, database, or GCS access. | I,T | SO |
| WEB-031 | Snapshot plus cursor shall converge to the same state under reconnect, duplicate delivery, batching, and failover. | T | SA |
| WEB-032 | A sequence, revision, schema, or integrity gap shall disable mutation until replay or snapshot resynchronization succeeds. | T | MO |
| WEB-033 | Command, prompt, alarm, lease, and effect-certainty events shall not be sampled or silently coalesced. | T | MO |
| WEB-034 | Concurrent prompt response, timeout, abort, and lease-loss tests shall produce exactly one durable terminal outcome. | T | MO |
| WEB-035 | The UI shall distinguish live, delayed, stale, invalid, gap, offline, and reauthorization conditions using server facts. | D,T | MO |
| WEB-036 | Load tests shall enforce bounded buffers and preserve critical event ordering during telemetry bursts and reconnect storms. | A,T | SA |
| WEB-037 | Incompatible schemas shall fail visibly and shall not silently corrupt the client projection. | T | QL |

## Operating Modes And Procedure Navigation

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| MODE-001 | An authenticated user shall enter only modes allowed by server-evaluated role, attributes, domain, environment, and session policy. | T | SO |
| MODE-002 | Execution Mode shall allow the valid controller to start, pause, resume, stop/abort, respond to prompts, provide operator input, and otherwise control executions according to state and policy. | D,T | MO |
| MODE-003 | An Execution Mode user without the valid controller lease shall remain read-only and shall not be treated as a second controller. | T | MO |
| MODE-004 | Monitoring Mode shall be enforced read-only for runtime and procedure resources at every API and service boundary, including WebSocket and exported links. The bounded control-authority workflow in MODE-025 and MODE-026 is not a runtime or procedure mutation: it permits an eligible requester to submit, withdraw, or decline one named non-authorizing request and, only after durable current-holder approval, to submit the request-bound responsibility acknowledgement that atomically settles transfer. | T | SO |
| MODE-005 | Monitoring users shall be able to observe authorized executions, logs, events, variables, telemetry, acknowledgments, alarms, prompts, and notifications in real time. | D,T | MO |
| MODE-006 | Edit Mode shall support authorized create, modify, delete, validate, organize, syntax-check, dependency-analysis, review, and promotion workflows through Git. | D,T | PO |
| MODE-007 | Edit Mode shall not directly mutate an active execution, deployed immutable bundle, runtime database row, or driver configuration. | T | SO |
| MODE-008 | Holding Edit Mode authorization shall not grant Execution Mode control, and holding controller authority shall not grant repository write authority. | T | SO |
| MODE-009 | The product shall impose no fixed licensing or application count on monitoring users; deployment capacity and admission behavior shall be measured, configured, published, and tested. | I,A,T | PO |
| MODE-010 | The procedure navigator shall support stable hierarchical folders, nested folders, search, filtering, favorites, recent procedures, and permission-aware results. | D,T | PO |
| MODE-011 | The initial category model shall support Bus, Payload, Platform, Test, Commissioning, Maintenance, Emergency, and authorized user-defined categories without encoding category names as security roles. | D,T | PO |
| MODE-012 | Favorites and recents shall be per-principal metadata, shall not alter repository structure, and shall not reveal unauthorized procedures. | T | SO |
| MODE-013 | Role, selected mode, and controller-lease authority shall be independent server decisions. | I,T | SO |
| MODE-014 | At most one active controller lease shall exist per domain under concurrent acquisition, failover, retry, and database contention. | T,A | SA |
| MODE-015 | A stale `control_fencing_token` shall be rejected at command acceptance and before every newly initiated external effect. | T | SA |
| MODE-016 | Explicit handover shall change session-bound authority without sharing credentials and shall preserve unresolved-effect visibility. | T,D | MO |
| MODE-017 | Lease loss, expiry, revocation, and forced takeover shall drive procedures to approved safe behavior and leave an auditable record. Forced takeover shall remain disabled until the dedicated authorization, recent-authentication, approval, reason, notification, and review policy is approved under `OD-006` and `OD-019`. | T,D | MO |
| MODE-018 | Every Monitoring Mode runtime or procedure mutation attempt shall be denied server-side, including direct API calls and prompt races. The only writes admitted from that workspace are eligible submission, withdrawal, or decline of the non-authorizing request in MODE-025 and the named requester's request-bound responsibility acknowledgement after durable current-holder approval; that acknowledgement may create authority only through the atomic MODE-026 transfer and shall have no independent runtime or procedure mutation path. | T | SO |
| MODE-019 | Edit Mode shall not change deployed or running source or reach an operational driver. | T | SO |
| MODE-020 | Monitoring shall have no product-imposed user cap and shall pass the deployment's declared capacity and reconnect-storm tests. | A,T | SA |
| MODE-021 | A controller lease shall be bound to one authenticated session and one non-exportable client-instance proof-of-possession key and shall not be reusable from another tab, device, server, or request context. | T | SO |
| MODE-022 | Reacquisition shall require acknowledgement of active executions, prompts, alarms, and uncertain effects before resume. | T,D | MO |
| MODE-023 | At authenticated startup, the server shall return the principal's effective capabilities and permitted modes. For a principal with exactly one permitted primary role and no more restrictive policy override, the server shall apply the baseline mapping Controller to the Execution workspace, Monitoring to the Monitoring workspace, and Developer to the Edit workspace. Opening Execution without a valid controller lease shall remain non-authorizing. An existing lease shall select active Execution only when current authentication, revocation, assurance, role, attribute, scope, policy, assignment, current-pointer, session, client-key, state, expiry, and fence checks all pass; a lease shall never override a restrictive or revoked authorization decision. Multi-role selection and restrictive overrides shall follow versioned policy, and the browser shall not infer authorization from role names. | T,D | SO |
| MODE-024 | For a multi-role principal, the server shall evaluate authorization within the selected mode without merging excluded capabilities from another role or mode, and a mode change shall not grant a controller lease or repository authority. | T | SO |
| MODE-025 | A controller-eligible principal in Monitoring Mode may create one non-authorizing named handover request for a different immutable principal subject. Transfer shall require durable approval by the current controller and a subsequent request-bound responsibility acknowledgement by the named requester. The request shall carry one immutable authoritative-database-time deadline that is clamped to the remaining lease lifetime and is never reset by approval, retry, or acknowledgement. | T,D | MO/SO |
| MODE-026 | Accepted handover shall atomically terminalize the old grant, create and install one new `ACTIVE` higher-fence grant, and commit authoritative mode projections plus audit and outbox rows placing the new holder in Execution Mode and the former holder in Monitoring Mode or another permitted non-control mode. External publication shall occur only after that transaction commits. | T,A,D | SA/MO |
| MODE-027 | Startup mode decisions and each handover stage, including rejection, shall produce append-only audit evidence. Every source event shall contain the approved common envelope; current-holder and requester identities, sessions and client keys, effective roles and policy revision, server/domain/satellite, request/approval/acknowledgement identities, old and new lease revisions and fences, and other extension fields shall be required only for the event types to which they apply and shall never be fabricated. The source event shall retain trusted service event time, reason, outcome, and correlation; an independent sink receipt shall retain ingestion time and bind the source event ID and digest. | I,T | SO |

## Procedure Source, Git, And Promotion

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| GIT-001 | Git shall be the source of truth for procedure source, folders, metadata, schemas, dictionaries, dependencies, tests, and review history. | I,T | CM |
| GIT-002 | Protected branches shall require authenticated authorship, review, passing validation, resolved findings, and organization-defined approval for sensitive procedure classes. | I,T | CM |
| GIT-003 | Procedure validation shall include parsing, syntax, semantic, type, dependency, cycle, policy, secret, provenance, compatibility, and test checks without executing untrusted source. | T | LA |
| GIT-004 | Promotion shall resolve one commit into an immutable bundle containing exact content, dependency closure, tool/profile versions, configuration references, manifest, signatures, and digest. | T | CM |
| GIT-005 | Runtime catalogs shall reference only approved promoted bundles and shall never execute a mutable branch, working tree, URL head, or unreviewed upload. | T | CM |
| GIT-006 | Rollback shall promote a previously approved immutable bundle through an audited operation; it shall not rewrite Git history or an active execution. | D,T | CM |
| GIT-007 | Deletion shall remove catalog eligibility through a reviewed commit and retention policy while preserving required history, audit, bundles, and as-run evidence. | T | CM |
| GIT-008 | Branch, tag, bundle, catalog, and deployment permissions shall use least privilege and separation of duties. | I,T | SO |
| GIT-009 | Source signing and provenance policy shall detect unauthorized history rewriting, forged releases, and dependency substitution before promotion. | T | SO |
| GIT-010 | Every execution shall retain durable source identity even after repository reorganization, rename, deletion, or retention transition. | T | QL |
| GIT-011 | Dependency resolution shall be deterministic, content pinned, bounded, and restricted to approved repositories and package types. | T | SO |
| GIT-012 | Emergency procedure changes shall use an explicit expedited workflow with named approvers, complete audit, bounded validity, and retrospective review. | I,D | MO |
| GIT-013 | Git shall be the editable source of truth; no branch, working tree, or editor buffer shall be loaded by an execution. | I,T | CM |
| GIT-014 | Protected history shall require verified signatures, required checks, code-owner review, and no force-push. | I,T | CM |
| GIT-015 | Parser and semantic services shall complete with network and execution disabled and without a GCS. | T | LA |
| GIT-016 | The same commit and pinned inputs shall produce identical diagnostics and an independently reproducible bundle digest. | T | CM |
| GIT-017 | Bundle manifests shall carry complete source, toolchain, dependency, catalog, approval, capability, and provenance identities. | I,T | CM |
| GIT-018 | Promotion shall verify a preexisting immutable artifact and shall not rebuild or overwrite it. | T | CM |
| GIT-019 | Promotion, supersession, withdrawal, and rollback shall never mutate a running execution implicitly. | T | MO |
| GIT-020 | Concurrent edits and case, rename, or dependency conflicts shall fail visibly without lost updates. | T | CM |
| GIT-021 | Separation-of-duties tests shall prevent authors from bypassing review, validation, artifact, or environment promotion policy. | T | SO |
| GIT-022 | Every historical execution shall resolve to retained source, manifest, signatures, approvals, validation evidence, and bundle bytes. | T | QL |
| GIT-023 | Folder and procedure organization shall be represented in versioned metadata with case-collision and dependency checks. | T | CM |
| GIT-024 | Operational and Edit trees shall display their distinct source commit, bundle, branch, and index states. | D,T | PO |

## Reliability, Recovery, And Availability

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| REL-001 | Every service shall publish health, readiness, dependency, saturation, and version signals suitable for automated supervision. | T | SA |
| REL-002 | Failure detection and automated restart shall be bounded to prevent crash loops, repeated external effects, and cascading resource exhaustion. | T | SA |
| REL-003 | Domain command authority shall use active-passive failover with durable leader election and fencing; multi-writer active-active command authority is prohibited. | A,T | SA |
| REL-004 | Failover shall preserve or explicitly reconcile controller lease, execution state, prompts, operations, event sequence, and driver attachment state. | T,E | MO |
| REL-005 | A dependency failure shall produce a documented domain/execution degraded state and fail-safe behavior based on effect certainty and operation class. | T,A | MO |
| REL-006 | Loss of authoritative persistence shall prevent new state-changing control or external-effect operations while allowing explicitly labeled cached observation where safe. | T | MO |
| REL-007 | Loss of a real-time delivery component shall not corrupt authoritative state; clients shall recover by snapshot and cursor. | T | SA |
| REL-008 | Loss of driver certainty shall pause or isolate affected operations and require reconciliation; it shall not report success or trigger automatic resend. | T | DA |
| REL-009 | Recovery shall be idempotent, revision guarded, audited, and testable after process, host, network, database, and site faults. | T,E | QL |
| REL-010 | The organization shall approve measurable availability, latency, freshness, capacity, RPO, RTO, failover, and data-retention targets for each environment before qualification. | I,A | PO |
| REL-011 | Watchdogs shall distinguish a slow operation from a dead service and shall not independently issue spacecraft commands or unsafe procedure transitions. | T | MO |
| REL-012 | Graceful shutdown shall stop admission, transfer or revoke authority, settle or checkpoint work, drain bounded streams, and record incomplete operations. | T,E | SA |
| REL-013 | Backup, restore, and disaster recovery shall be exercised at an approved cadence with evidence that restored state meets integrity and target values. | E | CM |
| REL-014 | A deployment shall publish qualified maximum executions, event rate, telemetry rate, monitor connections, reconnect surge, storage growth, and degraded behavior. | A,T | SA |
| REL-015 | Reliability profiles shall assign and qualify every `REL-PAR-*` parameter before operational authorization; this namespace shall remain distinct from NIST ODPs. | I,A | PO |
| REL-016 | A component shall expose separate liveness, readiness, safety-readiness, degradation, capacity, and freshness signals applicable to its role. | T | SA |
| REL-017 | A single service, worker, stream, driver host, or domain failure shall be isolated from unrelated domains and executions to the qualified fault set. | T,A | SA |
| REL-018 | Stale authority incarnations, assignment generations, leader epochs, controller fences, and driver generations shall be rejected at the authoritative write boundary and before driver effects. | T | SA |
| REL-019 | Database write-quorum loss shall stop new authoritative mutations and new external effects; cached observation shall be marked stale. | T | MO |
| REL-020 | Every nonterminal command, prompt, reservation, checkpoint, schedule, and driver operation shall have a deterministic restart reconciliation rule. | I,T | SA |
| REL-021 | `EFFECT_POSSIBLE` and `EFFECT_UNKNOWN` operations shall enter safe hold and shall never be automatically resent. | T | MO |
| REL-022 | A watchdog restart shall not alter command disposition, operation certainty, leader/controller fencing, or execution terminal state. | T | SA |
| REL-023 | Queue, journal, outbox, disk, and audit capacity shall reserve headroom and reject new work before required evidence can be overwritten or lost. | A,T | SA |
| REL-024 | Backup restore and site failover shall preserve immutable identities, monotonic fences, cursor continuity or explicit reset, audit integrity, and unresolved operation evidence. | T,E | CM |
| REL-025 | Restored or failed-over domains shall begin non-active and require a new leader epoch, dependency checks, driver fencing, and reconciliation before control resumes. | T,E | MO |
| REL-026 | Degraded operation shall be capability-specific, operator-visible, bounded by policy, and tested; no generic degraded flag shall imply control safety. | T,D | MO |
| REL-027 | Fault recovery shall preserve original time targets, telemetry cursors, prompt identities, and external-effect dispositions. | T | QL |
| REL-028 | Automatic restart and retry shall be bounded, observable, and quarantined after the configured threshold. | T | SA |
| REL-029 | Restore, failover, cutover, and failback shall allocate authority identity outside restored history and shall remain non-active until the prior integration path is proven fenced and unresolved effects are reconciled. | T,E | MO |

## Security And NIST SP 800-171 Support

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| SEC-001 | The governing agency, contract, or program authority shall establish and record SP 800-171 applicability and whether the system is operated on behalf of an agency; the System Owner shall then approve the CUI boundary, information flows, connected systems, data classes, responsible roles, and environment before any compliance assertion. | I,A | GA/SY |
| SEC-002 | The System Owner shall maintain an SSP, assign applicable ODPs, document requirement implementation, and permit non-applicability only when supported by governing scope, authorized tailoring, or agency/contract authority; controls shall be assessed and weaknesses tracked through an authorized POA&M and risk process. | I,E | SY/SO |
| SEC-003 | Human access shall use an approved enterprise identity provider, phishing-resistant MFA where required by policy, short-lived sessions, revocation, and reauthentication for sensitive actions. | I,T | SO |
| SEC-004 | Authorization shall combine role, principal attributes, domain, satellite, environment, procedure classification, operation, lease/fence, resource, and time/context policy using deny by default. | T | SO |
| SEC-005 | Service identities shall be unique, mutually authenticated, least privileged, rotatable, and attributable; shared service credentials are prohibited. | I,T | SO |
| SEC-006 | Administrative, security, procedure-development, promotion, controller, monitoring, and service duties shall be separable and independently assignable. | I,T | SO |
| SEC-007 | Privileged and security-sensitive actions shall require auditable reason, approved authorization, and step-up or dual approval where policy defines it. | T,D | SO |
| SEC-008 | Communications and stored protected data shall use approved cryptography and managed keys; FIPS-validated cryptographic modules shall be used when required by assigned cryptography type, agency policy, or contract. | I,T | SO |
| SEC-009 | Secrets shall be generated, stored, accessed, rotated, revoked, and audited through an approved secret/key management service and shall not appear in source, logs, bundles, browser storage, or routine exports. | I,T | SO |
| SEC-010 | Security audit shall record identity, action, target, domain, time source, outcome, reason, policy decision, lease/fence/revision, correlation, and relevant before/after references. | T | SO |
| SEC-011 | Audit records shall be access controlled, time synchronized, integrity protected, retained by policy, queryable, exportable to an independent tamper-resistant destination, and monitored for loss or modification. | T,E | SO |
| SEC-012 | Network policy shall segment ingress, control, execution, driver, data, artifact, management, and observability paths and shall deny unapproved east-west and outbound traffic. | I,T | SO |
| SEC-013 | Procedure workers and driver hosts shall run with hardened identities, resource limits, read-only base filesystems where feasible, controlled writable roots, restricted system calls, and no ambient privilege. | I,T | SO |
| SEC-014 | The product shall validate all untrusted browser, API, Git, procedure, configuration, driver, telemetry, and imported artifact input against bounded schemas and canonicalization rules. | T | SO |
| SEC-015 | Security baselines, configuration changes, vulnerability findings, patches, exceptions, and drift shall be versioned, approved, monitored, and retained. | I,T | SO |
| SEC-016 | The build shall produce dependency locks, SBOMs, provenance, signatures, vulnerability results, license results, and reproducibility evidence for each releasable artifact. | I,T | CM |
| SEC-017 | Releases shall be promoted by verified digest and signature from trusted builders; deployment shall reject unauthorized or tampered images, bundles, and configuration. | T | SO |
| SEC-018 | The organization shall maintain incident detection, triage, containment, evidence preservation, recovery, notification, and lessons-learned procedures for SPELL. | I,E | SO |
| SEC-019 | Security logs and alerts shall cover authentication, authorization denials, controller conflicts, stale fencing, configuration drift, integrity failure, audit loss, suspicious procedure/Git activity, driver anomalies, and export activity. | T,E | SO |
| SEC-020 | Media, export, backup, support-bundle, and diagnostic workflows shall enforce classification, minimization, authorization, encryption, accountability, and sanitization policy. | I,T | SO |
| SEC-021 | Personnel, training, physical, maintenance, and external-service requirements outside software shall have named organizational owners and assessment evidence. | I | SO |
| SEC-022 | The assessment sponsor or customer, in coordination with an authorized assessor, shall approve SP 800-171A Rev. 3 purpose, scope, depth, coverage, sampling, methods, and objects; findings and evidence shall be recorded, and assessor independence shall be required when governing policy or contract requires it. | I,E | AS/QL |
| SEC-023 | Each deployment assessment shall reconcile every official SP 800-171 requirement and SP 800-171A determination statement to applicability authority, ODPs, responsibility allocation, implementation, method, depth, coverage, evidence, result, finding, POA&M, risk decision, and exact assessed baseline. | I,E | AS/SO |

## Operations And Maintainability

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| OPS-001 | Each production service and domain shall have named owner, on-call route, dependency map, dashboards, alerts, runbooks, SLOs, and escalation policy. | I,E | PO |
| OPS-002 | Metrics, diagnostic logs, distributed traces, security audit, and as-run records shall be distinct data products with defined correlation and access rules. | I,T | SO |
| OPS-003 | Observability shall not expose secrets, protected procedure input, credentials, or unnecessary CUI and shall apply bounded cardinality and retention. | T | SO |
| OPS-004 | Time shall be synchronized to approved sources; loss of synchronization or excess uncertainty shall be detected, surfaced, audited, and handled by operation policy. | T,E | MO |
| OPS-005 | Alerts shall be actionable, severity classified, deduplicated, routed, acknowledged, escalated, and tested; loss of the alert path shall itself alert through an independent path. | T,E | QL |
| OPS-006 | Runbooks shall cover controller loss, stale client, leader failover, worker failure, driver uncertainty, database loss, stream gaps, identity outage, key compromise, audit failure, capacity exhaustion, and site recovery. | I,E | MO |
| OPS-007 | Administrative operations shall use authenticated, authorized, audited interfaces and shall not require direct production database mutation. | I,T | SO |
| OPS-008 | Configuration and release rollout shall use staged promotion, health checks, compatibility gates, bounded rollback, and recorded outcome. | D,T | CM |
| OPS-009 | Capacity forecasts shall use measured workload profiles and growth, not an assumption of unlimited compute, connections, storage, or operators. | A | SA |
| OPS-010 | Support bundles shall be minimal, filtered, manifest signed, access controlled, and independently reviewed before leaving the authorized environment. | I,T | SO |

## Compatibility And Migration

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| COMP-001 | Every in-scope language construct, function, modifier, constant, result, action, example, driver service, method, lifecycle behavior, and operator workflow shall have a compatibility disposition before its implementation gate. | I | QL |
| COMP-002 | Allowed dispositions shall be exact observable compatibility, equivalent with safety strengthening, legacy syntax translated, optional adapter capability, deliberately unsupported, or documentation ambiguity. | I | LA |
| COMP-003 | Each disposition shall identify source version/hash/pages, stable artifact identity, legacy behavior, modern behavior, effect class, recovery, target increment, conformance tests, and approvals. | I | QL |
| COMP-004 | A documentation ambiguity shall remain unimplemented until an approved decision and test oracle resolve it. | I,T | LA |
| COMP-005 | Deliberately unsupported behavior shall fail with a stable diagnostic and documented migration path; it shall not silently change meaning. | T | LA |
| COMP-006 | Python 2 syntax retained for compatibility shall be translated explicitly to the bounded Python 3 profile and shall not select a Python 2 runtime. | T | LA |
| COMP-007 | Driver capability negotiation shall distinguish unavailable service, unsupported method/modifier, invalid request, transient failure, permanent failure, timeout, cancellation, resource exhaustion, and uncertain effect. | T | DA |
| COMP-008 | Legacy procedure import shall be non-executing, preserve original bytes and provenance, report all diagnostics, and produce no promotable bundle until every blocking issue is resolved. | T | LA |
| COMP-009 | Migration shall proceed simulator first, then approved read-only observation, then separately authorized effect classes; no phase shall imply authority for the next. | I,D | MO |
| COMP-010 | Legacy and new-system comparison shall use approved golden traces, deterministic simulator vectors, and normalized observable outcomes without copying proprietary implementation code. | T | QL |
| COMP-011 | An active execution shall remain pinned to its bundle and compatibility profile across catalog update, rollback, or repository change. | T | LA |
| COMP-012 | A compatibility exception shall include operational impact, hazard/security analysis, affected procedures/adapters, rollback, expiry or review date, and explicit acceptance. | I | MO |
| COMP-013 | Authority manifests shall verify the exact Language Reference and Driver Manual hashes before compatibility work or release. | I,T | CM |
| COMP-014 | Every documented public item and example shall have one populated, reviewed disposition with reconciling source counts. | I | QL |
| COMP-015 | Source parsing, translation, validation, and compilation shall never execute procedure code or resolve uncontrolled resources. | T | LA |
| COMP-016 | Runtime shall load only signed, schema-valid, data-only IR from an immutable approved bundle. | T | SO |
| COMP-017 | Unsupported and ambiguous behavior shall fail with stable diagnostics; partial driver support shall never silently succeed. | T | LA |
| COMP-018 | Golden tests shall distinguish all documented results, defaults, ordering, actions, and failure or uncertainty outcomes. | T | LA |
| COMP-019 | Every promoted procedure shall pass deterministic simulation and approved trace comparison for all used ledger rows. | T,D | QL |
| COMP-020 | Legacy and modern command authority shall not be active for the same satellite during comparison or cutover. | T,D | MO |
| COMP-021 | Driver lifecycle ordering and advertised capability semantics shall pass contract and fault-injection tests. | T | DA |
| COMP-022 | Any semantic deviation shall identify owner, rationale, security/reliability impact, test oracle, approval, and user-visible migration guidance. | I | LA |

## Deployment And Scalability

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| DEP-001 | Deployment artifacts and configuration shall be declarative, versioned, reviewed, reproducible, signed, and promoted by digest. | I,T | CM |
| DEP-002 | Stateless ingress/API/read projection components may scale horizontally without creating a second command authority. | A,T | SA |
| DEP-003 | Each domain shall have independent quotas, scheduling, failure budget, database scope, driver binding, keys/policy scope, and observability dimensions. | I,T | SA |
| DEP-004 | Multiple domains may share approved platform services only when resource isolation, access control, failure containment, and recovery have been demonstrated. | A,T | SA |
| DEP-005 | Deployment shall support at least a single-site non-operational profile and an active-passive high-availability profile; production topology is an approved mission decision. | D,T | SA |
| DEP-006 | Scale-out of monitor delivery shall use authenticated fan-out and resumable projections and shall not load the authoritative database without bounded protection. | A,T | SA |
| DEP-007 | Resource requests, limits, disruption policy, topology placement, anti-affinity, storage class, backup, and secret injection shall be explicit per environment. | I,T | SA |
| DEP-008 | Upgrade compatibility shall be declared for API, event, database, IR, bundle, driver, configuration, and browser versions before rolling deployment. | I,T | CM |
| DEP-009 | Unsupported downgrade or mixed-version combinations shall fail before authority transfer rather than during procedure execution. | T | CM |
| DEP-010 | A deployment shall deny direct public access to databases, driver hosts, workers, message infrastructure, object storage administration, and management endpoints. | I,T | SO |
| DEP-011 | Production deployments shall use a version-controlled environment manifest with immutable artifact and configuration identities. | I,T | CM |
| DEP-012 | One satellite domain shall have one active service leader, one active controller lease at most, and no active-active driver effect path. | T,A | SA |
| DEP-013 | API and stream tiers shall scale horizontally without moving write authority from the domain leader and PostgreSQL. | A,T | SA |
| DEP-014 | Shared infrastructure shall enforce domain isolation with identity, authorization, network policy, queues, quotas, data scope, and failure-domain placement. | A,T | SO |
| DEP-015 | Browser and worker networks shall have no route to driver hosts, GCS endpoints, PostgreSQL, secrets, or management interfaces except their explicitly documented narrow services. | I,T | SO |
| DEP-016 | A deployment shall assign finite concurrency, throughput, storage, retention, replay, and recovery budgets and qualify them with required failure headroom. | A,T | SA |
| DEP-017 | Monitoring shall have no product-imposed fixed user cap, while each deployment shall publish tested connection and event-rate capacity and controlled overload behavior. | A,T | PO |
| DEP-018 | Engineering, HA, and disaster-recovery profiles shall be labelled accurately; an engineering or single-node install shall not claim high availability or operational authorization. | I | QL |
| DEP-019 | Site disaster recovery shall be active/passive for control and shall fence the previous site's integration authority before promotion. | T,E | MO |
| DEP-020 | Deployment configuration shall be typed, reviewed, immutable per generation, precedence-defined, integrity-protected, and rejected on unknown safety-relevant fields. | I,T | CM |
| DEP-021 | Secrets shall be delivered through approved secret-reference and workload-identity mechanisms and shall not be embedded in images, Git, configuration payloads, events, or logs. | I,T | SO |
| DEP-022 | Upgrades shall preserve mixed-version compatibility for the declared window, transition domains in a controlled order, and retain all audit and effect evidence across rollback. | T,D | CM |
| DEP-023 | Every production profile shall provide tested backup/restore, clock, identity, audit, observability, certificate rotation, vulnerability remediation, and incident access procedures. | I,E | QL |
| DEP-024 | Capacity and fault qualification shall include simultaneous peak monitoring, peak qualified execution, dependency degradation, and loss of one claimed failure domain. | A,T | SA |
| DEP-025 | Every command-capable deployment shall use the Satellite Assignment Authority across all clusters and sites; inability to reach it or prove the prior path fenced shall prevent activation while permitting explicitly stale or read-only observation. | T,E | SA |

## Verification And Release Gates

| ID | Requirement | Verify | Owner |
| --- | --- | --- | --- |
| VNV-001 | Every release claim shall identify exact source, dependencies, configuration, data fixture, environment, command, result, and evidence digest. | I | QL |
| VNV-002 | Requirements shall trace bidirectionally to design, implementation, tests, results, open findings, and approval. | I,T | QL |
| VNV-003 | Language conformance shall include accepted, boundary, malformed, adversarial, recovery, and manual-example vectors for each implemented compatibility row. | T | LA |
| VNV-004 | Driver conformance shall include lifecycle, schema, capability, deadline, cancellation, backpressure, concurrency, failure, restart, and effect-certainty vectors. | T | DA |
| VNV-005 | State, lease, fencing, revision, prompt, operation, and event invariants shall use model/property tests in addition to scenario tests. | T | QL |
| VNV-006 | Fault testing shall cover process kill, host loss, partition, duplication, reordering, latency, database failover, storage exhaustion, clock fault, identity outage, and site recovery. | T,E | QL |
| VNV-007 | Security verification shall include threat-model review, static and dynamic analysis, dependency and container scanning, configuration tests, penetration testing, and SP 800-171A-aligned assessment evidence as applicable. | I,T,E | SO |
| VNV-008 | Web acceptance shall cover supported browsers/viewports, accessibility, stale/gap/reconnect behavior, authorization races, prompt races, controller handover, critical workflows, and human factors. | T,D | MO |
| VNV-009 | Performance qualification shall use an approved workload profile and report latency distributions, freshness, throughput, saturation, errors, recovery, and evidence-bound configuration. | A,T | SA |
| VNV-010 | Backup and disaster-recovery qualification shall prove integrity and approved RPO/RTO through restore and service-recovery exercises. | E | CM |
| VNV-011 | An implementation shall not connect to an operational GCS or satellite until simulator, security, integration, recovery, operational, and authorization gates for that capability have passed. | I,D | MO |
| VNV-012 | A failed mandatory gate shall block promotion unless the accountable authority records a time-bounded exception with impact, compensating controls, evidence, and rollback. | I | QL |
