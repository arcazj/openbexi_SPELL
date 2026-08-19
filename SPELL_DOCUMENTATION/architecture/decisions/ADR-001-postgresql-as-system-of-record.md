# ADR-001: PostgreSQL As The Transactional System Of Record

## Status

Proposed for the next-generation design baseline. It becomes accepted only when
the repository baseline is approved. Reassessment then requires the measured
triggers below and a replacement ADR. Operational topology remains a separate
deployment approval.

## Context

SPELL must atomically coordinate domain leadership, one human controller lease,
multiple execution state machines, checkpoints, prompts, schedules, admission
reservations, idempotent commands, driver-operation certainty, audit evidence,
and committed real-time events. These records are relational, constrained, and
frequently changed together. A failure must be explainable, recoverable, and
testable without reconstructing control authority from best-effort messages.

The legacy product already used PostgreSQL. Modernization is not itself a reason
to replace a suitable database. The evaluation asks whether an alternative
improves measured performance, scalability, reliability, and operational
simplicity without weakening transactions, fencing, recovery, or audit.

## Decision Drivers

- atomic state, audit, and outbox commits;
- compare-and-set revisions and uniqueness constraints;
- durable monotonic leader and controller fencing;
- mature backup, point-in-time recovery, replication, failover, and tooling;
- predictable operation in disconnected or on-premises mission environments;
- strong Python ecosystem and portable deployment choices;
- structured relational data with bounded JSON flexibility;
- read replicas, partitioning, indexing, and archival for scale; and
- a small, understandable authoritative-data surface.

## Options Considered

### PostgreSQL As Authority, Specialized Derived Stores Where Justified

Strengths: ACID transactions, constraints, mature HA/backup ecosystem,
row-level concurrency, SQL analysis, JSONB for bounded extensions, logical and
physical replication options, and established operations. It supports the
transactional outbox so state and publishable events cannot diverge.

Limits: one write-primary model requires capacity engineering; high-rate raw
telemetry and large artifacts are poor fits; HA quality depends on disciplined
deployment and tested failover.

### Distributed SQL As The Initial Authority

Strengths: horizontal write distribution and multi-zone replication.

Limits: higher operational and failure-model complexity, latency from consensus,
product-specific SQL semantics, difficult disconnected deployment, and no
demonstrated need in the current workload. Multi-writer storage would not remove
the single-writer control requirement for a satellite.

### Event Store As The Sole Authority

Strengths: natural history and replay.

Limits: leases, uniqueness, prompt settlement, current-state constraints,
migrations, privacy/retention, and external-effect reconciliation become more
complex. Replay does not make GCS effects reversible. An append-only audit and
outbox can be obtained without making every aggregate event-sourced.

### Document Or Key-Value Database As The Authority

Strengths: flexible schemas and easy scale for some access patterns.

Limits: weaker or more complex cross-record constraints and transactions,
greater application responsibility for invariants, and no material advantage
for the core relational state.

### Polyglot Authorities From The Start

Strengths: each workload can use a specialized engine.

Limits: ambiguous ownership, distributed consistency, more credentials,
backups, migrations, security evidence, failure modes, and operator skill. This
increases mission risk before load proves the need.

## Decision

Use PostgreSQL as the sole transactional authority inside each domain for control,
leadership and controller fencing, executions, checkpoints, schedules,
reservations, prompts, commands, driver-operation state/certainty, audit, and
the transactional outbox. It also serializes one-use Effect Authorization Point
permit consumption with lease and authority changes immediately before effect.

Use:

- a separate mission-wide Satellite Assignment Authority as the linearizable
  authority for cross-cluster satellite assignment and non-restorable
  authority-incarnation allocation;
- a mandatory non-rollback generation anchor outside the SAA recovery set;
- Git as the authority for editable procedure source and review history;
- immutable object storage for promoted bundle bytes, large reports, protected
  log segments, and backup objects, referenced by digest from PostgreSQL;
- an optional broker only as replaceable outbox/telemetry transport;
- an optional time-series or analytics store for full-rate history and derived
  queries; and
- an approved secrets/key service for credentials and key material.

These systems have explicit ownership. A broker, cache, read replica, search
index, telemetry store, or object store cannot grant control, settle a prompt,
decide an execution transition, or resolve external-effect certainty.

PostgreSQL uses one writable primary per protected data set. High availability
uses qualified standby replication and failover. Domain-aware partitioning,
short transactions, pooling, appropriate indexes, archival, read replicas, and
derived-store offload precede any database replacement.

## Consequences

Positive:

- critical invariants are implemented and tested at both application and
  database boundaries;
- state, audit, and stream events commit atomically;
- recovery starts from one consistent operational ledger;
- operations, backup, security hardening, and assessment scope remain bounded;
  and
- optional high-rate systems can evolve without changing control semantics.

Costs and constraints:

- primary write capacity and lock behavior require measurement;
- schema migrations and partition maintenance are release-critical operations;
- replication mode must match declared RPO rather than rely on defaults;
- external driver effects still require a private journal/reconciliation
  protocol because no database transaction spans the GCS; and
- object, Git, key, and derived-store consistency must be verified through
  manifests and references.

## Guardrails

- No dual-write path may make PostgreSQL and another store co-authoritative.
- State change, audit evidence, and outbox record commit in one transaction.
- Common constrained fields use typed columns; JSONB is limited to versioned,
  validated extensions and safe event payloads.
- Workers, browsers, and driver hosts have no database route or credential.
  The Effect Authorization Point has a narrowly scoped primary route solely for
  final authority validation, permit consumption, and journal evidence.
- Restore preserves immutable IDs, event continuity or an explicit cursor
  reset, unresolved operation evidence, and artifact links. Restored numeric
  fences cannot authorize control until the assignment authority allocates a
  new `AuthorityIncarnationId` outside restored history.
- Full-rate telemetry may bypass PostgreSQL only if every sample used by a
  procedure or alarm is durably captured as execution evidence.

## Reconsideration Triggers

A replacement may be evaluated when repeatable qualification shows all of the
following:

1. A well-tuned, correctly partitioned HA PostgreSQL design cannot meet the
   declared workload with required failure headroom.
2. High-rate derived workloads have already been separated and query/index/
   transaction causes are understood.
3. The proposed alternative preserves or improves transactions, domain fencing,
   idempotency, backup/restore, audit, migration, disconnected operation, and
   operational support.
4. Migration and rollback can retain immutable identity and every unresolved
   external-effect disposition.
5. Total operational and security-assessment complexity is justified by a
   measured system benefit.

Adding satellites alone is not a trigger: domains can be placed across multiple
independent PostgreSQL clusters while keeping one authority per domain.

## Affected Requirements (Non-Normative Traceability)

This relationship list identifies central requirements potentially affected by
the decision; it does not allocate normative authority to this ADR. The
authoritative allocation is `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`.

`ARC-016`, `ARC-031`, `ARC-036` through `ARC-040`, `DATA-001` through
`DATA-029`, `REL-024` through `REL-029`, and `DEP-019` through `DEP-025`.

## Migration And Rollback

Migrate with expand/contract schema changes, dual-read comparison for derived
projections, immutable backups, and a rehearsed restore. Rollback may return to
a compatible application/schema version but cannot reuse an old authority
incarnation or discard records created by the newer version.

## Approval

Pending Gate G0 approval under `OD-023` by the System Architect, Configuration
Manager, Mission Operations Authority, System Owner, Security Officer, and
Quality Lead.

## Verification

- Measure transaction, lock, storage, replica-lag, failover, restore, and outbox
  performance at qualified multi-domain execution and monitor load.
- Prove all lease, prompt, idempotency, and revision races are constrained in
  the schema.
- Crash writers and relays at every boundary and verify state/event consistency.
- Restore populated backups and reconcile object, Git, cursor, fence, and driver
  operation references before activation.
