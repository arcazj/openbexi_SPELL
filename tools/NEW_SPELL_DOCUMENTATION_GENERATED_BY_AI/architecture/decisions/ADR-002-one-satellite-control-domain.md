# ADR-002: One Satellite Per Logical Control Domain

## Status

Proposed for the next-generation design baseline. It becomes accepted only when
the repository baseline is approved.

## Context

The product requirement states that each SPELL server controls one satellite,
may execute multiple procedures concurrently for that satellite, and shall
scale to multiple SPELL servers for multiple satellites. Modern deployment
platforms make the word "server" ambiguous: it might mean a process, VM,
container, host, replica set, or logical service.

Safety and recovery require a stable boundary for command authority,
controller ownership, driver configuration, telemetry namespace, capacity,
audit, and degraded behavior. Tying that boundary to one replaceable process
would prevent high availability; allowing one authority to span arbitrary
satellites would enlarge failure and credential scope.

## Decision

Define **Satellite Control Domain** as the logical modern equivalent of one
SPELL server. Each domain:

- has exactly one immutable `SatelliteId`;
- becomes command-active only under the current mission-wide satellite
  assignment and `AuthorityIncarnationId`;
- has one active service leader epoch at a time;
- has at most one active human execution-controller lease at a time;
- owns its context generations, driver bindings and credentials, executions,
  prompts, schedules, shared runtime data, alarms, audit, queues, and quotas;
- supports multiple concurrent procedure instances after explicit admission and
  resource-conflict checks; and
- may be implemented by several active/passive service replicas without
  becoming more than one logical server.

A mission platform supports multiple satellites by creating multiple domains.
Domains may share approved infrastructure, but not leadership epochs,
controller fencing tokens, driver credentials, mutable runtime namespace, or
control queues.

## Concurrency Within A Domain

Multiple procedures are independent by `execution_id`, even when they use the
same bundle. The scheduler enforces:

- domain and worker capacity;
- context and driver attachment capacity;
- capability-specific in-flight limits and serialization keys;
- declared exclusive satellite resources;
- shared-data compare-and-set policy;
- procedure dependencies and child-depth bounds; and
- mission-defined priority and conflict rules.

One human controller can manage all admitted procedures in the domain. Monitor
and developer rights do not fragment or bypass that ownership rule.

## Cross-Satellite Operations

Atomic cross-domain command groups are not part of the domain contract. A
mission coordinator may submit separately authenticated and authorized requests
to several domains, but each request retains that domain's controller lease,
fencing, command identity, effect certainty, and audit. Failure in one domain
cannot be rolled back by pretending an external effect in another did not
occur.

Read-only fleet views may aggregate domain projections. They display each
domain's cursor, freshness, health, controller, and uncertainty independently.
An aggregate view is not a control authority.

## Alternatives Considered

### One Physical Process Per Satellite

Rejected as the architectural definition. It is a valid small deployment but
cannot provide replica failover or independent public-tier scaling.

### One Global Control Server For All Satellites

Rejected. It enlarges blast radius, creates a global controller ambiguity,
couples maintenance/failure, and risks cross-satellite credential or command
routing.

### One Domain Per Procedure

Rejected. It loses the documented shared spacecraft context and one-controller-
per-server behavior and makes conflict arbitration across procedures unsafe.

### Dynamically Move One Execution Between Satellite Domains

Rejected for active executions. Satellite, bundle, context, and driver identity
are fixed at admission. A new execution may be created in another domain through
an explicitly authorized operation; state is not silently retargeted.

## Consequences

Positive:

- one clear safety, identity, audit, and failure-containment boundary;
- horizontal mission scale by adding domains;
- HA replicas do not change the product ownership model;
- concurrent procedures share a scheduler that can detect satellite resource
  conflicts; and
- monitoring and operations can reason about freshness and degradation per
  satellite.

Costs:

- mission-wide orchestration cannot rely on one ACID transaction;
- shared infrastructure needs strong domain isolation and noisy-neighbor
  controls; and
- configuration, capacity, backup, and disaster recovery must be recorded per
  domain even when centrally managed.

## Invariants

- No execution changes `SatelliteId` or `DomainId` after admission.
- A driver operation includes domain, satellite, context generation, driver
  binding, and leader epoch and is rejected on mismatch.
- At most one effect-enabled legacy or modern path may exist for the satellite
  throughout activation, drain, and transition. Entering `DRAINING` first sets
  `effect_enabled=false`; a replacement remains non-effecting until the old path
  is independently fenced. The sole Effect Authorization Point binds its
  credential and egress route to the current domain authority tuple.
- A human control token is valid in exactly one domain.
- A domain's failure or resource exhaustion cannot consume another domain's
  reserved control or audit capacity beyond the qualified shared-infrastructure
  fault model.
- A fleet UI clearly labels aggregated state as derived and never hides a stale
  or uncertain member domain.

## Affected Requirements (Non-Normative Traceability)

This relationship list identifies central requirements potentially affected by
the decision; it does not allocate normative authority to this ADR. The
authoritative allocation is `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`.

`ARC-001` through `ARC-003`, `ARC-026` through `ARC-040`, `SRV-001` through
`SRV-004`, `SRV-013`, `SRV-022`, `DEP-003`, `DEP-012`, and `DEP-025`.

## Migration And Rollback

Legacy server identities are mapped once to immutable `DomainId` and
`SatelliteId` values and to a legacy-adoption record containing every command
credential, session, endpoint, egress route, interlock, and operator path.
Cutover is active/passive through the Satellite Assignment Authority; rollback
is a new externally anchored assignment generation and authority incarnation,
never simultaneous legacy/new command authority.

## Approval

Pending Gate G0 approval under `OD-023` by the Product Owner, System Architect,
Mission Operations Authority, System Owner, Security Officer, Driver Authority,
and Quality Lead.

## Verification

- Run concurrent procedures with conflicting and nonconflicting resources and
  prove deterministic admission, serialization, and visible queue reasons.
- Attempt cross-domain token, cursor, execution, binding, telemetry, and driver
  operation substitution and verify rejection.
- Saturate and fail one domain while measuring qualified operation of another.
- Fail over a domain between service replicas and prove it remains one logical
  server with one leader, controller, and satellite identity.
