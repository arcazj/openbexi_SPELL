# ADR-003: Single-Writer Control With Active-Passive HA And Fencing

## Status

Proposed for the next-generation design baseline. It becomes accepted only when
the repository baseline is approved.

## Context

High availability needs redundant processes and sites. Satellite command
authority, execution transitions, prompts, and scheduler reservations cannot be
multi-writer without resolving conflicting decisions and uncertain external
effects. Network partitions can leave two processes or sites believing they are
active. A load balancer, orchestrator lease, or heartbeat alone does not prevent
a stale instance from reaching a database or driver.

The platform also has two different ownership questions:

1. Which service instance may commit domain state?
2. Which authenticated person may issue execution-control commands?

Conflating these leases would make failover either unsafe or dependent on one
browser session.

## Decision

Use active/passive control authority per Satellite Control Domain with layered
fencing:

- **Satellite assignment:** a mission-wide linearizable authority issues one
  active assignment generation and fresh `AuthorityIncarnationId` across all
  clusters, sites, and legacy/new systems.
- **Service leadership:** one active domain leader has a monotonically
  increasing `leader_epoch`. Passive candidates may serve no authoritative
  domain mutation.
- **Human control:** at most one controller lease has a monotonically
  increasing `control_fencing_token`. It survives ordinary API replica changes
  but follows its own expiry/revocation policy.
- **Integration generation:** driver host, context, execution attachment, and
  binding generations prevent delayed calls from an old configuration or
  process from reaching an effect boundary.
- **Operation identity:** stable `operation_id` and driver journal prevent
  duplicate effect when a response is lost.

Public API and WebSocket replicas may all be active. They forward or persist
requests through the current authoritative path; they do not independently
decide execution state. Read replicas and caches may scale observation with
visible freshness.

## Leadership Protocol

1. A candidate proves service identity, approved configuration, clock bounds,
   database primary connectivity, and required dependency readiness.
2. It acquires a bounded infrastructure leadership lease to reduce contention.
3. In an authoritative PostgreSQL transaction, it locks the domain leadership
   row, verifies takeover conditions, and increments `leader_epoch`.
4. It publishes the new epoch to workers and gateway, which reject lower terms.
5. It reconciles every nonterminal execution, command, prompt, reservation, and
   driver operation.
6. It declares the permitted capability set active only after reconciliation
   and safety-readiness checks.

The infrastructure lease is coordination; the PostgreSQL epoch is the write
fence. Every domain mutation compares the epoch. Driver requests also carry it
and all relevant generation values. The old leader cannot commit or dispatch an
accepted effect after takeover.

## Controller Protocol

Controller acquisition is a separate database transaction. A new ownership
grant increments `control_fencing_token`. A renewal by the same holder retains
the token, advances lease revision, and uses database time. Expiry, release,
revocation, or assurance loss makes the lease inactive without consuming a
fence; the next grant receives a greater token. Forced takeover creates a new
lease and token.

Every execution-control command records authority incarnation, lease ID and
revision, control fence, authenticated subject/session, tab-local client proof,
leader epoch, expected resource revision, idempotency key, and policy decision.
The write transaction revalidates all applicable fields. The effect boundary
revalidates the active lease, incarnation, fence, and dispatch credentials. A
stale request is rejected even if an API gateway authenticated it earlier.

## Driver Fencing

The gateway includes satellite and domain, authority incarnation, assignment
generation, leader epoch, control lease/fence when applicable, driver-host
generation, context generation, execution-attachment generation, binding ID,
operation ID, attempt ID, request digest, deadline, and decision-evidence digest
on an effecting call. The driver host has no effect credential or direct GCS
route. It submits the typed request to the Effect Authorization Point.

Immediately before effect, the Effect Authorization Point locks the primary
PostgreSQL authority, lease, and operation-attempt rows. While those locks are
held, it consumes a one-use attempt permit through a linearizable SAA operation.
Failed SAA consumption rolls back locally; an SAA permit whose local commit
fails is abandoned and never reused. The local commit records permit receipt and
journal intent before send. This orders SAA revocation at the SAA and controller
release, expiry, revocation, or takeover at PostgreSQL without claiming one
cross-system ACID transaction. If consume/commit wins, later authority loss
cannot erase the already authorized attempt and recovery must reconcile it. If
either authority change wins, dispatch is rejected. Loss of either quorum, time,
or credential certainty denies effect.
Once a generation is fenced, it never becomes active again; recovery creates a
new externally anchored generation.

External infrastructure should add an independent fence where possible, such
as exclusive authenticated session, endpoint-side epoch, or command-channel
ownership. If a legacy GCS cannot fence stale clients, takeover remains blocked
until the prior path is demonstrably isolated, and the limitation is part of
the operational risk decision.

## Failover And Uncertain Effects

Failover pauses new mutation while the new leader reconciles. For each driver
operation:

- proven not attempted or no-effect operations follow their declared retry
  policy using stable identity;
- confirmed effects are consumed without repetition; and
- possible or unknown effects hold the affected execution for reconciliation.

Availability pressure never converts missing acknowledgement into permission to
resend.

## Alternatives Considered

### Active-Active Writers Per Domain

Rejected. Conflict-free database writes would not resolve competing procedure
controls or duplicate satellite effects, and consensus at every application
edge would add complexity without permitting two command authorities.

### Orchestrator Lease Only

Rejected. A partitioned old process may retain database or driver access after
the orchestrator believes its lease expired.

### Database Advisory Lock Only

Rejected as the complete design. Connection loss releases the lock but does not
fence already dispatched work, workers, driver hosts, or another integration
session. A durable epoch and generation tuple remain necessary.

### One Lease For Service And Human Controller

Rejected. Service failover should not silently transfer or terminate human
ownership, and browser loss should not prevent backend HA.

## Consequences

Positive:

- split brain cannot produce two committed domain histories;
- service failover and human control ownership are independently explainable;
- delayed work from old processes and configurations is rejected;
- passive replicas improve availability without changing satellite authority;
  and
- operation recovery preserves effect certainty.

Costs:

- every mutation and driver call carries and validates more identity;
- takeover includes reconciliation and may take longer than process restart;
- generation changes and controller takeover require durable audit; and
- adapters without external fencing may limit automated failover.

## Affected Requirements (Non-Normative Traceability)

This relationship list identifies central requirements potentially affected by
the decision; it does not allocate normative authority to this ADR. The
authoritative allocation is `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`.

`ARC-013`, `ARC-022`, `ARC-029` through `ARC-040`, `SRV-005` through
`SRV-022`, `MODE-013` through `MODE-022`, `REL-003` through `REL-029`, and
`DEP-012`, `DEP-019`, `DEP-025`.

## Migration And Rollback

Introduce authority incarnation and controller-proof fields before enforcing
them, then rotate every domain through a controlled new assignment. Rollback
may use an older compatible binary only after a fresh externally anchored target
assignment is reserved effect-disabled, old-path fence evidence is bound to that
target, and reconciliation plus readiness pass. Only then may the assignment
activate and fresh credentials issue; rollback cannot reactivate an old command
path or fence tuple.

## Approval

Pending Gate G0 approval under `OD-023` by the System Architect, Mission
Operations Authority, System Owner, Security Officer, Driver Authority, and
Quality Lead.

## Verification

- Partition the leader independently from orchestrator, database, workers, and
  driver and prove only the current epoch can commit or effect.
- Race lease renew, expiry, release, revocation, and forced takeover with every
  control command.
- Delay old-generation RPCs until after takeover and prove driver rejection
  before Effect Authorization Point permit consumption/effect.
- Race final permit consumption against lease release, expiry, revocation, and
  takeover; prove one database-serialized winner and correct uncertain-effect
  reconciliation when dispatch wins.
- Deny the driver host direct GCS egress and credential access in policy and
  runtime tests.
- Crash each layer around effect intent/result and prove no possible or unknown
  effect is resent automatically.
- Restore a backup and prove a fresh authority incarnation is first reserved
  effect-disabled, final old-path fence evidence binds that target, restored
  state is reconciled and passes readiness, and only then may the grant activate
  and fresh effect credentials issue.
