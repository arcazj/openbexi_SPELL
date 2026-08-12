# System Context

## Purpose

This document defines the system boundary, external actors, trust relationships,
and non-negotiable architecture invariants for the next-generation SPELL
platform. It modernizes the deployment and integration model while preserving
the procedure and driver concepts defined by the authoritative SPELL 2.4.4
language and driver manuals.

## Scope

The product is a mission-operations platform for authoring, validating,
executing, and observing SPELL procedures. One logical **Satellite Control
Domain** controls one satellite. A deployment may run many domains, and each
domain may run many procedure instances concurrently subject to configured
resource and safety constraints.

The product boundary includes:

- the browser-based execution, monitoring, and editing experiences;
- authenticated public APIs and committed real-time projections;
- domain supervision, scheduling, execution, prompting, and recovery;
- isolated procedure workers, a typed driver gateway, and the Effect
  Authorization Point (EAP);
- authoritative operational state, audit evidence, and immutable procedure
  bundles; and
- health, metrics, logs, backup, and administrative interfaces.

Identity providers, Git hosting, secrets management, time sources, object
storage, ground-control systems, satellite links, and enterprise monitoring may
be external services. Their availability and assurance properties form part of
the deployed system's authorization boundary even when they are not delivered
by SPELL.

## Actors And External Systems

| Actor or system | Interaction | Trust rule |
| --- | --- | --- |
| Active controller | Starts and manages procedures and settles prompts | Exactly one authenticated user may hold the domain control lease at a time |
| Monitoring user | Reads state, logs, telemetry, alarms, and notifications | Has no mutation route, including through WebSocket or driver APIs |
| Procedure developer | Authors, validates, reviews, and promotes procedure source | Cannot edit an active runtime bundle or acquire execution rights by virtue of edit rights |
| Mission administrator | Configures domains, policies, limits, and emergency administrative actions | Uses separately authorized, audited operations; is not an implicit controller |
| Security auditor | Reads protected audit evidence and assessment exports | Cannot alter runtime or audit records |
| Enterprise identity provider | Authenticates people and supplies approved identity claims | Claims are mapped to local policy; absence or ambiguity fails closed |
| Git service | Stores procedure source, reviews, branches, and signed release references | Runtime consumes only approved immutable bundles, never a mutable branch checkout |
| Secrets and key service | Supplies short-lived credentials and cryptographic keys | Secrets are referenced by opaque identity and never included in procedure data or events |
| Satellite Assignment Authority | Grants one command-authority incarnation for a satellite across sites, clusters, and legacy/new systems | Uses linearizable mission-wide state and a signed non-rollback generation anchor; no domain can self-activate from restored local data |
| Effect Authorization Point | While holding local authority rows, consumes one linearizable SAA attempt permit and one primary-PostgreSQL dispatch permit, then alone uses the GCS effect credential and egress | SAA, primary-database, time, lease, fence, generation, operation, attempt, digest, and deadline failures close both permit paths |
| Pre-SAA legacy authority | Existing command path represented by a reviewed adoption inventory during migration | Counts as the one effect-enabled path until every inventoried credential, session, endpoint, egress route, interlock, queue, and operator authority is independently fenced |
| Ground-control system and adapters | Supply telemetry and accept authorized commands through the EAP | Browser, worker, gateway, and driver host have no GCS effect credential or direct effect route |
| Mission time source | Supplies UTC and, where required, mission clock state | Every consumed time value carries source, quality, and uncertainty metadata |
| Enterprise observability and audit archive | Receives metrics, alerts, and immutable audit exports | Export failure cannot erase local authoritative evidence |

## Context Diagram

```text
                 enterprise identity / policy
                              |
                              v
 controllers ----+     +-------------------+      +-------------------+
 monitors -------+---->| HTTPS access edge |----->| public API and    |
 developers -----+     +-------------------+      | stream gateways   |
                                                    +---------+---------+
                                                              |
                       Git service ----> bundle promotion -----+
                                                              v
  non-rollback anchor <-> Satellite Assignment Authority
                                      |
                                      v
             +----------------------------------------------------------+
             |        signed assignment -> Satellite Control Domain     |
             |                                                          |
             | domain supervisor -> execution scheduler -> workers      |
             |          |                 |                 |            |
             |          +---- controller lease and policy --+           |
             |                            |                             |
             |                    typed driver gateway                   |
             +----------------------------+-----------------------------+
                                          |
                                          v
                              out-of-process driver host
                                          |
                                          v
                              Effect Authorization Point
                                   |             |
                              PostgreSQL         v
                                      simulator or approved GCS adapter

             PostgreSQL <---- authoritative state and outbox
             object store <-- immutable bundles, reports, backups
             observability <- metrics, service logs, audit exports
```

Arrows show allowed logical calls, not permission by adjacency. Every boundary
requires authenticated service identity, explicit authorization, schema
validation, deadlines, and audit where applicable.

## Trust Zones

1. **Client zone.** Browsers are untrusted clients. No client decision,
   sequence number, role label, or cached state is authoritative.
2. **Access zone.** The access edge terminates approved HTTPS, applies request
   size and rate limits, and forwards an authenticated identity. It exposes no
   driver or database route.
3. **Application zone.** API, stream, supervisor, scheduler, and policy
   services process authenticated requests. Only the current domain leader may
   commit control transitions.
4. **Execution zone.** Each procedure execution runs bounded, versioned data-
   only IR in its own isolated process or container sandbox. It has no general
   network, shell, credential, or database access.
5. **Driver zone.** The gateway and driver hosts use workload identity and
   mutually authenticated transport. Driver hosts call only typed EAP methods;
   they have no GCS effect credential or effect-capable route.
6. **Effect zone.** The EAP is the only holder of the assignment-bound GCS
   effect credential and the only workload with effect-capable egress. Its
   narrow database role can consume dispatch permits but cannot administer
   domain state.
7. **Data zone.** PostgreSQL, object storage, backup targets, and key services
   are private. Service accounts receive the minimum schema, bucket, or key
   operations needed.
8. **Management zone.** Deployment, monitoring, break-glass, backup, and
   security administration are separated from routine operator traffic.

## Architecture Invariants

| ID | Normative invariant |
| --- | --- |
| ARC-026 | A Satellite Control Domain shall have exactly one `SatelliteId` and shall not route a procedure operation to another satellite. |
| ARC-027 | A deployment shall support multiple independent domains without sharing controller leases, leader epochs, driver credentials, or mutable runtime state. |
| ARC-028 | A domain may run multiple executions concurrently only after admission control evaluates domain, driver, procedure, and serialization constraints. |
| ARC-029 | At most one service leader shall have write authority for a domain at a time; every authoritative mutation shall carry the current monotonically increasing leader epoch. |
| ARC-030 | At most one person shall hold a domain's execution-control lease at a time; control commands shall carry the current monotonically increasing `control_fencing_token`. |
| ARC-031 | PostgreSQL shall be the authoritative source for committed control state, execution state, command disposition, prompts, and audit/outbox records. |
| ARC-032 | A real-time message shall be a projection of committed state and shall never become authoritative merely because a client received it. |
| ARC-033 | Browsers and procedure workers shall receive no driver endpoint, private key, GCS credential, or general route to a driver host. |
| ARC-034 | Runtime execution shall consume an immutable, validated procedure bundle identified by digest; editing shall not mutate an active bundle. |
| ARC-035 | Loss of certainty about an externally effective operation shall never trigger an automatic resend; the operation shall be reconciled or settled by an explicitly authorized decision. |
| ARC-036 | A mission-wide Satellite Assignment Authority shall permit at most one effect-enabled command-authority path for a `SatelliteId` across every cluster, site, and legacy or replacement system, including a path in drain or transition. |
| ARC-037 | Every activation, cutover, restore, or failback shall use a newly allocated `AuthorityIncarnationId` and assignment generation, externally fence the prior effect path, and issue fresh short-lived dispatch authority before control becomes active. |
| ARC-038 | Every externally effectful integration shall pass through one approved Effect Authorization Point that exclusively owns the effect credential and egress path and, immediately before effect, uses a fail-closed one-use permit protocol that linearly orders current assignment at the SAA and current leader, controller when required, operation attempt, and integration fences at primary PostgreSQL before journaled dispatch. |
| ARC-039 | Each assignment generation shall be reserved through a non-rollback authority outside the SAA recovery set; its signed reservation receipt shall commit before the generation or grant becomes observable, and loss or ambiguity of that proof shall block issuance. |
| ARC-040 | A pre-SAA legacy command path shall have an externally identified adoption record and complete credential, session, endpoint, egress, interlock, and operator inventory; a replacement shall remain non-effecting until every inventoried path is independently fenced. |

For the implementation of these allocated invariants, "active command
authority" means any record with `effect_enabled=true`, including an adopted
legacy path. `DRAINING` is effect-disabled and supports settlement or
reconciliation only. Every generation allocation has a synchronous signed
receipt from an external non-rollback anchor. Apparent loss of an old path is
never fence evidence.

## Principal Flows

### Acquire Control And Issue A Command

1. The user authenticates through the configured identity provider.
2. The API authorizes control acquisition for the requested domain.
3. The current domain leader proves its active satellite assignment and
   atomically grants or renews one lease in PostgreSQL, returning lease ID,
   revision, expiry, `control_fencing_token`, and client proof challenge.
4. A control command includes an idempotency key, expected resource revision,
   lease ID/revision, control fence, authority incarnation, client-instance
   proof, actor, and reason where policy requires it.
5. The leader validates policy and lease state in the same transaction that
   persists the accepted command and outbox event.
6. For an external effect, the driver host sends one `OperationId`, `AttemptId`,
   and request digest to the EAP. The driver host cannot reach the GCS.
7. While holding the primary PostgreSQL authority, lease, operation, and attempt
   rows, the EAP consumes a linearizable signed one-use SAA attempt permit for
   the current effect-enabled grant. It then consumes and commits the local
   dispatch permit, both receipts, journal evidence, and `EFFECT_POSSIBLE`.
8. SAA assignment changes serialize against the SAA consume; leader and lease
   changes serialize against the local row locks. If local commit fails, the SAA
   permit is abandoned and never reused. If both consumes and commit win, later
   authority loss cannot erase the in-flight attempt and it must reconcile. If
   either authority change wins, dispatch rejects before effect.

An authority-incarnation replacement invalidates the old controller lease and
current pointer, suspends affected executions with
`hold_reason=CONTROL_LOST`, and starts with no controller. Acknowledged
reacquisition creates a new lease and higher fence before explicit resume.

### Replace A Pre-SAA Legacy Command Path

1. Adopt the legacy path under a stable `LegacyAuthorityId` and approved
   inventory digest without fabricating a SPELL generation or incarnation.
2. Inventory every effect credential, key, account, session, endpoint, egress
   path, interlock, queued command, automation identity, and operator authority.
3. Reserve the replacement's fresh generation and incarnation through the
   non-rollback anchor. Create only an effect-disabled `RESERVED` grant; the
   legacy record remains the one effect-enabled path and the replacement remains
   read-only without effect credentials, routes, permits, or controller authority.
4. Independently fence and disposition every inventoried path. Host or site loss
   alone is not proof; every evidence item binds the reserved target tuple.
5. Commit tagged legacy fence evidence and transition the legacy record to
   effect-disabled `DRAINING`.
6. Only then activate the reserved replacement assignment and issue its fresh
   EAP credential and egress authorization.

### Observe In Real Time

1. A client obtains an authorized REST snapshot containing a snapshot revision
   and event cursor.
2. It opens an authorized WebSocket subscription from that cursor.
3. The stream gateway emits only committed, domain-scoped events in order for
   each stream key.
4. The client detects a sequence gap or explicit resynchronization notice and
   repeats the snapshot-plus-cursor flow. Monitoring never becomes a control
   action.

### Promote And Execute A Procedure

1. Source changes are committed and reviewed in Git.
2. Offline parsing and semantic validation produce a bounded IR and evidence.
3. Promotion creates a signed or otherwise integrity-protected immutable bundle
   with source commit, dependency lock, language profile, validation result,
   and digest.
4. The runtime admits only a bundle approved for the target domain and policy.
5. Each execution records the exact bundle digest and never reads mutable
   source while running.

## Boundary Assumptions And Exclusions

- No architecture document authorizes live spacecraft connectivity. Each real
  adapter and operational environment requires a separate assurance and
  authorization decision.
- "Unlimited monitoring" means there is no product or licensing constant that
  fixes a monitor count. Every deployment still has finite capacity and shall
  qualify a declared concurrent-user and event-rate envelope.
- Cross-satellite procedure transactions and atomic cross-domain command groups
  are outside the control-domain contract. A higher-level mission coordinator
  may orchestrate independently authorized domain operations but cannot bypass
  their leases or fencing.
- A cache, message broker, search index, analytics store, browser state, or
  object store is never the authority for a control decision.
- No direct driver-host-to-GCS exception exists. An adapter that cannot place
  the EAP before its effect endpoint is not command-qualified under this design.
- The platform provides technical mechanisms that support a system security
  plan; product installation alone does not establish regulatory compliance or
  operational authorization.

## Verification Hooks

- Architecture tests shall prove network denial from browser and worker zones
  to driver and data zones and from every non-EAP identity to GCS effect egress
  and credentials.
- Concurrency tests shall attempt simultaneous leader and controller acquisition
  and prove that stale epochs and fencing tokens cannot commit.
- Contract tests shall prove every real-time event maps to a committed outbox
  record and that gap recovery reaches the same state as a fresh snapshot.
- Fault tests shall kill each service between acceptance, persistence,
  dispatch, driver effect, and acknowledgement and verify the recorded
  certainty and recovery rule.
- EAP race tests shall prove exactly one winner between permit consumption and
  every lease/leader/assignment terminal transition; a winning permit is
  retained for reconciliation and a winning authority transition proves
  `NO_EFFECT` for the rejected attempt.
- Restore and legacy-cutover tests shall prove anchor ambiguity, apparent site
  loss, or one undispositioned legacy path prevents replacement activation.
- Multi-domain tests shall prove that saturation, failure, credentials, and
  control ownership in one domain do not leak into another.
