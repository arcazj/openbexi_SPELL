# Reliability And Recovery

## Reliability Objective

SPELL shall preserve safe, explainable control under component failure. High
availability is subordinate to state integrity, effect certainty, and operator
awareness. When the platform cannot prove that a control precondition holds, it
stops accepting affected mutations, contains the fault, preserves evidence,
and enters a documented degraded or recovery state.

Reliability is evaluated per Satellite Control Domain so failure of one
satellite path does not unnecessarily stop another.

## Core Principles

1. Persist an authoritative transition before publishing or acknowledging it.
2. Fence stale satellite assignments, authority incarnations, service leaders,
   controller leases, context generations, and driver operations before any
   effect.
3. Route every GCS effect through the Effect Authorization Point (EAP), the sole
   holder of effect credentials and egress, and consume both ordered SAA and
   PostgreSQL permits first.
4. Isolate workers, driver hosts, domain queues, credentials, and quotas.
5. Recover pure computation from atomic checkpoints.
6. Reconcile externally effective attempts by stable operation and attempt IDs.
7. Never automatically resend an operation whose external effect is possible
   or unknown.
8. Make stale, partial, degraded, and uncertain state visible to operators.
9. Test restore and failover; configuration alone is not recovery evidence.

## Service Objectives And Owner-Defined Parameters

Recovery requirements depend on mission criticality, site design, contract,
command consequence, and acceptable degraded behavior. The deployment owner
shall assign the following parameters in a version-controlled reliability
profile before operational qualification. `TBD` is not an acceptable value at
authorization. Project reliability parameters use the `REL-PAR-*` namespace.
They are not NIST
organization-defined parameters (ODPs), which remain reserved for parameters
embedded in NIST requirements.

| Parameter | Definition | Required design rule |
| --- | --- | --- |
| `REL-PAR-01` | Maximum unavailability of domain control after one qualified service-instance failure | Shall be less than the safe-hold tolerance for affected procedures |
| `REL-PAR-02` | Maximum unavailability of domain control after loss of the active compute node or zone | Shall reflect the qualified leader and database failover topology |
| `REL-PAR-03` | Maximum unavailability after total primary-site loss | Requires an approved disaster-recovery profile and human failover authority |
| `REL-PAR-04` | Permitted loss of committed control, audit, prompt, and effect-certainty records within each declared fault set | Target shall be zero for any fault set claimed as highly available; exceptions require documented risk acceptance |
| `REL-PAR-05` | Permitted loss of full-rate telemetry, service logs, and derived analytics | May differ by data class; procedure-consumed samples and alarm transitions follow `REL-PAR-04` |
| `REL-PAR-06` | Maximum controller-lease term, renewal interval, and controller-loss detection time | Must permit safe fencing without making normal transient latency cause unsafe oscillation |
| `REL-PAR-07` | Maximum age of an execution checkpoint and maximum recomputation of pure steps | Shall not cross an externally effective operation without its disposition |
| `REL-PAR-08` | Maximum snapshot staleness and stream reconnection/resynchronization time for control and monitoring views | UI shall mark a view stale before this bound expires |
| `REL-PAR-09` | Backup frequency, retention, restore time, and restore point for each data class | Must align with legal, audit, security, and mission continuity obligations |
| `REL-PAR-10` | Maximum clock offset/uncertainty for lease, schedule, telemetry, and command decisions | Exceeding the limit triggers the defined degraded behavior |
| `REL-PAR-11` | Outbox, driver-journal, queue, and object-cache capacity and exhaustion thresholds | Capacity exhaustion must fail predictably before evidence is lost |
| `REL-PAR-12` | Maximum automatic restart attempts and interval before quarantine | Prevents restart loops from hiding persistent corruption or dependency failure |

Suggested qualification classes provide planning structure, not universal
numbers:

| Class | Examples | RPO intent | Recovery intent |
| --- | --- | --- | --- |
| A: control integrity | leases, epochs, execution transitions, prompts, commands, audit, operation certainty | Zero committed-record loss inside the declared HA fault set | Automated local failover with fencing; explicit site-failover authority |
| B: operational observation | outbox projections, current telemetry, alarm views, operator logs | Replay or rebuild without losing Class A evidence | Restore quickly enough to maintain operator situation awareness |
| C: engineering productivity | authoring search indexes, caches, derived reports | Rebuild from Git, object, or database authority | May recover after control service, with documented dependency behavior |

Availability, durability, and latency targets are reported separately. A single
percentage shall not be used to conceal missed recovery or data-loss objectives.

## Health Model

Every component exposes separate signals:

- **Liveness:** the process can make internal progress. Used only to decide
  whether restart may help.
- **Readiness:** the instance can accept its assigned traffic without violating
  dependencies or capacity.
- **Safety readiness:** the domain can prove its mission-wide satellite
  assignment and authority incarnation, leadership, database write authority,
  controller fencing, EAP identity/credential/egress, SAA attempt-permit
  availability, generation-anchor lineage, configuration integrity, clock
  bounds, and required driver certainty for a class of mutations.
- **Degradation:** named capability, scope, start time, operator impact, allowed
  actions, and recovery owner.
- **Freshness:** age/revision/cursor of projections and external data.

An aggregate domain state is computed from explicit dependency policy. A
generic `healthy` boolean does not authorize control.

Watchdogs observe event-loop progress, queue age, checkpoint age, lease renewal,
database transaction latency, replication lag, outbox backlog, driver/EAP
heartbeat and permit/journal capacity, SAA and generation-anchor freshness,
clock quality, object integrity, stream gaps, resource limits, and audit-export
backlog. Watchdogs may restart a disposable instance within `REL-PAR-12`; they
do not change command certainty or force a controller takeover.

## Failure Behavior Matrix

| Failure | Required containment and service behavior | Recovery and evidence |
| --- | --- | --- |
| Public API instance loss | Load balancer removes instance; other replicas continue | Client resolves mutation by idempotency/command lookup; no blind retry |
| Stream gateway or broker loss | REST remains available; UI marks stream stale; canonical events remain in outbox | Reconnect from cursor or obtain snapshot; broker rebuilds from outbox |
| Domain leader process loss | New admissions, mutations, and EAP permit consumes pause | Passive candidate first reserves a newly anchored effect-disabled assignment/incarnation, obtains target-bound external fence proof, establishes a fresh local epoch, invalidates old controller authority, reconciles durable work, passes readiness, and only then receives an active grant and effect credentials |
| Old leader returns after partition | It may offer liveness but cannot commit a stale epoch or consume either EAP permit | SAA and database reject the stale assignment/epoch; alert and retain split-brain evidence |
| PostgreSQL primary loss with qualified quorum | Control and EAP local permit consumption pause during database failover | Promote only a replica meeting `REL-PAR-04`; obtain fresh authority/epoch, invalidate old controller authority, and reconcile |
| PostgreSQL write quorum unavailable | No authoritative mutation, prompt settlement, local EAP permit consume, or new external effect | Workers enter policy-defined safe hold; abandoned SAA permits are never reused; observation may continue with explicit stale status |
| Read replica lag or failure | Do not use it for control-consistent snapshots; mark monitor projection stale | Route to primary or another qualified replica; measure lag against `REL-PAR-08` |
| Worker crash or limit breach | Affected executions stop; other workers and domains continue | New worker restores last checkpoint; reconcile pending commands/effects first |
| Driver gateway crash | Stop new driver dispatch for affected bindings | Recover operation ledger; query driver journal; do not infer no effect from lost RPC |
| Driver host crash before EAP local permit commit | Resolve by `OperationId` and `AttemptId`; prove `NO_EFFECT` only when no local permit committed | Abandon any consumed SAA permit, allocate a new attempt only after proof and policy authorization |
| EAP crash or timeout before local permit commit | Roll back local rows; a consumed SAA permit is abandoned and never reused; uncertainty about commit is reconciled | Read primary permit/journal state before any retry |
| EAP crash or timeout after local permit commit | Attempt remains at least `EFFECT_POSSIBLE`, even if GCS send is not observed | No automatic resend; reconcile EAP and GCS evidence by both permit receipts and `AttemptId` |
| SAA attempt-permit service loss | Deny every new effect even with an unexpired cached grant | Restore linearizable service and reconcile outstanding consumed permits |
| Non-rollback generation-anchor loss or ambiguity | Deny generation reservation, activation, restore promotion, and failback | Prove anchor lineage and obtain a valid signed compare-and-advance receipt |
| GCS or satellite-link loss | Driver capability becomes unavailable/degraded; unrelated pure work may continue only by policy | Preserve queue and operation stages; do not convert transport loss into command failure certainty |
| Controller browser disconnect | Controller lease remains until renewal/expiry policy; new interactive decisions stop as configured | Notify monitors; pause affected executions at safe points; authenticated reacquisition gets a new or renewed fence |
| Authority incarnation replacement | Revoke/invalidate old lease, increment its revision, clear current pointer, and suspend affected executions with `CONTROL_LOST` | New incarnation starts without controller; acknowledged reacquisition gets a new lease and higher fence before explicit resume |
| Identity provider loss | Existing sessions follow short, preapproved continuity policy; new authentication and privilege elevation fail | Control acquisition/renewal fails closed after configured assurance window; audit recovery |
| Git/authoring loss | Active approved bundles continue; new edits/promotions unavailable | Restore Git service; verify commit and bundle relationships before promotion |
| Object store loss | Already loaded integrity-checked bundles may continue by profile; new loads and artifact writes fail or buffer only within qualified bound | Restore object service/cache; verify digest before use; never lose required evidence silently |
| Full-rate telemetry store loss | Control decisions requiring unavailable data fail/hold; unrelated state remains available | Use qualified live source if policy permits; preserve sample gaps; rebuild derived analytics |
| Clock offset exceeds bound | Lease, schedule, timeout, and time-tag-dependent mutations fail or enter safe hold | Restore time quality, increment relevant generation if required, and explicitly reconcile expired/queued actions |
| Disk, outbox, audit, or driver-journal near capacity | Reject new work before reserved safety capacity is consumed; alert | Drain/export under policy; prove integrity before resuming; never overwrite unresolved evidence |
| Audit-export/SIEM loss | Local append-only audit continues while backlog is within bound | Alert, retain, and resume export idempotently; block affected operations if local protected capacity reaches threshold |
| Configuration or bundle integrity failure | Quarantine the artifact/generation and stop affected admission | Restore approved bytes, create a new generation, and retain tamper evidence |

## Leader Failover

1. A candidate proves workload identity, database primary connectivity,
   configuration digest, clock quality, and required dependency health.
2. The SAA reserves a fresh generation and `AuthorityIncarnationId` through the
   non-rollback anchor and creates an effect-disabled `RESERVED` grant; the
   candidate receives no effect credential, route, permit, or controller authority.
3. It proves the prior EAP/GCS or inventoried legacy path externally fenced with
   evidence bound to the reserved target tuple; apparent loss alone is not proof.
4. It acquires the infrastructure leadership lease under the non-effecting
   reserved identity.
5. In PostgreSQL, it revokes or invalidates the old controller lease, increments
   its revision, clears the current pointer, and suspends affected executions
   with `hold_reason=CONTROL_LOST`.
6. It increments the domain leader epoch and records takeover
   reason and prior leader.
7. Every scheduler, worker, gateway, driver, and EAP request from the prior
   authority incarnation or epoch is fenced.
8. The candidate scans nonterminal executions, commands, prompts, reservations,
   schedules, operations, attempts, and both permit receipts.
9. It reconciles external attempts and driver/EAP generations without dispatching
   new work and never reuses an abandoned SAA permit.
10. It releases only proven orphan reservations, validates and stages compatible
    pure checkpoints without executing them, and publishes committed recovery
    transitions.
11. It passes safety-readiness checks for the advertised capability set while
    remaining non-active and without a controller.
12. Only after the SAA verifies the fence, reconciliation, local epoch, and
    readiness evidence does it activate the reserved grant and issue fresh
    short-lived EAP credentials. The domain then transitions to `ACTIVE` without
    a controller; reacquisition requires a new lease/higher fence,
    acknowledgement, and explicit resume.

Two leaders may temporarily believe they are live at the network layer; only
one epoch can commit. Network or orchestration leadership without database
fencing is insufficient.

## Execution Recovery

Checkpoints include IR location, immutable bundle and dependency identity,
typed variables, call/child context, pending wait or prompt, schedule/clock
metadata, controller policy, last applied command, and every referenced driver
operation. Checkpoints are atomic and schema-versioned.

Recovery classifies the next step:

- **Pure and checkpointed:** resume deterministically.
- **Pure but after last checkpoint:** recompute only within the declared bound.
- **Waiting on time/telemetry:** restore original target, cursor, and condition;
  do not reset the timeout silently.
- **Waiting on prompt:** restore the same prompt ID, deadline, warnings, and any
  accepted result.
- **External effect confirmed:** consume its recorded result exactly once.
- **External effect proven absent:** retry only under method policy using the
  same `OperationId` and digest with an incremented `AttemptNumber` and a new
  opaque `AttemptId` bound to the then-current authority, leader, controller,
  driver, and execution tuple. Preserve the prior attempt and tuple unchanged.
  A successor operation is new intent, not a retry.
- **External effect possible/unknown:** enter safe hold for reconciliation.
- **Bundle/configuration unavailable or changed:** do not substitute new bytes;
  fail or await restoration of the recorded digest.

## Graceful Degradation

Degradation is capability-specific, versioned policy. Examples:

- loss of WebSocket permits REST snapshots but displays stale real-time state;
- loss of full-rate history permits live current telemetry only if its source,
  quality, and mission policy remain valid;
- loss of authoring permits execution of previously approved cached bundles;
- loss of one nonessential driver capability rejects procedures requiring that
  capability but need not stop pure procedures;
- loss of primary-consistent reads or database writes blocks control even if a
  monitor cache still renders old state;
- loss of SAA attempt permits, non-rollback anchor, EAP credential/egress, or
  trusted time blocks every new effect while consumed attempts reconcile; and
- loss of controller identity assurance prevents new control decisions and
  moves interactive executions to the controller-loss policy.

Each degraded state states what remains available, what is blocked, data age,
risk, responsible owner, and exit criteria. Automatic return to full operation
requires all configured safety checks; it is audited and operator-visible.

## Backup, Restore, And Disaster Recovery

PostgreSQL uses encrypted base backups plus continuous transaction-log archive
or an equivalent tested mechanism. Object storage, Git, configuration, keys,
and external policy are backed up according to their own consistency and key-
recovery rules. A restore set includes manifests that link database position,
object digests, Git references, schema version, application version, and key
epochs.

Restore occurs into an isolated environment first. Automated checks validate
schema, constraints, checksums, fencing monotonicity, event cursor continuity,
artifact reachability, unresolved operation records, audit chains/manifests,
and identity/configuration references. A restored domain starts `STANDBY` or
`FAILED`, never directly `ACTIVE`. Promotion requires an authorized disaster-
recovery decision; a newly reserved effect-disabled authority incarnation with
a signed non-rollback-anchor receipt; external EAP/GCS or inventoried legacy
fence evidence bound to that target; a fresh local epoch; invalidation of
restored controller authority; reconciliation of every operation, attempt, and
permit receipt; and completed safety-readiness checks. Only after those gates
does the SAA activate the reserved grant and issue fresh short-lived EAP
credentials. The restored incarnation starts without a controller and requires
acknowledged reacquisition before explicit resume.

Cross-site operation is active/passive for control authority. Asynchronous
geographic replicas cannot support a zero-RPO claim for site loss unless the
accepted design proves it. The owner records the real `REL-PAR-03` and
`REL-PAR-04` values rather than assuming local HA covers disaster recovery.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| REL-015 | Reliability profiles shall assign and qualify every `REL-PAR-*` parameter before operational authorization; this namespace shall remain distinct from NIST ODPs. |
| REL-016 | A component shall expose separate liveness, readiness, safety-readiness, degradation, capacity, and freshness signals applicable to its role. |
| REL-017 | A single service, worker, stream, driver host, or domain failure shall be isolated from unrelated domains and executions to the qualified fault set. |
| REL-018 | Stale authority incarnations, assignment generations, leader epochs, controller fences, and driver generations shall be rejected at the authoritative write boundary and before driver effects. |
| REL-019 | Database write-quorum loss shall stop new authoritative mutations and new external effects; cached observation shall be marked stale. |
| REL-020 | Every nonterminal command, prompt, reservation, checkpoint, schedule, and driver operation shall have a deterministic restart reconciliation rule. |
| REL-021 | `EFFECT_POSSIBLE` and `EFFECT_UNKNOWN` operations shall enter safe hold and shall never be automatically resent. |
| REL-022 | A watchdog restart shall not alter command disposition, operation certainty, leader/controller fencing, or execution terminal state. |
| REL-023 | Queue, journal, outbox, disk, and audit capacity shall reserve headroom and reject new work before required evidence can be overwritten or lost. |
| REL-024 | Backup restore and site failover shall preserve immutable identities, monotonic fences, cursor continuity or explicit reset, audit integrity, and unresolved operation evidence. |
| REL-025 | Restored or failed-over domains shall begin non-active and require a new leader epoch, dependency checks, driver fencing, and reconciliation before control resumes. |
| REL-026 | Degraded operation shall be capability-specific, operator-visible, bounded by policy, and tested; no generic degraded flag shall imply control safety. |
| REL-027 | Fault recovery shall preserve original time targets, telemetry cursors, prompt identities, and external-effect dispositions. |
| REL-028 | Automatic restart and retry shall be bounded, observable, and quarantined after the configured threshold. |
| REL-029 | Restore, failover, cutover, and failback shall allocate authority identity outside restored history and shall remain non-active until the prior integration path is proven fenced and unresolved effects are reconciled. |

## Verification Program

- Run deterministic crash tests at every durable boundary of leases, commands,
  checkpoints, prompts, schedules, outbox relay, and driver journals.
- Run split-brain tests that isolate old leader, database, orchestrator, and
  driver/EAP networks independently and prove stale writes/effects are fenced.
- Race SAA attempt-permit consumption with assignment changes and local permit
  consumption with leader/controller changes. Crash between every ordered step
  and prove abandoned SAA permits are never reused, local rollback has no
  effect, and local commit remains `EFFECT_POSSIBLE` until reconciliation.
- Remove every EAP credential/egress, SAA permit, trusted-time, and
  non-rollback-anchor dependency independently and prove new effects fail
  closed without erasing consumed attempts.
- Run chaos and load together: instance loss, slow storage, packet loss, clock
  drift, queue saturation, disk pressure, and certificate/key rotation at the
  declared concurrent execution and monitor envelope.
- Restore encrypted backups into an isolated environment on a scheduled basis
  and measure actual restore point and time against the assigned profile.
- Conduct controlled site-failover exercises, including prevention of
  simultaneous EAP/GCS authority, inability to substitute apparent site loss
  for fence evidence, legacy inventory completeness, and documented failback.
- Compare reconstructed as-run evidence before and after every recovery path;
  unexplained difference is a release blocker.
