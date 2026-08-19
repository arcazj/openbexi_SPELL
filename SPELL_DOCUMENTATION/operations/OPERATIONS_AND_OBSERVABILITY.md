# Operations and Observability

## Operating objective

SPELL operations shall preserve command authority, state integrity, accountability, and safe degradation before optimizing availability. Automation may restart or replace stateless services, but it shall not infer command outcome, transfer control, resume a procedure, or resend an external effect without the state-machine and policy evidence required for that action.

This document implements `OPS-*`, supports `REL-*`, and consumes the security controls in [Security Architecture](../security/SECURITY_ARCHITECTURE.md).

## Operational roles

| Role | Primary responsibility |
| --- | --- |
| Mission Operations Lead | Operational readiness, controller staffing, mission rules, degraded-mode decisions |
| Controller | Holds execution control and manages active procedures within policy |
| Monitor | Read-only situational awareness and escalation |
| Platform On-call | Service health, infrastructure, deployment, capacity, and recovery |
| Application On-call | API, scheduler, worker, state machine, compiler, and real-time behavior |
| Driver/Integration On-call | Command, telemetry, archive, simulator, and external protocol adapters |
| Database/Storage Owner | PostgreSQL, object storage, backup, replication, integrity, and performance |
| Security Operations | Security monitoring, triage, containment coordination, and evidence preservation |
| Incident Commander | Cross-team authority, chronology, communications, decision log, and recovery gates |

Every alert and runbook shall name the primary and secondary role, paging route, response expectation, escalation condition, and authority for mission-impacting decisions. A platform administrator does not gain execution control by responding to an incident.

## Service-level indicators and objectives

Targets are approved per mission and recorded in the SSP, service catalog, and operating agreement. The following are initial engineering objectives for production qualification, not universal contractual promises.

| Service indicator | Measurement | Initial objective | Exclusions/notes |
| --- | --- | --- | --- |
| Authorized API availability | Valid eligible requests that receive a non-5xx terminal response / valid eligible requests | 99.95% per calendar month | Approved maintenance only if contract permits; authorization denials are successful service behavior |
| Execution-control safety | Mutations accepted with two valid controller holders for one domain | 0 events | Any event is Severity 1 regardless of duration |
| Command admission latency | API receipt to durable accept/reject decision | p99 <= 500 ms over 5-minute windows | Excludes external device/link acknowledgment; report by command class |
| Committed event delivery latency | Durable event commit to receipt at connected real-time gateway | p99 <= 1 second over 5-minute windows | Browser/network latency reported separately |
| Event continuity | Committed event sequences delivered or recoverable by cursor | 100%; no silent gaps | Explicit coalescing/drop policy for non-authoritative high-rate telemetry |
| Prompt visibility | Prompt commit to display acknowledgment from healthy managed client | p99 <= 2 seconds | Does not measure human acknowledgment time |
| Alarm path latency | Alarm ingestion to gateway publication | Target assigned by alarm class | Must be qualified under peak telemetry and monitor load |
| State recovery | Recoverable committed procedure state following eligible worker loss | 100% for defined recovery points | External-effect reconciliation may require suspended state |
| Audit durable handoff | Critical audited actions with accepted durable audit record | 100% | Failure behavior follows approved emergency policy |
| Monitor capacity | Concurrent monitors meeting latency/error objectives for qualified topology | Deployment-specific tested value | No product/licensing fixed cap; never describe capacity as physically unlimited |

Each SLI shall be computed from authoritative server-side events with a versioned query. Dashboards and alerts shall show numerator, denominator, missing data, deployment version, satellite/domain, and measurement window. Planned maintenance, test traffic, client error, upstream failure, and overload exclusions require explicit labels and cannot be used to conceal service failure.

## Error budgets

- The System Owner approves the error-budget policy for availability and latency objectives.
- Exhaustion blocks nonessential high-risk releases until reliability is restored or an accountable exception is approved.
- Safety-invariant, CUI-spillage, audit-integrity, and dual-controller events have no error budget; each triggers incident review.
- External mission-system and network failures are reported separately from SPELL failures, while end-to-end mission impact remains visible.
- SLO reporting shall distinguish API admission, durable state transition, gateway publication, browser receipt, driver transmission, and external acknowledgment.

## Observability model

Metrics, diagnostic logs, distributed traces, domain events, and security audit are distinct products (`OPS-002`, `OPS-003`). They may share correlation identifiers but have separate schemas, access policy, retention, durability, and failure behavior.

### Common correlation fields

Where applicable, all telemetry includes:

- UTC event time and ingestion time;
- service, instance, deployment, artifact and configuration revisions;
- environment, mission, satellite/control domain, procedure bundle, execution, and step;
- request, trace, correlation, command, prompt, domain event position,
  subscription delivery sequence, idempotency key, and
  `control_fencing_token`;
- outcome and stable reason code;
- data classification and schema version.

Sensitive values, credentials, full bearer tokens, private keys, raw operator secrets, and prohibited CUI fields shall not be labels or diagnostic text. Correlation IDs shall not embed classified or personally identifiable content.

### Metrics

Required platform signals include:

| Area | Minimum metrics |
| --- | --- |
| API/gateway | Request rate, errors by reason, latency, open connections, authorization denials, rate limits, message size, reconnects |
| Controller authority | Active lease holder count, acquire/renew/revoke result, lease-revision changes, age to expiry, control-fence changes, client-proof failures, conflicts, stale-token rejection |
| Satellite assignment | Active assignments per satellite, generation/incarnation, grant expiry/renewal, quorum, external-fence evidence, stale-grant rejection, credential revocation lag |
| Scheduler/execution | Queue depth/age, active executions, state transitions, step duration, pauses, cancellations, worker assignment/restart, checkpoint lag |
| Commands/prompts | Admission result, acknowledgment class/latency, uncertain outcome, duplicate suppression, prompt age, operator response age |
| Real-time delivery | Publish rate, sequence gaps, subscriber lag, cursor recovery, snapshot size/time, coalesced/dropped event counts |
| Drivers/integrations | Link state, request/response rate, errors, timeouts, retries, duplicate detection, protocol parse failures, clock/sequence anomalies |
| PostgreSQL | Availability, replication state/lag, connections, transactions, locks, deadlocks, query latency, storage/WAL growth, checkpoint/PITR health |
| Object/event/cache | Availability, errors, lag/backlog, object integrity, replication, eviction, storage, consumer health |
| Host/orchestrator | CPU, memory, disk/inode, network, process/container restarts, scheduling, node health, certificate expiry |
| Security/audit | MFA/auth failures, privilege changes, cross-scope denials, secret access, signature failures, drift, audit handoff/checkpoint/replication health |

High-cardinality identifiers such as execution or command IDs belong in exemplars, logs, traces, or bounded diagnostic views rather than unbounded metric labels. Per-satellite labels are allowed only after cardinality and access review.

### Diagnostic logs

Application logs are structured records for troubleshooting. They shall use stable event names and reason codes, controlled levels, schema validation, redaction, size bounds, and rate controls. User-provided strings are stored as data fields, not formatted log templates. Repeated faults are sampled only when an unsampled counter and first/last occurrence remain available.

Logs are not an authoritative execution journal and not the security audit record. A service restart may lose buffered debug logs, but cannot lose a committed state transition or accepted audit handoff.

### Distributed traces

Traces shall propagate across ingress, authorization, durable state transition, event publication, scheduler, worker, and driver boundaries. Sampling must retain errors, slow requests, uncertain command outcomes, authorization changes, lease transitions, and security-relevant paths. Trace payloads follow classification and redaction policy; raw command/telemetry bodies are not collected by default.

### Domain event journal

The authoritative event journal records versioned committed state transitions with a per-domain or per-execution sequence and durable cursor. Consumers detect gaps and recover with snapshot plus cursor. Metrics, WebSocket frames, and broker retention cannot replace this journal.

### Security audit

Security audit follows [Security Architecture](../security/SECURITY_ARCHITECTURE.md#audit-and-accountability). Operations dashboards show audit-pipeline health without granting platform staff the ability to alter security-retained records.

## Health model

Every service exposes separate authenticated health signals (`REL-001`):

- **Liveness:** the process event loop can make local progress. It does not test every dependency and is used only to replace a stuck instance.
- **Readiness:** the instance can perform its assigned class of work safely. A command-path instance is not ready if it lacks current policy, authoritative storage, required identity/key material, or control-authority connectivity.
- **Startup:** initialization/migration/cache warm-up is still within its allowed window and should not trigger a restart loop.
- **Dependency health:** identity, database, event transport, object store, audit sink, time, driver, and external mission links are reported independently.
- **Domain health:** each Satellite Control Domain reports authority epoch, controller lease state, execution recovery state, command admission state, event cursor, and degraded reasons.

A green process probe shall not override a red domain safety state. Health endpoints expose no secrets or unrestricted topology and are not public.

## Alert policy

Alerts are symptom- and invariant-oriented, deduplicated by affected domain, and tied to a tested runbook (`OPS-005`).

| Severity | Criteria | Notification and response |
| --- | --- | --- |
| SEV-1 Critical | Dual authority, wrong-satellite access/effect, confirmed command duplication, material CUI exposure, audit tampering, unreconciled command-path integrity | Immediate Mission Operations, Incident Commander, Platform/Application, Security, and affected driver owner; fence/contain under mission runbook |
| SEV-2 High | Production control unavailable, active procedure cannot safely progress, database leader/command link loss, uncertain command outcome, critical alarm delivery breach | Page responsible on-call and Mission Operations immediately; establish incident command and degraded state |
| SEV-3 Medium | Redundancy lost, growing replication lag/backlog, SLO burn, backup failure, certificate/key expiry risk, monitor capacity degradation | Page or urgent ticket according to time-to-impact; remediate before loss of safety margin |
| SEV-4 Low | Non-urgent drift, trend, isolated client issue, low-risk maintenance action | Work queue with owner and due date |

Every page includes affected environment/satellite, observable symptom, start time, current deployment/configuration, safe first action, prohibited actions, and links to dashboards/runbook. Alerts that repeatedly fire without an actionable response shall be redesigned, not muted indefinitely.

## Mandatory runbooks

Runbooks are version-controlled, reviewed by the roles that execute them, accessible during identity/control-plane outage, and exercised (`OPS-006`). Minimum set:

1. controller lease conflict, forced revocation, and abandoned session;
2. ambiguous command acknowledgment and reconciliation;
3. worker crash, checkpoint recovery, and suspended execution;
4. driver/link failure, isolation, and restart;
5. PostgreSQL failover, replication lag, storage exhaustion, and corruption suspicion;
6. event sequence gap, real-time gateway overload, and snapshot recovery;
7. identity-provider, certificate, secrets, time, DNS, object store, broker, and audit-sink outage;
8. wrong-satellite or cross-boundary access attempt;
9. vulnerable/compromised artifact, signing key, operator session, or administrator account;
10. backup restore, regional disaster recovery, and clean-room recovery;
11. safe deployment, failed migration, rollback, and emergency change;
12. monitor load shedding and critical notification prioritization.

Each runbook states prerequisites, decision authority, safety invariants, diagnostic evidence, step-by-step commands/actions, expected observations, stop conditions, communication path, rollback, evidence capture, and post-event follow-up. Destructive steps require independent confirmation and exact target verification.

## Degraded-mode policy

| Failure | Permitted behavior | Prohibited behavior |
| --- | --- | --- |
| Identity provider unavailable | Existing unexpired sessions may continue only if approved policy and cached authorization remain valid; monitoring may continue | New login, role escalation, or uncontrolled break-glass access |
| Real-time gateway unavailable | Authoritative execution may continue if controller interaction is not required; clients recover via snapshot/cursor | Treating missing browser updates as proof of failed execution |
| Monitor overload | Rate limit, coalesce approved telemetry, add read replicas/gateways, preserve alarms and controller path | Dropping committed transitions silently or consuming command-path capacity without bounds |
| PostgreSQL authority unavailable | Existing non-effecting views may show explicitly stale cached state; command/execution mutation pauses | Accepting mutation into cache/broker or electing an uncoordinated writer |
| Broker/cache unavailable | Rebuild publication/cache from authoritative state, use bounded direct fallback if designed/tested | Losing committed state or changing command authority |
| Audit durable handoff unavailable | Fail closed for designated critical actions, or enter preapproved emergency mode with local protected journal | Continuing silently without accountable record |
| Driver/link uncertain | Isolate affected integration and suspend dependent step/procedure | Automatic resend or false success |
| Time outside safety bound | Alert, use monotonic interval tracking, suspend lease/command actions per policy | Trusting wall-clock expiry/order that cannot be established |
| Security compromise suspected | Fence affected identity/component and preserve state under mission-aware playbook | Generic automated command/resume/cancel action |

The UI and API shall expose a stable degraded-reason code, affected capability, first observation, last authoritative update, and operator action. A banner alone is not a control; server-side admission enforces restrictions.

## Capacity and performance management

Each production topology shall be load-qualified with representative procedure concurrency, command rate, telemetry rate/size, prompt/alarm bursts, database history, monitor count, reconnection storm, audit volume, and component failure (`OPS-009`, `REL-014`). Results record hardware, network, versions, configuration, dataset, test duration, percentiles, error/gap counts, recovery time, and headroom.

Capacity planning shall reserve command/control and alarm resources from monitor/reporting workloads. Use independent pools, queues, connection budgets, and rate policies where needed. Publish a supported concurrent-monitor figure for each qualified deployment; there is no fixed product-imposed cap, but no deployment is physically unlimited.

Scaling out stateless API and gateway replicas shall preserve per-domain ordering, cursor recovery, authorization, and control fencing. Scaling workers shall preserve configured concurrency constraints and cannot create multiple command authorities.

## Change and release operations

- Production changes use approved, signed artifacts and version-controlled configuration (`OPS-008`, `SEC-017`).
- The change plan identifies affected satellites, active procedures, data/schema compatibility, mixed-version window, expected signals, abort thresholds, rollback limits, and communications.
- Deployment is blocked while an affected domain performs an incompatible critical operation unless the approved plan proves continuity.
- Database expansion/contraction changes are staged so old and new versions can coexist for the tested window. Irreversible migrations require tested forward recovery.
- Post-deployment verification checks authorization, lease fencing, event sequence, command admission (using safe simulation where necessary), audit, backups, and SLOs.
- Emergency changes are time-bounded, audited, independently reviewed, and reconciled into source after stabilization.

## Incident management

The Incident Commander maintains a UTC decision log, impact statement, affected versions/domains/data, current safety state, owners, communications, evidence holds, and recovery gates. Security and mission safety incident processes run together when both are affected.

Recovery requires proof that authority, state, artifact/configuration integrity, external-effect reconciliation, audit continuity, and monitoring are trustworthy. Service availability alone is insufficient. After restoration, the owner produces a blameless technical review with timeline, contributing conditions, control failures, corrective actions, owners, due dates, and validation.

## Operational readiness review

Before production activation for a satellite, approvers shall verify:

- service ownership, paging, escalation, maintenance, and supplier contacts;
- approved SLOs, capacity qualification, dashboards, alert rules, and synthetic tests;
- runbooks and exercises for command, lease, driver, database, audit, identity, and recovery failures;
- inventory of exact artifacts/configurations, certificates/keys, dependencies, and external endpoints;
- backup/PITR health and completed restore/DR exercise;
- monitoring and audit retention/access against data-classification policy;
- known risks, exceptions, POA&M items, expiry, and compensating controls;
- controller/monitor training and degraded-mode acceptance.

Operational readiness expires on the approved review interval and after material topology or command-path change.
