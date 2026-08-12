# Deployment And Scalability

## Deployment Principles

- One logical Satellite Control Domain owns one satellite.
- Many domains may run in one mission platform, but their leadership,
  controller lease, driver credentials, mutable state, queues, and quotas remain
  isolated.
- Control authority is single-writer and active/passive. Public API, monitoring,
  validation, and derived observation paths may scale horizontally.
- A mission-wide Satellite Assignment Authority coordinates every command-
  capable cluster, site, and legacy/new system. A local orchestrator or restored
  database cannot self-assign a satellite.
- A mandatory external non-rollback generation anchor receipts every SAA
  generation before it becomes observable. The anchor is outside SPELL and SAA
  restore domains.
- The Effect Authorization Point is the sole GCS effect-credential holder and
  sole effect-capable egress path. Driver hosts call the EAP and cannot reach a
  GCS directly.
- Workloads use immutable, digest-pinned images or packages, least-privilege
  identities, read-only roots, explicit resource bounds, and declarative
  configuration.
- Kubernetes is supported where it is part of the approved infrastructure, but
  the logical design also supports hardened VMs and container services. Product
  correctness shall not depend on an unrecorded orchestrator behavior.

## Supported Deployment Profiles

### Engineering Profile

Purpose: local development, deterministic simulator testing, and documentation
examples.

```text
browser -> local HTTPS edge -> API/stream/supervisor/scheduler
                                  |             |
                                  v             v
                            PostgreSQL     isolated worker
                                  |             |
                            object store   gateway -> simulator driver
```

Components may share one workstation or CI runner but retain distinct process
identities and network policy where tooling permits. This profile is not highly
available, does not connect to a real GCS or satellite, and cannot be used to
claim operational reliability or NIST compliance.

### Single-Site High-Availability Profile

Purpose: mission-site operations within a declared node, rack, or availability-
zone fault set.

- At least two failure domains host access, API, stream, supervisor candidates,
  schedulers, gateway candidates, and worker capacity.
- PostgreSQL uses a qualified primary/standby topology. Synchronous replication
  is used for the fault set in which the profile claims zero committed-control
  RPO.
- Each domain has one active supervisor leader and passive candidates on another
  failure domain.
- Each active domain continuously validates its signed, short-lived satellite
  assignment and fresh `AuthorityIncarnationId`. Every effect also requires an
  online one-use SAA permit; inability to consume one stops new effects
  immediately even when a cached grant is unexpired.
- EAP candidates may be passive across failure domains, but only the current
  effect-enabled assignment can consume SAA/local permits or use GCS egress.
  Each attempt uses a linearizable one-use SAA permit followed by a committed
  primary-PostgreSQL permit before send.
- Driver hosts use the adapter's approved primary/passive or restart topology.
  A passive host cannot reach the effect boundary until generation and external
  integration fencing succeed.
- Load balancers route stateless public traffic only to ready instances.
- Object storage, secrets, time, DNS, identity, audit archive, and monitoring
  meet their assigned recovery and dependency objectives.
- Anti-affinity prevents all replicas and database members from occupying one
  failure domain.

### Multi-Site Disaster-Recovery Profile

Purpose: recover after loss of the primary mission site.

One site has control authority. A secondary site receives protected database
logs/backups, objects, Git/configuration replicas, and deployment artifacts.
The secondary remains passive for driver/GCS effects. Site promotion is an
authorized procedure that:

1. obtains a newly reserved Satellite Assignment Authority generation and
   `AuthorityIncarnationId` with a signed external non-rollback-anchor receipt,
   creates an effect-disabled `RESERVED` grant, and issues no effect authority;
2. independently proves the primary site's EAP/GCS or inventoried legacy effect
   path externally fenced with evidence bound to the reserved target tuple;
   apparent site loss is never sufficient;
3. measures replica/backup currency and records the real recovery point;
4. restores and verifies all referenced data and key/configuration dependencies;
5. starts each domain non-active under the reserved target identity and allocates
   fresh service-leader, context, driver-host, and EAP generations using only
   non-effecting identities; driver hosts receive no GCS credential or route;
6. reconciles every nonterminal command, operation, attempt, and permit receipt;
7. verifies target-bound fence evidence, restored state, local leadership,
   safety-readiness, and operator checks while the target remains non-active; and
8. only then activates the reserved grant and issues fresh EAP dispatch
   credentials. Controller lease acquisition remains a separate explicit action.

Active-active site control for one satellite is rejected. Cross-site monitoring
may be active when its data freshness and authorization are visible.

## Multi-Satellite Placement

A domain is the smallest control-authority and failure-containment unit. Small
missions may place several domains on a shared cluster using namespaces,
service accounts, database roles/partitions, network policy, queues, quotas,
and anti-affinity. High-consequence or high-load satellites may receive
dedicated compute, gateway, database, or full cluster boundaries.

A placement policy considers:

- satellite and procedure criticality;
- command and telemetry data rates;
- concurrent procedure and monitor counts;
- driver/GCS endpoint and credential isolation;
- classification and mission separation;
- maintenance and failure correlation;
- latency to ground systems; and
- recovery and disaster-domain requirements.

Moving a domain is a controlled assignment-generation change and failover, not
a live multi-writer migration. If the prior command path cannot be proven
fenced, the destination remains read-only regardless of local health.

A pre-SAA legacy migration first registers a `LegacyAuthorityId` and reviewed
inventory digest covering all credentials, keys, accounts, sessions, endpoints,
egress paths, interlocks, queues, automation identities, and operators. That
record counts as the one effect-enabled path until independently verified fence
evidence dispositions every inventory item.

## Network Zones And Flows

| Source | Destination | Protocol | Rule |
| --- | --- | --- | --- |
| Managed browser | Access edge | HTTPS/WSS | Only public route; approved origins and identity controls |
| Access edge | Public API/stream | Authenticated internal HTTPS | Bounded routes; no data or driver access |
| API/supervisor/projectors | PostgreSQL | Encrypted database protocol | Role-specific grants; primary or qualified read endpoint |
| Bundle service/backup jobs | Object storage | Approved encrypted object API | Bucket/prefix and operation restrictions |
| Supervisor | Worker runtime | Authenticated bounded RPC | No arbitrary network forwarding |
| Driver gateway | Driver host | Mutually authenticated gRPC | Method allowlist, workload identity, generation fence |
| Driver host | Effect Authorization Point | Mutually authenticated typed adapter protocol | No GCS credential or route; full operation/attempt tuple |
| Effect Authorization Point | PostgreSQL primary | Encrypted database protocol or approved stored procedure API | Narrow dispatch-permit role; canonical row locks and compare-and-set only |
| Effect Authorization Point | Satellite Assignment Authority | Mutually authenticated linearizable permit API | Consume one signed one-use attempt permit for current effect-enabled grant |
| Effect Authorization Point | Simulator/GCS adapter endpoint | Adapter-specific protected protocol | Sole assignment-bound effect credential and egress identity |
| Services | Secrets/key service | Authenticated secret API | Opaque reference, short-lived retrieval, audited |
| Services | Observability/audit archive | Encrypted structured export | Egress only where possible; backpressure policy |
| Time clients | Approved time source | Protected time protocol | Multiple sources/monitoring as profile requires |

Browser-to-database, browser-to-driver, browser-to-worker, worker-to-database,
worker-to-driver-host, driver-host-to-GCS, and driver-host-to-public-browser
routes are denied. All non-EAP identities are denied GCS effect credentials and
effect-capable egress.
Administrative access uses a separate management plane, strong authentication,
session recording where required, and no shared operator credential.

## Horizontal Scaling

| Workload dimension | Scale mechanism | Authority constraint |
| --- | --- | --- |
| REST queries and command ingress | Add stateless API replicas behind the edge | Domain leader and PostgreSQL still serialize authoritative mutations |
| WebSocket monitoring | Add gateways, partition subscriptions by domain, and use broker-assisted fan-out or outbox readers | Gateways cannot mutate and all cursors trace to committed events |
| Procedure execution | Add isolated worker capacity and scheduler partitions | Domain admission quotas and serialization keys remain authoritative |
| Multiple satellites | Add independent domains and place across clusters/nodes | One active Satellite Assignment Authority grant per satellite, one leader and one controller lease per domain |
| Driver calls | Add gateway/driver-host capacity and passive EAP candidates by satellite/effect boundary | One effect-enabled EAP path, ordered SAA/local permit consumes, exact binding/generation, and capability-specific concurrency limits |
| Authoring/validation | Add stateless language-service workers and Git/object capacity | Promotion remains review- and digest-controlled |
| Telemetry observation | Partition by domain/item, coalesce qualified UI feeds, and use time-series/broker systems | Procedure-consumed evidence and alarm transitions stay durable |
| Historical search/reporting | Add read replicas, indexes, analytics, and object-processing workers | Derived results expose source revision/freshness and never control runtime |

PostgreSQL write scaling is first achieved through domain-aware partitioning,
short transactions, efficient indexes, connection pooling, archival, and
separating derived high-rate workloads. Sharding or distributed SQL is not a
default remedy. It is considered only when measured qualified load exceeds a
well-tuned HA PostgreSQL deployment and the new design preserves transactions,
fencing, restore, audit, and operational simplicity.

## Monitoring Capacity

The product shall not contain a licensing or application constant that fixes
the number of monitoring users. This is the implementable meaning of
"unlimited monitors". Physical capacity is finite and must be declared.

Each deployment qualifies at least:

- concurrent authenticated users and WebSocket connections per domain and
  platform;
- connection establishment and synchronized reconnect rates;
- event and byte rates for execution, logs, prompts, alarms, and telemetry;
- snapshot size, snapshot request rate, and database/read-replica effect;
- slow-consumer percentage and queue memory;
- cursor retention and maximum disconnected replay volume;
- control API latency while monitor load is at and above the declared envelope;
  and
- failure behavior when a gateway, broker, replica, or zone is lost at peak
  load.

Admission and rate policy protects control-plane capacity. When monitoring
capacity is exceeded, the system rejects new connections or disconnects slow
consumers with explicit retry/resynchronization information. It does not drop
canonical events silently or delay domain fencing and control commits beyond
their objective.

## Resource And Capacity Model

The version-controlled deployment profile assigns these finite budgets per
platform and, where appropriate, per domain:

- maximum queued, loading, active, waiting, prompt, paused, and recovering
  executions;
- worker CPU, memory, output, filesystem, process, and wall-time budgets;
- maximum contexts, attachments, lifecycle operations, child procedures, and
  driver operations;
- named driver capability concurrency and serialization keys;
- REST request rates/sizes, WebSocket connections/subscriptions/queue bytes,
  and replay rates;
- PostgreSQL connections, transaction/lock latency, storage growth, replication
  lag, and outbox backlog;
- object size/rate/cache, telemetry sample/item/rate, log rate, and retention;
- audit/journal reserved capacity and export backlog; and
- headroom during one replica or failure-domain loss.

Quotas are observable and alert before exhaustion. Safety evidence stores have
reserved capacity inaccessible to ordinary log or analytics growth.

## Configuration And Secrets

Deployment configuration is schema-versioned, reviewed, immutable within a
generation, and promoted between environments by automation. Resolved profile
digests exclude secret values but include secret reference identity and
required key/certificate epoch where needed for reproducibility.

Configuration layers have explicit precedence: product defaults, environment
baseline, domain/server profile, driver host profile, context binding, procedure
attachment, and narrowly permitted runtime settings. Invalid, ambiguous,
unknown, or conflicting safety-relevant settings fail startup or generation
activation.

Secrets are delivered through short-lived workload identity or read-only
in-memory/file mounts from an approved service. The GCS effect credential is
retrievable only by the current assignment-bound EAP identity. Images,
environment dumps,
Git, bundles, logs, events, crash reports, and support packages contain no
secret. Rotation supports overlap where the protocol requires it and records
credential epoch without exposing key material.

## Deployment And Upgrade

1. Build reproducible, signed or integrity-attested artifacts with SBOM and
   vulnerability evidence.
2. Verify schema and configuration compatibility in an isolated environment.
3. Expand the database schema and deploy backward-compatible readers/writers.
4. Deploy public and observation replicas, then passive domain components.
5. For each domain, reserve a fresh externally anchored generation and
   `AuthorityIncarnationId` as an effect-disabled target; issue no effect
   credential, route, permit, or controller authority.
6. Atomically effect-disable the source EAP, drain admission, settle or reconcile
   consumed attempts, and externally fence the old path with evidence bound to
   the reserved target tuple.
7. Perform the controlled leader/generation transition under the reserved
   identity, reconcile nonterminal work, and verify state, cursor, lease, driver
   capability, local fencing, and recovery evidence while non-active.
8. Only after readiness succeeds, activate the reserved grant and issue fresh
   EAP credentials before proceeding to the next domain.
9. Retain rollback artifacts and database compatibility through the declared
   window. Rollback never rewrites newer audit or effect-certainty evidence.
10. Contract the schema only after the rollback window closes and backups are
   verified.

Canary rollout uses a simulator or non-effecting domain first. An upgrade that
changes driver wire compatibility, IR behavior, state semantics, or persistence
requires the corresponding compatibility and recovery qualification, not only
an HTTP health check.

## Environment Manifest

Every deployed environment records:

- environment and mission identity, classification, authorization boundary,
  owner, and purpose;
- domains and satellites, placement, failure domains, and driver endpoints;
- artifact/image digests, SBOMs, schema and migration versions;
- server, context, driver, language, compatibility, policy, and configuration
  profile digests;
- identity provider, workload identity, secrets/key, time, Git, object,
  database, audit, and monitoring dependencies;
- SAA quorum, non-rollback generation anchor, EAP identity/generation,
  effect-boundary credential reference, egress policy, and both permit paths;
- all `REL-PAR-*` values and capacity budgets;
- approved ports/flows, certificates and credential epochs;
- backup/restore and site-failover profile; and
- last qualification suite, load envelope, recovery exercise, known
  limitations, and approval references.

## Normative Requirements

| ID | Requirement |
| --- | --- |
| DEP-011 | Production deployments shall use a version-controlled environment manifest with immutable artifact and configuration identities. |
| DEP-012 | One satellite domain shall have one active service leader, one active controller lease at most, and no active-active driver effect path. |
| DEP-013 | API and stream tiers shall scale horizontally without moving write authority from the domain leader and PostgreSQL. |
| DEP-014 | Shared infrastructure shall enforce domain isolation with identity, authorization, network policy, queues, quotas, data scope, and failure-domain placement. |
| DEP-015 | Browser and worker networks shall have no route to driver hosts, GCS endpoints, PostgreSQL, secrets, or management interfaces except their explicitly documented narrow services. |
| DEP-016 | A deployment shall assign finite concurrency, throughput, storage, retention, replay, and recovery budgets and qualify them with required failure headroom. |
| DEP-017 | Monitoring shall have no product-imposed fixed user cap, while each deployment shall publish tested connection and event-rate capacity and controlled overload behavior. |
| DEP-018 | Engineering, HA, and disaster-recovery profiles shall be labelled accurately; an engineering or single-node install shall not claim high availability or operational authorization. |
| DEP-019 | Site disaster recovery shall be active/passive for control and shall fence the previous site's integration authority before promotion. |
| DEP-020 | Deployment configuration shall be typed, reviewed, immutable per generation, precedence-defined, integrity-protected, and rejected on unknown safety-relevant fields. |
| DEP-021 | Secrets shall be delivered through approved secret-reference and workload-identity mechanisms and shall not be embedded in images, Git, configuration payloads, events, or logs. |
| DEP-022 | Upgrades shall preserve mixed-version compatibility for the declared window, transition domains in a controlled order, and retain all audit and effect evidence across rollback. |
| DEP-023 | Every production profile shall provide tested backup/restore, clock, identity, audit, observability, certificate rotation, vulnerability remediation, and incident access procedures. |
| DEP-024 | Capacity and fault qualification shall include simultaneous peak monitoring, peak qualified execution, dependency degradation, and loss of one claimed failure domain. |
| DEP-025 | Every command-capable deployment shall use the Satellite Assignment Authority across all clusters and sites; inability to reach it or prove the prior path fenced shall prevent activation while permitting explicitly stale or read-only observation. |

## Verification Hooks

- Deploy each supported profile from an empty environment using only the
  manifest and protected external credentials.
- Run network-policy probes from every workload identity and prove both allowed
  flows and denied lateral routes, including denial of all non-EAP GCS effect
  credentials and egress.
- Saturate monitors, telemetry, execution admission, object access, outbox, and
  database connections independently and together while measuring control
  latency and bounded resource use.
- Remove a node, zone/failure domain, database primary, gateway, object service,
  identity provider, and time source under load and compare actual behavior to
  the reliability profile.
- Race SAA attempt-permit consumption against assignment changes and local
  permit consumption against lease/leader changes. Crash between consumes,
  local commit, EAP send, and acknowledgement and prove the ordered outcomes.
- Remove the generation anchor or one adopted legacy inventory disposition and
  prove activation remains read-only; apparent source-site loss shall not alter
  the result.
- Upgrade and roll back a populated multi-domain deployment with active,
  waiting, prompted, and uncertain-operation fixtures.
- Restore and promote the disaster site, prove the old site cannot reach a
  GCS effect boundary except through the old disabled EAP, and reconcile every
  operation, attempt, and permit receipt before
  control acquisition.
