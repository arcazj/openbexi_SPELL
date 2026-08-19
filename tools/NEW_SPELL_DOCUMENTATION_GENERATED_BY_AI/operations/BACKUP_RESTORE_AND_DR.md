# Backup, Restore, and Disaster Recovery

## Purpose and principles

This document defines recoverability for SPELL authoritative state, procedure releases, audit evidence, configuration, and supporting data. It supports `DATA-010`, `REL-009`, `REL-010`, `REL-013`, `SEC-020`, and `VNV-010`.

Five rules govern recovery:

1. High availability is not a backup. Replication can reproduce deletion, corruption, or compromise.
2. A backup is not accepted until a representative restore verifies content, integrity, dependencies, and recovery procedure.
3. Recovery never grants command authority or automatically resumes external effects.
4. Point-in-time recovery must reconcile database, procedure bundle, object, audit, driver, and external command state.
5. Recovery targets are approved from mission impact and data classification, not copied uncritically from this baseline.

## Recovery ownership

| Role | Accountability |
| --- | --- |
| System Owner | Approves service tiers, RPO/RTO, data loss risk, recovery sites, and return to service |
| Mission Operations Lead | Approves satellite operational state, external-effect reconciliation, and procedure resume/termination |
| Database/Storage Owner | PostgreSQL PITR, object storage, integrity, restore tooling, and evidence |
| Platform Owner | Infrastructure, orchestration, configuration, networking, identity integration, and recovery environment |
| Security Officer | CUI handling, cryptographic/key recovery, privileged access, clean-room controls, evidence preservation |
| Application Owner | Schema/application compatibility, event/state validation, worker recovery, and functional acceptance |
| Driver/Integration Owner | Command/link reconciliation and external endpoint validation |
| Records/Audit Owner | Audit retention, immutable copies, legal/incident hold, and verification |
| Incident Commander | Coordinates disaster declaration, decision log, recovery gates, communication, and lessons |

No single operator shall both authorize destructive recovery and execute it without independent verification.

## Data and service classification

Every production deployment shall maintain a recovery inventory with owner, classification, authority, dependencies, backup method, encryption/key, retention, RPO, RTO, restore order, and test result.

| Class | Examples | Authority and recovery treatment |
| --- | --- | --- |
| A: Operational authority | PostgreSQL control lease/epoch, execution and effect journal, prompts/inputs, variables, command admission/outcome, domain stream epoch/head and projection checkpoints | Transactional authority; synchronous HA where required, continuous WAL/PITR, strict integrity and external-effect reconciliation |
| B: Accountability and release | Security audit, signed procedure/software manifests, approvals, deployment evidence, configuration/policy revisions | Append-only/immutable retention, signed checkpoints, cross-failure-domain copy, independently accessible evidence |
| C: Reconstructable operational data | Derived read models, search index, cache, WebSocket fan-out state, broker copies | Rebuild from Class A/B; no backup required unless rebuild exceeds approved RTO |
| D: Bulk mission/diagnostic data | High-rate telemetry copy, logs, traces, reports, exports | Retention and recovery based on mission, records, CUI, investigation, and capacity needs; never treated as command authority |
| E: External authority | Git origin/mirror, identity directory, external telemetry/archive, ground link/device state | Contract/interconnection recovery plus local verified releases and metadata; external service state must be reconciled |

Temporary data does not automatically fall outside CUI handling or recovery analysis.

## Recovery targets

The following targets are provisional design inputs. The System Owner shall approve or replace them after mission impact analysis and record the source of each target. `RPO 0` means no loss of an acknowledged committed transaction within the covered failure model; it is not a promise against every regional or malicious event.

| Capability/data | Local HA target | Disaster RPO | Disaster RTO | Notes |
| --- | --- | --- | --- | --- |
| Command authority and committed execution state | RPO 0 for committed transactions; failover <= 60 seconds where HA is required | <= 5 minutes | <= 30 minutes | Recovery begins fenced and suspended pending reconciliation |
| Critical security audit handoff | RPO 0 for actions acknowledged after durable handoff | <= 1 minute to protected secondary/immutable sink | <= 4 hours for query access | Retention may require longer independent archive |
| Promoted procedure/software bundles and manifests | RPO 0 after successful promotion | RPO 0 through replicated immutable object copy | <= 30 minutes for active releases | Digest/signature verification required |
| Git procedure repository | Provider/replica objective | <= 15 minutes, or provider contract | <= 4 hours | Active runtime does not depend on Git availability |
| Configuration, policy, and infrastructure source | On every approved merge/release | <= 15 minutes | <= 2 hours | Secrets are referenced, not stored in Git backup |
| High-rate telemetry/log/trace copies | Deployment-specific | Default <= 1 hour | Default <= 24 hours | Tighten for mission analysis, incident, or records obligations |
| Search/cache/read models | None | Reconstructable | <= 4 hours or service objective | Rebuild must not overload authority store |

The recovery plan shall distinguish instance, node, availability-zone, storage, region/site, identity/provider, supply-chain, and cyber-compromise failures. A target is valid only for the failure modes exercised.

## Backup architecture

### PostgreSQL

- Use tested physical base backups plus continuous write-ahead log (WAL) archiving for point-in-time recovery (`DATA-010`).
- Stream replication supports availability but is not counted as the independent backup copy.
- Base backups and WAL segments are encrypted, integrity-checked, access-controlled, and copied to a separate failure domain and administrative boundary appropriate to risk.
- Backup tooling records database/system identifier, timeline, start/end log sequence, engine and extension versions, schema migration revision, encryption key reference, object digests, and verification result.
- WAL archive failure, missing segment, stalled backup, insufficient retention, replication lag, checksum error, or untested engine version pages the storage owner before recoverability is lost.
- Retention shall cover the approved PITR window and known detection delay. Expiration cannot remove material subject to incident, legal, contract, or records hold.
- Logical exports may support portability and selective verification but do not replace physical PITR for operational recovery.

### Immutable procedure and software artifacts

- Object storage enables versioning, retention lock/immutability, encryption, access logging, and cross-failure-domain replication.
- Every object is addressed and verified by digest. The release manifest binds source, IR, dependencies, compiler, compatibility profile, approvals, SBOM/provenance, and target restrictions.
- The registry/object-store backup retains signatures, certificate chain and validation metadata, revocation history, and verification tooling needed for historical recovery.
- Restore shall not turn a revoked or expired release into an approved release. Current policy and vulnerability disposition are reevaluated.

### Git, configuration, and infrastructure

- Mirror repositories, protected references, review metadata, release tags, and configuration history to a separately administered location.
- Test that repository history, large-file objects, submodules or dependencies, branch protections, and approval/audit metadata can be recovered. A bare source mirror without review or release evidence is insufficient.
- Infrastructure recovery uses reviewed, signed source and pinned providers/modules. State backends have encryption, locking, versioning, and independent backup.
- Deployed configuration snapshots record secret references and version metadata, never plaintext secret values.

### Audit and evidence

- Replicate accepted audit records to a security-controlled append-only sink and retention-controlled immutable/WORM storage.
- Retain signed checkpoints/hash-chain anchors, schema, parsing/verification tools, time-source evidence, and access history.
- Assessment, release, deployment, incident, exercise, and backup evidence is indexed and integrity-protected under its classification and retention schedule.
- Application, platform, or database administrators cannot shorten audit retention or delete all copies through their normal roles.

### Secrets and cryptographic keys

- Use the approved secrets/key provider's documented backup, escrow, replication, and recovery mechanism. Do not export keys merely to make an ad hoc backup.
- Key recovery requires dual authorization where policy requires and is tested without disclosing key material.
- Recovery planning covers root/intermediate trust, workload certificate issuance, artifact verification, data encryption, backup decryption, audit verification, revocation, and historical key versions.
- A recovery site cannot operate by sharing production private keys through files or tickets. Reissue or securely recover according to the approved ceremony.
- Key destruction, expiry, or provider loss shall not make retained CUI, audit, or release evidence unrecoverable before its approved disposition date.

### Brokers, caches, and derived views

Message transports, caches, and search indexes are non-authoritative. Their state shall be reconstructable from the committed journal and object/database snapshots. If a broker retains data needed to meet event-delivery RTO, its configuration and cursors are backed up, but replay remains revision- and sequence-checked. Restoring a broker message never authorizes an external effect.

## Backup security

- Backup data inherits the highest classification and handling restrictions of its contents.
- Use encryption in transit and at rest with keys separated from backup storage administration.
- Backup identities have write-only or narrowly scoped capabilities where possible; restore and deletion use separate, time-limited privileged roles.
- Maintain immutable/offline or logically air-gapped copies for ransomware and malicious-administrator scenarios.
- Restrict recovery consoles and networks through privileged access management, MFA, managed endpoints, and recorded/audited actions.
- Scan portable restored artifacts in an isolated environment without modifying originals. Malware detection does not justify destroying evidence.
- Backup catalogs, object lists, logs, and support bundles shall not disclose secrets or CUI to a lower-classification monitoring system.

## Restore workflow

Every restore uses an approved change or incident record and executes these gates (`REL-009`, `REL-013`, `VNV-010`):

1. **Declare scope.** Identify event, affected satellites/domains, failure time, suspected compromise/corruption, target recovery point, data-loss window, authority, and approvers.
2. **Fence effects.** Disable the Effect Authorization Point's credential and
   egress route, controller lease acquisition/renewal, scheduler dispatch,
   worker resume, and driver actuation in the recovery environment. Revoke local
   dispatch permits; a restored epoch, lease, credential, or permit has no
   authority.
3. **Preserve evidence.** Snapshot affected systems, logs, audit, storage metadata, keys/certificates, deployment/configuration, and incident chronology according to forensic policy.
4. **Establish trusted environment.** Deploy verified infrastructure, identity, network, time, secrets/key access, monitoring, and exact compatible application artifacts from trusted sources.
5. **Verify backup.** Check catalog, signatures/digests, encryption/key access, PostgreSQL system/timeline, WAL continuity, engine/extensions, object manifests, malware indicators, and classification.
6. **Restore authority store.** Restore the base backup and replay WAL only to the approved point. Record every excluded or failed transaction range.
7. **Restore artifacts/configuration.** Restore immutable releases, policies, configuration, and required external metadata by verified digest. Rebuild non-authoritative caches and read models.
8. **Validate internally.** Run database consistency, schema, referential,
   `(DomainId, DomainStreamEpoch, domain_event_position)`, lease/epoch, bundle
   signature, authorization, audit-chain, and application invariant checks.
9. **Reserve authority.** The mission-wide Satellite Assignment Authority obtains
   and commits a signed reservation receipt from its independent non-rollback
   generation anchor, allocates a new assignment generation and
   `AuthorityIncarnationId` outside restored history, and creates an
   effect-disabled `RESERVED` grant. It issues no effect credential, route,
   permit, controller authority, or activation right.
10. **Reconcile and fence external effects.** Compare the command journal with
    driver, link, archive, device/spacecraft, and operator records. Independently
    fence every prior integration path and bind its evidence to the reserved
    target tuple. Every externally effective operation after the recovery point
    receives canonical certainty `NO_EFFECT`, `EFFECT_CONFIRMED`,
    `EFFECT_POSSIBLE`, or `EFFECT_UNKNOWN` with evidence; `NOT_ATTEMPTED` remains
    a dispatch-stage fact rather than a certainty value.
11. **Resolve executions.** Revoke or invalidate every restored controller lease,
     clear its current pointer, and move affected executions to `SUSPENDED` with
     `CONTROL_LOST`. For each execution, choose terminate, remain suspended, or
     mark eligible for post-activation resume from a verified checkpoint under
     current policy; do not execute or resume while the target is reserved.
     Never replay an effecting step solely because database state was rolled
     back. A later controller obtains a new lease and acknowledges current
     prompts, alarms, executions, and uncertain effects before any explicit
     resume.
12. **Functional acceptance.** Test monitoring, snapshot/cursor recovery, prompts, authorization, lease fencing, audit, alarm path, driver connectivity, and a non-effecting/simulated command path.
13. **Authorize service.** System Owner, Mission Operations, Application, Driver, Storage, and Security approvers sign the return-to-service record appropriate to impact.
14. **Activate authority.** Only after prior-path fence evidence and target
    readiness are verified, transition the reserved grant to `ACTIVE`, create a
    new `DomainStreamEpoch`, and issue fresh short-lived Effect Authorization
    Point credentials; no restored controller is carried forward.
15. **Re-enable in stages.** Monitoring first, then controlled lease acquisition, then explicitly selected procedures/integrations. Observe abort thresholds.
16. **Close and improve.** Preserve evidence, quantify data loss and objective achievement, rotate exposed credentials, correct root causes, update plans/tests, and track actions.

## Disaster recovery strategy

The default control architecture is active/passive for command authority (`REL-002`). Stateless read/API services may run in multiple locations, but only a domain holding the mission-wide signed assignment, current authority incarnation, and current leader epoch can admit command/execution mutations. A disaster site starts with actuation fenced.

### Failover prerequisites

- disaster declaration and named Incident Commander;
- a newly reserved, effect-disabled assignment generation and
  `AuthorityIncarnationId` from the
  Satellite Assignment Authority with a valid external non-rollback anchor
  receipt, never recovered from backup;
- proof the prior command authority is fenced by storage, network, credential,
  or physical mechanism, with evidence bound to that reserved target tuple;
- quorum/leader epoch established in the recovery site;
- database recovery/replication consistency within accepted loss window;
- identity, time, PKI, secrets, policy, audit, monitoring, and external link health;
- exact approved artifact/configuration and current revocation data;
- external command, operation-attempt, controller-lease, schedule, and
  active-execution reconciliation;
- Mission Operations and System Owner authorization to enable control.

If the old site cannot be proven fenced, the new site remains read-only/suspended. Availability pressure does not justify active-active command ownership.

### Disaster scenarios

The recovery plan and exercises shall cover:

- loss of process/node/availability zone;
- loss or corruption of PostgreSQL primary and replicas;
- site/region/network isolation, including ambiguous partial connectivity;
- identity, PKI, secrets/key provider, time, DNS, Git, registry, object store, or audit provider outage;
- accidental destructive migration or operator deletion;
- compromised build/artifact, administrator, signing key, database, or procedure release;
- ransomware with online replicas/backups considered untrusted;
- external command/telemetry system divergence during recovery;
- simultaneous component failure during peak procedure and monitor load.

## Cyber recovery and clean room

When compromise is suspected, recovery shall use a clean administrative environment and trusted artifact/key roots. Investigators determine the last known trustworthy source, build, configuration, data, and credential state. Restoring the most recent backup is unsafe if it contains persistence or corrupted state.

The clean-room process shall:

- preserve original evidence and work from verified copies;
- rotate or reissue affected human, service, database, driver, backup, signing, and encryption credentials according to key impact;
- rebuild systems from signed sources rather than cloning compromised hosts;
- validate artifacts with independent SBOM/provenance/signature and malware analysis;
- compare database/audit history and external mission records for unauthorized effects;
- maintain network isolation and disabled actuation until explicit recovery gates pass;
- increase monitoring and retain evidence during the defined post-recovery watch period.

## Testing and exercise schedule

Minimum proposed cadence, subject to stricter contract/agency requirements:

| Activity | Minimum cadence | Acceptance evidence |
| --- | --- | --- |
| Automated backup integrity/catalog/WAL continuity | Daily | Successful job, digest/checksum, coverage and alert test |
| Sample PostgreSQL PITR to isolated environment | Monthly and before/after major engine change | Achieved recovery point/time, integrity/application checks, issues |
| Immutable artifact/Git/configuration restore | Quarterly | Verified digests, history/metadata, build/deploy usability |
| Key/secrets recovery procedure | Quarterly tabletop; annual technical exercise | Dual-control record, service reauthentication, no key disclosure |
| Single-component/availability-zone failover | Quarterly | Fencing, achieved time/loss, procedure/command reconciliation |
| Disaster-site exercise | Semiannually | Full gate record, RPO/RTO, external integration, return-to-service decision |
| Cyber clean-room recovery | Annually | Trusted-root validation, credential rotation, evidence preservation, staged activation |
| Unannounced operations tabletop | Annually | Role readiness, contact/escalation, decisions and corrective actions |

At least one annual exercise includes active procedures in a safe simulation with command timeouts, an uncertain external outcome, monitor load, identity or time degradation, and an audit/backup complication. Production effects are never used merely to make an exercise realistic.

## Recovery evidence and metrics

For every backup and exercise, retain:

- scope, topology, artifact/configuration/database versions, owner and approvers;
- backup identifier, recovery point, integrity/key metadata, restore start/end, and target environment;
- achieved data loss and service recovery time against RPO/RTO;
- invariant, authorization, fencing, sequence, audit, and external-effect reconciliation results;
- manual steps, errors, missing dependencies, alert/runbook performance, and capacity observations;
- exceptions, risks, corrective actions, owners, due dates, retest, and closure evidence.

Operational dashboards report last successful backup, last verified restore, PITR window, WAL/archive lag, immutable-copy status, key recoverability status, exercise age, achieved RPO/RTO, unresolved findings, and time until policy breach (`OPS-001`, `REL-010`, `REL-013`). A successful backup job without a current restore test is reported as unverified recoverability.
