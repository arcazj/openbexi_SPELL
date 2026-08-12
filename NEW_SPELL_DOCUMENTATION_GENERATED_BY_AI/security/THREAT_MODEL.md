# SPELL Threat Model

## Purpose and method

This threat model identifies security abuse cases that can affect mission operations, CUI, auditability, and recovery. It uses trust-boundary review and STRIDE categories, then applies a mission-specific question: can the event create, suppress, repeat, misdirect, or conceal an operational effect?

The model is a living artifact. Product Security owns the method, but System Security, Mission Operations, Safety, architecture, driver owners, and procedure owners jointly approve its assumptions and dispositions. Review is required at least annually and after a boundary, protocol, driver, compiler, identity, storage, deployment, or mission-safety change.

## System assumptions

The baseline assumes:

- one Satellite Control Domain controls one satellite;
- many procedures may execute concurrently within policy constraints;
- one human holds execution control for a domain while any qualified number of users monitor read-only state;
- procedure source is managed in Git and production executes an immutable promoted bundle;
- browser clients use HTTPS and a committed-state WebSocket feed;
- control authority, workers, drivers, database, object storage, and security services are separate trust subjects;
- PostgreSQL holds authoritative transactional control and audit-handoff state; caches and message transports are non-authoritative;
- workers and drivers may fail or become hostile and therefore cannot grant themselves control authority;
- a mission-wide SAA and non-rollback generation anchor prevent restored or
  independent sites from reusing command authority, and one Effect
  Authorization Point exclusively owns each effect credential and egress path;
- spacecraft, ground systems, external telemetry, time, identity, Git, cloud, and supplier services can be unavailable or compromised.

Any deployment that violates an assumption shall update this model before authorization.

## Protected assets

| Asset | Required properties |
| --- | --- |
| Command intent and acknowledgment | Authenticity, integrity, correct satellite binding, ordering, non-repetition, explicit uncertainty |
| Controller authority | Exactly one valid holder, bounded lifetime, durable monotonic fencing, accountable transfer |
| Procedure release and execution state | Approved provenance, immutability, deterministic interpretation, recoverability |
| Telemetry, variables, prompts, alarms, logs | Integrity, sequence, freshness, classification, correct execution/satellite attribution |
| Credentials, keys, service identities | Confidentiality, scope, rotation, revocation, non-exportability where required |
| CUI and mission data | Authorized access, encrypted transfer/storage, retention, controlled export/disposal |
| Security audit | Completeness, attribution, ordering, tamper evidence, independent retention |
| Software/build/deployment chain | Source and dependency integrity, reviewer accountability, reproducible provenance |
| Availability and safe degradation | Bounded failure domains, observable degraded state, no unsafe automated recovery |

## Security and safety invariants

The following invariants are release-blocking. A risk acceptance cannot redefine them without the authorized Risk Owner or Authorizing Official, System Owner, and Mission Safety approval and a replacement safety argument.

1. A monitor cannot cause a procedure or command state mutation.
2. A controller with a stale or foreign lease, client proof, authority incarnation, or `control_fencing_token` cannot mutate execution state or reach a driver.
3. No request, procedure, worker, credential, query, event, or cache entry crosses its authorized satellite boundary.
4. Production cannot execute source that differs from the approved release digest.
5. An uncertain command outcome is never converted to success or automatically resent.
6. Restart, failover, replay, or reconnect cannot duplicate a previously accepted external effect.
7. Loss of database, time, identity, audit admission, or command-link certainty moves affected operations to an explicit degraded or fail-closed state.
8. Security and operational history cannot be silently edited by an application administrator.
9. Two clusters, sites, restored copies, or legacy/new systems cannot have effect-enabled command paths for one satellite simultaneously, including during drain or transition.
10. A driver, worker, gateway, or administrator cannot bypass the Effect Authorization Point or obtain its effect credential and route.

## Threat actors and failure sources

- unauthenticated external attacker;
- compromised monitor, controller, developer, reviewer, administrator, or security account;
- malicious insider acting within part of an authorized role;
- compromised operator workstation, browser extension, token, or session;
- vulnerable or compromised service, worker, driver, dependency, CI runner, or supplier update;
- hostile procedure source or dependency submitted through an authorized workflow;
- compromised identity, Git, artifact, database, message, object, secrets, time, DNS, telemetry, or mission integration service;
- accidental operator/developer error, software defect, resource exhaustion, network partition, stale replica, storage corruption, or clock failure.

## Trust boundaries and entry points

| Boundary | Principal entry points |
| --- | --- |
| Browser to access tier | Login callback, REST API, WebSocket, file import/export, procedure editor, search, notifications |
| Access tier to control tier | Authorized mutations, state queries, subscriptions, controller lease operations |
| Control tier to execution tier | Bundle assignment, lifecycle actions, prompt replies, variable changes, checkpoints |
| Execution tier to driver tier | Command request, telemetry subscription, acknowledgment, event callbacks |
| Platform to data services | SQL, object API, event transport, cache, audit sink, backup channel |
| Platform to management services | Identity, PKI, secrets, orchestration, CI/CD, Git, registry, monitoring, time, DNS |
| Driver to Effect Authorization Point to mission systems | Typed operation request, one-use permit consumption, command/telemetry links, archives, simulators, external device protocols |

## Threat register

Likelihood and impact are deployment-specific. The table records mandatory design treatment and detection; the deployment risk register assigns ratings and residual-risk owners.

| ID | Scenario and effect | Prevent/contain | Detect/evidence | Required safe state |
| --- | --- | --- | --- | --- |
| TM-01 | Stolen browser session lets an attacker acknowledge a prompt or start/stop a procedure | MFA, managed-device policy, short-lived audience-bound sessions, reauthentication for sensitive changes, CSRF/origin controls, server authorization | Session anomaly, new device/location, denied action, sensitive-action audit | Revoke session and lease; do not infer procedure outcome |
| TM-02 | XSS or dependency compromise steals data or issues same-origin actions | Restrictive CSP, output encoding, framework auto-escaping, reviewed dependencies, no bearer token in persistent browser storage, signed builds | CSP reports, browser integrity telemetry, dependency alerts, unusual API sequence | Disable affected UI artifact; fence exposed controller session |
| TM-03 | Cross-site request or hostile origin opens a real-time/control channel | Same-site secure cookies, anti-CSRF token, strict CORS, `Origin` and subprotocol validation, explicit content types | Rejected origin/CSRF events and rate alerts | Reject request before authorization/state change |
| TM-04 | A monitor calls a hidden mutating endpoint | Central deny-by-default authorization independent of UI, negative permission tests | Denied action audit with subject/role/resource | No mutation; repeated attempts trigger investigation |
| TM-05 | Two controllers race during reconnect, failover, or a forged/parallel handover | Serializable durable lease and singleton handover request; monotonic control fence; request-bound requester proof, separate current-holder approval proof, subsequent responsibility acknowledgement, atomic grant/pointer/mode-projection transfer, expiry, and effect-boundary revalidation | Lease/request conflict metric; request, approval, acknowledgement, transfer, stale-token, identity, and timestamp audit; concurrency test | Only the installed `ACTIVE` lease and current `control_fencing_token` remain valid; reject every stale predecessor and pause affected admission on authority ambiguity |
| TM-06 | API, broker, or worker replays a command | Idempotency key, expected revision, durable command ID, state-machine validation, driver deduplication where available | Duplicate/replay counters, command lineage audit | Return prior result or `EFFECT_UNKNOWN`; never reissue silently |
| TM-07 | Network timeout hides whether a command took effect | Explicit acknowledgment taxonomy, reconciliation interface, operator workflow | Timed-out command alert, link/ack trace, reconciliation record | Mark `EFFECT_UNKNOWN`, inhibit automatic retry |
| TM-08 | Satellite A identity or object is used against Satellite B | Resource-scoped workload identities, database/object partitions, authorization attributes, per-satellite driver credentials, egress policy | Cross-satellite canary tests, denied access, query and object audit | Reject and isolate subject; preserve evidence |
| TM-09 | Malicious procedure escapes language semantics to run shell/native/network code | Parse to bounded versioned data-only IR; reject dynamic import/reflection/native calls; isolated worker; no default egress | Compiler rejection, sandbox alert, unexpected process/egress detection | Reject bundle or terminate isolated execution without granting new effects |
| TM-10 | Developer promotes an unreviewed or substituted procedure | Protected Git branches, separation of duties, required review, signed immutable bundle, digest verification at admission | Git/release audit, signature failure, digest mismatch | Refuse promotion or execution |
| TM-11 | Compromised CI or dependency injects code | Isolated ephemeral build, pinned dependencies, SBOM, provenance, independent signing policy, artifact transparency, image admission | Provenance mismatch, dependency/vulnerability alert, reproducibility check | Quarantine artifact and deployment; roll back to verified digest |
| TM-12 | Driver parses malformed external data or maps command fields incorrectly | Out-of-process least-privilege driver, generated/strict schemas, size/time bounds, conformance corpus, fuzzing, command policy | Driver crash/error rate, schema rejection, semantic comparison tests | Isolate driver; stop affected command admission; preserve other domains |
| TM-13 | Compromised driver fabricates acknowledgment or telemetry | mTLS identity, source binding, protocol validation, sequence/time checks, independent correlation where mission system permits | Conflicting sources, impossible sequence/value, driver integrity alert | Mark data suspect; do not convert unverified acknowledgment to success |
| TM-14 | Telemetry/event flood exhausts APIs or hides alarms | Bounded queues, per-source quotas, backpressure, priority classes, admission limits, horizontal monitor delivery | Lag, drop, queue, CPU/memory, rate-limit and alarm-latency metrics | Preserve command/control and alarm priority; label dropped/coalesced noncritical data |
| TM-15 | SQL injection or overprivileged database role changes state/audit | Parameterized queries, schema validation, least-privilege roles, migration separation, database network isolation | Query/security logs, integrity checks, unexpected DDL/write alert | Revoke role, fence control if state integrity is uncertain, recover verified state |
| TM-16 | Event broker or cache is treated as authority and injects stale state | Database-authoritative revision and sequence, signed/service-authenticated events, cache namespace/scope, snapshot-plus-cursor recovery | Gap/revision mismatch, stale-event metric, broker access audit | Discard non-authoritative state and rebuild from committed snapshot |
| TM-17 | Application or administrator deletes incriminating audit | Separate audit identity/sink, append-only API, signed checkpoints/hash chain, immutable retention, dual control for retention policy | Missing sequence/checkpoint, WORM verification, audit-admin activity | Block critical actions if durable handoff unavailable; open incident |
| TM-18 | Secret leaks in Git, logs, support archive, image, or procedure | Secret manager, short-lived identity, pre-commit/build scanning, structured redaction, export review | Secret scans, access anomalies, provider detection | Revoke/rotate, quarantine artifact/export, assess data exposure |
| TM-19 | Time service manipulation reorders events or invalidates leases | Authenticated/approved time sources, multiple-source monitoring, monotonic timers for intervals, bounded skew policy | Clock offset/step alert, conflicting timestamps, lease anomaly | Suspend lease renewal or command admission when time safety bound is exceeded |
| TM-20 | Split brain during high-availability failover creates two command authorities | Quorum-based leader/lease store, storage/network fencing, monotonically increasing leader epoch, no active-active command writer | Epoch conflict, quorum loss, dual-leader probe, driver stale-epoch rejection | Fail closed for new external effects until a single authority is proven |
| TM-21 | Malicious administrator bypasses application policy | Separate platform/security/operator duties, privileged access management, just-in-time access, signed policy/deployment, independent audit | Privileged session/change audit, drift and signature alerts | Remove unauthorized change, rotate access, reassess affected commands/data |
| TM-22 | Backup theft or ransomware exposes CUI and prevents recovery | Encryption, separate backup identity, immutable/offline copy, restricted restore, key recovery separation | Deletion/change alerts, restore verification, key-access audit | Enter recovery environment with all actuation disabled until integrity approval |
| TM-23 | Git or artifact service outage causes runtime to fetch mutable source | Promoted bundles stored immutably inside runtime boundary; no runtime dependency on branch head or public registry | External-service health and attempted runtime fetch alert | Continue verified active bundles; block new unverified releases |
| TM-24 | Prompt text or operator notification deceives a controller about target/effect | Server-generated trusted context, visible satellite/procedure/step identity, sanitized procedure content, confirmation policy for hazardous action | Prompt lineage and acknowledgment audit, content validation failure | Reject malformed prompt; require fresh trusted-context confirmation |
| TM-25 | Browser or API enumerates other missions through IDs, search, errors, or timing | Opaque scoped identifiers, authorization before lookup, filtered indexes, uniform safe errors, query limits | Enumeration patterns, cross-scope denial tests | Return no protected existence information |
| TM-26 | Recovery replays stale worker checkpoint after later external effects | Commit checkpoint and effect journal atomically where possible, epoch/revision checks, reconciliation before resume | Checkpoint/effect mismatch, resume audit | Keep execution suspended until operator reconciles |
| TM-27 | Independent clusters, restored sites, or legacy/new systems activate command paths for one satellite | Mission-wide linearizable Satellite Assignment Authority, externally anchored non-rollback generation reservation, externally verified old-path fencing, grant-bound short-lived credentials, final effect-boundary validation | Assignment-generation conflicts, anchor-receipt mismatch, stale-incarnation rejection, dual-path probes, grant and credential audit | Revoke/fence affected grants; all candidates remain read-only until one effect-enabled path and unresolved effects are proven |
| TM-28 | A compromised driver host bypasses final authorization or sends after lease expiry, takeover, or delayed RPC | Deny direct mission egress; only the Effect Authorization Point holds the credential and route; a linearizable one-use SAA consume followed by transactional PostgreSQL permit/journal commit orders current assignment, leader, lease, operation-attempt, and generation state before send | Denied egress, permit conflicts, stale-tuple audit, credential-use correlation, delayed-RPC tests | Reject before effect; suspend owning execution and reconcile if the effect boundary may already have been crossed |
| TM-29 | SAA restore reuses an abandoned generation not present in the restored ledger | Mandatory external non-rollback generation anchor, signed reservation receipt committed before visibility, no issuance when anchor proof is missing or ambiguous | Anchor/ledger reconciliation, receipt continuity, generation-gap and rollback alerts | Disable issuance and effect authorization for the satellite; observation and evidence repair only |
| TM-30 | An undiscovered pre-SAA legacy credential, session, endpoint, or egress route remains command-capable during cutover | Externally identified legacy adoption record, complete independently reviewed path inventory, per-item fence evidence, dual-path probes, no target effect grant until inventory closure | Credential/session/egress inventory reconciliation, GCS and network audit, fence-provider attestations | Keep replacement read-only; isolate every discovered legacy path and repeat adoption review |

## Driver and external-command assurance

Drivers are a high-impact trust boundary because protocol-valid behavior may still be semantically unsafe. Each driver shall have:

- a versioned interface contract and compatibility statement tied to the authoritative Driver Development Manual;
- command and telemetry schemas with units, ranges, encoding, endianness, time basis, and error semantics;
- explicit mapping from SPELL request ID to external transaction/sequence and acknowledgment states;
- a declared retry and deduplication model, including protocols that cannot safely retry;
- protocol conformance, malformed-input, boundary-value, timeout, disconnect, restart, and failover tests;
- least-privilege credentials and satellite-specific endpoint policy;
- a simulation or hardware-in-the-loop qualification record using the exact driver artifact;
- an independent review for commands identified as hazardous by mission safety.

## Procedure and Git abuse cases

The procedure workflow shall test at least these abuses:

1. a developer changes a branch after approval but before release;
2. a release manifest references a dependency not reviewed in the pull request;
3. a symlink, path traversal, case collision, archive bomb, or oversized file escapes bundle boundaries;
4. a procedure imports an unsupported Python module or reaches a filesystem/network primitive;
5. Unicode or visual-confusable text causes a reviewer to approve code with different semantics;
6. a deleted or force-pushed Git reference hides approval history;
7. a validly signed bundle is used in the wrong mission, satellite, or environment;
8. an editor preview differs from compiled and executed source;
9. a running procedure observes edits from a mutable worktree;
10. a rollback selects a vulnerable or operationally incompatible release.

Release bundles therefore bind normalized source bytes, dependency digests, target compatibility profile, mission/satellite applicability, compiler version, validation results, approvals, and content digest.

## Security verification scenarios

The release test plan shall include automated and manual adversarial tests for:

- all role/action denials and privilege transitions;
- same-satellite lease acquisition races and stale fencing at API, worker, and driver layers;
- cross-satellite object, event, subscription, query, cache, backup, and driver access;
- replayed, reordered, duplicated, expired, malformed, oversized, and wrong-version messages;
- token theft, revocation, session expiry, WebSocket reauthorization, CSRF, XSS, and hostile origins;
- compiler/sandbox escape attempts and execution resource exhaustion;
- artifact, procedure, configuration, migration, and policy signature substitution;
- database, broker, cache, object store, identity, time, audit, and network partitions;
- driver crashes and ambiguous command outcomes during restart/failover;
- Effect Authorization Point bypass, permit/lease races, delayed RPCs, SAA or
  database-quorum loss, generation-anchor rollback, and incomplete legacy-path
  adoption;
- audit truncation, reordering, clock drift, sink loss, and retention-policy changes;
- backup compromise and clean-room recovery with actuation disabled.

Tests shall record the exact artifact/configuration, topology, seed/input, expected invariant, observed output, audit correlation, and evidence digest.

## Residual risk and acceptance

The platform cannot by itself prevent a properly authorized controller from making an operationally wrong decision, validate the physical truth of all external telemetry, guarantee availability of external ground/space links, or replace independent spacecraft safety protections. Those risks require training, mission rules, hazard analysis, command constraints, independent verification, and external controls.

Every open threat shall have an owner, likelihood, mission/security impact, affected assets, planned treatment, milestone, verification, residual risk, approver, expiry, and review trigger. A threat is not closed by citing this document or a control design; closure requires implementation and evidence from the deployed boundary.
