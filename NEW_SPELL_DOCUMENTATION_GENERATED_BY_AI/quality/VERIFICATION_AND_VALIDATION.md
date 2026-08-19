# Verification And Validation Strategy

## Purpose

Verification proves that the implementation satisfies the specification.
Validation proves that the resulting system supports mission operators safely
and effectively in its intended environment. Neither is replaced by a successful
demo, code coverage percentage, or NIST control mapping.

No live spacecraft or operational GCS connection is in scope until the specific
adapter, environment, effect class, procedures, organization, and operational
authority pass their independent gates.

## Current v0.10 And Planned v0.11 Application

The reconstructed v0.10 candidate applies this strategy without changing this
Draft specification's status. v0.10 has 195 numbered example outcomes and a separate 257-subcase variant
matrix; every identified form requires its own assertion and trace. Hash-bound
semantic adaptations are required for malformed, pseudocode, output-only,
placeholder, negative, and intentionally invalid source. They are not evidence
of verbatim snippet execution or unrestricted Python/SPELL compatibility.

The planned simulator-only v0.11 `BuildTC`/`Send` gate must cover the 26 command
statements in Examples 57 through 77; typed arguments; command, sequence, group,
and block expansion; duplicate-child identity; critical confirmation;
deterministic `Time`, `ReleaseTime`, `SendDelay`, per-element timeout, delayed
verification, tolerance, and adjustable-limit behavior; separate transport,
loading, release, acknowledgement, onboard execution, verification,
disposition, and certainty; cancellation; bounded checkpoint recovery;
reconciliation; uncertainty; and no automatic resend.

Focused suite success is insufficient. A future v0.11 record must retain exact
commands, counts, skips, limitations, artifact identity, built-image contract
availability, and full regression/frontend/build results from one consistent
working-tree state. Direct public-API extremes fail with bounded typed
diagnostics rather than raw runtime exceptions. v0.11 has no implementation or
local qualification record in the v0.10 release tree; no future local result
becomes accepted without its own immutable release endpoint and independent
gates.

## Evidence Contract

Every result used for a release decision shall record:

- requirement and test identifiers;
- exact source commit and candidate artifact digests;
- dependency locks, SBOMs, build provenance, and signatures;
- schema, migration, bundle, language profile, IR, API, event, driver, browser,
  database, and configuration versions;
- environment topology and trust profile;
- sanitized fixture/workload identity and digest;
- command or automated workflow used to reproduce the result;
- start/end time, clock source, result, logs, metrics, traces, and artifacts;
- known exclusions, findings, exceptions, reviewer, and approval state.

Evidence shall be immutable, access controlled, retention managed, and linked to
the released digest. A screenshot alone is not sufficient evidence for a state,
authorization, recovery, performance, or security claim.

## Test Environments

| Environment | Allowed connections/effects | Purpose | Exit control |
| --- | --- | --- | --- |
| Static/CI | No runtime network except approved build dependencies; no GCS | Parsing, schemas, policy, unit, model, supply chain | Reproducible pass and evidence manifest |
| Deterministic simulator | Approved local simulator only | Language, driver, execution, UI, failure, replay | Conformance and fault gates |
| Integration simulator | Representative distributed services; no operational GCS | HA, performance, security, backup, DR | Qualified workload and recovery report |
| Read-only shadow | Specifically approved observation adapter; structurally no effect authority | Compare telemetry/events/state to legacy evidence | Independent read-only enforcement review |
| Non-operational effect lab | Approved isolated target and effect classes | TC/resource/event mutation conformance | Hazard, certainty, reconciliation and rollback acceptance |
| Operational candidate | Contractually and operationally approved connections only | Supervised readiness and pilot | Formal authorization package |

Environment promotion does not transfer credentials, trust roots, data, or
authorization automatically.

## Verification Layers

### Documentation And Model

- Resolve every relative link and source authority digest.
- Validate requirement IDs for uniqueness and trace coverage.
- Build the GUI User Manual PDF from controlled source, verify its version and
  artifact metadata, inspect every rendered page, check headings, links,
  bookmarks, selectable text, image alternatives, and reading order, and prove
  its critical-workflow coverage against the accepted web application.
- Review state machines, lease/fence invariants, data ownership, trust boundaries,
  failure modes, sequence diagrams, schemas, and ADR consequences.
- Close or explicitly gate every safety/security/interoperability TBD.

### Language And Procedure

- Reconcile the manual catalogs and examples to detailed compatibility rows.
- Use golden positive, boundary, negative, malformed, adversarial, and resource
  exhaustion cases for every implemented grammar/function/modifier/result.
- Prove parsing and semantic analysis do not execute imported or embedded code.
- Test deterministic compilation, bundle identity, dependency closure, bounds,
  diagnostics, control flow, variables, conditions, timers, prompts, child
  procedures, files, shared data, recovery, and as-run reconstruction.
- Use mutation/property testing for parser and state invariants; code coverage is
  supporting evidence, not the acceptance criterion.

### Driver And External Effects

- Run one conformance suite against the deterministic simulator and every adapter.
- Cover lifecycle ordering, configuration precedence, capability negotiation,
  schema evolution, typing, deadlines, cancellation, concurrency, saturation,
  sequence/cursor gaps, backpressure, disconnect, restart, cleanup, and failover.
- For external effects, inject failures before dispatch, during transport, after
  acceptance, after external acknowledgment, and before local commit.
- Prove that uncertain effects are surfaced and reconciled without blind resend.
- Independently demonstrate that read-only adapters cannot reach mutation paths.

### Persistence And Protocol

- Test transaction rollback, uniqueness, revisions, fencing, state/event atomicity,
  migration from every supported version, PITR, corruption detection, restore,
  and retention.
- Test REST idempotency, expected revision, authorization races, expiry, rate
  limits, and typed errors.
- Test WebSocket snapshot/cursor handoff, ordering, duplicates, gaps, cursor expiry,
  reconnect storms, slow consumers, schema versions, revoked sessions, leader
  failover, and stale-state presentation.
- Delay competing PostgreSQL transactions and prove `(DomainId,
  DomainStreamEpoch, domain_event_position)` follows commit serialization.
  Change authority incarnations and prove stale cursors receive an explicit
  stream-epoch reset. Exercise authorization projections with long excluded
  ranges and prove contiguous projection/delivery sequences expose no excluded
  position, count, or timing metadata. Exercise subscriber filters only over
  authorized projection positions, heartbeat non-advancement, and scope-change
  resynchronization.
- Test internal RPC compatibility, identity, authorization, deadlines, retry
  budgets, cancellation, and version skew.

### Web And Human Factors

- Exercise all three modes with positive and negative authorization cases.
- Exercise controller acquire/renew/release/handover/expiry/revoke/failover and
  simultaneous contenders, including attempts to reuse a lease from another
  tab, client proof key, session, device, domain, or authority incarnation.
- Verify critical workflows with mission-representative operators, terminology,
  data density, alarms, degraded states, confirmations, and error recovery.
- Test supported desktop and mobile/tablet viewports without overlap or hidden
  state, and verify keyboard, focus, screen-reader semantics, contrast, scaling,
  non-color cues, reduced motion, and time-limited interaction accommodation.
- Verify historical/replayed/stale state cannot be mistaken for live state.
- Have representative controllers, monitors, and procedure developers complete
  the critical workflows using the published GUI User Manual; record ambiguity,
  omission, unsafe interpretation, accessibility, and recovery findings against
  the exact manual and application digests.

### Reliability And Operations

- Kill/restart each process and host at every durable transition boundary.
- Inject partition, latency, loss, duplication, reordering, clock drift, clock
  loss, database failover, object-store failure, broker failure, identity outage,
  DNS/certificate failure, storage exhaustion, resource saturation, and site loss.
- Exercise graceful shutdown, rolling upgrade, failed upgrade, rollback, backup,
  PITR, cross-site restore, controller recovery, operation reconciliation, audit
  export, and incident runbooks.
- Race independent clusters, restored sites, and a modeled pre-SAA legacy path
  for one test satellite. Partition the SAA and its non-rollback generation
  anchor, omit one legacy credential/egress path, delay old-generation RPCs, and
  prove that only one effect-enabled path can reach the Effect Authorization
  Point. Race permit consumption against lease release, expiry, revocation, and
  takeover and verify the database-serialized winner and safe reconciliation.
- Compare measured availability, latency, freshness, capacity, RPO, and RTO to the
  approved target profile. No target is inferred from a lab result.

### Security And Supply Chain

- Review the threat model on every trust-boundary or effect-capability change.
- Run secret, dependency, license, SAST, IaC, container, configuration, malware,
  DAST/API, fuzz, and penetration testing appropriate to the candidate.
- Verify least privilege, segmentation, MFA/session behavior, service identity,
  secret rotation, key/certificate rotation, audit integrity, log minimization,
  input bounds, worker/driver isolation, and deployment signature policy.
- Produce SP 800-171A Rev. 3 assessment evidence only after the organization has
  defined the CUI boundary, applicability, ODPs, SSP, assessment scope, depth,
  coverage, methods, and assessor independence.

## Required Model Invariants

At minimum, property/model tests shall prove:

1. One domain maps to one satellite.
2. At most one unfenced writer commits domain state.
3. At most one current controller fence authorizes interactive control.
4. A stale controller, leader, revision, session, or configuration cannot mutate.
5. A committed event corresponds to committed state and sequences do not regress.
6. A prompt and command request have at most one winning settlement.
7. Idempotent request replay cannot create a duplicate logical operation.
8. Transport retry cannot turn into an unapproved external-effect retry.
9. Terminal execution state cannot return to active state except through a new,
   explicitly modeled execution/reload identity.
10. Active executions remain pinned to exact source and configuration identity.
11. Monitoring and Edit authorization cannot reach runtime mutation paths.
12. Cross-domain identifiers and credentials cannot access another domain.
13. At most one mission-wide effect-enabled path can authorize a `SatelliteId`
    across active, draining, restored, and legacy/new systems.
14. A restored authority incarnation, assignment generation, dispatch
    credential, controller lease, or client proof cannot authorize an effect.
15. Authorization-filtered delivery is contiguous within an opaque projection
    and exposes no excluded domain position, count, or timing metadata.
16. Every telemetry/alarm fact influencing an external operation is committed
    and bound to operation intent before dispatch.
17. A generation cannot become visible without a valid non-rollback anchor
    receipt, and restore cannot reuse an abandoned generation.
18. Driver hosts cannot bypass the Effect Authorization Point or obtain its
    credential/egress route; delayed and stale attempts fail at final dispatch.
19. Controller authority replacement revokes the old lease, suspends affected
    executions, and requires explicit acknowledged reacquisition.
20. Every schedule restart preserves its original target, clock/policy, and
    occurrence identity and applies one bounded misfire outcome without duplicate
    execution creation.

## Workload Qualification

The product owner and architect shall approve a workload profile containing at
least domains, concurrent executions/domain, operations/execution, event rate,
telemetry rate and item cardinality, retained history, prompt rate, log size,
monitor connections, controller actions, reconnect surge, bundle size, Git
activity, report/export size, and fault scenario.

Report median and tail latency distributions, throughput, freshness, error rate,
queue/lag, resource saturation, database behavior, storage growth, recovery time,
and dropped/rejected work. Publish the qualified ceiling and deterministic
admission/degradation behavior; do not label capacity unlimited.

## Release Gates

| Gate | Mandatory evidence | Blockers |
| --- | --- | --- |
| G0 Specification | Approved requirements/ADRs, closed entry decisions, source hashes, detailed feature compatibility rows | Unapproved normative ambiguity or missing authority |
| G1 Build | Reproducible signed artifacts, locks, SBOM, provenance, scan results | Critical integrity/provenance gap or unapproved vulnerability |
| G2 Functional | Requirement tests and exact candidate evidence | Failed mandatory behavior or untraced implementation |
| G3 Compatibility | Language/driver/manual-example conformance for implemented scope | Missing detailed row, silent incompatibility, unresolved oracle |
| G4 Reliability | State models, fault injection, failover, backup/restore/DR results | Invariant violation, duplicate/uncertain effect mishandling, missed RPO/RTO |
| G5 Security | Threat review, security tests, SSP/control evidence and POA&M treatment as applicable | Boundary/ODP unknown, unacceptable risk, ineffective mandatory safeguard |
| G6 Performance | Approved workload and capacity/freshness/latency results | Unqualified ceiling or unsafe overload behavior |
| G7 Operator | Human factors, accessibility, mode/control and degraded workflow acceptance | Ambiguous authority/state or critical workflow failure |
| G8 Environment | Deployment, configuration, secrets, runbooks, monitoring and rollback | Unverified environment or operational dependency |
| G9 Operational | Named authority accepts scope, residual risks, capability, time window and rollback | No explicit authorization |

A waiver shall be time bounded, requirement specific, risk assessed, approved by
the accountable role, paired with compensating controls, and linked to rollback.
No waiver may be inferred from schedule pressure or prior release behavior.
