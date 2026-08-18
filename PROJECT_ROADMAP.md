# OpenBEXI SPELL Project Roadmap

## Document Control

| Field | Value |
| --- | --- |
| Document revision | Accepted v0.7.0 baseline and v0.8 candidate preparation |
| Update type | Accepted-release status, strict release bindings, v0.8 worktree implementation and verification, and requested-only v0.9 follow-on |
| Updated | 2026-08-17 |
| Current accepted product baseline | SPELL v0.7.0, tag `v0.7.0`, tag object `70e4d46a46d158dee3c63ec37a5d1922b3b61668`, release commit `cf18e9d887ba0476cbcc3d8194e321332a3ae864` |
| v0.3.1 status | Documentation set prepared; formal release commit and tag not claimed |
| v0.4 status | Accepted local-only synthetic non-CUI release; Final 74/74 tests and 209/209 assertions passed; no accepted exceptions |
| v0.5 status | Accepted at annotated tag `v0.5.0`; Final 1,096 concrete tests, 1,090 passes, six exact approved environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.6 status | Accepted at annotated tag `v0.6.0`; nine work packages `IMPLEMENTED_AND_QUALIFIED`; Final 1,626 concrete tests, 1,620 passes, six exact SQLite environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.7 status | Accepted at annotated tag `v0.7.0`; nine work packages `IMPLEMENTED_AND_QUALIFIED`; Final 2,041 concrete tests, 2,034 passes, seven exact SQLite environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.8 status | `V08-GATE-0A PASS`; all nine `V08-DATA-001` through `V08-DATA-009` packages are implemented in the worktree and pre-candidate backend/frontend verification passed; source freeze, canonical qualification, Gate 0B, Final, package, release commit, and tag remain pending |
| Next-generation design status | Broader specification `0.1.0-draft.1` remains Draft; organization-only acceptance is outside the local v0.4 gate |
| Runtime, API, schema, frontend, dependency, or driver change | Accepted v0.7 remains unchanged; the v0.8 worktree adds the bounded local data model, migrations, repository/mutation/runtime services, authenticated API, procedure data operations, Data Service frontend, release tooling, and patched PostgreSQL pin without adding a live GCS route |
| Operational authorization | None |
| Update model | Living document; revise at every version gate and release |

## Purpose And Authority

This document is the living, forward-looking roadmap for OpenBEXI SPELL. It
connects the delivered v0.1 through accepted v0.4 foundations to candidate v0.x work,
records dependencies and decision points, and makes deferred scope explicit.

The roadmap is an index and planning aid. It does not authorize implementation,
integration, deployment, or operational use. A candidate release becomes
approved only after its request, scope, exclusions, requirements, acceptance
tests, and entry decision are recorded through the version workflow in
[`PROMPT_Instructions.md`](PROMPT_Instructions.md).

SPELL v0.7.0 is now the accepted product baseline. Its annotated tag object
`70e4d46a46d158dee3c63ec37a5d1922b3b61668` peels to release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864`. Final validation,
supply-chain/SBOM checks, deterministic packaging, release-evidence validation,
and annotated tagging passed with no accepted exceptions. The verified tag
activated the conditional owner acceptance without a post-tag documentation
commit. This acceptance remains limited to `V07-OBS-001` through
`V07-OBS-009` and provides no operational authorization. The subsequent
[`V08-GATE-0A`](SPELL_v0.8_Pre-Implementation.md) authorizes only nine bounded
local synthetic non-CUI data-service work packages and 45 planned proof
identities. The authorized backend and frontend implementation is now present
and has passed pre-candidate working-tree verification. It has not yet been
frozen as a candidate or subjected to canonical candidate qualification, Gate
0B, Final qualification, packaging, release commit, or tag validation. v0.9
remains requested-only.

The owner limited v0.3.1 preparation to this file and
[`VERSION_TIMELINE.md`](VERSION_TIMELINE.md). Consequently, v0.3.1 identifies
this documentation set but is not represented as a formally accepted project
release. A later release commit or tag requires separately authorized updates
to the canonical history, test disposition, and project index.

The project owner subsequently revised v0.4 to a local-only, synthetic non-CUI
simulator engineering gate and approved Candidate A, its exclusions, budgets,
and test plan. The exact instruction and bounded non-claims are recorded in
[`G0_HUMAN_APPROVAL_LEDGER.json`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_HUMAN_APPROVAL_LEDGER.json).
Exact manifest binding and the pinned Python 3.13 Gate 0 qualification passed.
That historical gate authorized bounded Candidate A product edits but did not
itself make a release, operational, deployment, or compliance claim. The later
v0.4.0 release tag is the accepted product result.

On 2026-07-17, all 304 pages in the seven PDFs under
`SPELL-DOCUMENTATION/` were reviewed. The evidence inventory, conformance
policy, documented behavior map, safety deviations, and roadmap consequences
are recorded in
[`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md). That review
rebaselines future versions but does not rewrite accepted release facts or
authorize product implementation.

On 2026-07-18, the reviewed behavior was developed into a candidate
next-generation design repository at
[`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md).
It defines the proposed requirements, architecture decisions, one-satellite
control domain, multi-procedure execution, machine-readable state models, web
operating modes, Git procedure workflow, PostgreSQL data authority, filtered
real-time contracts with authorization-private projections, mission-wide
satellite assignment with a non-rollback generation anchor and legacy adoption,
a sole final Effect Authorization Point, reliability,
deployment, NIST SP 800-171 alignment, operations, verification, and phased
implementation blueprint. The specification is `0.1.0-draft.1`; only its
Candidate A-applicable technical boundaries are v0.4 gate inputs. It is not an
approved product baseline or operational authorization.

For next-generation planning, that repository is the authoritative design
source for implementation scope, requirement IDs, architecture, security,
reliability, and acceptance. Its authority prevents this roadmap from inventing
an alternative design. Its Draft status remains controlling for the broader
next-generation program. The bounded v0.4 Candidate A gate uses the project-
owner decision and its own technical evidence; organization, mission,
assessment, deployment, and authorizing-official approvals are outside that
local gate. No compliance, deployment, or operational connection is asserted.

After the owner requested that development move forward on 2026-07-18,
`NG-PROT-001` and its bounded continuation `NG-PROT-002` were prepared within
the Draft baseline's prototype-planning allowance. They are an isolated RBAC
startup evaluator and authenticated input-adaptation experiment under
`backend/experimental/`. The product
application imports neither module; no API route, product identity contract,
persistence, controller authority, frontend integration, schema migration, or
dependency changed. This activity does not start v0.4 product implementation,
close `NG-WP-00` or `NG-WP-01`, approve `MODE-023`, `MODE-024`, or `MODE-027`,
or change Gate G0.

The subsequent request to implement the next step authorized bounded
`NG-WP-00` readiness work. The Draft documentation now contains controlled
allocation rules, a 366-row per-requirement registry bound to canonical record
digests, stable planned verification/result identifiers, a separate unsigned
human-evidence overlay, a deterministic validator with adversarial unit
coverage, and an approval package for role-based startup, handover, audit,
`DOC-011`, and Phase-entry decisions. Structural validation passes, but G0
remains `BLOCKED`; this does not authorize `NG-WP-01` or any product route.

Earlier 62-row and 257-row compatibility increments were partial technical
checkpoints. They are superseded by the current validated exhaustive catalog
covering all seven authoritative sources, all 304 pages, and all 195 Language
Reference examples. Every catalog row is assigned either to the exact Candidate
A slice or to the approved Deferred/`EXCLUDE` boundary and has a unique planned
test identity. Deferred rows are static source and negative-scope evidence, not
implementation, semantic-oracle, execution-result, operational, or compliance
claims. At that intermediate checkpoint deterministic validation and fresh
independent source review passed while `V04-GATE-0` still awaited exact
manifest binding and pinned Python 3.13 qualification. Those criteria later
passed; the partial checkpoints are not the current gate disposition.

The following records remain authoritative when this roadmap conflicts with a
detailed requirement, test, or release result:

- [`PROMPT_Instructions.md`](PROMPT_Instructions.md) for durable architecture,
  safety, repository, and release rules.
- [`PROMPT_History.md`](PROMPT_History.md) for approved owner requests and
  version decisions.
- [`Test_and_Integration.md`](Test_and_Integration.md) for requirements,
  acceptance gates, executed evidence, and exceptions.
- [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md) for the
  supplied-manual inventory, compatibility policy, and documented behavior map.
- [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md)
  as the authoritative design source for next-generation architecture,
  security, data, web, operations, and verification scope. While it remains
  Draft, it cannot override an approved release record or authorize
  implementation or use.
- Version pre-implementation and release records for the scope and disposition
  of a particular release.
- Versioned source, migrations, API schemas, lock files, and tagged evidence for
  implementation facts.

## Classification Vocabulary

Lifecycle status:

| Status | Meaning |
| --- | --- |
| Delivered | A planning or documentation artifact was completed, but it is not an accepted product release. |
| Accepted | The bounded release passed its recorded gate and has an accepted release record. |
| Prepared | The requested artifact exists in the working tree, but no release commit or tag is claimed. |
| Candidate | A planning direction that has not passed a pre-implementation gate. |
| Deferred | Work intentionally has no assigned release or lacks a prerequisite. |
| Blocked | Work cannot enter implementation until a named missing decision or input is resolved. |

Release type:

| Type | Meaning |
| --- | --- |
| Planning | Architecture, evidence, requirements, or test planning without product implementation. |
| Product | Runtime, API, schema, dependency, deployment, or executable behavior changes. |
| Documentation-only | Project-record changes with no product runtime, API, schema, or dependency change. |

Dates for candidate releases are deliberately omitted. No target date should be
added until scope, staffing, dependencies, and acceptance cost are known.

## Mission And End State

OpenBEXI SPELL is a clean-room modernization of the Satellite Procedure
Execution Language and Library. Its target is a readable, deterministic,
observable, and portable procedure environment with explicit operator control,
recovery, replay, audit evidence, and typed integration boundaries.

The intended migration path advances from a simulator-only control plane to a
typed driver/context foundation, bounded documented language and operator
semantics, simulator service conformance, a separate development environment,
and only then read-only legacy observation, controlled non-operational
integration, incremental adapter migration, and separately authorized pilot
readiness. A software version alone can never grant operational authorization.

## Non-Negotiable Guardrails

Every version must preserve these constraints unless a later approved record
strengthens them:

- Default to deterministic simulators and non-operational environments.
- Never connect to a live GCS, spacecraft, or mission network without an
  explicit approved task, environment, procedure, and test plan.
- Keep browser, control plane, worker, persistence, and integration adapters in
  separate trust and ownership boundaries.
- Keep procedure source non-executing: parse it to bounded, allowlisted,
  versioned data-only IR.
- Persist authoritative commands, events, prompts, checkpoints, effects, and
  audit evidence before projecting them to clients.
- Never automatically repeat an externally effective command with an uncertain
  outcome; reconciliation is mandatory.
- Permit at most one effect-enabled path per satellite across active, draining,
  restored, legacy, and replacement systems. Only the final Effect Authorization
  Point may hold an effect credential or egress route.
- Treat assignment generations as externally anchored non-rollback identities;
  apparent site loss or restored local state never substitutes for independent
  old-path fence evidence.
- Keep legacy archives read-only, excluded from product builds, and separate
  from the Apache-2.0 implementation.
- Trace every claimed documented construct, function, modifier, state, control,
  and data type to an explicit compatibility disposition and test.
- Preserve an accessible 2D operator surface. Java and Eclipse components are
  not reintroduced.
- Treat performance evidence as version-specific engineering measurements, not
  operational service-level objectives.
- Require complete SQLite/PostgreSQL, security, recovery, browser,
  accessibility, performance, supply-chain, and reproducibility gates for each
  product release.

## Release Outlook

v0.2, v0.3, v0.4, v0.5, v0.6, and v0.7 are accepted product releases. v0.1 is a delivered planning
baseline that was later approved only for the bounded v0.2 entry scope. v0.3.1
is the prepared documentation set described above. Every later version number
is a planning label until its applicable gate is approved. Annotated tag
`v0.7.0` fixes the current accepted baseline. Final qualification, four SBOMs,
supply-chain validation, deterministic packaging, release-evidence validation,
and strict annotated-tag validation passed. v0.8 has passed its bounded Gate
0A for nine exact work packages and 45 planned proof identities. Those packages
are implemented in the worktree and pre-candidate backend/frontend verification
passed; the immutable candidate and canonical qualification/release evidence
chain is pending. v0.9 is requested after v0.8 and has no completed gate or
implementation.

| Version | Theme | Type | Status | Intended outcome | Required entry gate |
| --- | --- | --- | --- | --- | --- |
| v0.1 | Pre-Implementation Baseline | Planning | Delivered | Establish clean-room evidence, requirements, target architecture, safety model, test strategy, and phased migration plan; later conditionally approved for the bounded v0.2 slice. | Completed documentation verification and bounded v0.2 owner approval. |
| v0.2 | Simulator Vertical Slice | Product | Accepted | Prove one end-to-end local simulator workflow across parser, worker, durable control, recovery, WebSocket projection, 2D console, and as-run reporting. | Completed v0.2 plan and simulator-only approval. |
| v0.3 | Simulator Hardening and Language Foundation | Product | Accepted | Close v0.2 identity, isolation, migration, dependency, qualification, and language-foundation gaps. | Completed v0.3 plan, full evidence, commit `7bccbb4`, and tag `v0.3.0`. |
| v0.3.1 | Roadmap and Timeline Records | Documentation-only | Prepared | Establish `PROJECT_ROADMAP.md` and `VERSION_TIMELINE.md` as maintained project records without changing product behavior. | Owner request limited to these two documents; formal release workflow remains separate. |
| NG spec 0.1 | Next-Generation Design Specification | Documentation-only | Draft prepared | Convert the complete manual review and modernization objectives into a controlled, implementation-ready web/server/data/security/operations blueprint while preserving the two core 2.4.4 authorities. This specification version is independent of product versions. | Multidisciplinary approval, closed phase-entry decisions, feature-level compatibility rows, verified traceability, and a signed documentation baseline. |
| v0.4 | Typed Simulator Driver and Context Foundation | Product | Accepted | Delivered the typed, authenticated, out-of-process simulator lifecycle boundary without TM/TC service. | Final 74/74 tests and 209/209 assertions passed; accepted release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` and annotated tag `v0.4.0`. |
| v0.5 | Core Language and Deterministic Runtime | Product | Accepted at annotated tag `v0.5.0` for `V05-IR-001` only | Harden validation of existing IR 0.3; the broader language/runtime outcome remains Candidate scope outside Gates 0A/0B. | Final 1,096-test qualification, four SBOMs, supply-chain audit, deterministic package, release commit `e7b6bb9`, and annotated tag `v0.5.0` passed. |
| v0.6 | Durable Operator Workspace and Procedure Composition | Product | Accepted at annotated tag `v0.6.0`; no accepted exceptions | Add documented context/catalog/instance workflows, control leases and states, full durable prompts, monitoring, source/log/debug views, relative/absolute scheduling, safe user actions, and `StartProc`. | Final nine-suite qualification, four SBOMs, supply-chain audit, deterministic archive SHA-256 `b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c`, release commit `05ec783a6e54a76e0548bdd536c18538f6bff51b`, and annotated tag `v0.6.0` passed. |
| v0.7 | Simulator Read-Only Observation and Condition Engine | Product | Accepted at annotated tag `v0.7.0`; no accepted exceptions | Implement driver time, `GetTM`, `Verify`, telemetry `WaitFor`/scheduling, raw/engineering items, resource/lookup reads, limits/alarm state, and cursor streams against a deterministic simulator. | Final nine-suite qualification, four SBOMs, supply-chain audit, deterministic archive SHA-256 `90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2`, release commit `cf18e9d887ba0476cbcc3d8194e321332a3ae864`, and annotated tag `v0.7.0` passed. |
| v0.8 | Data and Local Service Compatibility | Product | Candidate preparation; nine authorized packages implemented and pre-candidate verified; freeze and canonical qualification pending | Add documented dictionaries, databases, shared data, virtual-root files, immutable dependencies, and durable local state. | Accepted v0.7.0 baseline plus approved typed storage, URI, transaction, quota, recovery, migration, and security contracts; Gate 0B, Final, package, release commit, and tag remain pending. |
| v0.9 | SPELL Development Environment | Product | Requested follow-on after v0.8; Gate 0A and implementation pending | Build the separate web project/editor/dictionary/catalog/Problems/semantic-check/collaboration workspace and immutable simulator promotion flow. | Stable compatibility grammar/catalog schemas, approved non-executing language-service design, and authoring acceptance plan. |
| v0.10 | Simulator Auxiliary Service Mutations | Product | Candidate | Add separately gated simulator event, ground-parameter, resource, limit/alarm, display-intent, and optional ranging tranches. | Read-only simulator conformance plus a capability-specific effect, authorization, certainty, rollback, and audit gate. |
| v0.11 | Simulator Telecommand Semantics | Product | Candidate | Implement `BuildTC` and `Send` with typed expansion, sequences/groups/blocks, critical preflight, time/load intent, per-element stages, certainty, and reconciliation. | Accepted simulator services, explicit no-resend/confirmation model, command corpus, and exhaustive fault tests. |
| v0.12 | Read-Only Legacy Observation | Product | Candidate | Compare an isolated legacy test environment to the proven typed simulator APIs with structurally zero command authority. | Accepted read-only simulator contracts, version-specific evidence, golden traces, and a read-only enforcement plan. |
| v0.13 | Controlled Non-Operational Procedure Control | Product | Candidate | Add audited legacy procedure control in an explicitly approved non-operational environment; no spacecraft command authority. | Accepted v0.12 observation and dedicated control-lease, failure, rollback, and environment safety plan. |
| v0.14 | Bounded Adapter Migration | Product | Candidate | Migrate one specifically approved adapter capability per tranche with conformance, certainty, security, load, and rollback evidence. | Accepted capability contract and separate environment/effect authorization for each tranche. |
| v0.15+ | Parallel Pilot Readiness | Product | Candidate | Progress from read-only shadow to supervised non-commanding pilots; consider commanding only through separate authorization with rapid rollback. | Prior phase acceptance, operational evidence, governance, workload budgets, and explicit pilot authorization. |

## Delivered Foundation

### v0.1 - Pre-Implementation Baseline

**Outcome:** documentation-only planning contract delivered on 2026-07-12 and
later approved only for the bounded v0.2 entry scope.

Delivered foundations:

- Inventoried supplied legacy Core, COTS, GUI, manuals, interfaces, licensing,
  capabilities, and evidence gaps.
- Defined the target control plane, worker, driver host, driver gateway,
  persistence, telemetry projection, compatibility adapter, and web-console
  responsibilities.
- Defined state, command, prompt, telemetry, telecommand, checkpoint, recovery,
  as-run, security, and migration models.
- Established stable requirements, risk register, test families, phased
  delivery, rollback direction, and explicit decisions required before product
  work.
- Confirmed that the Development Environment manual was absent from the
  originally supplied v0.1 evidence and that the supplied legacy tests were
  insufficient as a rewrite oracle. The manual was supplied separately and
  reviewed on 2026-07-17; that later evidence does not rewrite the v0.1 fact.

Primary record:
[`SPELL_v0.1_Pre-Implementation.md`](SPELL_v0.1_Pre-Implementation.md).

### v0.2 - Simulator Vertical Slice

**Outcome:** first executable release accepted for local simulator development
on 2026-07-12, with documented exceptions.

Delivered foundations:

- FastAPI control plane, isolated procedure worker, SQL persistence boundary,
  REST mutations, ordered WebSocket replay, and React/TypeScript 2D console.
- Restricted non-executing procedure subset for logs, simulated telemetry,
  waits, and durable prompts.
- Idempotent revision-guarded control, atomic checkpoints, crash recovery,
  prompt races, abort, reconnect/resync, and as-run reconstruction.
- SQLite and PostgreSQL verification, desktop/mobile browser workflows,
  accessibility checks, SBOMs, and provenance review.

The accepted exceptions included provisional authentication, incomplete
outbound isolation, unhashed Python artifacts, security residuals, and
unexecuted performance/soak targets. v0.3 addressed these within the bounded
simulator architecture.

Primary record: [`SPELL_v0.2_Release.md`](SPELL_v0.2_Release.md).

### v0.3 - Simulator Hardening and Language Foundation

**Outcome:** accepted local simulator engineering release on 2026-07-16.

Delivered foundations:

- Ordered SQLite/PostgreSQL migrations and durable variable/control recovery.
- Signed short-lived JWT identity, server-enforced roles, loopback-only ingress,
  and internal-only backend/database networking.
- Typed variables, safe expressions, conditions, bounded loops, bounded local
  calls, exact source identity, structured diagnostics, and bounded data IR.
- Transient source validation, responsive operator workflows, authenticated
  WebSocket expiry, and complete command settlement across failure paths.
- Hash-locked dependencies, audits, distinct image SBOMs, fingerprint-bound
  performance evidence, and reproducible packaging.

Primary records:
[`SPELL_v0.3_Pre-Implementation.md`](SPELL_v0.3_Pre-Implementation.md) and
[`SPELL_v0.3_Release.md`](SPELL_v0.3_Release.md).

### v0.3.1 - Roadmap and Timeline Records

**Outcome:** documentation set prepared on 2026-07-17; formal release not
claimed.

Scope is limited to:

- This living project roadmap.
- [`VERSION_TIMELINE.md`](VERSION_TIMELINE.md), including evidence-qualified
  durations for v0.1 through v0.3.

This patch does not change the accepted v0.3.0 product, runtime version, API,
database schema, dependencies, qualification evidence, release archive, or
operational authorization. A v0.3.1 tag and release commit are not claimed by
this document unless they are created separately.

## v0.4 Scope Decision

JC Arcaz, the project owner, approved Candidate A as the bounded local-only,
synthetic non-CUI v0.4 product scope together with its exclusions, engineering
budgets, and test plan. That owner decision satisfies the only human-approval
role in this local gate. At the gate revision, implementation remained blocked until the
source-grounded compatibility review, deterministic Gate 0 validation, exact
manifest binding, dependency and generator locks, and intended-change-set
checks passed. Those criteria and Gates 1-5 later passed, and v0.4.0 is now
accepted. Broader next-generation organization, mission, protected-data,
deployment, and compliance decisions remain outside this gate and are not
claims made by the owner decision.

Combining Candidate A with Candidate B would materially increase migration,
recovery, UI, and verification risk. The draft therefore defers Candidate B
rather than silently combining the two.

The `NG-WP-00` through `NG-WP-08` packages below are also cross-version
planning units. Their addition to this roadmap does not place RBAC startup, web
or backend modernization, controller handover, the GUI User Manual, NIST evidence,
HA/DR, or integrated acceptance into v0.4 without a revised and approved v0.4
pre-implementation gate.

### Candidate A - Typed Simulator Driver and Context Foundation

**Status:** Accepted at annotated tag `v0.4.0`; Final 74/74 tests and 209/209
assertions passed with no accepted exceptions.

This direction is explicitly carried forward by the accepted v0.3 planning
record and is the architectural prerequisite for later documented simulator
language, operator, and driver-service conformance.

Intended deliverables:

- A versioned protobuf/gRPC lifecycle contract with deterministic generated
  code, bounded typed messages, explicit compatibility rules, and stable
  server-profile, driver-host-generation, context-generation, execution,
  execution-attachment-generation, driver-binding, and operation identity.
- One bundled deterministic simulator driver in a separate non-root, read-only
  host with no published port, project-database access, public route, mission
  route, or arbitrary endpoint configuration.
- Separate host, context-binding, execution-attachment, capability setup/cleanup,
  and operation lifecycles with typed handshake, health, cancellation, and
  reconciliation behavior only.
- Typed host-profile, context-binding, and execution-attachment configuration
  with explicit precedence, schema versions, separate immutable
  digests/generations, out-of-band secret references, and named host/per-context
  capacity.
- Mutual service authentication, granular service/method/modifier/mutability/
  stream capabilities, least privilege, and a supervisor-owned gateway. The
  browser and procedure worker receive no usable driver identity.
- Stable operation identity, structured errors, deadlines, generation fencing,
  immutable attempt history, lexicographic attempt/stage progress, retained
  certainty evidence, durable reconciliation, and no automatic resend of
  `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` work.
- A private bounded simulator-host idempotency journal for restart deduplication
  without project-database access; full/corrupt storage fails closed, IDs are
  generation-bound and never reused, and the control plane remains canonical.
- Persist-before-publish driver audit state, authenticated read-only API/2D
  console projection, simulator conformance fixtures, and fault injection at
  every lifecycle boundary.
- Ordered SQLite/PostgreSQL migrations and version-isolated qualification,
  SBOM, audit, and reproducible-package evidence.
- An approved next-generation design and documentation-conformance baseline
  that inventories every documented
  language construct/public name/type/outcome, server configuration, driver
  contract/status, operator/development workflow/view, build/deployment
  concept, example, ambiguity, safe deviation, target phase, and test without
  implementing those services.

Minimum exit evidence:

- Contract compatibility, deterministic generation, malformed/oversized input,
  capability mismatch, and explicit unsupported-service tests.
- Exact nine-RPC descriptor/handshake allowlisting, absence of all future
  service capabilities/payloads, and proof that v0.3 `Telemetry` produces zero
  execution-correlated driver activity against a baselined active host.
- Context/execution binding, configuration precedence/digest, setup/cleanup
  order, capacity exhaustion, and host-versus-procedure-state separation tests.
- Mutual-identity, rotation, secret-canary, topology, network-matrix, and
  direct-browser/worker denial tests under the approved worker-isolation model.
- Driver/API/database crash and partition tests across acceptance, dispatch,
  simulator effect, persistence, publication, cancellation, late response,
  restart, and shutdown boundaries.
- Proof that each operation/attempt identity produces one durable disposition,
  that `EFFECT_POSSIBLE` and `EFFECT_UNKNOWN` are visible and enter
  reconciliation, and that a new attempt is never authorized without
  authoritative `NO_EFFECT` evidence.
- Fresh/populated/repeat/failure/rollback migration tests on SQLite and
  PostgreSQL, plus complete v0.3 regression, real-browser, accessibility,
  performance, audit, distinct-SBOM, install/disable/upgrade/rollback/uninstall,
  declared-platform, and reproducible-package gates.

Explicit exclusions:

- All telemetry and telecommand driver services, high-rate subscriptions, and
  routing of existing `Telemetry` or other procedure steps through the host.
- New procedure syntax or SDK calls, live/legacy GCS access, spacecraft or
  mission connectivity, arbitrary endpoints, externally effective operations,
  or operational deployment claims.

Entry-gate state:

- Satisfied: project-owner approval of Candidate A as the sole v0.4 scope, its
  exclusions, local budgets, and test plan.
- Satisfied: bounded non-executing IR and strict mTLS credential separation,
  with the shared local development route treated as an approved synthetic-
  scope residual risk and authentication required to fail closed.
- Outside this gate: organization-only next-generation decisions, proposed ADR
  acceptance, mission/protected-data/deployment decisions, and role-based
  sign-offs other than the project owner.
- Satisfied: exhaustive source-grounded compatibility and errata validation,
  including independent review and exact count/digest reconciliation.
- Satisfied: exact manifest binding and pinned Python 3.13 Gate 0 qualification.
- Satisfied at release: dependency/generator locks, the intended product change
  set, every approved Gate 1-5 result, release commit
  `4546d313a2d8f50504b2bc602d56b3b459ca7597`, and annotated tag `v0.4.0`.

### Candidate B - Durable Operator Decisions

**Status:** Deferred from v0.4 and assigned to the broader documented prompt
and operator-control scope proposed for v0.6.

This candidate is motivated by complex prompt-driven procedures: v0.3 prompts
block and audit a response, but the selected value cannot become typed procedure
state or drive later deterministic control flow.

Intended deliverables:

- Statically typed prompt-result binding for bounded choice and confirmation
  prompts while preserving existing unbound prompt behavior.
- Atomic persistence of prompt outcome, actor, typed value, variable
  checkpoint, and selected branch.
- Deterministic recovery and replay across competing responses, disconnect,
  process loss, and restart.
- Only a successfully answered bounded choice or confirmation becomes procedure
  data. Non-answer outcomes remain execution-control outcomes and are never
  assigned to a procedure variable in this candidate.
- Complete as-run reconstruction of prompt, response, variable, source line,
  and chosen branch.

Minimum exit evidence:

- Parser, IR-version, type, bound, and backward-compatibility tests.
- Crash and race tests at reservation, response, checkpoint, branch, and
  publication boundaries proving one durable outcome.
- Authorization, idempotency, revision, reconnect, recovery, and report tests.
- Accessible desktop/mobile real-backend execution of a prompt-rich procedure.
- Complete v0.3 regression, migration, browser, audit, and package gates.

Explicit exclusions:

- Arbitrary free-form data types, secrets/password prompts, persistent
  authoring, new timeout/cancel/controller-loss policies, long-procedure flow
  redesign, live integrations, externally effective commands, and operational
  claims unless separately approved.

## Next-Generation Governed Work Packages

The following packages translate the new implementation priorities into
measurable planning units. They span the phases in
[`quality/IMPLEMENTATION_ROADMAP.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/IMPLEMENTATION_ROADMAP.md)
and are not silently added to candidate v0.4. Each remains Candidate or Blocked
until its central requirements, owner, dependencies, exclusions, tests, and
entry gate are approved. A package result is valid only for the exact artifact,
configuration, environment, and evidence digest recorded at its gate.

### Experimental Pre-Gate Activity

| ID | Status | Bounded result | Explicit non-result |
| --- | --- | --- | --- |
| `NG-PROT-001` | Prepared in the working tree; not a product work package or release | Pure startup-policy evaluation for the three primary roles, safe multi-role selection, principal-scoped capability narrowing, restrictive policy, bounded decision/session/reauthentication expiry, deterministic audit-event candidates, and fail-closed invalid input; 63 focused Python 3.13 tests and the complete current regression passed on 2026-07-18 | No runtime authority, lease, fence, API/frontend/auth integration, durable audit, NIST claim, `MODE` acceptance, `NG-WP` completion, G0 approval, deployment approval, or operational authorization |
| `NG-PROT-002` | Prepared in the working tree; bounded continuation only | Authenticates the unchanged accepted v0.3 local JWT shape inside the experimental boundary; provisionally maps `viewer` to Monitoring and `operator` to Controller, denies `admin`, has no Developer mapping, consumes only server-owned policy/scope fixtures, preserves exact authorization time, derives a role-sensitive purpose-separated session surrogate, and records mapping provenance in a non-durable audit candidate; 96 combined experimental Python 3.13 tests, 209 complete backend tests, and 13 unchanged frontend tests passed on 2026-07-18; one PostgreSQL-only test skipped and the frontend production build succeeded | Not an authoritative identity/policy adapter or signed session bootstrap; no product route, token-policy/schema change, runtime or repository authority, lease, fence, durable audit, cache contract, NIST claim, `MODE` acceptance, `SEC` acceptance, `NG-WP` completion, G0 approval, deployment approval, or operational authorization; pre-evaluation authentication failures still lack an audit candidate |

The prototypes may inform later broader work, but they shall not be wired into
the v0.4 product or expanded into another integration prototype. Local Gate G0
passes; the mandatory next step is implementation and qualification of the
exact Candidate A boundary. Broader identity, handover, mission, compliance,
deployment, and organization-approval work remains outside this v0.4 gate.

### NG-WP-00 Gate Readiness

| Evidence area | Current result | Remaining gate condition |
| --- | --- | --- |
| Central requirement register | 366 unique, contiguous broader-spec IDs remain traceable | Informational for v0.4; per-row organization approval is not required by the local gate |
| Per-ID implementation allocation | 366 rows remain digest-bound and are generated as `OUTSIDE_LOCAL_V04_GATE` | No local blocker; the rows remain available for later broader work |
| Documentation/source checks | Seven unique supplied-source hashes, 304-page reconciliation, and exhaustive-catalog review pass | Retain deterministic validation and exact source bindings |
| Phase-entry decisions | Ten organization/mission/deployment decisions remain in the broader register | Outside the local synthetic non-CUI v0.4 gate |
| Accountability | Broader-spec role codes and composite owner rows remain recorded | Outside the local gate; JC Arcaz is the only required approval role |
| Architecture and compatibility | Exhaustive seven-source disposition catalog covers all 195 Language Reference examples; review and exact count/digest reconciliation pass for 1,682 rows | Owner-record manifest binding passes |
| G0 disposition | Owner scope decision, compatibility review, manifest, and Python 3.13 qualification pass | `PASS`; authorizes bounded product engineering only, with no release, operational, deployment, or compliance claim |

The controlling evidence is
[`quality/G0_READINESS_PACKAGE.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_READINESS_PACKAGE.md)
and its generated
[`G0_READINESS_REPORT.json`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/G0_READINESS_REPORT.json).
The recorded project-owner decision, passing technical validation, and exact
deterministic file manifest establish the local `PASS` result. The manifest is
integrity evidence, not a signature.

| ID | Candidate outcome | Depends on | Measurable gate |
| --- | --- | --- | --- |
| `NG-WP-00` | Approve the next-generation specification delta and allocate every central requirement family to implementation and evidence. | Named approvers, closed entry decisions, compatibility rows, and complete allocation/approval of `MODE-023..MODE-027` and registered `DOC-011` | Record exact per-family counts; map 100 percent of central IDs to owner, design, package, phase, test/result target, and gate; report zero orphan, duplicate, missing, or unapproved normative rows; sign G0. |
| `NG-WP-01` | Start each authenticated web session from server-evaluated RBAC and attributes without treating role, selected mode, or controller lease as the same authority. | `NG-WP-00`, `MODE-023`, `MODE-024`, `MODE-027`, IdP/session policy, approved role/attribute/domain/environment/mode matrix | Test every approved single-role and multi-role matrix row and negative row; prove the baseline single-role mapping opens Controller in Execution, Monitoring in Monitoring, and Developer in Edit, while Controller without a valid lease remains visibly non-authorizing. Prove browser-inferred or client-selected roles cannot elevate access, excluded capabilities do not merge, revocation is effective, no startup response grants a lease, and every allow/deny/mode decision is audited. |
| `NG-WP-02` | Modernize the Python backend around authoritative PostgreSQL transactions, typed internal services, REST mutations, WebSocket projections, migrations, audit, and isolated execution/driver boundaries. | `NG-WP-00`, state/schema/API decisions, identity/secrets, migration and rollback design | Contract, migration, contention, restart, authorization, idempotency, durability, audit-correlation, isolation, and rollback suites pass; browsers/workers have no direct database, driver, or GCS route. |
| `NG-WP-03` | Modernize the responsive web UI for Execution, Monitoring, Edit, and Replay workflows, real-time state, navigation, accessibility, and Git promotion. | `NG-WP-01`, `NG-WP-02`, approved workflows, API/event schemas, browser/workload profile | Supported viewport/browser, WCAG 2.2 AA, role/mode negative, stale/gap/reconnect, load, Git promotion/rollback, and representative mission-operator acceptance pass. |
| `NG-WP-04` | Implement normal controller handover as a secure two-party transaction with complete audit; keep forced takeover as a distinct break-glass path. | `NG-WP-01`, `NG-WP-02`, approved `MODE-025..MODE-027`, lease/fence state model, client proof, step-up policy, durable audit | Two distinct authenticated principals complete current-holder approval and subsequent request-bound acknowledgement by the named requester; one transaction terminalizes the old grant, creates the new active lease and higher fence, changes authoritative modes, preserves unresolved effects, and rejects stale/replayed decisions. Model, race, failover, cancellation, and revocation tests pass, and every attempt has a correlated tamper-evident audit chain for both actors, each decision, and the old/new authority. |
| `NG-WP-05` | Finalize and accept the existing Draft GUI User Manual source and accessible PDF for the accepted web application. | Produced `DOC-011` Draft artifacts, stable accepted `NG-WP-03` and `NG-WP-04` workflows, exact build identity, and approved audience/classification/publication path | The controlled source and `SPELL_GUI_USER_MANUAL.pdf` bind to the exact accepted product/specification versions and digests. A coverage matrix documents 100 percent of approved critical startup, mode, handover, execution, monitoring, Edit/Git, prompt, alarm, degraded/recovery, and support workflows. Link/metadata/accessibility checks, rendered-page inspection, secret/CUI scan, screenshot-to-build verification, digesting, and representative operator sign-off pass with no critical documentation defect. |
| `NG-WP-06` | Build deployment-specific NIST SP 800-171 Rev. 3 implementation and SP 800-171A Rev. 3 assessment evidence. | Governing applicability and operated-on-behalf decisions, CUI boundary/flows, SSP, ODPs, responsibility/evidence owners, assessment plan, exact deployed baseline | All 17 families, every pinned SP 800-171 requirement, and every applicable 171A determination statement have authority, implementation, owner, method, evidence digest, result, and finding/POA&M/risk disposition; zero unresolved applicability or ODP row remains for the asserted scope. SP 800-172 Rev. 3 remains conditional on agency selection, and evidence alone makes no compliance claim. |
| `NG-WP-07` | Qualify reliability, recovery, fault isolation, graceful degradation, HA/DR where approved, capacity protection, and operational runbooks. | `NG-WP-02`, approved workload/topology, `REL-PAR-*`, RPO/RTO, capacity and degradation decisions | The approved process/host/network/identity/clock/storage/database/site/upgrade/restore failure matrix passes; safety invariants hold; measured service and recovery results meet the approved profile; no mandatory reliability finding remains unresolved. |
| `NG-WP-08` | Run integrated testing, V&V, documentation acceptance, and the evidence-bound release decision. | All in-scope package results, approved fixtures/environments/workload/evidence schema, named acceptance roles | Bidirectional traceability covers 100 percent of approved requirements through design, implementation, test, result, finding, and approval; required unit, contract, integration, model/property, fault, security, browser, accessibility, performance, recovery, manual, and operator suites pass; G0 through G9 and every required sign-off record pass, block, or an authorized time-bounded exception. |

`NG-WP-00` is the first dependency for the broader next-generation work-package
sequence. The Draft central register states the role-based startup and two-party
request/approval/acknowledgement handover contract in `MODE-023..MODE-027`; its
366 rows retain their broader approval requirements before `NG-WP-01` or
`NG-WP-04` can enter implementation. Those requirements do not block the bounded
local Candidate A gate. The candidate compatibility catalog now inventories all
seven supplied sources, all 304 pages, all 195 Language Reference examples, and
assigns every artifact to v0.4 or Deferred/`EXCLUDE`. It remains a Gate 0
technical input until deterministic reconciliation, independent source review,
and exact digest binding pass; Deferred rows are not implementation, executable-
fixture, semantic-conformance, operational, or compliance evidence. `DOC-011`
is registered and allocated, and its Draft
deliverable is produced as controlled `web/SPELL_GUI_USER_MANUAL.md`, a tagged
`web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf`, four concept figures, print CSS, and
reproducible renderer tools. This resolves the missing atomic obligation and
Draft-deliverable gap.

The Draft manual has no accepted product-build binding or representative
operator acceptance. `NG-WP-05` therefore remains a later gate for reconciling
the manual with accepted `NG-WP-03` and `NG-WP-04` behavior, binding it to the
exact candidate build and digests, completing publication checks, and obtaining
the required operator and document approvals.

Package ordering is dependency-driven: `NG-WP-01` and `NG-WP-02` follow G0;
the web UI and handover follow the accepted authorization/backend contracts;
the final manual follows accepted UI behavior; NIST and reliability evidence
accumulate across increments; `NG-WP-08` closes only after every in-scope
package and requirement-family row has an evidence disposition.

## Proposed Post-v0.4 Sequence

The complete manual review changed the order: documented simulator behavior is
implemented and proven before any legacy connection. Version numbers remain
candidate labels until each pre-implementation gate is approved.

### v0.5 - Core Language And Deterministic Runtime

Goal: establish the documented source and execution vocabulary on the bounded
v0.3 IR without unrestricted Python.

#### Current Gates 0A And 0B

`V05-GATE-0A PASS` authorizes only `V05-IR-001`, a strict independent
validator/canonicalizer for the existing IR 0.3 contract plus parser
postvalidation, supervisor persisted-IR preflight before generation or process
creation, worker preflight before `worker.started` or effect, persisted-byte
compatibility without migration, and six focused test identities. The gate is
bound to annotated tag `v0.4.0` and release commit
`4546d313a2d8f50504b2bc602d56b3b459ca7597`.

This authorization adds no language construct, IR version, API, schema,
frontend, dependency, driver, source-to-IR reparse/integrity feature, or
operational scope. Gate 0A itself did not claim implementation. The authorized
work subsequently produced candidate commit
`aefa658ce01d49a7879d0471b50425ac3bcf9e2d`. Gate 0B records the candidate and
all six required identities as qualified and authorizes release closeout for
that work package only. The canonical work-package validator passes candidate
`aefa658` against qualification correction/source `ef26e53`, evidence SHA-256
`86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`, four
suites, six identities, and 949 concrete tests. The `ef26e53` delta changes
only Docker inspection test timeout metadata. Product metadata is now `0.5.0`,
while procedure IR 0.3, API v1, report schema 0.3, and the unchanged driver
implementation identity `0.4.0` remain stable.

Gate 0B was not by itself final release acceptance. The later supply-chain
result, four SBOMs, deterministic package and sidecar, Final validation,
release commit, and annotated tag passed, so `v0.5.0` is now accepted. The
remaining bullets in this section are still candidate release properties
beyond Gates 0A/0B and require a later entry decision.

Candidate release properties beyond Gates 0A/0B:

- Declare a safe Python 3 compatibility profile for expressions, collections,
  conditions, bounded loops/functions, and stable source-line diagnostics.
- Add typed `TIME`/`NOW` constructs, deterministic clocks, common modifier
  configuration, and distinct failure/false/operator/control outcomes.
- Add `Display`, `Notify`, `Step`, `DisplayStep`, `Pause`, `Abort`, `Finish`,
  safe scope-resolved `Goto`, `DataContainer`, `Var`, `ARGS`, `IVARS`, and
  `PROC` compatibility.
- Map documented procedure states to explicit durable modern states; do not
  confuse them with driver-host health.
- Preserve original failure/false evidence when compatibility `SKIP` changes
  control flow; never invent external success, automatically `RESEND` after a
  possible effect, or suppress canonical audit because `Notify=False` hides
  optional presentation.

Exit gate: the claimed construct/function/modifier rows pass parser, IR,
checkpoint, restart, source-identity, errata, and golden-trace tests.

### v0.6 - Durable Operator Workspace And Procedure Composition

Goal: preserve the documented context, catalog, multi-instance, control,
prompt, monitoring, scheduling, source, log, and subprocedure workflows in the
simulator-only 2D workspace.

Current disposition: the owner explicitly approved the exact bounded scope in
[`SPELL_v0.6_Pre-Implementation.md`](SPELL_v0.6_Pre-Implementation.md).
`V06-GATE-0A PASS` authorized the following work packages. Candidate commit
`0ea26105e72d7830de4a265989ed7d9074ffbe09` and canonical evidence SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`
now bind ten passing suites and all 45 required identities. `V06-GATE-0B PASS`
records all nine work packages as `IMPLEMENTED_AND_QUALIFIED` and authorizes
release closeout. Final qualification, four v0.6 SBOMs, supply-chain evidence,
the deterministic package and committed sidecar, and release-evidence
validation passed. Annotated tag `v0.6.0` now fixes release commit
`05ec783a6e54a76e0548bdd536c18538f6bff51b` as the accepted v0.6.0 release
with no accepted exceptions.

| Planned identity | Bounded requirement and acceptance focus |
| --- | --- |
| `V06-OP-001` | Context selection/attachment, immutable catalog resolution, procedure properties/history, stable multi-instance identity, and Master view |
| `V06-OP-002` | `C/M/B` modes, read-only monitoring, durable control leases, fencing, loss behavior, and authorized reacquisition |
| `V06-OP-003` | Approved state/command/safe-point matrix for run, step, step-over, pause, skip, goto, reload, background, stop, abort, recover, and deliberate kill rejection |
| `V06-OP-004` | Typed durable `Prompt` family, validation/defaults/warnings, commit/reset/abort, setting scope, one outcome, and controller-loss recovery |
| `V06-OP-005` | Durable relative and absolute schedules with validation, cancellation, restart recovery, and exactly one start disposition |
| `V06-OP-006` | Source/text/as-run/support-log views, outline/search/navigation, breakpoints/run-to-line, typed inspection, safe-state audited edits, and bounded non-evaluating console |
| `V06-OP-007` | Durable named user actions limited to allowlisted safe-point behavior, with authorization, idempotency, and audit |
| `V06-OP-008` | Immutable `StartProc` library resolution and durable parent-child identity, depth/cycle limits, crash handling, and restart recovery |
| `V06-OP-009` | Cross-feature desktop/mobile workflows, competing control, prompt/schedule races, disconnect/restart, recovery, certainty preservation, and arbitrary-code-execution rejection |

Required properties:

- Context selection/attachment, procedure catalog/properties/history, stable
  instance identity, Master view, `C/M/B` ownership, and strictly read-only
  monitor mode.
- Approved state/command matrix for run, step, step-over, pause, skip, goto,
  reload, abort, recover, background, stop, and any deliberately rejected kill.
- Full documented `Prompt` type family with validation, defaults, warning
  timers, commit/reset/abort, context-versus-execution settings, one durable
  outcome, controller-loss pause, and lease reacquisition.
- Relative/absolute scheduling; source/text/as-run/support-log views; outline,
  search, and nested procedure navigation.
- Breakpoints, run-to-line, typed variable/`ARGS`/`IVARS`/shared-data
  inspection, safe-state-limited audited edits, and a bounded inspection
  console; expression/function evaluation and arbitrary procedure-scope shell
  execution remain forbidden.
- Durable named user actions that invoke only allowlisted safe-point behavior,
  never arbitrary asynchronous Python.
- Immutable procedure-library resolution and durable `StartProc` parent-child
  state with depth, cycle, crash, and restart rules.

Exit gate: desktop/mobile operator workflows, competing control, prompt races,
disconnect/restart, scheduling, inspection/edit safety, user actions, and
parent-child recovery match the approved manual behavior matrix without
arbitrary code execution. `SKIP` and any hard termination retain original
failure/effect certainty; no kill action implies a clean external state.

### v0.7 - Simulator Read-Only Observation And Condition Engine

Goal: implement the documented read-only TM and driver-time contract against
the bundled deterministic simulator.

Current disposition: [`V07-GATE-0A PASS`](SPELL_v0.7_Pre-Implementation.md)
authorizes implementation of exactly `V07-OBS-001` through `V07-OBS-009` and
their 45 planned proof identities. The manifest and six planning matrices under
`contracts/v07` are hash-bound authorization inputs. Candidate
`82b497227aff097db9d4c3ff56adf56d76d892ca` implements those nine packages,
including the additive read-only driver service, durable observation and
condition state, procedure broker, APIs, frontend, and qualification tooling.
Canonical evidence SHA-256
`04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20`
passes ten suites, all 45 mapped identities, and 2,070 tests. The aggregate is
2,051 passes, 19 explicit suite-level platform skips, 36 subtests, and zero
failures or errors; mapped identity skips are zero. All nine packages are
`IMPLEMENTED_AND_QUALIFIED`, and `V07-GATE-0B PASS` authorized release
closeout. Final qualification then passed nine suite captures, 2,041 concrete
tests, 2,034 passes, seven exact SQLite environment skips, 36 subtests, and
zero failures or errors. Four SBOMs, supply-chain validation, deterministic
packaging, and release-evidence validation passed. Annotated tag `v0.7.0`,
object `70e4d46a46d158dee3c63ec37a5d1922b3b61668`, fixes accepted release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864` with no accepted exceptions and no
deployment, operational-use, or compliance authority.

| Planned identity | Bounded requirement and acceptance focus |
| --- | --- |
| `V07-OBS-001` | Typed deterministic simulator driver time with source, provenance, uncertainty, skew, and explicit host fallback |
| `V07-OBS-002` | Typed `GetTM` current/next samples with atomic raw/engineering values, metadata, time, source, validity, quality, freshness, and sequence |
| `V07-OBS-003` | Bounded declarative `Verify`, nested Boolean conditions, typed comparisons, tolerance, retry/deadline behavior, and atomic TM-to-TM sampling |
| `V07-OBS-004` | Relative, absolute, and telemetry `WaitFor` with durable identity, cancellation, disconnect, deadline, and recovery behavior |
| `V07-OBS-005` | Telemetry-conditioned durable procedure scheduling with quality/freshness gates and exactly one start outcome |
| `V07-OBS-006` | Typed bounded simulator `GetResource`, `MemoryLookup`, and `TMTCLookup` reads without generic filters or mutation |
| `V07-OBS-007` | Read-only `GetLimits` and `IsAlarmed` with explicit sample identity, quality, freshness, sequence, and indeterminate behavior |
| `V07-OBS-008` | Authorization-scoped snapshot/cursor streams with gaps, resynchronization, backpressure, cancellation, disconnect, and restart rules |
| `V07-OBS-009` | Cross-feature semantic, browser, accessibility, load, fault/recovery, and security acceptance |

Required properties:

- `GetTM` current/next sample, raw/engineering value, description, unit,
  acquisition/receive time, source, validity, quality, freshness, and sequence.
- Driver/GCS time acquisition with explicit clock source, provenance, and
  uncertainty; host-clock fallback can never silently claim GCS time.
- `Verify`, nested `AND`/`OR`, documented comparisons, tolerance, retries,
  timeout/delay, composite result, and TM-to-TM conditions.
- Relative/absolute/TM `WaitFor`, read-only `GetLimits` and `IsAlarmed`, and
  snapshot/cursor streams with gaps, backpressure, cancellation, and restart.
- Telemetry-conditioned scheduled procedure start with durable schedule
  identity, quality/freshness policy, restart recovery, and one start outcome.
- Typed simulator-only `GetResource`, `MemoryLookup`, and `TMTCLookup` reads
  with bounded catalogs/queries; no generic string filter or mutation.

Exit gate: semantic golden tests plus clock, staleness, atomic-sampling,
scheduled-start, resource/lookup typing, disconnect, cursor-gap, load, and
recovery tests pass without a legacy adapter.

### v0.8 - Data And Local Service Compatibility

Goal: add the documented non-GCS data model needed by real procedures.

Current disposition: [`V08-GATE-0A PASS`](SPELL_v0.8_Pre-Implementation.md)
authorizes exactly `V08-DATA-001` through `V08-DATA-009` and their 45 planned
proof identities under scope profile `LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE`.
The manifest and eight planning matrices under `contracts/v08` are hash-bound
authorization inputs. The gate itself claimed zero product constructs and zero
runtime artifacts. Subsequent work implemented all nine bounded packages in
the current worktree, including typed values and storage, scoped catalog and
dictionary exchange, containers and procedure data operations, shared data,
virtual files, authenticated API and durable mutation settlement, migration and
backup/recovery, the Data Service workspace, and version-scoped release
tooling. Backend and frontend pre-candidate verification passed. Candidate
freeze and commit, canonical qualification, Gate 0B, Final qualification,
SBOM/supply-chain evidence, deterministic packaging, release commit, and
annotated tag `v0.8.0` remain pending.

Required properties:

- Versioned `SCDB`, `GDB` catalog/mapping metadata, `PROC`, MMD,
  user-dictionary, DB/IMP compatibility, safe URI resolution, and immutable
  dependency identity; no live GCS resource access.
- Durable shared-data scopes with revisioned compare-and-set, namespace
  authorization, enumeration, and clear operations.
- Virtual-root procedure file APIs with traversal/symlink protection, quotas,
  encoding, atomic writes, and audit.
- Typed data/container persistence and restart semantics with no text or Python
  evaluation.

Exit gate: schema, import/export, concurrency, corruption, quota, path-security,
backup/restore, and migration tests pass for the claimed APIs.

### v0.9 - SPELL Development Environment

Goal: deliver the documented offline development workflows as a separate web
surface and controlled promotion pipeline.

Current disposition: requested after v0.8. Its bounded Gate 0A scope,
implementation, qualification, and acceptance are pending.

Required properties:

- Project explorer, procedure/dictionary editors, outline, TM/TC catalogs,
  Problems view, metadata/header creation, syntax, folding, snippets, and safe
  template generation.
- Parser-based procedure/folder/project semantic checks, cancellable progress,
  reports, library reparsing, check-on-save, and stable markers without source
  execution or a GCS.
- Safe import/export, external-change/case-conflict handling, Git or
  provider-neutral history/diff/conflict workflows.
- Immutable validated procedure bundles with digest, provenance, approval,
  simulator promotion, and rollback.

Exit gate: authoring accessibility, language-service non-execution,
project/dictionary compatibility, collaboration, promotion, installation, and
offline-package tests pass on the declared platform/browser matrix.

### v0.10 - Simulator Auxiliary Service Mutations

Goal: add GCS-oriented non-command service families one approved effect class
at a time, using only deterministic simulators.

Required properties:

- Separate tranches for `Event`, `SetGroundParameter`, `SetResource`, limit and
  alarm changes, external display intents, optional memory report/image
  operations, and optional ranging.
- Stable operation identity, capability-specific authorization, explicit stage
  and certainty, reconciliation, audit, rollback, and no generic retries.
- Driver facts and criticality remain separate from supervisor-owned prompts,
  authorization, persistence, retry policy, and publication.

Exit gate: each service has an independent conformance/fault/security gate; one
accepted service never implies acceptance of another.

### v0.11 - Simulator Telecommand Semantics

Goal: implement the documented `BuildTC` and `Send` surface in a simulator with
no operational route.

Required properties:

- Catalog-backed typed arguments and stable expansion of a logical command into
  ordered uniquely identified elements, including sequences, groups, and blocks.
- Explicit preflight/critical confirmation, global versus per-command
  modifiers, time/release/load-only intent, delays, closed-loop verification,
  and per-element stages.
- Separate transport, loading, release, acknowledgement, onboard execution,
  verification, disposition, effect certainty, and provider-native detail.
- No transport-success inference, no `LoadOnly` success inflation, and no
  automatic resend or false success after uncertainty.

Exit gate: command-corpus, confirmation, duplicate-child, stage, cancellation,
crash-boundary, uncertainty, reconciliation, and no-resend tests pass entirely
against deterministic simulators.

### v0.12 - Read-Only Legacy Observation

Goal: compare only proven typed read-only APIs with an isolated approved legacy
test environment.

Required properties:

- The adapter has structurally no mutation API, command credential, or route.
- Version-specific legacy data is translated through the accepted typed
  catalogs/TM/limit/resource schemas with explicit unsupported and quality data.
- Snapshot/cursor replay, malformed input, disconnect, rollback to simulator,
  and golden-trace classification are mandatory.

Exit gate: API, network, credential, source, and fault evidence proves zero
command authority and produces a bounded compatibility report.

### v0.13 - Controlled Non-Operational Procedure Control

Goal: introduce audited legacy procedure control only in an explicitly
approved non-operational environment.

Required properties:

- Stable operation identity, revisions, control leases, actors/reasons,
  command-state rules, competing controllers, reconnect, crash, and rollback.
- A demonstrated return to simulator/read-only mode and no driver/GCS command
  authority.

Exit gate: the dedicated environment safety plan and full control failure
matrix prove one authoritative outcome for every accepted operation.

### v0.14 - Bounded Adapter Migration

Goal: migrate one specifically approved adapter capability per tranche.

Required properties:

- Every tranche declares environment, methods/modifiers, mutability, identity,
  certainty, permissions, credentials, capacity, conformance, load, rollback,
  and prohibited behavior.
- Read-only shadow evidence precedes mutation consideration. No capability or
  environment inherits approval from another.

Exit gate: capability-specific acceptance only; no tranche implies full driver,
GCS, spacecraft, or operational acceptance.

### v0.15+ - Parallel Pilot Readiness

Goal: progress through read-only shadow and supervised non-commanding pilots
before any separately authorized commanding consideration.

Required properties:

- Complete differential traces, workload profiles, service ownership, incident
  response, backup/restore, monitoring, independent review, and rapid rollback.
- Software acceptance, environment deployment approval, and operational
  authorization remain separate decisions.

Exit gate: a version tag alone never authorizes mission or command use.

## Cross-Version Workstreams

| Workstream | Delivered baseline | Next required maturity |
| --- | --- | --- |
| Documentation conformance | Complete review of seven supplied PDFs and 304 pages plus next-generation specification `0.1.0-draft.1` with hash-pinned core authorities, requirements, ADRs, security/operations allocation, verification, externally anchored assignment, legacy adoption, final-effect authorization, roadmap, and the produced `DOC-011` Draft manual source/PDF artifact set | `NG-WP-00` closes immediate entry blockers and proves complete requirement-family allocation; `NG-WP-05` later binds the produced Draft manual to accepted behavior and the exact candidate build and obtains operator/publication acceptance. Later phases add source/trace comparison and claim-specific conformance reports. |
| Governance and evidence | Version gates, traceability, release records, source fingerprints | Governed package IDs, immutable per-version evidence, 100-percent bidirectional requirement coverage, explicit scope decisions, and maintained roadmap/timeline/review/manual records. |
| Procedure language | Bounded typed expressions, branches, loops, local calls, logs, simulated telemetry, waits, and unbound prompts | Documented safe Python profile, common modifier/outcome engine, exact public-name compatibility where safe, and per-family golden traces; never unrestricted source execution. |
| Execution and recovery | Isolated worker, atomic checkpoints, durable commands/prompts, fencing, crash recovery | External-effect reconciliation, driver lifecycle fencing, and compatibility recovery evidence. |
| Context and integration boundary | No driver host or GCS path | Typed host/context/execution binding, configuration precedence, granular capability/capacity contract, and simulator conformance before any legacy adapter. |
| Operator console | Accessible responsive 2D control, validation, prompt, recovery, report, reconnect | `NG-WP-03` completes the web UI modernization; `NG-WP-04` adds secure two-party controller handover and complete audit; `NG-WP-05` promotes the produced Draft GUI User Manual into a build-bound, operator-accepted publication. |
| Development environment | Transient source validation only | Separate non-executing web project/editor/dictionary/catalog/Problems/semantic-check/collaboration surface with immutable promotion. |
| Data services | Typed v0.3 variables and checkpoints | Documented containers, databases, dictionaries, shared scopes, files, immutable dependencies, and typed safe URI/storage rules. |
| Identity and authorization | Signed local JWT with viewer/operator/admin roles | `NG-WP-01` adds deny-by-default, server-evaluated RBAC startup without conflating role, mode, or lease; separately approved enterprise identity and policy remain deployment prerequisites. |
| Persistence and APIs | Versioned REST/WebSocket contracts and SQLite/PostgreSQL migrations | `NG-WP-02` implements the next-generation Python/PostgreSQL backend, typed driver/adapter schemas, compatibility migrations, operation/reconciliation resources, and immutable audit projections. |
| NIST security evidence | Security controls and evidence planning; no compliance claim | `NG-WP-06` reconciles all 17 SP 800-171 Rev. 3 families and every applicable 171/171A row to the exact deployed baseline, owners, ODPs, evidence, assessment results, and risk disposition. |
| Reliability and acceptance | Simulator crash recovery and version-specific qualification | `NG-WP-07` qualifies the approved fault/recovery profile; `NG-WP-08` executes full V&V, acceptance, traceability, and G0-through-G9 release evidence. |
| Supply chain and release | Hash-locked dependencies, audits, SBOMs, fingerprinted qualification, reproducible package | Version-parameterized release tooling, scanner/bootstrap debt disposition, additional host/browser evidence when claims expand. |

## Deferred And Unscheduled Scope

The following work has no approved version. It must not be implied by a
candidate row:

| Capability | Reason it remains unassigned |
| --- | --- |
| Features not assigned by the documentation-conformance ledger | The complete manual review exists, but individual rows still require an approved disposition, target phase, and test before implementation. |
| Full Python 2 or arbitrary Python compatibility | Unrestricted execution conflicts with the bounded non-executing IR. The roadmap targets documented observable SPELL compatibility through a safe Python 3 profile instead. |
| Live spacecraft connectivity or externally effective telecommands | Requires driver conformance, certainty/reconciliation, operational safety, environment approval, and separate authorization. |
| High availability, Kubernetes, or multi-node event transport | The candidate design defines active-passive authority and scalable projections, but no deployment topology, availability target, failure budget, workload, or operational owner is approved. |
| Production identity provider and enterprise role policy | The current identity system is intentionally local; production tenants and policy requirements are undefined. |
| Operational SLOs, accreditation, or mission approval | Operational workloads, environments, governance, and authorities have not been supplied. |
| Three.js or a 3D primary surface | Requires explicit version scope and cannot replace the accessible 2D control surface. |
| Legacy cutover and retirement | Requires successful shadow/pilot evidence, accepted rollback, and operational authorization. |

## Roadmap Update Policy

Update this file when a version is proposed, approved, started, materially
changed, accepted, deferred, or superseded.

For every update:

1. Change the document revision and updated date.
2. Keep accepted historical outcomes factual and linked to their release
   records; do not rewrite them to match later plans.
3. Mark future scope as Candidate until the required pre-implementation gate is
   explicitly approved.
4. Record scope changes, dependencies, exclusions, risks, and version-number
   shifts instead of silently replacing them.
5. Add target dates only when their basis is recorded; distinguish target,
   forecast, and actual dates.
6. Move completed factual dates and elapsed-time evidence into
   [`VERSION_TIMELINE.md`](VERSION_TIMELINE.md).
7. Keep detailed requirements, test IDs, results, artifact hashes, and exception
   dispositions in the authoritative version records rather than duplicating
   them here.
8. Never use a roadmap status to claim release acceptance, deployment approval,
   compatibility, performance, or operational authorization.
