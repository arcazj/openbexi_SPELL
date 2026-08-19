# OpenBEXI SPELL Project Roadmap

## Document Control

| Field | Value |
| --- | --- |
| Document revision | Accepted v0.9.0 baseline and bounded v0.10/v0.11 working-tree implementations |
| Update type | Accepted-release status plus non-release v0.10 verification and v0.11 implementation closeout scope |
| Updated | 2026-08-19 |
| Accepted product baseline | SPELL v0.9.0, tag `v0.9.0`, tag object `b47ee98429841afd7d91c928f3a314d6ac7f348c`, release commit `a8caa957179f8df301f9863e421e3fd7127e5318` |
| v0.3.1 status | Documentation set prepared; formal release commit and tag not claimed |
| v0.4 status | Accepted local-only synthetic non-CUI release; Final 74/74 tests and 209/209 assertions passed; no accepted exceptions |
| v0.5 status | Accepted at annotated tag `v0.5.0`; Final 1,096 concrete tests, 1,090 passes, six exact approved environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.6 status | Accepted at annotated tag `v0.6.0`; nine work packages `IMPLEMENTED_AND_QUALIFIED`; Final 1,626 concrete tests, 1,620 passes, six exact SQLite environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.7 status | Accepted at annotated tag `v0.7.0`; nine work packages `IMPLEMENTED_AND_QUALIFIED`; Final 2,041 concrete tests, 2,034 passes, seven exact SQLite environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.8 status | Accepted at annotated tag `v0.8.0`; nine work packages `IMPLEMENTED_AND_QUALIFIED`; Final 2,676 concrete tests, 2,661 passes, 15 exact SQLite environment skips, zero failures/errors, four SBOMs, and zero High/Critical findings |
| v0.9 source-freeze status | Implementation, version-scoped tooling, and exact product inventory frozen in candidate source; canonical candidate qualification and later endpoints were pending at freeze; later acceptance only by a strictly validated annotated tag |
| v0.9 current status | Accepted at annotated tag `v0.9.0`; strict Final, package, and tag validation passed with no accepted exceptions |
| v0.10 current status | Reference Example Adapter implemented and locally verified in the mutable worktree; no v0.10 candidate freeze, package, release commit, or tag |
| v0.11 current status | Simulator-only `BuildTC`/`Send` implementation locally qualified in the mutable worktree with recorded non-release exclusions; no v0.11 candidate freeze, package, release commit, or tag |
| Next-generation design status | Broader specification `0.1.0-draft.1` remains Draft; organization-only acceptance is outside the local v0.4 gate |
| Runtime, API, schema, frontend, dependency, or driver change | v0.9.0 is the accepted baseline; bounded v0.10 and simulator-only v0.11 changes exist only in the mutable worktree and are not released |
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

SPELL v0.9.0 is now the accepted product baseline. Its annotated tag object
`b47ee98429841afd7d91c928f3a314d6ac7f348c` peels to release commit
`a8caa957179f8df301f9863e421e3fd7127e5318`. Final validation,
supply-chain/SBOM checks, deterministic packaging, release-evidence validation,
and annotated tagging passed with no accepted exceptions. The verified tag
activated the conditional owner acceptance without a post-tag documentation
commit and provides no operational authorization. The earlier owner request
`start and complete asap V0.9` and the subsequent
[`V09-GATE-0A`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.9_Pre-Implementation.md) authorize only nine bounded
local synthetic non-CUI development-environment work packages and 45 planned
proof identities. At the authorization event, Gate 0A claimed zero implemented
constructs or runtime artifacts. At candidate source freeze, the bounded
implementation, version-scoped tooling, and exact product inventory were frozen
together. At that boundary, canonical candidate qualification had not yet run;
Gate 0B, Final qualification, packaging, release, and tag validation were
pending. That historical boundary was later superseded by the validated
`v0.9.0` tag. The v0.10 adapter and v0.11 simulator telecommand implementation
described below exist only in the mutable worktree; neither has a release
endpoint. The v0.11 local closeout record is complete and records every
environment-selected or intentionally inapplicable release-only check.

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

On 2026-07-17, all 304 pages in the historical seven-PDF source set were
reviewed. The five available 2.4.4 behavioral manuals are now versioned under
`SPELL_DOCUMENTATION/` with two supplementary earlier manuals. The evidence
inventory, conformance
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

For next-generation planning and delivery, every manual under
`SPELL_DOCUMENTATION/` is a mandatory source reference for the behavior and
concepts future work must address. The generated repository is the controlled,
derived design source for implementation scope, requirement IDs, architecture,
security, reliability, and acceptance. It may safely modernize mechanisms, but
it cannot silently override, omit, or weaken the source references. Its Draft
status remains controlling for the broader next-generation program. The bounded
v0.4 Candidate A gate uses the project-owner decision and its own technical
evidence; organization, mission, assessment, deployment, and
authorizing-official approvals are outside that local gate. No compliance,
deployment, or operational connection is asserted.

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

- [`SPELL_DOCUMENTATION/`](SPELL_DOCUMENTATION/) as the mandatory source
  reference for documented SPELL language, driver, server, operator, and
  development behavior that future work must address.
- [`PROMPT_Instructions.md`](PROMPT_Instructions.md) for durable architecture,
  safety, repository, and release rules.
- [`PROMPT_History.md`](PROMPT_History.md) for approved owner requests and
  version decisions.
- [`Test_and_Integration.md`](Test_and_Integration.md) for requirements,
  acceptance gates, executed evidence, and exceptions.
- [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md) for the
  supplied-manual inventory, compatibility policy, and documented behavior map.
- [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md)
  as the controlled derived design source for next-generation architecture,
  security, data, web, operations, and verification scope. It must trace to the
  source-reference manuals. While it remains Draft, it cannot override an
  approved release record or authorize implementation or use.
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

v0.2, v0.3, v0.4, v0.5, v0.6, v0.7, and v0.8 are accepted product releases. v0.1 is a delivered planning
baseline that was later approved only for the bounded v0.2 entry scope. v0.3.1
is the prepared documentation set described above. Every later version number
is a planning label until its applicable gate is approved. Annotated tag
At the v0.9 source-freeze boundary, `v0.8.0` fixed the accepted baseline. Final qualification, four SBOMs,
supply-chain validation, deterministic packaging, release-evidence validation,
and strict annotated-tag validation passed. v0.9 has passed its bounded Gate
0A for nine exact work packages and 45 planned proof identities. Its authorized
implementation, tooling, and exact product inventory were frozen together in
candidate source. At that boundary, canonical candidate qualification had not
yet run; Gate 0B, Final, package, release commit, and tag were pending. Later
acceptance is authoritative only through the strictly validated annotated tag.

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
| v0.8 | Data and Local Service Compatibility | Product | Accepted at annotated tag `v0.8.0`; no accepted exceptions | Add documented dictionaries, databases, shared data, virtual-root files, immutable dependencies, and durable local state. | Final nine-suite qualifi…8972 tokens truncated…ts. Candidate
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

Current disposition: accepted at annotated tag `v0.8.0`, object
`0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, over release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`. All nine `V08-DATA-001`
through `V08-DATA-009` packages and all 45 mapped identities are
`IMPLEMENTED_AND_QUALIFIED`. Final qualification, four image-bound SBOMs,
supply-chain validation, deterministic packaging, release-evidence validation,
and strict annotated-tag validation passed with no accepted exceptions.

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

Current disposition: accepted at annotated tag `v0.9.0`, object
`b47ee98429841afd7d91c928f3a314d6ac7f348c`, which peels to release commit
`a8caa957179f8df301f9863e421e3fd7127e5318`. The earlier
[`V09-GATE-0A PASS`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.9_Pre-Implementation.md) authorized exactly
`V09-DEV-001` through `V09-DEV-009` and their 45 planned proof identities under
scope profile `LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT`; its historical
zero-implementation claim remains true at the gate event. Candidate, Gate 0B,
Final, packaging, and strict annotated-tag validation subsequently passed with
no accepted exceptions.

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

### v0.10 - SPELL 2.4.4 Reference Example Adapter

Goal: make every numbered example in SPELL Language Reference 2.4.4 selectable
from one runnable procedure and prove its independently authored semantic
adaptation against deterministic simulator oracles.

Current disposition: implemented and locally verified on 2026-08-19 in the
mutable working tree. The canonical local result is 195 PASS with zero failed,
skipped, expected-failed, or unresolved examples; the strengthened traceability
gate contains 257 independently asserted variant subcases across those 195
examples. Public API and desktop/mobile browser execution are also local
evidence. This is not a candidate freeze, package, accepted release, or
annotated-tag endpoint.

Required properties:

- Exactly one bundled procedure with a searchable typed menu for Examples
  1 through 195 and durable index-to-example routing.
- A hash-pinned 195-row contract binding the reference authority, source spans,
  compatibility identities, semantic families, adaptations, expected effects,
  and success criteria.
- A generated 257-subcase variant matrix covering all 195 examples, including
  independent assertions and traces for every documented form and all 46
  multi-variant examples.
- Closed IR and runtime operations with no `exec`, `eval`, arbitrary import,
  shell, network, or live command dispatch.
- Exact expected-effect coverage for every PASS, including assertion and trace
  references; Example 195 must query real bundled TM and TC catalog entries and
  prove catalog provenance, filter bounds, types, directions, and a negative
  lookup.
- Direct adapter, worker, public API, and desktop/mobile menu verification with
  195 PASS, 0 FAIL, 0 SKIP, 0 XFAIL, and 0 unresolved.

This profile adapts semantic intent because the reference includes fragments,
pseudocode, output-only illustrations, and intentionally invalid examples. It
does not claim verbatim execution of PDF snippets or general SPELL 2.4.4 parser
compatibility. The previously planned auxiliary-service mutation tranche is
deferred; simulated effects in this adapter do not authorize or implement live
service or telecommand routes.

Exit gate: the contract, generator, single procedure, qualification artifact,
worker/API tests, and real browser proof all pass without waiver.

### v0.11 - Simulator Telecommand Semantics

Goal: implement the documented `BuildTC` and `Send` surface in a simulator with
no operational route.

Current disposition: the authorized simulator-only implementation is locally
qualified in the mutable working tree. Exact multi-suite commands, counts,
skips, non-applicable historical release checks, and the cold-cache offline
build limitation are recorded in
[`SPELL_v0.11_Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.11_Implementation.md). This is not a
candidate freeze, package, accepted release, or annotated-tag endpoint.

Required properties:

- Catalog-backed typed arguments and stable expansion of a logical command into
  ordered uniquely identified elements, including sequences, groups, and blocks.
- Explicit preflight/critical confirmation, global versus per-command
  modifiers, time/release/load-only intent, no-real-wait logical scheduling,
  per-element timeouts, delayed closed-loop verification, tolerance and
  adjustable-limit intent, and per-element stages.
- Separate transport, loading, release, acknowledgement, onboard execution,
  verification, disposition, effect certainty, and provider-native detail.
- No transport-success inference, no `LoadOnly` success inflation, and no
  automatic resend or false success after uncertainty.
- Durable intent and confirmation, bounded checkpoints, cancellation,
  crash-boundary recovery, canonical-state integrity checks, and reconciliation
  without dispatching a second command.

Exit gate result: command-corpus, confirmation, duplicate-child, stage,
cancellation, crash-boundary, uncertainty, reconciliation, and no-resend tests
pass against deterministic simulators. The strengthened 195-example/257-variant
v0.10 gate, current product regression, frontend, browser, build, and image
checks pass, including all 19 environment-selected PostgreSQL and Docker-Compose
tests. The implementation record preserves nine historical v0.5-v0.9
current-root release/package validators as explicit non-v0.11 closeout
boundaries rather than relabeling them as passes.

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
