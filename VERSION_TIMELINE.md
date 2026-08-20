# OpenBEXI SPELL Version Timeline

## Document Control

| Field | Value |
| --- | --- |
| Document revision | Accepted v0.10.0 baseline and v0.11 simulator telecommand release candidate |
| Update type | Record immutable v0.10 acceptance and the bounded v0.11 candidate/closeout sequence |
| Updated | 2026-08-19 |
| Time zone for local timestamps | America/New_York; EDT (UTC-04:00) for the recorded July and August 2026 events |
| Accepted product baseline | SPELL v0.10.0, tag `v0.10.0`, tag object `95f64a04bb15b1eb03250a8d0387a228b67727a7`, release commit `c33d1893d90f9d42c36eedd19cb83f079bf39a9f` |
| v0.3.1 status | Author-recorded documentation set prepared; no release commit or tag claimed |
| v0.4 status | Accepted 2026-08-12; annotated tag `v0.4.0`; Final 74/74 tests and 209/209 assertions passed; no accepted exceptions |
| v0.5 status | Accepted 2026-08-14 at annotated tag `v0.5.0`; scope remains bounded to `V05-IR-001`; no accepted exceptions |
| v0.6 status | Accepted 2026-08-16 at annotated tag `v0.6.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.7 status | Accepted 2026-08-17 at annotated tag `v0.7.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.8 status | Accepted 2026-08-18 at annotated tag `v0.8.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.9 source-freeze status | Implementation, version-scoped tooling, and exact product inventory frozen in candidate source; canonical candidate qualification and all later release endpoints were pending at freeze; later acceptance only by a strictly validated annotated tag |
| v0.9 current status | Accepted 2026-08-19 at annotated tag `v0.9.0`; Final qualification, package, and strict tag validation passed with no accepted exceptions |
| v0.10 current status | Accepted 2026-08-19 at annotated tag `v0.10.0`; package SHA-256 `b65af04f53475e8a4aa5f233485c17fd734793aeaddda6446ea969b8705f405d`; no accepted exceptions |
| v0.11 current status | Candidate source `e15d3314f9b97eb43d5d5057c8f1ba614844e0e7` committed 2026-08-19; focused/backend-browser prechecks pass; complete release qualification/package/tag pending |
| Next-generation specification | `0.1.0-draft.1` prepared 2026-07-18; broader organization acceptance remains pending and is outside local v0.4 Gate 0 |
| Experimental activity | `NG-PROT-001` and bounded continuation `NG-PROT-002` prepared and tested in isolation; no product work package, release, or Gate G0 claim |
| Historical local Gate G0 readiness | `PASS`; exhaustive seven-source compatibility review passed for 1,682 rows, including 125 v0.4 and 1,557 Deferred rows; exact manifest and pinned Python 3.13 qualification verified |
| Operational authorization | None |
| Update model | Living factual record; add one section for each version |

## Purpose

This document records when each OpenBEXI SPELL version was planned, built,
verified, and accepted, and states how much elapsed time can be supported by
retained evidence. It is the historical companion to
[`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md).

Elapsed time is not the same as active engineering effort or person-hours. The
repository does not contain time sheets, continuous activity logs, or complete
pre-commit history. This document therefore reports exact repository intervals
where possible and says `unknown` where the evidence cannot support a total.

## Evidence Rules

| Classification | Meaning |
| --- | --- |
| Exact repository interval | Both endpoints are immutable Git commit/tag timestamps or machine-readable artifact timestamps committed in the referenced tag or otherwise cryptographically anchored. |
| Recorded date range | Project records identify calendar dates but not complete times. |
| Observed evidence window | A retained artifact proves work existed by one timestamp and a later immutable endpoint exists; this is not the full build duration. |
| Unknown | No defensible start or completion endpoint exists for the requested duration. |

Conventions:

- Git author and commit timestamps are identical for the three retained commits.
- The v0.7 and v0.8 candidate, qualified-source, release, and tag intervals use their
  Git committer or annotated-tag creator timestamps as applicable.
- Annotated tag creator times are used for tag endpoints.
- UTC qualification timestamps are converted to EDT by subtracting four hours.
- Earlier entries remain unchanged except for factual corrections or stronger
  evidence. Corrections must identify the new evidence.
- A documentation-only patch is distinct from a product release. It does not
  change runtime, API, database, dependency, or qualification identities.
- A mutable worktree verification result is not an exact repository interval or
  immutable candidate result until source freeze and commit.

## Duration Summary

| Version | Scope | Supported start | Supported completion | Defensible elapsed time | Confidence |
| --- | --- | --- | --- | --- | --- |
| v0.1 | Pre-implementation planning baseline | Start not retained | Planning verification and bounded v0.2 approval recorded on 2026-07-12 | Total duration unknown | High confidence in completion date; no duration evidence |
| v0.2 | Simulator vertical slice | Implementation start not retained; earliest immutable v0.2 evidence is the Python SBOM at 2026-07-12 20:16:14.516807 EDT | Tag `v0.2.0` at 2026-07-12 21:04:40 EDT | Total duration unknown; retained evidence-to-tag window is 48m 25.483193s | Exact evidence window, not build duration |
| v0.3 | Simulator hardening and language foundation | Approved gate commit `85f2e06` at 2026-07-12 21:08:16 EDT | Tag `v0.3.0` at 2026-07-16 20:37:39 EDT | 3d 23h 29m 23s gate-to-tag | Exact repository interval |
| v0.3.1 | Roadmap and timeline documentation | Uncommitted author-recorded owner request date of 2026-07-17; intra-day request time not retained in project files | Uncommitted author-recorded preparation date of 2026-07-17 | Same calendar day; exact elapsed time unknown | Author-recorded date only; no release tag claimed |
| v0.4 gate draft | Typed simulator driver and context foundation planning | Uncommitted owner request date of 2026-07-17; intra-day request time not retained | Draft planning records revised after complete supplied-manual review on 2026-07-17; approval pending | Product build duration not applicable; planning elapsed time unknown | Author-recorded date only; no implementation or release claim |
| v0.4 local gate revision | Candidate A local-only synthetic non-CUI simulator engineering gate | Direct project-owner instruction recorded 2026-07-18; exact time not retained | Scope, exclusions, budgets, and test plan owner-approved and Gate 0 passed on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Direct owner instruction plus digest-bound Python 3.13 working-tree evidence; authorizes product engineering but makes no release, operational, or compliance claim |
| v0.4 | Typed Simulator Driver and Context Foundation | Gate date 2026-07-18; exact gate time not retained | Annotated tag `v0.4.0` at 2026-08-12 21:33:43 EDT | Total gate-to-tag duration unknown because the start has no exact time; candidate-source commit to tag was 16h 57m 56s | Exact Git interval only for candidate-source commit `f9a2cdb` at 04:35:47 EDT through tag; not total implementation effort |
| v0.5 / `V05-IR-001` | Existing IR 0.3 fail-closed validation hardening and bounded release closeout | Gate-ready work resumed 2026-08-12; exact start time not retained | Annotated tag `v0.5.0` at 2026-08-14 22:22:33 EDT | Total duration unknown; qualified-source commit to tag was 13m 21s, and release-commit to tag was 2m 25s | Exact Git intervals for qualified source `2f31e6a`, release commit `e7b6bb9`, tag object `a1b277d`, and accepted tag; not total implementation effort |
| v0.6 Gate 0A | Durable Operator Workspace and Procedure Composition | Owner request recorded 2026-08-15; exact time not retained | Explicit owner approval and Gate 0A PASS recorded 2026-08-15; exact time not retained | Same calendar day; exact elapsed time and active effort unknown | `V06-OP-001` through `V06-OP-009` authorized; no implementation or executed product evidence claimed |
| v0.6 | Nine bounded operator work packages and version-scoped qualification/release tooling | Gate 0A commit `f6eba8b` at 2026-08-15 07:28:35 EDT | Annotated tag `v0.6.0` at 2026-08-16 13:50:02 EDT | 1d 6h 21m 27s exact Gate-commit-to-tag interval; total active engineering effort unknown | Exact Git interval; Final qualification, SBOMs, supply chain, deterministic package, release commit, and tag passed with no accepted exceptions |
| v0.7 Gate 0A | Simulator Read-Only Observation and Condition Engine planning authorization | Owner request recorded 2026-08-16; exact time not retained | Explicit owner approval, exact contract binding, Gate validator PASS, 22 Gate tests, and eight contract tests recorded 2026-08-16 | Same calendar day; exact elapsed time and active effort unknown | `V07-OBS-001` through `V07-OBS-009` authorized; no implementation, product evidence, release, operational, or compliance claim |
| v0.7 | Nine bounded read-only observation packages and version-scoped qualification/release tooling | Gate 0A commit `07c1943` at 2026-08-16 14:33:34 EDT | Annotated tag `v0.7.0` at 2026-08-17 04:57:47 EDT | 14h 24m 13s exact Gate-commit-to-tag interval; candidate-to-tag 9h 39m 04s; qualified-source-to-tag 7h 35m 33s; release-commit-to-tag 6m 05s; total active engineering effort unknown | Exact Git intervals; Final qualification, SBOMs, supply chain, deterministic package, release commit, and tag passed with no accepted exceptions |
| v0.8 Gate 0A | Data and Local Service Compatibility planning authorization | Owner request and accepted v0.7.0 baseline recorded 2026-08-17; exact request time not retained | Explicit owner approval, nine-package/45-identity contract binding, and Gate validator PASS recorded 2026-08-17 | Same calendar day; exact elapsed time and active effort unknown | `V08-DATA-001` through `V08-DATA-009` authorized; no implementation, product evidence, release, operational, or compliance claim |
| v0.8 | Nine bounded local data-service packages plus version-scoped qualification/release tooling | Gate 0A commit `451c065740e7b6501f86094d9be79578b30b1591` at 2026-08-17 20:37:48 EDT | Annotated tag `v0.8.0` at 2026-08-18 15:48:51 EDT | 19h 11m 03s exact Gate-commit-to-tag interval; candidate-to-tag 1h 46m 40s; qualified-source-to-tag 35m 34s; release-commit-to-tag 1m 39s; total active engineering effort unknown | Exact Git intervals; Final qualification, SBOMs, supply chain, deterministic package, release commit, and tag passed with no accepted exceptions |
| v0.9 Gate 0A | SPELL Development Environment planning authorization | Owner request `start and complete asap V0.9` recorded 2026-08-18; exact time not retained | Explicit owner approval, nine-package/45-identity contract binding, and Gate validator PASS recorded 2026-08-18 | Same calendar day; exact elapsed time and active effort unknown | `V09-DEV-001` through `V09-DEV-009` authorized; no implementation, product evidence, release, operational, or compliance claim |
| v0.9 candidate source freeze | Bounded development-environment implementation and version-scoped qualification/release tooling | Gate 0A commit `92f3b4b82908d44e28b9506749e498386a428c27`; exact implementation start time not retained | Candidate source and exact product inventory frozen 2026-08-18; canonical qualification had not yet run | Elapsed time and active effort unknown | Gate 0B, Final, package, release commit, and tag were pending at freeze; later acceptance only by validated annotated tag |
| v0.9 | Bounded SPELL Development Environment | Candidate commit `060001baf423fb82f27041f6b842630370c1a786` at 2026-08-19 04:12:37 EDT | Annotated tag `v0.9.0` at 2026-08-19 05:56:44 EDT | Candidate-to-tag 1h 44m 07s; qualified-source-to-tag 52m 28s; release-commit-to-tag 2m 21s; total active engineering effort unknown | Exact Git intervals; strict release validation passed with no accepted exceptions |
| v0.10 | SPELL 2.4.4 Reference Example Adapter | Owner request recorded 2026-08-19; exact request time not retained | Annotated tag `v0.10.0` at 2026-08-19 19:37:21 EDT | Total effort unknown; release-commit-to-tag interval 1m 23s | Exact release commit/tag endpoint; 195/195 examples and 257/257 variants |
| v0.11 candidate | Simulator Telecommand Semantics | Accepted `v0.10.0` predecessor and recorded `V11-GATE-0A` | Candidate commit `e15d331` at 2026-08-19 19:44:43 EDT; final tag pending | Implementation effort unknown; v0.10-tag-to-candidate interval 7m 22s | Exact Git interval for candidate lineage; not an accepted release or active-effort measure |
| NG spec 0.1 draft | Next-generation requirements, architecture, web, security, operations, and assurance documentation | Documentation initiative recorded 2026-07-18; exact start time not retained | `0.1.0-draft.1` prepared in the working tree on 2026-07-18; human approval pending | Same calendar day; exact elapsed time and active effort unknown | Author-recorded dates and hash-verified source set; no baseline tag |
| NG-PROT-001 | Isolated RBAC startup-policy prototype | Owner request to move forward recorded 2026-07-18; exact start time not retained | Evaluator and tests passed in the working tree on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Working-tree and test evidence only; no product start, commit, tag, or gate approval |
| NG-PROT-002 | Isolated authenticated startup input-adaptation prototype | Owner request to move forward recorded 2026-07-18; exact start time not retained | Adapter hardening and qualification passed in the working tree on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Working-tree and test evidence only; no product start, commit, tag, or gate approval |
| NG-WP-00 readiness | Gate G0 allocation, validation, and decision package | Owner request to implement the next step recorded 2026-07-18; exact start time not retained | Gate G0 passed under pinned Python 3.13 on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Digest-bound working-tree evidence; no product delivery, release, operational, or compliance claim |
| NG-WP-00 compatibility seed | Candidate v0.4 Driver/Server source-assertion decomposition | Roadmap-directed continuation recorded 2026-07-18; exact start time not retained | 62-row partial seed and digest reconciliation prepared in the working tree on 2026-07-18; exhaustive gate remains incomplete | Same calendar day; exact elapsed time and active effort unknown | Working-tree evidence only; no row approval, product start, commit, tag, or gate pass |
| NG-WP-00 example index | Seven-source registration and exact Language Reference example identity indexing | Owner request to complete v0.4 before v0.5 recorded 2026-07-18; exact start time not retained | 195 example indexes plus the prior 62 decomposed Driver/Server rows reconciled in the working tree on 2026-07-18; example bodies/oracles and the exhaustive gate remain incomplete | Same calendar day; exact elapsed time and active effort unknown | Working-tree evidence only; no semantic example decomposition, fixture/result evidence, row approval, product start, commit, tag, or gate pass |

## 2026-08-19 - v0.11 Candidate Reconstruction And Release Closeout

| Field | Value |
| --- | --- |
| Accepted predecessor | `v0.10.0`, tag object `95f64a04bb15b1eb03250a8d0387a228b67727a7` |
| Entry authority | `V11-GATE-0A PASS` |
| Candidate commit and time | `e15d3314f9b97eb43d5d5057c8f1ba614844e0e7`; 2026-08-19 19:44:43 EDT |
| Implemented scope | Closed simulator catalog, typed `BuildTC`/`Send`, IR 0.11, staged execution/certainty, confirmation, cancellation, recovery, reconciliation, and no-resend |
| Pre-closeout evidence | 197 focused v0.11 tests passed; Chromium and mobile passed 2/2 against the v0.11 image; complete source-bound release gates pending |
| Immutable status | Candidate only; acceptance requires committed qualification/package evidence and validated annotated tag `v0.11.0` |
| Operational authorization or compliance determination | None |

The exact scope and conditional acceptance rule are recorded in
[`SPELL_v0.11_Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.11_Implementation.md).
The candidate is an immutable Git endpoint, but selected prechecks are not a
substitute for the complete release policy.

## 2026-08-19 - v0.10.0 Accepted

| Field | Value |
| --- | --- |
| Owner direction | Revisit v0.10 around the 195 numbered SPELL Language Reference 2.4.4 examples; expose one selectable procedure; implement and execute as soon as possible with approvals granted |
| Implemented scope | One production-catalog runner, a hash-pinned 195-example contract, a generated 257-subcase variant matrix, closed IR `0.10`, deterministic semantic adapters and oracles, catalog retirement, and searchable desktop/mobile prompt behavior |
| Product candidate | `8377760be59033b3372512ad812c43cd6d2f7e29` |
| Result boundary | 195 PASS, 0 FAIL, 0 SKIP, 0 XFAIL, 0 unresolved, with 257 independently asserted variant subcases; Example 195 proves bundled TM/TC catalog lookup provenance and values; complete release results are authoritative only in `artifacts/v0.10/release-qualification.json` |
| Claim boundary | Semantic adaptations, not verbatim execution of PDF fragments or general SPELL 2.4.4 parser compatibility; no live command dispatch |
| Release endpoint | Release commit `c33d1893d90f9d42c36eedd19cb83f079bf39a9f`; annotated tag object `95f64a04bb15b1eb03250a8d0387a228b67727a7`; package SHA-256 `b65af04f53475e8a4aa5f233485c17fd734793aeaddda6446ea969b8705f405d` |
| Immutable status | ACCEPTED; qualification, deterministic package, release evidence, and strict annotated-tag validation passed with no accepted exceptions |
| Operational authorization or compliance determination | None |

The exact local evidence is recorded in
[`Test_and_Integration.md`](Test_and_Integration.md) and
[`SPELL_v0.10_Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.10_Implementation.md). Elapsed time
and active engineering effort are unknown because the request time and a
continuous work log are not retained. Annotated tag `v0.10.0` is the
release-acceptance endpoint.

## 2026-08-19 - v0.9.0 Accepted

| Field | Value |
| --- | --- |
| Accepted release | SPELL v0.9.0, annotated tag `v0.9.0` |
| Tag object and time | `b47ee98429841afd7d91c928f3a314d6ac7f348c`; 2026-08-19 05:56:44 EDT |
| Release commit | `a8caa957179f8df301f9863e421e3fd7127e5318` |
| Qualified source | `09f4d6f5e793de8b0e1637c31344aed01f6d3b77` |
| Candidate | `060001baf423fb82f27041f6b842630370c1a786` |
| Decision | ACCEPTED; strict tag validation PASS; no accepted exceptions |
| Operational authorization or compliance determination | None |

This current acceptance status does not rewrite the earlier candidate-freeze
record below. It establishes the later immutable endpoint that record required.

## 2026-08-18 - v0.9 Candidate Source Freeze

| Field | Value |
| --- | --- |
| Accepted release status at source freeze | SPELL v0.8.0 was the accepted baseline |
| Gate authority | Final v0.9 Gate 0A commit `92f3b4b82908d44e28b9506749e498386a428c27`, sole parent `d…8032 tokens truncated…e claim, or authorize
deployment or operations. Exact elapsed time and active effort remain unknown.

## 2026-07-18 - NG-PROT-002 Authenticated Startup Input Adaptation

| Field | Value |
| --- | --- |
| Activity type | Experimental prototype planning; not a product release |
| Status | Prepared, hardened after review, and tested in the working tree |
| Governing baseline | Next-generation specification `0.1.0-draft.1`; Draft and Gate G0 pending |
| Product behavior/API/schema/dependency change | None |
| Product implementation authorization | None |
| Commit or tag | None |
| Operational authorization or compliance determination | None |

Bounded result:

- Added an isolated input adapter that authenticates a raw bearer through the
  unchanged v0.3 local JWT verifier before invoking NG-PROT-001.
- Provisionally mapped `viewer` to Monitoring and `operator` to Controller;
  `admin` fails closed and no accepted v0.3 role maps to Developer.
- Accepted policy, environment, and domain only from server-owned fixtures;
  ignored extra signed authority claims and exposed no client role input.
- Preserved exact UTC time for policy and reauthentication decisions while
  using the verifier's integer epoch contract for JWT authentication.
- Derived an opaque, role-sensitive credential-instance surrogate under a
  prototype-specific HMAC purpose and bounded it by exact JWT expiry.
- Kept the unsigned public candidate separate from an adaptation audit
  candidate that records source role, mapping revision, session semantics, and
  the deterministic evaluator event.

Verification recorded on 2026-07-18:

- Combined experimental Python 3.13 qualification: 96 passed.
- Complete backend regression: 209 passed and one dedicated PostgreSQL test
  skipped because no PostgreSQL migration database was configured.
- Unchanged frontend regression: 13 passed; production build succeeded.

Authentication failures occur before an adaptation audit candidate exists;
this remains a blocker before endpoint work. NG-PROT-002 is not the
next-generation identity/policy adapter, a signed session bootstrap, or a
product route. It does not establish authoritative roles or scopes, persist
audit evidence, create a controller lease or fence, authorize runtime or Git
actions, start or complete an `NG-WP`, satisfy `MODE-023`, `MODE-024`,
`MODE-027` or `SEC-003..SEC-006`/`SEC-010`, pass Gate G0, change v0.3.0/v0.4
scope, support a NIST compliance claim, or grant deployment or operational
authorization. The next step is Gate G0 and `NG-WP-00`; exact elapsed time and
active effort remain unknown.

## 2026-07-18 - NG-PROT-001 RBAC Startup Policy Evaluator

| Field | Value |
| --- | --- |
| Activity type | Experimental prototype planning; not a product release |
| Status | Prepared and tested in the working tree |
| Governing baseline | Next-generation specification `0.1.0-draft.1`; Draft and Gate G0 pending |
| Product behavior/API/schema/dependency change | None |
| Product implementation authorization | None |
| Commit or tag | None |
| Operational authorization or compliance determination | None |

Bounded result:

- Added a pure, data-only evaluator and adjacent status record under
  `backend/experimental/`.
- Modeled Controller startup as Execution with `AWAITING_CONTROL`, Monitoring
  as read-only Monitoring, and Developer as development-only Edit without
  creating runtime or repository mutation authority.
- Kept multi-role capabilities mode-scoped, applied the documented
  Monitoring-then-Edit safe recommendation, rejected client capability hints,
  and produced deterministic decision and audit-event candidates.
- Added fail-closed coverage for policy, identity, session, roles, attributes,
  scopes, requested modes, expiry, malformed runtime values, and every
  non-empty primary-role subset.

Verification recorded on 2026-07-18:

- Focused Python 3.13 qualification: 63 passed.
- Complete backend regression: 176 passed and one dedicated PostgreSQL test
  skipped because no PostgreSQL migration database was configured.
- Unchanged frontend regression: 13 passed; production build succeeded.

The evaluator is not imported by `backend/app.py` and exposes no route. It has
no authentication dependency, signed projection, controller state, command,
Git authorization, web-client, revocation, or durable-audit integration. The
later NG-PROT-002 composes it with the accepted verifier only inside the same
experimental boundary. These results do not close `NG-WP-00`, `NG-WP-01`,
`MODE-023`, `MODE-024`, `MODE-027`, Gate G0, NIST assessment, deployment
approval, or operational authorization. The retained records establish the
calendar date only; exact elapsed time and active effort remain unknown.

## 2026-07-18 - Next-Generation Specification 0.1 Draft

| Field | Value |
| --- | --- |
| Release type | Documentation initiative; not a product release |
| Status | `0.1.0-draft.1`; multidisciplinary review and Gate G0 pending |
| Reviewed source | Seven PDFs, 304 pages, exact SHA-256 values retained |
| Product behavior change | None |
| Runtime/API/schema/dependency change | None |
| Product implementation authorization | None |
| Operational authorization or compliance determination | None |

Scope:

- Created [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md)
  as the authoritative next-generation implementation-scope specification;
  Draft status and human Gate G0 approval remain controlling.
- Preserved the Language Reference 2.4.4 and Driver Development Manual 2.4.4
  through external hash-pinned authority records without modifying their bytes.
- Added the modern server/data/web/Git/reliability/security/operations design,
  objective-level NIST assessment template, machine-readable state models,
  mission-wide externally anchored satellite assignment, legacy adoption,
  final-effect authorization, authorization-private real-time projections,
  verification strategy, and implementation roadmap.
- Registered role-based startup and secure controller handover requirements,
  including current-controller approval, subsequent requester responsibility
  acknowledgment, atomic higher-fence transfer, automatic mode changes, and
  complete identity/timestamp audit evidence.
- Added controlled GUI User Manual source, four next-generation concept
  wireframes, a tagged/outlined PDF, and a reproducible publication pipeline;
  recorded ChatGPT 5.6 SOL as the project-declared AI assistance tool without
  assigning it an approval or authorization role.
- Reconciled the root and generated roadmaps to treat the Draft repository as
  the authoritative next-generation implementation-scope specification while
  preserving human Gate G0 and release authorization.
- Integrated the draft as a required input to the pending v0.4 gate without
  claiming it is approved or that v0.4 implementation has started.

Duration statement:

- The source review date and documentation preparation date are recorded, but
  no immutable draft-start or approval tag exists. Exact elapsed time, active
  engineering effort, and person-hours remain unknown.
- A later signed documentation baseline will establish an approval endpoint;
  it will not retroactively establish the draft's start time.

## 2026-07-17 - v0.3.1 - Roadmap and Timeline Records

| Field | Value |
| --- | --- |
| Release type | Documentation-only patch |
| Status at document preparation | Prepared in the working tree; no release commit or tag claimed |
| Baseline | v0.3.0 |
| Requested | 2026-07-17 |
| Prepared | 2026-07-17 |
| Product behavior change | None |
| Runtime/API/schema/dependency change | None |
| Operational authorization | None |

Scope:

- Created [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) as the maintained
  historical and forward-looking release roadmap.
- Created this file as the maintained version timing record.
- Made no claim that unrelated working-tree changes are part of v0.3.1.

Duration statement:

- Both documents use the author-recorded request and preparation date of
  2026-07-17. At preparation time, that date is not yet corroborated by a
  release commit, tag, or anchored artifact.
- The conversation request time is not stored in an authoritative project
  record, and no v0.3.1 release commit or annotated tag exists at preparation
  time. Exact elapsed time is therefore unknown.

## 2026-07-16 - v0.3.0 - Simulator Hardening and Language Foundation

| Field | Value |
| --- | --- |
| Release type | Product engineering release |
| Status | Accepted local simulator engineering release |
| Baseline | v0.2.0 |
| Pre-implementation gate commit | `85f2e06a24c465c722a0a576f9afc6f91b058afd` |
| Release commit | `7bccbb4eb096b22d0d1f2f765d5172f6dde244f1` |
| Annotated tag | `v0.3.0` |
| Operational authorization | None |

### Milestones

| Milestone | Timestamp or range | Evidence |
| --- | --- | --- |
| v0.2 baseline tagged | 2026-07-12 21:04:40 EDT | Annotated tag `v0.2.0` |
| v0.3 pre-implementation gate committed | 2026-07-12 21:08:16 EDT | Commit `85f2e06` |
| Gate opened after baseline tag | 3m 36s | Exact tag-to-commit interval |
| Final verification activity | 2026-07-13 through 2026-07-16 EDT | Recorded in [`Test_and_Integration.md`](Test_and_Integration.md) |
| Quick qualification generated and finished | 2026-07-16 20:17:57.066663 through 20:19:05.065099 EDT | `artifacts/v0.3/qualification-quick.json` |
| Soak qualification generated and finished | 2026-07-16 20:19:19.087893 through 20:29:19.315544 EDT | `artifacts/v0.3/qualification-soak.json` |
| Browser-stream qualification generated and finished | 2026-07-16 20:29:51.656 through 20:30:57.776 EDT | `artifacts/v0.3/qualification-browser-stream.json` |
| Qualification composed | 2026-07-16 20:30:59.625229 EDT | `artifacts/v0.3/qualification.json` |
| Release committed | 2026-07-16 20:37:26 EDT | Commit `7bccbb4` |
| Release tagged | 2026-07-16 20:37:39 EDT | Annotated tag `v0.3.0` |

### Duration Calculations

| Interval | Calculation | Interpretation |
| --- | --- | --- |
| v0.3 gate commit to release commit | 2026-07-12 21:08:16 to 2026-07-16 20:37:26 | 3d 23h 29m 10s exact repository interval |
| v0.3 gate commit to release tag | 2026-07-12 21:08:16 to 2026-07-16 20:37:39 | 3d 23h 29m 23s exact repository interval |
| v0.2 tag to v0.3 tag | 2026-07-12 21:04:40 to 2026-07-16 20:37:39 | 3d 23h 32m 59s exact release-to-release interval |
| Final qualification evidence window | 2026-07-16 20:17:57.066663 to 20:30:59.625229 | 13m 2.558566s exact artifact interval |
| Qualification composition to tag | 2026-07-16 20:30:59.625229 to 20:37:39 | 6m 39.374771s exact interval |
| Release commit to annotated tag | 2026-07-16 20:37:26 to 20:37:39 | 13s exact interval |

The gate-to-tag interval is the exact implementation-authorized repository
interval for v0.3. It does not include pre-gate planning and does not prove
continuous implementation activity, so total version effort remains unknown.
The exact final qualification window covers only performance evidence
generation and composition; it excludes the broader backend, PostgreSQL,
frontend, browser, security, supply-chain, and package work performed during
the recorded July 13-16 verification range.

### Delivered Outcome

- Added versioned migrations, signed identity and roles, network isolation,
  hash-locked supply chain, reproducible packaging, and fingerprint-bound
  qualification.
- Expanded the restricted data IR with typed state, expressions, deterministic
  branches, bounded loops, and bounded local calls.
- Passed the recorded SQLite/PostgreSQL, browser, accessibility, recovery,
  performance, soak, audit, SBOM, and reproducibility gates.

Records:

- [`PROMPT_History.md`](PROMPT_History.md)
- [`SPELL_v0.3_Pre-Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.3_Pre-Implementation.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`SPELL_v0.3_Release.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.3_Release.md)

## 2026-07-12 - v0.2.0 - Simulator Vertical Slice

| Field | Value |
| --- | --- |
| Release type | First product implementation release |
| Status | Accepted for local simulator development with exceptions |
| Baseline | v0.1 planning baseline |
| Release commit | `7df7743950b8f92fc1700c0005c7ea5bd099d622` |
| Annotated tag | `v0.2.0` |
| Operational authorization | None |

### Milestones

| Milestone | Timestamp or duration | Evidence |
| --- | --- | --- |
| v0.1 baseline approved for bounded v0.2 work | 2026-07-12; exact time not retained | [`Test_and_Integration.md`](Test_and_Integration.md) and [`PROMPT_History.md`](PROMPT_History.md) |
| v0.2 implementation and final verification | 2026-07-12; start time not retained | Version history and test record |
| Earliest immutable v0.2 machine timestamp | 2026-07-12 20:16:14.516807 EDT | Python SBOM metadata timestamp `2026-07-13T00:16:14.516807+00:00` |
| SQLite backend suite | 15.07s | 18 passing tests; recorded test duration |
| PostgreSQL backend suite | 15.73s | 18 passing tests; recorded test duration |
| Real-backend Playwright suite | 18.6s | Eight passing desktop/mobile tests; recorded test duration |
| Release committed | 2026-07-12 21:04:39 EDT | Commit `7df7743` |
| Release tagged | 2026-07-12 21:04:40 EDT | Annotated tag `v0.2.0` |

### Duration Calculations

| Interval | Calculation | Interpretation |
| --- | --- | --- |
| Earliest retained SBOM to tag | 2026-07-12 20:16:14.516807 to 21:04:40 | 48m 25.483193s exact observed evidence window |
| Release commit to annotated tag | 2026-07-12 21:04:39 to 21:04:40 | 1s exact interval |

The v0.2 root commit contains the v0.1 records and the complete v0.2 product
implementation as one consolidated change. Git therefore does not retain a
v0.2 implementation-start commit or intermediate engineering history. The
48-minute interval proves only that immutable release evidence was being
generated before the tag; it is not the total build duration. The actual v0.2
elapsed time and active engineering effort are unknown.

The individually reported test durations must not be added to manufacture a
total. They omit setup, dependency installation, implementation, debugging,
other tests, browser preparation, evidence capture, audits, and packaging, and
may overlap or run in separate environments.

### Delivered Outcome

- Implemented the simulator-only control plane, isolated worker, restricted
  procedure parser, durable persistence, REST/WebSocket contracts, and 2D web
  console.
- Verified execution control, prompts, crash recovery, reconnect/resync,
  as-run reporting, SQLite/PostgreSQL behavior, and desktop/mobile workflows.
- Accepted explicit security, isolation, dependency-hash, manual-keyboard, and
  performance/soak exceptions that became v0.3 prerequisites.

Records:

- [`PROMPT_History.md`](PROMPT_History.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`SPELL_v0.2_Release.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.2_Release.md)

## 2026-07-12 - v0.1 - Pre-Implementation Baseline

| Field | Value |
| --- | --- |
| Release type | Documentation and planning only |
| Status | Planning baseline completed; approved for the bounded v0.2 entry scope |
| Baseline | Supplied legacy evidence and owner requirements |
| Independent commit | None |
| Annotated tag | None |
| Product behavior change | None |
| Operational authorization | None |

### Recorded Work

On 2026-07-12 the project recorded completion of:

- Hashing and inventory of the three supplied legacy archives.
- Review of 716 Core-source entries and 2,322 GUI-distribution entries.
- Review of the then-available embedded Server, GUI, Language, Driver
  Development, and Build manuals plus the draft Server Communication ICD.
- Manual-versus-source comparison, capability inventory, architecture,
  requirements, safety model, risks, migration phases, and test strategy.
- Confirmation that the required Development Environment manual was absent
  from the v0.1 evidence and that legacy test coverage was insufficient for a
  safe rewrite oracle. The separately supplied manual was reviewed on
  2026-07-17 and is recorded as later evidence rather than backdated v0.1 work.
- Owner approval to proceed only to the bounded v0.2 simulator vertical slice.

### Duration Statement

The retained records provide a completion date but no authoritative v0.1 start
timestamp, intermediate commits, independent release commit, or tag. The v0.1
documents first appear in the consolidated v0.2 root commit. Filesystem creation
times in one current workspace are not portable historical evidence and are not
used as a build-duration endpoint.

The actual elapsed time and active effort required to build v0.1 are therefore
unknown. Reporting a minutes-or-hours value would be invented precision.

Records:

- [`PROMPT_History.md`](PROMPT_History.md)
- [`SPELL_v0.1_Pre-Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.1_Pre-Implementation.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)

## Cumulative Release Intervals

| Interval | Elapsed time | Evidence class |
| --- | --- | --- |
| v0.2 tag to v0.3 gate commit | 3m 36s | Exact Git/tag interval |
| v0.2 tag to v0.3 tag | 3d 23h 32m 59s | Exact Git/tag interval |
| v0.4 tag to v0.5 tag | 2d 0h 48m 50s | Exact annotated-tag interval |
| v0.5 qualified-source commit to v0.5 tag | 13m 21s | Exact Git/tag interval; not total implementation effort |
| v0.1 completion date to v0.3 release date | Four calendar days between 2026-07-12 and 2026-07-16; five inclusive calendar dates | Recorded dates only; not an exact elapsed-time interval because v0.1 completion time is absent |

## Known Evidence Gaps

- Git history through tag `v0.3.0` contains only three commits. v0.1 and most
  v0.2 authoring history were consolidated into the v0.2 root commit.
- v0.1 and v0.2 records provide calendar dates but no authoritative start times,
  time sheets, or complete execution timestamps.
- v0.2 stores individual test durations but no aggregate qualification start
  and finish time.
- v0.3 records final verification as July 13-16; exact timestamps exist only for
  the final performance qualification and Git endpoints.
- Repository timestamps measure elapsed calendar intervals, not active work,
  staffing, parallelism, review effort, or person-hours.
- Filesystem modification times, uncommitted screenshots, and an untagged
  release archive alone are not used as historical release evidence.

Future versions should close these gaps by recording approved gate time,
implementation start, verification start/finish, release commit, annotated tag,
and active-effort estimates where the project actually maintains them.

## Timeline Update Policy

Update this file whenever a version is finalized or stronger historical
evidence becomes available.

For each version:

1. Add its newest factual entry above older versions.
2. Record release type, baseline, status, product impact, operational
   authorization, commit, tag, and authoritative record links.
3. Record separate timestamps for request approval, gate completion,
   implementation start, verification start/finish, release commit, and tag
   whenever they exist.
4. Calculate intervals only from stated endpoints and identify whether they are
   exact, date-only, an observed evidence window, or unknown.
5. Keep elapsed calendar time, active engineering time, test runtime, and
   person-hours separate.
6. Never infer missing effort by adding selected test durations or using current
   filesystem timestamps as immutable history.
7. Preserve earlier factual entries. Correct them only with stronger evidence
   and record the reason in the version's authoritative history.
8. Update [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) so the accepted release and
   next candidate remain aligned, without treating this timeline as an
   implementation authorization.
