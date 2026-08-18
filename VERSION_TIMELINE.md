# OpenBEXI SPELL Version Timeline

## Document Control

| Field | Value |
| --- | --- |
| Document revision | Accepted v0.8.0 baseline and v0.9 Gate 0A authorization |
| Update type | Accepted-release timing and bindings plus bounded v0.9 development-environment planning authorization |
| Updated | 2026-08-18 |
| Time zone for local timestamps | America/New_York; EDT (UTC-04:00) for the recorded July and August 2026 events |
| Current accepted product baseline | SPELL v0.8.0, tag `v0.8.0`, tag object `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, release commit `d6e01222de3bf52013279e48a099b6ae7ded121d` |
| v0.3.1 status | Author-recorded documentation set prepared; no release commit or tag claimed |
| v0.4 status | Accepted 2026-08-12; annotated tag `v0.4.0`; Final 74/74 tests and 209/209 assertions passed; no accepted exceptions |
| v0.5 status | Accepted 2026-08-14 at annotated tag `v0.5.0`; scope remains bounded to `V05-IR-001`; no accepted exceptions |
| v0.6 status | Accepted 2026-08-16 at annotated tag `v0.6.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.7 status | Accepted 2026-08-17 at annotated tag `v0.7.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.8 status | Accepted 2026-08-18 at annotated tag `v0.8.0`; nine work packages implemented and qualified; no accepted exceptions |
| v0.9 status | `V09-GATE-0A PASS` recorded 2026-08-18; nine work packages and 45 planned proof identities authorized; no implementation claim |
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
| NG spec 0.1 draft | Next-generation requirements, architecture, web, security, operations, and assurance documentation | Documentation initiative recorded 2026-07-18; exact start time not retained | `0.1.0-draft.1` prepared in the working tree on 2026-07-18; human approval pending | Same calendar day; exact elapsed time and active effort unknown | Author-recorded dates and hash-verified source set; no baseline tag |
| NG-PROT-001 | Isolated RBAC startup-policy prototype | Owner request to move forward recorded 2026-07-18; exact start time not retained | Evaluator and tests passed in the working tree on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Working-tree and test evidence only; no product start, commit, tag, or gate approval |
| NG-PROT-002 | Isolated authenticated startup input-adaptation prototype | Owner request to move forward recorded 2026-07-18; exact start time not retained | Adapter hardening and qualification passed in the working tree on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Working-tree and test evidence only; no product start, commit, tag, or gate approval |
| NG-WP-00 readiness | Gate G0 allocation, validation, and decision package | Owner request to implement the next step recorded 2026-07-18; exact start time not retained | Gate G0 passed under pinned Python 3.13 on 2026-07-18 | Same calendar day; exact elapsed time and active effort unknown | Digest-bound working-tree evidence; no product delivery, release, operational, or compliance claim |
| NG-WP-00 compatibility seed | Candidate v0.4 Driver/Server source-assertion decomposition | Roadmap-directed continuation recorded 2026-07-18; exact start time not retained | 62-row partial seed and digest reconciliation prepared in the working tree on 2026-07-18; exhaustive gate remains incomplete | Same calendar day; exact elapsed time and active effort unknown | Working-tree evidence only; no row approval, product start, commit, tag, or gate pass |
| NG-WP-00 example index | Seven-source registration and exact Language Reference example identity indexing | Owner request to complete v0.4 before v0.5 recorded 2026-07-18; exact start time not retained | 195 example indexes plus the prior 62 decomposed Driver/Server rows reconciled in the working tree on 2026-07-18; example bodies/oracles and the exhaustive gate remain incomplete | Same calendar day; exact elapsed time and active effort unknown | Working-tree evidence only; no semantic example decomposition, fixture/result evidence, row approval, product start, commit, tag, or gate pass |

## 2026-08-18 - v0.8.0 Accepted And v0.9 Gate 0A

| Field | Value |
| --- | --- |
| Accepted release | SPELL v0.8.0, annotated tag `v0.8.0` |
| Tag object and time | `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`; 2026-08-18 15:48:51 EDT; raw tag-object SHA-256 `c609c25cb8987222df0b143f71aa792140171acffd454e31a760c16fb263eede` |
| Release commit and time | `d6e01222de3bf52013279e48a099b6ae7ded121d`; committed 2026-08-18 15:47:12 EDT |
| Qualified source | `d80c4d43969018633bc17650a23412b7274e58ea`; committed 2026-08-18 15:13:17 EDT; source fingerprint `6eafe23737e266f0038930703656eb569b5e321d718dfef218a1448c3b2f5268`; product fingerprint `c6f835a5fcc6289408493e68d866493b882bf00139a83ea3709283745a1a4554` |
| Candidate and work-package evidence | `f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c`; nine packages/45 identities PASS; evidence SHA-256 `5fdfa848edf1bdfa8b3b2a161e4dc2c1a356a95cfc424e0e079e5719b1d046d7` |
| Final qualification | PASS; nine suite captures, 2,676 concrete tests, 2,661 passes, 15 exact SQLite environment skips, 36 subtests, zero failures/errors |
| Supply chain and package | PASS; four image-bound SBOMs, zero High/Critical findings, zero unlocked inputs; archive SHA-256 `87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb` |
| Release evidence | Manifest SHA-256 `82e90f0d3a9481423d948d83559bde56ff332833f14ab2d01a8089ebf6a5e50e`; evidence fingerprint `6a8f5446aeee9084ef58c9ec2323d6e1d2f8e957cb07e21f46ab9300fab5b1ae`; strict tag validation PASS |
| Accepted scope and exceptions | `V08-DATA-001` through `V08-DATA-009`; no accepted exceptions |
| v0.9 owner request | `start and complete asap V0.9` |
| v0.9 Gate 0A | `V09-GATE-0A PASS`; `V09-DEV-001` through `V09-DEV-009` and 45 planned proof identities authorized under `LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT` |
| v0.9 gate marker | `gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0` |
| v0.9 status at Gate 0A | Not implemented, qualified, released, or accepted; no operational authorization or compliance determination |

The annotated v0.8.0 tag activated the conditional acceptance recorded in the
release commit without a post-tag documentation commit. The v0.9 Gate 0A
record independently binds that accepted baseline and its exact planning
contracts. It authorizes bounded implementation entry only.

## 2026-08-17 - v0.8 Worktree Implementation And Candidate Preparation

| Field | Value |
| --- | --- |
| Accepted baseline | SPELL v0.7.0, annotated tag `v0.7.0`, unchanged |
| Gate 0A | `V08-GATE-0A PASS` at commit `451c065740e7b6501f86094d9be79578b30b1591`; nine packages and 45 planned proof identities authorized |
| Latest implemented version | SPELL v0.8 Data and Local Service Compatibility in the current worktree |
| Implemented scope | `V08-DATA-001` through `V08-DATA-009`: typed values/catalogs/dictionaries/containers, shared data, virtual files, authorized local API, durable mutation/audit/outbox, migration and recovery, Data Service frontend, and release tooling |
| Pre-candidate verification | Backend and frontend implementation verification PASS in the mutable worktree; frontend unit tests and production build included; exact canonical aggregate deferred to source freeze |
| Pending endpoints | Candidate commit, canonical work-package qualification, Gate 0B, Final qualification, SBOM/supply-chain evidence, deterministic package and sidecar, release commit, and annotated `v0.8.0` tag |
| Accepted release status | v0.7.0 remains accepted; no v0.8 release or acceptance claim |
| v0.9 status | Requested-only; no completed Gate 0A or implementation claim |
| Operational authorization or compliance determination | None |

This entry records mutable worktree status only. It does not provide an
immutable duration endpoint, canonical candidate evidence, or release
authority. The Gate 0A event below remains the authorization-time record.

## 2026-08-17 - v0.7.0 Accepted And v0.8 Gate 0A

| Field | Value |
| --- | --- |
| Accepted release | SPELL v0.7.0, annotated tag `v0.7.0` |
| Tag object and time | `70e4d46a46d158dee3c63ec37a5d1922b3b61668`; 2026-08-17 04:57:47 EDT; raw tag-object SHA-256 `dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae` |
| Release commit and time | `cf18e9d887ba0476cbcc3d8194e321332a3ae864`; committed 2026-08-17 04:51:42 EDT |
| Qualified source | `6ac43c5be7670ead09de821578cc6c6a680af109`; committed 2026-08-16 21:22:14 EDT; source fingerprint `a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb`; product fingerprint `fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633` |
| Candidate and work-package evidence | `82b497227aff097db9d4c3ff56adf56d76d892ca`; ten suites/45 identities PASS; evidence SHA-256 `04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20` |
| Final qualification | PASS; nine suite captures, 2,041 concrete tests, 2,034 passes, seven exact SQLite environment skips, 36 subtests, zero failures/errors |
| Supply chain and package | PASS; four image-bound SBOMs, zero High/Critical findings, zero unlocked inputs; archive SHA-256 `90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2` |
| Release evidence | Manifest SHA-256 `e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a`; evidence fingerprint `7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718`; strict tag validation PASS |
| Accepted scope and exceptions | `V07-OBS-001` through `V07-OBS-009`; no accepted exceptions |
| v0.8 Gate 0A | `V08-GATE-0A PASS`; `V08-DATA-001` through `V08-DATA-009` and 45 planned proof identities authorized under `LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE` |
| v0.8 gate marker | `gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0` |
| v0.8 status at the Gate 0A decision | Not implemented, not qualified, not released, and not accepted at that event |
| v0.9 status | Requested-only; no completed Gate 0A or implementation claim |
| Operational authorization or compliance determination | None |

The annotated v0.7.0 tag activated the conditional acceptance recorded in the
release commit without a post-tag documentation commit. The v0.8 Gate 0A
record independently binds that accepted baseline and nine planning-contract
files. Its approval is limited to the nine explicit work packages and creates
no product, live/legacy integration, deployment, operational, compliance, or
cryptographic-signature claim.

## 2026-08-16 - v0.7 Candidate Qualification And Gate 0B

| Field | Value |
| --- | --- |
| Accepted baseline | SPELL v0.6.0, annotated tag `v0.6.0`, unchanged |
| Latest implemented version | Qualified SPELL v0.7 candidate implementing `V07-OBS-001` through `V07-OBS-009` |
| Candidate source | `82b497227aff097db9d4c3ff56adf56d76d892ca`; tree `2f553c152ce103c7ded70af811f2f84257f7c1b5`; sole parent `07c19437d28bc32a88d9970a4104d6c0fde53073` |
| Canonical work-package evidence | `artifacts/v0.7/work-package/qualification.json`; SHA-256 `04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20` |
| Candidate qualification | PASS; ten suites, 45 mapped identities, 2,070 concrete tests, 2,051 passes, 19 explicit suite-level platform skips, 36 subtests, zero failures/errors |
| Identity and package disposition | Zero mapped skips, failures, accepted failures, or waivers; all nine packages `IMPLEMENTED_AND_QUALIFIED` |
| Gate 0B result | PASS; `gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED` |
| Pending v0.7 endpoints | Final qualification, SBOM and supply-chain evidence, deterministic package and sidecar, release commit, and annotated `v0.7.0` tag |
| Subsequent owner direction | Finish v0.7, then v0.8, then v0.9; Markdown table repair and living-document synchronization also requested |
| v0.8/v0.9 status | Requested follow-on only; no completed Gate 0A, implementation, qualification, release, or acceptance claimed |
| Operational authorization or compliance determination | None |

Gate 0B authorizes release closeout only and does not accept or release v0.7.
The qualified v0.7 candidate is the latest implementation, while v0.6.0
remains the accepted baseline until every v0.7 release condition and tag
validation passes.

## 2026-08-16 - v0.6.0 Accepted And v0.7 Gate 0A

| Field | Value |
| --- | --- |
| Accepted release | SPELL v0.6.0, annotated tag `v0.6.0` |
| Tag object and time | `b6dc64dc8fb6cfe9845f454904a078ec6f3c0919`; 2026-08-16 13:50:02 EDT |
| Release commit and time | `05ec783a6e54a76e0548bdd536c18538f6bff51b`; committed 2026-08-16 13:45:56 EDT |
| Qualified source | `8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213`; committed 2026-08-16 13:19:01 EDT |
| Candidate and work-package evidence | `0ea26105e72d7830de4a265989ed7d9074ffbe09`; ten suites/45 identities PASS; evidence SHA-256 `16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538` |
| Final qualification | PASS; nine suite captures, 1,626 concrete tests, 1,620 passes, six exact SQLite environment skips, 36 subtests, zero failures/errors |
| Supply chain and package | PASS; four image-bound SBOMs, zero High/Critical findings, zero unlocked inputs; archive SHA-256 `b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c` |
| Accepted scope and exceptions | `V06-OP-001` through `V06-OP-009`; no accepted exceptions |
| v0.7 Gate 0A | `V07-GATE-0A PASS`; `V07-OBS-001` through `V07-OBS-009` and 45 planned proof identities authorized |
| v0.7 planning verification | Exact validator marker PASS; 22 adversarial Gate tests and eight semantic contract tests PASS under locked Python 3.13.14 |
| v0.7 implementation/release status at Gate 0A | Not implemented, not qualified, and not accepted |
| Operational authorization or compliance determination | None |

The annotated v0.6.0 tag activated the conditional acceptance recorded in the
release commit without a post-tag documentation commit. The v0.7 Gate 0A
record independently binds that accepted baseline and seven planning-contract
files. Its approval is limited to the nine explicit work packages; the gate
itself creates no product, live/legacy integration, deployment, operational,
compliance, or cryptographic-signature claim. The later committed candidate
recorded above does not rewrite that gate-time fact.

## 2026-08-16 - v0.6 Candidate Qualification And Gate 0B

| Field | Value |
| --- | --- |
| Accepted baseline | SPELL v0.5.0, annotated tag `v0.5.0`, unchanged |
| Candidate commit | `0ea26105e72d7830de4a265989ed7d9074ffbe09` |
| Canonical work-package evidence | `artifacts/v0.6/work-package/qualification.json`; SHA-256 `16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538` |
| Candidate qualification | PASS; ten suites, 45 identities, zero mapped skips, failures, accepted failures, or waivers |
| Gate 0B result | PASS; `gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED` |
| Work-package disposition | All nine `V06-OP-001` through `V06-OP-009` work packages are `IMPLEMENTED_AND_QUALIFIED` |
| Pending release endpoints | Final qualification, four v0.6 SBOMs, supply-chain evidence, deterministic package and committed sidecar, release commit, annotated `v0.6.0` tag |
| Operational authorization or compliance determination | None |

Gate 0B authorizes release closeout only; it does not accept or release v0.6.
The historical Gate 0A section below remains its gate-time authorization record
and is not rewritten by this later candidate result.

## 2026-08-15 - v0.5.0 Accepted Baseline And v0.6 Gate 0A

| Field | Value |
| --- | --- |
| Current accepted release | SPELL v0.5.0, annotated tag `v0.5.0` |
| Tag object | `a1b277d74d2fb19062ca3e4388e9104d45c50ec4`; created 2026-08-14 22:22:33 EDT |
| Release commit | `e7b6bb9428833437e0160040541eb840deee7cca`; committed 2026-08-14 22:20:08 EDT |
| Qualified source | `2f31e6a011b8aad63b29bd55780c37c1b68712f1`; committed 2026-08-14 22:09:12 EDT |
| Final validation | PASS; 1,096 concrete tests, 1,090 passes, six exact approved SQLite environment skips, 36 subtests, zero failures/errors |
| Supply chain and package | PASS; four image-bound SBOMs, zero High/Critical findings, archive SHA-256 `cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241` |
| Accepted scope and exceptions | `V05-IR-001` only; no accepted exceptions |
| v0.6 owner direction | Finish v0.6; explicitly approve `V06-OP-001` through `V06-OP-009` |
| v0.6 status | Bounded candidate and ten-suite/45-ID closeout contract prepared; Gate 0B, release, and tag pending |
| Operational authorization or compliance determination | None |

This section reconciles the now-verifiable tag result and the later explicit
v0.6 Gate 0A approval; it does not rewrite the
2026-08-13 Gate 0B record below. That earlier section correctly describes the
conditional state at its recorded date. The annotated tag later activated the
conditional acceptance without requiring a post-tag documentation commit.

## 2026-08-13 - v0.5 Gate 0B And Release Closeout

| Field | Value |
| --- | --- |
| Release type | Bounded product release closeout candidate |
| Status | `V05-GATE-0B PASS`; closeout authorized for `V05-IR-001`; Final release acceptance pending |
| Accepted baseline | Annotated tag `v0.4.0`; release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Gate 0A | PASS at commit `d13397f51241c6bac10289ea21b69aafff66b1fb` |
| Qualified candidate | `aefa658ce01d49a7879d0471b50425ac3bcf9e2d` |
| Qualification correction/source | `ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`; test-only Docker inspection timeout metadata correction |
| Product metadata | `0.5.0` for Python/backend/frontend package identity |
| Preserved compatibility | IR 0.3, API v1, report schema 0.3, driver contract `spell.driver.v1`, driver implementation/default `0.4.0` |
| Live canonical candidate evidence | PASS; SHA-256 `86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`; 4 suites, 6 identities, 949 concrete tests |
| Live Gate 0B validator | PASS; `gate=PASS work_packages=1 identities=6 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED` |
| Final release commit or tag | None |
| Operational authorization or compliance determination | None |

Gate 0B resolves the owner's bounded tag request to one annotated `v0.5.0`
tag and authorizes the remaining release-record, evidence, supply-chain,
package, commit, and tag work. It does not accept the release. Product metadata
can identify the closeout candidate as `0.5.0`, but accepted release status
continues to derive from the immutable v0.4.0 tag until the remaining v0.5
controls pass against a fixed release commit and the verified `v0.5.0` tag
makes the conditional acceptance effective. That tag is the final condition;
no post-tag documentation commit is required.

The bundled driver retains implementation/default identity `0.4.0` because the
v0.5 work package does not change driver code or contract. This is a preserved
subsystem compatibility identity, not a stale product-version marker.

Pending endpoints are the supply-chain result, four distinct image-bound SBOMs,
byte-identical source package and committed sidecar, complete Final validation,
exact release commit, and verified annotated tag. No defensible closeout
duration can be calculated until those endpoints exist.

Records:

- [`SPELL_v0.5_Gate_0B.md`](SPELL_v0.5_Gate_0B.md)
- [`SPELL_v0.5_Release.md`](SPELL_v0.5_Release.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`PROVENANCE.md`](PROVENANCE.md)

## 2026-08-12 - v0.5 Gate 0A

| Field | Value |
| --- | --- |
| Release type | Bounded product pre-implementation gate |
| Status | `V05-GATE-0A PASS`; candidate implementation committed and locally verified; completion not claimed |
| Accepted baseline | Annotated tag `v0.4.0`; tag object `86390c90e8d5f96f872be43274cbc9d789a34c2d`; peeled release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Authorized work | `V05-IR-001` existing IR 0.3 fail-closed validation hardening only |
| Candidate result | Commit `aefa658ce01d49a7879d0471b50425ac3bcf9e2d`; configured backend/driver-host pytest passed 328 tests with 18 environment-only skips; PostgreSQL evidence pending |
| New language/API/schema/frontend/dependency/driver/operational scope | None |
| v0.5 release commit or tag | None |
| Operational authorization or compliance determination | None |

Gate 0A binds the raw annotated-tag SHA-256, tagged v0.4 release record,
compatibility ledger and v0.4 scope hashes, required tag-message markers, one
work package, zero claimed constructs, zero claimed artifacts, and the six
planned `V05-IR-001-*` test identities. It authorizes strict independent IR
0.3 validation/canonicalization, parser postvalidation, persisted supervisor
preflight before worker generation or process creation, worker preflight
before `worker.started` or effect, valid persisted-byte preservation without
migration, and adversarial/golden tests.

The gate does not authorize the broader candidate v0.5 language properties,
source-to-IR reparse/integrity expansion, or any public contract or operational
change. The authorized work later produced a candidate commit that passed local
verification plus the unchanged Gate 0A validator. PostgreSQL, Linux metadata,
and opt-in Compose checks remain unexecuted or skipped. Because all six planned
identities have not passed, the record does not claim `V05-IR-001` implemented,
accepted, or released. The gate start has no exact timestamp, so total elapsed
time and active effort remain unknown.

Records:

- [`SPELL_v0.5_Pre-Implementation.md`](SPELL_v0.5_Pre-Implementation.md)
- [`PROMPT_History.md`](PROMPT_History.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md)

## 2026-08-12 - v0.4.0 - Typed Simulator Driver And Context Foundation

| Field | Value |
| --- | --- |
| Release type | Product engineering release |
| Status | Accepted local-only synthetic non-CUI simulator release |
| Release commit | `4546d313a2d8f50504b2bc602d56b3b459ca7597` at 2026-08-12 21:32:56 EDT |
| Annotated tag | `v0.4.0`; tag object `86390c90e8d5f96f872be43274cbc9d789a34c2d`; tagged 2026-08-12 21:33:43 EDT |
| Final validation | PASS; 74/74 tests and 209/209 assertions |
| Accepted exceptions | None |
| Operational authorization or compliance determination | None |

The accepted release delivered the bounded Candidate A typed simulator driver
and context foundation. The exact tag-to-commit interval is 47 seconds. The
candidate-source commit `f9a2cdb` at 04:35:47 EDT to tag interval is 16h 57m
56s; it is a final repository evidence window, not total implementation time.
The gate began on a date-only record, so total gate-to-release elapsed time and
active engineering effort remain unknown.

Records:

- [`SPELL_v0.4_Release.md`](SPELL_v0.4_Release.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)

## Historical v0.4 Gate Milestones

This is the preserved planning record as it stood before the accepted v0.4.0
release entry above. Its pending language is historical, not current status.

| Field | Value |
| --- | --- |
| Planning target | SPELL v0.4.0 - Typed Simulator Driver and Context Foundation |
| Accepted baseline | Commit `7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`, tag `v0.3.0` |
| Next-step request recorded | 2026-07-17; exact time not retained |
| Candidate A gate drafted | 2026-07-17; exact time not retained |
| Seven supplied PDFs and 304 pages reviewed | 2026-07-17; exact time not retained |
| Documentation-conformance rebaseline prepared | 2026-07-17; exact time not retained |
| Next-generation design specification `0.1.0-draft.1` prepared | 2026-07-18; exact time not retained |
| Compatibility ledger | Exhaustive seven-source catalog covers all 304 pages and 195 exact Language Reference examples; independent review and final digest pins pass for 1,682 rows, with 125 v0.4 and 1,557 Deferred |
| Gate decision | `V04-GATE-0 PASS`; Candidate A scope, exclusions, budgets, and test plan owner-approved; exact manifest and Python 3.13 qualification verified |
| Product implementation | Authorized to begin; not yet delivered or accepted |
| Isolated experimental prototypes | `NG-PROT-001` and bounded continuation `NG-PROT-002` prepared outside the product runtime; not a v0.4 or `NG-WP-01` start |
| Local Gate G0 readiness | Broader 366-row allocation generated as `OUTSIDE_LOCAL_V04_GATE`; compatibility validation, independent review, owner manifest, and final report qualification pass; G0 `PASS` |
| Mandatory next step | Implement the exact Candidate A slice and execute Gates 1-5; record v0.4 acceptance only if every required gate passes |
| Product behavior/API/schema/dependency change | None from gate drafting |
| Release commit or tag | None |
| Operational authorization | None |

Draft records:

- [`PROMPT_History.md`](PROMPT_History.md)
- [`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md)
- [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md)
- [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md)

Duration statement:

- The retained repository records establish only the calendar date of the
  request and draft. They do not retain exact intra-day endpoints, active
  planning effort, or an immutable gate commit.
- PDF hashes and page counts identify the reviewed inputs, but do not prove the
  exact review start, finish, active effort, or person-hours.
- Product implementation is authorized but has not yet been delivered, so no
  v0.4 build duration, release completion, or acceptance duration exists.
- The working-tree Gate 0 evidence establishes the authorization date as
  2026-07-18 but not an exact intra-day time. A later commit may anchor the
  evidence immutably but must not be represented as the original gate time.

## 2026-07-18 - Local v0.4 Candidate A Gate Revision

| Field | Value |
| --- | --- |
| Activity type | Local product engineering gate revision and technical compatibility preparation |
| Scope | Candidate A, local-only, synthetic non-CUI simulator |
| Owner decision | JC Arcaz approved Candidate A, its exclusions, budgets, and test plan |
| Required approval roles | Project owner only |
| Organization-only decisions | Retained in broader records; outside local v0.4 Gate 0 |
| Product behavior/API/schema/dependency change | None yet |
| Gate state | `PASS`; owner scope decision, compatibility review, exact manifest binding, and pinned Python 3.13 qualification verified |
| Operational authorization or compliance determination | None |

The revision preserves the exact nine-RPC typed simulator lifecycle boundary,
synthetic-only endpoint resolution, bounded non-executing IR and strict mTLS
credential separation, fail-closed authentication, lifecycle/idempotency/
certainty behavior, migrations and rollback, security/supply-chain checks,
v0.3 regression, and evidence-bound release acceptance. It removes broader
organization, mission, protected-data, assessment, deployment, proposed-ADR,
and role-signature requirements from the local gate.

The exhaustive seven-source catalog covers all 304 pages and all 195 Language
Reference examples. Every row targets Candidate A or Deferred/`EXCLUDE` and has
a unique planned test identity. Deterministic validation and independent review
pass for all 1,682 rows. Deferred rows are static source and negative-scope
evidence, not implementations or executed semantic oracles. Exact owner-record
manifest binding and qualification under Python 3.13.14 pass; the compatibility
and G0 suites report 21 and 17 passing tests respectively. No commit, tag,
release, operational, deployment, or compliance claim is made by this entry.

## 2026-07-18 - NG-WP-00 Language Example Index

| Field | Value |
| --- | --- |
| Activity type | Documentation-conformance identity indexing; not semantic decomposition or product implementation |
| Status | Seven-source, 257-row partial increment structurally reconciled; exhaustive compatibility and Gate G0 remain blocked |
| Source scope | All seven source records, exact number/title/page indexes for 195 Language Reference examples, and the prior 40 Driver plus 22 Server decomposed assertions |
| Product behavior/API/schema/dependency change | None |
| Product implementation authorization | None |
| Commit or tag | None |
| Operational authorization or compliance determination | None |

Bounded result:

- Expanded the source inventory from two to all seven authoritative records.
- Added exact number/title/page indexes for all 195 sequential Language Reference
  examples for 257 total canonical rows with all 25 required fields.
- Retained the prior 40 Driver and 22 Server assertions without claiming their
  catalogs complete.
- Kept the 195 example rows `Indexed`, `AMBIG`, and target `Unassigned`, with
  bodies/oracles, effects/capabilities, fixtures, and results pending `OD-008`.
  The 62 Driver/Server rows remain `Decomposed` for v0.4. Every row remains
  `PENDING_HUMAN_APPROVAL`; scope and global reconciliation remain false.
- Updated the digest-pinned validator, adversarial tests, reconciliation, and G0
  readiness report.

Verification recorded on 2026-07-18 with the pinned Python 3.13 image:

- Compatibility validator: candidate scope `RECONCILED`, 257 rows, 195
  examples `Indexed`, 62 Driver/Server rows `Decomposed`, global scope
  `INCOMPLETE`, approval pending.
- Compatibility and G0 validator suites: 30 passed.
- G0 structural result: `PASS`; gate result: `BLOCKED`; the default command
  returned the expected blocked exit code 2.

The non-example Language Reference catalog, complete Driver and Server
catalogs, and detailed GUI, Development Environment, Build, and GUI 4.0.2
catalogs remain open. This activity does not complete `COMP-001`, `NG-WP-00`,
`V04-GATE-0`, or G0 and does not start product implementation.

## 2026-07-18 - NG-WP-00 Candidate v0.4 Compatibility Seed

| Field | Value |
| --- | --- |
| Activity type | Documentation-conformance decomposition; not product implementation |
| Status | Partial Candidate v0.4 seed structurally reconciled; exhaustive compatibility and Gate G0 remain blocked |
| Source scope | Selected Driver Development Manual and Server Manual assertions |
| Product behavior/API/schema/dependency change | None |
| Product implementation authorization | None |
| Commit or tag | None |
| Operational authorization or compliance determination | None |

Bounded result:

- Added a source-bound inventory, canonical 25-field ledger, explicit Candidate
  v0.4 partial scope, and input-digest reconciliation record.
- Decomposed 62 unique assertions: 40 Driver Manual lifecycle, registry,
  callback, failure, accessor, and configuration rows plus 22 Server Manual
  configuration and startup rows.
- Added a dedicated validator and adversarial tests for source identity, page
  bounds, exact keys, cross-file membership, counts, approval spoofing, and
  reconciliation freshness.
- Kept every row `Decomposed` and `PENDING_HUMAN_APPROVAL`; both full-scope
  reconciliation flags remain false.

Verification recorded on 2026-07-18 with pinned Python 3.13.14:

- Compatibility validator: partial seed `RECONCILED`, 62 rows, global scope
  `INCOMPLETE`, approval pending.
- Compatibility adversarial suite: 11 passed.
- Integrated G0 validator suite: 15 passed.
- G0 structural result: `PASS`; gate result: `BLOCKED`; the default command
  returned the expected blocked exit code 2.
- Current documentation checks: 45/45 Markdown paths, 152 tables, 135 relative
  links, 63 ASCII-controlled artifacts, seven source hashes, and 304 pages.

The other five sources, complete Driver and Server catalogs, and all normative
examples remain open. This activity does not complete `COMP-001`, `NG-WP-00`,
`V04-GATE-0`, or G0 and does not start `NG-WP-01` or product implementation.

## 2026-07-18 - NG-WP-00 Gate G0 Readiness Scaffolding

| Field | Value |
| --- | --- |
| Activity type | Specification traceability and approval readiness; not product implementation |
| Status | Structural evidence prepared and checked; Gate G0 `BLOCKED` |
| Governing baseline | Next-generation specification `0.1.0-draft.1`; Draft and human approval pending |
| Product behavior/API/schema/dependency change | None |
| Product implementation authorization | None |
| Commit or tag | None |
| Operational authorization or compliance determination | None |

Bounded result:

- Added controlled allocation rules and generated one row bound to the canonical
  record digest for each of 366 central requirements, including owner, design,
  primary/supporting work packages, phases, verification method, planned
  test/result target, gates, and approval relation.
- Added a separate empty unsigned human-evidence ledger and a deterministic
  validator with twelve tests covering register/allocation identity, exact
  package/gate mapping, approval and baseline-binding spoofing, approver
  validation, canonical report output, empty compatibility evidence, and
  mandatory blocked-gate behavior.
- Added a machine-readable readiness report and human decision package for the
  startup role/mode matrix, signed bootstrap, session and lease parameters,
  two-party handover, stage-specific audit, `DOC-011`, and Phase-entry closure.
- Tightened the Draft multi-role rule so an unapproved recommendation cannot
  silently select a mode, and made server signing plus `OD-005` dependencies
  explicit.

Verification recorded on 2026-07-18:

- G0 validator structural result: `PASS`; gate result: `BLOCKED`.
- Central requirements/allocation: 366/366 across 15 families; no missing,
  duplicate, extra, or non-contiguous ID.
- Documentation checks: 45/45 Markdown paths allocated, 151 tables, 124
  relative-link paths, 57 ASCII-controlled text artifacts, seven unique source
  hashes with a 304-page reconciliation, and
  two state-model requirement references passed.
- Validator unit tests: 12 passed.
- Default G0 validation returns the expected blocked exit; only explicit
  `--structural-only` execution returns zero for structural checks.

The blockers are ten open Phase-entry decisions, 366 pending requirement
approvals, six composite owner rows, 12 unnamed signers, five Proposed ADRs,
incomplete exhaustive compatibility coverage and approval, no approved signed
baseline/manifest, and no trusted signature verifier for the unsigned approval
overlay.
This activity does not complete `NG-WP-00`, pass G0, start `NG-WP-01`, change
v0.3.0/v0.4 product scope, support a NIST compliance claim, or authorize
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
- [`SPELL_v0.3_Pre-Implementation.md`](SPELL_v0.3_Pre-Implementation.md)
- [`Test_and_Integration.md`](Test_and_Integration.md)
- [`SPELL_v0.3_Release.md`](SPELL_v0.3_Release.md)

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
- [`SPELL_v0.2_Release.md`](SPELL_v0.2_Release.md)

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
- [`SPELL_v0.1_Pre-Implementation.md`](SPELL_v0.1_Pre-Implementation.md)
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
