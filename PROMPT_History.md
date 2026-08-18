# Prompt History

This document records approved project requests, planning decisions, delivery
status, and unresolved issues by OpenBEXI SPELL version. The current version is
inserted at the top so it is visible first; earlier entries retain their original
delivery order. Later versions may supersede a decision but must not rewrite an
earlier request or result.

## 2026-08-18 - v0.8.0 Accepted And v0.9 Gate 0A Approved

### v0.8.0 Accepted Release

The conditional v0.8.0 acceptance recorded in release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d` became effective when the project
owner created and strictly verified annotated tag `v0.8.0` on 2026-08-18. Tag
object `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, raw tag-object SHA-256
`c609c25cb8987222df0b143f71aa792140171acffd454e31a760c16fb263eede`, peels
to that release commit and binds qualified source
`d80c4d43969018633bc17650a23412b7274e58ea`, candidate
`f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c`, source fingerprint
`6eafe23737e266f0038930703656eb569b5e321d718dfef218a1448c3b2f5268`,
product fingerprint
`c6f835a5fcc6289408493e68d866493b882bf00139a83ea3709283745a1a4554`, and
evidence fingerprint
`6a8f5446aeee9084ef58c9ec2323d6e1d2f8e957cb07e21f46ab9300fab5b1ae`.

Final qualification passed nine suite captures with 2,676 concrete tests,
2,661 passes, 15 exact SQLite environment skips, 36 subtests, and zero
failures or errors. Four distinct image-bound SBOMs, the supply-chain audit,
and deterministic packaging passed with zero High or Critical findings and
zero unlocked inputs. Release-manifest SHA-256 is
`82e90f0d3a9481423d948d83559bde56ff332833f14ab2d01a8089ebf6a5e50e`, and
final archive SHA-256 is
`87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb`.
Strict release and annotated-tag validation passed with no accepted exceptions.

### v0.9 Owner Direction And Gate 0A Approval

The owner request was recorded exactly as: `start and complete asap V0.9`.
The accepted v0.8.0 tag satisfies the baseline precondition, and
[`SPELL_v0.9_Pre-Implementation.md`](SPELL_v0.9_Pre-Implementation.md) maps
that direction to exactly `V09-DEV-001` through `V09-DEV-009` and 45 planned
proof identities under
`LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT`. `V09-GATE-0A PASS` is
planning and implementation-entry authorization only. Its exact marker is
`gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0`.
At this event no v0.9 source, API, schema, migration, dependency, runtime
artifact, executed product test, candidate evidence, Gate 0B, qualification,
release, deployment, cryptographic-signature, compliance, or operational claim
exists.

## 2026-08-17 - v0.8 Worktree Implementation And Candidate Preparation

The owner direction to finish v0.8 after accepted v0.7.0 remains bounded by
`V08-GATE-0A PASS` and the exact `V08-DATA-001` through `V08-DATA-009`
contracts. Subsequent work implemented those nine local synthetic non-CUI data
service packages in the current worktree: canonical typed values, scoped and
revisioned catalogs/dictionaries/containers, DB/IMP exchange, procedure
`ARGS`/`IVARS` and dictionary file operations, shared data, virtual-root files,
authorization-scoped APIs, durable mutation/audit/outbox behavior, ordered
SQLite/PostgreSQL migration and recovery, backup/restore, the Data Service web
workspace, and version-scoped qualification/release tooling.

Backend and frontend pre-candidate verification passed during implementation,
including frontend unit tests and the production build. Exact canonical totals
are deliberately deferred until source freeze and qualification. No v0.8
candidate commit or canonical work-package evidence is claimed yet;
`V08-GATE-0B` remains `PENDING_CANDIDATE`, and Final qualification, SBOM and
supply-chain evidence, deterministic packaging, the release commit, and
annotated tag `v0.8.0` remain pending. SPELL v0.7.0 remains the accepted
baseline. v0.9 remains requested-only with no completed Gate 0A or
implementation claim.

## 2026-08-17 - v0.7.0 Accepted And v0.8 Gate 0A Approved

### v0.7.0 Accepted Release

The conditional v0.7.0 acceptance recorded in release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864` became effective when the project
owner created and strictly verified annotated tag `v0.7.0` on 2026-08-17. Tag
object `70e4d46a46d158dee3c63ec37a5d1922b3b61668`, raw tag-object SHA-256
`dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae`, peels
to that release commit and binds qualified source
`6ac43c5be7670ead09de821578cc6c6a680af109`, candidate
`82b497227aff097db9d4c3ff56adf56d76d892ca`, source fingerprint
`a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb`,
product fingerprint
`fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633`, and
evidence fingerprint
`7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718`.

Final qualification passed nine suite captures with 2,041 concrete tests,
2,034 passes, seven exact SQLite environment skips, 36 subtests, and zero
failures or errors. Four distinct image-bound SBOMs, the supply-chain audit,
and deterministic packaging passed with zero High or Critical findings and
zero unlocked inputs. Release-manifest SHA-256 is
`e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a`, and
final archive SHA-256 is
`90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2`.
Strict release and annotated-tag validation passed with no accepted exceptions.

### v0.8 Owner Direction And Gate 0A Approval

Following accepted v0.7.0, the owner direction to proceed to v0.8 authorized
the bounded Data and Local Service Compatibility gate recorded in
[`SPELL_v0.8_Pre-Implementation.md`](SPELL_v0.8_Pre-Implementation.md).
`V08-GATE-0A PASS` authorizes exactly `V08-DATA-001` through `V08-DATA-009`
and their 45 planned proof identities under
`LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE`. The exact marker is
`gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0`.
At the Gate 0A decision, this was planning and implementation-entry
authorization only: it claimed no v0.8 source, API, schema, migration,
dependency, runtime artifact, executed product test, qualification, release,
operational authorization, compliance determination, or acceptance. The later
worktree implementation event above preserves rather than rewrites that
gate-time result. v0.9 remains requested-only with no completed Gate 0A or
implementation claim.

## 2026-08-16 - v0.7 Candidate Qualified And Gate 0B Passed

Canonical candidate qualification passed for commit
`82b497227aff097db9d4c3ff56adf56d76d892ca`, directly over the v0.7 Gate 0A
commit. The evidence at `artifacts/v0.7/work-package/qualification.json` has
SHA-256
`04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20`.
All ten suites and all 45 mapped identities PASS. The 2,070-test aggregate
contains 2,051 passes, 19 explicit suite-level platform skips, 36 subtests,
and zero failures or errors; no mapped identity is skipped, failed, accepted as
failed, or waived.

All nine `V07-OBS-001` through `V07-OBS-009` packages are
`IMPLEMENTED_AND_QUALIFIED`. Gate 0B passed with the exact marker
`gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED`.
This authorizes deterministic release closeout only. Final qualification,
SBOMs, supply-chain evidence, the deterministic package and sidecar, release
commit, and annotated `v0.7.0` tag remain pending. SPELL v0.6.0 remains the
accepted baseline. The requested v0.8 and v0.9 follow-ons remain ungated and
unimplemented.

## 2026-08-16 - Documentation Repair And v0.7-v0.9 Direction

The owner request was recorded exactly as: `table are not correctly formated
for some md file like SPELL_v0.7_Release.md. fix that. make sure to update all
docs as well regarding last version implemented. then resume and finish up
V0.7 asap, asap. once done finish up V0.8 and v0.9 asap. You have all
approvals.` This directs repair of malformed Markdown tables, synchronization
of living documentation with the latest implemented version, completion of
v0.7, and then bounded v0.8 and v0.9 work. At this event, v0.7 is the latest
committed implementation candidate; its canonical qualification, Gate 0B,
Final evidence, release, and tag remain pending. v0.8 and v0.9 are requested
follow-on versions and are not represented as gated, implemented, qualified,
released, or accepted.

## 2026-08-16 - v0.7 Candidate Committed, Qualification Pending

The owner direction remained the explicit authorization recorded by Gate 0A.
The nine approved simulator read-only observation packages were implemented
and committed as the current candidate,
including additive driver time and telemetry reads, durable projections and
conditions, brokered `GetTM`/`Verify`/`WaitFor`, telemetry schedules, bounded
catalog reads, alarm state, cursor streaming, and the operator UI. Pre-freeze
regressions passed, but no canonical candidate result, Gate 0B authorization,
Final evidence, release package, or v0.7.0 tag is claimed by this event.

## 2026-08-16 - v0.6.0 Accepted And v0.7 Gate 0A Approved

### v0.6.0 Accepted Release

The conditional v0.6.0 acceptance recorded in release commit
`05ec783a6e54a76e0548bdd536c18538f6bff51b` became effective when the project
owner created and verified annotated tag `v0.6.0` on 2026-08-16. Tag object
`b6dc64dc8fb6cfe9845f454904a078ec6f3c0919` peels to that release commit and
binds qualified source `8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213`, candidate
`0ea26105e72d7830de4a265989ed7d9074ffbe09`, the canonical evidence
fingerprints, and final archive SHA-256
`b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c`.

Final qualification passed nine suite captures with 1,626 concrete tests,
1,620 passes, six exact SQLite environment skips, 36 subtests, and zero
failures or errors. Four image-bound SBOMs, the supply-chain audit, and
deterministic packaging passed with zero High or Critical findings, zero
unlocked inputs, and no accepted exceptions. This post-tag reconciliation does
not modify the tagged release record or grant deployment, operational,
compliance, or cryptographic-signature authority.

### v0.7 Owner Direction And Gate 0A Approval

The owner request was recorded exactly as: `resume and finish up asap v0.6 asap and move forward to finis up v0.7 asap. you have all aprrovals.` The
accepted v0.6.0 tag satisfies the baseline precondition, and
[`SPELL_v0.7_Pre-Implementation.md`](SPELL_v0.7_Pre-Implementation.md) maps
that direction to the bounded explicit authorization set `V07-OBS-001` through
`V07-OBS-009`. The exact owner marker is
`V07-GATE-0A OWNER-APPROVAL: APPROVED`.

Gate validation passed under locked Python 3.13.14 with the exact marker
`gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0`.
All 22 adversarial Gate tests and eight semantic planning-contract tests
passed. The manifest and six matrices under `contracts/v07` bind the exact 45
planned proof identities and the read-only simulator time, telemetry,
condition, resource/lookup, limits/alarm, and stream boundaries.

At the Gate 0A decision, the gate authorized bounded implementation only and
claimed no v0.7 product construct, runtime artifact, candidate evidence,
qualification result, release, deployment, live or legacy GCS route,
operational authorization, or compliance determination. The later candidate
event above preserves rather than rewrites that gate-time result.

## 2026-08-16 - v0.6 Candidate Qualified And Gate 0B Passed

### Candidate And Evidence Binding

Candidate commit `0ea26105e72d7830de4a265989ed7d9074ffbe09` is bound to the
canonical work-package evidence at
`artifacts/v0.6/work-package/qualification.json`, SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`.
All ten suites and all 45 planned identities PASS with no mapped skips,
failures, accepted failures, or waivers. All nine `V06-OP-001` through
`V06-OP-009` work packages are `IMPLEMENTED_AND_QUALIFIED`.

Gate 0B passed and authorized release closeout with the exact validator marker
`gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED`.

### Closeout Boundary

Gate 0B authorizes release closeout only; it is not Final qualification or
release acceptance. SPELL v0.5.0 remains the accepted baseline unchanged.
Final qualification, four v0.6 SBOMs, supply-chain evidence, the deterministic
package and committed sidecar, the release commit, and the annotated `v0.6.0`
tag remain pending. No v0.6 release, deployment, operational authorization,
compliance determination, or cryptographic-signature claim is made.

## 2026-08-15 - v0.5.0 Accepted And v0.6 Completion Requested

### Accepted Baseline

The conditional v0.5.0 acceptance recorded in release commit
`e7b6bb9428833437e0160040541eb840deee7cca` became effective when the project
owner created and verified annotated tag `v0.5.0` on 2026-08-14. The tag object
is `a1b277d74d2fb19062ca3e4388e9104d45c50ec4` and peels to that release
commit. Final qualification passed 1,096 concrete tests with 1,090 passes, six
exact approved SQLite environment skips, 36 subtests, no failures or errors,
four image-bound SBOMs, no High or Critical supply-chain findings, and no
accepted exceptions. The deterministic archive SHA-256 is
`cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241`.

This entry is a post-tag factual reconciliation. It does not alter the tagged
release record or imply that the tag contained a later documentation update.
The tag itself activated the conditional decision exactly as the tagged record
specified. Operational authorization and compliance determination remain none.

### v0.6 Owner Direction And Gate 0A Approval

The project owner requested completion of v0.6 and subsequently explicitly
approved the exact bounded Gate 0A recorded in
[`SPELL_v0.6_Pre-Implementation.md`](SPELL_v0.6_Pre-Implementation.md).
`V06-GATE-0A PASS` authorizes implementation of `V06-OP-001` through
`V06-OP-009` under the accepted v0.5.0 baseline binding, exclusions, operator
state/command/prompt/inspection matrices, and recovery/security acceptance
rules. The exact owner marker is `V06-GATE-0A OWNER-APPROVAL: APPROVED`.

Gate 0A is implementation authorization, not an implementation or release
result. Subsequent work prepared the bounded candidate implementation, exact
ten-suite/45-ID qualification contract, version-scoped release tooling, and
pending Gate 0B/release records. The latest owner instruction reaffirmed the
exact `V06-OP-001` through `V06-OP-009` approval and requested prompt v0.6
completion. Canonical candidate evidence, Gate 0B PASS, Final qualification,
the release commit, and annotated tag remain pending; no release, deployment,
operational, broad compatibility, or compliance result is claimed.

## 2026-08-13 - v0.5 Candidate Evidence Integrated And Release Closeout Continued

### Owner Direction And Gate Decision

The project owner directed the qualified `V05-IR-001` increment through
release closeout and requested the v0.5 tag when all required work is done.
[`SPELL_v0.5_Gate_0B.md`](SPELL_v0.5_Gate_0B.md) resolves the tag request to
the repository's one authorized semantic-version tag, `v0.5.0`, and records
`V05-GATE-0B PASS` with authorization
`V05_IR_001_RELEASE_CLOSEOUT_ONLY`.

Gate 0B is a scope and closeout authorization, not final release acceptance.
It permits version/provenance/release-record updates, canonical evidence
integration, deterministic packaging, supply-chain evidence, the release
commit, and the annotated tag only for the single Gate 0A work package. It does
not authorize the broader v0.5 language/runtime roadmap or any new API, schema,
migration, frontend behavior, dependency, driver contract, or operational
capability.

### Candidate Closeout State

Product package, backend, and frontend metadata are advanced to `0.5.0` for
the closeout candidate. The accepted procedure IR remains 0.3, API remains
`v1`, and report/event schema remains `0.3`. The bundled driver retains
implementation/default identity `0.4.0` because `V05-IR-001` does not modify
the driver; changing its handshake identity would make an unsupported
compatibility claim.

The canonical candidate record at
`artifacts/v0.5/work-package/qualification.json` is integrated and independently
validated. It binds candidate `aefa658ce01d49a7879d0471b50425ac3bcf9e2d`
to test-only Docker inspection metadata correction and qualification source
`ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`. Evidence SHA-256
`86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`
covers four suites, six identities, and 949 concrete tests. The live Gate 0B
validator passes with exact marker
`gate=PASS work_packages=1 identities=6 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED`.

Supply-chain results, four distinct SBOMs, deterministic package hashes, the
complete Final validation, release commit, and annotated tag remain pending.
SPELL v0.4.0 remains the accepted product baseline until every conditional
release control passes and the verified `v0.5.0` tag is created; that tag makes
the recorded conditional acceptance effective without a post-tag documentation
commit. No present v0.5 final acceptance, tag, deployment, operational
authorization, compliance determination, or cryptographic-signature claim is
made.

## 2026-08-12 - v0.4.0 Accepted And v0.5 Gate 0A Opened

### Accepted Baseline

SPELL v0.4.0 is the current accepted local simulator engineering release. Its
annotated tag `v0.4.0` has tag-object identity
`86390c90e8d5f96f872be43274cbc9d789a34c2d` and peels to release commit
`4546d313a2d8f50504b2bc602d56b3b459ca7597`. The tag records owner acceptance,
Final qualification of 74/74 tests and 209/209 assertions, no accepted
exceptions, no compliance determination, and no operational authorization.

### Gate 0A Decision

The next bounded step is recorded in
[`SPELL_v0.5_Pre-Implementation.md`](SPELL_v0.5_Pre-Implementation.md).
`V05-GATE-0A PASS` authorizes only `V05-IR-001`: strict independent validation
and canonicalization of the existing IR 0.3 payload, parser-output
postvalidation, persisted-IR supervisor preflight before worker generation or
process creation, a second worker preflight before `worker.started` or any
effect, byte-preserving compatibility without migration, and focused
fail-closed tests.

The gate tooling binds the annotated tag object, raw tag-object hash, peeled
release commit, tagged baseline file hashes, required acceptance markers, one
work package, zero claimed new constructs, and zero claimed new artifacts.
The planned acceptance identities are `V05-IR-001-UNIT`,
`V05-IR-001-PARSER`, `V05-IR-001-SUPERVISOR`, `V05-IR-001-WORKER`,
`V05-IR-001-COMPAT`, and `V05-IR-001-ADVERSARIAL`.

### Scope Boundary

Gate 0A does not claim that the authorized implementation exists. It does not
authorize a new language construct, IR version, API, schema, migration,
frontend, dependency, driver, package, source-to-IR reparse/integrity feature,
or operational behavior. The broader Core Language and Deterministic Runtime
roadmap remains Candidate scope and requires later approval. No v0.5 release,
deployment, compliance, signature, or operational claim is made.

### Implementation Start Result

Implementation of the authorized work package subsequently started, producing
candidate commit `aefa658ce01d49a7879d0471b50425ac3bcf9e2d`. The candidate adds
the independent IR 0.3 validator/canonicalizer, parser postvalidation,
persisted supervisor preflight, worker preflight, bounded rejection evidence,
byte-preservation checks, and the six planned local test families without
adding language, API, schema, dependency, frontend, driver, or operational
scope.

The locked Python 3.13 project-configured backend/driver-host pytest run passed
328 tests with 18 environment-only skips. Gate 0A still passed its exact
validator marker and all 24 gate-tooling tests. The skipped coverage includes
the unconfigured PostgreSQL migration database and Linux/opt-in Compose checks.
Because the Gate 0A completion rule requires all six planned identities to
pass, `V05-IR-001` is not yet claimed implemented or accepted. No v0.5 release,
tag, deployment approval, compliance determination, or operational
authorization is recorded.

## 2026-07-18 - v0.4 Gate 0 Pass And Implementation Start

### Gate Result

The final local `G0` / `V04-GATE-0` record passed under the digest-pinned
Python 3.13 image after exact owner-manifest binding. The exhaustive
compatibility catalog reconciles 1,682 approved disposition rows across all
seven sources and 304 pages, with 125 rows in the Candidate A slice and 1,557
Deferred/`EXCLUDE` rows. The compatibility and Gate 0 suites report 21 and 17
passing tests respectively, with zero structural errors or technical blockers.

### Implementation Status

Bounded Candidate A product engineering is authorized and has started. Work is
limited to the exact nine-RPC typed simulator lifecycle boundary, separate
driver host and private journal, mutual service identity, canonical persistence,
and authenticated read-only projection. Existing v0.3 procedure semantics are
not routed through the driver. Candidate B and all telemetry data-plane,
telecommand, operational, connected, mission, broader language, and broader GUI
behavior remain excluded.

This is an implementation-start record, not v0.4 acceptance. Gates 1-5 remain
mandatory, and no release, operational authorization, deployment approval, or
compliance determination is recorded.

## 2026-07-18 - Local v0.4 Candidate A Gate Approval

### Owner Request

JC Arcaz stated: "Revise v0.4 to a local-only, synthetic non-CUI simulator
engineering gate. I, JC Arcaz, am the project owner and approve Candidate A,
its exclusions, budgets, and test plan. Remove organization-only approval
requirements without making operational or compliance claims."

### Gate Revision

The v0.4 gate now requires the project-owner record plus bounded engineering
evidence for Candidate A. Candidate B remains deferred. Organization, mission,
protected-data, assessment, deployment, authorizing-official, proposed-ADR, and
other role-based approvals remain in the broader next-generation records but
are not local v0.4 entry requirements.

The approved worker boundary is bounded non-executing IR plus strict mTLS
credential separation and fail-closed driver authentication. A route may exist
on the shared local development network, but the procedure worker may have no
product call path or usable driver credential. This is a bounded local
engineering decision, not a deployment or isolation claim for another scope.

Gate 0 requires exhaustive source identity/span, classification, Candidate A or
Deferred/`EXCLUDE` disposition, target phase, a unique planned test identity,
errata handling, and reconciled counts. Deferred rows require static source and
negative-scope evidence; they do not require executable fixtures, semantic
oracles, or results and do not claim implementation. In-scope v0.4 fixtures
execute at the applicable later release gates.

### Current Disposition

The owner scope decision is recorded. Product edits remain blocked until the
candidate exhaustive seven-source catalog passes deterministic validation and
fresh independent source review and the exact local gate files are bound by the
owner-record SHA-256 manifest. The manifest is change-detection evidence, not a
signature. No release acceptance, operational authorization, deployment
approval, or compliance determination is recorded by this entry.

## 2026-07-18 - Complete v0.4 Before Beginning v0.5

**Superseded gate note:** The later owner instruction recorded above preserves
the required v0.4-before-v0.5 sequence but replaces this entry's organization-
approval blockers with the local Candidate A owner record and technical Gate 0.
The partial-catalog facts below remain historical checkpoints.

### Owner Request

The owner requested: "so complete V 0.4 and start implementing v 0.5 once V
0.4 done".

This request establishes the required order: Candidate v0.4 must pass its entry
gate, implementation, complete qualification, release decision, commit, and tag
before a separately gated v0.5 implementation may begin. It does not identify
the owner or the other named approval-role holders, sign the exact Draft
baseline, close the ten G0 phase-entry decisions, approve the 366 normative
allocations, or supply the remaining compatibility dispositions. Those actions
cannot be inferred or performed by the project-declared AI assistance tool.

### Current Disposition

Gate G0 and `V04-GATE-0` remain blocked. The next permitted work is the
source-grounded completion of the seven-manual compatibility inventory and
preparation of the exact approval inputs. No v0.4 product runtime, API, schema,
dependency, deployment, or operational change is authorized until the required
named human decisions and signatures are verified. After v0.4 is accepted,
v0.5 requires its own pre-implementation scope, compatibility/errata approval,
requirements, acceptance tests, and entry decision before product edits.

### Bounded Progress

The permitted documentation-conformance increment now represents all seven
authoritative source records and reconciles 257 rows: 195 exact Language
Reference example number/title/page indexes, 40 prior Driver Manual assertions,
and 22 prior Server Manual assertions. The example bodies and oracles are not
decomposed, no fixture or result evidence exists, and their target increment is
unassigned pending `OD-008`. The four GUI, Development Environment, Build, and
GUI 4.0.2 source catalogs still have zero detailed rows; the non-example
Language Reference catalog and the complete Driver and Server catalogs also
remain open. The record contains 195 `Indexed` and 62 `Decomposed` rows, all
`PENDING_HUMAN_APPROVAL`. Focused compatibility and G0 validator tests pass
structurally, while the default G0 decision remains `BLOCKED` as required.

## 2026-07-18 - Roadmap-Directed NG-WP-00 Continuation

**Superseded gate note:** The later local v0.4 revision recorded above removes
the organization-only approvals and signed-baseline conditions described here
from Candidate A Gate 0. This entry remains the factual record of the earlier
bounded increment.

### Owner Request

The owner requested: "move forward according `PROJECT_ROADMAP.md`".

The roadmap keeps Gate G0 blocked and prohibits starting `NG-WP-01` or wiring
the experimental startup modules into the product before named human decisions,
approvals, and a signed baseline. This request therefore authorizes the next
machine-actionable `NG-WP-00` documentation-conformance increment; it is not a
substitute for `OD-023`, per-decision approval, per-requirement signatures, or
the explicit v0.4 product gate.

### Bounded Outcome

A partial Candidate v0.4 compatibility seed was prepared from selected Driver
Development Manual and Server Manual source assertions:

- 62 unique source-bound rows with all 25 required compatibility fields;
- 40 Driver Manual and 22 Server Manual assertions;
- an explicit partial v0.4 scope and digest-pinned reconciliation record;
- a validator and adversarial tests for identity, hashes, pages, schema,
  counts, membership, approval spoofing, and reconciliation freshness; and
- no product runtime, API, schema, dependency, deployment, or operational
  change.

Every row remains `Decomposed` and `PENDING_HUMAN_APPROVAL`. The other five
sources, full Driver and Server catalogs, and all normative examples remain
open. The result does not complete `COMP-001`, `NG-WP-00`, `V04-GATE-0`, or G0
and does not authorize `NG-WP-01`.

## 2026-07-17 - SPELL v0.4 Gate Draft

### Release Identity

| Field | Value |
| --- | --- |
| Version target | 0.4.0 |
| Release name | Typed Simulator Driver and Context Foundation |
| Request type | Next-step planning and pre-implementation gate |
| Status | Gate revised after complete supplied-manual review; owner approval pending |
| Accepted product baseline | Commit `7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`, tag `v0.3.0` |
| Product implementation | Not authorized |
| Operational authorization | None |

### Owner Request

After creating the v0.3.1 roadmap and version timeline, the owner requested:
"implement next step". The roadmap identifies two possible v0.4 foundations
and requires one to be selected through a new pre-implementation gate.

This request is recorded as authorization to draft the next required planning
gate, not as unambiguous approval to change product behavior. Candidate A was
selected for the draft because v0.3 explicitly carries driver-host contracts
forward to v0.4 and it is the prerequisite for documented simulator service
conformance and eventual read-only legacy observation. Candidate B remains
deferred from v0.4.

The owner then requested a complete review of the SPELL documentation under
`SPELL-DOCUMENTATION/`, a roadmap revision, and a check that future development
follows the documentation closely. Seven PDFs totaling 304 pages were reviewed
page by page on 2026-07-17. That request authorizes documentation-conformance
and planning corrections only; it does not approve v0.4 product implementation.

### Consolidated Version 0.4 Gate Prompt

Before any v0.4 product edit, propose one bounded, simulator-only Typed
Simulator Driver and Context Foundation release based on the accepted v0.3.0
tag and the complete supplied-manual review.

The proposal must:

- Define a versioned protobuf/gRPC contract with bounded typed messages,
  deterministic generated code, explicit compatibility rules, and a
  capability/version/identity/configuration/generation handshake.
- Separate host, context-binding, execution-attachment, capability lifecycle,
  and operation state; carry stable server-profile, context, execution,
  driver-binding, and operation identity.
- Define typed host-profile, context-binding, and execution-attachment
  configuration with separate generations/digests, explicit precedence,
  out-of-band secret references, granular capabilities, setup/cleanup order,
  and named host/per-context capacity.
- Add exactly one bundled deterministic simulator driver in a separate
  non-root, read-only host with no published port, database route, public route,
  mission route, or arbitrary endpoint configuration.
- Limit the driver surface to the nine infrastructure methods `Handshake`,
  `Health`, `OpenContext`, `CloseContext`, `AttachExecution`,
  `DetachExecution`, `CancelLifecycleOperation`, `DrainHost`, and
  `GetOperation`.
- Keep the control-plane supervisor as the sole gateway and owner of canonical
  project-database, audit, and event persistence. Give the driver only a
  private bounded idempotency journal for restart reconciliation; neither the
  browser nor the procedure worker may hold a usable driver credential or
  invoke the host directly under the approved threat model.
- Use mutual service authentication independent of browser JWTs, with no
  insecure fallback and no credential leakage into workers, clients, logs,
  events, reports, images, SBOMs, or packages.
- Persist a stable operation ID before dispatch, deduplicate retries by that
  identity, separate lifecycle stage from effect certainty, fence stale
  generations, and latch uncertain outcomes for reconciliation without
  automatic resend.
- Add only authenticated read-only driver snapshots and console projection; no
  browser driver-control mutation is allowed.
- Define fresh/populated SQLite and PostgreSQL migrations, rollback, failure
  injection, compatibility regression, local performance budgets, dependency
  locks, audits, driver SBOM, and reproducible v0.4 evidence.
- Parameterize release evidence so v0.4 cannot overwrite or satisfy itself with
  retained v0.3 artifacts.
- Record a populated compatibility disposition and errata process for every
  documented language artifact, server/configuration item, driver contract,
  operator/development workflow or view, build/deployment concept, and example
  without implementing later language, UI, development, telemetry, or command
  phases in v0.4.

Do not add telemetry or telecommand driver services, route existing procedures
through the host, add new procedure syntax, implement prompt-result binding,
connect to a live or legacy GCS or spacecraft, permit arbitrary endpoints, add
externally effective behavior, or claim operational authorization.

### Unresolved Entry Decisions

The owner must explicitly resolve or approve:

1. Candidate A as the sole v0.4 product scope and Candidate B as deferred.
2. Worker-to-driver network and credential isolation. Workers currently share
   the backend container network namespace, so route isolation is not yet a
   supported claim.
3. Contract namespace, compatibility rules, bounded messages, lifecycle
   methods, context/execution identity, configuration precedence, capabilities,
   capacity, errors, stages, certainty values, and deterministic simulator
   fixture.
4. Local mutual-authentication identity issuance, rotation, expiry, revocation,
   storage, and redaction.
5. Migration, canonical operation-ledger, private driver-journal
   retention/corruption/fail-closed behavior, read-only API/event, rollback,
   performance, and release-evidence designs.
6. The intended clean repository change set, excluding unrelated staged,
   modified, untracked, and potentially credential-bearing artifacts.
7. A populated exhaustive cross-manual compatibility ledger, reconciled
   per-manual artifact counts, errata decisions, and any
   licensing/publication boundary for the external PDFs.

### Entry Decision

**Pending.** [`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md)
and the v0.4 section of [`Test_and_Integration.md`](Test_and_Integration.md) are
draft proposals. Their creation does not approve the release or authorize
implementation. Product code, schemas, dependencies, services, and deployment
configuration must remain unchanged until the owner explicitly approves or
revises the complete gate.

### Gate Draft Outcome

The v0.4 scope, exclusions, trust boundary, operation-certainty model,
requirements, planned tests, local budgets, rollback, risks, and entry/exit
criteria were documented on 2026-07-17. The later page-complete manual review
revised the gate to include context/execution binding, typed configuration,
granular capability/capacity, lifecycle ordering, documentation traceability,
and package lifecycle tests. It also reordered future work so documented
simulator language, operator, telemetry, data, development, auxiliary service,
and telecommand conformance precedes legacy observation. No v0.4 product
implementation, qualification result, release commit, tag, or operational
authorization is claimed. The required populated compatibility ledger and
owner gate decision remain incomplete.

## 2026-07-16 - SPELL v0.3

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.3 |
| Release name | Simulator Hardening and Language Foundation |
| Request type | Hardening, restricted-language expansion, and validation workflow |
| Status | Delivered and accepted as a local simulator engineering release |
| Baseline | Commit `7df7743`, tag `v0.2.0` |
| License | Apache License 2.0 |
| Operational authorization | None |

### Owner Request

Execute all recommendations required before v0.3, show the newest version at
the top of this history, license the new implementation under Apache License
2.0, and then deliver SPELL v0.3.

### Consolidated Version 0.3 Prompt

Freeze the verified v0.2 simulator baseline in source control without
committing IDE metadata or legacy reference archives. Add the official Apache
License 2.0 text and project notice, preserve the v0.2 evidence, and tag the
baseline `v0.2.0`.

Before v0.3 implementation, define its exact requirements, exclusions,
acceptance tests, performance budgets, security dispositions, and evidence
rules in `SPELL_v0.3_Pre-Implementation.md`, `PROMPT_History.md`, and
`Test_and_Integration.md`.

Then implement one simulator-only v0.3 release that:

- Uses versioned migrations for fresh and existing SQLite/PostgreSQL stores.
- Uses signed JWT claims and server-enforced roles, with an explicitly gated
  loopback development issuer for the local console.
- Removes general backend outbound networking through the Compose topology.
- Produces hash-locked Python dependencies, reproducible packages, SBOMs, and
  zero unreviewed dependency advisories.
- Expands the non-executing procedure IR with typed variables, safe
  expressions, conditions, bounded loops, reusable local calls, and durable
  variable checkpoints.
- Adds validation-only REST and 2D console workflows without persistent
  authoring or Python source execution.
- Exercises concurrency, faults, migrations, restart/recovery, 10,000-event
  replay, accessibility, performance, and a sustained local soak.

Do not add Java, Three.js, arbitrary Python execution, drivers, GCS or
spacecraft connections, operational commanding, high availability, or
operational authorization.

### Entry Decision

The owner explicitly authorized this bounded v0.3 work. The v0.2 baseline was
committed and tagged before v0.3 product edits. Implementation may begin only
after the v0.3 test section in `Test_and_Integration.md` is present. Release
acceptance requires actual evidence or an explicit non-safety exception for
every v0.3 test.

### Version 0.3 Implementation Outcome

Version 0.3 was finalized on 2026-07-16 under Apache License 2.0. It delivered
versioned SQLite/PostgreSQL migrations, strict signed JWT identity and roles,
internal-only backend/database networking, hash-locked dependencies, SBOMs,
reproducible packaging, the typed restricted language and variable recovery,
and transient API/console validation.

Final verification passed 112 backend tests with one PostgreSQL-only skip under
network-disabled SQLite, all 113 tests on PostgreSQL, 13 frontend unit tests, a
strict production build, 16 desktop/mobile browser tests, and 26 release-tooling
tests. The 100-command latency and 10,000-event replay gates passed. Two
independent Chromium processes each received all 6,002 sequences at 100.022
events/second after an explicit subscription-readiness handshake, and the
10-minute soak persisted 12,001 exact events at 20.002 events/second with
bounded scheduling lag and memory growth. Dependency audits reported no known
product dependency vulnerabilities; separate backend, proxy, and frontend SBOMs
and their checksum manifest were generated.

The release is recorded in `SPELL_v0.3_Release.md` and tagged `v0.3.0`. No GCS,
spacecraft, driver, Java, arbitrary Python execution, Three.js, or operational
authorization was added.

## 2026-07-12 - SPELL v0.1

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.1 |
| Release name | Pre-Implementation Baseline |
| Request type | Documentation, research, and architecture only |
| Status | Delivered; awaiting review and approval |
| Product implementation | Not authorized |
| Operational authorization | None |

### Prompt Lineage

The v0.1 request was developed through the following user decisions:

1. Replace inherited OpenBEXI Earth Orbit instructions with project-specific
   SPELL guidance.
2. Use the supplied legacy SPELL Core, COTS, and GUI archives as references.
3. Read the Server, GUI, Language, Driver Development, Development Environment,
   and Build manuals before implementation.
4. Plan a new Python implementation with no Java components.
5. Replace the Eclipse GUI with a real-time 2D web interface.
6. Revisit the SPELL APIs and real-time execution architecture.
7. Deliver every pre-implementation artifact together as SPELL v0.1 before any
   implementation begins.
8. Create `PROMPT_History.md`, `Test_and_Integration.md`, and `README.md`, and
   make the test plan a prerequisite for every later version.
9. Treat v0.1 as the approved behavioral and architectural contract and reserve
   the first simulator-only implementation slice for v0.2.

### Consolidated Version 0.1 Prompt

Produce a complete planning baseline for a modern replacement of SPELL using the
supplied legacy archives, embedded manuals, version-specific source behavior,
and reproducible legacy traces as the compatibility reference.

This is a documentation-only release. Do not create backend, frontend, procedure
engine, driver, database, deployment, or integration code. Do not modify the
legacy archives or connect to a live Ground Control System or spacecraft.

The planned target must:

- Use Python 3 for the backend, execution engine, services, and procedure SDK.
- Contain no Java or Eclipse RCP/SWT components.
- Provide a real-time 2D browser-based operator interface.
- Preserve readable, sequential SPELL procedure behavior where practical.
- Keep spacecraft and Ground Control System behavior behind typed drivers.
- Preserve execution control, monitoring, prompts, telemetry, telecommands,
  variables, resources, logs, recovery, replay, and as-run evidence.
- Redesign the legacy client/server API into versioned REST commands and
  snapshots, ordered WebSocket events, internal typed gRPC services, and a
  versioned Python procedure SDK.
- Use isolated procedure workers and separate driver hosts so that neither the
  API server nor browser directly executes or accesses operational integrations.
- Persist authoritative command, event, prompt, state, checkpoint, and audit
  data before projecting real-time updates.
- Treat an uncertain telecommand result as reconciliation-required and never
  repeat it automatically.
- Migrate incrementally using simulators, legacy adapters, golden traces,
  differential execution, parallel operation, and rollback.

Before defining the target, locate and review:

- SPELL Server Manual.
- SPELL GUI User Manual.
- SPELL Language Reference.
- SPELL Driver Development Manual.
- SPELL Development Environment Manual.
- SPELL Build Manual.
- All relevant material in `SPELL2.6.10-src.zip`,
  `SPELL-COTS-2.6.10.zip`, and
  `SPELL_GUI_4.0.12-win32.win32.x86.zip`.

Record versions, applicable components, behavior to preserve, obsolete
technology, compatibility-sensitive interfaces, safety/recovery behavior,
missing information, and conflicts. Do not invent behavior when evidence is
missing.

Deliver one coordinated v0.1 package containing:

1. Manual and source review.
2. Legacy component and capability inventory.
3. State-transition and command matrix.
4. Documented-versus-implemented comparison.
5. Stable, traceable requirements.
6. Target architecture and legacy-to-new mapping.
7. REST, WebSocket, gRPC, event, command, and procedure SDK direction.
8. Procedure-language and configuration migration strategy.
9. Ground Control System driver architecture.
10. Real-time 2D operator-interface specification.
11. Persistence, checkpoint, recovery, and as-run strategy.
12. Security, safety, licensing, and supply-chain assessment.
13. Test, simulation, replay, fault-injection, accessibility, and performance
    strategy.
14. Phased implementation, parallel validation, cutover, and rollback plan.
15. Architecture decisions, risks, assumptions, missing information, and
    unresolved decisions.

Create the v0.1 test plan before the master deliverable. Update and approve the
test plan before implementation of every later version. Do not begin v0.2 until
the complete v0.1 package is reviewed and explicitly approved.

### Inputs Reviewed

| Input | Result |
| --- | --- |
| `SPELL2.6.10-src.zip` | Core C++/Python source, interfaces, configuration, build, deployment, and sparse tests inventoried |
| `SPELL-COTS-2.6.10.zip` | Obsolete/mixed dependency bundle inventoried; not accepted for target reuse |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | Binary Eclipse GUI, plug-in capabilities, and embedded manuals inventoried |
| Server Manual 2.4.4 | Reviewed as older configuration/startup evidence |
| GUI User Manual 2.4.4 | Reviewed for operator workflows and execution control |
| Language Reference 2.4.4 | Reviewed for procedure and service semantics |
| Driver Development Manual 2.4.4 | Reviewed for GCS abstraction and service contracts |
| Build Manual 2.4.4 | Reviewed for legacy build/component context |
| Server Communication ICD draft | Reviewed as historical API evidence only |
| Development Environment Manual | Not found; recorded as an open gap |

### Decisions

| Decision | Status in v0.1 |
| --- | --- |
| New implementation with legacy behavioral compatibility | Accepted direction |
| Python 3 backend and engine | Accepted direction |
| No Java in target product | Accepted direction |
| Real-time 2D web interface | Accepted direction |
| No Three.js in 2D baseline | Proposed |
| Modular control plane before microservices | Proposed |
| Isolated procedure workers | Proposed |
| Out-of-process typed driver hosts | Proposed |
| REST commands, WebSocket events, internal gRPC | Proposed |
| PostgreSQL authoritative store | Proposed |
| React and strict TypeScript console | Proposed |
| Simulator-only v0.2 vertical slice | Proposed for approval |

### Delivered Documents

- `SPELL_v0.1_Pre-Implementation.md`
- `Test_and_Integration.md`
- `README.md`
- `PROMPT_History.md`

`PROMPT_Instructions.md` remains the durable project-wide execution reference.

### Important Findings

- Manual content is 2.4.4 while the source and GUI packages identify as 2.6.10
  and 4.0.12 respectively.
- The required Development Environment manual was absent from the evidence
  supplied for v0.1. It was supplied and reviewed later on 2026-07-17.
- Core release notes stop before the archive version and GUI release notes stop
  before the product version.
- The core has dual Python 2/3 executors, while the target will be Python 3 only.
- Legacy GUI/client IPC is custom socket messaging; driver gRPC is separate and
  contains weakly typed payloads and insecure defaults.
- The source includes no substantive core automated test suite.
- Optional/proprietary drivers referenced by build metadata are absent.
- The COTS bundle is obsolete, duplicated, mixed-license, and not reproducible
  as supplied.
- Legacy material includes internal infrastructure references and a draft ICD
  with a confidentiality marking; publication boundaries require review.

### Approval Status

The v0.1 documentation package is delivered as a draft for review. Approval is
not inferred from delivery. Product implementation remains blocked until the
project owner approves or revises the architecture, requirements, safety model,
test plan, unresolved issues, and v0.2 entry scope.

This was the status at v0.1 delivery. The explicit bounded approval recorded in
the v0.2 entry below supersedes this implementation block for that scope only.

## 2026-07-12 - SPELL v0.2

### Release Identity

| Field | Value |
| --- | --- |
| Version | 0.2 |
| Release name | Simulator Vertical Slice |
| Request type | First bounded implementation release |
| Status | Approved to begin; v0.2 pre-implementation test plan recorded |
| Product implementation | Authorized only for the scope below |
| Operational authorization | None |

### Approval Record

The project owner asked whether v0.2 could proceed, accepted the recommended
conditional gate, and then requested v0.2 incorporating all recommendations.
This records approval of the v0.1 baseline for this bounded implementation
slice. It does not approve live Ground Control System (GCS), spacecraft,
production, or operational use.

At the time of the v0.2 gate, the missing SPELL Development Environment manual
was waived for v0.2 only because this release did not implement the full
authoring environment. The manual was later supplied and reviewed on
2026-07-17. Operational workload profiles and service-level objectives were
also deferred; v0.2 used provisional local engineering targets only.

### Consolidated Version 0.2 Prompt

Implement one clean-room, simulator-only vertical slice of the new SPELL
architecture. Do not copy legacy implementation code. Legacy manuals, archives,
source inspection, and reproducible behavior may be used to define compatibility
requirements and tests, subject to the unresolved legal and publication review.

Before implementation, update `PROMPT_History.md` and
`Test_and_Integration.md`. Then implement only the following capabilities:

- A Python 3 modular control plane.
- Procedure execution in an isolated operating-system worker process, never in
  the API process.
- A small, explicitly documented and restricted procedure subset parsed into a
  validated AST or intermediate representation; arbitrary legacy Python is out
  of scope.
- Versioned REST resources for snapshots and durable start, pause, resume,
  prompt-response, and abort commands.
- Idempotency keys and expected execution revisions for every state-changing
  request.
- Ordered downstream WebSocket events with event identity, per-execution
  sequence, schema version, timestamps, and correlation metadata.
- Snapshot-plus-cursor resynchronization after a client reconnect or detected
  sequence gap.
- PostgreSQL as the target authoritative store, accessed behind a persistence
  boundary. SQLite is permitted as a fast local development and unit-test
  fallback. PostgreSQL integration verification will be attempted using the
  project Docker Compose environment.
- A React and strict TypeScript real-time 2D operator console with no Java and
  no Three.js dependency.
- One-procedure load, validation, execution, current-line display, pause,
  resume, durable prompt, safe abort, controlled worker-crash recovery, and an
  auditable as-run report.

Use deterministic simulator inputs, an injectable clock where required, and
versioned procedure/configuration identities. Persist authoritative command,
event, prompt, state, checkpoint, and audit changes before projecting them to
the browser. A command or prompt response must have one durable outcome even
when the client retries or reconnects.

### Scope Boundaries

Version 0.2 must not include:

- A live, legacy, or non-operational GCS connection.
- A spacecraft connection or operational telecommand capability.
- Production deployment, high availability, or operational authorization.
- Full legacy procedure-language or Python 2 compatibility.
- Java, Eclipse RCP/SWT, Three.js, or a complete development environment.
- Proprietary driver implementation or reuse of the legacy COTS bundle.
- Automatic retry of an externally effective or outcome-uncertain action.

The simulator interface must be incapable of resolving to an operational
endpoint through normal v0.2 configuration. Tests and demonstrations must use
only synthetic, recorded, or deterministic simulated data.

### Accepted And Deferred Decisions

| Decision | v0.2 disposition |
| --- | --- |
| Clean-room implementation | Accepted for v0.2 |
| Python 3 control plane and isolated worker | Accepted |
| Restricted AST/IR procedure subset | Accepted |
| REST commands and ordered WebSocket events | Accepted |
| Idempotency and optimistic revision checks | Accepted |
| PostgreSQL target persistence | Accepted direction |
| SQLite fast local and unit-test fallback | Accepted; does not replace PostgreSQL integration evidence |
| PostgreSQL Docker Compose integration run | Planned for v0.2 verification |
| React with strict TypeScript 2D console | Accepted |
| Simulator-only safety boundary | Mandatory |
| Operational latency, load, availability, and retention SLOs | Deferred pending workload evidence |
| Full Python 2 and legacy language compatibility | Deferred |
| Internal gRPC worker/driver boundary | Target direction; not required unless the v0.2 slice needs it |
| Production authentication, HA, deployment, and live GCS drivers | Deferred and not authorized |

### Version 0.2 Deliverables

1. The updated history and approved v0.2 test and integration plan.
2. The bounded Python 3 control plane and isolated worker vertical slice.
3. The restricted procedure-subset definition and validation behavior.
4. Versioned REST and WebSocket contracts for the v0.2 workflows.
5. The simulator and deterministic scenario used for acceptance.
6. The React/TypeScript 2D operator workflow.
7. Durable persistence, recovery, and as-run evidence for the slice.
8. Test results, limitations, skipped or blocked evidence, and release decision.

### Approval Conditions

Implementation may start only after the v0.2 section of
`Test_and_Integration.md` is complete. Release acceptance requires all mandatory
v0.2 tests to pass or have an explicit written disposition. Passing v0.2 grants
no authority to connect to a live GCS or spacecraft. PostgreSQL integration
verification must be attempted for v0.2 and its actual result recorded. SQLite
results must not be presented as proof of PostgreSQL production readiness.

### Version 0.2 Implementation Outcome

The approved slice was implemented on 2026-07-12 and accepted as a local,
simulator-only developer release with documented exceptions. This outcome
supersedes the entry status above without changing the historically approved
prompt.

- The isolated Python worker, restricted AST subset, durable REST and WebSocket
  contracts, SQLite/PostgreSQL persistence, crash recovery, 2D web console, and
  as-run report were delivered.
- The backend suite passed 18 tests with SQLite and Docker networking disabled,
  then the same 18 tests against PostgreSQL 18 using `spell_test`.
- Seven frontend component/store tests, the strict production build, and eight
  real-backend desktop/mobile Playwright scenarios passed.
- The performance and soak plan, a separate manual keyboard-only review, and a
  single outbound-disabled full browser workflow remain accepted exceptions.
- Five Starlette advisories, Python artifact hash locking, project licensing,
  production authentication, and the then-missing Development Environment
  manual remained open at v0.2 acceptance.
- Full language compatibility, authoring, driver/GCS, spacecraft, high
  availability, and operational workload qualification remain deferred.

The detailed evidence and release restrictions are recorded in
`SPELL_v0.2_Release.md`. No operational authorization was granted.

### Version 0.2 Freeze Note

Before the v0.3 entry gate opened, the owner selected the Apache License,
Version 2.0 for the new OpenBEXI SPELL implementation. `LICENSE` and `NOTICE`
were added, the v0.2 provenance and release records were updated, and the
legacy reference archives were explicitly excluded from the source release.
This supersedes the earlier open project-license item without changing the
licenses or distribution restrictions of legacy or third-party material.
