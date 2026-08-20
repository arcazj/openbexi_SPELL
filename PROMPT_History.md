# Prompt History

This document records approved project requests, planning decisions, delivery
status, and unresolved issues by OpenBEXI SPELL version. The current version is
inserted at the top so it is visible first; earlier entries retain their original
delivery order. Later versions may supersede a decision but must not rewrite an
earlier request or result.

## 2026-08-19 - v0.10 Acceptance And v0.11 Candidate Restoration

The owner directed restoration of the complete v0.10 and v0.11 work, followed
by GitHub publication, and approved the recommendation to close the releases
in order. History inspection found no clean v0.10 release commit: a later
working-tree snapshot mixed v0.10 reference-runner work with v0.11 command
runtime work. v0.10 was therefore reconstructed from the accepted `v0.9.0`
tag instead of relabeling the mixed snapshot.

The reconstructed v0.10 product candidate was
`8377760be59033b3372512ad812c43cd6d2f7e29`. It contains the 195-example,
257-variant reference adapter, one bundled procedure, complete supporting
backend/frontend tests and browser evidence, and no v0.11 product path. The
strict release policy pins all eight mandatory legacy references while
excluding their PDF/ZIP bytes from product images and packages. All strict
gates passed. Annotated tag `v0.10.0`, tag object
`95f64a04bb15b1eb03250a8d0387a228b67727a7`, accepts release commit
`c33d1893d90f9d42c36eedd19cb83f079bf39a9f` with package SHA-256
`b65af04f53475e8a4aa5f233485c17fd734793aeaddda6446ea969b8705f405d`
and no accepted exception.

v0.11 was then branched directly from that accepted tag. Candidate
`e15d3314f9b97eb43d5d5057c8f1ba614844e0e7` restores the closed simulator
telecommand contracts, parser/IR/runtime, supervisor/worker/operator
integration, all eight v0.11 backend test modules, version bindings, and the
latest legacy auditor implementation. The auditor CLI/runner mismatch was
fixed and bound by three tests. The focused v0.11 suite passes 197 tests, and
fresh Chromium/mobile evidence passes 2/2 against the v0.11 image.

The v0.11 release remains conditional on its complete source-bound gate,
deterministic package, evidence validation, and annotated tag `v0.11.0`.
Earlier mutable main-line evidence is historical context only and is not used
as final release evidence.

## 2026-08-19 - GitHub Delivery Default

The owner directed that completed repository changes always be committed and
pushed to the configured GitHub repository when GitHub has not already been
updated. The durable workflow is to validate the intended scope, stage it
deliberately, commit it clearly, push the current branch, and verify that the
remote branch resolves to the local commit. Any remaining worktree change or
publication blocker must be reported.

This delivery default does not turn a normal GitHub push into an accepted
release, deployment authorization, compliance result, or operational approval.
Those states continue to require their explicit release gates and evidence.

## 2026-08-19 - SPELL Documentation Forward Reference Baseline

The owner directed that all documents under `SPELL_DOCUMENTATION/` be used as
the reference baseline for moving forward with SPELL coding and delivery, and
that this rule be made explicit in the durable project instructions and other
affected documentation.

The resulting authority model separates domains. The manuals define the source
behavior and concepts that future work must address. The AI-generated
documentation is a controlled, traceable modern interpretation and may not
silently replace, weaken, omit, or contradict those sources. Approved code,
contracts, and tests define the implemented modern behavior, while immutable
release records and validated tags continue to define release status. Ambiguity,
obsolete mechanisms, unsafe behavior, or intentional incompatibility requires
an explicit compatibility or architecture decision and corresponding test
evidence. This direction does not authorize copying legacy code, packaging the
manuals with the product, live connectivity, deployment, compliance, or
operational use.

## 2026-08-19 - Release Record Consolidation

The owner directed all root-level version-specific release Markdown records to
move under `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/` and requested
the resulting documentation changes be committed and pushed to GitHub. The
v0.10 release tree retains 22 applicable `SPELL_v*.md` planning, gate,
implementation, and release records through v0.10. Later v0.11 records are
deliberately absent from this earlier release boundary. Their canonical index is
[`releases/README.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md).

Cross-version records remain at the repository root. Documentation links follow
the new layout, while immutable historical tag, artifact, qualification-tool,
and hash-manifest path identities retain the paths recorded when those releases
were accepted.

## 2026-08-19 - Documentation Tree Deduplication

The owner directed the project to separate AI-generated documentation from
legacy SPELL source manuals. `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/` is the
canonical location for the generated requirements, architecture, security,
web, assurance, assets, and validation tools. `SPELL_DOCUMENTATION/` is
reserved for legacy manuals supplied to the project now or later.

The two trees were compared by relative path and SHA-256. All 100 generated
files under `SPELL_DOCUMENTATION/` were exact duplicates of files already
present under `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/` and were removed from
the legacy folder. The unique legacy file
`SPELL_DOCUMENTATION/SPELL_Language_Manual.pdf` was retained. The resulting
trees contain 100 generated files, one legacy manual, and zero cross-tree
content duplicates.

The later source-reference baseline superseded that inventory state. The
versioned legacy tree now contains seven distinct manuals plus the read-only
`SPELL2.6.10-src.zip`, all hash-pinned as mandatory source inputs. None is
copied into product images or release packages.

## 2026-08-19 - Strengthened v0.10 Gate And v0.11 Direction

The owner required v0.10 to be audited before any v0.11 implementation. The
direction requires all 195 Language Reference examples, their associated SPELL
and Python adaptations, and every identified syntax variant to have test
evidence. Example 60 specifically requires independent coverage of
`Send(command = 'CMDNAME')` and `Send(command = tc_item)`. Tests or valid
examples may not be weakened merely to obtain a pass.

The initial audit found that the earlier 195-row qualification proved one
semantic adapter per example but collapsed multi-variant examples. The v0.10
contract was therefore strengthened to 257 stable variant subcases across all
195 examples, including 46 multi-variant examples. Each subcase now binds an
independent assertion and trace. Malformed, pseudocode, output-only, negative,
and placeholder material remains explicitly classified as a semantic
adaptation; the project does not claim arbitrary Python or verbatim execution
of those fragments.

After that prerequisite, the owner direction identifies the bounded v0.11
simulator telecommand scope in `PROJECT_ROADMAP.md`. The v0.10 release tree
retains it as future scope only; its later gate and implementation records must
be created on a branch based on accepted v0.10.
The scope includes catalog-backed `BuildTC`/`Send`, all 26 documented command
statements in Examples 57 through 77, durable confirmation and settlement,
deterministic timing and verification, failure policy, recovery, effect
certainty, and no-resend behavior. It excludes any operational driver, GCS,
spacecraft, credential, browser mutation route, deployment, compliance, or
release authorization.

Later mutable main-line v0.11 work does not rewrite the authorization decision
above and is not evidence for v0.10. It is deliberately absent from this
release tree and must be requalified from the accepted v0.10 endpoint.

## 2026-08-19 - v0.10 Reference Example Adapter Direction And Local Result

The owner directed the project to revisit v0.10 around the complete 195-example
index in SPELL Language Reference 2.4.4, remove the prior bundled demo
procedures, provide one menu-driven procedure, and implement and execute the
scope as soon as possible with approvals granted. The resulting bounded scope
uses one production-catalog runner, a hash-pinned 195-row contract, closed IR
`0.10`, independently authored semantic adaptations, deterministic simulator
oracles, and exact per-effect evidence.

Local verification records 195 PASS, 0 FAIL, 0 SKIP, 0 XFAIL, and 0 unresolved
examples. Example 195 queries real bundled TM and TC catalog entries and proves
their catalog identity, direction, type, filter bounds, and a negative lookup.
Focused backend, PostgreSQL, mTLS, frontend unit/build, and authenticated
Chromium/Pixel 7 checks passed. The production image contains one
`*.spell.py` and no stale Python bytecode.

The Language Reference contains fragments, pseudocode, output illustrations,
and intentionally invalid examples. v0.10 therefore proves a deterministic
semantic-adaptation profile, not verbatim PDF-snippet execution or general
SPELL 2.4.4 parser compatibility. External effects are simulator projections;
telecommand dispatch remains disabled. The later reconstruction freezes product
candidate `8377760be59033b3372512ad812c43cd6d2f7e29`; package and acceptance
remain conditional on the v0.10 qualification and annotated-tag gates. No
deployment approval, compliance determination, or operational authorization is
claimed.

The accepted baseline for this work is v0.9.0, annotated tag object
`b47ee98429841afd7d91c928f3a314d6ac7f348c`, release commit
`a8caa957179f8df301f9863e421e3fd7127e5318`, with no accepted exceptions.

## 2026-08-18 - Prompt, Markdown, Local Session, And v0.9 Direction

The owner directed the project to revisit and optimize `PROMPT_Instructions.md`,
repair Markdown preview behavior for every tracked Markdown document, provide a
signed effectively long-lived local JWT, and start and complete v0.9. The
approved local-session exception is one loopback-only token in an ignored local
file under `var/`, with a finite `exp` and issuance by a one-shot transient
issuer while issuance remains disabled in the running service. The ignored
local `.env` contains issuer configuration and the signing secret, not the
issued token. Default and qualification tokens remain short-lived. The local
token is never expiry-free, and no token or signing-secret bytes may be printed,
logged, committed, packaged, or recorded in evidence or documentation.

The durable prompt workflow and pinned real Markdown renderer validation were
prepared for the v0.9 candidate source freeze. The conflicting IntelliJ
Markdown provider is disabled pending an IDE restart. The JWT login and
expiration-timer path is fixed, while the one-shot local token issuance remains
pending outside source and release evidence. At candidate source freeze, the
bounded v0.9 implementation, qualification tooling, and exact product inventory
were frozen together; canonical candidate qualification had not yet run. Gate
0B, Final qualification, packaging, release, and tag creation were pending at
that boundary. Any later v0.9 acceptance is authoritative only through its
strictly validated annotated tag and committed evidence.

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
[`SPELL_v0.9_Pre-Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.9_Pre-Implementation.md) maps
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
[`SPELL_v0.8_Pre-Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.8_Pre-Implementation.md).
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
[`SPELL_v0.7_Pre-Implementation.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.7_Pre-Implementation.md) maps
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

Gate 0B authorizes release closeout only; it is not Final qualificati…5689 tokens truncated…e commit, tag, or operational
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
