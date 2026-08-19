# SPELL v0.5.0 Release Closeout Record

## Post-Tag Verification - 2026-08-15

The conditional decision preserved below became effective when annotated tag
`v0.5.0` was created and verified on 2026-08-14. This is a retrospective
status addendum; it does not imply that the immutable tag contains a later
documentation commit. The tagged record deliberately made the verified tag
the final condition and required no post-tag documentation commit.

| Verified release field | Accepted value |
| --- | --- |
| Decision | ACCEPTED for the bounded `V05-IR-001` increment; no accepted exceptions |
| Annotated tag | `v0.5.0`; tag object `a1b277d74d2fb19062ca3e4388e9104d45c50ec4`; created 2026-08-14 22:22:33 EDT |
| Release commit | `e7b6bb9428833437e0160040541eb840deee7cca` |
| Qualified source | `2f31e6a011b8aad63b29bd55780c37c1b68712f1` |
| Final qualification | PASS; eight suites, 1,096 concrete tests, 1,090 passes, six exact approved SQLite environment skips, 36 subtests, zero failures/errors |
| Supply chain | PASS; four image-bound SBOMs, zero High/Critical findings, zero unlocked inputs |
| Source fingerprint | `84681e915fa3b0decc2a36f18588bd74f4840a7f4d1dcfae419e69753f6dda8d` |
| Evidence fingerprint | `c3df31909b8c16f57c80ab3db906e3d25df72c91a855019022098ddd46aab0bd` |
| Product package fingerprint | `e5b5b69c5951c1ec7fe7023293f0584471fed98d144a97afde12323d78fd7901` |
| Deterministic archive | `artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz`; SHA-256 `cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241` |
| Operational authorization | None |
| Compliance determination | None |

The Document Control, evidence-status, and conditional-decision sections below
are the pre-tag release-commit record and intentionally retain their original
pending language. They are historical conditions, not the current status.

## Document Control

| Field | Value |
| --- | --- |
| Product version | `0.5.0` |
| Record date | 2026-08-13 |
| Status | Canonical candidate qualification and live Gate 0B validation PASS; Final validation, SBOM/supply-chain evidence, release commit, package publication, and tag are pending |
| Current accepted baseline | SPELL v0.4.0; annotated tag `v0.4.0`; release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Gate 0A | `V05-GATE-0A PASS`; one work package authorized |
| Gate 0B | `V05-GATE-0B PASS`; release closeout authorized for `V05-IR-001` only |
| Qualified implementation | `aefa658ce01d49a7879d0471b50425ac3bcf9e2d` |
| Final release commit | Pending |
| Annotated release tag | Pending; only `v0.5.0` is authorized |
| Operational authorization | None |
| Compliance determination | None |

This is a bounded candidate closeout record. Product metadata is set to
`0.5.0` so the release candidate can be built and inspected, but metadata does
not accept the release. SPELL v0.4.0 remains the accepted product until Final
validation, SBOM/supply-chain validation, deterministic packaging, the release
commit, and the project owner's annotated `v0.5.0` tag are complete.

## Authorized Scope

The release contains one product work package:

| Work package | Result authorized by Gate 0B | Release disposition |
| --- | --- | --- |
| `V05-IR-001` - existing IR 0.3 fail-closed validation hardening | Implemented and qualified at candidate commit `aefa658` | Authorized for release closeout; final release acceptance pending |

The implementation adds an independent, bounded validator/canonicalizer for
the existing data-only IR 0.3 payload. Parser output is postvalidated. Stored
IR, current position, prompt recovery metadata, and checkpoint variables are
validated before supervisor worker allocation. The isolated worker repeats the
payload validation before `worker.started`, state acknowledgement, checkpoint,
prompt, or procedure effect. Rejections use bounded deterministic audit data,
and valid persisted IR bytes are not rewritten.

No new language construct, IR version, REST or WebSocket contract, database
schema, migration, frontend behavior, dependency, or driver capability is part
of this release.

## Preserved Identities

| Identity | v0.5.0 value | Reason |
| --- | --- | --- |
| Product/package/backend/frontend version | `0.5.0` | Release identity for the bounded product increment |
| Candidate qualification marker | `0.5.0-candidate` | Immutable pre-closeout evidence identity; not the runtime product version |
| Procedure IR | `spell-restricted-ast/0.3` | `V05-IR-001` hardens the existing format without creating a new one |
| Public API | `v1` | No API change was authorized |
| Report/event schema | `0.3` | No report or event contract change was authorized |
| Driver contract | `spell.driver.v1` | The accepted typed driver contract is unchanged |
| Bundled driver implementation/default | `0.4.0` | The driver executable and its compatibility handshake did not change in v0.5 |
| Release toolchain lock | `scripts/release-toolchain-v04.json` | Gate 0B deliberately inherits the accepted, digest-pinned v0.4 toolchain |

The driver implementation identity is intentionally not coupled to the product
package version. Advertising it as `0.5.0` without a driver change would create
a false compatibility identity and invalidate accepted handshake, persistence,
and regression evidence.

## Qualification And Closeout Evidence

Gate 0B is the approved release-closeout authorization. Its decision records
the required six `V05-IR-001` identities as qualified against the immutable
candidate commit. The canonical work-package record is now integrated and its
independent validator passes for candidate
`aefa658ce01d49a7879d0471b50425ac3bcf9e2d`, qualification correction/source
`ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`, evidence SHA-256
`86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`, four
suites, six identities, and 949 concrete tests. Commit `ef26e53` changes only
Docker inspection test timeout metadata; it does not change product behavior.
The live Gate 0B validator also passes with exact marker
`gate=PASS work_packages=1 identities=6 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED`.

| Evidence | Required path or identity | Current release-record status |
| --- | --- | --- |
| Gate 0A authorization | [`SPELL_v0.5_Pre-Implementation.md`](SPELL_v0.5_Pre-Implementation.md) | PASS |
| Gate 0B authorization | [`SPELL_v0.5_Gate_0B.md`](SPELL_v0.5_Gate_0B.md) | PASS for closeout scope; not final release acceptance |
| Candidate qualification | `artifacts/v0.5/work-package/qualification.json` | PASS; SHA-256 `86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`; 4 suites and 949 concrete tests |
| Six work-package identities | `V05-IR-001-UNIT`, `PARSER`, `SUPERVISOR`, `WORKER`, `COMPAT`, `ADVERSARIAL` | PASS in the canonical work-package record; Gate 0B live validation PASS |
| Supply-chain result | `artifacts/v0.5/supply-chain.json` and four image-bound SBOMs | Pending |
| Deterministic source package | `artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz` and external `.sha256` sidecar | Pending |
| Final validation | Complete release-source and evidence validation | Pending |
| Release commit | Immutable commit containing the complete closeout | Pending |
| Annotated tag | `v0.5.0` over the verified release commit | Pending |

No pending item may be represented as a pass by inference, a placeholder hash,
or inherited v0.4 evidence. Retained v0.4 artifacts are support and regression
evidence only; they are not v0.5 release evidence.

## Conditional Final Decision

| Decision field | Current value |
| --- | --- |
| Final release decision | Conditional project-owner acceptance, not yet effective; it becomes effective only when every condition below passes and the annotated `v0.5.0` tag is verified over the fixed release commit |
| Accepted exceptions | None authorized by this conditional decision |
| Release package SHA-256 | Pending; must come from the published external sidecar |
| Release commit | Pending |
| Tag object and peeled commit | Pending |
| Deployment approval | None |
| Operational authorization | None |
| Compliance determination | None |

Canonical candidate qualification integration is complete. Final acceptance
still requires all of the following without source drift:

1. Generate and validate the v0.5 supply-chain evidence and four distinct
   image-bound SBOMs.
2. Produce byte-identical deterministic packages and verify the external
   SHA-256 sidecar.
3. Run the complete Final release validation against the fixed release tree.
4. Commit this conditional record with the exact pre-tag results and hashes and
   bind the fixed source/evidence identities in the canonical release manifest.
5. Create and verify one annotated `v0.5.0` tag over that release commit.

Until every item is complete, this file is not an acceptance record and does
not authorize deployment, operational use, spacecraft connectivity, mission
use, or a compliance claim. If every condition passes, the verified annotated
tag makes the conditional project-owner acceptance recorded here effective at
that tag; no post-tag documentation commit is required. A failed or missing
condition leaves SPELL v0.4.0 as the accepted release.
