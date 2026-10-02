# SPELL v0.17 Direct Language Conformance

Accepted `v0.17.0` was published on 2026-10-02 after independent clean-tag validation. It succeeds accepted v0.16.0. The original entry gate and earlier release evidence remain unchanged.

## Scope

- Direct scalar, operator, conditional and range evidence, including empty
  ranges and bounded integer power/bitwise operations.
- Native Display and Prompt syntax, typed answers and explicit default,
  timeout, cancellation and recovery behavior.
- Complete source inventory with separate missing-implementation,
  missing-proof and manual-conflict reasons.
- Expanded 292-choice reference runner: 195 adaptations, 96 direct/rejection
  cases and an all-suite choice. All 257 adapted variants and earlier direct-case
  identities are retained.
- Concise user documentation and complete source-bound qualification.

The local profile retains fixed types, finite numeric values, resource bounds,
controller permissions and source non-execution. Collections, general function
arguments/returns, exceptions, real legacy connectivity and operational
authorization remain outside this release. Passing bounded cases does not
establish full SPELL 2.4.4 compatibility.

## Compatibility Decisions

The dedicated Prompt section (Language Reference 2.4.4 page 72) governs the
conflicting page-112 timeout summary: a positive timeout without Default warns
once and remains open. Timeout zero waits indefinitely. Default automatically
settles only with a positive timeout. Native Cancel answers remain answers;
local Abort ends execution without fabricating a result. Earlier stored IR and
explicit lowercase prompt forms retain their contracts.

New bare Prompt calls use the documented default OK type. Native string/date
answers, finite numeric answers and list key/index/value results use the typed,
bounded profile recorded by the implementation; legacy date-object equivalence
is not claimed. Dynamic Display values accept bounded empty strings in IR 0.17.

New native features cannot be mixed with the earlier data/argument, file,
environment or telecommand service profiles. Those profiles retain their
existing nonempty Display/log behavior and authoritative runtime paths.
Unsupported combinations are rejected explicitly; their support remains a gap.

Native assignments require the exact Prompt result type. LIST is limited to
1-1000 choices; literal ranges to 1000 iterations. Numeric answers must be finite
and fit the 128-character decimal representation used by the worker. Timeout
is limited to seven days.

## Verification

Annotated `v0.17.0` passed independent clean-tag validation and was published. The seven final suites recorded 4,563 passed executions; all 24 environment-selected skips were resolved by complementary runs. The candidate gate passed 363 checks. Four package builds across two independent exports matched, with no accepted exceptions.

| Final gate | Passed executions | Environment-selected skips |
| --- | --- | --- |
| SQLite | 2,169 | 21 |
| PostgreSQL | 2,105 | 3 |
| Frontend | 150 | 0 |
| Desktop/mobile browser | 20 | 0 |
| Compose | 3 | 0 |
| Documentation | 18 | 0 |
| Release tooling | 98 | 0 |

The 763-entry inventory records 195 ADAPTED, 76 PARTIAL and 492 GAP entries. All 96 cases passed: 67 direct-source checks and 29 expected rejections. The 195 adaptations retain 257 variants. Neither adaptations nor correct rejection establish complete language support.

Language, build, soak, image, SBOM and supply-chain gates passed. Raw scanner findings and their applicability dispositions remain in the bound evidence; this is not a claim that images contain no advisories. Original manuals and historical releases are unchanged.

## Accepted Release Binding

| Binding | Accepted value |
| --- | --- |
| Annotated tag object | `a7311ddad24a4c74599f8d518331dfc398109fb9` |
| Release commit | `e525b9c842e3c26a35058d85fc40bd3ee4b16c85` |
| Qualified source / tree | `b4e5382010050bc56346c77628b9ddaf425e3d7e` / `a655471616718d460f2ad42364d933212306d76e` |
| Source fingerprint | `088790991cf1b2412b57d89a8df4ad31cb41a7dedb360c15b2ae7937734b0cf9` |
| Accepted predecessor | `v0.16.0`, release commit `1b0aa8e582cb13b9d6aa5196fd66fc56d9d3ad10` |
| Candidate source / checks | `b112cce6f02790091c7b4dc67abe89343e50c7ef` / 363 passed |
| Package SHA-256 | `14a532ccbde01b5a33970e04a7594a25d34d3d6fc6c1fbfcca36c9f105cfb69d` |
| Qualification SHA-256 | `996132c5897939e2d0b145cd873d0c0edfbfad873c1a6b07df123d0f2f731b90` |
| Manifest SHA-256 | `745bcefff47ef1a52d876afb9753b6b846fb8b98ad52ec4dc4e8c2738c19cf68` |
| Reproducibility SHA-256 | `9322d56751fbb4b9d6e228f5516febb8ce9eb0781662c8bc26deeeb326a1fec1` |
| Language report SHA-256 | `6c7abc60faa5bfcca27b5e3d9cec6ab9a2fc08f130f94d55a43f2e5838d3ae53` |
| Tag / publication time | 2026-10-02 06:30:01 EDT / 2026-10-02 06:31:18 EDT |

Published [GitHub release](https://github.com/arcazj/openbexi_SPELL/releases/tag/v0.17.0) includes four verified assets. The [qualification](../../artifacts/v0.17/qualification.json), [manifest](../../artifacts/v0.17/release-manifest.json) and [reproducibility record](../../artifacts/v0.17/reproducibility.json) retain detailed evidence. Later documentation closeout does not change the tagged source, package or acceptance.

Full SPELL 2.4.4 compatibility, real legacy qualification and operational authorization remain outside this local simulator profile.
