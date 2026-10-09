# SPELL v0.19.1 Implementation

Accepted `v0.19.1` was published on 2026-10-09 with the isolated Python runtime,
source-line debugger and inherited v0.19 local DSS product. The annotated tag and its independently
validated committed qualification, manifest and reproducibility records under
`artifacts/v0.19.1/` govern acceptance. A mutable worktree or this document alone
does not establish a passing release.

## Python Runtime And Controls

The explicit `python-stdlib/3.13` profile runs captured source in a networkless
service. The trusted launcher drops the child to an unprivileged identity inside
a private chroot containing only CPython, its standard library and required
shared libraries. The child receives no service credentials. Source digests,
output and exit status are bound to the request, generation and execution.

Console jobs load paused before their first executable line. Permanent
breakpoints stop before execution and repeat on later loop visits. Step enters
functions; Step Over stops in the caller unless an inner breakpoint is reached.
Run to Line uses a temporary target. Traced pauses stop all descendants. Signal
Pause can interrupt a C call and clears the unavailable exact source highlight.
Abort/Stop fence cleanup of the entire process family. Paused source position
and complete bounded output survive refresh and reopening.

Line debugging covers the captured script's main thread, including its functions
and async work on that thread. Imported modules, other filenames, threads and
subprocesses are outside line tracing. Evaluation, object editing, SKIP/GOTO,
background execution and replay are unavailable. Source metadata is bounded and
compiled only for static executable-line discovery; it is never executed by the
control plane. Existing closed SPELL profiles retain their validators.

Completion stores summary variables only after every output event is durable
and the actual process exits successfully. Python objects are not recovery
checkpoints. Interrupted source must be explicitly admitted as a new execution.
All pauses count toward the job lifetime. Setup and exact bounds are documented
in the [procedure guide](../../procedures/README.md#python-feature-reference).

## Qualification Contract

The [entry record](SPELL_v0.19.1_Pre-Implementation.md) requires source, isolation,
debugger, durability, procedure, DSS, browser and release proofs. The collected
test identities are frozen in `contracts/v19.1/release_policy.json` before
candidate and final qualification. PostgreSQL/Compose runs must resolve every
environment-selected SQLite skip. The actual runner participates in both
database suites and the candidate suite.

The automatic DSS inventory includes all 12 procedure files and every inherited
language case, adaptation, variant and menu selection: 956 identities and
32 declared scenarios. Native Test Python must finish all 261 checks over
39 topics without optional skips; Test Python Core must finish all six checks.
Native Python scenarios also prove no spacecraft command dispatch. The inherited
DSS scenarios retain actual correlated binary CCSDS TC and decoded Kafka TM,
fault outcomes and a final paused, fault-free state.

Seven distinct image identities require inspected runtime boundaries, CycloneDX
SBOMs and vulnerability disposition: backend, driver, DSS, Kafka, frontend build,
proxy and Python runner. Release publication requires all canonical gates,
four identical packages across two independent source exports, and validation
of the clean annotated tag. Earlier accepted evidence remains immutable.

This is a local simulator. Full SPELL 2.4.4 language conformance, real legacy
system qualification and operational authority are not claimed.

## Accepted Results

The seven final suites recorded **7,305 passed executions** and 45 environment-selected skips, all resolved by complementary runs. The candidate separately passed 1,426 checks. Full DSS delivery passed 956 identities and 32 scenarios; Test Python completed all 261 checks over 39 topics, and Test Python Core completed six checks. Seven image inventories, supply-chain checks, four matching packages, independent clean-tag validation and all four public downloads passed. No exceptions were accepted.

| Final gate | Passed executions | Environment-selected skips |
| --- | --- | --- |
| sqlite | 3,263 | 41 |
| postgresql | 3,179 | 4 |
| frontend | 190 | 0 |
| browser | 34 | 0 |
| compose | 4 | 0 |
| documentation | 18 | 0 |
| tooling | 617 | 0 |

Every DSS identity and scenario ran freshly against the qualified source and seven bound images. The actual Python scenarios prove completion without spacecraft command dispatch. The final DSS state is paused and fault-free.

## Accepted Release Binding

| Binding | Accepted value |
| --- | --- |
| Annotated tag object | `6ee72201741563768b36f1063ff635f48ba83a81` |
| Release commit | `4ca64a4170a646a1f0528b90e237f8aedf2b2bfa` |
| Qualified source / tree | `5fbc85b5ae263a66a5768e1a42331884b80992c5 / c14344b304abb2491044cefb434bc87affae4fcb` |
| Source fingerprint | `82a76b956dd4ec948b83b81d2e0dd55bdbdf1851b20d84494096f6e42867b9a6` |
| Accepted predecessor | `v0.19.0, commit 57cc80d969ebc222d47f0e8d19f962682c47d10c` |
| Candidate source / checks | `8fbd50cb894c9f5b8c75e120415cd015de7b4051 / 1,426 passed` |
| Package SHA-256 | `6eb93c400d66a918eb5ba91d4b2a01d1cc7734d47c2e1b8ed8be4a14332d64db` |
| Qualification SHA-256 | `793dc13392647f55f32b962a5ab76b5dd5bf31b37bf25bb4ce068c00a0be0d9e` |
| Manifest SHA-256 | `c848a836488edecd94449ed2ac7913c2f64af6ef2aa6bcb26c8cec39d106ceef` |
| Reproducibility SHA-256 | `2e490056e9450888a9d4304a5c77d1b18a1e02fac4e69a0742540c73527c7a16` |
| DSS report SHA-256 | `890fce6bc29802993b0a3309cfe19c69ed062de0d56e7ba93d5f5442cdb7c7ee` |
| DSS producer bindings SHA-256 | `87c44bfee123176c16e00d88dd0930c5b3201b39592226548d1bf44bca6c92f0` |
| DSS raw captures / governed requirements | `1061 / 8` |
| Tag / publication time | `2026-10-09 17:45:16 EDT / 2026-10-09 17:55:13 EDT` |

The [GitHub release](https://github.com/arcazj/openbexi_SPELL/releases/tag/v0.19.1) contains four verified assets. The [qualification](../../artifacts/v0.19.1/qualification.json), [manifest](../../artifacts/v0.19.1/release-manifest.json) and [reproducibility record](../../artifacts/v0.19.1/reproducibility.json) retain the exact evidence. Documentation closeout does not alter the tagged package or acceptance.
