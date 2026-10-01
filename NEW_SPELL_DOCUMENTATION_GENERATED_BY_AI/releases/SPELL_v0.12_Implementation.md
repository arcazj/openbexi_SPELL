# SPELL v0.12 Read-Only Observation

## Delivered Scope

The accepted v0.12.0 release adds a strict translator for immutable synthetic captures
of the documented SPELL 2.4.4 telemetry model. It provides typed raw and
engineering values, lossless integer transport, validity and quality,
recorded acquisition time, bounded catalogs, resource and limit reads,
snapshot recovery, source-bound replay cursors, and explicit simulator fallback.

An independently authored simulator oracle supplies the comparison baseline.
The bundled report contains five equivalent, three indeterminate, and one
unsupported observations across telemetry, resource, and limit comparisons.
Those categories describe the fixture evidence, not implementation test failures.
Changed values, units, times, resources, and limits produce different results;
missing or unusable evidence never becomes an equivalent result.

The operator console exposes **Legacy observation replay** under **Driver
foundation**. Select the reference capture or simulator fallback, inspect raw
and engineering values, and refresh the recorded snapshot. All observation
requests use authenticated GET endpoints under `/api/v1/legacy-observation`.
Viewer access is supported; no mutation, command, upload, credential, endpoint,
or network dispatch interface exists in the replay source.

## Reference And Limits

See the source sections and compatibility decisions in
[the entry gate](SPELL_v0.12_Pre-Implementation.md). Source data and the oracle
are explicitly `INDEPENDENT_SYNTHETIC_FIXTURE`; they are not captures from a
running legacy system. A real legacy test environment was not supplied and its
compatibility remains unqualified. This release does not complete the broader
SPELL 2.4.4 language surface or authorize operational use.

No parser or database schema changes are required. Existing simulator procedure
execution, v0.10 reference examples, and v0.11 telecommand semantics remain
inherited regression requirements. The HTTPX2/httpcore2 locks move to 2.12.0;
Vitest moves to 4.1.11 and affected browser-mapping dependencies are updated to
resolve the advisories observed during the release audit.

The Debian runtime updates libc, OpenSSL, PCRE2, and SQLite to exact patched
package versions. zlib is built from hash-pinned upstream commit
`df84af25dc1942490e1d1c899a07619152a46148`; its upstream tests run during the
image build, and runtime probes bind its actual shared-library bytes and version.
The [upstream correction](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148)
addresses CVE-2026-85091, for which the distribution scan had no packaged fix.
This pinned upstream snapshot is an explicit dependency choice for the local
synthetic release. The proxy removes unused optional dynamic modules and updates
OpenSSL, PCRE2, and xz; its configured HTTP/WebSocket behavior is unchanged.
Lower-severity advisories have individual IDs and a 2026-10-30 review deadline
in the committed supply-chain evidence.

## Verification And Release

`scripts/release_v12.py` validates raw test identities, exact environment skips,
their resolution, source and manual hashes, replay soak, dependency audit,
four image SBOMs, deterministic package bytes, and the annotated release tag.
All JSON evidence is written as canonical UTF-8/LF bytes. Product PNG assets
are preserved; generated screenshots, manuals, legacy archives, prior release
artifacts, caches, and credentials are excluded from the package.

The policy is `contracts/v12/release_policy.json`. Canonical evidence is
`artifacts/v0.12/qualification.json` and its `evidence/` directory. Acceptance
requires a clean `v0.12.0` checkout to pass
`python -m scripts.release_v12 validate --require-tag`; a candidate or this
document alone is not an accepted release.

On the qualified Windows host, run canonical producers through
`scripts/run_release_v12.ps1 -Module scripts.qualify_release_v12 -Arguments @('sqlite')`.
The wrapper verifies `scripts/release-toolchain-v12.json`, including Python
3.13.14, Node 24.19.0, Docker, scanner, SBOM, and Git executables.
The complete gate names are defined by the producer; `prepare` builds the images
and starts the loopback stack, and `assemble` joins their source-bound records.
The seven test suites contain 1,699 SQLite/driver, 1,617 PostgreSQL, three Compose,
114 frontend, 18 documentation, 17 tooling, and four real browser cases.
The 19 SQLite and three PostgreSQL environment skips must resolve through the
PostgreSQL and Compose runs. Replay includes a 60-second deterministic soak,
a one-second per-iteration latency budget, and all 195 inherited reference
examples with their 257 variants.

## Accepted Release Binding

The annotated tag and an independent clean tagged checkout both passed
`scripts/release_v12.py validate --require-tag`. This documentation closeout is
subsequent to the immutable release; validate the tag checkout, not the later
default-branch documentation fingerprint.

| Endpoint | Immutable identity |
| --- | --- |
| Qualified source | `f01363685ba79582a93bc677cbcf0c415ad4ee84` |
| Source fingerprint | `afb52322e59265bbfe37ad74b5e6b146dfb83e159665e0c90d296f3693fc461a` |
| Release commit | `978c89ecec5ae1bdc57a9fc27395b7c12c8acbb6` |
| Annotated tag | `v0.12.0`, object `48b577faafdb9b5011cc5240201e8ce45d88cfee` |
| Package SHA-256 | `9395fa09f2724c389a711b0d3bdeeda638358729a0922d662223b14b81eb45d9` |
| Package inventory | 711 files; 3,445,082 bytes |
| Accepted exceptions | None |

| Executed gate | Result |
| --- | --- |
| Complete SQLite/driver regression, network disabled | 1,680 passed; 19 exact environment skips |
| Complete PostgreSQL regression | 1,614 passed; three exact Compose skips |
| Compose isolation and builders | Three passed; all environment skips resolved across the PostgreSQL and Compose runs |
| Frontend and production build | 114 passed; TypeScript/Vite build passed |
| Documentation and release tooling | 18 and 17 passed |
| Real browser | Four passed across desktop and mobile, including reference Example 195 and observation replay |
| Reference examples and replay | 195 examples, 257 variants, and 60-second deterministic replay soak passed |
| Dependencies and images | Python/npm audits clear; four strict CycloneDX SBOMs; zero Critical/High image findings |
| Reproducibility | Two builds in each of two independent exports; all four archive hashes identical |

The aggregate is 3,450 passed test executions in 3,472 cases, with 22 resolved
environment skips and no failed tests. Canonical retained records are
[qualification](../../artifacts/v0.12/qualification.json),
[raw evidence](../../artifacts/v0.12/evidence/), and
[reproducibility](../../artifacts/v0.12/reproducibility.json).

Qualification corrected parameterized-test inventory handling for identifiers
containing `::` and synchronized the handover-expiry test with its background
reconciler. One resource-contended SQLite attempt exceeded an existing worker
acknowledgment deadline. The full suite then passed in isolation on the same
frozen source, with no timeout or behavior weakened; failed attempts are retained
locally outside the canonical evidence. The verified loopback application was
restored after qualification and reports runtime `0.12.0` at
`http://127.0.0.1:8080`, Compose project `spellv012release`. Its ignored local
environment file is `.qualification/v12/final/runtime.env`.
