# SPELL v0.9.0 Release Record

<!-- V09_RELEASE_CONDITIONAL_RECORD_BEGIN -->
## Record Status

| Field | Value |
| --- | --- |
| Version | SPELL v0.9.0 |
| Release name | SPELL Development Environment |
| Record state | `CONDITIONAL_PENDING`; this document is not an acceptance claim |
| Scope | `V09-DEV-001` through `V09-DEV-009` only |
| Accepted baseline | SPELL v0.8.0, annotated tag `v0.8.0` |
| Gate 0A | `PASS` at commit `92f3b4b82908d44e28b9506749e498386a428c27` |
| Gate 0B | `PENDING_CANDIDATE` |
| Candidate source commit | Pending |
| Final qualified source commit | Pending |
| Release commit | Pending |
| Release tag | Pending annotated tag `v0.9.0` |
| Accepted exceptions | None proposed; final evidence must contain no accepted failure or waiver |
| Operational authorization | None |
| Compliance determination | None |
| Cryptographic signature | Not claimed |
| Project owner | JC Arcaz |

Owner request: `start and complete asap V0.9`

Release decision: `PENDING_FINAL_EVIDENCE_RELEASE_COMMIT_AND_ANNOTATED_TAG`
<!-- V09_RELEASE_CONDITIONAL_RECORD_END -->

## Conditional Decision

This record defines the bounded v0.9.0 release outcome but remains conditional.
It is not evidence that Gate 0B passed and is not an accepted release record.
Acceptance requires a frozen candidate, all 45 exact Gate 0A identities passing
without mapped skips or waivers, final qualification and supply-chain evidence,
a deterministic package, one release commit, one annotated `v0.9.0` tag, and
strict post-tag validation with a clean worktree.

## Bounded Product Result

The intended release is a bounded local development environment with project
and resource lifecycle management, non-executing language services,
dictionary/catalog authoring, semantic checks and Problems, safe import/export,
provider-neutral local history and collaboration, immutable validated bundles,
and a local simulator promotion registry. The product exposes a separate
`/development.html` browser entry point backed by authenticated APIs.

The accepted v0.8 execution, authority, persistence, audit, effect-certainty,
serialized IR, release evidence, and driver boundaries remain in force. This
record does not authorize source execution, a live data source, command path,
host-filesystem escape, arbitrary evaluation, deployment, or operational use.

## Evidence Bindings

<!-- V09_RELEASE_EVIDENCE_BINDINGS_BEGIN -->
The following values must be inserted only after their canonical producers and
independent validators pass:

| Evidence | Required canonical location | Current value |
| --- | --- | --- |
| Candidate qualification | `artifacts/v0.9/work-package/qualification.json` | Pending |
| Gate 0B machine scope | `.../scopes/v0.9-gate-0b.json` | Pending activation |
| Final qualification | `artifacts/v0.9/final/qualification.json` | Pending |
| Release qualification manifest | `artifacts/v0.9/release-qualification.json` | Pending |
| Backend SBOM | `artifacts/v0.9/sbom/backend.cdx.json` | Pending |
| Frontend SBOM | `artifacts/v0.9/sbom/frontend.cdx.json` | Pending |
| Driver SBOM | `artifacts/v0.9/sbom/driver.cdx.json` | Pending |
| Proxy SBOM | `artifacts/v0.9/sbom/proxy.cdx.json` | Pending |
| Supply-chain result | `artifacts/v0.9/supply-chain.json` | Pending |
| Deterministic archive | `artifacts/v0.9/openbexi-spell-v0.9.0.tar.gz` | Pending |
| Archive sidecar | `artifacts/v0.9/openbexi-spell-v0.9.0.tar.gz.sha256` | Pending |
| Release commit | Git commit | Pending |
| Annotated tag object | `refs/tags/v0.9.0` | Pending |

<!-- V09_RELEASE_EVIDENCE_BINDINGS_END -->

## Final Closeout Sequence

Only after Gate 0B is atomically activated may final qualification, versioned
SBOMs, supply-chain evidence, deterministic packaging, release commit, and
annotated tagging proceed. Gate 0B itself changes this record only to
`CONDITIONAL_FINAL_CLOSEOUT`; it never changes it directly to accepted.

## Current Finding

<!-- V09_RELEASE_CURRENT_FINDING_BEGIN -->
SPELL v0.9.0 is not yet accepted by this record. Gate 0B activation, final
qualification, supply-chain evidence, deterministic packaging, the release
commit, annotated tag, and strict post-tag verification remain pending.
<!-- V09_RELEASE_CURRENT_FINDING_END -->
