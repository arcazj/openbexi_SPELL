# SPELL v0.8.0 Release Record

<!-- V08_RELEASE_CONDITIONAL_RECORD_BEGIN -->
## Record Status

| Field | Value |
| --- | --- |
| Version | SPELL v0.8.0 |
| Release name | Local Data Service |
| Record state | `CONDITIONAL_PENDING`; this document is not an acceptance claim |
| Scope | `V08-DATA-001` through `V08-DATA-009` only |
| Accepted baseline | SPELL v0.7.0, annotated tag `v0.7.0` |
| Gate 0A | `PASS` at commit `451c065740e7b6501f86094d9be79578b30b1591` |
| Gate 0B | `PENDING_CANDIDATE` |
| Candidate source commit | Pending |
| Final qualified source commit | Pending |
| Release commit | Pending |
| Release tag | Pending annotated tag `v0.8.0` |
| Accepted exceptions | None proposed; final evidence must contain no accepted failure or waiver |
| Operational authorization | None |
| Compliance determination | None |
| Cryptographic signature | Not claimed |
| Project owner | JC Arcaz |

Owner request: `table are not correctly formated for some md file like SPELL_v0.7_Release.md. fix that. make sure to update all docs as well regarding last version implemented. then resume and finish up V0.7 asap, asap. once done finish up V0.8 and v0.9 asap. You have all approvals.`

Release decision: `PENDING_FINAL_EVIDENCE_RELEASE_COMMIT_AND_ANNOTATED_TAG`
<!-- V08_RELEASE_CONDITIONAL_RECORD_END -->

## Conditional Decision

This record defines the bounded v0.8.0 release outcome but remains conditional.
It is not evidence that Gate 0B passed and is not an accepted release record.
Acceptance requires a frozen candidate, all 45 exact Gate 0A identities passing
without mapped skips or waivers, final qualification and supply-chain evidence,
a deterministic package, one release commit, one annotated `v0.8.0` tag, and
strict post-tag validation with a clean worktree.

## Bounded Product Result

The intended release is the local synthetic runtime's bounded data-service
increment: canonical typed values, immutable catalog revisions and dependency
graphs, non-executing DB/IMP dictionary exchange, typed ARGS/IVARS containers,
revisioned shared data, virtual-root procedure files, and authenticated data
APIs with idempotency and transactional audit/outbox records.

The accepted v0.7 execution, authority, persistence, audit, effect-certainty,
IR 0.3/0.6/0.7, and accepted driver boundaries remain in force. This record
does not authorize a live data source, command path, host-filesystem access,
executable import, arbitrary evaluation, deployment, or operational use.

## Evidence Bindings

<!-- V08_RELEASE_EVIDENCE_BINDINGS_BEGIN -->
The following values must be inserted only after their canonical producers and
independent validators pass:

| Evidence | Required canonical location | Current value |
| --- | --- | --- |
| Candidate qualification | `artifacts/v0.8/work-package/qualification.json` | Pending |
| Gate 0B machine scope | `.../scopes/v0.8-gate-0b.json` | Pending activation |
| Final qualification | `artifacts/v0.8/final/qualification.json` | Pending |
| Release qualification manifest | `artifacts/v0.8/release-qualification.json` | Pending |
| Backend SBOM | `artifacts/v0.8/sbom/backend.cdx.json` | Pending |
| Frontend SBOM | `artifacts/v0.8/sbom/frontend.cdx.json` | Pending |
| Driver SBOM | `artifacts/v0.8/sbom/driver.cdx.json` | Pending |
| Proxy SBOM | `artifacts/v0.8/sbom/proxy.cdx.json` | Pending |
| Supply-chain result | `artifacts/v0.8/supply-chain.json` | Pending |
| Deterministic archive | `artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz` | Pending |
| Archive sidecar | `artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz.sha256` | Pending |
| Release commit | Git commit | Pending |
| Annotated tag object | `refs/tags/v0.8.0` | Pending |

<!-- V08_RELEASE_EVIDENCE_BINDINGS_END -->

## Final Closeout Sequence

Only after Gate 0B is atomically activated may final qualification, versioned
SBOMs, supply-chain evidence, deterministic packaging, release commit, and
annotated tagging proceed. Gate 0B itself changes this record only to
`CONDITIONAL_FINAL_CLOSEOUT`; it never changes it directly to accepted.

## Current Finding

<!-- V08_RELEASE_CURRENT_FINDING_BEGIN -->
SPELL v0.8.0 is not yet accepted by this record. Gate 0B activation, final
qualification, supply-chain evidence, deterministic packaging, the release
commit, annotated tag, and strict post-tag verification remain pending.
<!-- V08_RELEASE_CURRENT_FINDING_END -->
