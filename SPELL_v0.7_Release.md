# SPELL v0.7.0 Release Record

<!-- V07_RELEASE_CONDITIONAL_RECORD_BEGIN -->
## Record Status

| Field | Value |
| --- | --- |
| Version | SPELL v0.7.0 |
| Release name | Read-Only Observation and Condition Engine |
| Record state | `CONDITIONAL_FINAL_CLOSEOUT`; this document is not yet an acceptance claim |
| Scope | `V07-OBS-001` through `V07-OBS-009` only |
| Accepted baseline | SPELL v0.6.0, annotated tag `v0.6.0` |
| Gate 0A | `PASS` at commit `07c19437d28bc32a88d9970a4104d6c0fde53073` |
| Gate 0B | `PASS` |
| Candidate source commit | `82b497227aff097db9d4c3ff56adf56d76d892ca` |
| Final qualified source commit | Pending |
| Release commit | Pending |
| Release tag | Pending annotated tag `v0.7.0` |
| Accepted exceptions | None proposed; final evidence must contain no accepted failure or waiver |
| Operational authorization | None |
| Compliance determination | None |
| Cryptographic signature | Not claimed |
| Project owner | JC Arcaz |

Owner request: `resume and finish up asap v0.6 asap and move forward to finis up v0.7 asap. you have all aprrovals.`

Release decision: `PENDING_FINAL_EVIDENCE_RELEASE_COMMIT_AND_ANNOTATED_TAG`
<!-- V07_RELEASE_CONDITIONAL_RECORD_END -->

## Conditional Decision

This record defines the bounded v0.7.0 release outcome but remains conditional.
It is not evidence that Gate 0B passed and is not an accepted release record.
Acceptance requires a frozen candidate, all 45 exact Gate 0A identities passing
without mapped skips or waivers, final qualification and supply-chain evidence,
a deterministic package, one release commit, one annotated `v0.7.0` tag, and
strict post-tag validation with a clean worktree.

## Bounded Product Result

The intended release is the local synthetic simulator's read-only observation
and condition increment: explicit driver time/provenance, typed current/next
telemetry, declarative Verify, durable WaitFor and condition schedules, typed
resource/lookups, read-only limits/alarm state, durable snapshot/cursor streams,
and integrated observation acceptance.

The accepted v0.6 execution, authority, persistence, audit, effect-certainty,
IR 0.3/0.6, and legacy nine-RPC driver boundaries remain in force. This record
does not authorize a live data source, command path, observation mutation,
arbitrary evaluation, deployment, or operational use.

## Evidence Bindings

<!-- V07_RELEASE_EVIDENCE_BINDINGS_BEGIN -->
The following values must be inserted only after their canonical producers and
independent validators pass:

| Evidence | Required canonical location | Current value |
| --- | --- | --- |
| Candidate qualification | `artifacts/v0.7/work-package/qualification.json` | `PASS`; SHA-256 `04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20` |
| Gate 0B machine scope | `.../scopes/v0.7-gate-0b.json` | `PASS`; SHA-256 `8b8a6985bf4942d6554f9c10b0d2eaf0cab7cd84adcbea170f00eef87249f28f` |
| Final qualification | `artifacts/v0.7/final/qualification.json` | Pending |
| Release qualification manifest | `artifacts/v0.7/release-qualification.json` | Pending |
| Backend SBOM | `artifacts/v0.7/sbom/backend.cdx.json` | Pending |
| Frontend SBOM | `artifacts/v0.7/sbom/frontend.cdx.json` | Pending |
| Driver SBOM | `artifacts/v0.7/sbom/driver.cdx.json` | Pending |
| Proxy SBOM | `artifacts/v0.7/sbom/proxy.cdx.json` | Pending |
| Supply-chain result | `artifacts/v0.7/supply-chain.json` | Pending |
| Deterministic archive | `artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz` | Pending |
| Archive sidecar | `artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256` | Pending |
| Release commit | Git commit | Pending |
| Annotated tag object | `refs/tags/v0.7.0` | Pending |

<!-- V07_RELEASE_EVIDENCE_BINDINGS_END -->

## Final Closeout Sequence

Only after Gate 0B is atomically activated may final qualification, versioned
SBOMs, supply-chain evidence, deterministic packaging, release commit, and
annotated tagging proceed. Gate 0B itself changes this record only to
`CONDITIONAL_FINAL_CLOSEOUT`; it never changes it directly to accepted.

## Current Finding

<!-- V07_RELEASE_CURRENT_FINDING_BEGIN -->
Gate 0B has passed for the exact nine-package v0.7 candidate, but SPELL v0.7.0 is not yet accepted by this record. Final qualification, supply-chain evidence, deterministic packaging, the release commit, annotated tag, and strict post-tag verification remain pending.
<!-- V07_RELEASE_CURRENT_FINDING_END -->
