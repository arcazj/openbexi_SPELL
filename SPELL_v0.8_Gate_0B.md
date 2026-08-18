# SPELL v0.8 Gate 0B Release Closeout

<!-- V08_GATE_0B_ACTIVATION_RECORD_BEGIN -->
## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.8.0 |
| Gate | `V08-GATE-0B` |
| Gate status | `PENDING_CANDIDATE`; no release closeout authorization yet |
| Record date | 2026-08-17 |
| Accepted product baseline | Annotated tag `v0.7.0`; release commit `cf18e9d887ba0476cbcc3d8194e321332a3ae864` |
| Gate 0A authorization | Commit `451c065740e7b6501f86094d9be79578b30b1591`; `V08-DATA-001` through `V08-DATA-009` |
| Candidate source | Pending source freeze |
| Canonical candidate evidence | Pending at `artifacts/v0.8/work-package/qualification.json` |
| Required result inventory | Nine work packages; 45 exact test identities; zero mapped skips, failures, accepted failures, or waivers |
| Release tag requested | One annotated semantic-version tag: `v0.8.0` |
| Project owner | JC Arcaz |

Owner request: `table are not correctly formated for some md file like SPELL_v0.7_Release.md. fix that. make sure to update all docs as well regarding last version implemented. then resume and finish up V0.7 asap, asap. once done finish up V0.8 and v0.9 asap. You have all approvals.`

Gate 0B decision: `PENDING_CANONICAL_V08_CANDIDATE_QUALIFICATION`

Release closeout authorization: `NOT_YET_AUTHORIZED`

Release acceptance by Gate 0B: No

Operational authorization: None
<!-- V08_GATE_0B_ACTIVATION_RECORD_END -->

## Pending Decision

This is a fail-closed closeout contract for the exact work authorized by the
accepted v0.8 Gate 0A. Owner authorization permits implementation, but it does
not substitute for a frozen candidate, canonical evidence, or independent
qualification. Candidate identity and evidence digest therefore remain
explicit null bindings rather than wildcards.

Gate 0B can become `PASS` only through the validator's atomic activation
protocol after all of these conditions hold:

1. One candidate commit has Gate 0A commit
   `451c065740e7b6501f86094d9be79578b30b1591` as its sole parent.
2. Its exact changed-path, blob, and SHA-256 inventory is derived from Git
   object storage.
3. Canonical evidence at
   `artifacts/v0.8/work-package/qualification.json` is byte-bound to that
   candidate and independently passes
   `scripts/validate_candidate_evidence_v08.py` under CPython 3.13.14.
4. Every one of the 45 exact identities has concrete passing proof with zero
   mapped skips, failures, accepted failures, or waivers.
5. The reviewed driver, IR, API, migration, dependency, and compatibility
   boundaries remain exact.

## Immutable Inputs

The accepted baseline is annotated tag `v0.7.0`, tag object
`70e4d46a46d158dee3c63ec37a5d1922b3b61668`, peeled release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864`. The validator rechecks the
raw tag SHA-256, required nonclaim markers, and tagged evidence bytes from Git
objects.

The sole Gate 0A authority is commit
`451c065740e7b6501f86094d9be79578b30b1591`, tree
`bc979259b873f1632ba10398dc31606c25e5bd9c`, directly over the accepted
release commit. It binds four governance records plus the nine exact
`contracts/v08` files. Candidate activation must preserve those blobs.

## Exact Work-Package Results

<!-- V08_GATE_0B_PACKAGE_DISPOSITIONS_BEGIN -->
Each package remains `PENDING_QUALIFICATION`. On Gate 0B activation, every row
must change to `IMPLEMENTED_AND_QUALIFIED` and every listed identity must have
one or more concrete passing proof nodes.
<!-- V08_GATE_0B_PACKAGE_DISPOSITIONS_END -->

| Work package | Exact required identities |
| --- | --- |
| `V08-DATA-001` | `UNIT`, `TYPE-MATRIX`, `SERIALIZATION`, `CORRUPTION`, `SECURITY` |
| `V08-DATA-002` | `UNIT`, `CONTRACT`, `GRAPH`, `RECOVERY`, `SECURITY` |
| `V08-DATA-003` | `UNIT`, `COMPATIBILITY-GOLDEN`, `IMPORT-EXPORT`, `CORRUPTION-RECOVERY`, `SECURITY` |
| `V08-DATA-004` | `UNIT`, `MATRIX`, `INTEGRATION`, `RECOVERY`, `SECURITY` |
| `V08-DATA-005` | `UNIT`, `INTEGRATION`, `RACE`, `RECOVERY`, `SECURITY` |
| `V08-DATA-006` | `UNIT`, `INTEGRATION`, `PATH-SECURITY`, `QUOTA-ATOMICITY`, `RECOVERY` |
| `V08-DATA-007` | `CONTRACT`, `AUTHORIZATION`, `IDEMPOTENCY-RACE`, `AUDIT-OUTBOX`, `SECURITY` |
| `V08-DATA-008` | `SCHEMA`, `SQLITE`, `POSTGRES`, `BACKUP-RESTORE`, `MIGRATION-ROLLBACK` |
| `V08-DATA-009` | `SEMANTIC-GOLDEN`, `INTEGRATION`, `FAULT-RECOVERY`, `LOAD`, `SECURITY` |

The machine scope contains the authoritative full identity strings in exact
package order. Ranges, wildcards, aliases, reordered identities, mapped skips,
or waivers fail closed.

## Reviewed Delta

The candidate may add internal IR 0.8 only for the closed catalog, dictionary,
data-container, shared-data, and virtual-file operation set. Accepted IR 0.3,
IR 0.6, and IR 0.7 blobs remain byte-pinned; source not selecting IR 0.8
retains its accepted behavior.

The v0.4 `DriverInfrastructureService` remains exactly nine unary RPCs with
its service body byte-preserved. `DriverObservationService` is a separate,
additive, read-only service with only `GetTime` and `GetTM`. The handshake
implementation version remains `0.4.0`; this gate makes no broad driver
compatibility claim.

The backend delta is restricted to canonical typed values, immutable local
catalog revisions, non-executing DB/IMP exchange, typed containers, authorized
shared data, and virtual-root files. Migration `0007_data_local_service` may
add only its declared 15 tables and must prove fresh install, populated upgrade,
idempotence, rollback, backup/restore, and SQLite/PostgreSQL behavior. The data
API remains authenticated, domain scoped, idempotent, and transactionally
audited. No new Python or frontend runtime dependency is authorized.

## Nonclaims

This pending gate does not claim implementation, qualification, release
acceptance, deployment approval, operational authorization, compliance, or
cryptographic signature verification. It does not authorize live GCS,
spacecraft, mission-network, telemetry, telecommand, commanding, external
effects, direct database access, host-filesystem escape, executable imports,
arbitrary evaluation, ambiguous coercion, partial write success, or unbounded
values, dependencies, queries, retries, quotas, or retention.

## Activation

The preparer is non-destructive and refuses the canonical scope as output. The
applier rederives and byte-compares that proposal, locks activation, atomically
replaces the scope and both marked documents, validates the published state,
and rolls all three targets back on any failure. Run both steps in one session
with a unique noncanonical proposal that is removed afterward:

```powershell
$proposal = Join-Path ([IO.Path]::GetTempPath()) `
  ("spell-v08-gate-0b-{0}.json" -f [guid]::NewGuid().ToString("N"))
try {
  & ./scripts/assert_release_toolchain_v04.ps1
  if ($LASTEXITCODE -ne 0) { throw "release toolchain validation failed" }
  & $env:SPELL_RELEASE_PYTHON_EXE -I NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v08_gate_0b.py --prepare-activation $proposal
  if ($LASTEXITCODE -ne 0) { throw "Gate 0B activation preparation failed" }
  & $env:SPELL_RELEASE_PYTHON_EXE -I NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v08_gate_0b.py --apply-activation $proposal
  if ($LASTEXITCODE -ne 0) { throw "Gate 0B activation failed" }
}
finally {
  Remove-Item -LiteralPath $proposal -Force -ErrorAction SilentlyContinue
}
```

While bindings remain pending, the only repository marker is:

```text
gate=PENDING work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=DENIED
```

A fully bound and independently qualified activation emits only:

```text
gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED
```

## Current Finding

<!-- V08_GATE_0B_CURRENT_FINDING_BEGIN -->
`V08-GATE-0B PENDING_CANDIDATE` records the exact release-closeout contract but
does not authorize closeout. Candidate freeze, canonical evidence, independent
validation, 45 passing identities, and reviewed delta binding remain required.
<!-- V08_GATE_0B_CURRENT_FINDING_END -->
