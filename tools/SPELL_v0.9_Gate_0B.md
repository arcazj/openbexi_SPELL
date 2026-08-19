# SPELL v0.9 Gate 0B Release Closeout

<!-- V09_GATE_0B_ACTIVATION_RECORD_BEGIN -->
## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.9.0 |
| Gate | `V09-GATE-0B` |
| Gate status | `PASS`; exact v0.9 release closeout authorized |
| Record date | 2026-08-18 |
| Accepted product baseline | Annotated tag `v0.8.0`; release commit `d6e01222de3bf52013279e48a099b6ae7ded121d` |
| Gate 0A authorization | Commit `92f3b4b82908d44e28b9506749e498386a428c27`; `V09-DEV-001` through `V09-DEV-009` |
| Candidate source | Commit `060001baf423fb82f27041f6b842630370c1a786`; tree `92689552d1dccdcbba53563306bdfbc505269b8a`; sole parent `92f3b4b82908d44e28b9506749e498386a428c27` |
| Canonical candidate evidence | `artifacts/v0.9/work-package/qualification.json`; SHA-256 `a1820154709f3893e88d32e772af6ced0a1635b379d108592a9635dc5b54b16e` |
| Required result inventory | Nine work packages; 45 exact test identities; zero mapped skips, failures, accepted failures, or waivers |
| Release tag requested | One annotated semantic-version tag: `v0.9.0` |
| Project owner | JC Arcaz |

Owner request: `start and complete asap V0.9`

Gate 0B decision: `V09_DEV_001_THROUGH_V09_DEV_009_RELEASE_CLOSEOUT_ONLY`

Release closeout authorization: `AUTHORIZED`

Release acceptance by Gate 0B: No

Operational authorization: None
<!-- V09_GATE_0B_ACTIVATION_RECORD_END -->

## Pending Decision

This is a fail-closed closeout contract for the exact work authorized by the
accepted v0.9 Gate 0A. Owner authorization permits implementation, but the
source freeze does not substitute for a committed candidate, canonical
evidence, or independent qualification. Candidate identity and evidence digest
therefore remain explicit null bindings rather than wildcards.

Gate 0B can become `PASS` only through the validator's atomic activation
protocol after all of these conditions hold:

1. One candidate commit has Gate 0A commit
   `92f3b4b82908d44e28b9506749e498386a428c27` as its sole parent.
2. Its exact changed-path, blob, and SHA-256 inventory is derived from Git
   object storage.
3. Canonical evidence at
   `artifacts/v0.9/work-package/qualification.json` is byte-bound to that
   candidate and independently passes
   `scripts/validate_candidate_evidence_v09.py` under CPython 3.13.14.
4. Every one of the 45 exact identities has concrete passing proof with zero
   mapped skips, failures, accepted failures, or waivers.
5. The reviewed development service, non-executing language service, separate
   browser surface, migration, dependency, and compatibility boundaries remain exact.

## Immutable Inputs

The accepted baseline is annotated tag `v0.8.0`, tag object
`0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, peeled release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`. The validator rechecks the
raw tag SHA-256, required nonclaim markers, and tagged evidence bytes from Git
objects.

The sole Gate 0A authority is commit
`92f3b4b82908d44e28b9506749e498386a428c27`, tree
`e6b90f1e277f905a1d885008262916d86d6cdceb`, directly over the accepted
release commit. It binds four governance records plus the nine exact
`contracts/v09` files. Candidate activation must preserve those blobs.

## Exact Work-Package Results

<!-- V09_GATE_0B_PACKAGE_DISPOSITIONS_BEGIN -->
All nine exact work packages are `IMPLEMENTED_AND_QUALIFIED`. Every listed identity has one or more concrete passing proof nodes; no mapped identity is skipped, failed, accepted as failed, or waived.
<!-- V09_GATE_0B_PACKAGE_DISPOSITIONS_END -->

| Work package | Exact required identities |
| --- | --- |
| `V09-DEV-001` | `CONTRACT`, `PROJECT-LIFECYCLE`, `WORKSPACE-RACE`, `BROWSER`, `SECURITY` |
| `V09-DEV-002` | `PARSER-GOLDEN`, `EDITOR`, `COMPLETION`, `NON-EXECUTION`, `DETERMINISM` |
| `V09-DEV-003` | `SCHEMA`, `DICTIONARY`, `CATALOG`, `REFERENCE`, `SECURITY` |
| `V09-DEV-004` | `UNIT`, `PROJECT-CHECK`, `CANCELLATION`, `PROBLEMS`, `RECOVERY` |
| `V09-DEV-005` | `IMPORT-EXPORT`, `EXTERNAL-CHANGE`, `CASE-CONFLICT`, `PATH-SECURITY`, `PROVENANCE` |
| `V09-DEV-006` | `HISTORY`, `DIFF`, `CONFLICT`, `COLLABORATION-RACE`, `SECURITY` |
| `V09-DEV-007` | `CANONICALIZATION`, `REPRODUCIBILITY`, `TAMPER`, `RETENTION`, `SECURITY` |
| `V09-DEV-008` | `STATE-MACHINE`, `AUTHORIZATION`, `TRANSACTION-AUDIT`, `ROLLBACK-WITHDRAWAL`, `PINNING` |
| `V09-DEV-009` | `SEMANTIC-GOLDEN`, `INTEGRATION`, `BROWSER-MATRIX`, `OFFLINE-PACKAGE`, `FAULT-RECOVERY` |

The machine scope contains the authoritative full identity strings in exact
package order. Ranges, wildcards, aliases, reordered identities, mapped skips,
or waivers fail closed.

## Reviewed Delta

The candidate adds a bounded authenticated development service and a separate
`/development.html` browser entry point. Project/resource lifecycle, language
services, dictionary/catalog authoring, semantic checks, import/export,
history/collaboration, immutable bundles, and local promotion remain inside
the eight accepted contract matrices. Language analysis is non-executing;
browser code receives no direct database, host-filesystem, credential, worker,
or unrestricted-network authority.

Migration `0008_development_environment` may add only its declared 19 tables
and must prove fresh install, populated upgrade, idempotence, rollback,
backup/restore, and SQLite/PostgreSQL behavior. Mutations remain authenticated,
revision checked, idempotent, and transactionally audited. The accepted v0.8
artifacts, Gate 0A contract blobs, legacy serialized IR, driver protocol, and
driver implementation version `0.4.0` remain unchanged. No product Python or
frontend runtime dependency is authorized.

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
  ("spell-v09-gate-0b-{0}.json" -f [guid]::NewGuid().ToString("N"))
try {
  & ./scripts/assert_release_toolchain_v04.ps1
  if ($LASTEXITCODE -ne 0) { throw "release toolchain validation failed" }
  & $env:SPELL_RELEASE_PYTHON_EXE -I NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py --prepare-activation $proposal
  if ($LASTEXITCODE -ne 0) { throw "Gate 0B activation preparation failed" }
  & $env:SPELL_RELEASE_PYTHON_EXE -I NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py --apply-activation $proposal
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

<!-- V09_GATE_0B_CURRENT_FINDING_BEGIN -->
`V09-GATE-0B PASS` authorizes release closeout for exactly `V09-DEV-001` through `V09-DEV-009`. It does not itself accept the release, authorize deployment or operational use, or make a compliance or cryptographic-signature claim.
<!-- V09_GATE_0B_CURRENT_FINDING_END -->
