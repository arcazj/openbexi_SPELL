# SPELL v0.5 Gate 0B Release Closeout

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.5.0 |
| Gate | `V05-GATE-0B` |
| Gate status | `PASS`; release closeout is authorized only for `V05-IR-001` |
| Gate date | 2026-08-13 |
| Accepted product baseline | Annotated tag `v0.4.0`; commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Gate 0A authorization | Commit `d13397f51241c6bac10289ea21b69aafff66b1fb` |
| Qualified implementation | Commit `aefa658ce01d49a7879d0471b50425ac3bcf9e2d` |
| Frozen qualification source | Commit `ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`; one test compatibility correction only |
| Work package | `V05-IR-001` - existing IR 0.3 fail-closed validation hardening |
| Work-package evidence SHA-256 | `86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9` |
| Release tag authorized | One annotated semantic-version tag: `v0.5.0` |
| Project owner | JC Arcaz |

Owner request: `execute 1, 2, 3, 4, 5. when done finish up and tag v0.5.`

Release closeout authorization: `V05_IR_001_RELEASE_CLOSEOUT_ONLY`

Broader v0.5 product work authorized: No

Release acceptance by Gate 0B: No

## Decision

Gate 0B records that the only Gate 0A work package has completed its required
qualification and may proceed through release closeout. It authorizes recording
`V05-IR-001` as implemented, publishing its canonical evidence, updating
product version and release records, producing the deterministic package and
supply-chain evidence, committing those closeout records, and creating the
annotated `v0.5.0` release tag.

The owner's abbreviated tag request is resolved to `v0.5.0`, the exact release
target established by Gate 0A and the repository's semantic-version tag
convention. Gate 0B does not authorize a lightweight `v0.5` alias or a second
tag for the same release.

This gate is not itself the final release acceptance record. The release record,
release commit, deterministic package result, and annotated tag must still be
completed and verified. Gate 0B grants authority to perform those actions only
after its validator passes against the canonical candidate qualification.

## Immutable Inputs

### Accepted v0.4.0 Baseline

The validator independently verifies the existing immutable release:

| Binding | Value |
| --- | --- |
| Tag ref | `refs/tags/v0.4.0` |
| Object type | `tag` |
| Tag object | `86390c90e8d5f96f872be43274cbc9d789a34c2d` |
| Raw tag-object SHA-256 | `ae7030aa54ad9c69761ae764c4edd2535b47ae842a2f4f5b4c20aad859fca663` |
| Peeled commit | `4546d313a2d8f50504b2bc602d56b3b459ca7597` |

The validator also checks the three baseline file digests recorded in the
machine-readable scope and the exact release tag markers for owner, decision,
exceptions, operational authorization, and compliance determination.

### Gate 0A Authorization

Gate 0B reads Gate 0A from Git object storage at commit
`d13397f51241c6bac10289ea21b69aafff66b1fb`. It requires that commit's exact
single parent, tree, four controlling blob IDs, and blob SHA-256 values. It
strict-parses the committed Gate 0A scope and confirms the original one-package
authorization and six planned identity IDs.

This deliberately does not run the Gate 0A validator against mutable current
documents. Later history and release edits cannot retroactively change the
authorization that governed the implementation.

### Candidate Implementation

The qualified candidate is exactly
`aefa658ce01d49a7879d0471b50425ac3bcf9e2d`, with Gate 0A as its sole parent
and tree `958c43e867228b536fd21c0da59d5530e9fe155b`. The machine-readable scope
binds all nine changed paths, their add/modify status, Git blob ID, and SHA-256.
Any extra path, merge parent, replacement object, altered blob, or displaced
ancestry fails the gate closed.

Qualification runs against commit
`ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`, tree
`f646a40bcd70ec9ebc28f3ebf3783e54c1c8f9a1`. Its sole delta from its
documentation-bridge parent is `backend/tests/test_driver_isolation.py`, blob
`60ed5164ffe190ccbb5cee91ffe619eba7c8c9c2`, SHA-256
`d0eca2c56705068027b910991719971838d5f84033806f9a0ff9de0f7b3e0756`.
The correction reads the current Docker `Config.StopTimeout` inspection field;
it changes only test compatibility with the pinned and installed Docker
versions. It does not alter product behavior, the `aefa658` implementation
identity, Gate 0A scope, or any compatibility claim.

## Qualification Evidence

Canonical work-package evidence is stored at
[`qualification.json`](../../artifacts/v0.5/work-package/qualification.json). Its
independent validator is
[`validate_candidate_evidence_v05.py`](../../scripts/validate_candidate_evidence_v05.py).
Gate 0B invokes that validator in a separate locked-Python process, requires
one strict JSON success line, and independently checks the evidence digest and
security-critical bindings.

Qualification must prove:

1. The evidence is bound to the exact candidate commit, parent, tree, paths,
   and blobs.
2. CPython 3.13.14 and the repository's hash-locked toolchain were used.
3. The SQLite backend, isolated PostgreSQL backend, driver-host, and tooling
   suites all passed.
4. `SPELL_TEST_DATABASE_URL` and `SPELL_MIGRATION_TEST_DATABASE_URL` were both
   bound to distinct isolated PostgreSQL databases.
5. PostgreSQL qualification contains zero skips, failures, or errors.
6. The inherited v0.4 regression evidence passed and is source-fingerprint
   bound.
7. All referenced JUnit files and the qualification record match their
   recorded SHA-256 values.

The six required identity results are exactly:

| Identity | Required result |
| --- | --- |
| `V05-IR-001-UNIT` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |
| `V05-IR-001-PARSER` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |
| `V05-IR-001-SUPERVISOR` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |
| `V05-IR-001-WORKER` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |
| `V05-IR-001-COMPAT` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |
| `V05-IR-001-ADVERSARIAL` | PASS; concrete nodes; SQLite and PostgreSQL; zero skips |

An identity cannot pass through a waiver, inferred coverage, an empty node
list, or a skipped PostgreSQL result. Evidence JSON is strict: duplicate keys,
non-finite values, unexpected fields, symlinks, unsafe artifact paths, malformed
JUnit XML, entity declarations, count mismatches, or digest mismatches fail
closed in the evidence validator.

## Authorized Closeout

Gate 0B authorizes only these remaining changes:

- mark `V05-IR-001` implemented and record its six passing identities;
- publish canonical qualification evidence and hashes;
- update release, version, provenance, history, roadmap, and test records;
- set product version metadata to `0.5.0`;
- generate and verify deterministic packaging and required supply-chain
  evidence;
- commit the release closeout; and
- create and verify one annotated `v0.5.0` tag.

Closeout edits must not introduce product behavior. If qualification or later
release inspection changes the candidate product tree, the candidate binding
no longer matches and a new gate decision is required.

## Preserved Compatibility

The accepted procedure IR remains `spell-restricted-ast/0.3`. Valid persisted
IR bytes are validated in memory and are not rewritten. Gate 0B adds no
compatibility-ledger row, construct ID, artifact ID, migration, public API,
database schema, frontend behavior, dependency, or driver contract.

The implementation remains the defense-in-depth boundary authorized by Gate
0A: parser output postvalidation, persisted supervisor preflight before worker
generation or process creation, worker preflight before `worker.started` or an
effect, bounded deterministic rejection evidence, and compatibility proof for
accepted IR 0.3 behavior.

## Explicit Exclusions

Gate 0B does not authorize:

- a second product work package or any broader candidate v0.5 language item;
- new syntax, functions, modifiers, types, outcomes, states, or IR version;
- source-to-IR reparsing, a persistence redesign, or stored-IR migration;
- unrestricted Python or source execution;
- REST, WebSocket, protobuf/gRPC, database-schema, frontend, dependency, or
  driver-contract changes;
- telemetry, telecommand, GCS, spacecraft, mission-network, or externally
  effective routing;
- a lightweight or secondary `v0.5` tag; or
- deployment approval, operational authorization, compliance determination,
  or cryptographic-signature claim.

## Gate Tooling

The machine-readable scope is
[`v0.5-gate-0b.json`](../requirements/compatibility/scopes/v0.5-gate-0b.json).
The gate validator and its focused mutation tests are:

- [`validate_v05_gate_0b.py`](../quality/tools/validate_v05_gate_0b.py)
- [`test_validate_v05_gate_0b.py`](../quality/tools/test_validate_v05_gate_0b.py)

```powershell
C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v05_gate_0b.py
C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe -m unittest discover -s NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools -p "test_validate_v05_gate_0b.py" -v
```

The only success marker is:

```text
gate=PASS work_packages=1 identities=6 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED
```

Any mismatch denies release closeout. A passing Gate 0B permits the release
record, package, commit, and annotated tag to be completed; only those later
artifacts can record final v0.5.0 release acceptance.
