# SPELL v0.6 Gate 0B Release Closeout

<!-- V06_GATE_0B_ACTIVATION_RECORD_BEGIN -->
## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.6.0 |
| Gate | `V06-GATE-0B` |
| Gate status | `PASS`; exact v0.6 release closeout authorized |
| Record date | 2026-08-15 |
| Accepted product baseline | Annotated tag `v0.5.0`; release commit `e7b6bb9428833437e0160040541eb840deee7cca` |
| Gate 0A authorization | Commit `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1`; `V06-OP-001` through `V06-OP-009` |
| Candidate source | Commit `0ea26105e72d7830de4a265989ed7d9074ffbe09`; tree `e1bc151e253882c27ebc159e11cf958cbd4531df`; sole parent `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1` |
| Canonical candidate evidence | `artifacts/v0.6/work-package/qualification.json`; SHA-256 `16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538` |
| Required result inventory | Nine work packages; 45 exact test identities; zero mapped skips, failures, accepted failures, or waivers |
| Release tag requested | One annotated semantic-version tag: `v0.6.0` |
| Project owner | JC Arcaz |

Owner request: `you have the explicit owner approval for the exact V06-OP-001..009 gate, please finish up v0.6 asap`

Gate 0B decision: `V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY`

Release closeout authorization: `AUTHORIZED`

Release acceptance by Gate 0B: No

Operational authorization: None
<!-- V06_GATE_0B_ACTIVATION_RECORD_END -->

## Pending Decision

This record defines the fail-closed Gate 0B closeout decision for the exact
nine work packages approved by Gate 0A. It is intentionally pending. The owner
has requested completion and reaffirmed the exact Gate 0A scope, but that
request does not substitute for canonical candidate qualification.

Gate 0B may change to `PASS` only after all of the following are bound and
independently verified:

1. One frozen candidate commit with Gate 0A as its sole parent and a complete,
   exact changed-path/blob inventory.
2. Canonical candidate evidence at
   `artifacts/v0.6/work-package/qualification.json` bound to that commit.
3. A passing `scripts/validate_candidate_evidence_v06.py` result from locked
   CPython 3.13.14.
4. All 45 Gate 0A test identities mapped to concrete passing nodes with zero
   mapped skips, failures, accepted failures, or waivers.
5. Explicit review of the internal IR 0.6, operator API, strict request schema,
   and migration 0004 deltas, including proof that accepted IR 0.3 bytes remain
   unchanged.

Until those conditions are met, deterministic packaging, final evidence,
supply-chain closeout, a release commit, and an annotated tag are not
authorized by this gate. The pending document and machine scope are scaffolding
for a later evidence-bound decision, not a statement that implementation or
qualification has passed.

## Immutable Authorization Inputs

### Accepted v0.5.0 Baseline

Gate 0B independently retains the accepted v0.5.0 release identity:

| Binding | Value |
| --- | --- |
| Tag ref | `refs/tags/v0.5.0` |
| Object type | `tag` |
| Tag object | `a1b277d74d2fb19062ca3e4388e9104d45c50ec4` |
| Raw tag-object SHA-256 | `6c642ec6f7461db9fdce2347ca6ab493686430d5bd36218a4c0306b1b70ba48f` |
| Peeled release commit | `e7b6bb9428833437e0160040541eb840deee7cca` |
| Qualified source commit | `2f31e6a011b8aad63b29bd55780c37c1b68712f1` |

The validator requires the accepted owner, decision, Gate 0B, exception,
operational-authorization, compliance, and signature nonclaim markers from the
annotated tag. It reads the three tagged evidence hashes recorded by the
machine scope from Git object storage, not mutable working files.

### Gate 0A Authorization

The sole accepted v0.6 implementation authorization is commit
`f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1`, whose parent is the v0.5.0
release commit and whose tree is
`8a75227ad372a819159be7ac276b6d90f0d95c82`. Gate 0B binds all four
controlling Gate 0A records and all seven accepted contract files by Git blob
and SHA-256.

The required Gate 0A markers remain:

```text
V06-GATE-0A OWNER-APPROVAL: APPROVED
gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0
```

The committed Gate 0A scope must still contain exactly nine explicitly named
authorized work packages and 45 explicitly named planned identities. A range,
wildcard, mutable current-file substitution, extra package, or contract change
fails Gate 0B closed.

## Candidate And Evidence Binding

The machine-readable Gate 0B scope currently carries explicit `null` candidate
commit, tree, source-commit, and evidence-digest bindings. Its candidate
changed-path inventory is empty. These are deliberate pending values; they are
not wildcards.

After source freeze, the closeout operator must replace them with:

- the candidate commit, its sole Gate 0A parent, and its exact tree;
- every changed path with status, Git blob ID, and byte SHA-256;
- the canonical qualification manifest SHA-256; and
- the identical source commit returned by the candidate validator.

The candidate validator must emit exactly one strict-JSON success line with
schema `spell.v06.candidate-qualification/1`, gate `PASS`, ten suites, 45 test
identities, a positive executed-test count, the frozen source commit, and the
canonical manifest digest. Success noise, stderr, malformed UTF-8, duplicate
JSON keys, non-finite values, a different interpreter, or a digest mismatch
fails the gate.

## Exact Work-Package Results

<!-- V06_GATE_0B_PACKAGE_DISPOSITIONS_BEGIN -->
All nine exact work packages are `IMPLEMENTED_AND_QUALIFIED`. Every listed identity has one or more concrete passing proof nodes; no mapped identity is skipped, failed, accepted as failed, or waived.
<!-- V06_GATE_0B_PACKAGE_DISPOSITIONS_END -->

| Work package | Exact required identities |
| --- | --- |
| `V06-OP-001` | `UNIT`, `INTEGRATION`, `RECOVERY`, `UI`, `SECURITY` |
| `V06-OP-002` | `UNIT`, `INTEGRATION`, `RACE`, `RECOVERY`, `SECURITY` |
| `V06-OP-003` | `UNIT`, `MATRIX`, `RACE`, `RECOVERY`, `SECURITY` |
| `V06-OP-004` | `UNIT`, `INTEGRATION`, `RACE`, `RECOVERY`, `UI` |
| `V06-OP-005` | `UNIT`, `INTEGRATION`, `CLOCK`, `RACE`, `RECOVERY` |
| `V06-OP-006` | `UNIT`, `INTEGRATION`, `UI`, `RECOVERY`, `SECURITY` |
| `V06-OP-007` | `UNIT`, `INTEGRATION`, `RACE`, `RECOVERY`, `SECURITY` |
| `V06-OP-008` | `UNIT`, `INTEGRATION`, `GRAPH`, `RECOVERY`, `SECURITY` |
| `V06-OP-009` | `DESKTOP`, `MOBILE`, `ACCESSIBILITY`, `FAULT-RECOVERY`, `SECURITY` |

The complete identity is the package ID plus the suffix shown above. The
machine scope contains all 45 full strings and is authoritative. Historical
platform skips may be explicitly classified only outside these mapped
identities; no mapped test identity may be skipped or waived.

Qualification must cover the full SQLite and isolated PostgreSQL backend
inventories, host Docker inspection, bounded replay soak, driver-host suite,
tooling suite, frontend unit/build suites, mocked desktop/mobile browser suite,
and live-backend browser suite. The two PostgreSQL database variables must
refer to distinct internal databases with no published host port.

## Reviewed Implementation Delta

### Internal IR

The bounded implementation introduces internal IR version `0.6` in
`backend/ir_v06.py` only for typed prompts, static allowlisted user actions,
`StartProc`, and operator safe-point/call-frame metadata. Existing source that
uses none of those constructs remains on IR `0.3`.

Accepted `backend/ir_v03.py` bytes are pinned to blob
`87f202e9e3ff192e348c2aea9f7009ea7fc95841`, SHA-256
`2726774ed5873e0c0c1eeaffa7b3713c708ac7f61a6fa93e544a8dbc8c79963c`.
The candidate must retain those exact bytes and prove the v0.3 parser/runtime
path still serializes and recovers without a persisted rewrite. Internal IR
0.6 is not a broad legacy-language compatibility claim and creates no new
compatibility-ledger construct or artifact ID.

### Operator API And Request Schema

The reviewed API change is additive within the existing local `/api/v1`
service. It covers contexts and catalog history; Master and execution
snapshots; control leases, monitors, and handovers; durable commands and typed
prompts; schedules; workspace views/search/inspection/edits; the bounded
non-evaluating console; user actions; relationships and `StartProc`;
breakpoints; and redacted reports.

Mutation bodies use the strict models in `backend/schemas.py`; authority,
session, fencing, expected revisions, and idempotency are server-evaluated in
`backend/operator_service.py`. This is an exact local operator-workspace delta,
not a general API compatibility, multi-tenant, remote-service, or operational
support claim.

### Database Schema And Migration

Migration `0004_operator_workspace` adds exactly 20 operator ledger tables for
contexts, catalog revisions, execution projections, leases, monitors,
handovers, requests, audit events, commands, prompts and attempts, edits,
breakpoints, actions and invocations, schedules and occurrences, `StartProc`,
and parent-child links. The migration declares existing execution/event/
command/prompt tables only to resolve foreign keys; it does not create or
rewrite them.

Fresh install, v0.2/v0.3 upgrade, idempotence, failed-migration rollback, and
SQLite/PostgreSQL equivalence are mandatory candidate evidence. This is not a
broad database compatibility or production migration claim.

### Dependency And Driver Boundary

No new runtime dependency is authorized by this closeout record. Product
metadata may be `0.6.0`, while the bundled simulator driver implementation and
gateway expectation remain `0.4.0`. No live driver, GCS, spacecraft,
telemetry, telecommand, or external-effect route is added or authorized.

## Conditional Closeout Actions

Only a passing, evidence-bound Gate 0B may authorize these actions:

1. Record all nine work packages as implemented and qualified.
2. Publish final version-scoped qualification evidence and its hashes.
3. Update release, provenance, history, timeline, roadmap, and test records.
4. Produce v0.6 SBOM and supply-chain evidence.
5. Produce and byte-verify the deterministic v0.6 source archive and sidecar.
6. Commit one release closeout containing all canonical evidence.
7. Create one annotated `v0.6.0` tag over that exact release commit.

Gate 0B never authorizes new product work. It is not the final release
acceptance record. Final qualification, deterministic packaging, release
commit identity, tag object type, tag payload, target commit, archive digest,
and clean-tree state must still be checked after Gate 0B passes.

## Nonclaims And Exclusions

This pending gate does not claim or authorize:

- scope beyond `V06-OP-001` through `V06-OP-009`;
- non-local, non-synthetic, CUI, classified, production, or operational data;
- a live driver, GCS, spacecraft, telemetry, telecommand, mission-network, or
  external-effect path;
- arbitrary Python, source, expression, function, or shell execution;
- unsafe shared-data editing, an unbounded console, arbitrary actions, hard
  kill, or inference of clean external state after uncertainty;
- mutable library resolution or an unbounded parent-child graph;
- broad legacy-language, API, database, driver, deployment, or operational
  compatibility;
- a lightweight tag, a second v0.6 tag, or a `v0.6` alias;
- release acceptance, deployment approval, operational authorization,
  compliance determination, or cryptographic-signature verification.

## Gate Tooling

Machine scope:
[`v0.6-gate-0b.json`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/v0.6-gate-0b.json)

Validator:
[`validate_v06_gate_0b.py`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0b.py)

Focused tests:
[`test_validate_v06_gate_0b.py`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/test_validate_v06_gate_0b.py)

```powershell
C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0b.py
C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe -m unittest discover -s NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools -p "test_validate_v06_gate_0b.py" -v
```

While bindings remain pending, the only expected repository marker is:

```text
gate=PENDING work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=DENIED
```

After every activation requirement is rebound and independently passes, the
only success marker will be:

```text
gate=PASS work_packages=9 identities=45 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED
```

## Deterministic Activation And Freeze Sequence

The validator contains a non-destructive activation preparer and a separate
transactional applier. They can run only after canonical candidate
qualification exists and passes. The preparer refuses to overwrite the
canonical scope, derives every Git binding from object storage, invokes the
candidate validator under the same locked interpreter, validates the proposed
PASS shape, then validates its candidate Git and evidence bindings again before
writing a proposal.

The release operator must execute this exact sequence:

1. Commit the candidate source as the sole child of Gate 0A commit
   `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1`. The commit includes the product,
   tests, release tooling, and this still-pending governance record.
2. Run candidate qualification from that immutable commit. Publish only the
   canonical ten-suite evidence tree at `artifacts/v0.6/work-package/`; all 45
   mapped identities must pass with zero mapped skips, failures, accepted
   failures, or waivers.
3. Create an owned noncanonical output directory, then prepare the bound scope:

   ```powershell
   $activation = "artifacts/v0.6/.qualification/gate-0b-activation"
   New-Item -ItemType Directory -Path $activation -ErrorAction Stop | Out-Null
   C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0b.py --prepare-activation "$activation/v0.6-gate-0b.bound.json"
   ```

4. Require the preparer to exit zero and emit one strict JSON line with
   `activation=READY`, the candidate commit, evidence SHA-256, proposal path,
   and proposal SHA-256. A pre-existing output, non-3.13.14 interpreter,
   non-Gate-0A parent, rename/delete diff, changed contract, IR 0.3 byte change,
   dependency/driver change, candidate-validator noise, or evidence mismatch
   fails preparation.
5. Review the generated proposal as the complete replacement for
   `v0.6-gate-0b.json`, then apply that exact canonical proposal:

   ```powershell
   C:\Users\arcaz\AppData\Local\OpenBEXI\release-toolchain\python-3.13.14-embed-amd64\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0b.py --apply-activation "$activation/v0.6-gate-0b.bound.json"
   ```

   The applier must rederive and byte-compare the proposal, hold the exclusive
   activation lock, and atomically replace the machine scope, this Gate 0B
   record, and the conditional release record. It validates all three after
   publication and rolls every target back on failure. It changes
   `SPELL_v0.6_Release.md` only to a conditional Final-closeout state; Gate 0B
   never changes that record directly to accepted.
6. Run the focused Gate 0B tests and the validator. The validator must emit the
   exact PASS marker above with exit zero and empty stderr. Commit the canonical
   candidate evidence, activated Gate 0B records, and their tooling as one Gate
   0B closeout commit.
7. Use that Gate 0B closeout commit as the next final-source freeze. Run Final
   qualification before producing SBOMs, supply-chain evidence, the release
   manifest, or the deterministic package.
8. Commit all canonical Final evidence and the archive/sidecar pair in one
   release commit. Create the annotated `v0.6.0` tag only after release
   validation passes against that exact commit; then rerun strict validation
   with the tag required and a clean worktree.

The order is therefore: Gate 0A commit, candidate source commit, canonical
candidate evidence, activated Gate 0B closeout commit, final source freeze,
Final/SBOM/supply-chain/package evidence, release commit, annotated tag, and
post-tag validation. No later step may repair or reinterpret a failed earlier
binding.

## Current Finding

<!-- V06_GATE_0B_CURRENT_FINDING_BEGIN -->
`V06-GATE-0B PASS` authorizes release closeout for exactly `V06-OP-001` through `V06-OP-009`. It does not itself accept the release, authorize deployment or operational use, or make a compliance or cryptographic-signature claim.
<!-- V06_GATE_0B_CURRENT_FINDING_END -->
