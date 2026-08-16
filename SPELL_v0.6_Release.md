# SPELL v0.6.0 Release Record

<!-- V06_RELEASE_CONDITIONAL_RECORD_BEGIN -->
## Record Status

| Field | Value |
| --- | --- |
| Version | SPELL v0.6.0 |
| Release name | Durable Operator Workspace and Procedure Composition |
| Record state | `CONDITIONAL_PENDING`; this document is not an acceptance claim |
| Scope | `V06-OP-001` through `V06-OP-009` only |
| Accepted baseline | SPELL v0.5.0, annotated tag `v0.5.0` |
| Gate 0A | `PASS` at commit `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1` |
| Gate 0B | `PENDING_CANDIDATE` |
| Candidate source commit | Pending |
| Final qualified source commit | Pending |
| Release commit | Pending |
| Release tag | Pending annotated tag `v0.6.0` |
| Accepted exceptions | None proposed; final evidence must contain no accepted failure or waiver |
| Operational authorization | None |
| Compliance determination | None |
| Cryptographic signature | Not claimed |
| Project owner | JC Arcaz |

Owner request: `you have the explicit owner approval for the exact V06-OP-001..009 gate, please finish up v0.6 asap`

Release decision: `PENDING_FINAL_EVIDENCE_RELEASE_COMMIT_AND_ANNOTATED_TAG`
<!-- V06_RELEASE_CONDITIONAL_RECORD_END -->

## Conditional Decision

This record is prepared for the bounded v0.6.0 closeout, but it remains
conditional. It becomes an accepted release record only when all of these
conditions are satisfied against one fixed release commit:

1. `V06-GATE-0B` passes against canonical candidate evidence for all nine work
   packages and all 45 exact test identities.
2. Final version-scoped qualification passes with zero mapped skips, failures,
   accepted failures, or waivers.
3. v0.6 SBOM and supply-chain evidence pass and the accepted v0.5 artifacts
   remain byte-identical.
4. The deterministic source package is built repeatedly with identical bytes
   and its archive/sidecar pair is committed.
5. One annotated `v0.6.0` tag targets the exact release commit and carries the
   required owner, decision, Gate 0B, exception, authorization, evidence, and
   package markers.
6. Strict post-tag validation passes with a clean worktree.

Until then, this file records an intended release contract, not a completed
release, tag, deployment approval, or operational authorization.

## Bounded Product Result

The v0.6 candidate implements the local synthetic simulator's durable operator
workspace and procedure-composition scope authorized at Gate 0A:

| Work package | Bounded release result | Required release evidence |
| --- | --- | --- |
| `V06-OP-001` | Context attachment, immutable catalog/history, stable instances, Master workspace | Unit, integration, recovery, UI, security |
| `V06-OP-002` | C/M/B control modes, exclusive durable lease, fencing, handover, loss and reacquisition | Unit, integration, race, recovery, security |
| `V06-OP-003` | Durable state/safe-point command matrix; hard kill rejected | Unit, exhaustive matrix, race, recovery, security |
| `V06-OP-004` | Typed durable prompts, defaults, timers, settlement, controller-loss behavior | Unit, integration, race, recovery, UI |
| `V06-OP-005` | Durable relative/absolute local schedules and one start outcome | Unit, integration, clock, race, recovery |
| `V06-OP-006` | Source/text/as-run/log/outline/search views, breakpoints, typed inspection, safe edits and bounded console | Unit, integration, UI, recovery, security |
| `V06-OP-007` | Named, versioned, allowlisted safe-point user actions | Unit, integration, race, recovery, security |
| `V06-OP-008` | Immutable `StartProc` resolution and bounded durable parent-child composition | Unit, integration, graph, recovery, security |
| `V06-OP-009` | Integrated desktop/mobile, accessibility, fault/recovery and security acceptance | Desktop, mobile, accessibility, fault/recovery, security |

The authoritative behavior is the exact seven-file contract inventory under
`contracts/v06/`, as accepted in Gate 0A. Release evidence must prove that
inventory without rewriting it during closeout.

## Reviewed Technical Delta

### Internal IR 0.6 With Preserved IR 0.3

The candidate adds internal IR `0.6` for the four bounded opt-in areas: typed
prompts, static allowlisted actions, `StartProc`, and operator safe-point/
call-frame metadata. This is an internal execution contract, not a claim of
broad legacy SPELL compatibility.

Accepted `backend/ir_v03.py` bytes must remain identical to v0.5.0. Procedures
without v0.6 constructs continue to select IR `0.3`; persisted v0.3 material
must validate, serialize, recover, and replay without rewrite. No compatibility
ledger row, legacy construct ID, or legacy artifact ID is added by v0.6.

### Local Operator API And UI

The existing `/api/v1` service gains strictly bounded operator routes for
contexts, catalogs, executions, leases, monitors, handovers, commands, prompts,
schedules, views/search, inspection/edits, console operations, actions,
relationships, `StartProc`, breakpoints, and redacted reporting. Mutations use
strict bodies and server-derived actor/session/role/fencing authority.

The React UI exposes the same bounded workflows in desktop and mobile layouts.
This is not a remote-service, multi-tenant, production, or broad public API
compatibility commitment.

### Migration 0004

`0004_operator_workspace` adds 20 new durable operator-ledger tables. Existing
execution, event, command, and prompt tables are referenced for foreign keys
but are not created or rewritten by the migration. Fresh install, historical
upgrade, rollback on failure, idempotence, and SQLite/PostgreSQL behavior must
all pass before release acceptance.

### Dependency And Driver Boundary

No new runtime dependency is part of the bounded delta. Product, backend, and
frontend metadata advance to `0.6.0`; the bundled local simulator driver and
gateway implementation contract remain `0.4.0`. No live driver, GCS,
spacecraft, telemetry, telecommand, or external-effect route is introduced.

## Qualification Contract

Candidate evidence is canonical only at
`artifacts/v0.6/work-package/qualification.json`. It must be generated from a
fixed Git source, strict-parsed, digest-bound, and independently validated by
`scripts/validate_candidate_evidence_v06.py` under locked CPython 3.13.14.

The evidence contract requires:

- ten exact suites covering SQLite, isolated PostgreSQL, Docker-host controls,
  replay soak, driver host, tooling, frontend unit/build, mocked browsers, and
  live-backend browsers;
- a bijection between collected nodes and result captures;
- exact concrete proofs for all 45 planned identities;
- distinct PostgreSQL application and migration databases on an internal
  network, with no mapped skip;
- desktop and Pixel mobile browser artifacts, accessibility proof, reconnect
  and replay, competing-control, prompt, schedule, edit, action, composition,
  and fault/recovery workflows;
- bounded performance/concurrency/soak evidence and complete resource teardown;
- secret scanning with zero findings and zero waivers; and
- immutable accepted v0.5 artifacts.

Inherited v0.4/v0.5 evidence may support regression context, but it cannot
replace direct v0.6 proof.

## Final Evidence Placeholders

<!-- V06_RELEASE_EVIDENCE_BINDINGS_BEGIN -->
The following values must be inserted only after their canonical producers and
independent validators pass:

| Evidence | Required canonical location | Current value |
| --- | --- | --- |
| Candidate qualification | `artifacts/v0.6/work-package/qualification.json` | Pending |
| Gate 0B machine scope | `.../scopes/v0.6-gate-0b.json` | Pending activation |
| Final qualification | `artifacts/v0.6/final/qualification.json` | Pending |
| Release qualification manifest | `artifacts/v0.6/release-qualification.json` | Pending |
| Backend SBOM | `artifacts/v0.6/sbom/backend.cdx.json` | Pending |
| Frontend SBOM | `artifacts/v0.6/sbom/frontend.cdx.json` | Pending |
| Driver SBOM | `artifacts/v0.6/sbom/driver.cdx.json` | Pending |
| Proxy SBOM | `artifacts/v0.6/sbom/proxy.cdx.json` | Pending |
| Supply-chain result | `artifacts/v0.6/supply-chain.json` | Pending |
| Deterministic archive | `artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz` | Pending |
| Archive sidecar | `artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256` | Pending |
| Release commit | Git commit | Pending |
| Annotated tag object | `refs/tags/v0.6.0` | Pending |
<!-- V06_RELEASE_EVIDENCE_BINDINGS_END -->

No placeholder may remain when this record changes to accepted. Every digest,
commit, tree, tag object, and result count must be taken from canonical bytes
and independently rechecked.

## Release Package Boundary

The release package may contain only tracked, release-eligible source and the
canonical v0.6 evidence selected by the version-scoped package manifest. It
must exclude reference archives, COTS binaries, credentials, runtime journals,
qualification scratch, historical v0.4/v0.5 canonical artifacts, caches,
screenshots not explicitly admitted as v0.6 evidence, and all secret-like
material.

Repeated package builds from the exact release commit must be byte-identical.
Archive traversal, links, devices, duplicate members, noncanonical metadata,
unexpected evidence placement, or archive/sidecar mismatch fails release
closeout.

## Residual Boundaries

Even after acceptance, v0.6.0 remains limited to a local deterministic
simulator using synthetic non-CUI data. It does not authorize or establish:

- production, classified, operational, or representative mission use;
- live GCS or spacecraft connectivity, commanding, telemetry, or telecommand;
- arbitrary Python/source/expression/function/shell execution;
- unsafe shared-data edits, arbitrary asynchronous actions, or hard kill;
- clean external-state inference after failure, timeout, skip, stop, abort,
  crash, or effect uncertainty;
- unbounded procedure graphs or mutable library resolution;
- broad legacy language/API/database/driver compatibility;
- high availability, operational service levels, deployment approval,
  compliance determination, or a cryptographic signature.

## Tag Activation Contract

The requested shorthand `v0.6` resolves to one annotated semantic-version tag,
`v0.6.0`; no alias or lightweight tag is permitted. The tag payload must name
the owner, `Decision: ACCEPTED`, `Gate 0B: PASS`, `Accepted exceptions: None`,
the operational/compliance/signature nonclaims, the exact release and qualified
source commits, source/evidence/product-package fingerprints, work-package
evidence digest, and final archive digest.

The tag activates this conditional decision only when its object type, raw
payload, peeled commit, package sidecar, evidence hashes, release manifest,
clean worktree, and ancestry all pass strict validation. A tag name alone is
not release evidence.

## Current Finding

<!-- V06_RELEASE_CURRENT_FINDING_BEGIN -->
SPELL v0.6.0 is not yet accepted by this record. Gate 0B activation, final
qualification, supply-chain evidence, deterministic packaging, the release
commit, annotated tag, and strict post-tag verification remain pending.
<!-- V06_RELEASE_CURRENT_FINDING_END -->
