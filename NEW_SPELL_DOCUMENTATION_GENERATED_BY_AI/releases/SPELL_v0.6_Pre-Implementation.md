# SPELL v0.6 Pre-Implementation Gate 0A

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.6.0 |
| Gate | `V06-GATE-0A` |
| Gate status | `PASS`; `V06-OP-001` through `V06-OP-009` are authorized |
| Proposal date | 2026-08-15 |
| Owner approval date | 2026-08-15 |
| Accepted product baseline | Annotated tag `v0.5.0`; release commit `e7b6bb9428833437e0160040541eb840deee7cca` |
| Baseline tag object | `a1b277d74d2fb19062ca3e4388e9104d45c50ec4` (`tag`, not a lightweight tag) |
| Proposed work packages | `V06-OP-001` through `V06-OP-009` |
| Authorized work packages | `V06-OP-001` through `V06-OP-009` |
| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |
| Product implementation at this gate | Authorized but not implemented or accepted by this gate |
| Operational authorization or compliance determination | None |
| Project owner | JC Arcaz |

V06-GATE-0A OWNER-APPROVAL: APPROVED

This record is the Gate 0A entry decision for the full v0.6 program. The owner
explicitly authorizes the nine bounded work packages listed below. This gate
does not claim that any package is implemented or that v0.6.0 is accepted.

## Objective And Boundary

The proposed v0.6 increment would add the durable operator workspace and
procedure-composition workflows assigned to v0.6 by the accepted roadmap. The
entire authorization remains confined to the local deterministic simulator using
synthetic non-CUI data. It provides no live driver, GCS, spacecraft, telemetry,
telecommand, external-effect, production, classified, or operational route.

Any eventual implementation must preserve the accepted v0.5.0 fail-closed IR,
execution, audit, persistence, and effect-certainty boundaries. New API,
schema, dependency, language, or compatibility surface needed by an approved
package requires explicit design and evidence inside that package; this
gate claims none.

## Authorized Work Packages

| ID | Proposed bounded result | Required proof families |
| --- | --- | --- |
| `V06-OP-001` | Context attachment, immutable procedure catalog/properties/history, stable multi-instance identity, and Master workspace | Unit, integration, restart/recovery, desktop/mobile UI, authorization |
| `V06-OP-002` | `C/M/B` modes with exclusive control, strictly read-only monitor mode, background behavior, durable leases, fencing, disconnect pause, and explicit reacquisition | Unit, competing-controller race, fencing, restart/recovery, security |
| `V06-OP-003` | Approved state/safe-point matrix for run, step, step-over, pause, skip, goto, reload, background, stop, abort, and recover; hard kill remains rejected | Unit, exhaustive matrix, race, crash/recovery, effect-certainty security |
| `V06-OP-004` | Documented typed durable `Prompt` family with validation, defaults, warning timers, commit/reset/abort, context/execution settings, exactly one durable outcome, controller-loss pause, and lease reacquisition | Unit, integration, race, restart/recovery, desktop/mobile UI |
| `V06-OP-005` | Durable local-clock relative and absolute schedules with stable identity, validation, cancellation, exactly one start outcome, and restart recovery | Unit, integration, clock boundary, race, recovery |
| `V06-OP-006` | Source/text/as-run/support-log views; outline, search, nested navigation; breakpoints, run-to-line, typed variable/`ARGS`/`IVARS`/shared-data inspection; safe-state audited edits; bounded non-evaluating console | Unit, integration, desktop/mobile UI, recovery, security/non-execution |
| `V06-OP-007` | Durable named, versioned, allowlisted user actions executed only at approved safe points | Unit, integration, race, recovery, security/non-execution |
| `V06-OP-008` | Immutable procedure-library resolution and durable `StartProc` parent-child identity with bounded depth, cycle rejection, crash rules, and restart recovery | Unit, integration, graph limits, recovery, security |
| `V06-OP-009` | Cross-feature desktop/mobile, accessibility, competing-control, prompt, scheduling, inspection, action, composition, fault/recovery, and security acceptance | Real desktop, real mobile, accessibility, fault/recovery, security |

Every row has status `IMPLEMENTATION_AUTHORIZED`. The explicit authorization
set is exactly `V06-OP-001` through `V06-OP-009`; it does not authorize work
outside those package boundaries or accept the release.

## Cross-Package Invariants

- One stable identity and one authoritative durable outcome apply to commands,
  prompts, schedules, user actions, and parent-child transitions.
- Control authority is server-evaluated and fenced. Monitor mode is strictly
  read-only; controller loss pauses control-sensitive work until explicit
  reacquisition.
- Commands and edits occur only in their approved state and safe-point matrix.
  `SKIP`, stop, abort, crash, or any rejected hard termination never imply a
  clean external state.
- Prompt validation, defaults, warning timers, commit/reset/abort, and recovery
  cannot create multiple outcomes or silently transfer control authority.
- Inspection is typed and bounded. The console cannot evaluate expressions or
  functions, execute procedure-scope source, invoke a shell, or bypass audit.
- Named user actions are immutable allowlist entries, never arbitrary or
  asynchronous Python.
- Procedure-library resolution is digest-bound and immutable. Parent-child
  depth and cycle checks fail closed before a child starts.
- All faults, disconnects, races, restarts, rejected requests, and safe edits
  produce bounded durable audit evidence without secret-bearing payloads.

## Explicit Exclusions

Gate 0A does not authorize or claim:

- any scope beyond `V06-OP-001` through `V06-OP-009`;
- non-local execution or non-synthetic, CUI, classified, production, or
  operational data;
- a live driver, GCS, spacecraft, telemetry, telecommand, mission-network, or
  external-effect route;
- arbitrary Python, source, expression, or function evaluation, procedure-scope
  shell execution, an unbounded inspection console, or unsafe variable/shared
  data edits;
- arbitrary asynchronous or non-allowlisted user actions;
- hard kill or an inference of clean external state after skip, stop, abort,
  crash, timeout, uncertainty, or failure;
- mutable procedure-library resolution or an unbounded parent-child graph;
- an unreviewed IR, language, API, database-schema, dependency, migration, or
  compatibility change;
- implementation outside the nine exact authorized package contracts; or
- release acceptance, deployment approval, operational authorization,
  compliance determination, or cryptographic-signature verification.

## Accepted Baseline Evidence

The machine-readable scope is
[`v0.6-gate-0a.json`](../requirements/compatibility/scopes/v0.6-gate-0a.json).
It binds the accepted v0.5.0 release independently of mutable working files:

| Baseline item | Bound value |
| --- | --- |
| Tag ref | `refs/tags/v0.5.0` |
| Tag object type and ID | `tag`; `a1b277d74d2fb19062ca3e4388e9104d45c50ec4` |
| Raw tag-object SHA-256 | `6c642ec6f7461db9fdce2347ca6ab493686430d5bd36218a4c0306b1b70ba48f` |
| Peeled release commit | `e7b6bb9428833437e0160040541eb840deee7cca` |
| Qualified source commit | `2f31e6a011b8aad63b29bd55780c37c1b68712f1` |
| Tagged `SPELL_v0.5_Release.md` SHA-256 | `055da745f54da76da097741e84dc15725d0584f54a20b499e658fbcfd9f85a4e` |
| Tagged `v0.5-gate-0b.json` SHA-256 | `f98d50498ef8caf7304ad2e027f0eb8f03c02b486d8ec871f6ca95cc28987248` |
| Tagged `release-qualification.json` SHA-256 | `fe66fa5c232b063f8920f6087a49205754e6fa75fdefb1a105383b6f528e48ba` |

The validator requires an annotated tag, exact raw tag bytes, the accepted
release commit, exact owner/decision/Gate 0B/no-exception/no-operational/no-
compliance tag markers, ancestry from v0.5.0 to `HEAD`, and hashes read from
the tagged commit rather than the working tree. The tag is not a cryptographic
signature and this gate makes no signature claim.

## Approval Record

The exact standalone owner marker, dated decision, machine `PASS` status,
authorization value, nine explicit authorized IDs, authorized package states,
and independently compiled validator contract must remain mutually consistent.
Removing or changing any element fails Gate 0A closed. A range or wildcard in
the machine authorization list is never accepted.

Gate tooling:

- [`validate_v06_gate_0a.py`](../quality/tools/validate_v06_gate_0a.py)
- [`test_validate_v06_gate_0a.py`](../quality/tools/test_validate_v06_gate_0a.py)

```powershell
.venv\Scripts\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v06_gate_0a.py
.venv\Scripts\python.exe -m unittest discover -s NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools -p "test_validate_v06_gate_0a.py" -v
```

The only successful marker for this accepted Gate 0A record is:

```text
gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0
```

## Gate Finding

`V06-GATE-0A PASS` authorizes implementation of exactly `V06-OP-001` through
`V06-OP-009`. It does not claim an implementation, accept SPELL v0.6.0, or
permit deployment or operational use.
