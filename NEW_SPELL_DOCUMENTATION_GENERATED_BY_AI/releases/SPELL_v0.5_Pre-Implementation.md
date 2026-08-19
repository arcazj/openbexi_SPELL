# SPELL v0.5 Pre-Implementation Gate 0A

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.5.0 |
| Gate | `V05-GATE-0A` |
| Gate status | `PASS`; only `V05-IR-001` implementation is authorized |
| Gate date | 2026-08-12 |
| Accepted product baseline | Annotated tag `v0.4.0`; release commit `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Baseline tag object | `86390c90e8d5f96f872be43274cbc9d789a34c2d` (`tag`, not a lightweight tag) |
| Authorized work package | `V05-IR-001` - existing IR 0.3 fail-closed validation hardening |
| Product implementation | Authorized but not implemented or accepted by this gate |
| Runtime/API/schema/frontend/dependency/driver change at gate | None |
| Operational authorization or compliance determination | None |
| Project owner | JC Arcaz |

This record is an incremental entry gate, not approval of the full candidate
v0.5 language roadmap. It authorizes one defense-in-depth change to the
existing `spell-restricted-ast/0.3` boundary. Any other v0.5 implementation
requires a separately recorded gate decision.

## Objective And Finding

The accepted v0.4 baseline compiles the v0.3 safe source subset directly to
data-only procedure steps. Those steps can later be loaded from persistence
and sent to the procedure worker. The compiler constrains its own output, but
the baseline has no independent validator and canonicalizer that treats an IR
payload as untrusted at every execution boundary.

`V05-IR-001` closes only that validation gap. Valid accepted IR 0.3 behavior
and persisted bytes remain compatible. Malformed, unsupported, non-canonical,
or semantically inconsistent IR must fail closed before it can start a worker
or produce a procedure effect.

## Authorized Scope

The only authorized product changes are:

1. `STRICT_IR_0_3_VALIDATOR_AND_CANONICALIZER`: add one independent, bounded
   structural and semantic validator/canonicalizer for the existing IR 0.3
   vocabulary.
2. `PARSER_OUTPUT_POSTVALIDATION`: pass every newly compiled parser result
   through that boundary before returning an accepted `Procedure`.
3. `SUPERVISOR_PERSISTED_IR_PREFLIGHT_BEFORE_GENERATION_OR_PROCESS`: validate
   the stored IR version, steps, start position, and checkpoint variables
   before incrementing worker generation or creating a process.
4. `WORKER_IR_VERSION_AND_PAYLOAD_PREFLIGHT_BEFORE_WORKER_STARTED`: repeat the
   version, IR, start-position, and checkpoint validation inside the isolated
   worker before `worker.started`, a running-state acknowledgement, a prompt,
   a checkpoint, or any procedure effect.
5. `PERSISTED_IR_BYTE_PRESERVATION_WITHOUT_MIGRATION`: do not rewrite accepted
   persisted IR 0.3 rows, change their version, or add a data/schema migration.
   Canonical validation is an in-memory acceptance boundary, not an in-place
   persistence rewrite.
6. `ADVERSARIAL_AND_GOLDEN_FAIL_CLOSED_TESTS`: add focused unit, parser,
   supervisor, worker, compatibility, and adversarial proof for this boundary.

No additional work package is implicitly authorized by a supporting refactor
or test fixture.

## Validation Contract

The validator must accept only the exact existing IR 0.3 step and expression
shapes, scalar types, limits, and semantic relationships. At minimum it must
fail closed on:

- an unsupported or malformed IR version and missing, unknown, or extra
  fields;
- Boolean values substituted for integers, non-finite numbers, oversized
  values or collections, excessive nesting, and an excessive serialized
  payload;
- duplicate, non-contiguous, negative, or position-mismatched step indexes;
- unknown step or expression kinds, malformed expression trees, unsupported
  operators, invalid operand/result/guard types, and excessive expression
  depth;
- invalid or undeclared variable names, reads before a value is available,
  declaration/type conflicts, and checkpoint names or values that do not
  match the validated program state;
- malformed prompt choices, duplicate choices, or a default outside the
  accepted choices; and
- persisted-row tampering at initial start or recovery, including invalid
  current-step and prompt-resume relationships.

Validation errors must be bounded, deterministic, safe to audit, and must not
echo an unbounded or secret-bearing payload. Validation itself must not execute
source or IR, create a process, mutate worker generation, emit
`worker.started`, or produce a procedure effect.

## Failure Boundary

The supervisor is the primary pre-spawn enforcement point. Invalid persisted
IR or checkpoint state is rejected and durably reported before worker
generation changes and before process creation. The worker preflight is an
independent final defense against payload substitution or a missed caller; it
runs before `worker.started`, state acknowledgement, step dispatch, prompt
creation, checkpoint output, or effect.

A validation failure cannot be converted to success, retried with altered
bytes, or silently normalized into a different procedure. Existing execution
failure and audit contracts remain authoritative; this gate does not add a new
public error schema or state.

## Requirements And Planned Evidence

| Requirement | Required proof |
| --- | --- |
| Strict IR 0.3 acceptance | Exact allowlists, types, bounds, indexes, expression semantics, variable flow, prompt invariants, start position, and checkpoint state are validated independently of parser construction. |
| Parser boundary | Every compiled result is postvalidated; valid golden IR stays unchanged and invalid internal output is not returned. |
| Supervisor boundary | Stored IR and checkpoint tampering fail before generation increment or process creation and produce bounded durable failure/audit evidence. |
| Worker boundary | The worker checks explicit IR version and payload before `worker.started` or any state/effect output. |
| Compatibility | Accepted valid v0.3/v0.4 IR behavior and persisted bytes remain unchanged; no schema migration, API change, or new language behavior is introduced. |
| Adversarial coverage | Mutation and boundary cases prove missing/extra/type/size/depth/index/version/semantic/checkpoint failures are closed and deterministic. |

The planned acceptance identities are exactly:

| Test ID | Scope | Gate 0A result |
| --- | --- | --- |
| `V05-IR-001-UNIT` | Direct validator/canonicalizer valid and invalid corpus | Planned |
| `V05-IR-001-PARSER` | Parser postvalidation and unchanged golden compiler output | Planned |
| `V05-IR-001-SUPERVISOR` | Persisted IR/start/checkpoint preflight before generation or process creation | Planned |
| `V05-IR-001-WORKER` | In-worker version/payload preflight before `worker.started` or effect | Planned |
| `V05-IR-001-COMPAT` | Accepted v0.3/v0.4 behavior and persisted-byte compatibility | Planned |
| `V05-IR-001-ADVERSARIAL` | Cross-boundary mutation, tampering, malformed-audit, and fail-closed cases | Planned |

Gate 0A plans these product tests; it does not mark them executed. Their later
passing results are required before `V05-IR-001` can be claimed implemented.

## Explicit Exclusions

Gate 0A does not authorize:

- new procedure syntax, functions, modifiers, types, outcomes, execution
  states, or a new IR version;
- source-to-IR reparsing, source/IR integrity expansion, a persistence format
  redesign, or migration of accepted stored IR;
- changes to REST, WebSocket, protobuf/gRPC, database schemas, migrations,
  frontend behavior, dependencies, packaging, or driver contracts;
- implementation of `TIME`, `NOW`, `Display`, `Notify`, `Step`,
  `DisplayStep`, `Pause`, `Abort`, `Finish`, `Goto`, `DataContainer`, `Var`,
  `ARGS`, `IVARS`, `PROC`, or any other broader candidate v0.5 property;
- telemetry, telecommand, GCS, spacecraft, mission-network, legacy-adapter, or
  externally effective capability; or
- a v0.5 release decision, deployment approval, compliance determination,
  cryptographic-signature claim, or operational authorization.

## Baseline And Gate Evidence

The machine-readable scope is
[`v0.5-gate-0a.json`](../requirements/compatibility/scopes/v0.5-gate-0a.json).
It binds this accepted baseline:

| Baseline item | Bound value |
| --- | --- |
| Tag ref | `refs/tags/v0.4.0` |
| Tag object type and ID | `tag`; `86390c90e8d5f96f872be43274cbc9d789a34c2d` |
| Raw tag-object SHA-256 | `ae7030aa54ad9c69761ae764c4edd2535b47ae842a2f4f5b4c20aad859fca663` |
| Peeled release commit | `4546d313a2d8f50504b2bc602d56b3b459ca7597` |
| Tagged `SPELL_v0.4_Release.md` SHA-256 | `6c3288a3a83d679e82713f09613a640117817fc9cbd05fdf4853a5db64202aa8` |
| Tagged `COMPATIBILITY_LEDGER.json` SHA-256 | `f1d4e20383c81a1109e93b39e2aac04f04b2366e91eae613170488a6acf8458f` |
| Tagged `scopes/v0.4.json` SHA-256 | `2de37c751c084fad96d1bf1c3842deab57bb697920d0cc0bc15b206a46aee1f5` |

Validation must read the three bound files from the tagged commit rather than
accept matching working-tree paths.

The raw digest binds the complete tag message. The validator additionally
requires exact `Owner: JC Arcaz`, `Decision: ACCEPTED`,
`Accepted exceptions: None`, `Compliance determination: None`, and
`Operational authorization: None` lines, plus the release-commit and Final
qualification markers. The annotated tag is not a cryptographic signature and
Gate 0A makes no signature claim.

Gate tooling:

- [`validate_v05_gate_0a.py`](../quality/tools/validate_v05_gate_0a.py)
- [`test_validate_v05_gate_0a.py`](../quality/tools/test_validate_v05_gate_0a.py)

```powershell
.venv\Scripts\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v05_gate_0a.py
.venv\Scripts\python.exe -m unittest discover -s NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools -p "test_validate_v05_gate_0a.py" -v
```

The success marker is:

```text
gate=PASS work_packages=1 claimed_constructs=0 claimed_artifacts=0
```

Any baseline mismatch, missing tag marker, additional work package, claimed
language construct/artifact, unauthorized change category, missing test ID, or
scope-record inconsistency fails Gate 0A closed.

## Gate Decision

`V05-GATE-0A PASS` authorizes implementation of `V05-IR-001` and nothing
else. The authorized work must remain on the accepted v0.4.0 baseline and must
produce all six planned test results before implementation is claimed.

This gate does not claim that `V05-IR-001` is implemented, accept SPELL
v0.5.0, or authorize the broader Core Language and Deterministic Runtime
candidate. No deployment, operational use, or compliance claim follows from
this decision.
