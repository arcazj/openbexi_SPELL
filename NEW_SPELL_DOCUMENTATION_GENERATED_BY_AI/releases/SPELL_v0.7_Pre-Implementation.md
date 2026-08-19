# SPELL v0.7 Pre-Implementation Gate 0A

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.7.0 |
| Gate | `V07-GATE-0A` |
| Gate status | `PASS`; `V07-OBS-001` through `V07-OBS-009` are authorized |
| Proposal date | 2026-08-16 |
| Owner approval date | 2026-08-16 |
| Owner request | `resume and finish up asap v0.6 asap and move forward to finis up v0.7 asap. you have all aprrovals.` |
| Accepted product baseline | Annotated tag `v0.6.0`; release commit `05ec783a6e54a76e0548bdd536c18538f6bff51b` |
| Baseline tag object | `b6dc64dc8fb6cfe9845f454904a078ec6f3c0919` (`tag`, not a lightweight tag) |
| Proposed work packages | `V07-OBS-001` through `V07-OBS-009` |
| Authorized work packages | `V07-OBS-001` through `V07-OBS-009` |
| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |
| Product implementation at this gate | Authorized but not implemented or accepted by this gate |
| Operational authorization or compliance determination | None |
| Project owner | JC Arcaz |

V07-GATE-0A OWNER-APPROVAL: APPROVED

This record is the Gate 0A entry decision for the full v0.7 program. The owner
explicitly authorizes the nine bounded work packages below. This gate records
authorization only: it does not claim an implemented construct or artifact,
does not accept v0.7.0, and does not authorize deployment or operational use.

## Objective And Boundary

The proposed v0.7 increment would add a read-only observation and condition
engine against the bundled deterministic simulator. The authorization is
confined to local synthetic non-CUI data and preserves the accepted v0.6.0
execution, authority, persistence, audit, and effect-certainty boundaries.

No package authorizes a live GCS, spacecraft, telemetry, telecommand, mission
network, production, classified, or external-effect route. Driver time must
carry explicit source, provenance, and uncertainty; a host fallback can never
claim to be GCS time. Observation APIs remain read-only and bounded, condition
plans remain declarative and non-evaluating, and gaps or stale/invalid samples
fail closed rather than being silently treated as current valid telemetry.

The seven design contracts bound below authorize implementation boundaries;
their presence is not evidence that their constructs or product artifacts have
been implemented. Any implementation claim requires later candidate evidence
and Gate 0B closeout.

## Authorized Work Packages

| ID | Proposed bounded result | Required proof identities |
| --- | --- | --- |
| `V07-OBS-001` | Typed deterministic simulator driver time with source, provenance, uncertainty, skew, and explicit host fallback | `UNIT`, `CONTRACT`, `CLOCK`, `RECOVERY`, `SECURITY` |
| `V07-OBS-002` | Typed `GetTM` current/next samples with atomic raw/engineering projection, metadata, time, source, validity, quality, freshness, and sequence | `UNIT`, `INTEGRATION`, `ATOMIC`, `QUALITY`, `SECURITY` |
| `V07-OBS-003` | Bounded declarative `Verify` with nested `AND`/`OR`, documented comparisons, tolerance, retries, timeout/delay, composite results, and TM-to-TM conditions | `UNIT`, `MATRIX`, `CLOCK`, `RECOVERY`, `SECURITY` |
| `V07-OBS-004` | Deterministic relative, absolute, and telemetry `WaitFor` with monotonic deadlines, quality/freshness policy, cancellation, disconnect behavior, and one durable outcome | `UNIT`, `INTEGRATION`, `CLOCK`, `RACE`, `RECOVERY` |
| `V07-OBS-005` | Telemetry-conditioned durable scheduling with stable identity, quality/freshness gates, cancellation, restart recovery, and exactly one start outcome | `UNIT`, `INTEGRATION`, `CLOCK`, `RACE`, `RECOVERY` |
| `V07-OBS-006` | Typed bounded simulator `GetResource`, `MemoryLookup`, and `TMTCLookup` catalog/query reads without generic filters or mutation | `UNIT`, `INTEGRATION`, `BOUNDARY`, `RECOVERY`, `SECURITY` |
| `V07-OBS-007` | Read-only `GetLimits` and `IsAlarmed` with sample identity, quality, freshness, and sequence | `UNIT`, `MATRIX`, `QUALITY`, `RECOVERY`, `SECURITY` |
| `V07-OBS-008` | Authorization-scoped snapshot/cursor streams with contiguous sequence, gap/resynchronization, backpressure, cancellation, disconnect, and restart rules | `UNIT`, `INTEGRATION`, `BACKPRESSURE`, `RECONNECT`, `SECURITY` |
| `V07-OBS-009` | Cross-feature semantic, browser, accessibility, load, fault/recovery, and security acceptance for the read-only observation surface | `SEMANTIC-GOLDEN`, `BROWSER`, `ACCESSIBILITY`, `FAULT-RECOVERY`, `LOAD-SECURITY` |

Every row has status `IMPLEMENTATION_AUTHORIZED`. The machine-readable scope
lists the exact 45 planned test identities in package order. A wildcard, range,
renamed identity, additional identity, or reordered identity fails the gate.

## Cross-Package Invariants

- Sample identity, source, acquisition/receive time, sequence, quality,
  validity, freshness, and time uncertainty are explicit and durable where
  applicable; no fallback silently upgrades provenance or quality.
- Multi-item condition evaluation uses the contract's atomic snapshot policy.
  A gap, stale sample, invalid sample, timeout, disconnect, or unavailable
  capability cannot be silently treated as a satisfied condition.
- `Verify`, `WaitFor`, and scheduled starts use bounded declarative condition
  plans. They cannot evaluate arbitrary source, Python, expressions, functions,
  shell input, or generic string filters.
- Wait and schedule identity, cancellation, retry, recovery, and terminal
  settlement are durable and produce exactly one authoritative outcome.
- Resource, lookup, limit, alarm, snapshot, and cursor surfaces are read-only,
  authorization-scoped, typed, bounded, and auditable.
- Cursor discontinuity is explicit. Backpressure, reconnect, cancellation, and
  restart cannot invent continuity or replay a sample as newly acquired.

## Explicit Exclusions

Gate 0A does not authorize or claim:

- scope beyond `V07-OBS-001` through `V07-OBS-009`;
- non-local execution or non-synthetic, CUI, classified, production, or
  operational data;
- a live GCS, spacecraft, mission-network, telemetry, telecommand, commanding,
  or external-effect route;
- a host clock represented as driver/GCS time, hidden time uncertainty, or
  implicit sample freshness/validity;
- telemetry, resource, lookup, limit, or alarm mutation;
- arbitrary code, source, expression, function, shell, or generic string-filter
  evaluation;
- unbounded queries, subscriptions, buffers, cursors, retries, or condition
  graphs;
- continuity across an unacknowledged cursor gap or a satisfied result inferred
  from stale, invalid, missing, uncertain, or disconnected data;
- an unreviewed IR, language, API, database-schema, dependency, migration, or
  compatibility change;
- implementation outside the exact authorized work-package and contract
  boundaries; or
- implementation completion, release acceptance, deployment approval,
  operational authorization, compliance determination, or cryptographic-
  signature verification.

## Accepted Baseline Evidence

The machine-readable scope is
[`v0.7-gate-0a.json`](../requirements/compatibility/scopes/v0.7-gate-0a.json).
It binds the accepted v0.6.0 release independently of mutable refs and working
documents:

| Baseline item | Bound value |
| --- | --- |
| Tag ref | `refs/tags/v0.6.0` |
| Tag object type and ID | `tag`; `b6dc64dc8fb6cfe9845f454904a078ec6f3c0919` |
| Raw tag-object SHA-256 | `b08b3e66b0018a6f559b696cdd478b639f5ecbabc750b9049c85a8f8a17dd8a4` |
| Peeled release commit | `05ec783a6e54a76e0548bdd536c18538f6bff51b` |
| Qualified source commit | `8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213` |
| Candidate implementation commit | `0ea26105e72d7830de4a265989ed7d9074ffbe09` |
| Tagged release record SHA-256 | `9eb9121470f7cdf097f55917bdcead7748b0257209ff8adfa957d7ca1bb4a7da` |
| Tagged Gate 0B scope SHA-256 | `0deef3794c7dd34ef9995f95d33f2688aebfa198b96579e655273603555205bc` |
| Tagged release qualification SHA-256 | `cbff6f30fca8708260a0a94bf60f3834455dee9cfa2021b5ae4dd2ec83b4c98f` |
| Accepted archive SHA-256 | `b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c` |
| Accepted sidecar SHA-256 | `7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520` |

The validator requires the exact annotated tag object and raw bytes, all tag
markers, exact peel and ancestry, exact tagged paths/blob IDs/blob bytes, and
the byte-exact archive/sidecar pair both in the accepted commit and in the
workspace. It validates the sidecar grammar and recomputes the archive digest.
It reads accepted bytes from Git objects rather than trusting mutable files.
The tag is not a cryptographic signature and this gate makes no signature
claim.

## Authorization Contract Bindings

Exactly seven authorization files are admitted: one manifest and six matrices
under `contracts/v07`. Their exact SHA-256 values are recorded in the scope and
compiled independently into the validator. Missing, additional, symlinked,
oversized, non-strict JSON, or byte-mutated files fail Gate 0A closed.

| Authorization contract | SHA-256 |
| --- | --- |
| `contracts/v07/manifest.json` | `df1c8060cf6ec8259d2949ac6ec14f7aebca7ceba041bb274fdbec6c354d1a7d` |
| `contracts/v07/time_and_sample_identity.json` | `08a36552d311c6cb6297a493197480a5fbe2df0153ac4e4c63ddf9c0d66d58cd` |
| `contracts/v07/condition_engine.json` | `5373bbe93f0b19656cd266dc0341f03df11e02e4e7a1038e8b64ff30a253ef1b` |
| `contracts/v07/waitfor_and_scheduling.json` | `53cfb3d168765495ee46b2383dfd14dca79154ac59eed3fd857953cf14119f79` |
| `contracts/v07/resource_and_lookup_reads.json` | `07c93d6960f312eb8c31832f455ae874ac6b54b05cbc85df038f5acd8be16eb8` |
| `contracts/v07/limits_and_alarm_state.json` | `e42c7da301fb340f0e8cada67806a620194802f77658bc8029df2857a0cf4977` |
| `contracts/v07/cursor_streams.json` | `e18f62e3cb949ddeab7c0533712d0f6666f6b9eef59b78e6255bd3c963a41c8d` |

## Approval Record

The standalone owner marker, exact owner request, dated decision, machine
`PASS` status, authorization value, nine explicit authorized IDs, 45 planned
test identities, baseline object bindings, and seven authorization contract
hashes must remain mutually consistent. Tool success does not create approval.

Gate tooling:

- [`validate_v07_gate_0a.py`](../quality/tools/validate_v07_gate_0a.py)
- [`test_validate_v07_gate_0a.py`](../quality/tools/test_validate_v07_gate_0a.py)

```powershell
.venv\Scripts\python.exe NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v07_gate_0a.py
.venv\Scripts\python.exe -m unittest discover -s NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools -p "test_validate_v07_gate_0a.py" -v
```

The only successful marker for this accepted Gate 0A record is:

```text
gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0
```

## Gate Finding

`V07-GATE-0A PASS` authorizes implementation of exactly `V07-OBS-001` through
`V07-OBS-009`. It claims zero implemented constructs and zero implemented
artifacts. It does not accept SPELL v0.7.0 or permit deployment or operational
use.
