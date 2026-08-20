# SPELL v0.11 Simulator Telecommand Semantics

## Record Status

| Field | Value |
| --- | --- |
| Accepted predecessor | SPELL v0.10.0 at annotated tag `v0.10.0` |
| Candidate source | `e15d3314f9b97eb43d5d5057c8f1ba614844e0e7` |
| Product version | `0.11.0` |
| Entry authority | `V11-GATE-0A PASS` in `SPELL_v0.11_Pre-Implementation.md` |
| Release policy | `contracts/v11/release_policy.json` |
| Release disposition | Conditional: accepted only when committed qualification/package evidence and annotated tag `v0.11.0` pass `scripts.validate_release_evidence_v11` |
| Accepted exceptions | None permitted |
| Operational authorization | None |
| Updated | 2026-08-19 |

This record describes a simulator-only release candidate. It does not claim a
live Ground Control System integration, network command dispatch, spacecraft
commanding, deployment approval, compliance determination, or cryptographic
signature.

## Implemented Surface

The candidate adds:

- `contracts/v11/telecommand_catalog.json`, a closed seven-command,
  two-sequence deterministic simulator catalog;
- `contracts/v11/telecommand_execution.json`, the explicit stage, certainty,
  modifier, confirmation, recovery, and no-resend policy;
- `backend/telecommand_v11.py`, the bounded command construction, planning,
  provider, result, checkpoint, cancellation, and recovery core;
- `backend/ir_v11.py`, typed validation for construction and send steps;
- `backend/telecommand_runtime_v11.py`, worker-facing preflight, request,
  result, prompt, failure-policy, and reconciliation behavior; and
- parser, worker, supervisor, serialization, operator-service, API, image, and
  development-bundle provenance integration.

Eight version-scoped backend test modules cover parser, IR, command corpus,
core runtime, worker, supervisor, API, and operator integration. The v0.10
reference runner and all earlier product behavior remain present.

## Command And Modifier Boundary

`BuildTC` creates an immutable catalog-backed item with typed bounded
arguments. `Send` accepts a direct command name or built item and supports
closed deterministic expansion for command, sequence, group, and block
selectors. Duplicate children receive unique stable element identities.

Supported behavior includes time and release intent, load-only settlement,
confirmation, critical confirmation, timeout, additional information,
send/verification delay, verification conditions, adjustable-limit intent,
tolerance, failure policy, prompt policy, and per-command overrides.
Unknown, duplicate, conflicting, excessive, non-finite, secret-like, or
unbounded values fail closed.

## Stage And Certainty Model

Each element records transport, loading, release, acknowledgement, onboard
execution, verification, terminal disposition, effect certainty, timing, and
provider-native detail separately. Transport or loading success cannot be
promoted to onboard execution. `LoadOnly` never implies release or execution.

Closed-loop verification uses deterministic injected telemetry. Verification
pass, failure, and indeterminate outcomes remain distinct from execution
evidence. A failed verification cannot erase a proven onboard-execution stage,
and an indeterminate result cannot be represented as success.

## Confirmation, Failure, And Recovery

Critical or explicitly confirmed plans require a digest-bound durable prompt.
The registered canonical plan, not caller-supplied mutable stage data, controls
execution and cancellation.

Cancellation terminalizes remaining elements without inventing success.
Nonterminal recovery enters reconciliation and validates operation identity,
request identity, plan digest, confirmation evidence, stage coherence, cursor
coherence, and bounded JSON. A possible or unknown effect forbids automatic
resend. A new attempt requires a new authorized operation after authoritative
`NO_EFFECT` evidence.

`OnFailure` and `PromptUser` govern only whether the procedure may continue
after an already-settled failure. They cannot resend or rewrite completed
element outcomes. Non-answer and denial fail closed.

## Operator And Security Boundary

The operator service fences v0.11 control commands and forbids backward
`GOTO` for telecommand procedures. User actions and inspection edits cannot
mutate built items or scalar variables on which a command plan depends.

The product image contains both v10 and v11 contracts and exactly one bundled
reference procedure. It excludes legacy manuals, the legacy source archive,
generated documentation, release tools, caches, and bytecode. The runtime
exposes no arbitrary endpoint, driver credential, live dispatch route, or
spacecraft interface.

## Qualification Contract

| Gate | Required boundary |
| --- | --- |
| Inherited v0.10 | 443 total, 442 passed, one selected PostgreSQL skip |
| Focused v0.11 | 197 passed, zero failures/errors/skips |
| Full backend | 1,563 total, 19 environment-selected skips, zero failures/errors |
| PostgreSQL selection | 16 passed |
| Docker Compose selection | 3 passed |
| Frontend unit | 112 passed |
| Auditor integration | 3 passed |
| Release tooling | At least 8 passed |
| Documentation | Clean export tests and Markdown rendering pass |
| Real browser | Chromium and mobile, 2/2, zero retries |

The v0.11 browser evidence is stored under `artifacts/v0.11/browser-e2e` and
is hash-pinned in the policy. It exercises the real v0.11 backend while
retaining the single v0.10 reference procedure and confirms Example 195 PASS
on desktop and mobile.

Qualification evidence will bind the exact source commit, Git tree, source
fingerprint, image identity, gate totals, mandatory reference hashes, contract
hashes, and browser hashes. The deterministic source archive will be built
twice byte-for-byte, exclude prior-release artifacts and legacy inputs, and be
validated before tagging.

## Acceptance Rule

The source tree is a release candidate until all of these are true:

1. `artifacts/v0.11/release-qualification.json` is committed and validates.
2. `artifacts/v0.11/openbexi-spell-v0.11.0.tar.gz`, its SHA-256 sidecar, and
   release manifest are committed and reproduce exactly.
3. Annotated tag `v0.11.0` targets the release commit and carries the exact
   validator-generated message.
4. Remote branch and tag object identities match the local validated objects.

An accepted tag remains a local simulator engineering release only. It grants
no deployment or operational authority.
