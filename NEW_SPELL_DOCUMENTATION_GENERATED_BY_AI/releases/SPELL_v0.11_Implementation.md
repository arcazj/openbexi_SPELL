# SPELL v0.11 Simulator Telecommand Semantics

## Record Status

| Field | Value |
| --- | --- |
| Accepted predecessor | SPELL v0.10.0 at annotated tag `v0.10.0` |
| Candidate source | `e15d3314f9b97eb43d5d5057c8f1ba614844e0e7` |
| Qualified source | `276b222a43dfbde260b3919c16f4080114251a8e`; fingerprint `2a29599e035f79bca9802562665a9a648b1fc15b3ffd949fe43076c1a746d56b` |
| Product version | `0.11.0` |
| Entry authority | `V11-GATE-0A PASS` in `SPELL_v0.11_Pre-Implementation.md` |
| Release policy | `contracts/v11/release_policy.json` |
| Release endpoint | Commit `a41be7f5c8472213fa027d7bb94a2389477b1b86`; annotated tag `v0.11.0`; tag object `eb9e95f357bda3e505035e6f0f54ef5fb164a6c5` |
| Package | 691 files; SHA-256 `61576af94aec59cfb06384d1050e1a9c2e33b0d0a7ad0b6de86b1a1da9683170` |
| Release disposition | ACCEPTED: qualification, deterministic package, evidence, and strict annotated-tag validation passed |
| Accepted exceptions | None permitted |
| Operational authorization | None |
| Updated | 2026-08-19 |

This record describes an accepted simulator-only engineering release. It does not claim a
live Ground Control System integration, network command dispatch, spacecraft
commanding, deployment approval, compliance determination, or cryptographic
signature.

## Implemented Surface

The accepted release adds:

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

Qualification evidence binds the exact source commit, Git tree, source
fingerprint, image identity, gate totals, mandatory reference hashes, contract
hashes, and browser hashes. The deterministic source archive was built twice
byte-for-byte, excludes prior-release artifacts and legacy inputs, and passed
independent rebuild validation before tagging.

## Acceptance Record

All release conditions are satisfied:

1. `artifacts/v0.11/release-qualification.json` is committed at
   `8d2c00c902b41a032265bd219439cc8e491036cb` and validates.
2. `artifacts/v0.11/openbexi-spell-v0.11.0.tar.gz`, its SHA-256 sidecar, and
   release manifest are committed at
   `a41be7f5c8472213fa027d7bb94a2389477b1b86` and reproduce exactly.
3. Annotated tag `v0.11.0` targets the release commit and carries the exact
   validator-generated message; tag object is
   `eb9e95f357bda3e505035e6f0f54ef5fb164a6c5`.
4. GitHub branch, tag object, and peeled-tag identities match the local
   validated objects.

An accepted tag remains a local simulator engineering release only. It grants
no deployment or operational authority.
