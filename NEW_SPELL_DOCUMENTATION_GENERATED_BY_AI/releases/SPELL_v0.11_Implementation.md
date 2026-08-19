# SPELL v0.11 Simulator Telecommand Implementation

## Record Status

| Field | Value |
| --- | --- |
| Accepted product baseline | SPELL v0.9.0 at annotated tag `v0.9.0` |
| Entry authority | `V11-GATE-0A PASS` in `SPELL_v0.11_Pre-Implementation.md` |
| Working-tree status | Simulator-only implementation locally qualified with the recorded non-release exclusions below |
| Release status | No v0.11 candidate freeze, package, release commit, or tag |
| Operational authorization | None |
| Updated | 2026-08-19 |

This is a mutable working-tree implementation record. The bounded v0.11
implementation is locally qualified by the exact commands and results below. It is not an
accepted release, deployment approval, compliance determination, cryptographic
signature, live Ground Control System integration, or spacecraft-command
authorization.

## Entry Gate And Compatibility Boundary

v0.11 began only after the strengthened v0.10 traceability work represented all
195 numbered Language Reference examples as 257 independently asserted variant
subcases. Example 60 retains separate evidence for:

```spell
Send(command = 'CMDNAME')
Send(command = tc_item)
```

The v0.10 example outcomes and variant proofs are distinct evidence dimensions:
195 example results do not by themselves prove all 257 variants. The reference
also contains malformed fragments, pseudocode, output illustrations,
placeholders, negative examples, and intentionally invalid code. Those inputs
remain source-hash-bound semantic adaptations with independently authored
oracles. Neither v0.10 nor v0.11 claims verbatim execution of arbitrary PDF
snippets, unrestricted Python, or general SPELL 2.4.4 compatibility.

The v0.11 command corpus covers the 26 documented command statements in
Language Reference Examples 57 through 77 through closed parser, IR, runtime,
and simulator forms. The Language Reference supplies syntax and
procedure-visible intent; the Driver Development Manual supplies stage and
provider concepts. The safety decisions in the pre-implementation record take
precedence where legacy prose is ambiguous or unsafe.

## Implemented Surface

The working tree contains:

- pinned simulator-only command and execution contracts under `contracts/v11`;
- catalog-backed typed `BuildTC(name, args=...)` construction;
- closed `Send` selectors for a direct command name, immutable built item,
  sequence, group, and block;
- deterministic ordered expansion with stable unique element identities,
  including duplicate sequence or group children;
- global, built-item, and per-command modifier precedence with conflict and
  unsupported-field rejection;
- closed IR `0.11`, worker execution, supervisor-owned durable request and
  result records, public execution routing, and bounded checkpoints;
- deterministic scripted transport/provider behavior and injected logical
  clock and telemetry evaluation with no real waiting or live dispatch.

The primary implementation records are `backend/telecommand_v11.py`,
`backend/ir_v11.py`, `backend/telecommand_runtime_v11.py`, the v0.11 parser,
worker, supervisor, and API branches, and their version-scoped tests. The
catalog and execution policy are data contracts rather than configurable live
driver endpoints.

## Deterministic Execution Semantics

`Time` and `SendDelay` gate the transport stage on an injected logical UTC
clock. `ReleaseTime` gates release after loading. Intentional schedule,
release, and verification-delay holds advance logical time instantly and do not
consume the active per-element execution timeout; provider work and telemetry
evaluation do consume it. Shared transport retains a single dispatch while
applying each element's own timeout.

`LoadOnly` settles as `LOADED_ONLY` after loading and never implies release,
onboard execution, verification, or legacy boolean success. Release and load
intent remain independently visible.

Closed-loop verification supports deterministic delay, per-condition or global
tolerance, per-condition timeout, and adjustable-limit intent against injected
telemetry fixtures. Verification pass, failure, and indeterminate outcomes are
separate from onboard execution evidence. A failed or indeterminate
verification cannot erase a proven onboard-execution stage, and no transport or
loading result is promoted to execution success.

## Safety, Integrity, And Recovery

Critical commands and explicit confirmation requests produce a digest-bound
preflight challenge. Start uses the canonical registered plan; supplied plan or
confirmation fields cannot be edited while reusing a copied digest. Runtime
advance and cancellation use the canonical registered snapshot rather than
trusting caller-provided stage fields.

Each element records transport, loading, release, acknowledgement, onboard
execution, verification, terminal disposition, effect certainty, timing, and
provider-native detail separately. Secret-like material is rejected before it
can enter persisted additional information or provider detail.

Cancellation terminalizes remaining work without inventing success. A
nonterminal recovered checkpoint enters reconciliation, validates identity,
digest, confirmation evidence, stage coherence, cursor coherence, and bounded
JSON, and does not dispatch while reconciling. An uncertain possible effect is
never automatically resent. A new attempt is permitted only through a new,
separately authorized operation after authoritative `NO_EFFECT` evidence.

The simulator exposes no live driver credential, arbitrary endpoint, browser
telecommand mutation route, network dispatch, GCS connection, or spacecraft
command path.

## Final Closeout Evidence

All commands below ran against the final 2026-08-19 mutable working-tree state.
No focused result is presented as the repository-wide result.

| Gate | Exact command | Final result | Evidence or limitation |
| --- | --- | --- | --- |
| Strengthened v0.10 example and variant gate | Commands 1-3 below | 442 passed, one dedicated-PostgreSQL guard skipped; generator PASS; qualification 195/195 examples and 257/257 variants | Example matrix `ab7535...e4c`; variant matrix `35ccaf...94c8`; qualification content binding `55817d...6f2a` |
| v0.11 command corpus, parser, IR, core, runtime, worker, supervisor, and API | Command 4 | 197 passed in 29.31 seconds; zero failures or skips | All 26 command statements in Examples 57-77; independent Example 60 name/item execution; timing, verification, prompts, faults, recovery, tamper, certainty, and no-resend cases |
| Full backend and environment-selected regression | Commands 5-6 | 1,544 passed and 19 environment-selected skips in 463.36 seconds; all 16 PostgreSQL and all three Docker-Compose selections then passed | The PostgreSQL selection passed in 50.46 seconds; Compose isolation, networkless builders, restart, credential-epoch, and worker-credential boundaries passed 3/3 |
| Historical tooling inventory | Command 7 | 1,018 passed, 23 platform skips, 9 fail-closed legacy release/package checks in 165.87 seconds | The nine checks require the mutable root to still advertise or package itself as v0.5-v0.9. They are deliberately not relabeled as v0.11 passes; Markdown validation separately passed 11/11 |
| Frontend and real browser | Commands 8-10 | 112 Vitest tests passed; production build passed; Chromium and Pixel 7 passed 2/2 | npm emitted only its existing `min-release-age` future-warning; browser observed no off-loopback request |
| Product image and documentation audit | Commands 11-14 | Image/runtime/hygiene PASS; compileall PASS; diff check PASS; 78 Markdown files, 344 links, and 339 tables PASS | Image `sha256:c399b4...7a00` contains both v0.11 contracts. A cold-cache `--network=none` build cannot download hash-locked dependencies; the normal hash-locked build passed |

### Artifact Identities

| Artifact | SHA-256 |
| --- | --- |
| `contracts/v10/language_reference_example_matrix.json` | `ab7535a2db540664f1303fb8cd73f1599fe7aa81d469003cfe15fe7fa3ba7e4c` |
| `contracts/v10/language_reference_variant_matrix.json` | `35ccaf6f276a2a6571e96f43c8aeb33ebf33cca16de3d6b9740e0217d45f94c8` |
| `artifacts/v0.10/reference-examples.json` bytes | `14192c9d991b33b502b080539db62a0f0ebfd476d7ee1830c1eb53bfdbd72c74` |
| Qualification content binding | `55817de4eb2d6e42e65ff319985c5294b69b86557b245f3b13541404fe0a6f2a` |
| `contracts/v11/telecommand_catalog.json` | `f60b574d18d4c3aa23c8c986b6ea3242e4e83fd41bc611f4ff6a37a15eb6e64c` |
| `contracts/v11/telecommand_execution.json` | `d757eb602b03476ee512e8a89a714fae3024d3be3a4b590ebabca0dcd06021a3` |
| `openbexi-spell-backend:v11-local` image | `c399b4878791e548c524073a727ae82790909cbf3ca65ac58be228e729407a00` |

### Exact Commands

1. `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m --entrypoint python -e PYTHONDONTWRITEBYTECODE=1 -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-backend:local -m pytest backend/tests/test_ir_v10.py backend/tests/test_reference_examples_v10.py backend/tests/test_reference_runner_v10.py backend/tests/test_reference_runner_api_v10.py backend/tests/test_reference_qualification_v10.py backend/tests/test_v10_language_reference_example_matrix.py backend/tests/test_catalog_retirement_v10.py -q -p no:cacheprovider`
2. `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --entrypoint python -e PYTHONDONTWRITEBYTECODE=1 -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-backend:local -m scripts.generate_reference_runner_v10 --check`
3. The same bounded container invocation with `-m scripts.qualify_reference_examples_v10 --check`.
4. `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m --entrypoint python -e PYTHONDONTWRITEBYTECODE=1 -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-backend:local -m pytest backend/tests/test_telecommand_v11.py backend/tests/test_ir_v11.py backend/tests/test_v11_command_corpus.py backend/tests/test_telecommand_runtime_v11.py backend/tests/test_worker_v11.py backend/tests/test_supervisor_v11_runtime.py backend/tests/test_v11_api_runtime.py backend/tests/test_v11_operator_integration.py -q -p no:cacheprovider`
5. `docker run --rm --network none --entrypoint python -e PYTHONDONTWRITEBYTECODE=1 -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-backend:v10-regression-deps -m pytest backend/tests -q -p no:cacheprovider`
6. The 16 PostgreSQL tests skipped by command 5 were rerun by exact node ID with `SPELL_MIGRATION_TEST_DATABASE_URL=postgresql+psycopg://spell:...@pg:5432/spell_migration_test` against a fresh isolated PostgreSQL 18 container. The three Docker selections were rerun by exact node ID with `SPELL_RUN_COMPOSE_RUNTIME_TESTS=1` in a disposable Docker CLI/Compose qualification image with the host daemon socket.
7. `docker run --rm --network none --entrypoint python -e PYTHONDONTWRITEBYTECODE=1 -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/workspace -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-qualification:v11-local-tools -m pytest scripts/tests -q -p no:cacheprovider`
8. `npm test -- --run`
9. `npm run build`
10. `npx playwright test e2e/language-reference-v10-real.spec.ts --workers=1 --retries=0 --project=chromium --project=mobile` with a fresh v0.11 product-image backend and signed local operator token.
11. `docker build -t openbexi-spell-backend:v11-local -f backend/Dockerfile .`
12. A network-disabled product-image Python probe loaded both `contracts/v11` files and executed `Send(command='CMDNAME')` and `Send(command=item)`; a second probe required one bundled `*.spell.py` and zero bytecode/cache paths.
13. `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m --entrypoint python -e PYTHONPYCACHEPREFIX=/tmp/pycache -v "${PWD}:/workspace:ro" -w /workspace openbexi-spell-backend:v10-regression-deps -m compileall -q backend scripts spell` and `git diff --check`.
14. The v0.9 Markdown validator, extended only to include the three new untracked version records, validated all 78 Markdown files.

## Closeout Disposition

The completed gates confirm:

- all 195 example outcomes and all 257 variant subcases pass with distinct
  trace and assertion evidence;
- all 26 documented command statements compile and execute through the real
  v0.11 runtime, including both Example 60 forms;
- extreme numeric values passed directly to the public telecommand core fail
  with bounded typed diagnostics rather than leaking `OverflowError` or another
  raw exception;
- timing, release, load-only, timeout, delayed verification, tolerance, and
  adjustable-limit behavior affect deterministic stage progression and outcome;
- confirmation, cancellation, crash recovery, reconciliation, checkpoint
  tampering, snapshot tampering, uncertainty, and no-resend cases pass;
- no test or valid example was weakened or rewritten merely to make a gate pass;
- the current product regression, frontend, browser, build, and product-image
  checks pass; and
- every remaining limitation and environment-selected check is recorded next
  to the command that exposed it.

The accurate disposition is:
**simulator-only v0.11 implementation locally qualified in the mutable working
tree, with recorded non-release exclusions; not an accepted release**. The
repository-wide historical tooling command is not represented as universally
green because its nine v0.5-v0.9 current-root release/package validators
correctly reject a mutable v0.11 root.
