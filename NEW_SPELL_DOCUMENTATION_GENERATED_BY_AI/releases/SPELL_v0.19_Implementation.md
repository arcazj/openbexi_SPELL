# SPELL v0.19.0 Implementation

Status: implemented; full release qualification and publication pending. The
accepted predecessor is v0.18.0. This record does not yet claim release acceptance.

## Delivered Scope

- Closed IR `0.19` combines bounded target-based GetTM, Verify and WaitFor with
  native core expressions, branches, Display/Prompt and literal BuildTC/Send.
- GetTM assigns its exact typed scalar only for OK with VALID, GOOD, FRESH,
  COMPLETE evidence and the expected policy revision. Other outcomes stop the
  step. Verify always overwrites its target with the explicit outcome; compare
  it with `"TRUE"`. WaitFor advances only on SATISFIED.
- The supervisor binds requests, results, complete checkpoint variables and
  effects to durable records, source steps and the current worker generation.
  NEXT waits retain their anchor/deadline and reuse the first durable result.
  Recovery does not automatically repeat uncertain command effects.
- SKIP/GOTO are excluded for IR19, including source Goto. Run, Step, Step Over,
  run-to-line, Pause and Abort retain their bounded behavior.
- Authoring profile `spell-lrm244-conformance/0.19` supports checking, independent
  reproducible builders, separate review, immutable bundle promotion and actual
  execution. Legacy authoring profile 0.9 remains explicit and supported.
- The reference runner retains 195 adaptations and 257 variants and adds 20
  checks to the inherited 128: 148 cases, 112 direct and 36 expected rejections.
  Three observation procedures cover command approval, false decisions and
  timeout. The compact manual workspace and automatic local connection remain.

Observation procedures require an admitted bundled driver context with current
samples. The [quick start](../../README.md#quick-start) initializes this through
the existing durable OpenContext boundary; missing context remains a rejection.

## Limits

This is a local simulator profile without live command transport or operational
approval. Values are committed snapshots: prompts and waits do not refresh them,
and Send does not automatically revalidate live telemetry. Reread before a new
freshness-dependent decision. Dynamic service/command operands, data/file/env
mixtures, general Python, full native observation return objects and modifiers
remain outside this increment. Full SPELL Language Reference 2.4.4 support is false.

Exact bounds and source decisions are in the [entry record](SPELL_v0.19_Pre-Implementation.md)
and [coverage contract](../../contracts/v19/language_coverage.json).

## Qualification

All mandatory gates must pass on one frozen source before this status changes:
SQLite/PostgreSQL/Compose regression; frontend, build and 28 desktop/mobile
browser journeys; reference generation/conformance; documentation and tooling;
replay/adapter/pilot soaks; installed-image and supply-chain checks; four matching
package builds, independent clean-tag validation and public asset verification.
