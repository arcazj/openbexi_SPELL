# SPELL v0.19.0 Implementation

Accepted `v0.19.0` was published on 2026-10-06 after independent clean-tag validation. It succeeds accepted v0.18.0. Earlier release evidence and the entry gate remain unchanged.

## Delivered Scope

The operator, development and DSS workspaces share soft metallic colors with stronger text, control and chart contrast.

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
- Docker GENERIC DSS, binary CCSDS CMD and Kafka TLM share one satellite state
  and database. Command loading, release, execution and verification preserve
  procedure/operation/epoch correlation and durable uncertainty. The separate
  compact DSS page controls and observes the same satellite.
- The reference runner uses isolated inner workers with parent-brokered actual
  DSS services when DSS is configured. Per-case intents and full captures remain
  durable; an unresolved case cannot silently replay command effects.

Observation procedures require an admitted bundled driver context with current
samples. The [quick start](../../README.md#quick-start) initializes this through
the existing durable OpenContext boundary; missing context remains a rejection.

## Limits

This is a local satellite simulator with actual local binary transport and no
operational approval. Values are committed snapshots: prompts and waits do not refresh them,
and Send does not automatically revalidate live telemetry. Reread before a new
freshness-dependent decision. DSS commands also retain the physical source epoch
of consumed observations: a scenario reset blocks a command derived from an old
epoch before binary dispatch. Dynamic service/command operands, data/file/env
mixtures, general Python, full native observation return objects and modifiers
remain outside this increment. Full SPELL Language Reference 2.4.4 support is false.

Exact bounds and source decisions are in the [entry record](SPELL_v0.19_Pre-Implementation.md)
and [coverage contract](../../contracts/v19/language_coverage.json).

## Qualification

Annotated `v0.19.0` passed independent clean-tag validation and was published. The seven final suites recorded 7,130 passed executions; all 45 environment-selected skips were resolved by complementary runs. The candidate gate passed 1325 checks. Four package builds across two independent exports matched, with no accepted exceptions.

| Final gate | Passed executions | Environment-selected skips |
| --- | --- | --- |
| SQLite | 3,195 | 41 |
| PostgreSQL | 3,111 | 4 |
| Frontend | 186 | 0 |
| Desktop/mobile browser | 32 | 0 |
| Compose | 4 | 0 |
| Documentation | 18 | 0 |
| Release tooling | 584 | 0 |

The 763-entry inventory records 195 ADAPTED, 79 PARTIAL and 489 GAP entries. All 148 cases passed: 112 direct-source checks and 36 expected rejections. The 195 adaptations retain 257 variants. Neither adaptations nor correct rejection establish complete language support.

The mandatory DSS gate passed 954 inventory identities, including 10 procedures and 344 menu choices, plus 30 fault scenarios. Configured DSS runners use the parent-owned broker: service cases dispatch binary CCSDS commands and consume Kafka telemetry, while local-only and rejection cases prove no command dispatch. Historical helper reports remain separate evidence. All 6 image SBOMs/audits, build, soak and installed-image gates passed; raw captures and scanner dispositions remain bound in the evidence.

The continuation independently revalidated 947 retained identities and 8 scenarios from `3e7d991123034bf6c83408f100bbdb00d7cc78ae`, preserving their original source and image bindings and the original failed report. The remaining 22 scenarios executed on the qualified release source.

## Accepted Release Binding

| Binding | Accepted value |
| --- | --- |
| Annotated tag object | `de2ec8f3db9c079838591a06d2d5b743fabb9b11` |
| Release commit | `57cc80d969ebc222d47f0e8d19f962682c47d10c` |
| Qualified source / tree | `8658e3c62b62d9c9431f3d0478d336faaf83a9e3` / `6959bbf77a838023c0c2d05ea5b825b6ed8b056e` |
| Source fingerprint | `0e499314ee2c525a9c75cde1718d1ba2f6c0729848964cf53fa8f06c6b788249` |
| Accepted predecessor | `v0.18.0`, release commit `8e9a252db7860cee8b4d5f291ed1d803d8bc3b48` |
| Candidate source / checks | `39d7ad0e48c9d4b08579b8fe0c9f046d85069ca2` / 1325 passed |
| Package SHA-256 | `fe37d37924e23d3b65b6f76666221445b23a2b27b434e5ea6944634d97c1f4e3` |
| Qualification SHA-256 | `925a2dcbccfea98dcf3edbac540b2deb2f0eae241ebec660cdd0bea52a89d77a` |
| Manifest SHA-256 | `06ff204c1452a22b0005343b982e19473a9438d895bf05cdeaa9c321ae96cab9` |
| Reproducibility SHA-256 | `5205b0a018346aa8e73d30e01da712b91bdabc7cdd6ca8b79b03a7c42372cb9c` |
| Language report SHA-256 | `ea7bd5623dd3be24be7248870663c6d64e904e6b8015279105c9fec0d78acbd8` |
| DSS report / producer bindings SHA-256 | `bcae4ce0a065844231e0f9d431ba89c5143be7c67c6406ac179acdebbb4c2b37` / `7e746408c56ec2c9bde63818ef12edbbedf4ea4e81bb609913563d6a0e599fac` |
| DSS raw captures / governed requirements | 1059 hash-bound captures / 14 requirements |
| Tag / publication time | 2026-10-06 15:42:21 EDT / 2026-10-06 15:51:59 EDT |

The published [GitHub release](https://github.com/arcazj/openbexi_SPELL/releases/tag/v0.19.0) contains four verified assets. The [qualification](../../artifacts/v0.19/qualification.json), [manifest](../../artifacts/v0.19/release-manifest.json) and [reproducibility record](../../artifacts/v0.19/reproducibility.json) retain the evidence. Documentation closeout does not change the tagged source, package or acceptance.

Full SPELL 2.4.4 compatibility, real legacy qualification and operational authorization remain outside this local simulator profile.
