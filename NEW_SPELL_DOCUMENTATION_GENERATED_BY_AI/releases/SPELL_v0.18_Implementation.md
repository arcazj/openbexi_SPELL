# SPELL v0.18 Native Telecommand Workflows

Accepted `v0.18.0` was published on 2026-10-02 after independent clean-tag validation. It succeeds accepted v0.17.0. The entry gate and earlier release evidence remain unchanged.

## Scope

- Native Prompt results and bounded expressions select branches containing
  existing simulator BuildTC/Send calls, followed by Display.
- Durable prompt answers, command confirmation, command intent and recovery
  retain their distinct authority and outcomes.
- The reference runner retains all earlier cases and adaptations and adds
  direct source checks for supported command behavior and native integration.
- Four additional [testing procedures](../../procedures/README.md) provide
  branch, default, command-mode and core-language walkthroughs.

IR 0.18 permits literal catalog command names or immutable BuildTC items;
arguments stay literal and modifiers retain closed constant/temporal forms.
Older IR 0.11 string-variable selectors remain unchanged in their earlier
profile. Native Prompt does not
replace required command confirmation. Abort cannot produce a later Send;
possible or unknown command effects cannot trigger automatic resend.
Earlier IR contracts remain unchanged. IR 0.18 does not add the v0.8 data,
argument, file or environment profiles or direct observation instructions to
native telecommand procedures. Collections, general function arguments/returns,
live connections and operational authorization remain outside scope.

The compact manual workspace and automatic local connection remain in place.
Full SPELL 2.4.4 compatibility is not claimed. Adapted examples, correct
rejections and bounded source tests remain distinct forms of evidence.

## Verification

Annotated `v0.18.0` passed independent clean-tag validation and was published. The seven final suites recorded 5,146 passed executions; all 24 environment-selected skips were resolved by complementary runs. The candidate gate passed 395 checks. Four package builds across two independent exports matched, with no accepted exceptions.

| Final gate | Passed executions | Environment-selected skips |
| --- | --- | --- |
| SQLite | 2,434 | 21 |
| PostgreSQL | 2,370 | 3 |
| Frontend | 150 | 0 |
| Desktop/mobile browser | 24 | 0 |
| Compose | 3 | 0 |
| Documentation | 18 | 0 |
| Release tooling | 147 | 0 |

The 763-entry inventory records 195 ADAPTED, 79 PARTIAL and 489 GAP entries. All 128 cases passed: 95 direct-source checks and 33 expected rejections. The 195 adaptations retain 257 variants. Neither adaptations nor correct rejection establish complete language support.

The language report proves actual source/worker and validated simulator service behavior. Supervisor, API and browser gates separately prove durable authority and recovery; reference-runner helper checks never dispatch an outer procedure command. Build, soak, image, SBOM and supply-chain gates also passed. Raw scanner findings and applicability dispositions remain bound in the evidence.

## Accepted Release Binding

| Binding | Accepted value |
| --- | --- |
| Annotated tag object | `0bdd0ade51dbcc7822927fb95b5f962b6194b40f` |
| Release commit | `8e9a252db7860cee8b4d5f291ed1d803d8bc3b48` |
| Qualified source / tree | `ca6ebee137e99ad87968d7a0efb30813d2c4e650` / `32011640ff0a1ab9b95fb5b588ee31b3bd4262a2` |
| Source fingerprint | `8cbf208198a78be6a2e53d67853bf79aaef8970b610a086c480e91bdc1d44e4a` |
| Accepted predecessor | `v0.17.0`, release commit `e525b9c842e3c26a35058d85fc40bd3ee4b16c85` |
| Candidate source / checks | `f2385955c75525e57f68ccb631fe7fcbc11dce5d` / 395 passed |
| Package SHA-256 | `3e2821b8c0db18d07a33c9b55625e5bbe0d47125d03fbbbf6d768756ba71d62c` |
| Qualification SHA-256 | `07bc944b3bd703b9a82cc871be37851bff0d9d3c79906457a9af8a257b0a09af` |
| Manifest SHA-256 | `118f25a8bb146a97d72ab3858f2fd620dcd8812350cc023d399a8adffb52bb4f` |
| Reproducibility SHA-256 | `d946c8c711b302bc9cad2d4f495030620b0bd1e6318d8ce2d3a2aa70bb404940` |
| Language report SHA-256 | `df22a4b359b47846bb37c6954a2461b256e45e81a3eeffba9f92d2c7cfd19e06` |
| Tag / publication time | 2026-10-02 23:03:17 EDT / 2026-10-02 23:05:16 EDT |

The published [GitHub release](https://github.com/arcazj/openbexi_SPELL/releases/tag/v0.18.0) contains four verified assets. The [qualification](../../artifacts/v0.18/qualification.json), [manifest](../../artifacts/v0.18/release-manifest.json) and [reproducibility record](../../artifacts/v0.18/reproducibility.json) retain the evidence. Later documentation closeout does not change the tagged source, package or acceptance.

Full SPELL 2.4.4 compatibility, real legacy qualification and operational authorization remain outside this local simulator profile.
