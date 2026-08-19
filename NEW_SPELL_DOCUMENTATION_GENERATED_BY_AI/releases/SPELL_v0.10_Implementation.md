# SPELL v0.10 Reference Example Runner

## Scope

v0.10 provides a deterministic semantic-adaptation runner for all 195 numbered
examples in `SPELL - Language Reference - 2.4.4` (February 2015,
`SES-SSO-SOE-SPELL-2015/06`). The external authority is pinned by SHA-256
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`.
The PDF is not packaged or copied into product source.

The repository exposes exactly one bundled procedure,
`procedures/language_reference_244.spell.py`. Its typed `LIST` prompt contains
all examples in numeric order. The selected index is stored in a declared
integer, converted to `1..195`, and passed to the closed
`ReferenceExample(...)` IR instruction.

## Compatibility Contract

`contracts/v10/language_reference_example_matrix.json` contains one explicit
record per example. Each record binds the existing compatibility artifact ID,
title, page, extracted-span hashes, semantic family, required simulator
capabilities, ambiguity resolution, adaptation identity, and exact oracle.

`contracts/v10/language_reference_variant_matrix.json` expands those 195
example identities into 257 stable variant subcases. Forty-six examples contain
more than one documented form. Every subcase has its own source anchor, adapter,
oracle, test ID, assertion ID, and trace operation. Example 60 therefore proves
`Send(command = 'CMDNAME')` and `Send(command = tc_item)` independently rather
than treating the two forms as one execution.

The reference includes fragments, pseudocode, output illustrations, known
syntax omissions, and intentionally wrong code. Consequently, this increment
claims deterministic semantic adaptation, not verbatim execution of PDF text.
No reference text is passed to `exec`, `eval`, imports, a shell, or a network.

## Runtime Boundary

IR `0.10` adds only:

1. A typed `LIST` prompt in `INDEX` mode may store its answered integer in a
   declared target.
2. `ReferenceExample(number, target=result)` invokes the bounded simulator
   registry and stores its short PASS summary in a declared string.

The production catalog exposes IR `0.10` only through the source-controlled
bundled runner. The parser and validation API retain bounded IR `0.10` support
for testing, while the v0.9 development-bundle manifest continues to accept
only IR `0.3`, `0.6`, `0.7`, and `0.8`. An edited or promoted project therefore
cannot add another production reference-adapter entry point.

Every execution emits a structured result with ordered trace operations,
variant-specific assertions, and a canonical evidence digest. Existing IR
versions retain their prior validators and behavior.

External-effect examples use in-memory simulator projections. Telecommand
`Send` explicitly records `live_dispatch=false`. Example 195 is stronger: it
uses the bundled observation catalog, filters real TM and TC entries, checks
their direction/type/catalog digest, and proves an out-of-range lookup returns
`NOT_FOUND`.

## Delivery Gate

Delivery requires all of the following with no waiver:

- Contract identities are exactly `1..195`, with no gaps or duplicates.
- The generated variant matrix contains exactly 257 stable subcases across all
  195 examples, with distinct successful assertion and trace evidence for every
  identified syntax form.
- The generated runner is current and the catalog contains that one procedure.
- Language-service analysis has zero diagnostics and the runner compiles to
  IR `0.10`.
- Every example passes direct deterministic-oracle execution.
- Every example passes through `worker_main` and produces a nonempty trace and
  assertion set.
- The menu path routes index `194` to Example 195 and records its catalog
  provenance assertion.
- Summary is exactly 195 PASS, 0 FAIL, 0 SKIP, 0 XFAIL, 0 unresolved.

Canonical per-example evidence is `artifacts/v0.10/reference-examples.json`;
variant coverage is bound by the generated variant matrix and its qualification
checks. Raw malformed, pseudocode, output-only, placeholder, and intentionally
invalid fragments remain hash-bound semantic adaptations, not verbatim source
execution.

## Verification

```powershell
docker run --rm --network none --entrypoint python `
  -v "${PWD}:/workspace:ro" -w /workspace `
  openbexi-spell-backend:local -m pytest `
  backend/tests/test_ir_v10.py `
  backend/tests/test_reference_examples_v10.py `
  backend/tests/test_reference_runner_v10.py `
  backend/tests/test_reference_runner_api_v10.py `
  backend/tests/test_reference_qualification_v10.py `
  backend/tests/test_v10_language_reference_example_matrix.py `
  backend/tests/test_catalog_retirement_v10.py -q

docker run --rm --network none --entrypoint python `
  -v "${PWD}:/workspace:ro" -w /workspace `
  openbexi-spell-backend:local `
  -m scripts.generate_reference_runner_v10 --check

docker run --rm --network none --entrypoint python `
  -v "${PWD}:/workspace:ro" -w /workspace `
  openbexi-spell-backend:local `
  -m scripts.qualify_reference_examples_v10 `
  --check

Push-Location frontend
npm test
npm run build
Pop-Location
```

The authenticated real-browser proof runs
`frontend/e2e/language-reference-v10-real.spec.ts` against a fresh loopback
Compose stack for Chromium and Pixel 7 with one worker and zero retries. Its
success-only JSON and PNG captures are under
`artifacts/v0.10/browser-e2e/results/`.

The browser menu remains usable with 195 choices through its option filter.
This increment grants no spacecraft, mission-network, live commanding,
deployment, compliance, or operational authority.
