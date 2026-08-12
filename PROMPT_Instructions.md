# OpenBEXI SPELL Project Instructions

This file is the durable execution prompt for `openbexi_spell`. Read it before
analysis, design, implementation, testing, integration, packaging, or release
work. Release-specific requests and results belong in `PROMPT_History.md`,
`Test_and_Integration.md`, and the applicable version record.

## Mission

OpenBEXI SPELL is a clean-room modernization of the Satellite Procedure
Execution Language and Library. Its purpose is to make automated satellite
procedures readable, repeatable, observable, portable across organizations, and
independent of a particular Ground Control System or spacecraft.

Reliability, deterministic behavior, traceability, explicit recovery, and
operator control take priority over convenience or visual novelty. The project
must reduce operational risk; a local simulator result must never be presented
as operational qualification.

## Current Baseline And Candidate

SPELL v0.3.0, tag `v0.3.0`, remains the accepted local simulator engineering
baseline. It is built from new first-party code and provides:

- Python 3.13 FastAPI control plane and isolated procedure workers.
- Restricted AST parser and data-only IR; submitted Python text is never
  imported, compiled, evaluated, or executed.
- Bounded binary source reads, AST complexity, expansion, and serialized IR;
  malformed text receives stable non-echoing diagnostics before persistence.
- Typed variables, safe expressions, deterministic conditions, bounded loops,
  bounded zero-argument local calls, and durable variable checkpoints.
- SQLite development storage and PostgreSQL 18 target storage with ordered,
  versioned migrations.
- Versioned REST mutations and snapshots plus authenticated, downstream-only,
  ordered WebSocket events.
- React and strict TypeScript real-time 2D operator console. Java, Eclipse,
  SWT, and Three.js are not runtime dependencies.
- Signed short-lived JWT identity, server-enforced viewer/operator/admin roles,
  loopback reverse-proxy ingress, and an internal backend/database network.
- Hash-locked Python dependencies, npm integrity locking, reproducible source
  packages, distinct backend/proxy/frontend CycloneDX SBOMs, and dependency
  audit gates.

SPELL v0.4.0 is the owner-approved Candidate A engineering target. Its scope is
strictly local-only, synthetic, non-CUI simulator engineering. Candidate scope
is limited to a typed `spell.driver.v1` infrastructure-lifecycle contract, one
bundled deterministic simulator driver in a separate host, control-plane-owned
context and attachment supervision, mTLS service identity, durable operation
reconciliation, read-only REST/WebSocket projections, and a read-only console
projection. Existing v0.3 procedure semantics and their versioned schemas stay
unchanged and do not route through the driver.

The v0.4 candidate exposes no telemetry or telecommand data plane, no
procedure-facing driver call, no arbitrary endpoint, and no browser mutation of
driver state. It does not provide a legacy or live Ground Control System client,
spacecraft or mission-network connection, externally effective command,
persistent procedure authoring, production PKI or identity, high availability,
deployment approval, compliance determination, mission authority, or
operational authorization. Configuration must not make any excluded capability
appear to exist. Gate 0 authorized bounded implementation; only executed and
published Gates 1-5 evidence plus an explicit project-owner decision can accept
the release candidate.

## Legacy Evidence

The following excluded archives are read-only compatibility and historical
evidence. Never compile, import, link, package, or silently copy implementation
code from them into the Apache-2.0 project:

- `SPELL2.6.10-src.zip`: legacy C++/Python core source.
- `SPELL-COTS-2.6.10.zip`: legacy third-party dependency bundle.
- `SPELL_GUI_4.0.12-win32.win32.x86.zip`: legacy 32-bit Eclipse GUI binary.

The supplied Server, GUI, Language, Driver Development, Development Environment,
and Build manuals and GUI build instructions are read-only external evidence.
For v0.4, use their page-complete review and compatibility ledger for
classification and traceability, not as implementation source or a
version-exact executable oracle. Do not copy their code or weakly typed wire
contracts, and do not place the supplied PDFs, extracted manual text, or legacy
archives in product images or release packages. Record conflicts and exclusions;
do not invent compatibility. Core and GUI legacy versions are independent
version series.

## Architecture Rules

- Keep the browser, control plane, execution worker, persistence, and bundled
  simulator driver host as separate trust and ownership boundaries.
- REST is authoritative for commands and snapshots. Mutations require durable
  idempotency keys; state-sensitive commands require expected revisions.
- WebSocket is downstream-only. Persist ordered events before publication, and
  recover gaps through snapshot plus cursor replay.
- Parse procedure source into a versioned, normalized, data-only IR. Maintain an
  explicit allowlist; reject imports, attributes, reflection, arbitrary calls,
  dynamic loop bounds, recursion, filesystem, network, database, subprocess,
  asynchronous, and exception syntax.
- Bound source bytes before decoding or parsing, then bound AST nodes and depth,
  expanded steps, and serialized IR bytes before IR is handed to a worker or
  persisted. Catalog discovery must use bounded binary reads and reject files
  that exceed policy before reading their contents into memory.
- Reject invalid UTF-8, unpaired Unicode surrogates, and NUL characters with
  stable structured diagnostics that never echo submitted source. Preserve the
  exact accepted source and compute its SHA-256 over the same exact text; do not
  substitute normalized or reparsed text for either value.
- Enforce definite assignment across branches, loops, and local calls. Protect
  compiler/runtime-reserved names from user declarations, assignments, loop
  targets, and function definitions.
- Commit procedure position, variables, effects, prompts, commands, events, and
  audit data atomically at safe checkpoints. Fence stale worker generations.
- Preserve one durable outcome under retry, concurrency, late worker messages,
  database failure, process restart, and recovery. Every accepted command must
  reach a durable terminal outcome on worker terminal messages, consumer
  failure, bounded shutdown, and supervisor restart; no accepted command may
  remain indefinitely pending.
- Keep any future GCS or spacecraft behavior behind typed driver boundaries.
  Neither the browser nor the control plane may directly access an operational
  integration.
- Do not add Java. A future Three.js feature requires explicit version scope and
  must not replace the primary accessible 2D control surface.

## Safety Rules

- Never connect to a live Ground Control System, spacecraft, or mission network
  without an explicit approved task, environment, procedure, and test plan.
- Use simulated, recorded, stubbed, or otherwise non-operational data by
  default. Keep simulator identifiers and operational disclaimers visible in
  API metadata, reports, and release records.
- Preserve prompts, holds, confirmations, aborts, disconnect interlocks, and
  recovery barriers. Never weaken them silently.
- Never retry an externally effective command automatically. An uncertain
  result requires reconciliation before any later operational implementation
  may continue.
- Validate telemetry identity, unit, time, freshness, validity, quality, and
  limits before a future operational decision consumes it.
- Preserve chronological events, commands, user identity, reasons, prompts,
  hashes, state transitions, checkpoints, results, and as-run evidence.
- Treat timeout, cancellation, stale data, partial response, disconnect,
  restart, migration failure, worker loss, and malformed input as normal failure
  cases with explicit behavior.
- Fail closed when identity, role, driver, service, schema, procedure,
  dependency, secret, or configuration is missing or incompatible.

## Identity And Network Rules

- Derive actor and role only from a verified signed credential. Never trust
  caller-supplied actor or role headers.
- Validate JWT algorithm, signature, issuer, audience, subject, role, issued-at,
  not-before, expiry, identifier, and maximum lifetime.
- Re-evaluate WebSocket credential expiry after the connection is established
  and close an expired session with code `4401`. The frontend must close its
  socket and erase session credentials on logout, and a `4401` close must erase
  the stored token and return the operator to session access.
- Development token issuance must be disabled by default, explicitly enabled,
  loopback-only, short-lived, and unavailable through a general HTTP endpoint.
- Do not embed tokens or signing secrets in frontend builds, source, examples,
  logs, reports, packages, screenshots, or commits.
- Expose only the loopback reverse proxy in the local Compose profile. The
  backend and database remain un-published on an internal network, and the
  backend must have no general public-network route.
- Keep trusted-host, CORS, content-security, framing, content-type, and referrer
  policies constrained to the required local surface.

## Compatibility And Evolution

- Treat REST schemas, WebSocket events, IR versions, procedure semantics,
  migration history, persisted fields, command outcomes, and report hashes as
  versioned contracts.
- Prefer backward-compatible additions. Any breaking change requires an
  approved migration, rollback plan, compatibility evidence, and explicit
  release note.
- Never edit an applied migration. Add an ordered migration and test fresh,
  prior-version, repeated, and failed-upgrade paths on SQLite and PostgreSQL.
- Migration revisions are immutable, static schema transformations. They must
  not derive an applied revision from live ORM metadata or mutable application
  models.
- Keep legacy compatibility evidence separate from claims of full legacy SPELL
  language compatibility. Unsupported syntax must fail with stable diagnostics.
- Do not claim support for an operating system, browser, GCS, spacecraft,
  driver, deployment, performance level, or recovery mode until its gate has
  actually passed.

## Repository And Supply Chain

- The new first-party implementation is licensed under Apache License 2.0. The
  project license does not relicense excluded legacy archives or dependencies.
- Keep legacy ZIPs, IDE metadata, build output, caches, credentials, tokens,
  private certificates, machine paths, and local databases out of commits and
  release packages.
- Do not edit vendored legacy COTS code to implement product behavior.
- Use exact dependency locks with artifact hashes where the ecosystem supports
  them. Install Python release dependencies with `--require-hashes` and Node
  dependencies with `npm ci`.
- Produce the exact version-scoped SBOM set required by the active gate and a
  checksum manifest, and run dependency audits for every release. The v0.4 set
  is four distinct CycloneDX inventories for backend, driver, frontend build,
  and proxy image identities under `artifacts/v0.4/sbom`. Critical or High
  findings require resolution; every other advisory requires a recorded,
  time-bounded disposition.
- Build the release package twice from the same frozen source and require
  identical SHA-256 results. The manifest must exclude archives, secrets,
  generated browser screenshots, caches, and IDE files. Screenshot exclusion
  must be path- and file-type-specific; it must retain PNG or other visual
  assets that are part of the product.
- Keep qualification and packaging version-aware. For v0.4, stage every
  built-in or environment-bound Gate 1-5 result through
  `scripts/qualify_v04.py`; require the exact test catalog, shared source
  fingerprint, semantic validation, no missing or skipped mandatory result, and
  atomic publication under `artifacts/v0.4`. Do not read, satisfy, overwrite, or
  package retained v0.3 evidence as v0.4 evidence.
- Generate and validate v0.4 contracts offline from pinned inputs. Inspect
  source, package bytes, and the exact four images for secrets, manual/PDF or
  legacy material, generated journals, and runtime generator tooling. Build the
  v0.4 source package repeatedly from immutable inputs and require identical
  SHA-256 results before recording any release decision.
- Preserve unrelated user changes. Do not rewrite or discard them to obtain a
  clean working tree.

## Version Workflow

1. Read this file, the latest entry at the top of `PROMPT_History.md`, the
   accepted baseline record, the active candidate gate/release record,
   provenance, and relevant code/tests.
2. Inspect repository and dependency state. Establish the last verified tag and
   keep unrelated or local-only files out of the change.
3. Before implementation, add the new version request at the top of
   `PROMPT_History.md`, define scope and exclusions, and add requirements and
   acceptance tests to `Test_and_Integration.md`.
4. Do not implement until that pre-implementation gate is explicit. Resolve
   ambiguity by narrowing scope, especially around operational behavior.
5. Implement in small ownership-aligned changes. Update migrations, schemas,
   examples, documentation, threat controls, and tests with the behavior.
6. Execute every mandatory gate. Record exact environments, commands, totals,
   timings, failures, exceptions, and artifact hashes. Never report an
   unexecuted test as passed.
7. Update `README.md`, `PROVENANCE.md`, the version release record, test results,
   and the latest history entry. Keep earlier history immutable.
8. Commit only intended project files, create the requested annotated version
   tag, and leave the verified local service running on its documented
   loopback URL when the release includes a web application.

## Required Verification

Scale verification with risk, but every product release must include:

- Python compilation and backend unit/integration tests with Docker networking
  disabled using SQLite.
- Full backend tests against the target PostgreSQL version, including fresh and
  prior-version migrations.
- Parser allowlist, type, complexity, recursion, loop-bound, size, and
  non-execution tests.
- Authentication, role-spoofing, token-policy, ingress, header, internal-service,
  and outbound-isolation tests.
- Crash, pause, prompt, abort, database-failure, restart, recovery,
  idempotency, concurrency, late-message, and audit-integrity tests.
- Frontend unit tests, strict TypeScript production build, desktop/mobile real
  browser workflows, keyboard control, responsive containment, and Axe checks.
- Canonical replay, latency, throughput, concurrency, and sustained soak tests
  against version-specific budgets. These are engineering gates, not
  operational SLOs.
- Fingerprint-bound, version-specific built-in and environment-bound evidence,
  with a separate validator that recomputes catalog completeness, identities,
  budgets, and integrity. For v0.4 use `python scripts/qualify_v04.py plan`,
  `run`/`collect`, `status`, and finally `publish`; staged evidence is not release
  evidence until publication succeeds.
- Hash-locked dependency installation, Python and Node audits, exact image
  identity, version-scoped SBOM generation, proxy and driver isolation checks,
  package-manifest inspection, exact generated-browser evidence exclusion, and
  repeated-build reproducibility. For v0.4 use
  `scripts/audit_supply_chain_v04.ps1`, `scripts/generate_sbom_v04.ps1`,
  `scripts/inspect_release_v04.ps1`, and
  `scripts/package_release_v04.ps1` within the Gate 5 qualification workflow.

Any unresolved Critical or High defect in safety boundaries, identity,
authorization, persistence, ordering, migration, recovery, isolation, or source
non-execution blocks release. Exceptions must be concrete and cannot waive a
safety boundary.

## Authoritative References

Local versioned code, migrations, tests, lock files, license files, and release
records are authoritative for the implementation. Use upstream SPELL material
for historical and architectural context:

- SPELL Wiki: `https://sourceforge.net/p/spell-sat/wiki/Home/`
- SPELL project: `https://sourceforge.net/projects/spell-sat/`
- Getting started: `https://sourceforge.net/p/spell-sat/wiki/Start%20using%20SPELL/`
- Licensing overview: `https://sourceforge.net/p/spell-sat/wiki/Licensing/`

When local evidence and upstream documentation disagree, record the discrepancy
and follow the approved local version contract unless a later prompt explicitly
adopts different behavior.
