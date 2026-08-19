# OpenBEXI SPELL Project Instructions

This file is the durable execution policy for `openbexi_spell`. Read it before
analysis, design, implementation, testing, integration, packaging, or release
work. Keep request history, executed results, and release-specific bindings in
`PROMPT_History.md`, `Test_and_Integration.md`, the active gate records, and the
applicable version record. Never infer release acceptance from this prompt or
from a mutable worktree; the strictly validated annotated tag and its committed
evidence are authoritative.

## Mission

OpenBEXI SPELL is a clean-room modernization of the Satellite Procedure
Execution Language and Library. Its purpose is to make automated satellite
procedures readable, repeatable, observable, portable across organizations, and
independent of a particular Ground Control System or spacecraft.

Reliability, deterministic behavior, traceability, explicit recovery, and
operator control take priority over convenience or visual novelty. The project
must reduce operational risk; a local simulator result must never be presented
as operational qualification.

## Source-Freeze Baseline And Candidate

At the v0.9 candidate source-freeze boundary, SPELL v0.8.0 was the accepted
local synthetic non-CUI simulator engineering baseline. Annotated tag object
`0dcf4f539fd1a9036fe4db4bc159cde04c35cfae` peels to release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`. The cumulative accepted product is
built from new first-party code and provides:

- Python 3.13 FastAPI control plane and isolated procedure workers.
- Restricted AST parser and data-only IR; submitted Python text is never
  imported, compiled, evaluated, or executed.
- Bounded binary source reads, AST complexity, expansion, and serialized IR;
  malformed text receives stable non-echoing diagnostics before persistence.
- Typed variables, safe expressions, deterministic conditions, bounded loops,
  bounded zero-argument local calls, and durable variable checkpoints.
- A separately isolated, authenticated simulator driver lifecycle, durable
  operator workspace and procedure composition, and simulator-only read-only
  observations, conditions, scheduling, resource reads, limits, and cursors.
- Canonical typed values, revisioned catalogs and dictionaries, non-executing
  DB/IMP exchange, typed `ARGS`/`IVARS`, durable shared data, virtual-root
  files, authenticated data APIs, transactional audit/outbox settlement,
  migration and recovery, and the Data Service console workspace.
- SQLite development storage and PostgreSQL 18 target storage with ordered,
  versioned migrations.
- Versioned REST mutations and snapshots plus authenticated, downstream-only,
  ordered WebSocket events.
- React and strict TypeScript real-time 2D operator console. Java, Eclipse,
  SWT, and Three.js are not runtime dependencies.
- Signed JWT identity, server-enforced viewer/operator/admin roles, loopback
  reverse-proxy ingress, and an internal backend/database network. Default and
  qualification credentials are short-lived; the narrowly bounded local
  session exception below remains finite and loopback-only.
- Hash-locked Python dependencies, npm integrity locking, reproducible source
  packages, version-scoped backend/driver/frontend/proxy CycloneDX SBOMs, and
  dependency audit gates.

The owner request `start and complete asap V0.9` is recorded on 2026-08-18.
`V09-GATE-0A PASS` authorizes exactly `V09-DEV-001` through `V09-DEV-009` and
their 45 planned proof identities under
`LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT`. Final Gate 0A commit
`92f3b4b82908d44e28b9506749e498386a428c27` has sole parent accepted v0.8.0
release commit `d6e01222de3bf52013279e48a099b6ae7ded121d`. At its authorization-time
boundary, Gate 0A claims zero implemented product constructs or runtime
artifacts. At v0.9 candidate source freeze, the bounded implementation,
version-scoped qualification/release tooling, and exact product inventory were
frozen together for one candidate commit. Canonical candidate qualification
had not yet run at that boundary, and Gate 0B, Final qualification, packaging,
the release commit, and the annotated tag were pending. Later v0.9 acceptance
is authoritative only through its strictly validated annotated tag;
the source-freeze record itself claims no release, deployment, compliance,
cryptographic-signature, or operational authority. No accepted release provides a legacy or live Ground
Control System client, spacecraft or mission-network connection, externally
effective command, production identity, high availability, deployment
approval, compliance determination, mission authority, or operational
authorization. Configuration must not make an excluded capability appear to
exist.

## Legacy Evidence

The following excluded archives are read-only compatibility and historical
evidence. Never compile, import, link, package, or silently copy implementation
code from them into the Apache-2.0 project:

- `SPELL2.6.10-src.zip`: legacy C++/Python core source.
- `SPELL-COTS-2.6.10.zip`: legacy third-party dependency bundle.
- `SPELL_GUI_4.0.12-win32.win32.x86.zip`: legacy 32-bit Eclipse GUI binary.

The supplied Server, GUI, Language, Driver Development, Development Environment,
and Build manuals and GUI build instructions are read-only external evidence.
Use the active version's hash-bound, page-complete review and compatibility
ledger for classification and traceability, not as implementation source or a
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
  dynamic loop bounds, recursion, direct or arbitrary filesystem, network, or
  database access, subprocesses, asynchronous syntax, and exception syntax.
  Approved data and virtual-file operations must lower to closed, typed IR and
  execute only through supervisor-brokered, schema-validated services with
  authenticated scope, revisions, bounds, audit, and recovery. Never expose a
  raw database connection or general host-filesystem handle to procedure code.
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
- Development token issuance must be disabled by default and in every running
  service, explicitly invoked through a one-shot transient issuer, loopback-only,
  and unavailable through a general HTTP endpoint. Default and qualification
  tokens must be short-lived.
- The sole owner-requested local-session exception may issue one effectively
  long-lived token into an ignored local file under `var/` only. Issuer
  configuration and the signing secret stay in the ignored local `.env`; the
  token must remain loopback-only, carry a finite `exp` (never be expiry-free),
  and be created by the one-shot transient issuer while service-side issuance
  stays disabled. Never print, log, commit, package, or retain its token or
  signing-secret bytes in evidence; secret rotation invalidates it.
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
  checksum manifest, and run dependency audits for every release. The current
  release contract requires four distinct CycloneDX inventories for backend,
  driver, frontend-build, and proxy image identities under the active version's
  artifact root. Critical or High findings require resolution; every other
  advisory requires a recorded, time-bounded disposition.
- Build the release package twice from the same frozen source and require
  identical SHA-256 results. The manifest must exclude archives, secrets,
  generated browser screenshots, caches, and IDE files. Screenshot exclusion
  must be path- and file-type-specific; it must retain PNG or other visual
  assets that are part of the product.
- Keep qualification and packaging version-aware. Require the exact test
  catalog, one frozen source fingerprint, semantic validation, no missing or
  skipped mandatory identity, and atomic publication under the active version's
  artifact root. Never use one version's retained evidence to satisfy, replace,
  or package another version.
- Use only the active version's hash-pinned toolchain and canonical producers.
  Initialize v0.9 commands with `scripts/assert_release_toolchain_v04.ps1`,
  validate the accepted baseline with
  `scripts/assert_accepted_v08_release_v09.ps1`, and invoke Python tools with
  the resulting `SPELL_RELEASE_PYTHON_EXE` and `-I`; never substitute an
  ambient interpreter. The v0.9 scope profile is
  `LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT`, while qualification
  requires the distinct exact confirmation `LOCAL_SYNTHETIC_NON_CUI_ONLY`.
  The Gate 0A validator is
  `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0a.py`.
  The prepared version-scoped canonical producers and validators are
  `scripts/qualify_candidate_v09.ps1`,
  `scripts/validate_candidate_evidence_v09.py`,
  `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_v09_gate_0b.py`,
  `scripts/qualify_release_v09.ps1`, `scripts/generate_sbom_v09.ps1`,
  `scripts/audit_supply_chain_v09.ps1`,
  `scripts/create_release_qualification_v09.py`,
  `scripts/package_release_v09.ps1`, and
  `scripts/validate_release_evidence_v09.py`. At candidate source freeze, set
  `PRODUCT_INVENTORY_FROZEN = True` only after the complete product test
  inventory, selectors, allowed skips, suite totals, inventory hashes, and
  mapped identities have been collected from stable tests and independently
  reviewed together. The v0.9 candidate source meets that precondition. Any
  subsequent product-test, selector, skip, total, hash, or proof-map change
  invalidates the freeze and requires a fresh joint collection before another
  candidate; both candidate and Final runners must fail closed otherwise.
  Inspect source, package bytes, and all four images for secrets, excluded
  manuals or archives, generated journals, and runtime generator tooling.
- Preserve unrelated user changes. Do not rewrite or discard them to obtain a
  clean working tree.

## Version Workflow

1. Establish authority: read this policy, the newest history entry, the accepted
   tag evidence, the active gate/release records, provenance, and relevant code
   and tests. Inspect Git, dependency, toolchain, and local-only state.
2. Before implementation, record the owner request, scope, exclusions,
   requirements, acceptance identities, and a fail-closed pre-implementation
   gate. Narrow ambiguous or operational behavior; do not implement it by
   assumption.
3. Implement only the authorized packages in ownership-aligned changes. Update
   migrations, schemas, documentation, threat controls, and tests with behavior.
4. Resolve every pre-candidate defect, finalize all source-fingerprinted policy
   files, and freeze exactly one candidate commit with the ancestry required by
   the active gate. Never qualify mutable working-tree bytes.
5. Run the canonical candidate producer and independent validator. Activate
   Gate 0B only through its atomic prepare/apply protocol and commit the exact
   candidate evidence and activated records.
6. After Gate 0B passes, run Final qualification from the committed qualified
   source, then generate and validate the SBOM and supply-chain evidence and
   create the release-qualification manifest. Record exact environments,
   commands, totals, timings, failures, exceptions, and hashes; never report an
   unexecuted test as passed.
7. When the active deterministic packager requires clean committed manifest
   bytes, create a transient prepackage evidence commit solely as its immutable
   input. Run the canonical packager's two builds in each of two independent
   source exports, require all four archive hashes to be identical, stage the
   archive and sidecar, and amend the transient commit so only the amended
   object is eligible as the release commit. Never tag, publish, or describe the
   transient object as a release.
8. On the clean complete release commit, run
   `scripts/validate_release_evidence_v09.py` before tagging, create the
   requested annotated semantic-version tag, then rerun that validator with
   `--require-tag`. Keep prior history and accepted evidence immutable.
9. When the release includes a web application, start the verified local stack
   and leave it running on its documented loopback URL after acceptance.

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
- Documentation integrity for every tracked Markdown file: strict UTF-8,
  balanced fences and controlled HTML markers, valid GFM table delimiters with
  unambiguous block separation, resolvable repository-local paths and heading
  fragments, and rendering through the hash-locked real CommonMark plus GFM
  preview engine. Validate same-document anchors, URL decoding, duplicate
  heading suffixes, explicit HTML IDs, and safe parent paths that remain inside
  the repository. Never autoformat validator-owned marker blocks after they are
  bound.
- Canonical replay, latency, throughput, concurrency, and sustained soak tests
  against version-specific budgets. These are engineering gates, not
  operational SLOs.
- Fingerprint-bound, version-specific built-in and environment-bound evidence,
  with an independent validator that recomputes catalog completeness,
  identities, budgets, and integrity. Scratch or staged output is never release
  evidence; only the atomically published canonical artifact is eligible.
- Hash-locked dependency installation, Python and Node audits, exact image
  identity, version-scoped SBOM generation, proxy and driver isolation checks,
  package-manifest inspection, exact generated-browser evidence exclusion, and
  repeated-build reproducibility. Use the active version's pinned scripts and
  validate their output independently before any release decision or tag.

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
