# OpenBEXI SPELL

At the v0.9 candidate source-freeze boundary, OpenBEXI SPELL v0.8.0 was the
accepted clean-room, simulator-only engineering release. It combines a Python
execution service, isolated workers,
durable state and event storage, a restricted typed procedure language, a
typed simulator-driver lifecycle foundation, durable operator workspace and
procedure-composition workflows, simulator-only read-only observations and
conditions, typed local data services, and a real-time 2D web console.
Annotated tag object `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae` for `v0.8.0`
peels to release commit `d6e01222de3bf52013279e48a099b6ae7ded121d`
and activated the conditional acceptance recorded in that commit with no
accepted exceptions.

`V09-GATE-0A PASS` now authorizes only `V09-DEV-001` through `V09-DEV-009`
and their 45 planned proof identities under the bounded local synthetic
non-CUI development-environment profile. At v0.9 candidate source freeze, the
authorized implementation, version-scoped qualification/release tooling, and
exact product inventory were frozen together. Canonical candidate
qualification had not yet run; Gate 0B, Final qualification, packaging, the
release commit, and the annotated tag were pending at that boundary. Later
v0.9 acceptance is authoritative only through its strictly validated annotated
tag and committed evidence. The source-freeze status is not a release,
deployment, compliance, cryptographic-signature, or operational claim.

It has no Ground Control System driver, spacecraft connection, operational
telecommand capability, or authorization for mission use.

## Version 0.5 Release

- Independently validates and canonicalizes existing IR 0.3 at parser,
  persisted supervisor, and isolated worker boundaries.
- Rejects malformed or semantically inconsistent IR before worker allocation
  where detected by the supervisor and before `worker.started` or procedure
  effects in the worker.
- Validates recovery position, prompt identity, and checkpoint variable state
  with bounded deterministic audit diagnostics.
- Preserves accepted IR 0.3 behavior and persisted bytes without a migration,
  new language feature, API change, frontend behavior change, dependency
  change, or driver-contract change.
- Reports product/package/backend/frontend version `0.5.0`; the unchanged
  bundled driver correctly retains implementation identity `0.4.0`.

`V05-GATE-0A PASS` authorized the single `V05-IR-001` work package.
`V05-GATE-0B PASS` authorized its release closeout. The canonical work-package
qualification passed for candidate `aefa658`, test-only Docker inspection
timeout metadata correction and qualification source `ef26e53`, four suites,
six identities, and 949 concrete tests. Final qualification then passed 1,096
concrete tests with 1,090 passes, six exact approved SQLite environment skips,
36 subtests, and zero failures or errors. Four image-bound SBOMs and the
supply-chain audit passed with zero High or Critical findings. The deterministic
archive SHA-256 is
`cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241`.

## Version 0.6 Release

The owner has requested completion of v0.6, Durable Operator Workspace and
Procedure Composition. Its nine bounded operator work packages are
`V06-OP-001` through `V06-OP-009`, covering context/catalog/instances,
control leases and modes, the command matrix, durable prompts, schedules,
operator views and bounded inspection, safe named user actions, durable
`StartProc`, and cross-feature recovery/security. The owner explicitly approved
the exact bounded gate in
[`SPELL_v0.6_Pre-Implementation.md`](SPELL_v0.6_Pre-Implementation.md), so
`V06-GATE-0A PASS` authorized those nine work packages. Candidate commit
`0ea26105e72d7830de4a265989ed7d9074ffbe09` is now bound to canonical
work-package evidence SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`.
All ten candidate suites and all 45 mapped identities PASS, all nine work
packages are `IMPLEMENTED_AND_QUALIFIED`, and
[`V06-GATE-0B PASS`](SPELL_v0.6_Gate_0B.md) authorized release closeout. Final
qualification passed nine suite captures with 1,626 concrete tests, 1,620
passes, six exact SQLite environment skips, 36 subtests, and zero failures or
errors. Four image-bound SBOMs and the supply-chain audit passed with zero High
or Critical findings and zero unlocked inputs. The deterministic archive
SHA-256 is
`b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c`.
Release commit `05ec783a6e54a76e0548bdd536c18538f6bff51b` and annotated tag
`v0.6.0` completed acceptance with no accepted exceptions. This release grants
no deployment, operational authorization, broad compatibility, or compliance
result.

## Version 0.7 Release

The owner explicitly authorized the bounded simulator read-only observation
and condition-engine increment in
[`SPELL_v0.7_Pre-Implementation.md`](SPELL_v0.7_Pre-Implementation.md).
`V07-GATE-0A PASS` authorizes exactly `V07-OBS-001` through `V07-OBS-009` and
their 45 planned proof identities. The seven hash-bound planning contracts
cover driver time and sample identity, `GetTM`, declarative `Verify`, telemetry
`WaitFor` and scheduling, resource and lookup reads, limits and alarm state,
and cursor streams. Candidate
`82b497227aff097db9d4c3ff56adf56d76d892ca` adds the read-only observation
driver service, durable observation and condition migrations, brokered
procedure operations, authenticated APIs and cursor stream, and operator UI.
Its canonical evidence SHA-256 is
`04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20`.
Ten suites and all 45 mapped identities PASS; 2,070 concrete tests contain
2,051 passes, 19 explicit suite-level platform skips, 36 subtests, and zero
failures or errors. No mapped identity is skipped, failed, accepted as failed,
or waived.
All nine work packages are `IMPLEMENTED_AND_QUALIFIED`, and `V07-GATE-0B PASS`
authorized release closeout. Qualified source
`6ac43c5be7670ead09de821578cc6c6a680af109` has source fingerprint
`a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb` and
product fingerprint
`fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633`.
Final qualification passed nine suite captures with 2,041 concrete tests,
2,034 passes, seven exact SQLite environment skips, 36 subtests, and zero
failures or errors. Four image-bound SBOMs and the supply-chain audit passed
with zero High or Critical findings and zero unlocked inputs.

Release manifest SHA-256
`e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a`
binds evidence fingerprint
`7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718`.
The deterministic archive SHA-256 is
`90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2`.
Release commit `cf18e9d887ba0476cbcc3d8194e321332a3ae864` and annotated tag
`v0.7.0`, object `70e4d46a46d158dee3c63ec37a5d1922b3b61668`, completed acceptance.
The raw tag-object SHA-256 is
`dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae`.
This release creates no live GCS, spacecraft, mission-network, telecommand,
external-effect, deployment, operational, or compliance authority.

## Version 0.8 Release

The bounded v0.8 implementation adds canonical finite typed values, owner- and
revision-scoped catalogs and containers, deterministic non-executing DB/IMP
dictionary exchange, durable shared data, virtual-root procedure files, an
authorization-scoped local data API, ordered SQLite/PostgreSQL migration and
recovery support, and the Data Service operator workspace. Procedure `ARGS`,
`IVARS`, dictionary load/save, durable mutation settlement, path and symlink
protection, quota enforcement, audit/outbox binding, backup/restore, and
rollback are covered by the implementation test surface.

Candidate `f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c` and all 45 mapped
identities passed canonical qualification with no mapped skips, accepted
failures, or waivers. `V08-GATE-0B PASS` authorized release closeout. Final
qualification passed nine suite captures with 2,676 concrete tests, 2,661
passes, 15 exact SQLite environment skips, 36 subtests, and zero failures or
errors. Four image-bound SBOMs and the supply-chain audit passed with zero High
or Critical findings and zero unlocked inputs. Qualified source is
`d80c4d43969018633bc17650a23412b7274e58ea`; release-manifest SHA-256 is
`82e90f0d3a9481423d948d83559bde56ff332833f14ab2d01a8089ebf6a5e50e`;
the deterministic archive SHA-256 is
`87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb`.
Release commit `d6e01222de3bf52013279e48a099b6ae7ded121d` and annotated tag
`v0.8.0`, object `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, completed acceptance.

## Version 0.9 Gate 0A And Candidate Preparation

The owner request `start and complete asap V0.9` authorized the bounded
development-environment planning contract in
[`SPELL_v0.9_Pre-Implementation.md`](SPELL_v0.9_Pre-Implementation.md).
`V09-DEV-001` through `V09-DEV-009` cover the separate project workspace,
non-executing procedure language services, dictionary/catalog authoring,
semantic checks and Problems, safe import/export and external changes,
provider-neutral local history/collaboration, immutable validated bundles,
local simulator promotion/rollback, and cross-feature offline acceptance.
At the Gate 0A decision, the gate claimed zero implementation or runtime
artifacts. The bounded implementation, canonical v0.9 producer/validator
tooling, and exact product inventory were frozen together at candidate source
freeze. At that boundary, canonical candidate qualification had not yet run,
and Gate 0B, Final qualification, packaging, release, deployment, compliance,
and operational authorization were unclaimed. Later acceptance is established
only by the strictly validated annotated tag and committed evidence.

## Version 0.3 Foundation

- Python 3.13 control plane with one spawned worker per execution.
- Restricted non-executing AST parser and data-only IR for typed variables,
  safe expressions, conditions, bounded loops, bounded local calls, logs,
  simulated telemetry, waits, and operator prompts.
- Bounded binary source reads, AST shape, expanded step count, and serialized IR
  size, with stable non-echoing diagnostics for invalid UTF-8, unpaired Unicode
  surrogates, NUL characters, and other rejected input.
- Exact accepted procedure source and SHA-256 identity, definite-assignment
  checks, and protected compiler/runtime-reserved names.
- Atomic, durable checkpoints containing procedure position and variables.
- Idempotent and revision-guarded start, pause, resume, prompt, abort, simulated
  crash, and recovery operations.
- Ordered database migrations for fresh and v0.2 SQLite/PostgreSQL stores.
- Signed short-lived JWT identity and server-enforced viewer/operator/admin
  roles; unsigned identity headers are ignored.
- Authenticated WebSocket replay with snapshot/cursor resynchronization.
- Established WebSockets expire with their JWT. Logout and a `4401` close both
  close the socket, erase the session token, and return to session access.
- Durable settlement of every accepted command across worker completion,
  consumer failure, bounded shutdown, and supervisor restart terminal paths.
- React and strict TypeScript console with source validation, responsive
  desktop/mobile layouts, keyboard controls, telemetry charts, and as-run
  reports.
- Loopback reverse proxy as the sole ingress; backend and PostgreSQL remain on
  an internal network with no backend public-network route.
- Immutable static migrations; applied revisions do not depend on live ORM
  metadata.
- Hash-locked Python dependencies, npm integrity locking, distinct
  backend/proxy/frontend CycloneDX SBOMs with checksums, dependency audits, and
  reproducible source packages.

## Quick Start

Prerequisites are Docker Desktop and PowerShell.

```powershell
Copy-Item .env.example .env
# Set SPELL_DB_PASSWORD and a SPELL_JWT_HS256_SECRET of at least 32 bytes.
docker compose up --build -d

$token = (docker compose run --rm --no-deps `
  -e SPELL_ALLOW_LOCAL_DEV_TOKEN=true backend `
  python /app/scripts/issue_dev_token.py `
  --subject local.operator --role admin --lifetime 900 | Select-Object -Last 1).Trim()
```

Open `http://127.0.0.1:8080`, enter the signed token in the session-access form,
and connect. The token remains in browser session storage and is not built into
the frontend. Local issuance is disabled in the running backend by default and
is enabled only for the one-shot loopback helper command above.

`docker compose down` stops the stack without deleting the PostgreSQL volume.

## Procedure Language

Files named `*.spell.py` are parsed with Python's AST but are never imported,
compiled, evaluated, or run as Python source. The parser emits a versioned,
normalized data IR consumed by the worker. Source is read with a byte limit
before decoding; AST nodes/depth, expanded steps, and serialized IR are bounded
before worker handoff or persistence. Accepted source is preserved exactly and
its SHA-256 is computed over that same text.

| Construct | v0.3 behavior |
| --- | --- |
| `name: type = expression` | Declare `bool`, `int`, `float`, or `str` state |
| `name = expression` | Type-checked assignment to a declared variable |
| Arithmetic/comparison/boolean expressions | Evaluate through the allowlisted data interpreter |
| `if` / `else` | Select one deterministic guarded branch |
| `for name in range(...)` | Expand a statically bounded loop, maximum 1,000 iterations |
| `def name()` plus `Call(name)` | Expand a bounded, non-recursive zero-argument local call |
| `Log(...)` | Persist a procedure log |
| `Telemetry(...)` | Persist a deterministic simulated telemetry sample |
| `Wait(...)` | Wait at an interruptible checkpoint |
| `Prompt(...)` | Persist and latch an operator prompt |

Imports, attribute access, comprehensions, recursion, arbitrary calls, dynamic
loop bounds, filesystem, networking, subprocesses, reflection, exceptions, and
asynchronous syntax are rejected with structured diagnostics. Invalid UTF-8,
unpaired surrogates, and NUL characters receive stable diagnostics that do not
echo source. Definite assignment is checked across control flow, and reserved
compiler/runtime names cannot be redefined. See
[`procedures/v03_language_demo.spell.py`](procedures/v03_language_demo.spell.py).

## Architecture

The browser communicates with the loopback Nginx proxy. Only the proxy publishes
a host port. It serves the frontend and forwards `/api` and WebSocket traffic to
the internal FastAPI service. FastAPI validates identity, procedures, revisions,
and idempotency keys, persists authoritative state, and sends data-only IR to an
isolated worker process.

REST is authoritative for mutations and snapshots. WebSocket is downstream-only
and provides ordered per-execution events. Clients recover from a disconnect or
sequence gap by loading a snapshot and replaying from its cursor. Worker output
is generation-fenced and committed atomically with effects, variables,
checkpoint position, and events before publication. The supervisor durably
settles accepted commands when a worker terminates, a consumer fails, shutdown
times out, or recovery runs after restart.

## API Surface

All resources except health require a signed bearer JWT. WebSocket sends the JWT
as a subprotocol rather than placing it in the URL.

| Method | Resource |
| --- | --- |
| `GET` | `/api/v1/health`, `/api/v1/procedures`, `/api/v1/executions` |
| `POST` | `/api/v1/procedures/validate`, `/api/v1/executions` |
| `GET` | `/api/v1/executions/{id}/snapshot`, `/api/v1/executions/{id}/events`, `/api/v1/executions/{id}/report` |
| `POST` | `/api/v1/executions/{id}/commands` |
| `POST` | `/api/v1/prompts/{id}/responses` |
| `WS` | `/api/v1/ws?execution_id={id}&after_sequence={n}` |

Validation is transient: it returns subset version, SHA-256, normalized IR,
declared variables, and diagnostics without saving or executing submitted text.

## Verification

The accepted v0.5 work-package qualification and release-closeout commands are defined
by [`SPELL_v0.5_Gate_0B.md`](SPELL_v0.5_Gate_0B.md). They use locked Python
3.13, isolated SQLite/PostgreSQL suites, source-bound JUnit evidence,
deterministic packaging, and supply-chain inspection. The canonical candidate
record at `artifacts/v0.5/work-package/qualification.json` passes with SHA-256
`86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`;
the live Gate 0B marker also passes. Final evidence is published under
`artifacts/v0.5`, and [`Test_and_Integration.md`](Test_and_Integration.md) plus
[`SPELL_v0.5_Release.md`](SPELL_v0.5_Release.md) distinguish the immutable
pre-tag decision from the later verified tag result.

The v0.5 package excludes qualification staging, retained v0.4 evidence,
legacy archives, supplied/generated PDFs, secrets, and runtime journals.
Product PNG and other required visual assets remain included.

The canonical v0.6 candidate record at
`artifacts/v0.6/work-package/qualification.json` passes for candidate
`0ea26105e72d7830de4a265989ed7d9074ffbe09` with SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`.
Its ten suites prove all 45 required identities without a mapped skip, failure,
accepted failure, or waiver. Final qualification and release closeout later
passed, and annotated tag `v0.6.0` fixes that accepted historical release.
The v0.7 candidate is bound to canonical ten-suite, 45-identity evidence and
`V07-GATE-0B PASS`. Final qualification, SBOMs, supply-chain evidence,
deterministic packaging, release-evidence validation, and strict annotated-tag
validation then passed; annotated tag `v0.7.0` now fixes the accepted release.
The v0.8 candidate, Gate 0B, Final, SBOM, supply-chain, deterministic package,
release, and strict tag evidence passed; annotated tag `v0.8.0` fixes the
accepted release. The v0.9 implementation, tooling, and exact product inventory
were frozen together at candidate source freeze; canonical candidate
qualification and all later closeout endpoints were pending at that boundary.
The strictly validated annotated tag is authoritative for any later acceptance.

## Project Documents

| Document | Purpose |
| --- | --- |
| [`PROMPT_Instructions.md`](PROMPT_Instructions.md) | Durable architecture, safety, and release rules |
| [`PROMPT_History.md`](PROMPT_History.md) | Latest-first approved request and version history |
| [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) | Living delivered-version and candidate-release roadmap |
| [`VERSION_TIMELINE.md`](VERSION_TIMELINE.md) | Evidence-qualified version dates and elapsed-time record |
| [`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md) | Page-complete supplied-manual inventory, compatibility policy, behavior map, safety deviations, and roadmap consequence |
| [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md) | Authoritative next-generation design specification for implementation scope; currently Draft and not an implementation or operational authorization |
| [`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/web/SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf) | Validated Draft tagged PDF manual for the intended next-generation web interface, RBAC startup, modes, secure handover, operations, and procedure development |
| [`SPELL_v0.3_Pre-Implementation.md`](SPELL_v0.3_Pre-Implementation.md) | Approved v0.3 scope and exclusions |
| [`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md) | Project-owner-approved local synthetic non-CUI Candidate A scope; Gate 0 passed and bounded product engineering authorized |
| [`SPELL_v0.4_Release.md`](SPELL_v0.4_Release.md) | Accepted v0.4.0 scope, Final qualification, limitations, and tag decision |
| [`SPELL_v0.5_Pre-Implementation.md`](SPELL_v0.5_Pre-Implementation.md) | Gate 0A authorization for the single existing-IR hardening work package |
| [`SPELL_v0.5_Gate_0B.md`](SPELL_v0.5_Gate_0B.md) | Gate 0B release-closeout authorization; not final release acceptance |
| [`SPELL_v0.5_Release.md`](SPELL_v0.5_Release.md) | v0.5.0 conditional closeout record and post-tag acceptance verification |
| [`SPELL_v0.6_Pre-Implementation.md`](SPELL_v0.6_Pre-Implementation.md) | Approved Gate 0A scope for the nine bounded operator work packages; not implementation or release acceptance |
| [`SPELL_v0.6_Gate_0B.md`](SPELL_v0.6_Gate_0B.md) | Evidence-bound Gate 0B PASS and authorized deterministic release-closeout sequence |
| [`SPELL_v0.6_Release.md`](SPELL_v0.6_Release.md) | Conditional v0.6.0 release record activated by the verified annotated tag |
| [`SPELL_v0.7_Pre-Implementation.md`](SPELL_v0.7_Pre-Implementation.md) | Approved Gate 0A scope and hash-bound planning contracts for nine read-only simulator observation work packages; not implementation or release acceptance |
| [`SPELL_v0.7_Gate_0B.md`](SPELL_v0.7_Gate_0B.md) | Evidence-bound Gate 0B PASS for the qualified v0.7 candidate and authorized release closeout |
| [`SPELL_v0.7_Release.md`](SPELL_v0.7_Release.md) | v0.7.0 conditional closeout record activated by the verified annotated tag |
| [`SPELL_v0.8_Pre-Implementation.md`](SPELL_v0.8_Pre-Implementation.md) | Approved Gate 0A scope and hash-bound planning contracts for nine bounded local data-service work packages; not implementation or release acceptance |
| [`SPELL_v0.8_Gate_0B.md`](SPELL_v0.8_Gate_0B.md) | Evidence-bound Gate 0B PASS for the qualified v0.8 candidate and authorized release closeout |
| [`SPELL_v0.8_Release.md`](SPELL_v0.8_Release.md) | v0.8.0 conditional closeout record activated by the verified annotated tag |
| [`SPELL_v0.9_Pre-Implementation.md`](SPELL_v0.9_Pre-Implementation.md) | Approved Gate 0A scope and hash-bound planning contracts for nine bounded development-environment work packages; not implementation or release acceptance |
| [`SPELL_v0.9_Gate_0B.md`](SPELL_v0.9_Gate_0B.md) | v0.9 release-closeout decision contract; activation was pending at candidate source freeze |
| [`SPELL_v0.9_Release.md`](SPELL_v0.9_Release.md) | v0.9 conditional release contract; qualification and acceptance were pending at candidate source freeze |
| [`Test_and_Integration.md`](Test_and_Integration.md) | Versioned acceptance plans and executed evidence |
| [`PROVENANCE.md`](PROVENANCE.md) | Clean-room, dependency, and licensing review |
| [`SPELL_v0.3_Release.md`](SPELL_v0.3_Release.md) | v0.3 release scope, results, limitations, and decision |

At v0.9 candidate source freeze, SPELL v0.8.0 was the accepted product baseline
at annotated tag `v0.8.0` and release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`. Its acceptance is
limited to the nine `V08-DATA-001` through `V08-DATA-009` work packages and creates
no deployment, operational-use, broad-compatibility, or compliance authority.

The Development Environment manual was absent from the original v0.1 evidence
but was supplied separately on 2026-07-17. All seven PDFs now under
`SPELL-DOCUMENTATION/`, totaling 304 pages, were reviewed. The recovered manual
supports a later separate web authoring environment; it does not authorize that
product work before its roadmap gate or permit copying legacy Eclipse/Java code.
The validated exhaustive compatibility catalog contains 1,682 rows across all
seven source records, all 304 pages, and all 195 Language Reference examples.
It assigns 125 rows to the exact Candidate A slice and 1,557 rows to
Deferred/`EXCLUDE`; each row has a unique planned test identity. Deferred rows
are static source and negative-scope evidence, not implementations or executed
semantic oracles. Exact SHA-256 manifest binding and pinned Python 3.13 Gate 0
qualification pass; organization-only approvals are outside this local gate.
The accepted v0.4 through v0.8 release evidence remains immutable. v0.9 Gate
0A authorizes nine exact local synthetic non-CUI development-environment
packages and 45 planned proof identities. Their bounded implementation,
version-scoped tooling, and exact product inventory were frozen together at
candidate source freeze. At that boundary, canonical candidate qualification
had not yet run and no Gate 0B result, Final result, package, release commit, or
tag existed. The strictly validated annotated tag is authoritative for any
later acceptance.

The next-generation design specification was prepared on 2026-07-18 under
`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`. It preserves the two core 2.4.4
manuals as external hash-pinned authorities and provides a modern web, server,
data, reliability, Git, security, and operations blueprint. It is the
authoritative broader design source, including the Draft GUI User Manual. Its
status is `0.1.0-draft.1`: only the exact local synthetic v0.9 Gate 0A subset is
authorized. Accountable multidisciplinary review, open-decision closure,
detailed feature compatibility rows, and a signed approval baseline remain
required for broader remote, signed, production, or operational use.

## License

The new OpenBEXI SPELL implementation is licensed under Apache License 2.0. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Excluded legacy archives and
third-party packages retain their own licenses.
