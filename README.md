# OpenBEXI SPELL

OpenBEXI SPELL v0.3 is a clean-room, simulator-only engineering release of a
modern Satellite Procedure Execution Language and Library environment. It
combines a Python execution service, isolated workers, durable state and event
storage, a restricted typed procedure language, and a real-time 2D web console.

It has no Ground Control System driver, spacecraft connection, operational
telecommand capability, or authorization for mission use.

## Version 0.3

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

```powershell
.\scripts\qualify_release.ps1
.\scripts\build_v03.ps1
```

`qualify_release.ps1` creates fingerprint-bound quick, soak, and two-process
Chromium stream reports and composes them independently. `build_v03.ps1`
validates that evidence against the current source, then runs the complete
SQLite/PostgreSQL, frontend, real-backend browser, isolation, audit, distinct
SBOM, package inspection, and reproducibility gates. Exact commands and results
are recorded in [`Test_and_Integration.md`](Test_and_Integration.md).

Release packaging excludes only generated evidence screenshots under the
versioned artifacts path; product PNG and other visual assets remain included.

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
| [`Test_and_Integration.md`](Test_and_Integration.md) | Versioned acceptance plans and executed evidence |
| [`PROVENANCE.md`](PROVENANCE.md) | Clean-room, dependency, and licensing review |
| [`SPELL_v0.3_Release.md`](SPELL_v0.3_Release.md) | v0.3 release scope, results, limitations, and decision |

SPELL v0.3.0 remains the accepted product baseline. JC Arcaz approved the
bounded local v0.4 Candidate A scope, its exclusions, budgets, and test plan.
Gate 0 passed under the digest-pinned Python 3.13 image after exact manifest
binding and compatibility qualification. This authorizes only the bounded v0.4
product-engineering work; the v0.4 documents do not yet describe delivered
runtime behavior or a release result.

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
Release acceptance still requires every approved v0.4 Gate 1-5 criterion.

The next-generation design specification was prepared on 2026-07-18 under
`NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/`. It preserves the two core 2.4.4
manuals as external hash-pinned authorities and provides a modern web, server,
data, reliability, Git, security, and operations blueprint. It is the
authoritative source for next-generation implementation scope, including the
Draft GUI User Manual. Its status is `0.1.0-draft.1`: accountable human review,
open-decision closure, detailed feature compatibility rows, and a signed
approval baseline remain required before implementation starts or any
operational use is authorized.

## License

The new OpenBEXI SPELL implementation is licensed under Apache License 2.0. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Excluded legacy archives and
third-party packages retain their own licenses.
