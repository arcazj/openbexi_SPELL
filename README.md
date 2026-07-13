# OpenBEXI SPELL

OpenBEXI SPELL v0.2 is a clean-room, simulator-only vertical slice of a modern
Satellite Procedure Execution Language and Library environment. It combines a
Python execution service, isolated procedure workers, durable state and event
storage, and a real-time 2D web console.

Version 0.2 is development software. It has no Ground Control System driver,
spacecraft connection, operational telecommand capability, or authorization
for mission use.

## Implemented in v0.2

- Python 3.10+ control plane, verified with Python 3.13.
- One spawned operating-system worker per execution.
- Restricted, non-executing AST parser for four procedure steps.
- Idempotent, revision-guarded start, pause, resume, prompt, abort, crash, and
  recovery operations.
- Persist-before-publish execution, command, prompt, checkpoint, audit, and
  ordered event records.
- PostgreSQL target storage with SQLite support for fast isolated tests.
- Authenticated downstream WebSocket replay plus snapshot/cursor resync.
- React and strict TypeScript 2D operator console with responsive desktop and
  mobile layouts, accessibility checks, telemetry charts, and as-run reports.
- Python 3.13 development container and loopback-only Docker Compose services.

## Quick Start

Prerequisites are Docker Desktop and a current Node.js LTS or newer release.

```powershell
docker compose up --build -d
Set-Location frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open the operator console at `http://127.0.0.1:5173`. API documentation is at
`http://127.0.0.1:8000/docs`. The checked-in credentials are local simulator
defaults only. `docker compose down` stops the services without deleting the
PostgreSQL volume.

## Procedure Subset

Files named `*.spell.py` are parsed with `ast.parse` and `ast.literal_eval`.
They are never imported or evaluated as Python source.

| Step | v0.2 behavior |
| --- | --- |
| `Log(message, level=...)` | Persist a simulator procedure log |
| `Telemetry(channel, value=..., unit=...)` | Persist a deterministic simulated sample |
| `Wait(seconds)` | Wait at an interruptible safe boundary |
| `Prompt(question, choices=..., default=...)` | Persist and latch an operator prompt |

Only top-level calls with literal arguments are accepted. Imports, assignment,
attribute access, arbitrary calls, filesystem access, networking, subprocesses,
drivers, and secrets are rejected during validation. See
[`procedures/demo.spell.py`](procedures/demo.spell.py) for the complete sample.

## Architecture

The browser communicates only with the FastAPI control plane. The control plane
validates procedures into a versioned intermediate representation, stores the
authoritative execution record, and launches the validated steps in a spawned
worker. Worker output is generation-fenced and committed atomically with its
step completion and checkpoint before events are published.

REST is the authoritative mutation and snapshot interface. Every mutation uses
an idempotency key, and execution commands also require the expected revision.
WebSocket is downstream-only and provides ordered per-execution events. Clients
recover from a disconnect or sequence gap by loading a snapshot and replaying
from its cursor.

The simulator context is the only accepted execution context. The v0.2 source
contains no GCS or spacecraft client. Compose uses a dedicated development
network with host ports bound only to loopback. Container outbound networking
is not blocked by Compose; the backend acceptance suite is also run separately
with Docker networking disabled.

## API Surface

| Method | Resource |
| --- | --- |
| `GET` | `/api/v1/health`, `/procedures`, `/executions` |
| `POST` | `/api/v1/executions` |
| `GET` | `/api/v1/executions/{id}/snapshot`, `/events`, `/report` |
| `POST` | `/api/v1/executions/{id}/commands` |
| `POST` | `/api/v1/prompts/{id}/responses` |
| `WS` | `/api/v1/ws?execution_id={id}&after_sequence={n}` |

All paths except health are under `/api/v1`. REST uses the development bearer
token and role headers; WebSocket authentication uses a subprotocol so the token
is not placed in the URL. This development identity mechanism is not suitable
for a shared or operational deployment.

## Verification

```powershell
docker compose build backend
docker run --rm --network none openbexi_spell-backend python -m pytest backend/tests -q
docker compose run --rm -e SPELL_TEST_DATABASE_URL=postgresql+psycopg://spell:spell-dev-only@postgres:5432/spell_test backend python -m pytest backend/tests -q

Set-Location frontend
npm test
npm run build
$env:SPELL_REAL_BACKEND='1'; npm run test:e2e
npm audit
```

The authoritative executed-test matrix and all exceptions are recorded in
[`Test_and_Integration.md`](Test_and_Integration.md).

## Project Documents

| Document | Purpose |
| --- | --- |
| [`PROMPT_Instructions.md`](PROMPT_Instructions.md) | Durable project and safety rules |
| [`SPELL_v0.1_Pre-Implementation.md`](SPELL_v0.1_Pre-Implementation.md) | Legacy evidence and architecture baseline |
| [`Test_and_Integration.md`](Test_and_Integration.md) | Versioned acceptance plan and actual results |
| [`PROMPT_History.md`](PROMPT_History.md) | Approved requests, decisions, and version history |
| [`PROVENANCE.md`](PROVENANCE.md) | Clean-room and direct-dependency review |
| [`SPELL_v0.2_Release.md`](SPELL_v0.2_Release.md) | v0.2 scope, evidence, limitations, and decision |

The required legacy SPELL Development Environment manual remains unavailable.
Its absence was waived only for this v0.2 slice because v0.2 does not implement
a procedure authoring environment.

## License

OpenBEXI SPELL is licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
