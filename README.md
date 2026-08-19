# OpenBEXI SPELL

OpenBEXI SPELL is a local, simulator-only environment for developing,
validating, and executing bounded satellite procedures. It combines a FastAPI
control plane, isolated procedure workers, PostgreSQL persistence, a React and
TypeScript operator console, and deterministic simulator services.

The current source tree reports product version `0.11.0`. The latest accepted,
immutable release is **v0.9.0** at annotated tag `v0.9.0`. The v0.10 and v0.11
increments are implemented and locally qualified in the mutable source tree,
but they are not released or operationally authorized.

> **Safety boundary:** this repository does not provide a live Ground Control
> System (GCS) connection, spacecraft command path, production deployment
> approval, or compliance determination. The v0.11 `BuildTC` and `Send`
> implementation is deterministic and simulator-only.

## Capabilities

- Restricted SPELL source parsing into bounded, versioned intermediate
  representations without unrestricted Python execution.
- Durable execution state, revision-guarded operator control, prompts,
  schedules, checkpoints, recovery, event replay, and as-run reporting.
- Authenticated REST and WebSocket APIs with short-lived JWT identities and
  server-enforced viewer, operator, and administrator roles.
- Responsive operator console for procedure selection, execution control,
  monitoring, telemetry, source, logs, prompts, and data-service workflows.
- Separate web development environment for project resources, semantic checks,
  history, immutable bundle construction, review, and simulator promotion.
- Read-only simulator telemetry, conditions, limits, alarms, resources,
  memory/TM/TC lookup, and deterministic driver time.
- Revisioned catalogs, dictionaries, containers, shared data, and fixed virtual
  file roots backed by server-owned storage.
- A bounded v0.10 runner for all 195 numbered SPELL Language Reference 2.4.4
  examples, represented by 257 independently asserted semantic variants.
- Closed v0.11 simulator telecommand semantics for typed `BuildTC` and `Send`,
  including command/sequence/group/block expansion, critical confirmation,
  scheduling, release, load-only behavior, verification, cancellation,
  recovery, reconciliation, and no automatic resend after uncertain effects.
- Hash-locked dependencies, digest-pinned container bases, release evidence,
  SBOM tooling, deterministic packaging, and version-scoped qualification.

## Version Status

| Version | Scope | Status |
| --- | --- | --- |
| v0.1 | Pre-implementation requirements and architecture baseline | Delivered planning baseline |
| v0.2 | End-to-end simulator vertical slice | Accepted at `v0.2.0` |
| v0.3 | Security, isolation, recovery, and language hardening | Accepted at `v0.3.0` |
| v0.4 | Typed out-of-process simulator driver lifecycle | Accepted at `v0.4.0` |
| v0.5 | Fail-closed validation for the existing IR 0.3 scope | Accepted at `v0.5.0` |
| v0.6 | Durable operator workspace and procedure composition | Accepted at `v0.6.0` |
| v0.7 | Read-only observation and condition engine | Accepted at `v0.7.0` |
| v0.8 | Data and local service compatibility | Accepted at `v0.8.0` |
| v0.9 | Web-based SPELL development environment | Latest accepted release at `v0.9.0` |
| v0.10 | SPELL 2.4.4 reference example adapter | Implemented and locally qualified; not released |
| v0.11 | Simulator telecommand semantics | Implemented and locally qualified; not released |

See [PROJECT_ROADMAP.md](PROJECT_ROADMAP.md) for exact scope and gate status,
and [VERSION_TIMELINE.md](VERSION_TIMELINE.md) for the evidence-qualified
release history.

## Architecture

```text
Browser
   |
   | HTTP/WebSocket on 127.0.0.1:8080
   v
Nginx proxy + built React frontend
   |
   v
FastAPI control plane ---------------- PostgreSQL
   |          |               |
   |          |               +------ durable state and audit
   |          +---------------------- isolated procedure workers
   +-------------------------------- networkless bundle builders

Optional Compose `driver` profile:
FastAPI gateway -- internal mTLS -- synthetic driver host
```

The default Compose stack publishes only the Nginx proxy on the loopback
interface. The backend and PostgreSQL remain on internal Docker networks. Two
bundle builders run with `network_mode: none`. The optional driver profile is a
separate synthetic lifecycle service and does not add live TM/TC connectivity.

| Service | Responsibility | Exposure |
| --- | --- | --- |
| `proxy` | Frontend, security headers, API and WebSocket reverse proxy | `127.0.0.1:8080` |
| `backend` | API, parser, supervisor, runtime, data and development services | Internal only |
| `postgres` | Authoritative transactional persistence | Internal only |
| `bundle-builder-a/b` | Independent immutable development bundle construction | No network |
| `pki-init` | One-use local driver credential provisioning | Optional `driver` profile |
| `spell-driver` | Synthetic driver lifecycle and observation service | Optional internal profile |

## Requirements

For the normal workflow:

- Git
- Docker Engine or Docker Desktop with Docker Compose v2
- Enough resources to build the Python 3.13 backend and Node 22 frontend images

For host-side frontend development, install Node.js 22 and npm. Project
metadata permits Python 3.10 or newer, while the controlled container and
qualification environment uses Python 3.13.

## Quick Start

1. Clone the repository and enter it.

   ```powershell
   git clone https://github.com/arcazj/openbexi_SPELL.git
   Set-Location openbexi_SPELL
   ```

2. Create local configuration.

   ```powershell
   Copy-Item .env.example .env
   ```

   Set these two values in `.env` before starting the stack:

   ```dotenv
   SPELL_DB_PASSWORD=<URL-safe-random-value>
   SPELL_JWT_HS256_SECRET=<at-least-32-random-bytes>
   ```

   Do not commit `.env` or reuse these local secrets in another environment.

3. Build and start the local stack.

   ```powershell
   docker compose up --build -d --wait
   docker compose ps
   ```

4. Verify the public health endpoint.

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8080/api/v1/health
   ```

   A healthy response reports version `0.11.0`, mode `simulator-only`, and
   `operational_use: false`.

5. Issue a short-lived local operator token.

   ```powershell
   docker compose run --rm --no-deps `
     -e SPELL_ALLOW_LOCAL_DEV_TOKEN=true backend `
     python /app/scripts/issue_dev_token.py `
     --subject local-operator --role operator --lifetime 900
   ```

   Token issuance is disabled in the running service by default. The command
   enables it only in a loopback-oriented one-off container.

6. Open [http://127.0.0.1:8080](http://127.0.0.1:8080) and enter the token in
   the session-access form.

The separate v0.9 development workspace is available at
[http://127.0.0.1:8080/development.html](http://127.0.0.1:8080/development.html).
It uses the same authentication boundary.

Stop the stack without deleting persistent volumes:

```powershell
docker compose down
```

## Run The v0.10 Reference Procedure

The production catalog contains one bundled v0.10 procedure:
[`procedures/language_reference_244.spell.py`](procedures/language_reference_244.spell.py).

After signing in to the operator console:

1. Select **SPELL 2.4.4 reference examples** in the `simulator` context.
2. Choose **Start procedure**. The console creates the execution and acquires
   operator control.
3. Filter or scroll through the 195-example prompt.
4. Select an example and commit the response.
5. Review the completed execution, ordered trace, assertions, and as-run report.

Each choice invokes a source-hash-bound deterministic adaptation and oracle.
This is not verbatim execution of arbitrary PDF snippets and is not a claim of
general SPELL 2.4.4 source compatibility. External-effect examples remain
in-memory simulator operations with live dispatch disabled.

The exact v0.10 contracts and evidence are in:

- [`contracts/v10/language_reference_example_matrix.json`](contracts/v10/language_reference_example_matrix.json)
- [`contracts/v10/language_reference_variant_matrix.json`](contracts/v10/language_reference_variant_matrix.json)
- [`artifacts/v0.10/reference-examples.json`](artifacts/v0.10/reference-examples.json)
- [SPELL_v0.10_Implementation.md](SPELL_v0.10_Implementation.md)

## v0.11 Telecommand Boundary

v0.11 adds catalog-backed simulator handling for the 26 documented command
statements in Language Reference examples 57 through 77. Its contracts are:

- [`contracts/v11/telecommand_catalog.json`](contracts/v11/telecommand_catalog.json)
- [`contracts/v11/telecommand_execution.json`](contracts/v11/telecommand_execution.json)

The runtime records transport, loading, release, acknowledgement, onboard
execution, verification, terminal disposition, timing, and effect certainty as
separate facts. Confirmation challenges are digest-bound; recovery validates
canonical checkpoints; and a possible uncertain effect is never automatically
resent. Provider behavior, telemetry, and time are injected deterministic
fixtures. No browser route can configure a live command endpoint.

See [SPELL_v0.11_Pre-Implementation.md](SPELL_v0.11_Pre-Implementation.md) and
[SPELL_v0.11_Implementation.md](SPELL_v0.11_Implementation.md) for the approved
scope, semantics, exact commands, evidence hashes, and exclusions.

## Development

### Backend

Build the local backend image:

```powershell
docker build -t openbexi-spell-backend:local -f backend/Dockerfile .
```

Create a Python 3.13 test environment from the hash-locked dependency sets and
run the backend plus driver-host suites:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install --require-hashes `
  -r backend/requirements.hashes.lock `
  -r driver_host/pki-requirements.hashes.lock `
  -r contracts/generator-requirements.hashes.lock
.\.venv\Scripts\python -m pytest `
  backend/tests driver_host/tests -q -p no:cacheprovider
```

Environment-selected PostgreSQL and Docker Compose integration tests require
their dedicated services and variables. The version implementation records
contain the exact qualification invocations; a skipped environment-selected
test is not equivalent to a pass.

### Frontend

With the Compose proxy running on port 8080:

```powershell
Set-Location frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Vite serves the development frontend at `http://127.0.0.1:5173` and proxies
`/api` plus WebSocket traffic to the loopback Compose proxy.

Run the frontend checks:

```powershell
npm test
npm run build
npm run test:e2e
```

The mocked Playwright suite does not require a backend. Real integration uses a
fresh Compose stack and the `SPELL_REAL_BACKEND`, `SPELL_E2E_BASE_URL`, and
`SPELL_E2E_TOKEN` variables described in [frontend/README.md](frontend/README.md).

### v0.10 Checks

After building `openbexi-spell-backend:local`, verify that the generated runner
and evidence remain current:

```powershell
docker run --rm --network none --entrypoint python `
  -v "${PWD}:/workspace:ro" -w /workspace `
  openbexi-spell-backend:local `
  -m scripts.generate_reference_runner_v10 --check

docker run --rm --network none --entrypoint python `
  -v "${PWD}:/workspace:ro" -w /workspace `
  openbexi-spell-backend:local `
  -m scripts.qualify_reference_examples_v10 --check
```

## Recorded Qualification

The v0.11 closeout record dated 2026-08-19 reports:

| Gate | Recorded result |
| --- | --- |
| Strengthened v0.10 backend gate | 442 passed; one dedicated-PostgreSQL guard skipped |
| Reference adapter | 195/195 examples and 257/257 variants passed |
| Focused v0.11 telecommand gate | 197 passed with no skips or failures |
| Full backend regression | 1,544 passed plus all selected PostgreSQL and Compose checks passed separately |
| Frontend | 112 unit tests and production build passed |
| Real browser | Chromium and Pixel 7 workflows passed 2/2 |
| Product image and documentation | Runtime, hygiene, compile, diff, and Markdown checks passed |

These are recorded mutable-worktree results, not v0.10 or v0.11 release
acceptance. Historical release/package validators for v0.5 through v0.9 are
designed to fail closed when the current root identifies itself as v0.11. See
[Test_and_Integration.md](Test_and_Integration.md) for the complete test and
integration record.

## Repository Layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI application, parser, IR, supervisor, runtime, services, migrations, and tests |
| `frontend/` | React/TypeScript operator console, development workspace, unit tests, and Playwright tests |
| `proxy/` | Nginx loopback ingress and multi-stage frontend image |
| `driver_host/` | Optional isolated synthetic driver lifecycle and observation service |
| `spell/` | Shared restricted-language and runtime support package |
| `procedures/` | Source-controlled bundled production procedures |
| `contracts/` | Versioned machine-readable behavior, compatibility, and gate contracts |
| `artifacts/` | Qualification, release, browser, SBOM, and reference-example evidence |
| `scripts/` | Build, qualification, audit, packaging, token, and evidence tools |
| `SPELL_DOCUMENTATION/` | Controlled next-generation requirements, architecture, security, web, and assurance specification |
| `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/` | Preserved documentation-generation source set |
| `tools/` | Standalone legacy SPELL Procedure Compliance Auditor and its own documentation |

The compliance auditor is a separate tool. Its usage, policies, cases, and
output schema are documented in [tools/README.md](tools/README.md); they do not
define the root project README.

## Documentation

- [PROJECT_ROADMAP.md](PROJECT_ROADMAP.md): product scope, release status, gates,
  guardrails, and future sequence.
- [VERSION_TIMELINE.md](VERSION_TIMELINE.md): evidence-qualified history through
  the v0.10 and v0.11 working-tree increments.
- [Test_and_Integration.md](Test_and_Integration.md): per-version test plans,
  commands, evidence, and exit decisions.
- [SPELL_DOCUMENTATION/README.md](SPELL_DOCUMENTATION/README.md): controlled
  next-generation design specification and document map.
- [SPELL_DOCUMENTATION/SOURCE_AUTHORITY.md](SPELL_DOCUMENTATION/SOURCE_AUTHORITY.md):
  reviewed source authority, precedence, and evidence hashes.
- [PROVENANCE.md](PROVENANCE.md): source, build, dependency, and release
  provenance records.
- [PROMPT_History.md](PROMPT_History.md): retained project prompt and decision
  history.

## Security And Operational Limits

- Keep `.env`, tokens, private keys, and mission data out of Git.
- Keep the public proxy bound to loopback unless a separately reviewed
  deployment architecture replaces the local Compose assumptions.
- Local token issuance is disabled by default and is not an authentication
  service for shared or production use.
- Arbitrary Python, imports, shell access, browser-to-driver access, generic
  database access, and configurable live command endpoints are outside the
  procedure execution contract.
- The documentation may support security-control implementation and assessment,
  but this software does not itself establish NIST SP 800-171 compliance.
- Any connection to a mission network, GCS, or spacecraft requires independent
  engineering, safety, security, governance, and operational authorization.

## License And Notices

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [PROVENANCE.md](PROVENANCE.md) for
the repository's license, notices, source authority, and attribution records.
