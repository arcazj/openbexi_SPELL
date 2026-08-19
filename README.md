# OpenBEXI SPELL

OpenBEXI SPELL is a local, simulator-only environment for developing,
validating, and executing bounded satellite procedures. It combines a FastAPI
control plane, isolated procedure workers, PostgreSQL persistence, a React and
TypeScript operator console, and deterministic simulator services.

Every document under `SPELL_DOCUMENTATION/` is a required source reference for
future SPELL planning, coding, testing, and delivery. The AI-generated
documentation translates those sources into controlled modern requirements and
designs; it does not independently replace or weaken the documented behavior.
Conflicts and deliberate safety-driven deviations require explicit traceability,
decision, and test evidence.

The current source tree reports product version `0.10.0` and is the reconstructed
v0.10 release candidate. Its accepted predecessor is **v0.9.0** at annotated
tag `v0.9.0`. v0.10 becomes an accepted engineering release only when the
committed qualification and package evidence pass the version-scoped validator
and annotated tag `v0.10.0` is present. v0.11 is planned and is not included in
this source tree.

> **Safety boundary:** this repository does not provide a live Ground Control
> System (GCS) connection, spacecraft command path, production deployment
> approval, or compliance determination. Reference examples involving commands
> execute only through deterministic in-memory adaptations with live dispatch
> disabled.

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
| v0.9 | Web-based SPELL development environment | Accepted at `v0.9.0`; predecessor to this candidate |
| v0.10 | SPELL 2.4.4 reference example adapter | Reconstructed release candidate; acceptance requires validated tag `v0.10.0` |
| v0.11 | Simulator telecommand semantics | Planned next increment; no v0.11 code or release claim in this tree |

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

   A healthy response reports version `0.10.0`, mode `simulator-only`, and
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
- [SPELL_v0.10_Implementation.md](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.10_Implementation.md)

## Planned v0.11 Boundary

v0.11 is the next proposed simulator-only increment for catalog-backed
`BuildTC` and `Send` semantics. It must start from the accepted `v0.10.0` tag,
re-evaluate every mandatory source under `SPELL_DOCUMENTATION/`, establish a
separate entry gate, and preserve distinct construction, authorization,
transport, loading, release, execution, verification, certainty, recovery, and
reconciliation facts. A possible or unknown effect must never be resent
automatically.

This v0.10 tree deliberately contains no `contracts/v11`, v0.11 IR, command
runtime, v0.11 procedure, package, evidence, or release record. Planning in
[PROJECT_ROADMAP.md](PROJECT_ROADMAP.md) is not implementation authorization.

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

## Release Qualification

v0.10 uses version-specific release controls in `scripts/release_v10.py` and
the associated create, validate, and reproducible-package entry points. The
gate requires the 195-example and 257-variant contracts, complete backend
regression, explicit execution of every PostgreSQL and Docker-selected test,
112 frontend tests, a production build, two real-browser projects, the product
image hygiene probe, documentation validation, and deterministic packaging.
No unresolved skip or accepted exception is permitted.

The canonical machine record is `artifacts/v0.10/release-qualification.json`
once generated from one committed source state. Package and tag validation are
separate final gates. See [Test_and_Integration.md](Test_and_Integration.md)
for the complete commands and result boundaries.

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
| `SPELL_DOCUMENTATION/` | Mandatory source-reference manuals for future SPELL coding and delivery; legacy source archives remain read-only evidence |
| `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/` | Controlled AI-generated interpretation: requirements, architecture, security, web, assurance, and version-specific release records |
| `tools/` | Standalone legacy SPELL Procedure Compliance Auditor and its own documentation |

The compliance auditor is a separate tool. Its usage, policies, cases, and
output schema are documented in [tools/README.md](tools/README.md); they do not
define the root project README.

## Documentation

The manuals under `SPELL_DOCUMENTATION/` are the forward source-reference
baseline. Generated documents and implementation artifacts must trace relevant
behavior, intentional exclusions, and safety strengthening back to them.

- [PROJECT_ROADMAP.md](PROJECT_ROADMAP.md): product scope, release status, gates,
  guardrails, and future sequence.
- [VERSION_TIMELINE.md](VERSION_TIMELINE.md): evidence-qualified history through
  the v0.10 release candidate and the planned v0.11 boundary.
- [Test_and_Integration.md](Test_and_Integration.md): per-version test plans,
  commands, evidence, and exit decisions.
- [NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md):
  AI-generated next-generation design specification and document map.
- [NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/SOURCE_AUTHORITY.md](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/SOURCE_AUTHORITY.md):
  reviewed source authority, precedence, and evidence hashes.
- [NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md):
  index of version-specific planning, gate, implementation, and release records.
- [SPELL - Language Reference - 2.4.4.pdf](SPELL_DOCUMENTATION/SPELL%20-%20Language%20Reference%20-%202.4.4.pdf):
  primary reference for language syntax and procedure-visible behavior.
- [SPELL - Driver Development Manual - 2.4.4.pdf](SPELL_DOCUMENTATION/SPELL%20-%20Driver%20Development%20Manual%20-%202.4.4.pdf):
  primary reference for driver services and lifecycle concepts.
- [SPELL - Server Manual - 2.4.4.pdf](SPELL_DOCUMENTATION/SPELL%20-%20Server%20Manual%20-%202.4.4.pdf):
  source reference for server, context, executor, and configuration concepts.
- [SPELL - GUI User Manual - 2.4.4.pdf](SPELL_DOCUMENTATION/SPELL%20-%20GUI%20User%20Manual%20-%202.4.4.pdf):
  source reference for operator workflows and visible behavior.
- [SPELL - Development Environment Manual - 2.4.4.pdf](SPELL_DOCUMENTATION/SPELL%20-%20Development%20Environment%20Manual%20-%202.4.4.pdf):
  source reference for authoring and development workflows.
- [SPELL_DOCUMENTATION/SPELL_Language_Manual.pdf](SPELL_DOCUMENTATION/SPELL_Language_Manual.pdf):
  supplementary earlier SPELL language manual.
- [SPELL_DOCUMENTATION/SPELL_DEV_Manual.pdf](SPELL_DOCUMENTATION/SPELL_DEV_Manual.pdf):
  supplementary earlier SPELL development environment manual.
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
