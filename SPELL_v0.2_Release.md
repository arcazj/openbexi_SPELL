# SPELL v0.2 Release Record

## Release Decision

SPELL v0.2 is accepted as a local, simulator-only developer release with the
exceptions recorded below. It is not approved for a shared deployment, a live
Ground Control System, a spacecraft connection, operational commanding, or
mission use.

| Field | Value |
| --- | --- |
| Version | 0.2.0 |
| Release name | Simulator Vertical Slice |
| Date | 2026-07-12 |
| Status | Accepted for local simulator development with exceptions |
| Operational authorization | None |

## Delivered Scope

- Python 3.13 FastAPI control plane with one spawned worker per execution.
- Restricted, non-executing AST procedure parser for `Log`, `Telemetry`,
  `Wait`, and `Prompt`.
- Durable idempotent REST mutations with revision guards.
- Ordered, authenticated downstream WebSocket replay and snapshot resync.
- Atomic command, event, prompt, checkpoint, audit, and execution persistence.
- SQLite development tests and PostgreSQL 18 target integration tests.
- Running, paused, and prompting crash recovery from committed checkpoints.
- React and strict TypeScript 2D console with desktop and mobile layouts.
- Real disconnect interlocks, crash recovery, abort, prompt, and as-run flows.
- CycloneDX dependency inventories and clean-room provenance record.

## Verification Results

All commands were run on 2026-07-12 from Windows build 26200 on an Intel
Core i7-9700 with 31.8 GiB RAM. The runtime used Docker 26.1.1, Python 3.13,
PostgreSQL 18, Node 24.13.0, npm 11.6.2, and Playwright Chromium desktop and
mobile projects.

| Gate | Result |
| --- | --- |
| Backend, SQLite, Docker network disabled | 18 passed in 15.07 s |
| Backend, dedicated PostgreSQL `spell_test` database | 18 passed in 15.73 s |
| Frontend Vitest | 7 passed |
| Strict TypeScript and Vite production build | Pass |
| Real-backend Playwright, desktop and mobile | 8 passed in 18.6 s |
| Axe serious or critical findings | 0 in both browser projects |
| Browser requests outside loopback during real workflows | 0 |
| `npm audit --audit-level=low` | 0 known vulnerabilities |
| Exact-pinned Python `pip-audit` | 5 accepted Starlette residuals |

The Playwright flow exercises keyboard activation for pause and resume, prompt
crash and recovery, report display, safe abort, responsive layout, and actual
offline/reconnect resynchronization. The complete acceptance disposition is in
[`Test_and_Integration.md`](Test_and_Integration.md).

## Evidence

- [Desktop as-run report](artifacts/v0.2/desktop-as-run-report.png)
- [Mobile recovered prompt](artifacts/v0.2/mobile-recovered-prompt.png)
- [Python CycloneDX SBOM](artifacts/v0.2/python-sbom.cdx.json)
- [Node CycloneDX SBOM](artifacts/v0.2/node-sbom.cdx.json)
- [Provenance and dependency review](PROVENANCE.md)

## Accepted Exceptions

- The provisional latency, load, throughput, 10,000-event resync, and two-hour
  soak targets were not executed. They remain non-operational engineering work.
- The backend acceptance suite passed with Docker networking disabled, and the
  real browser suite observed only loopback requests. A single full browser
  workflow with container outbound networking disabled was not run.
- Axe checks and keyboard activation passed, but no separate manual end-to-end
  keyboard-only review was recorded.
- Compose binds published ports to loopback but does not block container
  outbound networking.
- Python dependencies are exactly version-pinned but artifact hashes are not
  locked. The Node lock includes registry integrity hashes.
- Development authentication is caller-asserted and suitable only for the
  loopback simulator. Production authentication and authorization are absent.
- The required legacy Development Environment manual is still missing.

## Security Residuals

The Python audit reports five advisories against Starlette 0.49.3:
[PYSEC-2026-161](https://osv.dev/vulnerability/PYSEC-2026-161),
[PYSEC-2026-248](https://osv.dev/vulnerability/PYSEC-2026-248),
[PYSEC-2026-249](https://osv.dev/vulnerability/PYSEC-2026-249),
[GHSA-wqp7-x3pw-xc5r](https://github.com/advisories/GHSA-wqp7-x3pw-xc5r), and
[GHSA-x746-7m8f-x49c](https://github.com/advisories/GHSA-x746-7m8f-x49c).

As of 2026-07-12, their fixed Starlette versions are outside the supported
range of the selected FastAPI release. Trusted-host validation, loopback binds,
and non-use of the affected static-file, form, and endpoint-class surfaces
reduce exposure for this local slice; they do not resolve the advisories. Any
shared or production deployment is blocked pending re-evaluation and upgrade.

## Deferred Product Scope

Version 0.2 does not provide a driver host, GCS or spacecraft adapter, full
SPELL language compatibility, procedure authoring environment, high
availability, production identity, operational workload qualification, or
operational authorization. Each requires a separately approved version plan
and test gate.
