# SPELL v0.3 Release Record

## Release Decision

SPELL v0.3 is accepted as a local, simulator-only engineering release. It is
not approved for a shared deployment, live Ground Control System, spacecraft
connection, operational command, or mission use.

| Field | Value |
| --- | --- |
| Version | 0.3.0 |
| Release name | Simulator Hardening and Language Foundation |
| Date | 2026-07-16 |
| Status | Accepted; all v0.3 engineering gates passed |
| License | Apache License 2.0 |
| Baseline | `v0.2.0` |
| Operational authorization | None |

## Delivered Scope

- Ordered, idempotent migrations for fresh and populated v0.2 SQLite and
  PostgreSQL stores, including visible rollback on controlled failure.
- Strict HS256 JWT validation with issuer, audience, subject, role, lifetime,
  expiry, not-before, issued-at, and token identifier checks.
- Server-enforced viewer/operator/admin authorization; caller role and actor
  headers cannot elevate identity.
- CLI-only, disabled-by-default, loopback-gated short-lived development token
  issuance and session-only browser token storage.
- Loopback Nginx ingress, security headers, un-published backend/PostgreSQL, and
  an internal network that blocks backend internet access.
- Typed `bool`, `int`, `float`, and `str` variables; safe expressions;
  deterministic conditions; bounded literal `range` loops; bounded,
  non-recursive local calls; and data-only versioned IR.
- Pre-allocation source-byte and catalog limits, bounded AST shape and expansion,
  bounded serialized IR, exact source/hash identity, definite assignment, and
  protected compiler/runtime names.
- Stable, non-echoing diagnostics for invalid UTF-8, unpaired Unicode
  surrogates, NUL characters, unsafe syntax, and excessive complexity.
- Atomic persistence and recovery of variable state, control position, prompts,
  effects, events, and worker generation.
- Durable terminal settlement of every accepted command across normal worker
  completion, consumer failure, bounded shutdown, and supervisor restart.
- Transient validation REST and console workflows with normalized IR, variable
  inventory, SHA-256, and structured diagnostics.
- Responsive 2D console workflows for validation, execution, pause/resume,
  prompt, abort, simulated crash/recovery, disconnect/resync, and as-run review.
- Hash-locked Python installation, npm integrity locking, zero-vulnerability
  audits, separate backend/proxy/frontend image SBOMs, and a deterministic
  source release package.
- Established WebSocket expiry at the JWT deadline and client-side token/socket
  teardown on logout or authentication close code `4401`.
- Immutable static migrations and source-fingerprint-bound qualification and
  packaging evidence.

## Verification Summary

| Gate | Result |
| --- | --- |
| SQLite backend with Docker networking disabled | 112 passed, 1 PostgreSQL-only skip |
| PostgreSQL 18.4 backend and migration suite | 113 passed |
| Frontend unit tests and production build | 13 passed; build passed |
| Desktop/mobile Playwright | 16 passed: 8 mocked and 8 signed-token real-backend |
| Release composer/package tooling | 26 passed |
| Serious/critical Axe results in real flows | 0 |
| Python/Node dependency vulnerabilities | 0 |
| REST command p95 | 12.452 ms for 100 durable mutations and 100 identity-preserving retries |
| 10,000-event replay | 0.13462 s, exact order and payloads |
| Native browser stream | Two Chromium processes, each 100.022 events/s over 59.9967 s with 6,002 exact sequences |
| Browser producer | 100.012 events/s over 60.002974 s; schedule lag 0.91 ms p95 and 7.336 ms max |
| Supporting EventHub fan-out | 100.013 events/s for 60.003304 s, no loss/duplicate/overflow |
| Ten-minute soak | 12,001 exact events at 20.002 events/s for 600.001721 s |
| Soak schedule and memory | 0.548 ms p95/2.653 ms max lag; 1.375 MiB growth; 0.188 MiB/min slope |
| Reproducible package | Two immutable-input builds plus a current-context drift check with identical SHA-256 |

The complete test mapping, environment, and measurement boundaries are in
[`Test_and_Integration.md`](Test_and_Integration.md). Performance results are
local engineering measurements, not operational SLOs.

## Evidence

- [Combined qualification index](artifacts/v0.3/qualification.json)
- [Quick qualification component](artifacts/v0.3/qualification-quick.json)
- [Soak qualification component](artifacts/v0.3/qualification-soak.json)
- [Native browser stream component](artifacts/v0.3/qualification-browser-stream.json)
- Typed-language validation console screenshot (not retained as a versioned artifact)
- [Desktop as-run report](artifacts/v0.2/desktop-as-run-report.png)
- [Mobile recovered prompt](artifacts/v0.2/mobile-recovered-prompt.png)
- [Session access gate](artifacts/v0.3/session-access.png)
- [Backend image SBOM](artifacts/sbom/backend.cdx.json)
- [Proxy runtime image SBOM](artifacts/sbom/proxy.cdx.json)
- [Frontend builder image SBOM](artifacts/sbom/frontend.cdx.json)
- [SBOM checksum manifest](artifacts/sbom/SHA256SUMS)
- [Provenance and dependency review](PROVENANCE.md)

The release archive is `artifacts/openbexi-spell-v0.3.tar.gz`; its external
`.sha256` sidecar records the final digest without creating a self-referential
package manifest.

## Measurement Boundaries

- `V03-PERF-003` uses two independent Chromium processes, native WebSocket
  connections, and a loopback Uvicorn/FastAPI server. Each browser independently
  measures data-delivery cadence and exact sequence integrity. Production starts
  only after both clients receive the server keepalive emitted after subscription
  and replay; the composer verifies that readiness precedes first data. The
  producer persists events off the WebSocket transport loop, matching the
  application worker-consumer boundary. `V03-PERF-003A` is a separate supporting
  EventHub gate and is not used as a substitute for browser evidence.
- Quick and soak performance use runtime-local SQLite on container `tmpfs` with
  outbound networking disabled. PostgreSQL correctness and migrations are
  covered by the complete integration suite, not by those local latency values.
- The composed schema `1.1` report validates quick, soak, and browser component
  identities, rates, durations, integrity, and the shared source fingerprint
  `454d79fdbadc6d5076f415fa9bc1d03dd12552511e58c59330ad5315d50eb734`.
- SBOM tooling is fixed to Docker SBOM 0.6.0 with Syft v0.43.0. It reported
  relationship-conversion warnings while producing valid component inventories
  and checksums. Dependency audits completed separately with no known product
  dependency vulnerabilities. The fixed `pip-audit` bootstrap's own transitive
  installation dependencies are not hash-locked; this tooling-only limitation is
  recorded in `PROVENANCE.md`.
- Only the Windows 11 host with Linux containers described in the test record
  was used for final release evidence. Native Linux-host and additional browser
  claims are deferred.

## Deferred Scope

Version 0.3 does not provide full legacy SPELL compatibility, arbitrary Python
execution, persistent authoring, a development IDE, driver hosts, GCS or
spacecraft adapters, externally effective telecommands, high availability,
Kubernetes, an operational identity provider, or operational accreditation.
Each requires a separately approved version scope and pre-implementation test
gate.
