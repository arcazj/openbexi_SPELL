# SPELL v0.12 Read-Only Observation Gate

## Owner Direction And Entry

The 2026-09-30 owner request authorizes completion and GitHub publication of
v0.11.1 followed by v0.12. `V12-GATE-0A PASS` applies to the local isolated
replay profile below, after accepted documentation tag `v0.11.1` and runtime
tag `v0.11.0`. The owner supplied no legacy endpoint, capture, or credential.
The default source is therefore an independently authored synthetic replay of
the documented 2.4.4 telemetry model. An actual legacy-system comparison remains
unqualified until source captures or an isolated test environment are supplied.

## Reference And Compatibility Decisions

All eight source inputs remain pinned by SHA-256 in the v0.12 release policy.
The relevant Driver Development Manual 2.4.4 sections are 4.1 (page 12),
5.1 and 5.2.1 (pages 17-19), and 5.5.2 (page 34). The Language Reference
2.4.4 sections are 4.2 (pages 36-38), 4.8 (pages 59-67), 4.11 (page 69),
and 4.21 (pages 102-103). Server context concepts and the inherited operator
and development workflows retain their existing manual authority.

- Raw and engineering values, acquisition time, validity, quality, unit, and
  source identity remain separate typed fields.
- Legacy booleans cannot turn unknown quality into good quality.
- Unsupported fields, types, services, and modifiers receive explicit outcomes;
  the manual's suggestion to ignore unsupported modifiers is not adopted.
- Read-only replay has a recorded logical clock. It never represents archived
  data as current spacecraft telemetry or authorizes a procedure effect.
- Missing samples, gaps, stale values, disconnects, and incompatible epochs
  remain visible. Recovery is an explicit snapshot or simulator selection.
- Catalog, resource, and limit reads are bounded; arbitrary queries, command
  methods, credentials, endpoint configuration, and network dispatch are absent.
- No legacy implementation is imported, executed, compiled, or packaged.

## Authorized Work And Acceptance

| Identity | Scope | Required evidence |
| --- | --- | --- |
| V12-OBS-001 | Strict bounded capture translator into existing typed scalar and quality concepts | Valid fixtures plus malformed, duplicate, overflow, invalid UTF-8, missing, unsupported, and type-confusion cases |
| V12-OBS-002 | Immutable catalog, snapshot, current/next sample, limits and resource reads | Raw/engineering distinction, lossless uint64, acquisition time, freshness, validity, quality, unavailable and unsupported outcomes |
| V12-OBS-003 | Source/epoch/digest-bound cursor replay and explicit simulator fallback | Gap, future cursor, wrong source, disconnect, snapshot recovery, and rollback tests |
| V12-OBS-004 | Independent golden comparison and bounded compatibility report | Equivalent, different, indeterminate and unsupported classifications; independently supplied oracle values |
| V12-OBS-005 | Authenticated GET-only API and read-only operator inspection | Viewer access, no unauthenticated access, mutation rejection, source switching, keyboard/mobile and real browser checks |
| V12-OBS-006 | Isolated offline qualification and release | Network-disabled capture checks, full SQLite/PostgreSQL/driver regression, all environment selections, frontend/build/browser, source hygiene, four SBOMs, dependency audits, repeated package builds, strict tag validation |

The product version is `0.12.0`. Existing parser and procedure semantics remain
bounded by their inherited contracts; this release does not claim full SPELL
2.4.4 compatibility. No new database migration is needed for immutable replay.
Both sources and every comparison are labeled synthetic and read-only.

## Exit

Freeze source and test identities before final qualification. Record every
executed gate and input hash under `artifacts/v0.12/`; every selected environment
test must execute, and no unresolved failure or skip may be accepted. Preserve
all prior tags and evidence. Publish and independently validate the annotated
`v0.12.0` tag only after the package reproduces from clean source exports.
