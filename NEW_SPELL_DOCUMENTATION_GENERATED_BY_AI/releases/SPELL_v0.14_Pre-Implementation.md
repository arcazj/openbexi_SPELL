# SPELL v0.14 Read-Only Adapter Tranche Gate

The owner's 2026-10-01 authorization covers implementation and publication of
v0.13.0, v0.14.0 and v0.15.0. `V14-GATE-0A PASS` authorizes only the local
synthetic GetTM adapter tranche below. It uses the accepted v0.12 immutable
observation fixtures, requires no remote endpoint or credential, and has no
mutation or command interface. Work may proceed in an isolated worktree while
v0.13 qualification runs; candidate freeze, integration and release acceptance
require the accepted v0.13.0 tag as ancestor. No preceding gate is bypassed.

## Source And Compatibility Contract

Language Reference 2.4.4 section 4.2, pages 36-38, and Driver Development Manual
2.4.4 sections 5.1-5.2, pages 17-19, define current/next acquisition, RAW/ENG,
Timeout, extended metadata and failure behavior. Their exact hashes, alongside
all mandatory references, remain bound in the release policy.

This capability translates GetTM acquisition into authenticated GET-only REST
over pinned synthetic captures. Methods are profile discovery, catalog, current
or next GetTM read, and two-source shadow comparison. Modifiers are
`value_format=RAW|ENG`, `wait`, `after`, `timeout_ms`, and `extended`. Current
reads use the capture's final logical clock. Next reads require a source-,
epoch- and digest-bound cursor; Timeout is a finite integer millisecond budget
in recorded logical time, at most 60,000 ms. There is no wall-clock wait or
network stream. Extended returns immutable typed metadata, not a Python object
with arbitrary methods; repeating the GET explicitly refreshes the observation.

Unlike the manuals' permissive ignored modifiers, unknown options and Timeout
without Wait are rejected. Only exact catalog identifiers are accepted;
description-prefixed aliases, arbitrary time expressions and GCS-specific
configuration are unsupported. All non-good quality/validity, stale, absent,
unsupported, disconnected, gap, cursor and timeout outcomes yield no value.
This is an explicit modern compatibility boundary, not full GetTM language or
legacy driver conformance. Existing procedure IR behavior is unchanged.

## Capability And Proof

| Identity | Required behavior | Acceptance evidence |
| --- | --- | --- |
| V14-TM-001 | Closed GET-only profile, pinned source identities and bounded modifiers | Schema, source, authorization, unknown option and mutation rejection |
| V14-TM-002 | Typed RAW/ENG and extended immutable current/next reads | UInt64, refresh, cursor, logical timeout, quality, gap and disconnect matrix |
| V14-TM-003 | Differential trace and explicit simulator fallback | Both source identities, field differences, no non-good equivalence, failed-source recovery |
| V14-TM-004 | Bounded capacity and accessible console | 128 reads with eight callers within 30 seconds, desktop/mobile keyboard and Axe workflows |
| V14-TM-005 | Immutable version-scoped release | Exact full SQLite/PostgreSQL/Compose catalogs, audits, image profile probes, candidate gate and four deterministic builds |

The capability has viewer read permission, no driver credential, at most 128
catalog items and 4,096 samples per existing capture, pages of at most 256, and
one bounded item per request. It does not accept user-supplied files, endpoints,
capture data, telemetry injection, command configuration or arbitrary calls.
Selecting the simulator is an explicit per-request fallback, never a silent
substitution for a failed reference observation. No global route changes occur.

## Exit And Rollback

The annotated v0.14.0 tag requires source-bound proof after v0.13 acceptance.
Replay faults stop the read with an explicit outcome; the console clears old
values and permits the user to select the simulator. This tranche does not
authorize another adapter service, real legacy environment, deployment, GCS,
spacecraft connection or operational pilot.
