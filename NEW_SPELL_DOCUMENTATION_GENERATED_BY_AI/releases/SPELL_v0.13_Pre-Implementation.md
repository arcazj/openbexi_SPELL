# SPELL v0.13 Procedure Control Gate

## Authority And Environment

The owner's 2026-10-01 request to execute and publish v013.0, v014.0 and v15.0
is interpreted as the roadmap sequence v0.13.0, v0.14.0 and v0.15.0.
Existing approval to complete and publish persists. No legacy endpoint or
credential was supplied. `V13-GATE-0A PASS` authorizes the bounded local
synthetic procedure-control profile below, after accepted `v0.12.0`.
Real legacy integration, deployment, mission control, and full language
compatibility remain outside this profile. Later releases require their own
recorded capability contracts and acceptance evidence.

## Source Review And Compatibility

All eight mandatory inputs are hash-bound in the release policy. Reviewed
GUI User Manual 2.4.4 sections 5.1-5.3 (pages 38-39), 5.7 (pages 43-44),
and 7 (pages 49-50) define execution state, control, as-run records and
monitoring. Server Manual 2.4.4 sections 1-2 (pages 4-5) establish context
separation. Driver Development Manual 2.4.4 sections 3.4, 4.1 and 5.1-5.2
(pages 10, 12, 17-19) define explicit failures and bounded driver services.
Language Reference 2.4.4 section 4.2 (pages 36-38) remains the observation
authority inherited from v0.12.

This release adapts documented Run, Step, Pause and Abort operations to the
existing local execution engine. It does not implement the legacy TCP protocol.
`RETURN_TO_READ_ONLY` requests the existing safe STOP operation and reports
read-only completion only after authoritative terminal settlement. A stopped
execution cannot resume through this adapter. Other legacy commands, arbitrary
targets, background dispatch, GCS credentials and remote endpoints are absent.
Actor, lease, revision and session checks strengthen the old GUI model.

## Authorized Packages And Proof

| Identity | Required behavior | Acceptance evidence |
| --- | --- | --- |
| V13-CTL-001 | Closed typed control profile, simulator context and source-digest binding | Contract, malformed/unknown fields, wrong source/context and role tests |
| V13-CTL-002 | Fenced durable commands through the existing supervisor | Run/step/pause/abort, stable operation ID, actor/reason, duplicate and conflicting retry tests |
| V13-CTL-003 | Authoritative readback and rollback | Reconnect/restart, competing controllers, stale lease/revision, rejected state, settlement and read-only rollback matrix |
| V13-CTL-004 | Accessible operator controls and honest status | Unit tests and desktop/mobile browser workflow with keyboard, containment and Axe checks |
| V13-CTL-005 | Immutable release qualification | Full SQLite/PostgreSQL/Compose regression, source-bound exact catalogs, four image SBOMs/audits, inherited examples, soak and four reproduced package builds |

Commands use the existing durable command, event, audit and controller-lease
tables. No new migration or independent in-memory command ledger is introduced.
Database failure aborts acceptance; worker loss and restart retain the existing
fencing and terminal reconciliation rules. API retries look up the durable
operation and never automatically issue a replacement command.

## Exit And Rollback

Freeze source and the exact test catalog before qualification. Validate all
raw evidence independently, including resolution of environment-selected tests.
The committed candidate evidence is the Gate 0B input; acceptance requires the
validated annotated `v0.13.0` tag and an independent clean tagged checkout.
Preserve every predecessor tag and artifact. Leave the verified loopback stack
running. Local software acceptance does not qualify a real legacy environment.
