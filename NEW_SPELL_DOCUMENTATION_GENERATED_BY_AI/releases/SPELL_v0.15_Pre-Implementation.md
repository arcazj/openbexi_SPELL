# SPELL v0.15 Local Shadow-Pilot Readiness Gate

The owner's 2026-10-01 request authorizes v0.15.0 implementation and publication.
`V15-GATE-0A PASS` covers the local synthetic read-only readiness workflow below.
Isolated implementation can proceed while earlier qualification completes;
integration, candidate activation and release require accepted v0.14.0 ancestry.
There is no authorized real pilot environment, mission workload or operational
reviewer. Software tests of independent review are not independent human or
operational acceptance.

## Reference And Compatibility

The reviewed Language Reference 2.4.4 section 4.2 (pages 36-38) and Driver
Development Manual 2.4.4 sections 5.1-5.2 (pages 17-19) govern the inherited
read-only observations. GUI User Manual 2.4.4 sections 5.7 and 7 (pages 43-44,
49-50) govern retained as-run evidence and monitoring. Server Manual 2.4.4
sections 1-2 (pages 4-5) establish context separation. All mandatory input hashes
are retained in the release policy. The new readiness workflow is a modern
local engineering facility, not an emulation of an undocumented legacy pilot
protocol.

## Authorized Work And Proof

| Identity | Required behavior | Acceptance evidence |
| --- | --- | --- |
| V15-PILOT-001 | Bounded read-only plan and complete differential report | Closed schema; one to eight unique catalog items, RAW/ENG, one to four repetitions; source hashes; every result retained; non-good observations never pass |
| V15-PILOT-002 | Durable identity, ownership, review and monitoring | Creator identity, revision-guarded operation UUIDs, independent administrator review, restart/readback, database failure, conflict and concurrency tests |
| V15-PILOT-003 | Incident response and rapid rollback | Incident permanently revokes readiness; explicit simulator/read-only rollback, retained actor/reason and audit history; no automatic restart or operational effect |
| V15-PILOT-004 | Backup and restore drill | Bounded canonical JSON plus digest; source/trace validation; new restore identity; restored records always read-only and never inherit approval |
| V15-PILOT-005 | Accessible readiness workspace and immutable release | Desktop/mobile keyboard/Axe workflow; fresh/prior/repeated/failed migration tests on SQLite/PostgreSQL; exact full regression, version-scoped source evidence, audits and four reproducible package builds |

Each plan has at most 32 comparison rows (64 underlying reads), a 10-second
local execution budget, and a 500-ms maximum comparison budget. A report is
eligible for local independent review only when every row is equivalent and
all budgets pass. The authenticated creator owns the record; a different
authenticated administrator may record review. This never changes execution
leases, driver permissions, telemetry routes or mission authority. Monitoring
reports counts, budget results, report hashes, state, revision and audit events.

Plans and reports are stored in new migration 0010 tables. Each mutation uses
a UUID and exact request hash, actor and revision. Repeated identical requests
return the durable result; conflicting reuse fails. Serial transaction fencing
prevents competing revisions from both changing a record. At most 512 local
pilot records and 128 audit events per record bound persistence.

Backup content is data-only with a 256-KiB bound, exact keys and canonical hash.
Restore revalidates plans and differential traces against current pinned
fixtures, creates a new record and records restore provenance. Approval is not
restored; rerun and a new independent review are required. No host path, network
endpoint, command credential or externally effective operation is accepted.

## Incident And Exit Procedure

The creator or local administrator records an incident reason, obtains the
authoritative read-only state, and uses rollback to retain an explicit simulator
fallback disposition. Review cannot reopen an incident or restored run. A new
run is required after investigation. Backup/restore drills verify evidence
recovery; they do not claim database disaster-recovery or availability SLOs.

Final acceptance is software-only at the independently validated annotated
v0.15.0 tag. Real legacy integration, supervised real pilots, production
identity, organizational governance, full SPELL language support, deployment
and operational authority remain separate outstanding gates.
