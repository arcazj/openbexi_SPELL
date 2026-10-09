# SPELL v0.19.1 Pre-Implementation

The owner authorized execution of release qualification and publication on
2026-10-09. The accepted predecessor is v0.19.0. This release packages the
already implemented isolated Python runtime and source-line debugger together
with the inherited local DSS product. Acceptance is pending all gates.

| Requirement | Scope and independent acceptance evidence |
| --- | --- |
| V191-SOURCE-001 | Explicit Python profile, exact captured UTF-8 source/digest, non-executing bounded metadata, complete 261-check/39-topic procedure output. |
| V191-ISOLATION-001 | Networkless, unprivileged child in a credential-free chroot; filesystem, process, output, CPU/memory/lifetime bounds and descendant cleanup on the actual runner. |
| V191-DEBUG-001 | Before-line entry/breakpoint stops, repeated loops, function Step/Step Over, temporary Run to Line, removal, signal pause and interruption of long calls. |
| V191-DURABILITY-001 | Source/request/generation binding, controller fencing, stale/malformed control rejection, worker loss, complete output persistence and success-only atomic checkpoint without replay. |
| V191-PROCEDURES-001 | Automatically inventory every procedure, embedded case and reference selection; declare inputs, operator actions, limits and exact outcomes, including Test Python and Test Python Core. |
| V191-DSS-001 | Full DSS delivery through the actual binary CCSDS command driver and Kafka telemetry, independently validated captures, all required fault scenarios and exact database/image/source bindings. |
| V191-UI-001 | Actual desktop/mobile breakpoint, Step, Step Over, Run to Line, reload and complete output; compact layout, keyboard and accessibility gates. |
| V191-RELEASE-001 | Frozen test catalog, candidate and final SQLite/PostgreSQL/Compose/frontend/documentation/tooling gates, seven image SBOMs/audits, soaks, four matching package builds and independent clean annotated-tag validation. |

The source reference inventory retains the accepted manuals' exact hashes.
Python debugger semantics were reviewed against GUI User Manual 2.4.4 sections
3.2.1, 3.2.4 and 5.8 (pages 11, 17 and 44-45), and Server Manual 2.4.4 executor
configuration (page 6). The native Python profile is separate from the closed
SPELL IR and does not establish full SPELL 2.4.4 conformance.

Line debugging covers the captured script's main thread. Evaluation, live-object
editing, SKIP/GOTO, background execution and replay are excluded. All pauses
count toward the job lifetime. Accepted v0.19.0 artifacts and evidence remain
immutable. This local simulator release grants no real-system or operational
authority. Missing cases, unexpected failures, unresolved mandatory skips or
High/Critical findings block acceptance and publication.
