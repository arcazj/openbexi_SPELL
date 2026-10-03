# SPELL v0.19 Observation-To-Command Workflow Gate

The owner authorized `EXECUTE AND COMMIT v0.19` on 2026-10-03, against the
[project roadmap](../../PROJECT_ROADMAP.md). This entry gate precedes product
edits. The accepted predecessor is `v0.18.0`, release commit
`8e9a252db7860cee8b4d5f291ed1d803d8bc3b48`. Standing delivery authorization
includes qualification, documentation, commit, push and release publication.

## Scope And Proof

| Identity | Required behavior | Required proof |
| --- | --- | --- |
| V19-IR-001 | Closed IR 0.19 combines existing bounded GetTM/Verify/WaitFor with native scalar expressions, Prompt/Display and BuildTC/Send | Parser and real worker composition, exact types/indexes/guards, malformed IR and source non-execution; prior IR contracts unchanged |
| V19-RUNTIME-001 | Supervisor-authoritative observation results control command branches | Durable exact request/result, full typed variables and effects; independent command confirmation, immutable dependencies, leases/generations and guards; missing/stale/invalid quality and false/indeterminate outcomes cannot masquerade as success |
| V19-RECOVERY-001 | Restart, cancellation and navigation preserve observation and command truth | NEXT anchors/deadlines, first-result replay, crash before/after settlement/intent, forged/late messages, abort/timeout races and no automatic resend; backward jumps and unresolved-service bypass fail closed |
| V19-RUNNER-001 | Reference runner adds the currently supported observation-to-command profile | Preserve all 128 inherited cases/source hashes, 195 adaptations and 257 variants; independent expected results and actual worker/service proof, distinguished from full manual support |
| V19-PROCEDURES-001 | Add runnable observation-to-command testing procedures under procedures/ | At least three new catalog procedures with inputs/outcomes documented and actual runtime tests; positive decision, no-command decision and failure/wait paths |
| V19-AUTHORING-001 | v0.19 authoring, checks, completion, highlighting, bundles and promotion agree | Add explicit v19 project/profile binding through checks and independent bundle rebuild/revalidation; preserve the older profile; distinct review identities; real author-to-promoted-execution browser workflow |
| V19-DOC-001 | All affected current documentation describes the exact bounded product | Concise README, guides, compatibility, roadmap, history, provenance and release summaries; complete tracked-Markdown rendering/link checks |
| V19-RELEASE-001 | Independently qualified local simulator release | Exact frozen catalog and candidate; full SQLite/PostgreSQL/Compose, frontend/build/browser, language, replay/soaks, image/SBOM/audits; four matching package builds across two exports and clean-tag validation |

## Supported Contract And Decisions

The workflow reads telemetry, evaluates a condition, waits, obtains a native
operator answer, takes an explicit branch and requests a simulator command.
The existing target-based observation dialect is retained. It is an explicit
bounded adaptation; native GetTM/Verify return objects and the complete manual
modifier set remain for the later full observation milestone.

- GetTM assigns the declared exact scalar only on OK. Other outcomes fail the
  step without advancing or leaving a fabricated successful reading.
  The new profile requires supervisor-validated VALID/GOOD/FRESH/COMPLETE
  evidence and the expected policy revision. This deliberately strengthens
  v0.19 admission; older observation profiles retain their accepted semantics.
- Verify overwrites its declared string target with the exact terminal outcome.
  Branches compare explicitly with `"TRUE"`; a nonempty outcome string is not
  proof that verification succeeded.
- WaitFor advances only on SATISFIED. Cancellation, timeout and indeterminate
  data retain their distinct outcomes and cannot produce later command intent.
- Freshness and quality are checked at observation evaluation time. Committed
  values are snapshots. Prompt or WaitFor does not refresh an earlier value,
  and Send does not provide live freshness revalidation. A new decision needs
  a new read/evaluation when fresh data is required.
- Service identifiers and command operands remain literal; existing immutable
  BuildTC items and closed modifiers retain their bounds. Native Prompt remains
  separate from required digest-bound command confirmation.
- Bind observation checkpoints to the durable request/result, exact variables
  and exact effect. Preserve NEXT watermarks and deadlines across restart;
  reject stale generations, forged settlement and unresolved-service bypass.
- Reject SKIP and GOTO in IR 0.19, including source Goto: observation request
  identities are bound to execution plus source step. Navigation must not
  replay an old reading or bypass an unresolved read/wait/decision. RUN, STEP,
  STEP_OVER, RUN-to-line, PAUSE and ABORT retain execution of intervening steps.
  Bounded compile-time loop expansion retains distinct indexes. Older profiles
  retain their accepted navigation contract.
- Preserve strict toolchain and review binding for development bundles. An
  older bundle requiring rebuild/review is rejected explicitly; it is not
  silently promoted under the new profile.

Collections, general functions/returns, other data/file/environment mixtures,
dynamic command operands, live drivers, full SPELL 2.4.4 support and operational
authorization remain outside this local release. Preserve compact manual UI
and automatic local access at `http://127.0.0.1:8080/`.

## Mandatory Source References

All eight inherited source inputs remain hash-bound in the release policy.
The primary Language Reference 2.4.4 is
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`:
sections 4.2-4.3, pages 36-47 cover GetTM/Verify; sections 4.4-4.5, pages 47-55
cover commands; section 4.6, pages 55-59 covers WaitFor; pages 17-23, 68 and
70-72 cover core flow, Display and Prompt.

Driver Manual pages 12-13, 17-19 and 25 govern typed items, CURRENT/NEXT,
quality/time, timeout and cleanup. Server concepts govern execution ownership,
service lifecycle and recovery. GUI Manual pages 19, 39-40 and 48 govern compact
prompts and connection protection. Development Environment Manual pages 21-28
and 52-55 govern project metadata, editor assistance and nonexecuting checks.
The older supplementary language manual pages 31-37, 44-46 and 68 provide
historical context; the primary 2.4.4 reference resolves version differences.
In particular, supplementary page 46 describes PAUSE/RUN/SKIP for WaitFor,
whereas primary pages 57-58 distinguish INTERRUPT, STEP, SKIP and PAUSE. The
existing bounded wait lifecycle is retained here; full native interruption
semantics remain for v0.26 and are not inferred from the older manual.
Supplied PDFs and archives remain read-only and excluded from product packages.

## Gate And Acceptance

`scripts/validate_v19_gate.py` must report `V19-GATE-0A PASS` before product
edits. This authorizes implementation of the scoped requirements; it
claims no passing product test or release acceptance. Candidate and final
evidence must be produced from clean committed source. Only independently
validated committed evidence and annotated `v0.19.0` can establish acceptance.

## Owner Amendment: Docker DSS Before Delivery

The owner added the supplied DSS architecture and instructions 10-11 on
2026-10-03 before v0.19 delivery. This is a mandatory dependency of this release
and every later SPELL delivery. Earlier qualification attempts do not satisfy it.

| Requirement | Required result |
| --- | --- |
| V19-DSS-001 | Docker DSS owns one persisted GENERIC satellite bus, core and payload state, with a versioned deterministic dynamics engine and compact control/telemetry pages. |
| V19-DATABASE-001 | One revision/digest-bound satellite database defines every command, argument and telemetry item needed by the complete procedure-validation suite. |
| V19-CMD-001 | Actual binary CCSDS TC over the DSS port 3080 interface; resolve database operands and preserve procedure/execution/command correlation, acceptance, execution, rejection, timeout and uncertainty. |
| V19-TLM-001 | DSS publishes binary CCSDS telemetry through Kafka; the actual TLM driver decodes values, units, time, validity, quality, freshness, source epochs, sequences and database bindings. Command effects are observed through this path. |
| V19-SCENARIOS-001 | Automatically inventory all procedures, embedded cases, reference choices and variants; declare inputs, answers, initial state, expected outcomes and time bounds; isolate independent cases. |
| V19-DSS-DELIVERY-001 | Every required case and applicable test passes its declared outcome against actual CMD/TLM and DSS. Missing/unexecuted cases, unexpected failures/timeouts, unexplained skips or unavailable services block delivery. |

Produce a version-specific report binding the exact source commit, DSS and
engine versions, database revision/digest, exact inventory, individual outcomes,
logs, correlated raw TC/TM evidence, scenarios and reproduction commands.
Expected negative outcomes must be proved explicitly. Preserve visible language
gaps and the distinction between adaptations and original-language support.

The supplied architecture is implemented as DSS TC ingress on TCP 3080 and
DSS binary TM broadcast through Kafka to SPELL. The packet secondary-header
profile is declared by this project; using the port does not establish vendor
Cortex or spacecraft hardware compatibility. Full SPELL 2.4.4 compatibility and
operational authorization remain outside this increment.
