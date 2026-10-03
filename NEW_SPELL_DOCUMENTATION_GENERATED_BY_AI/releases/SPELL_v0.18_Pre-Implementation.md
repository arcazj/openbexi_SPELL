# SPELL v0.18 Native Telecommand Workflow Gate

The owner authorized the proposed v0.18.0 prompt: integrate native language
with existing simulator telecommands, expand `language_reference_244.spell.py`
with currently supported behavior, add testing procedures under `procedures/`,
qualify, update concise documentation, commit, push and publish. This entry gate
precedes product edits. The accepted predecessor is `v0.17.0`, release commit
`e525b9c842e3c26a35058d85fc40bd3ee4b16c85`.

## Scope And Proof

| Identity | Required behavior | Required proof |
| --- | --- | --- |
| V18-IR-001 | Closed versioned IR combines native Prompt/Display and bounded core expressions with existing BuildTC/Send forms | Direct parser/worker cases, typed prompt results, original indexes and lexical targets, malformed IR rejection and unchanged earlier IR contracts |
| V18-RUNTIME-001 | Prompt answers and conditions determine whether a simulator command is requested through the authoritative supervisor | Exact durable answer/default/Cancel/Abort behavior; command catalog, arguments, confirmation, leases, generation and fencing enforced before dispatch; no worker-fabricated authority |
| V18-RECOVERY-001 | Recover prompts and command intent without duplicate effects or backward replay | Crash before/after intent, immutable dependencies, stale/forged messages, timeout/response races and uncertain-effect reconciliation; no automatic resend |
| V18-RUNNER-001 | Reference runner includes supported source behavior and new native/command combinations | Preserve 195 adaptations, 257 variants and all 96 earlier case identities/source hashes; independent expected results and actual parser/worker/service evidence; adaptations and rejections remain distinct from direct support |
| V18-PROCEDURES-001 | Additional runnable testing procedures demonstrate supported language and complete native command workflows | At least three new catalog procedures with documented inputs and expected outcomes; every new procedure executes in runtime tests; real desktop/mobile prompt-to-command workflow |
| V18-DOC-001 | Current README, procedure guide, compatibility and release summaries stay concise | Accurate supported behavior, limits and current status; complete tracked-Markdown rendering and link checks |
| V18-RELEASE-001 | Independently validated local release | Frozen exact catalog, candidate gate, full SQLite/PostgreSQL/Compose regression, frontend/build/browser, language, soaks, image checks, four SBOMs/audits and four identical package builds across two exports |

## Reference Decisions And Limits

Language Reference 2.4.4 sections 4.4-4.5, pages 47-55, define BuildTC and
Send, including built/direct items, arguments, confirmation, load-only,
sequences/groups, timing and verification. Pages 17-23 define core expressions
and control flow; page 68 defines Display; pages 70-72 define Prompt. The
reference SHA-256 is
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`.
GUI Manual pages 19-20 govern prompt interaction. The Driver and Server manuals
remain authoritative for service lifecycle, outcome stages and recovery.
All eight inherited source inputs remain hash-bound and unchanged.

The concrete new workflow is Prompt, typed answer, conditional branch,
BuildTC/Send and Display. A native Prompt is not a substitute for required
digest-bound command confirmation. Native Cancel answers remain answers;
Abort stops execution without a fabricated result or later command. The
v0.17 interpretation of Prompt timeout/default conflicts remains unchanged.
Prompt settlement and command intent must survive reconnect and restart.

IR 0.18 accepts literal catalog command names or immutable BuildTC items;
command argument values retain literal-only bounds, and modifiers keep the
existing closed literal and constant temporal forms. Earlier
IR 0.11 string-variable selectors remain available in that older profile,
but are rejected in the new composition profile. New scalar expressions may
control branches but do not broaden command operand evaluation. Built items and their
dependencies remain immutable. Loading is not execution; possible or unknown
effects are not success and never trigger automatic resend. Recovery must
retain the original operation/request identity and enforce current authority.

IR 0.18 must validate the combined instruction stream independently, including
prompt target types, command-item declarations, checkpoints, guards and lexical
targets. It must not obtain authority by relabeling an older IR or removing a
parser rejection alone. Earlier persisted IR and earlier registry contracts
retain their exact semantics. Bounded integer and native prompt limits remain.

This release does not combine the v0.8 data, argument, file or environment
profiles or direct GetTM/Verify/WaitFor instructions with native telecommands.
Their existing separate profiles remain available. Collections, general function arguments
and returns, imports and exception syntax remain outside scope. The compact
workspace and finite automatic loopback operator session remain unchanged.
No live GCS/spacecraft connection or operational authorization is added.

The complete inventory must retain unresolved gaps and manual conflicts.
Passing bounded source cases, simulator adaptations, correct rejection, or a
successful example does not establish whole-function or full SPELL 2.4.4
compatibility. The runner must report the distinction explicitly.

## Release Decision

Freeze the exact test catalog only after implementation and review. Candidate
and final producers reject mutable source, missing or failed proof, unresolved
mandatory skips and mismatched source bindings. Only v0.18 captures qualify
v0.18. Preserve earlier contracts, evidence, tags and original manuals. Publish
only after independent clean-tag validation; planned tests are not results.
