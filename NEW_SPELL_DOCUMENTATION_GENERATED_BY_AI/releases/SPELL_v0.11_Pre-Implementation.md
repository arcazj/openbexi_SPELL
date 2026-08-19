# SPELL v0.11 Pre-Implementation Authorization

## Decision

The project-owner direction recorded on 2026-08-19 authorizes the bounded
v0.11 simulator telecommand increment only after the strengthened v0.10
reference-example gate passes. The exact request time was not retained, so
this record does not claim an exact implementation-start timestamp.

`V11-GATE-0A PASS` authorizes implementation and testing. It is not a release,
deployment, operational, compliance, or spacecraft-command authorization.

## Entry Gate

The v0.10 entry condition is:

- Examples 1 through 195 have a complete variant-level traceability contract.
- Every identified variant has distinct assertion and trace evidence.
- Example 60 independently proves both `Send(command = 'CMDNAME')` and
  `Send(command = tc_item)`.
- Direct adapter, worker, API, generator, and qualification checks pass.
- Semantic adaptations remain explicitly distinguished from verbatim source
  execution for malformed, pseudocode, output-only, and negative fragments.

## Authorized Scope

The v0.11 product boundary is the `PROJECT_ROADMAP.md` section
"v0.11 - Simulator Telecommand Semantics":

- Closed, catalog-backed `BuildTC` and `Send` syntax and IR.
- Typed arguments and deterministic command, sequence, group, and block
  expansion with stable per-element identities.
- Global and per-command modifiers, critical confirmation, time and release
  intent, load-only behavior, deterministic delays, timeout, and closed-loop
  verification.
- Separate transport, loading, release, acknowledgement, onboard execution,
  verification, disposition, certainty, and bounded provider detail.
- Durable supervisor-owned intent, confirmation, result settlement, recovery,
  reconciliation, cancellation, and fail-closed procedure behavior.
- Deterministic simulator providers only. No browser mutation route, driver
  credential, arbitrary endpoint, shell, evaluation, network dispatch, live
  GCS route, or automatic resend is authorized.

## Compatibility Decisions

- `LoadOnly` may settle as `LOADED_ONLY`; it never claims onboard execution.
- Unsupported or conflicting modifiers are rejected instead of ignored.
- `OnFailure=CONTINUE` permits remaining elements and procedure continuation;
  `CANCEL` cancels remaining elements but may continue the procedure;
  `ABORT` terminates the procedure when no operator override is requested.
- `PromptUser=True` asks only whether the procedure may continue after the
  already-settled failure. It does not resend or change completed element
  outcomes. Non-answer and `NO` fail closed.
- Any possible or unknown effect forbids automatic retry. Reconciliation uses
  the original operation and request identities.
- Legacy boolean success is represented without conflating transport,
  loading, execution, verification, or certainty.

## Exit Gate

v0.11 may be described as locally complete only when:

- all 26 documented command statements across Examples 57 through 77 compile
  and execute through the closed runtime;
- the complete 195-example, 257-variant v0.10 gate still passes;
- parser, IR, core, worker, supervisor, public API, recovery, uncertainty,
  no-resend, timing, verification, and failure-policy tests pass;
- the full backend, script, frontend, build, and image checks pass without a
  regression;
- all relevant Markdown and version metadata describe the actual boundary;
- the final report records exact commands, counts, skips, and limitations.

An accepted v0.11 release still requires a fixed release commit and validated
annotated tag. Mutable working-tree evidence cannot create that status.

The authorized implementation surface and the exact final-gate placeholders are
recorded in
[`SPELL_v0.11_Implementation.md`](SPELL_v0.11_Implementation.md). Until those
placeholders are replaced from one complete final run, the accurate status is
implemented and locally qualified in the mutable working tree. The separate
implementation record retains exact commands and non-release exclusions.
