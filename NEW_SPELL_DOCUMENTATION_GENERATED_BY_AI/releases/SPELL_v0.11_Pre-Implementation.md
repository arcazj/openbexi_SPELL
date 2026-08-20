# SPELL v0.11 Pre-Implementation Authorization

## Decision

The project-owner direction recorded on 2026-08-19 authorizes the bounded
v0.11 simulator telecommand increment after acceptance of v0.10. That
predecessor condition is now satisfied by annotated tag `v0.10.0`, tag object
`95f64a04bb15b1eb03250a8d0387a228b67727a7`, and release commit
`c33d1893d90f9d42c36eedd19cb83f079bf39a9f`.

`V11-GATE-0A PASS` authorizes implementation and qualification of the scope
below. It is not deployment approval, operational authorization, a compliance
determination, or permission to command a spacecraft.

## Mandatory Source Inputs

Every document under `SPELL_DOCUMENTATION/` is a required read-only source
reference. The Language Reference constrains procedure-visible syntax and
intent. The Driver and Server manuals constrain stages, services, lifecycle,
context, and execution. The GUI and Development Environment manuals constrain
operator and authoring workflows. The supplementary manuals remain
compatibility references. The legacy source ZIP is evidence only and is not a
code source for this implementation.

Generated documentation may interpret those sources but cannot silently
override them. Ambiguity, obsolete behavior, deliberate incompatibility, and
safety strengthening require a recorded decision and test.

## Entry Gate

The v0.10 entry condition is immutable and inherited:

- all 195 numbered examples have a source-bound compatibility record;
- all 257 identified variants have distinct assertion and trace identities;
- Example 60 independently proves direct command-name and built-item forms;
- the v0.10 qualification, deterministic package, evidence validator, and
  annotated tag pass with no accepted exceptions; and
- semantic adaptations remain distinct from verbatim execution of malformed,
  pseudocode, output-only, placeholder, or intentionally invalid fragments.

## Authorized Scope

- Closed catalog-backed `BuildTC` and `Send` parser and IR forms.
- Typed command arguments and deterministic command, sequence, group, and
  block expansion with stable per-element identities.
- Global and per-command modifiers, critical confirmation, time and release
  intent, load-only behavior, bounded delay and timeout, and closed-loop
  verification.
- Separate transport, loading, release, acknowledgement, onboard execution,
  verification, disposition, effect certainty, and bounded provider detail.
- Durable supervisor-owned intent, settlement, recovery, reconciliation,
  cancellation, and fail-closed procedure behavior.
- Deterministic simulator providers only.

No browser telecommand mutation route, driver credential, arbitrary endpoint,
shell, unrestricted evaluation, network dispatch, live GCS route, automatic
resend, or spacecraft command path is authorized.

## Compatibility Decisions

- `LoadOnly` may settle as `LOADED_ONLY`; it never proves onboard execution.
- Unsupported or conflicting modifiers are rejected rather than ignored.
- A possible or unknown effect is never automatically retried.
- Reconciliation retains the original operation and request identities.
- Critical commands require digest-bound explicit confirmation.
- Operator actions and inspection edits cannot mutate telecommand items or
  their dependencies.
- Legacy boolean success cannot collapse transport, loading, execution,
  verification, or certainty into one fact.

## Exit Gate

v0.11 can be accepted only when:

- all eight focused v0.11 backend modules pass 197 tests with no skip;
- the inherited v0.10 suite retains its exact 442-pass/one-PostgreSQL-skip
  boundary and both generators pass in check mode;
- the full backend suite, all 16 PostgreSQL selections, and all three Compose
  selections meet the version policy;
- frontend unit/build and both real-backend browser viewports pass;
- the latest legacy auditor passes its three integration tests;
- documentation, product-image, source hygiene, and deterministic package
  validators pass; and
- annotated tag `v0.11.0` validates against committed qualification and
  package evidence.

The exact policy is `contracts/v11/release_policy.json`. The implementation
record is
[`SPELL_v0.11_Implementation.md`](SPELL_v0.11_Implementation.md).
