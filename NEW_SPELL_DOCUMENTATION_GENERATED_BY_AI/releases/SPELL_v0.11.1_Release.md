# SPELL v0.11.1 Documentation Maintenance Release

## Scope

This maintenance release restores four truncated cross-version records and
adds rejection of embedded tool-output omission markers to the Markdown gate.
The accepted runtime remains `v0.11.0`. No new language, driver, or operational
capability is claimed.

The missing spans in `PROJECT_ROADMAP.md`, `VERSION_TIMELINE.md`,
`PROMPT_History.md`, and `Test_and_Integration.md` are restored from intact
commit `060001baf423fb82f27041f6b842630370c1a786`. Later retained acceptance
entries remain authoritative. Links in the restored spans follow the current
release-document layout.

## Verification And Acceptance

The entry decision is [V111-GATE-0A](SPELL_v0.11.1_Pre-Implementation.md).
The complete documentation preview and layout suite must pass from frozen
source, including adversarial omission-marker checks and ordinary prose.
Canonical machine evidence is recorded in `artifacts/v0.11.1/qualification.json`.

Acceptance requires an annotated `v0.11.1` tag binding the qualification digest,
source commit, and unchanged `v0.11.0` runtime predecessor. GitHub branch and
annotated-tag identities must match the local objects. This file alone is not
an acceptance claim.
