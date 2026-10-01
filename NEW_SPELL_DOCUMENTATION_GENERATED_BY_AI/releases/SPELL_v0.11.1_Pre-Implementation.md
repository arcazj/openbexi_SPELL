# SPELL v0.11.1 Documentation Maintenance Gate

## Owner Direction And Decision

On 2026-09-30 the project owner requested completion and GitHub publication of
v0.11.1 followed by v0.12, with approval to complete both. No separate v0.11.1
feature specification exists. Review found embedded truncation markers and
missing sections in four cross-version records, despite a passing Markdown
preview gate. This patch repairs that demonstrated documentation defect.

`V111-GATE-0A PASS` authorizes the bounded documentation and validation scope
below. This is a documentation maintenance release over accepted product
`v0.11.0`; runtime, dependency, API, IR, and database identities stay unchanged.
It does not claim new language compatibility or product qualification.

## Scope And Acceptance

| Identity | Change | Required proof |
| --- | --- | --- |
| V111-DOC-001 | Restore missing roadmap, timeline, history, and test-plan sections from intact Git history | Record source commits and compare restored spans; retain later accepted release facts |
| V111-DOC-002 | Reject embedded tool-output truncation markers in tracked Markdown | Negative tests for token/byte/line omission markers; ordinary prose remains valid |
| V111-DOC-003 | Publish an immutable maintenance release and evidence | Clean frozen source, complete Markdown rendering/link tests, source-bound qualification, annotated tag, verified remote branch/tag |

The mandatory manual inventory remains the eight hash-pinned references in
`contracts/v11/release_policy.json`. No manual behavior is changed or newly
implemented. Historical accepted tags and their artifacts remain immutable.

## Exit Conditions

All required documentation and validator tests must pass from a committed
source. The release record must identify restored source revisions and exact
test results. The tag accepts only this maintenance scope; the accepted runtime
continues to be `v0.11.0`. v0.12 receives its own implementation gate and product
qualification before its release can be accepted.
