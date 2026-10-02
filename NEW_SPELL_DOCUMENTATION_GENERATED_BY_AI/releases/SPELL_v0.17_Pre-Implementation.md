# SPELL v0.17 Direct Language Conformance Gate

The owner's 2026-10-02 **execute** instruction authorizes the proposed v0.17.0
language-conformance release, including qualification, concise documentation,
Git push and release publication. `V17-GATE-0A` precedes product edits. Its
accepted predecessor is `v0.16.0`, release commit
`1b0aa8e582cb13b9d6aa5196fd66fc56d9d3ad10`; documentation closeout retains that
ancestry. Only the validated annotated tag and committed evidence establish
product acceptance.

## Scope And Proof

| Identity | Required behavior | Required proof |
| --- | --- | --- |
| V17-CORE-001 | Direct scalar, operator, short-circuit, conditional and literal-range semantics; correct empty ranges; bounded versioned operator additions | Positive, boundary and invalid-source cases through the real parser/worker; numeric/result bounds, dead-body validation, definite assignment, isolation and checkpoint recovery |
| V17-PROMPT-001 | Documented Display and native Prompt argument forms, severity/defaults, prompt types, list key/index/value modes and assigned results | Exact typed IR and result assertions, native positional/keyword cases, malformed/conflicting arguments and bounded values; earlier IR contracts preserved |
| V17-PROMPT-002 | Durable prompt answers, cancellation, default settlement, timeout warning, indefinite wait and recovery | Real API/worker restart, expiry/response races, one durable settlement, authorization/interlocks, and desktop/mobile prompt workflows |
| V17-COVERAGE-001 | Distinguish missing implementation, missing direct proof and manual conflicts across the complete reference inventory | Preserve all 763 source identities and hashes; explicit limitations and proof mappings; no adaptation or rejection relabeled as full support |
| V17-RUNNER-001 | Expand language_reference_244.spell.py for individual and complete-suite execution | Preserve 195 adaptations/257 variants and earlier direct case identities; source-bound new cases, actual results, deterministic validation and full-support failure while gaps remain |
| V17-DOC-001 | Concise current README, operator guide, coverage and release records | Complete Markdown rendering/link checks; correct current status, historical records and immutable manuals preserved |
| V17-RELEASE-001 | Independently validated local release | Frozen exact test catalog, candidate gate, full SQLite/PostgreSQL/Compose regression, frontend/build/browser, language, soaks, image checks, four SBOMs/audits and four identical package builds across two exports |

## Reference Decisions And Limits

Language Reference 2.4.4 pages 17-23 define scalar, expression, branch and loop
behavior; page 68 defines Display; pages 70-72 define Prompt. Appendices on
pages 108-117 supply constants, modifiers and configuration defaults. The
source SHA-256 is
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`.
GUI Manual 2.4.4 pages 19-20 define prompt interaction. Its SHA-256 is
`1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6`.
All eight inherited source inputs remain hash-bound by the version policy.

An empty literal range performs zero body iterations. The compiler still
validates unreachable source against the allowlist, type and complexity rules.
Existing fixed scalar types, finite values and resource bounds remain explicit
profile limits. Newly supported operators must use versioned IR validation;
they must not silently broaden older persisted IR contracts. Collections,
general function arguments/returns, exception syntax, imports and unrestricted
Python execution remain outside this increment.

IR 0.17 adds integer-only `**`, `&` and `|` expression nodes. Boolean and float
operands are rejected. Power uses nonnegative integer exponents from 0 through
4096 with checked evaluation and the existing 4096-bit integer result bound.
Invalid literal bounds reject at compilation; invalid variable bounds fail
explicitly during execution. Fractional/negative powers remain unsupported.

For native v0.17 Prompt calls, the dedicated section 4.12 on page 72 takes
precedence over the contradictory Timeout summary on page 112: a positive
timeout without a Default warns the operator and keeps waiting. Timeout zero
waits indefinitely; a Default becomes an automatic result only with a positive
timeout. This conflict and the selected behavior must remain in the coverage
report. Earlier lowercase prompt forms retain their versioned behavior.
Selecting a Cancel answer is distinct from aborting an execution. Reset clears
the native prompt draft. Browser audio restrictions require visible warning
feedback even when a sound cannot play.

New compilation of bare `Prompt(message)` follows the manual's default OK
type, replacing the earlier implicit `continue` choice. Explicit lowercase
project syntax and stored earlier IR retain their existing contracts. Dynamic
Display values must accept empty strings as well as literal empty strings;
their new compilation can use IR 0.17 while historical persisted IR stays intact.
Inherited conformance execution helpers may adapt to that lowering without
changing earlier source-case identities, hashes, expected outcomes or artifacts.

Native calls lower to closed typed instructions; no submitted Python is
evaluated. Date/number representations and supported scalar result bounds must
be explicit in the v0.17 contract and tested. The combined runner may use a
new hash-bound IR 0.17 registry, with independent validation and recovery proof.
It must retain the existing execution budgets and earlier example selections.

Native fixed/ALPHA/DATE and LIST key/value results use bounded strings; DATE
uses the explicit ISO representation rather than claiming a legacy time object.
LIST index results are integers and NUM results are finite floats. Timeout
accepts bounded literal duration arithmetic with SECOND/MINUTE/HOUR, up to seven
days. A timeout warning occurs once and never resets its deadline on reconnect
or restart. Native Display accepts bounded empty and whitespace-only strings,
but has no assignment result. Local Abort stops subsequent native prompt steps;
it never fabricates a returned answer. These bounded type/cancellation choices
remain visible compatibility dispositions.

The scalar profile retains fixed types, finite floats, 4096-bit integers,
100000-character strings and definite assignment. Division retains the accepted
modern true-division profile; the manual's division table does not settle the
Python-2 integer-division ambiguity. Dynamic retyping, broader numeric domains,
collection loops, while/break/continue and legacy `<>` remain explicit gaps.

The compact v0.16 workspace and finite automatic loopback operator session
remain the baseline. There is no automatic administrator grant, new external
connection, live GCS/spacecraft effect, deployment or operational authorization.
Full SPELL 2.4.4 compatibility remains false until every applicable behavior has
complete direct proof and all conflicts are resolved.

## Release Decision

Collect and freeze the exact test catalog after implementation. Candidate and
Final producers must reject mutable source, an unfrozen catalog, failed or
missing evidence, unresolved mandatory skips and incorrect source bindings.
Only new v0.17 captures can qualify v0.17. Earlier tags, contracts and accepted
evidence remain immutable. Planned checks are not passed results.
