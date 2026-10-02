# SPELL v0.16 Language Coverage And Manual Workspace Gate

The owner's 2026-10-01 instruction, **execute**, authorizes implementation,
qualification and publication of the complete six-part v0.16.0 prompt recorded
in `PROMPT_History.md`. `V16-GATE-0A` covers the local simulator profile below.
The accepted predecessor is `v0.15.0`, release commit
`b7bceaf2489156271c91a939d897d040caeb0be1`; later documentation commits retain
that ancestry. Gate validation precedes product edits. Acceptance requires the
independently validated annotated `v0.16.0` tag and committed evidence.

## Scope And Proof

| Identity | Delivered behavior required | Required proof |
| --- | --- | --- |
| V16-LANG-001 | Complete inventory of Language Reference sections 2-4 and function, modifier and configuration appendices, beyond the 195 example adaptations | Exact source hash/page/section mapping; explicit direct, partial, adapted and gap classifications; no missing inventory entries or unsupported-success claims |
| V16-LANG-002 | Direct source conformance cases and bounded language additions: inferred scalar assignments and documented Display severity | Parser/worker assertions, definite assignment, typing, invalid source/modifier and isolation tests; no unrestricted Python execution |
| V16-RUNNER-001 | Updated language_reference_244.spell.py with individual selection and automated complete-suite execution | Retain all 195 examples/257 semantic variants; execute direct cases and report all remaining gaps; strict full-compatibility mode fails while gaps remain |
| V16-UI-001 | Compact GUI-manual workspace with navigation, Master/instance tabs, source Code/Data/Result presentation and lower execution/prompt/log controls | Component tests and real desktop/mobile geometry, keyboard, Axe and workflow tests; visual comparison against source manual screenshots |
| V16-SESSION-001 | Automatic local operator session at http://127.0.0.1:8080/ without Session access or manual token entry | Disabled outside explicitly enabled local profile; exact loopback origin/host/ingress checks, anti-CSRF checks, finite signed credentials, stable browser identity, no administrator auto-grant or credential leakage |
| V16-SESSION-002 | Fresh load, reload, renewal, reconnect and unavailable-backend handling | API negative tests; frontend bootstrap/renewal/retry tests; real browser access with empty session storage |
| V16-DOC-001 | Concise current README, operator guide, coverage and release documentation | Real Markdown rendering and local links; no stale current-version instructions; preserve historical evidence and original references |
| V16-RELEASE-001 | Complete independently validated local release | Frozen exact test inventory, full SQLite/PostgreSQL/Compose regression, frontend/build/browser, language results, soaks, image checks, four SBOMs, audits and four identical package builds from two exports |

## Source References And Decisions

The GUI User Manual 2.4.4, pages 6-29 (notably screenshots on pages 6, 10 and
21), defines the main window, Navigation, Master/instance, source, execution
controls and prompt structure. Its SHA-256 is
`1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6`.
Browser navigation and responsive rearrangement replace native Eclipse window
management; no unrestricted shell or unavailable live-system function is shown
as implemented.

Language Reference 2.4.4 sections 2-4 and appendices A-D define the inventory,
syntax and service semantics. Its SHA-256 is
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`.
Existing Driver and Server manual authority remains applicable to the local
simulator and session/context boundary. Every mandatory source input is pinned
in the version policy. Source manuals and legacy implementations remain
read-only evidence and are excluded from product images and packages.

The owner's direct-connect requirement authorizes a narrow replacement of the
previous manual-token workflow: the loopback Compose profile can automatically
issue short-lived signed operator credentials after exact local-origin and
proxy-boundary checks. The backend default remains disabled outside this
profile. A signed HttpOnly SameSite cookie binds renewals to the local browser
identity. No caller-supplied identity/role, automatic administrator credential,
static frontend token or signing secret is permitted. Existing independent
administrator identities retain their own permissions and expiry.

The complete language inventory and test runner must report unsupported
semantics as gaps. This gate authorizes the specified direct-language increment;
it does not authorize relabeling semantic adaptations or unsupported constructs
as full language conformance. Real legacy connections, externally effective
commands, production identity, deployment and operational approval remain out
of scope.

## Release Decision

Implementation refinement: direct assignment and Display still lower to
existing typed instructions. The combined reference procedure needs a closed
IR 0.16 selection instruction: expanding all cases as flat guarded instructions
left Example 195 running beyond the inherited 15-second API budget. The new
instruction selects only source-hash-bound example/direct/all-case catalog
entries, preserves older IR dispatch, and must pass malformed-input, bounds,
worker, recovery and existing API latency tests. It does not evaluate submitted
Python or turn a coverage gap into a pass. This refinement implements the
owner-authorized complete runner without weakening the latency gate.

The exact product inventory is collected and frozen after implementation;
pre-implementation proof names are plans, not passed results. Candidate and
Final producers must reject an unfrozen inventory, mutable source, missing
evidence, unresolved mandatory skips, failed assertions or incorrect source
bindings. Original v0.15 evidence cannot qualify v0.16.
