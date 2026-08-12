# Gate G0 Readiness Package

## Document Control

| Field | Value |
| --- | --- |
| Work package | `NG-WP-00` |
| Gate | G0 Specification |
| Specification input | `0.1.0-draft.1` |
| Prepared | 2026-07-18 |
| Status | `PASS` - bounded Candidate A product engineering authorized; v0.4 release not accepted |
| Evidence status | Verified deterministic working-tree SHA-256 manifest and pinned Python 3.13 qualification; no signature or signed-tag claim |
| Product runtime, API, schema, or dependency change | None |
| Operational authorization or compliance determination | None |
| Project-declared AI assistance tool | ChatGPT 5.6 SOL |

JC Arcaz's exact project-owner instruction is recorded in
[`G0_HUMAN_APPROVAL_LEDGER.json`](G0_HUMAN_APPROVAL_LEDGER.json). It approves
Candidate A, its exclusions, local qualification budgets, and the v0.4 test
plan for a local-only, synthetic, non-CUI simulator scope. The record uses
content digests for deterministic change detection and does not claim a
cryptographic signature, compliance determination, release acceptance, or
operational authorization.

## Current Disposition

The project-owner scope decision, exhaustive compatibility decomposition,
reconciliation, independent review, exact owner-record manifest binding, and
pinned Python 3.13 qualification pass. Gate G0 / `V04-GATE-0` authorizes the
bounded Candidate A product-engineering slice. It does not accept v0.4 or make
an operational or compliance claim.
The generated report is
[`G0_READINESS_REPORT.json`](G0_READINESS_REPORT.json), and the per-ID relation
is
[`IMPLEMENTATION_ALLOCATION.csv`](../requirements/IMPLEMENTATION_ALLOCATION.csv).

| Check | Current result | Gate consequence |
| --- | --- | --- |
| Central register | 366 unique, contiguous requirements in 15 families | Structural pass |
| Per-ID allocation | 366 rows with canonical requirement-record digest, registered owner, design, primary/supporting work packages and phases/gates, methods, planned test/result targets, and approval relation | Structural pass |
| Markdown inventory | Every current Markdown path allocated exactly once after this package is registered | Structural pass |
| Relative-link paths and Markdown structure | Checked by the G0 validator | Structural pass only with explicit `--structural-only` execution |
| Legacy source integrity | Seven unique supplied PDFs, 304-page reconciliation, and recorded SHA-256 values checked | Structural pass only with explicit `--structural-only` execution |
| Organization decisions | Ten prior organization/mission/deployment decisions remain in the broader register | Outside this local synthetic non-CUI gate; they become applicable only if scope expands |
| Broader specification rows | 366 allocation rows remain structurally tracked as `OUTSIDE_LOCAL_V04_GATE` | Informational; no per-row organization approval is required for this bounded product gate |
| Broader accountable-owner assignments | Six central rows retain composite role codes | Outside this local product gate |
| Required owner record | JC Arcaz approved Candidate A, exclusions, budgets, and test plan on 2026-07-18 | Scope decision recorded; no cryptographic signature claim |
| ADR state | Five next-generation ADRs remain Proposed | Outside Candidate A's local engineering entry gate |
| Detailed compatibility rows | The exhaustive ledger covers all seven authoritative sources and assigns 125 rows to the exact Candidate A slice and 1,557 rows to its approved Deferred/`EXCLUDE` boundary | Deterministic source/page/count/identity/disposition/errata validation, reconciliation, and exact owner-record manifest binding pass; excluded rows do not require executable fixtures or results at Gate 0 |
| Independent compatibility review | `V04_COMPATIBILITY_TECHNICAL_REVIEW.json` binds each final source subset to its PDF hash, row count, canonical digest, and zero blocking/high findings | `PASS`; this is AI-assisted technical evidence, not a human approval or runtime-conformance claim |
| Baseline identity | Exact approved-scope files are bound by a deterministic SHA-256 manifest to product base commit `7bccbb4`; no tag/signature claim | Verified by the passing Python 3.13 validator |

The exact family count is:

| Family | Count | Family | Count | Family | Count |
| --- | ---: | --- | ---: | --- | ---: |
| `DOC` | 11 | `ARC` | 40 | `SRV` | 22 |
| `EXEC` | 28 | `COM` | 27 | `DATA` | 29 |
| `WEB` | 37 | `MODE` | 27 | `GIT` | 24 |
| `REL` | 29 | `SEC` | 23 | `OPS` | 10 |
| `COMP` | 22 | `DEP` | 25 | `VNV` | 12 |

## Allocation Evidence Contract

`IMPLEMENTATION_ALLOCATION_RULES.json` is the controlled local-gate allocation
source. The validator expands it against the sole central register and creates
one CSV row per requirement. The registry deliberately distinguishes:

- the registered owner copied unchanged from `SYSTEM_REQUIREMENTS.md`;
- one accountable owner, or `PENDING_OWNER_SELECTION` for a composite central
  owner that humans must resolve;
- required technical approvers inherited from the selected primary design's
  controlled document allocation or explicitly overridden for a requirement;
- one proposed primary design and primary work package;
- supporting work packages that must not be mistaken for shared authority;
- one primary implementation phase and acceptance gate plus any supporting
  phases and gates;
- stable planned verification IDs `NGV-<RequirementId>`;
- stable planned result targets `NGR-<RequirementId>`;
- an `OUTSIDE_LOCAL_V04_GATE` state for broader next-generation requirements;
  and
- the separate `G0_HUMAN_APPROVAL_LEDGER.json` owner record that binds the exact
  instruction and approved-scope file manifest without representing a digital
  signature.

The planned verification and result identifiers are trace targets, not tests or
evidence that already exist. The canonical requirement-record digest binds the
ID, statement, verification methods, and registered owner so any normative row
change requires regeneration and review (`DOC-002`, `DOC-006`, `VNV-002`). The
owner record clears the human Candidate A scope-selection and exclusion-
disposition requirement. It does not assert that the owner personally reviewed
each extracted source statement, and it does not clear incomplete technical
catalog validation, source review, reconciliation, or in-scope execution work.
Deferred/`EXCLUDE` rows require static source and negative-scope evidence plus
a planned test identity; executable fixtures, semantic oracles, and results are
required only when a row enters an implemented increment.

The six composite registered owners (`MODE-025`, `MODE-026`, `SEC-001`,
`SEC-002`, `SEC-022`, and `SEC-023`) remain preserved for a future broader
specification or connected deployment and are not local v0.4 entry blockers.

## Identity, Session, And Authorization Input

This section is a **broader next-generation design input**, not a local v0.4
gate requirement or approved policy. It
elaborates `MODE-001`, `MODE-013`, `MODE-023..MODE-027`, `SEC-003..SEC-006`,
`SEC-010`, `WEB-002`, `WEB-005`, and `WEB-013` without closing `OD-004`,
`OD-005`, `OD-006`, or `OD-011`.

### Canonical Primary Role And Mode IDs

The recommended schema IDs are:

| Concept | Candidate canonical ID | Display-label examples |
| --- | --- | --- |
| Read-only primary role | `MONITOR` | Monitoring, Monitor, Observer |
| Execution-eligible primary role | `CONTROLLER` | Controller, Operator, Executor |
| Procedure-authoring primary role | `PROCEDURE_DEVELOPER` | Developer, Procedure Developer |
| Read-only workspace | `MONITORING` | Monitoring Mode |
| Runtime workspace | `EXECUTION` | Execution Mode |
| Authoring workspace | `EDIT` | Edit Mode |

System Administrator, Security Administrator, Procedure Reviewer, Release
Manager, Auditor, and Control Supervisor remain independent roles. None implies
Controller authority, lease ownership, source promotion, or risk acceptance.
IdP group names are inputs to a server-owned versioned mapping and are never
used as browser authorization labels.

### Candidate Startup Matrix

| Effective primary roles | Modes before restrictive policy | Initial decision |
| --- | --- | --- |
| `MONITOR` | `MONITORING` | Select `MONITORING` |
| `CONTROLLER` | `EXECUTION`, `MONITORING` | Select `EXECUTION`; authority is `AWAITING_CONTROL` unless a current-policy-valid, same-subject, same-session, same-client-key `ACTIVE` lease exists |
| `PROCEDURE_DEVELOPER` | `EDIT` | Select `EDIT` |
| `MONITOR` + `CONTROLLER` | `MONITORING`, `EXECUTION` | Current-policy-valid matching lease selects `EXECUTION`; otherwise require explicit choice |
| `MONITOR` + `PROCEDURE_DEVELOPER` | `MONITORING`, `EDIT` | Require explicit choice |
| `CONTROLLER` + `PROCEDURE_DEVELOPER` | `EXECUTION`, `MONITORING`, `EDIT` | Current-policy-valid matching lease selects `EXECUTION`; otherwise require explicit choice |
| All three | `EXECUTION`, `MONITORING`, `EDIT` | Current-policy-valid matching lease selects `EXECUTION`; otherwise require explicit choice |
| None, unknown, unmapped, stale, or ambiguous | None | Deny with stable reason and correlation |

Until a versioned multi-role default is approved, the server must require an
explicit selection from its returned set. It may recommend a safer mode for
display, but the browser recommendation cannot become an authorization
decision. A client `requested_mode` is only a selection input and is denied if
it is not in the returned set. Restrictions may subtract modes or capabilities
or deny entry; they never add authority. Only normalized policy-relevant
attributes are returned, not raw directory groups (`MODE-023`, `MODE-024`,
`SEC-004`).

An existing lease never bypasses the current policy decision. It selects active
Execution only after current authentication, revocation, assurance, Controller
eligibility, attributes, domain/environment/resource scope, policy revision,
assignment generation, authority incarnation, domain current-lease pointer,
session, client key, `ACTIVE` state, expiry, and fence all validate. Any stale,
missing, ambiguous, restricted, or revoked fact invalidates that path and cannot
be converted into authority by the browser.

### Capability Boundaries

| Selected mode | Candidate capability boundary | Authority that remains separate |
| --- | --- | --- |
| `MONITORING` | Authorized procedure, execution, telemetry, event, alarm, notification, history, and health reads | Runtime mutation, prompt response, source mutation, promotion, lease ownership |
| `MONITORING` with Controller eligibility | Read-only capabilities plus create/withdraw/decline of one named non-authorizing handover request; after durable holder approval, only its named requester may submit the exact request-bound responsibility acknowledgement | The acknowledgement has no independent runtime path and creates authority only through the atomic transfer; every other Monitoring write remains denied |
| `EXECUTION` without active lease | Operational reads plus acquire available control only when the domain is `AVAILABLE`; a principal requesting handover must switch to Monitoring, and requester acknowledgement remains in that bounded workflow | Lease renewal, holder approval, prompt response, and every runtime mutation remain denied for this principal |
| `EXECUTION` with matching active lease | Mode capabilities allowed by policy; command acceptance validates the exact expected lease revision plus current session, client proof, lease/fence/state, resource revision, and idempotency | Git authoring/promotion, administration, security policy, risk acceptance |
| `EDIT` | Git-backed source create/read/update/delete, refactor, validation, static analysis, dependency analysis, branch/commit, and review submission as separately granted | Runtime mutation and self-promotion/release authority |

Capabilities are recalculated inside the selected mode. They are never unioned
from an excluded role or workspace, and an administrative role never implies
Controller or Release Manager authority (`MODE-024`, `SEC-006`).

Final-effect validation records accepted and current lease revisions without
requiring equality when only a benign renewal or non-authorizing request-metadata
change advanced the revision. It still requires the same current lease,
holder/session/client key, `ACTIVE` state, unexpired interval, authority
incarnation, and fence. Holder approval changes the state to
`HANDOVER_PENDING`, so it rejects the effect independently of revision equality.

### Server-Signed Startup Projection

The recommended `NG-WP-01` contract is a short-lived, purpose-separated,
asymmetrically signed projection. The exact algorithm, module, trust root, key
lifetime, and rotation remain pending under `OD-005`.

Required candidate content:

- schema version, projection ID, `kid`, exact audience, correlation ID, issued
  time, decision time, and expiry;
- immutable principal key `(issuer, subject)`, session ID, authentication time,
  assurance, reauthentication deadline, and revocation/policy revision;
- client-instance ID and non-exportable client-key thumbprint;
- normalized effective roles and policy-relevant attributes;
- domain, satellite, environment, and permitted resource scopes;
- mode-specific capabilities and constraints, permitted modes, selected mode or
  `SELECTION_REQUIRED`, reason code, and explicit control state;
- a pre-existing lease only when current authorization still permits Controller
  and Execution and subject, session, client key, domain, satellite, assignment
  generation, authority incarnation, current pointer, policy, state, expiry,
  revision, and fence all match.

The tab must create its non-exportable client key before requesting startup and
prove possession by signing a single-use server challenge bound to the
authenticated session, client-instance ID, intended domain, origin, and expiry.
The server registers the verified public key under a server-issued key ID and
retains its thumbprint. Later proofs resolve that registered key, verify its
thumbprint and signature, and enforce nonce/clock bounds. A later projection
can include a lease only for the same surviving tab/session/key; a reload or
second tab with a new key cannot recover it. The response uses `Cache-Control:
no-store`, is never stored in a URL or persistent browser storage, and is not a
bearer command credential. Every command independently revalidates current
authorization and authority state. Authentication failures are audited at the
access edge without logging raw tokens or trusting unverified claims
(`MODE-023`, `MODE-027`, `SEC-003`, `SEC-010`).

### Deferred Human And Workload Identity Decisions

This Draft does not select the production IdP or session implementation. The
`OD-004` closure shall name the enterprise issuer/tenant, protocol and client,
allowed redirect/origin set, authoritative immutable subject claim, accepted
signed attributes and assurance claims, phishing-resistant MFA and step-up
rules, session storage and anti-CSRF design, fixation prevention and rotation,
logout and directory-revocation behavior, WebSocket deauthorization, device
posture, and named non-shared break-glass governance. IdP group names are never
accepted directly as capabilities. Local HS256 credentials remain isolated
development inputs and cannot satisfy this decision (`SEC-003`, `SEC-004`).

Automatic lease renewal, WebSocket traffic, subscriptions, and background
requests shall not count as human activity or silently extend a browser session.
`OD-004` shall define the explicit interactions that reset inactivity and the
warning, reauthentication, revocation, and control-loss behavior at expiry.

The `SEC-005` candidate boundary requires a unique, attributable identity and
least-privilege grant for each access, authorization, control, audit, worker,
driver, migration, backup, and deployment workload; mutually authenticated
internal calls; purpose/environment/domain scoping; rotation and revocation;
and rejection of browser or human credentials at internal service endpoints.
Shared service credentials remain prohibited. The identity platform, trust
roots, certificate/credential lifetimes, custody, and recovery stay pending
under `OD-005` and `OD-015`.

Planned `NGV-SEC-003` evidence covers issuer/client/redirect validation,
assurance and step-up, session fixation/expiry/inactivity, logout and directory
revocation, WebSocket deauthorization, CSRF/origin controls, and break-glass
alert/review. Planned `NGV-SEC-005` evidence covers mutual identity, least
privilege, wrong-service and wrong-environment denial, rotation/revocation,
attribution, shared-credential rejection, and browser-token rejection. These
are planned targets, not implemented tests or accepted results.

### Candidate Qualification Profile

These numbers are engineering starting points for deterministic testing. They
are not NIST-derived values and are not policy until the named human owners
accept or replace them after latency, outage, human-factors, and hazard review.

| Parameter | Candidate test value | Accountable open-decision owner | Required concurrence/input |
| --- | ---: | --- | --- |
| Browser-session absolute lifetime | 12 hours | SO under `OD-004` | SY/MO |
| Browser-session inactivity timeout | 15 minutes | SO under `OD-004` | SY/MO |
| Maximum authentication age for acquire/approve/acknowledge and privileged policy actions | 15 minutes | SO under `OD-004`; MO for handover use under `OD-006` | SY/SA |
| Startup projection lifetime | 60 seconds | SO under `OD-004` and `OD-005` | SA |
| Maximum identity/role revocation propagation | 30 seconds | SO under `OD-004` | SY/SA |
| WebSocket credential lifetime | 60 seconds | SO under `OD-004` | SA |
| One-use client-proof nonce lifetime | 30 seconds | SO under `OD-004` | SA |
| Controller lease lifetime | 60 seconds | MO under `OD-006` | SO/SA |
| Controller renewal interval | 15 seconds | MO under `OD-006` | SO/SA |
| Renewal cutoff before expiry | 10 seconds | MO under `OD-006` | SO/SA |
| One immutable authoritative-database-time handover deadline from request creation | 45 seconds, clamped to remaining lease lifetime and never reset | MO under `OD-006` | SO/SA |
| Grace for new effects after authority expiry | Zero | MO under `OD-006` | SO/SA |
| Forced takeover | Disabled | MO under `OD-006`; accountable `OD-019` owner still to be selected | SO/RO/SA |

The IdP product, issuer/tenant, client IDs, redirect URIs, accepted assurance
claims, authenticator policy, device posture, break-glass governance, and exact
revocation source remain visibly pending. Local HS256 development identities
remain isolated test inputs and are not a production identity design.

## Broader MODE-023 Through MODE-027 Packet (Outside Local v0.4 Gate)

The following is the retained broader next-generation approval and evidence
packet. Every row remains pending for that broader work, but none is a human-
approval or technical blocker for the bounded local-only, synthetic non-CUI
Candidate A v0.4 gate.

| Requirement | Proposed decision boundary | Planned verification target | Required human approval |
| --- | --- | --- | --- |
| `MODE-023` | Approve canonical role/mode IDs, startup matrix, signed projection fields, current-policy plus same-session/client-key lease binding, restrictive policy, and no browser-inferred authority | `NGV-MODE-023`: single-role, unknown/no-role, restrictive policy, matching/wrong-session lease, stale policy/role/assignment/current-pointer/fence, scope staleness, requested-mode elevation, expiry and revocation cases | PO, MO, SA, SO; QL verifies |
| `MODE-024` | Approve per-mode capability evaluation and explicit multi-role selection unless a matching lease selects Execution | `NGV-MODE-024`: all seven non-empty primary-role combinations, every permitted mode, non-union, switch audit, and no lease/Git authority from switching | PO, MO, SA, SO; QL verifies |
| `MODE-025` | Approve one named, non-authorizing request bound to a distinct immutable subject/session/client key, domain, environment, lease revision, reason, and one immutable deadline clamped at creation to remaining lease lifetime; approve the named requester's post-holder-approval acknowledgement as the only additional Monitoring control-authority settlement | `NGV-MODE-025`: eligibility, subject/session/key distinction, singleton request, immutable-deadline behavior, notification, no runtime mutation reach, acknowledgement ordering, withdrawal/decline/cancel/expiry/replay/revision/auth-loss races | MO, SO, SY; PO/SA concur; QL verifies |
| `MODE-026` | Approve one serializable transfer: predecessor terminal, exactly one successor `ACTIVE` grant with new ID and higher fence, atomic current pointer, audit/outbox, and both mode projections | `NGV-MODE-026`: concurrent transfer, retry, failover, stale predecessor, no two-controller intermediate state, and one correlated two-mode event | MO, SA, SY, SO; PO concurs; QL verifies |
| `MODE-027` | Approve common audit envelope plus event-applicable startup/handover extensions; never fabricate inapplicable fields; atomically commit successful handover state, local durable audit admission/record and outbox row; publish and assign independent ingestion time asynchronously | `NGV-MODE-027`: every allow/deny/stage/rejection/terminal path, conditional completeness, local-admission failure, state/audit/outbox-row atomicity, asynchronous publication, sink outage, reorder/truncation/tamper, and secret leakage | SO, SY, MO, SA, CM; QL verifies |

Normal handover requires two different immutable principal subjects, not merely
two sessions or tabs. The request grants no authority and records one immutable
authoritative-database-time deadline clamped to the remaining lease lifetime;
approval, retry, and acknowledgement never reset it. Current-holder approval
changes the old lease to `HANDOVER_PENDING` and blocks new effects. Only the named
requester can acknowledge the exact request, approval, and operational context.
That acknowledgement is the sole post-approval control-authority settlement
allowed from Monitoring and has no independent runtime mutation path. One
database transaction terminalizes the old grant, installs one new active grant
with a higher fence, commits the local audit record/admission and outbox rows,
and records the two authoritative mode projections. Publication occurs only
after commit. Any auth, role, policy, key, expiry, revision, cancellation, or
replay failure creates no successor. Browser or network loss never causes
automatic handover (`MODE-025`, `MODE-026`, `SEC-004`, `SEC-006`).

Forced takeover remains a separate break-glass operation and is disabled until
`OD-006` and `OD-019` approve its dedicated permission, recent authentication,
independent approval where required, reason, notification, and post-event
review.

## Audit Event-Type Contract

`MODE-027` and `SEC-010` are interpreted through event types so startup events
do not invent handover-only data.

| Field group | Required applicability |
| --- | --- |
| Source-event common envelope | Schema/event IDs, trusted service event time, actor type, action, target/scope, outcome, reason, request/correlation IDs, event-applicable idempotency ID, and software/configuration/deployment identity |
| Startup extension | Authentication decision reference, normalized effective roles/attributes, domain/satellite/environment scopes, permitted modes, selected/required mode, mode-specific capabilities, projection/expiry, and matching control state |
| Handover extension | Holder and requester subjects, sessions and client keys; request/approval/acknowledgement IDs and safe digests; predecessor/successor lease IDs, revisions and fences; old/new modes; deadline and terminal outcome |
| Authentication failure extension | Access-edge identity provider/credential class, endpoint, failure class, source/network context allowed by policy, and correlation; never raw token, password, secret, or unverified claim content |
| Independent sink receipt | Sink identity, ingestion time, receipt result, and source event ID plus digest; this receipt is asynchronous and is not fabricated in the source event |

Every successful lease renewal retains a durable event with actor/session/key,
prior and resulting lease revisions and expiries, trusted time, policy revision,
outcome, reason, and correlation. Presentation and exports may aggregate those
events, but authoritative renewal evidence is not sampled.

For successful handover transitions, authoritative state, the local durable
audit record/admission, and the outbox row commit atomically in PostgreSQL.
External publication and independent-sink ingestion occur after commit and are
not a distributed transaction; the sink assigns the independent ingestion
time. An authenticated startup allow and every handover success or rejection
that requires audit fail closed when the required local durable audit handoff
cannot accept the event, subject only to an approved emergency operating policy.
An authentication denial remains denied during audit degradation and uses the
approved emergency/fallback audit path with an alert. Exact online and WORM
retention, export, outage behavior, custody, deletion, and emergency policy
remain pending under `OD-011`.

## DOC-011 Disposition

The Draft manual source, versioned Draft PDF, four concept images, print CSS,
and renderer tools exist. The proposed G0 disposition is **accept as a Draft
design and workflow input only**. This does not close `DOC-011` or `NG-WP-05`.

Final acceptance still requires:

- exact source, PDF, image, tool, specification, and product-build digests;
- tracked artifact custody and a reproducible publication manifest;
- reconciliation against accepted startup, mode, handover, Git, alarm,
  degraded, recovery, and support behavior;
- link, metadata, accessibility, secret/CUI, and page-render checks;
- page-by-page visual review with findings disposition;
- representative Controller, Monitor, and Procedure Developer validation; and
- approved audience, classification, publication path, owner signatures, and
  exact baseline.

This publication work and its organization-specific review roles remain in
`NG-WP-05` and later operator/release gates; they do not block local v0.4
implementation entry.

## Local Gate Decision Disposition

The local gate does not require organization, mission, protected-data,
deployment, or authorizing-official decisions. `OD-001`, `OD-002`, `OD-004`,
`OD-005`, `OD-006`, `OD-010`, `OD-011`, `OD-012`, `OD-015`, and `OD-023`
remain in the broader decision register but are excluded from this bounded
scope. Their safe defaults continue to apply: synthetic non-CUI data, local
single-node execution, no real endpoint or credential, no compliance claim,
and no operational authority.

The approved worker-isolation choice is bounded non-executing IR plus strict
mTLS credential separation and fail-closed driver authentication. A route may
exist in the shared local development network; the worker must have no product
call path or usable driver credential. The project owner accepts that residual
routing risk only for this synthetic local scope. A later connected or
operational scope must select a stronger deployment boundary and obtain its own
approval.

## Completed Gate Sequence

1. Retained the passing independent review of the exhaustive seven-source
   compatibility catalog: exact source identity and page coverage, unique
   artifact and planned-test identities, source-grounded classifications,
   Candidate A or Deferred/`EXCLUDE` dispositions, explicit errata handling,
   and reconciled per-source counts. Excluded rows remain static source and
   negative-scope evidence, not implementation claims or executed fixtures.
2. Generated the deterministic local scope manifest and owner-record digest
   after the compatibility evidence changes. Neither digest is represented as
   a signature.
3. Regenerated the allocation/report and ran the default gate validation under
   the pinned Python 3.13 image. Zero structural errors and zero technical
   blockers authorize the bounded product edits.

## Reproduction

Run from the project root with Docker. The digest-pinned Python 3.13 image is the
qualification interpreter for this package; do not use bare `python` or the
current local `.venv`, which is Python 3.9 and below the project minimum.

```powershell
$pythonImage = "python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280"
$workspace = (Get-Location).Path
$docs = "/workspace/NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"

docker run --rm --mount "type=bind,source=$workspace,target=/workspace" `
  --workdir $docs $pythonImage python quality/tools/validate_compatibility.py `
  --write-reconciliation
docker run --rm --mount "type=bind,source=$workspace,target=/workspace" `
  --workdir $docs $pythonImage python quality/tools/test_validate_compatibility.py
docker run --rm --mount "type=bind,source=$workspace,target=/workspace" `
  --workdir $docs $pythonImage python quality/tools/validate_g0.py `
  --generate-allocation --write-report quality/G0_READINESS_REPORT.json `
  --structural-only
docker run --rm --mount "type=bind,source=$workspace,target=/workspace" `
  --workdir $docs $pythonImage python quality/tools/test_validate_g0.py
docker run --rm --mount "type=bind,source=$workspace,target=/workspace" `
  --workdir $docs $pythonImage python quality/tools/validate_g0.py
```

The compatibility validator must retain reconciliation of the complete
seven-source catalog, including all 195 Language Reference example identities,
exact Candidate A and Deferred counts, and the independently pinned artifact
manifest. Both unit suites and G0 structural validation pass. The default G0
validator returns zero only while every Gate 0 input and the canonical report
remain fresh. Treating `--structural-only` as a G0 pass is prohibited.
