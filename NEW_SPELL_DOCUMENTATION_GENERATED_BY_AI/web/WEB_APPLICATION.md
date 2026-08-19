# Web Application Specification

## 1. Purpose

This document defines the operator-facing and developer-facing web application
for next-generation SPELL. It is normative for information architecture,
interaction safety, accessibility, responsive behavior, and failure
presentation. Operating authority is defined in
[Operating Modes](OPERATING_MODES.md); stream behavior is defined in
[Real-Time State](REAL_TIME_STATE.md).

The application is a client of the SPELL control plane. It is never an
execution engine, a source of authoritative state, or a direct client of a
driver or Ground Control System (GCS).

## 2. Design Principles

1. The server is authoritative for execution state, control ownership,
   prompts, acknowledgments, alarms, variables, and audit events.
2. Critical state is visible without opening a menu or relying on color.
3. Every mutating action has a durable command identity and a visible terminal
   result.
4. Monitoring remains useful during degraded connectivity, but stale data is
   never presented as current.
5. Dense operational views favor scanning, comparison, keyboard use, and
   predictable placement over decorative presentation.
6. Authoring and active execution are separate workspaces with separate
   authorization and data paths.

These principles implement requirements `WEB-013`, `WEB-014`,
`WEB-016`, `WEB-018`, and `MODE-013`.

## 3. Application Shell

The authenticated shell shall contain the following stable regions.

| Region | Required content and behavior |
| --- | --- |
| Global status bar | Mission, satellite, SPELL server, environment, authenticated identity, role, selected mode, control owner, connection state, data age, UTC clock, and active critical-alarm count |
| Left navigation | Hierarchical procedure tree, search, filters, favorites, recent procedures, and Git branch/status when in Edit Mode |
| Primary workspace | Execution console, monitoring console, editor, validation results, history, or administrative view selected by route |
| Context panel | Selection details, variables, arguments, prompts, command acknowledgments, telemetry details, dependencies, or Git change details |
| Event area | Chronological logs, events, alarms, operator notifications, command outcomes, and audit-correlated messages |

The regions may be resized or collapsed, but the selected satellite, server,
mode, connection condition, staleness, critical alarms, and control owner shall
remain visible. Layout preferences are per user and do not alter operational
state.

### 3.1 Authorized Startup

The application shall obtain the server's startup authorization projection
before mounting a workspace. Before that request, the tab creates a
non-exportable client-instance key and proves possession over a single-use
server challenge bound to the authenticated session, domain, origin, and
expiry. The projection supplies effective capabilities, permitted modes,
selected or selectable initial mode, policy revision, domain and environment
scope, decision time and expiry, and any controller lease bound to the same
surviving session and client-instance key. A reload or another tab cannot
recover a lease by registering a new key. The shell shall fail closed if this
projection or proof is missing, expired, ambiguous, or inconsistent with the
route.

A single-role principal uses the baseline startup mapping: Controller opens the
Execution workspace, Monitoring opens the Monitoring workspace, and Developer
opens the Edit workspace. A same-session controller lease activates Execution
controls only after current authentication, revocation, assurance, Controller
eligibility, attributes, scope, policy, assignment, current-pointer, state,
expiry, client-key, and fence checks all pass. A lease cannot override a current
restriction or revoked authorization decision. Without a valid lease, a
Controller still opens Execution but the workspace is visibly non-authorizing
and all operational mutations remain disabled until an available lease is
acquired or handover completes. Multiple permitted modes use the server-selected
safe default or an explicit chooser containing only returned modes. An approved
policy restriction may select a more restrictive mode or deny entry, but it
cannot elevate authority.

For a multi-role user, each workspace exposes only that mode's effective
capabilities; opening another workspace never unions controls into the current
one. The authenticated identity, effective roles, selected mode, and controller
status remain separately visible. The client shall never infer control from an
operator role or an Execution route.

The URL shall identify the logical view and stable resource identifiers. It
shall not contain access tokens, driver endpoints, credentials, prompt
responses, sensitive variable values, or procedure source fragments.

## 4. Primary Workspaces

### 4.1 Execution Workspace

The Execution workspace shall provide:

- procedure definition, immutable bundle digest, version, and execution
  instance identity;
- canonical execution state and state revision;
- source view with current, executed, waiting, error, and selected lines;
- parent and child procedure navigation;
- arguments, scoped variables, shared-data references, and approved resources;
- durable prompts with validation and response outcome;
- procedure controls authorized by the active control lease;
- chronological as-run, support, command, event, and alarm projections;
- explicit command progress and final settlement;
- recovery and uncertainty notices that cannot be dismissed without an audited
  disposition.

Multiple instances of one procedure shall be distinct by `execution_id`.
Selecting a definition in the tree shall never silently switch an existing
instance. The workspace shall show an instance selector when more than one
instance exists.

### 4.2 Monitoring Workspace

The Monitoring workspace shall use the same authoritative projections as the
Execution workspace and shall expose the same observational detail permitted by
policy. All execution controls and prompt-response operations shall be absent
or disabled with an accessible explanation. Client-side disabling is not an
authorization boundary; the API shall reject all monitor runtime and procedure
mutations.

A controller-eligible user may see a **Request control** action in Monitoring.
It calls only the dedicated non-authorizing handover-request resource and cannot
mutate an execution. The server rejects a requester with the same immutable
principal subject as the current holder, even from another session or tab.
After the current controller approves the exact request,
the requester shall receive a responsibility acknowledgement naming the server,
satellite, active executions, prompts, alarms, commands, and unresolved effects.
Only that named requester may submit the request-bound acknowledgement. This is
the sole post-approval control-authority settlement admitted from Monitoring;
it has no direct runtime or procedure mutation path and can create authority
only through the atomic transfer. No Execution controls appear until the
committed transfer event names this session and client key as the new holder.

### 4.3 Edit Workspace

The Edit workspace shall provide a project tree, source and dictionary editors,
outline, TM/TC catalog references, dependency view, Problems view, diff,
history, review status, and validation reports. Parsing and analysis shall
never execute procedure source or require a live GCS.

The editor shall make the active repository, branch, base commit, working
revision, language profile, and validation state visible. It shall never edit
the source bundle of a loaded or running execution. See
[Authoring and Git](../procedures/AUTHORING_AND_GIT.md).

### 4.4 History and Replay

Authorized users shall be able to reconstruct an execution from persisted
events without contacting a driver. Replay shall be visually distinct from
live operation, include the original bundle digest and configuration identity,
and disable all operational commands. Moving a replay cursor shall not change
server state.

## 5. Operational Presentation

### 5.1 State and Ownership

Procedure state and infrastructure health are separate fields. Driver states
such as `READY` or `FAILED` shall not be rendered as procedure states.
Control ownership shall identify the current controller in a privacy-preserving
form, lease health, and whether a handover is pending.

Permanently unauthorized actions shall be absent. Actions authorized by role
but temporarily invalid because of mode, lease ownership, state, revision,
freshness, approval, or acknowledgement shall be disabled with a programmatic
and visible reason. The server independently evaluates every request; changing
markup, calling an endpoint directly, or replaying a prior enabled state cannot
gain authority.

The handover UI shall present four distinct durable stages: requested, approved
by current controller, responsibility acknowledged by requester, and
transferred. Current-controller approval names the requester. The requester
acknowledgement follows approval and cannot be pre-authorized. One immutable
authoritative-database-time deadline, clamped to the remaining lease lifetime
when the request is created, governs every stage and is not reset by approval,
retry, or acknowledgement. On the committed transfer event, the requester
workspace automatically enters Execution Mode and
the former holder immediately enters Monitoring Mode or another server-returned
non-control mode. Controls remain disabled during event-gap recovery, and stale
former-holder requests are rejected by lease and fence checks regardless of UI
latency.

Forced takeover controls are absent while `OD-006` or `OD-019` remains open.
Their later presence requires the dedicated authorization, recent-authentication,
approval, reason, notification, safe-hold, and review policy accepted by the
named human authorities.

The application shall map legacy procedure states, including `UNINIT`,
`LOADED`, `RUNNING`, `WAITING`, `PROMPT`, `PAUSED`, `ERROR`,
`ABORTED`, `FINISHED`, `RELOADING`, `INTERRUPTED`, and `UNKNOWN`, to
the approved modern state machine. It shall not infer state from log text.

### 5.2 Source and Data

Source lines shall be addressed by immutable bundle digest, document identity,
and parser-assigned source span. A stale editor buffer shall never be used to
explain a running procedure.

Compound values shall be expandable with type, scope, revision, and update
time. Sensitive values shall be redacted by the server. Redaction markers shall
be distinguishable from null, empty, unavailable, and stale values.

### 5.3 Commands

Every command submission shall show:

- command name, target, and parameters before submission;
- whether a confirmation, reason, dual approval, or step-up authentication is
  required;
- submitting identity and UTC time;
- accepted command identifier and expected target revision;
- progress, final outcome, and any effect uncertainty.

The UI shall prevent accidental duplicate submission while a request is in
flight. Retries shall reuse the original idempotency key. A network timeout
shall display `EFFECT_UNKNOWN` until the command resource is reconciled; it
shall not imply failure or resend automatically.

Abort, skip, goto, reload, recovery, forced takeover, alarm suppression, and
other policy-designated critical actions require a consequence-specific
confirmation and a reason. Confirmation text shall name the satellite,
execution, and requested transition. Generic confirmations such as "Are you
sure?" are insufficient.

### 5.4 Prompts and Alarms

A prompt shall display its procedure, source location, type, allowed response,
default and precedence, deadline, scope, and response state. Validation occurs
on the server and is repeated client-side only for immediate feedback.

Critical alarms, control loss, stale state, uncertain command effects, rejected
responses, and recovery-required states shall be latched until the server
records a terminal disposition. Transient toast notifications are not an
adequate presentation for these conditions.

## 6. Responsive Behavior

The application shall support qualified desktop, tablet, and mobile viewport
profiles without horizontal page overflow or overlapping controls.

| Profile | Required behavior |
| --- | --- |
| Desktop | Simultaneous navigation, primary workspace, context, and event views; keyboard-first operation |
| Tablet | Primary workspace remains full fidelity; navigation and context become independently opened panels; critical status remains fixed |
| Mobile | Monitoring and prompt workflows remain usable; one operational pane is shown at a time; critical status and mode remain fixed; destructive controls require the same policy as desktop |

Responsive adaptation shall not remove a warning, change command meaning, or
convert a labeled critical action into an ambiguous icon. A deployment may
prohibit Execution Mode on an unqualified device profile; that restriction is
server policy and shall be explained before control acquisition.

Touch targets shall be at least 44 by 44 CSS pixels where practical. Dense
tables shall provide column selection and an accessible detail view rather than
shrinking text below the approved minimum.

## 7. Accessibility and Human Factors

The delivered application shall meet
[WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/) and the mission's approved
accessibility test plan. At minimum:

- all workflows are keyboard operable with logical focus order and visible
  focus;
- landmarks, headings, tables, dialogs, validation errors, and live regions
  have correct accessible semantics;
- state, severity, ownership, and freshness do not rely on color alone;
- text and non-text contrast meet the applicable success criteria;
- zoom to 200 percent and reflow do not hide controls or critical state;
- motion respects reduced-motion preferences and is never the only alarm cue;
- time-limited prompts expose their deadline and follow approved extension
  policy;
- screen-reader announcements are rate-limited and prioritize critical
  transitions over high-rate telemetry.

User preference changes shall not suppress required alarms or audit facts.

## 8. Connectivity and Degraded Operation

The shell shall expose these connection conditions as text and symbol:

| Condition | Meaning | Required interaction |
| --- | --- | --- |
| Synchronizing | Snapshot or gap recovery is in progress | Mutations disabled |
| Live | Cursor is contiguous and data age is within policy | Mode-authorized interactions enabled |
| Delayed | Stream is contiguous but exceeds the warning age | Mutations policy-controlled; warning latched |
| Gap detected | One or more committed events are missing | Mutations disabled; automatic resynchronization |
| Offline | No authenticated control-plane connection | Cached data marked stale; all mutations disabled |
| Reauthorization required | Session or stream credential is no longer valid | Sensitive content cleared according to policy; mutations disabled |

The client may retain non-sensitive presentation state locally. It shall not
treat browser storage as an operational checkpoint or queue state-changing
commands for later delivery.

## 9. Client Security Boundary

- Content Security Policy, trusted types where supported, strict output
  encoding, CSRF defenses, origin checks, and dependency integrity controls are
  required.
- Authentication tokens shall be held using the approved session design and
  shall never be placed in query strings or application logs.
- WebSocket traffic, subscription delivery, automatic lease renewal, and other
  background activity shall not count as human activity or silently extend the
  browser session. Only interactions selected by the approved session policy
  may reset inactivity, and the UI shall warn before expiry.
- Procedure source, logs, telemetry, and operator text are untrusted content
  and shall never be interpreted as HTML or executable script.
- The browser shall receive neither driver credentials nor routable internal
  driver addresses.
- Authorization decisions and redaction are made by the server.
- Clipboard, file export, printing, and screen-capture controls follow the
  system CUI handling policy; the UI shall label exported artifacts with
  provenance and classification metadata supplied by the server.

## 10. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `WEB-013` | A user can always identify mission, satellite, server, environment, identity, mode, control owner, connection state, and data age. |
| `WEB-014` | Execution, Monitoring, Edit, and Replay views never conflate authoritative runtime state with editor or cached state. |
| `WEB-015` | Multiple executions of one definition remain independently selectable and carry stable identities. |
| `WEB-016` | Each mutation displays durable submission and terminal settlement, including an explicit unknown outcome. |
| `WEB-017` | Critical actions name their target and consequence, collect required reasons or approvals, and are audited. |
| `WEB-018` | Offline, stale, delayed, synchronizing, gap, and reauthorization states are visually and programmatically distinct. |
| `WEB-019` | Desktop, tablet, and mobile test matrices complete without overlap, loss of critical state, or changed command semantics. |
| `WEB-020` | WCAG 2.2 AA automated and manual checks pass for all critical workflows. |
| `WEB-021` | Security tests prove that browser content cannot reach a driver directly and that untrusted text is not executable markup. |
| `WEB-022` | Replay can reconstruct an as-run view from persistence while all operational commands remain disabled. |

## 11. Source Basis

This specification modernizes the operator and development workflows described
in the SPELL GUI User Manual 2.4.4 and Development Environment Manual 2.4.4.
The evidence and known limitations are recorded in
`../../SPELL_DOCUMENTATION_REVIEW.md` at the project root. Visual similarity to
the legacy desktop application is not required; observable operational
semantics and safety-relevant information are.
