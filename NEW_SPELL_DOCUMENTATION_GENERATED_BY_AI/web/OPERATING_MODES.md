# Operating Modes and Control Ownership

## 1. Purpose

This document defines Execution, Monitoring, and Edit modes and the exclusive
control protocol for one SPELL server. A SPELL server is the control authority
for one satellite control domain. It may execute multiple procedures
concurrently, but at most one authenticated client session holds interactive
execution control for the server at a time.

## 2. Three Separate Concepts

The implementation shall not conflate:

1. **Role and permission**: what an authenticated subject is allowed to do.
2. **Workspace mode**: which user interface and API surface the subject has
   selected.
3. **Control lease**: temporary, fenced authority to issue interactive runtime
   commands to one SPELL server.

An operator role does not itself confer control. Selecting Execution Mode does
not confer control. Only a valid server-issued lease and
`control_fencing_token` allow a runtime mutation. This implements `MODE-013`
and `MODE-014`.

### 2.1 Startup Mode Decision

After authentication and before a workspace is rendered, the server shall
return a server-signed authorization projection containing the
principal ID, effective role and attribute set, permitted modes, mode-specific
capabilities, policy revision, domain and environment scope, decision time and
expiry, and any controller lease bound to the same session and client key. The
browser shall render only from that projection and shall not derive permissions
from token labels or role names. The approved algorithm, purpose-separated key,
trust root, lifetime, and rotation remain Phase-entry decisions under `OD-005`.

The versioned startup policy shall apply these rules in order. A lease is never
evaluated as an alternative to current authorization:

1. A valid `ACTIVE` lease already bound to the same subject, session, domain,
   and client key opens Execution Mode with active authority only when current
   authentication, revocation, assurance, Controller eligibility, attributes,
   domain/environment scope, policy revision, assignment, authority
   incarnation, current-lease pointer, state, expiry, and fence checks also
   pass. A stale or revoked authorization decision invalidates this path; the
   lease cannot elevate the principal or override a restriction.
2. With exactly one permitted primary role and no more restrictive policy
   override, the baseline role mapping applies: Controller opens the Execution
   workspace, Monitoring opens the Monitoring workspace, and Developer opens
   the Edit workspace. A Controller without an active lease sees Execution in
   an explicit non-authorizing `AWAITING_CONTROL` state; the user may acquire
   an available lease or switch to Monitoring to request handover.
3. Multiple permitted modes use the policy's declared safe default or require
   an explicit choice from the returned set. Until a default is approved, the
   server shall require that explicit choice. It may recommend Monitoring, then
   Edit, for presentation, but a recommendation is not a selected mode or an
   authorization decision. Merely opening Execution never manufactures control.
4. An approved domain, environment, device, or incident restriction may select
   a more restrictive permitted mode or deny entry, but shall never elevate
   authority. The response shall identify the governing policy revision and a
   stable reason code.
5. No permitted mode denies application entry with a stable authorization
   result and correlation ID.

Representative capability mapping is explicit: Monitor permits authorized
observation; Controller permits Execution eligibility and lease workflows;
Procedure Developer permits Git-backed Edit workflows. A principal may hold
more than one role, but each request is evaluated within the selected mode.
Excluded capabilities from another role or workspace are not merged into the
current workspace. Switching mode does not acquire control, answer a prompt,
or grant Git write or promotion authority. These rules implement `MODE-023` and
`MODE-024`.

## 3. Mode Contract

| Mode | Purpose | Runtime reads | Runtime mutations | Source mutations |
| --- | --- | --- | --- | --- |
| Execution | Active operation of procedures for one satellite | Yes | Yes, only with permission and active control lease | No |
| Monitoring | Read-only observation of live and historical state | Yes, subject to data policy | Never; the bounded request/approval/acknowledgement transfer workflow is control-authority metadata, not a runtime mutation | No |
| Edit | Procedure development and validation | Only explicitly opened read-only context | Never | Yes, through Git workflow |

The same subject may be authorized for multiple modes, but permissions and lease
checks apply to each request and client instance independently. A user-selected
mode change is explicit, visible, and audited. The only automatic changes are
the authoritative post-transfer projections defined in Section 6. Opening Edit
Mode shall not grant execution access; opening Monitoring Mode shall not acquire
or renew a lease.

## 4. Execution Mode

Execution Mode may expose start, stop, pause, resume, step, skip, goto, reload,
abort, recover, prompt response, operator input, scheduling, and user-action
commands when each command is supported by the procedure state machine and
policy.

Every runtime mutation shall include:

- subject and authenticated session identity;
- target `domain_id`, `satellite_id`, `authority_incarnation_id`, and, where applicable,
  `execution_id`;
- `lease_id`, expected `lease_revision`, and current
  `control_fencing_token`;
- a client-instance proof bound to the canonical request;
- expected resource revision;
- unique idempotency key;
- command-specific parameters and reason;
- recent-authentication or approval evidence when policy requires it.

The server validates all fields atomically with command acceptance. A browser
cannot make an otherwise invalid transition valid.

## 5. Exclusive Control Lease

### 5.1 Lease Resource

The server shall persist immutable control-lease grant records plus a domain
current-lease pointer. Each grant contains:

| Field | Meaning |
| --- | --- |
| `domain_id` | Stable SPELL Satellite Control Domain identity |
| `satellite_id` | Satellite bound to that control domain |
| `authority_incarnation_id` | Current non-reusable command-authority incarnation |
| `lease_id` | Unique lease instance |
| `holder_subject_id` | Authenticated human controller |
| `holder_session_id` | Single client session allowed to use the lease |
| `holder_client_instance_id` | Single tab-local client instance |
| `holder_client_key_thumbprint` | Public-key thumbprint for request proof of possession |
| `issued_at` and `expires_at` | Server-clock lease interval |
| `heartbeat_deadline` | Latest acceptable renewal time |
| `control_fencing_token` | Monotonically increasing ownership epoch |
| `state` | `ACTIVE`, `HANDOVER_PENDING`, `RELEASED`, `EXPIRED`, `REVOKED`, or `TRANSFERRED` |
| `lease_revision` | Optimistic concurrency revision for every lease-state change |
| `acquisition_reason` | Audited operator reason |
| `handover_request` | Optional request ID, requester subject/session/client key, reason, request time, deadline, and policy revision |
| `handover_approval` | Optional current-holder approval ID, subject/session/client key, decision time, and request digest |
| `responsibility_acknowledgement` | Optional requester acknowledgement ID, time, context digest, and request-bound proof |
| `pending_holder` | Optional authenticated handover recipient bound by the request |

`AVAILABLE` is a derived domain projection meaning that the current-lease
pointer names no unexpired `ACTIVE` or `HANDOVER_PENDING` grant. It is never a
grant state. The database transaction that acquires or transfers a lease shall
prove that no other current grant exists. Each successful acquisition,
completed normal handover, forced takeover, or reacquisition creates a new
lease identity and increments `control_fencing_token`. Renewal and
handover-request metadata transitions advance `lease_revision`; only
current-holder approval changes `ACTIVE` to `HANDOVER_PENDING`. Release,
expiry, and revocation also change state and revision. None of these
non-transfer transitions consumes a fence. Fence values never decrease or
repeat within an `AuthorityIncarnationId`; a new incarnation prevents reuse
after restore.

### 5.2 Fencing

All runtime command handlers, execution supervisors, and effect dispatch paths
shall reject an inactive, expired, wrong-lease, wrong-incarnation, or stale-
fence request. Long-running operations revalidate current lease state, expiry,
lease identity, holder binding, `control_fencing_token`, and
`AuthorityIncarnationId` before each new human-authorized external effect. A
renewal or non-authorizing handover-request metadata revision does not invalidate
an already accepted command when all authority facts remain current. Current-
holder approval changes the lease to `HANDOVER_PENDING` and therefore blocks
the effect. A stale controller may receive delayed network traffic but cannot
mutate state.

Command acceptance requires the exact expected lease revision and records it.
Final-effect validation records both that accepted revision and the then-current
revision, but does not require them to be equal when only a benign renewal or
non-authorizing request-metadata transition advanced the current revision. It
still requires the same current lease, holder/session/client key, `ACTIVE`
state, unexpired interval, authority incarnation, and fence. Holder approval or
any authority change therefore rejects the effect independently of revision
equality.

Before requesting the startup projection, the tab generates a non-exportable
ephemeral signing key through WebCrypto and proves possession by signing a
single-use, server-issued challenge bound to its authenticated session,
client-instance ID, intended domain, origin, and expiry. The server registers
the verified public key under a server-issued key ID and retains its thumbprint;
lease acquisition reuses that exact key-ID/public-key/thumbprint binding.
A later projection may include an existing lease only when it is requested by
the same surviving tab, session, and key. A reload or second tab with a new key
cannot recover or use the old lease.

Each mutation carries a proof over method, resource, canonical body digest,
idempotency key, server nonce, and issued time. The server resolves the verified
public key by key ID, checks its thumbprint against the lease, verifies the
signature, and enforces single-use nonce and clock bounds.
The private key remains in tab memory and is never placed in cookies, browser
storage, a service worker, a URL, or a cross-tab channel. This proof limits
credential copying; it does not replace XSS prevention, session security, or
device assurance. A second tab can monitor; it can request handover only when it
belongs to a different eligible principal. A same-subject tab cannot request
handover or act with the first tab's lease.

### 5.3 Renewal and Loss

The holder renews the lease over an authenticated server command, not merely by
maintaining a WebSocket. The server clock is authoritative. Renewal intervals
and lease duration are deployment parameters with tested lower and upper
bounds.

Automatic lease renewal, WebSocket traffic, subscription delivery, and other
background activity shall not by themselves reset the human-session inactivity
timer. The approved identity/session policy defines which explicit human
interactions count as activity and shall warn before session expiry without
silently extending authentication.

When renewal fails or the session is revoked:

1. The lease becomes expired or revoked and its `lease_revision` advances; its
   previously issued fence is invalid because the lease is no longer `ACTIVE`.
2. No new operator-directed external effect may begin under the old token.
3. Procedures reach the configured control-loss safe point. The default is a
   durable `SUSPENDED` state with `hold_reason=CONTROL_LOST` and a recorded
   resume target before the next operator-dependent or external effect; an
   already committed atomic operation is reconciled, not resent.
4. Monitoring remains available if authorization and the control plane remain
   healthy.
5. An eligible operator may acquire a new lease and make an explicit,
   audited resume or recovery decision.

Autonomous safety behavior approved in the procedure policy may continue
without an interactive controller, but it uses system authority, is bounded in
advance, and is not represented as a human lease.

## 6. Acquisition, Handover, and Takeover

| Transition | Preconditions | Result |
| --- | --- | --- |
| Acquire available control | Eligible role, qualified session/device/client key, no active lease, reason supplied | New active lease and incremented fence |
| Request handover | Controller-eligible requester is currently in Monitoring Mode; active holder exists; requester proof, expected revision, reason, and deadline validate | Lease remains `ACTIVE`; one non-authorizing named request is recorded and the current holder is notified |
| Approve handover | Current holder proof, matching request, expected revision, requester eligibility, and deadline validate | Lease becomes `HANDOVER_PENDING`; new effects are blocked and the requester is asked to acknowledge responsibility |
| Acknowledge responsibility and transfer | Named requester proof and context-specific acknowledgement follow the current-holder approval; request, approval, lease, authority, and deadline remain current | One transaction makes the old grant `TRANSFERRED`, creates and installs the new `ACTIVE` grant with a higher fence, and commits the mode projections, audit, and outbox rows; external publication follows commit |
| Withdraw/decline/cancel/expire request | Current holder or named requester as applicable, or authoritative deadline | Request fields clear; the existing lease returns to `ACTIVE` without changing its fence only if it remains unexpired and authorized, otherwise expiry/revocation wins and the pointer clears |
| Release | Current holder, expected revision | Grant becomes `RELEASED`, current pointer clears to the `AVAILABLE` projection, revision advances, and fence is not reused |
| Administrative or trusted-event revocation | Dedicated permission or authenticated identity/authority event, expected revision where applicable | Grant becomes `REVOKED`, current pointer clears, and control-loss policy applies |
| Forced takeover | Disabled while `OD-006` or `OD-019` is open; when enabled, dedicated permission, recent authentication, reason, and every approval required by the accepted policy | Old grant becomes `TRANSFERRED`; a new `ACTIVE` grant and higher fence are issued atomically, affected executions remain safely held until acknowledged, and the event is independently notified and reviewed |
| Expire | Renewal deadline passes | Grant becomes `EXPIRED`, current pointer clears, and control-loss policy applies without reusing its fence |

Handover is never implemented by sharing a credential. It follows one ordered
request identified by `HandoverRequestId`:

1. A user in Monitoring Mode who also has the effective Controller capability
   and a different immutable principal subject from the current holder submits
   the named request. This dedicated control-plane write cannot start,
   stop, modify, acknowledge, or otherwise affect a procedure and grants no
   lease authority. The request records one immutable authoritative-database-
   time deadline, clamped to the remaining lease lifetime, that approval,
   retries, and acknowledgement never reset. The old lease remains `ACTIVE`.
2. The current controller alone approves the exact request using its bound
   session, client key, proof, and expected lease revision. Approval records the
   holder identity and trusted database time and moves the lease to
   `HANDOVER_PENDING`, which admits no new external effect.
3. The requester reviews and acknowledges the current server, satellite,
   active executions, alarms, prompts, outstanding commands, and
   `EFFECT_POSSIBLE` or `EFFECT_UNKNOWN` operations. The acknowledgement states
   that the requester accepts controller responsibility and is bound to the
   request, current projection digest, session, and client key. This is a
   narrowly authorized control-authority settlement from Monitoring, not a
   general Monitoring write or a runtime/procedure mutation.
4. The acknowledgement command atomically records the acknowledgement, marks
   the old grant `TRANSFERRED`, creates one new `ACTIVE` grant with a new ID and
   higher fence, and replaces the domain current-lease pointer. No intermediate
   state has two controllers.
5. The committed transfer event selects Execution Mode for the new holder and
   immediately selects Monitoring Mode for the former holder when permitted, or
   another server-selected non-control mode when Monitoring is not permitted.
   The server rejects the former holder's stale lease even before either browser
   consumes the event.

Request submission, holder approval, responsibility acknowledgement, and atomic
transfer use independent request-bound proofs and are never inferred from a
WebSocket connection or UI state. Cancellation, withdrawal, decline, expiry,
authorization loss, session loss, or revision conflict cannot create a
successor grant.

Forced takeover remains disabled until `OD-006` and `OD-019` approve its
dedicated authorization, recent-authentication, approval, reason, notification,
and review policy. When enabled, it shall not imply that an uncertain effect
failed. The new controller sees every unresolved command and must reconcile it
before a conflicting effect can be dispatched.

## 7. Monitoring Mode

Monitoring Mode is strictly read-only for procedure and runtime resources:

- no start, pause, resume, stop, abort, skip, goto, recovery, prompt response,
  operator input, acknowledgment, alarm suppression, scheduling, lease renewal,
  or hidden write is permitted;
- favorites and layout preferences may be stored in a separate user-preference
  service and shall not mutate the SPELL server or execution;
- exports are reads governed by data-handling and audit policy;
- read authorization and field redaction still apply.

The sole exception is the bounded handover workflow in Section 6. An eligible
user may submit, withdraw, or decline one non-authorizing control request. After
durable current-holder approval, only the named requester may submit the exact
request-bound responsibility acknowledgement; that command may create authority
only by atomically completing the transfer in Section 6. These operations have
no independent path to an execution, prompt, variable, alarm, driver, or effect.
Every other Monitoring Mode mutation is denied server-side even if a hidden API
is called directly.

The phrase "unlimited monitoring users" means the product imposes no licensing
or hard-coded monitor count. It cannot mean infinite physical capacity. Each
deployment shall publish and qualify concurrent-session, event-rate, replay,
latency, and reconnect-storm limits. Read replicas, event gateways, and
horizontal fan-out may scale monitoring without transferring control authority.
When capacity is reached, the service returns an explicit retryable response
and preserves active execution.

## 8. Edit Mode

Edit Mode permits repository-backed source operations to authorized developers.
It shall not:

- acquire or renew execution control;
- answer a runtime prompt;
- write runtime variables, telemetry, or resources;
- modify a promoted bundle or a running execution;
- execute arbitrary procedure source in the browser or language service;
- use a live driver or GCS for parsing or static validation.

Simulation is initiated as a separately authorized execution of an immutable
candidate bundle in a non-operational environment. It does not grant production
control.

## 9. Role and Permission Baseline

Deployments may add roles, but the following capabilities remain separate.
The labels in this table are presentation terms. Canonical role identifiers and
aliases remain pending in the G0 identity/session decision package and shall not
be frozen into a product schema before approval.

| Capability | Monitor | Operator | Procedure developer | Control supervisor | Security administrator |
| --- | ---: | ---: | ---: | ---: | ---: |
| Observe permitted live data | Yes | Yes | Optional | Yes | Policy |
| Acquire available control | No | Yes | No | Only with separate Controller capability | No |
| Request or acknowledge handover while Monitoring | Only with separate Controller capability | Yes, under the named request state | Only with separate Controller capability | Only with separate Controller capability | No |
| Force takeover | No | No | No | Disabled until approved policy grants it | No |
| Respond to prompts | No | With active lease | No | Only with separate Controller capability and active lease | No |
| Edit procedure source | No | No | Yes | No | No |
| Approve procedure change | No | Only with a separately assigned reviewer role | Only with a separately assigned reviewer role | Only with a separately assigned reviewer role | No |
| Promote bundle | No | Only with a separately assigned Release Manager role | Only with a separately assigned Release Manager role | Only with a separately assigned Release Manager role | No |
| Change identity/security policy | No | No | No | No | Yes |

No role may approve its own change when separation-of-duties policy requires an
independent reviewer. A multi-role assignment does not union excluded workspace
capabilities: the selected mode, resource policy, lease, session, and client
proof are evaluated for every request. Control Supervisor is an independent
oversight role and receives no Controller, reviewer, or release capability
unless that separate role is also assigned. Service identities are not human
roles.

## 10. Audit Events

Startup mode decision; lease acquisition; renewal failure; handover request,
holder approval, requester responsibility acknowledgement, withdrawal, decline,
cancellation, expiry, and atomic transfer; release; revocation; forced takeover;
automatic or user-selected mode change; rejected stale token; and rejected
monitor mutation shall produce append-only audit events.

Each source event includes a common envelope with event/schema ID, trusted
service event time, actor type, action, target/scope, outcome, reason, request
and correlation IDs, and software/configuration identity. Authenticated
subject or service identity, session, client key, effective roles/attributes,
policy revision, server/domain/satellite/environment, mode, lease, fence, and
request/approval/acknowledgement fields appear only in the event-specific
extensions where they apply. Ownership-change events identify both the former
holder and requester. Secret acknowledgement content is represented by an
approved safe digest, not copied into generic audit text. The independent sink
creates a separate receipt containing its ingestion time and identity, bound to
the source event ID and digest.

Authoritative state, the local durable audit record/admission, and the outbox
row commit in one PostgreSQL transaction for a successful handover transition.
External publication and independent-sink ingestion occur only after that
commit and are not represented as one distributed transaction. An authenticated
startup allow and every handover success or rejection that requires audit shall
fail closed when the required local durable audit handoff cannot accept the
event, subject only to an approved emergency operating policy. An authentication
denial always remains denied and uses the approved fallback audit path and
alerting when normal admission is degraded.

Every successful lease renewal retains durable per-renewal identity, prior and
new revision, prior and new expiry, time, outcome, reason, and correlation
evidence. User interfaces and exports may summarize that retained evidence, but
the authoritative renewal records are not sampled. Failures and ownership
changes are never sampled.

## 11. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `MODE-013` | Tests prove that role, selected mode, and lease authority are independent decisions. |
| `MODE-014` | At most one active lease exists per SPELL server under concurrent acquisition, failover, retry, and database contention. |
| `MODE-015` | A stale `control_fencing_token` is rejected at command acceptance and before every newly initiated external effect. |
| `MODE-016` | Explicit handover changes session-bound authority without sharing credentials and preserves unresolved-effect visibility. |
| `MODE-017` | Loss, expiry, and revocation drive procedures to approved safe behavior and leave an auditable record; forced takeover remains disabled until its dedicated policy is approved and then follows the same safe-hold and audit rules. |
| `MODE-018` | Every Monitoring Mode runtime or procedure mutation is denied server-side; only eligible request submission, withdrawal, decline, and the named requester's post-approval responsibility acknowledgement in the bounded `MODE-025`/`MODE-026` control-authority workflow are allowed. |
| `MODE-019` | Edit Mode cannot change deployed/running source or reach an operational driver. |
| `MODE-020` | The monitoring service has no product-imposed user cap and passes the deployment's declared capacity and reconnect-storm tests. |
| `MODE-021` | A lease is bound to one authenticated session and non-exportable client-instance proof key and cannot be reused from another tab, device, server, or request context. |
| `MODE-022` | Reacquisition requires acknowledgement of active executions, prompts, alarms, and uncertain effects before resume. |
| `MODE-023` | At authenticated startup, the server returns effective capabilities and permitted modes; the single-role baseline mapping applies without granting control, and an existing lease activates Execution only after every current authentication, policy, scope, assignment, pointer, session, key, state, expiry, and fence check passes. |
| `MODE-024` | For a multi-role principal, the server shall evaluate authorization within the selected mode without merging excluded capabilities from another role or mode, and a mode change shall not grant a controller lease or repository authority. |
| `MODE-025` | A controller-eligible Monitoring principal may create one non-authorizing request for a different immutable subject under one immutable lease-bounded database-time deadline; transfer requires current-holder approval followed by the named requester's request-bound acknowledgement. |
| `MODE-026` | Accepted handover atomically terminalizes the old grant, creates and installs one new `ACTIVE` higher-fence grant, commits local audit and outbox rows, records both authoritative mode projections, and publishes only after commit. |
| `MODE-027` | Startup mode decisions and every handover stage or rejection produce append-only evidence with the source-event common envelope, every event-applicable identity/session/key/policy/scope/request/lease/fence field, trusted source time, reason, outcome, correlation, and a linked independent-sink ingestion receipt; inapplicable fields are never fabricated. |
