# Satellite Assignment Authority

## Purpose

This document defines the mission-wide Satellite Assignment Authority (SAA).
The SAA is the authority that prevents two SPELL clusters or sites from holding
command authority for the same `SatelliteId` at the same time. Local database
leadership and controller leases remain necessary, but neither can establish
mission-wide exclusivity after a site partition, backup restore, failover, or
domain relocation.

The SAA is part of the command authorization boundary. It is highly available
across independent failure domains, uses a linearizable assignment ledger, and
issues signed, short-lived grants. The Effect Authorization Point (EAP) is the
only component that holds a GCS effect credential or effect-capable GCS egress.
Loss of the SAA or EAP may reduce availability, but shall not create two command
paths.

## Scope And Non-Goals

The SAA governs activation of a Satellite Control Domain for one satellite. It
is consulted during initial activation, transfer, failover, restore, failback,
credential renewal, and revocation. It does not:

- schedule or execute procedures;
- replace the domain leader epoch or human controller lease;
- transport telemetry, procedure events, or routine commands;
- decide whether a command is operationally appropriate; or
- infer that a legacy GCS path is fenced from a SPELL process health report.

Driver hosts translate typed adapter operations but call the EAP, not the GCS.
The EAP is the final authorization and dispatch boundary for every externally
effecting attempt.

Monitoring, authoring, validation, backup inspection, and reconciliation that
cannot cause an external effect may continue without an active command grant,
subject to ordinary authorization and freshness labels.

## Safety Invariants

1. The authoritative ledger shall contain at most one `effect_enabled=true`
   authority record for a `SatelliteId`. This invariant includes `ACTIVE` SPELL
   grants and adopted pre-SAA legacy command paths in every cluster and site.
2. An `ACTIVE` assignment shall bind one `MissionId`, `SatelliteId`, `DomainId`,
   `AuthorityIncarnationId`, `assignment_generation`, site, cluster, workload
   identity, EAP identity, and approved effect boundary.
3. `assignment_generation` shall increase monotonically for each `SatelliteId`
   and shall never be reused, including after point-in-time restore.
4. `AuthorityIncarnationId` shall be globally unique and shall never be reused.
   A new activation, transfer, restore, failback, or replacement command path
   shall receive a new value.
5. No candidate shall receive an active command grant until the prior command
   path is externally fenced or proven never to have become active.
6. If the prior path cannot be fenced with acceptable evidence, every candidate
   shall remain read-only.
7. A signature proves grant integrity and issuer identity; it does not prove
   that an expired, revoked, superseded, wrong-audience, or stale grant remains
   authorized.
8. Every effecting request shall be rejected unless its complete authority
   tuple wins both a linearizable one-use SAA attempt-permit consume and an
   atomic primary-PostgreSQL dispatch-permit consume at the EAP immediately
   before effect.
9. Restoring a SPELL database, site snapshot, virtual machine, or local secret
   shall not restore command authority.
10. Network partition policy shall be fail-closed for new activation and grant
    renewal. There is no autonomous partition-side preference or last-writer
    rule.
11. `DRAINING` shall mean `effect_enabled=false`. It permits settlement and
    reconciliation only and shall have no policy exception for a new external
    effect.
12. Apparent loss, unreachability, failed health checks, or presumed destruction
    of a prior site shall never substitute for independent external fence proof.

## Authority Tuple

The complete command-authority tuple is:

```text
MissionId
SatelliteId
DomainId
AuthorityIncarnationId
assignment_generation
assignment_grant_id
assignment_grant_revision
grant_not_before / grant_expires_at
site_id / cluster_id / workload_identity
EffectAuthorizationPointId / effect_boundary_id / authorization_audience
LeaderEpoch
ControllerLeaseId / ControlFencingToken when human control is required
DriverHostGeneration / DriverBindingId / ContextGeneration
ExecutionAttachmentGeneration
OperationId / AttemptId / canonical request digest / attempt deadline
saa_attempt_permit_id / dispatch_permit_id / dispatch_permit_revision
```

The SAA governs the tuple through `assignment_grant_revision`. PostgreSQL
leadership, controller leasing, and driver lifecycle components govern their
respective inner fences. Possession of one fence never substitutes for another.
Every command journal, EAP permit record, and audit record shall retain the
complete applicable tuple so a reviewer can prove which authority won the
dispatch race and was presented at the effect boundary.

## Authority Architecture

### Mission-Wide Placement

One logical SAA serves a `MissionId` across every site and cluster that could
reach a command effect boundary. It shall run as a quorum service across at
least three independent failure domains in profiles that claim site-failure
tolerance. Quorum membership, failure-domain independence, latency limits, and
recovery objectives are deployment-profile inputs, not hidden product defaults.

The assignment ledger shall provide linearizable compare-and-set operations by
`SatelliteId`. A consensus-backed relational or key-value implementation is
acceptable when it preserves the transaction, history, backup, signing, and
verification requirements in this document. An eventually consistent cache,
DNS record, Kubernetes lease, object-store marker, or individual site's SPELL
database is not sufficient authority.

Every command-capable deployment also provides one logical EAP service. The EAP
may have passive instances, but only its current assignment-bound workload
identity can use the satellite's effect credential and egress route. Driver
hosts have neither. The EAP uses a narrowly authorized PostgreSQL role that can
execute the dispatch-permit transaction and no general application query.

SAA signing keys shall be non-exportable where the approved key service
supports that property. Verification keys, key identifiers, algorithms,
validity periods, and revocation status shall be distributed through a
versioned trust bundle. Signing-key rotation shall support bounded overlap and
shall not extend an assignment's expiry.

### High-Water Protection

The assignment ledger is independent of SPELL operational backups. For each
`SatelliteId`, the SAA retains the greatest allocated `assignment_generation`
in quorum-replicated durable state. A separate non-rollback generation anchor
shall retain the authoritative high-water value outside both SPELL and SAA
restore domains. The anchor shall provide a linearizable compare-and-advance
operation and a signed receipt binding mission, satellite, generation,
`AuthorityIncarnationId`, request nonce, anchor revision, and time.

Allocation locks the satellite ledger record, proposes the next generation,
synchronously advances the external anchor, verifies its signed receipt, and
only then commits the reserved generation, incarnation, and receipt digest. The
generation or grant shall not be returned, published, signed, or otherwise
observable before that commit. If the anchor advances but the SAA transaction
fails, that generation is permanently skipped. It is never recovered for use.

After SAA recovery or ledger restore, issuance shall remain disabled until the
service proves that its recovered high-water mark is at least the maximum of:

- every surviving quorum member;
- the latest verified external-anchor value and signed receipt;
- every non-expired or historically active signed grant in the retained grant
  ledger; and
- any external effect-boundary record retained for the satellite.

The first post-recovery allocation shall be advanced and receipted by the
non-rollback anchor at a value strictly greater than that proven maximum and
shall create a fresh `AuthorityIncarnationId`. If the anchor is unavailable,
its lineage or signature is ambiguous, or the maximum cannot be established,
the SAA shall not reserve a generation or issue a grant for the affected
satellite. Operators may restore observation services, collect evidence, and
repair the authority ledger, but shall not manually select a guessed generation.

Generation reservation and grant creation shall be one durable transaction.
An allocated generation may be abandoned, but shall never be filled later or
assigned to another incarnation.

### Components

| Component | Responsibility | Prohibited authority |
| --- | --- | --- |
| Assignment API | Authenticates activation requests and exposes grant state | Cannot bypass ledger compare-and-set or signing policy |
| Assignment ledger | Serializes generations, state transitions, legacy adoption, and one-effect-enabled-path constraint | Cannot infer external fencing from local SPELL state |
| Non-rollback generation anchor | Advances the per-satellite high-water value and signs an allocation receipt outside SAA/SPELL restore history | Cannot grant command authority or accept a caller-selected rollback value |
| Grant signer | Signs canonical grant envelopes after committed authorization | Cannot sign uncommitted or caller-supplied grant fields |
| Fence verifier | Validates evidence from an approved external fence provider | Cannot accept self-attestation by the candidate being activated |
| Credential broker | Mints grant-bound EAP workload and GCS authorization plus non-effecting driver-to-EAP identity | Cannot give a driver host a GCS effect credential or mint beyond grant scope or expiry |
| Revocation publisher | Publishes signed revocation and trust-bundle updates | Cannot make an expired grant valid |
| Domain activation agent | Persists and enforces the received grant locally | Cannot allocate a generation or declare itself active |
| Effect Authorization Point | While holding local authority rows, consumes a linearizable one-use SAA attempt permit, commits one PostgreSQL dispatch permit, then alone uses GCS effect egress | Cannot dispatch from an unconsumed, replayed, stale, abandoned, or uncertain permit |

## Assignment State Model

| State | Meaning | Effect permission |
| --- | --- | --- |
| `REQUESTED` | Authenticated activation request recorded; no generation allocated | None |
| `LEGACY_ADOPTED` | Approved inventory represents an existing pre-SAA command path by `LegacyAuthorityId`; it is the one effect-enabled record until externally fenced | Existing legacy path only; SAA issues no new effect grant |
| `RESERVED` | Fresh generation and incarnation durably allocated | None |
| `FENCING` | Old-path fence actions and evidence collection are in progress | None |
| `READ_ONLY` | Candidate may observe/reconcile but fencing or readiness is incomplete | None |
| `ISSUING` | Exact grant envelope is committed for signing after fence and readiness checks pass | None |
| `ACTIVE` | Signed grant issued after fence and readiness evidence was accepted | Only within tuple, audience, policy, and expiry |
| `DRAINING` | Effect authorization is durably disabled; consumed attempts may settle and uncertain attempts may reconcile | No new effect under any policy |
| `REVOKED` | Grant explicitly invalidated | None |
| `EXPIRED` | Grant validity ended | None |
| `ABANDONED` | Reserved generation will never activate | None |

Transitions use expected assignment revision and ledger compare-and-set. Only
`RESERVED` or `FENCING` may become `READ_ONLY`; only `FENCING` or `READ_ONLY`
may become `ISSUING`; and only `ISSUING` may become `ACTIVE`. `ACTIVE` becomes
`DRAINING` only in a transaction that sets `effect_enabled=false`, disables new
EAP permit consumption, and records credential/egress revocation work.
`LEGACY_ADOPTED` becomes `DRAINING` only after independent evidence proves every
inventoried legacy effect path fenced. `DRAINING` becomes `REVOKED` only after
all consumed attempts are settled or explicitly retained for reconciliation and
external fence evidence is committed. `REVOKED`, `EXPIRED`, and `ABANDONED` are
terminal for that grant.

`ISSUING` becomes `ACTIVE` only when the signature over the exact committed
envelope is durably attached by compare-and-set and no other record for the
satellite is effect-enabled. An `ISSUING` grant is never released to a candidate
as command authority. A target cannot become effect-enabled while an old SPELL
or legacy path remains effect-enabled, merely appears lost, or lacks accepted
external fence proof. A new activation always allocates a new generation and
incarnation.
An active token renewal may retain the generation and incarnation only when the
same holder, site, cluster, effect boundary, and security posture remain valid.

## External Fencing Contract

External fencing is evidence that the previous path can no longer cause a
command effect. The required mechanisms are determined per adapter and mission
hazard analysis. Acceptable mechanisms may include:

- effect-boundary validation of SAA grants on every command;
- EAP revocation and rotation of the exclusive GCS effect credential;
- GCS-enforced exclusive session ownership with a generation-aware takeover;
- independent network egress isolation confirmed by the network control plane;
- driver or gateway hardware interlock; or
- an approved physical or procedural isolation control when no automated
  mechanism exists.

Process termination, loss of heartbeat, local database lease expiry, an
orchestrator pod deletion, DNS change, load-balancer removal, or operator belief
is not by itself proof of an external fence. The fence evidence shall be issued
or witnessed by a system outside the candidate command path and shall include:

- `MissionId`, `SatelliteId`, and effect-boundary identity;
- `source_kind` and the source-specific SPELL or legacy identity defined below;
- target `AuthorityIncarnationId` and `assignment_generation`;
- fence mechanism and policy identifier;
- authoritative observation time and clock-quality evidence;
- provider identity, evidence ID, nonce, result, and expiry;
- digest of supporting records; and
- an integrity signature or authenticated evidence-channel reference.

The verifier shall reject missing, stale, ambiguous, replayed, wrong-satellite,
wrong-boundary, or self-issued evidence. Where an effect boundary cannot enforce
or prove revocation of the old path, automated takeover is prohibited. The
candidate remains `READ_ONLY` until independent network, credential, physical,
or procedural isolation is verified under the approved runbook.

Before collecting final fence evidence, the SAA shall reserve the target
`assignment_generation` and `AuthorityIncarnationId` through the non-rollback
anchor and create an `effect_enabled=false` `RESERVED` grant. That reservation
authorizes only readiness, reconciliation, and evidence submission; it provides
no effect permit, credential, route, controller authority, or activation right.

### Pre-SAA Legacy Bootstrap And Adoption

Before a new SPELL path can replace a command-capable system that predates the
SAA, an authorized bootstrap operation shall create a `LEGACY_ADOPTED` record.
It has a stable `LegacyAuthorityId`, `MissionId`, `SatelliteId`, effect-boundary
identity, inventory digest, inventory revision, accountable owner, adoption
time, and `effect_enabled=true`. It does not fabricate a legacy `DomainId`,
`AuthorityIncarnationId`, or assignment generation.

The reviewed inventory shall enumerate every path that can cause a GCS effect:

- client credentials, private keys, certificates, tokens, accounts, and roles;
- active, resumable, cached, and unattended GCS sessions;
- GCS endpoints, protocol routes, relays, gateways, and alternate interfaces;
- host, network, VPN, firewall, proxy, and site egress paths;
- hardware or software interlocks and exclusive-session controls;
- scheduled, queued, delayed, buffered, or automatically retried commands; and
- human operators, service identities, break-glass methods, and custody owners.

The inventory is incomplete if any credential, session, endpoint, egress path,
interlock, queue, or operator authority cannot be dispositioned. In that case no
replacement path may activate.

Fence evidence is explicitly tagged `source_kind=SPELL` or
`source_kind=LEGACY`. SPELL evidence carries the prior `DomainId`,
`AuthorityIncarnationId`, and `assignment_generation`. Legacy evidence instead
carries `LegacyAuthorityId`, exact inventory revision and digest, and one signed
disposition for every inventoried path. The fence verifier rejects a mixed,
untagged, incomplete, or stale evidence set. Apparent loss of a legacy host or
site is not a disposition.

## Activation Protocol

### Initial Activation

1. An authorized actor submits an idempotent activation request containing the
   target identities, expected current assignment revision, effect boundary,
   deployment digest, and reason.
2. The SAA authenticates the actor and candidate workload, checks policy and
   maintenance state, and reads the satellite record with linearizable
   consistency.
3. The ledger allocates a fresh `assignment_generation` and
   `AuthorityIncarnationId` only after the non-rollback anchor advances and
   returns a valid signed receipt for the exact allocation.
4. The SAA creates a `RESERVED` grant record. A provisional token permits only
   health, reconciliation, and fence-evidence submission.
5. The candidate starts non-active, denies command egress, and proves its
   deployment, configuration, time, key, database, driver, and network posture.
6. For a satellite with no prior active path, the fence verifier obtains proof
   from the effect boundary that no other authorized command session exists.
7. The SAA commits the fence evidence, activation decision, and exact grant
   envelope in `ISSUING`, then signs that committed envelope.
8. The SAA conditionally attaches the signature, verifies the satellite has no
   other effect-enabled record, transitions the same revision to `ACTIVE` with
   `effect_enabled=true`, and only then releases the signed grant. The credential
   broker issues short-lived EAP workload and GCS effect authorization bound to
   the grant tuple and no later than its expiry. A driver host receives only a
   non-effecting identity for its typed EAP channel.
9. The candidate verifies the signature and trust bundle, persists the grant,
   evidence digests, credentials' key identifiers, and activation audit record
   in PostgreSQL, then atomically marks the domain active.
10. The EAP independently checks the current grant and consumes the SAA and
    local dispatch permits in the ordered protocol before the first and every
    subsequent external effect attempt.

If a step after generation allocation fails, the generation is abandoned or
remains read-only. It is never recycled.

### Planned Cutover

1. Record an approved cutover request, hazard controls, source and target,
   rollback conditions, and maintenance window.
2. Reserve a fresh target generation and incarnation through the non-rollback
   anchor and create an `effect_enabled=false` `RESERVED` target grant. Never
   copy the source grant or its short-lived credentials; issue no target effect
   credential, route, permit, or controller authority.
3. For an SAA-native source, atomically transition `ACTIVE` to `DRAINING`, set
   `effect_enabled=false`, disable EAP permit consumption, and reject every new
   effect. For a legacy source, begin the approved external freeze and fence
   procedure while its `LEGACY_ADOPTED` record continues to block target
   activation. There is no runbook or policy exception that can effect-enable
   the target early.
4. Settle or classify every in-flight operation and persist a final source
   checkpoint and command journal export.
5. Revoke source dispatch authorization and externally fence every source
   EAP/GCS or inventoried legacy path. Bind every evidence item to the reserved
   target generation and incarnation. After complete legacy fence evidence is
   accepted, atomically transition `LEGACY_ADOPTED` to `DRAINING` with
   `effect_enabled=false`. The source cannot be a fallback after this point
   without another new assignment or legacy adoption.
6. Start the reserved target read-only, restore or synchronize state, verify integrity,
   and reconcile nonterminal operations against effect-boundary evidence.
7. Submit external fence evidence and target readiness evidence to the SAA.
8. Only after the old path is durably effect-disabled and externally fenced,
   the SAA supersedes it, transitions the reserved grant to `ACTIVE`, and issues
   one effect-enabled target grant with fresh short-lived authorization.
9. Persist and enforce the target grant before allowing admission or command
   dispatch. Verify the old path continues to reject delayed requests.

Rollback before source fencing may cancel the cutover without changing active
authority. Rollback after source fencing is a new activation with another fresh
generation and incarnation; it is not reactivation of the old grant.

### Unplanned Failover

1. Detect failure and place the candidate in read-only recovery; failure
   detection does not grant authority.
2. Read the SAA's current assignment and deny local command egress if the
   service cannot obtain a fresh, authenticated result.
3. Reserve a new generation and incarnation through the non-rollback anchor and
   create an `effect_enabled=false` `RESERVED` grant for the recovery candidate;
   issue no effect credential, route, permit, or controller authority.
4. Revoke or expire the old grant, effect-disable its EAP, and externally fence
   every old command path, including delayed driver sessions and site egress.
   Bind every fence evidence item to the reserved target tuple.
5. Restore current state from qualified replicated data or backup, then
   reconcile every nonterminal operation.
6. Activate only after the SAA verifies old-path fence evidence, recovered-state
   integrity, and candidate readiness.
7. Mint new short-lived authorization and reject all old authority tuples.

Forced failover is not an exception to fencing. If old-path isolation cannot be
proved, the recovery site remains read-only even when the primary site appears
lost.

### Point-In-Time Restore

1. Restore SPELL data and artifacts into a network state with command egress
   denied.
2. Mark every restored local assignment, leader epoch, controller lease,
   workload credential, driver session, and cached grant invalid.
3. Query the independent SAA and compare the restored command journal with the
   current satellite assignment and effect-boundary records.
4. Reconcile operations that occurred after the restored recovery point.
5. Allocate a fresh post-restore generation and incarnation from the SAA's
   non-restored high-water state.
6. Complete the normal external fencing and activation protocol.

A restored numeric leader epoch or controller fence is never evidence that the
restored site may command. Local generation values are meaningful only inside
the fresh authority incarnation.

### Failback

Failback follows planned cutover. The recovered original site is a new
candidate. It first reserves a new generation and incarnation as an
effect-disabled target without credentials, proves the currently active recovery
site externally fenced with evidence bound to that target, synchronizes and
reconciles state, and passes readiness. Only then may the SAA activate the
reserved grant and issue new credentials. No former grant, credential, driver
session, or cached authority is revived.

## Grant And Credential Lifecycle

Active grants and all derived authorization shall be short-lived. Deployment
profiles define maximum lifetime, renewal lead time, clock uncertainty, and
offline tolerance as approved parameters. A derived EAP workload or GCS effect
credential shall:

- name the grant ID and revision, generation, incarnation, satellite, domain,
  site, cluster, workload identity, audience, and allowed capabilities;
- be cryptographically bound to the intended workload key where supported;
- expire no later than the active grant;
- be revocable by grant ID, credential ID, or key ID; and
- be unusable at another effect boundary or from another network identity.

A driver-host identity authorizes only the typed driver-to-EAP interface. It is
not derivable into a GCS credential and has no effect-capable GCS network route.

Renewal is a compare-and-set update of the same active grant. The SAA rechecks
holder identity, current revision, external fence health, deployment posture,
time quality, policy, and revocation state. A missed renewal causes expiry and
effect denial. A grace period may preserve monitoring and reconciliation but
shall never preserve command effects beyond token expiry.

Revocation shall be published to every verifier and credential broker. For an
effect boundary that cannot consume revocations promptly, credential lifetime
and independent path fencing shall bound exposure. Revocation delivery latency
is a qualified safety and capacity metric.

An assignment replacement also terminates human control authority in the old
incarnation. In one PostgreSQL transition, the domain shall revoke or invalidate
the old controller lease with reason `AUTHORITY_REPLACED`, increment its lease
revision, clear the current-lease pointer, and drive affected executions to
`SUSPENDED` with `hold_reason=CONTROL_LOST` and their saved resume targets. The
new incarnation starts with no controller. Reacquisition creates a new lease
and higher control fence and requires acknowledgement of active executions,
prompts, alarms, and uncertain effects before any explicit resume.

## Persisted Evidence

Before a domain enters its local active state, one PostgreSQL transaction shall
persist:

- the canonical signed grant bytes and digest;
- issuer key ID, trust-bundle version, and signature-validation result;
- complete authority tuple and assignment revision;
- signed non-rollback anchor receipt and digest;
- external fence evidence IDs, digests, providers, and validation results;
- activation request, actor, approver, reason, and policy decision;
- local deployment/configuration digest and readiness evidence;
- credential identifiers and expiry, excluding secret material;
- database commit time and clock-quality evidence; and
- audit and committed outbox records.

The active-domain row shall reference this evidence and use compare-and-set to
exclude another local activation. The local copy supports recovery and audit;
it never overrides a newer SAA decision. Evidence retention shall cover the
mission, incident, legal, audit, and command-history periods assigned by policy.

## API Outline

All mutation APIs use mutually authenticated transport, authenticated workload
or human identity, explicit authorization, canonical request encoding,
idempotency key, expected revision, deadline, nonce, and audit correlation.

| Method and path | Purpose | Required authority |
| --- | --- | --- |
| `POST /v1/satellites/{SatelliteId}/legacy-authorities` | Adopt and inventory one pre-SAA effect-enabled command path | Legacy adoption role, accountable owner, and required approvals |
| `POST /v1/satellites/{SatelliteId}/activation-requests` | Request generation reservation and read-only candidate setup | Mission activation role and candidate workload proof |
| `POST /v1/assignments/{grant_id}/fence-evidence` | Submit independently issued fence evidence | Approved fence provider or authorized orchestration role |
| `POST /v1/assignments/{grant_id}/activate` | Commit active decision and return signed grant | Activation approver; server enforces readiness policy |
| `POST /v1/assignments/{grant_id}/renew` | Renew unchanged holder and authority scope | Current grant-bound workload identity |
| `POST /v1/assignments/{grant_id}/drain` | Stop new effects for planned transfer | Current holder or mission activation role |
| `POST /v1/assignments/{grant_id}/revoke` | Revoke active or provisional authority | Authorized revocation role; break-glass policy where applicable |
| `GET /v1/satellites/{SatelliteId}/assignment` | Return linearizable current state and signed proof | Authorized domain, verifier, auditor, or operator |
| `POST /v1/grants/introspect` | Validate exact grant, audience, tuple, and current status | Registered effect-boundary verifier |
| `GET /v1/trust-bundles/current` | Retrieve signed verification-key and revocation metadata | Authenticated platform component |
| `GET /v1/audit/assignments` | Query protected assignment evidence | Auditor or authorized incident role |

An activation response shall not return an active grant until the active state,
fence evidence, high-water update, and audit record are durably committed. A
timeout or transport failure is resolved by querying the idempotency key or
grant ID, never by assuming success or allocating a replacement implicitly.

## Canonical Grant Schema Outline

The wire schema shall use an approved enveloped or detached signature profile,
such as a constrained JWS or COSE profile, and shall be versioned and formally
published. The following JSON is a non-normative enveloped field outline; exact
types, canonicalization, and algorithms are defined by the approved interface
specification.

```json
{
  "protected": {
    "schema": "spell.assignment-grant-envelope/1",
    "algorithm": "approved-algorithm",
    "key_id": "saa-signing-key-2026-03"
  },
  "payload": {
    "issuer": "saa:mission-01",
    "mission_id": "mission-01",
    "satellite_id": "sat-001",
    "domain_id": "domain-sat-001",
    "authority_incarnation_id": "0198-example-unique-value",
    "assignment_generation": "1842",
    "assignment_grant_id": "grant-example",
    "assignment_grant_revision": 7,
    "effect_enabled": true,
    "site_id": "site-b",
    "cluster_id": "cluster-b1",
    "workload_identity": "spiffe://mission-01/spell/domain-sat-001",
    "effect_authorization_point_id": "eap-gcs-1",
    "effect_boundary_id": "gcs-adapter-1",
    "audiences": ["spell-eap", "gcs-adapter-1"],
    "capabilities": ["TC_DISPATCH"],
    "anchor_receipt_digest": "sha256:example",
    "not_before": "2026-07-18T14:00:00Z",
    "expires_at": "2026-07-18T14:05:00Z",
    "fence_evidence_digests": ["sha256:example"],
    "policy_digest": "sha256:example",
    "deployment_digest": "sha256:example",
    "nonce": "example",
    "issued_at": "2026-07-18T13:59:59Z"
  },
  "signature": "base64url-signature-over-protected-and-payload"
}
```

The signing input is exactly the profile-defined canonical encoding of
`protected` and `payload`. The `signature` member and external transport
metadata are excluded from that input; the signature therefore never signs
itself. Protected algorithm and key fields cannot be substituted by an
unprotected header. Parsers reject duplicate keys, unknown critical fields,
non-canonical encodings, unsupported algorithms, invalid time ranges, and
identifier format violations. Integer generation comparison shall not pass
through a lossy JSON number representation.

## Effect Authorization Point And Dispatch Permit

The EAP is the sole component with a GCS effect credential and effect-capable
egress. A driver host sends it a bounded typed request and has no direct GCS
route. Immediately before an effect, the EAP validates:

1. signature, trust chain, key status, schema, canonical encoding, and audience;
2. grant state, not-before time, expiry, current revision, and revocation;
3. exact mission, satellite, domain, incarnation, and assignment generation;
4. site, cluster, workload key proof, network identity, and effect boundary;
5. current leader epoch and driver/context/binding/attachment generations;
6. current controller lease and fence for operations requiring human control;
7. operation ID, attempt ID, request digest, capability, limits, deadline, and
   replay state;
8. time-source quality within the configured uncertainty bound; and
9. any operation-specific interlock or mission policy.

The EAP starts a primary-PostgreSQL transaction and locks the domain assignment,
leader, current-controller, driver binding, execution attachment, operation,
and attempt rows in a canonical order. While holding those locks, it calls the
SAA's linearizable attempt-permit operation with the current effect-enabled
grant revision, full tuple, request digest, `AttemptId`, nonce, and deadline.
The SAA serializes that consume against assignment disable, expiry, revocation,
and replacement and returns a signed one-use receipt. If it rejects, times out,
or returns an unverifiable receipt, the EAP rolls back and proves no local
dispatch permit was consumed.

After a successful SAA consume, the EAP rechecks all local guards under database
time, verifies the attempt is `NO_EFFECT`, and commits one local dispatch-permit
consume by compare-and-set. The transaction records both permit IDs and receipt,
the complete tuple, accepted and current lease revisions, decision-evidence
digest, audit/outbox evidence, and transition to `EFFECT_POSSIBLE`. If this
local transaction rolls back or its outcome cannot be proved, the SAA attempt
permit is abandoned and shall never be reused; reconciliation resolves the
local outcome before any new attempt. After a proven local commit, the EAP sends
the request immediately through its exclusive GCS credential and egress.

Release, expiry, revocation, handover, forced takeover, and leader replacement
lock the same PostgreSQL authority rows and therefore serialize against the
local consume. Assignment disable, expiry, revocation, and replacement serialize
against the SAA consume. There is no claim of one distributed transaction. If
both permit consumes and the local commit win, that attempt is authorized and
in flight; a later local or SAA authority loss cannot erase or cancel it and
recovery must reconcile it. If either authority change wins, the corresponding
consume rejects and no effect occurs. A timeout or crash after local commit is
`EFFECT_POSSIBLE` until reconciliation proves a more specific result. It is
never automatically resent.

A successful check at public API, scheduler, gateway, or driver-host ingress
cannot authorize a delayed request. SAA quorum or attempt-permit service,
assignment revision/revocation, PostgreSQL primary/write quorum, EAP credential,
trust, clock, nonce, or deadline freshness loss fails closed. Cached state
cannot extend a grant or either permit.

`OperationId` identifies one logical external-effect intent and retains one
canonical request digest. `AttemptId` identifies one dispatch attempt within
that operation. A retry retains `OperationId` and request digest, increments the
attempt number, and creates a new `AttemptId` only after authoritative evidence
sets the prior attempt to `NO_EFFECT` and policy authorizes retry. The new
attempt receives a new SAA permit bound to the then-current assignment,
authority, dispatch authorization, and local fence tuple; the prior attempt and
tuple remain immutable. A successor `OperationId` represents new intent, not a
retry, and cannot bypass a possible or unknown prior effect. Operations with
`effect_class=NONE` use a distinct read-only EAP capability and have no
effect-certainty value; absence is not a fifth certainty enum.

## Failure Behavior

| Failure | Required behavior | Recovery evidence |
| --- | --- | --- |
| SAA quorum or attempt-permit service unavailable | Deny allocation, activation, transfer, renewal, and every new EAP permit consume; allow observation and reconciliation of consumed attempts | Quorum health and linearizable attempt-permit service restored |
| Network partition isolates an active site from SAA | Deny every new effect even when a cached grant is unexpired; consumed attempts may settle or reconcile | Fresh grant introspection, attempt-permit service, and renewal |
| Non-rollback generation anchor unavailable or ambiguous | Deny reservation, generation allocation, and issuance; never fall back to a restored counter | Valid anchor lineage and a signed compare-and-advance receipt |
| Two sites request activation concurrently | Serialize by satellite compare-and-set; at most one authority record can be effect-enabled | Ledger history and rejected revision evidence |
| Old site appears down but cannot be fenced | Keep candidate read-only | Independent external fence proof |
| Legacy inventory is incomplete or a path lacks disposition | Keep the legacy record effect-enabled and the replacement read-only | Approved inventory revision and complete independently verified fence evidence |
| EAP or PostgreSQL write quorum unavailable | Deny new local permit consumption and effects; abandon but never reuse an SAA permit whose local transaction failed, preserve proven unconsumed local attempts as `NO_EFFECT`, and reconcile uncertain commits | Primary write authority, EAP health, both permit ledgers, and reconciliation evidence |
| Candidate crashes after generation allocation | Leave generation reserved until timeout, then abandon; never reuse it | Terminal grant transition and audit |
| Activation response is lost | Query by idempotency key or grant ID | Canonical committed grant state |
| Signing service fails after `ISSUING` commit | Keep grant non-active until the exact committed envelope is signed and conditionally activated, or revoke/abandon it | Signature record tied to committed revision |
| Revocation publication is delayed | Block new effects where freshness bound is exceeded; invoke external fence as required | Verifier acknowledgement and effect-boundary test |
| SAA ledger restored from backup | Disable issuance until high-water reconstruction succeeds | Signed high-water recovery report |
| SPELL database restored | Treat all restored authority as stale and start read-only | New generation, incarnation, reconciliation, and fence evidence |
| Clock uncertainty exceeds bound | Deny issuance, renewal, and new effects | Approved time source and measured uncertainty restored |
| Credential broker unavailable | Do not reuse old credentials or broaden grant lifetime | Fresh grant-bound credential issuance |
| Fence provider gives conflicting evidence | Quarantine the transition and alert; no active grant | Independent investigation and resolved signed evidence |
| Generation overflow or format limit approached | Stop allocation before wraparound | Approved schema/counter migration with preserved ordering |

An existing effect may be classified as uncertain after a failure. Assignment
recovery shall preserve the canonical effect-certainty state and shall not
automatically resend an operation merely because authority moved to a new site.

## Security And Audit

- Human activation, transfer, failback, and break-glass actions require strong
  authentication, role separation, explicit reason, and policy-defined
  approval. Routine domain control authority does not imply assignment rights.
- Workload calls use mutually authenticated, grant-bound identity. Service
  identities are distinct by site, cluster, component, and environment.
- Least privilege separates request, fence evidence, activation approval,
  signing, credential issuance, revocation, audit review, and key management.
- Only the EAP workload identity can retrieve or use a GCS effect credential or
  traverse effect-capable GCS egress. Driver identities are denied both.
- Canonical requests and responses are integrity protected against substitution
  of satellite, domain, generation, audience, or effect boundary.
- Tokens, evidence, API errors, logs, metrics, traces, and support bundles shall
  exclude secret key material and sensitive command content unless explicitly
  authorized and protected.
- Every request, decision, anchor allocation/receipt, generation allocation,
  state transition, fence result, signature, introspection, permit consume,
  credential issuance, renewal, rejection, expiry, and revocation produces
  immutable audit evidence with synchronized time, actor/workload identity,
  request ID, target, policy digest, result, and safe before/after digest.
- Audit export failure shall not erase local evidence. Reserved storage,
  backpressure, alerts, and fail-closed thresholds protect the assignment
  ledger and security audit path.
- Administrators cannot edit a historical grant. Corrections append a signed
  superseding record and retain the original.
- Security monitoring detects repeated activation races, stale-token use,
  signature failures, unexpected audiences, revocation lag, generation gaps,
  fence conflicts, and cross-site requests.

## Operations

The SAA publishes health for quorum, commit latency, signing latency,
non-rollback-anchor reachability/revision, EAP permit latency, clock uncertainty,
grant expiry, renewal error, revocation propagation, fence-provider health,
audit backlog, and trust-bundle freshness.
Health endpoints shall not disclose sensitive assignments to unauthorized
callers.

Operators use version-controlled runbooks for planned cutover, unavailable old
site, inability to fence, authority-ledger recovery, signing-key compromise,
generation exhaustion, trust-bundle rollback, and audit export failure. Every
exercise records achieved recovery time, unavailability interval, evidence
completeness, and whether any command path remained ambiguous.

SAA software, schema, keys, consensus membership, policy, and trust bundles use
reviewed configuration changes and staged upgrade compatibility. A rollback
shall not roll the generation high-water mark backward or restore a revoked key
or grant. Disaster-recovery exercises include total loss of the primary SAA
failure domain and loss of the site currently holding satellite authority.

## Verification Hooks

- Model-check the assignment state machine and one-effect-enabled-path invariant under
  concurrent requests, retries, reordered messages, duplicate delivery,
  process crashes, and quorum leadership changes.
- Run two real clusters against one test `SatelliteId` and prove simultaneous
  activation attempts produce one active grant and one read-only or rejected
  candidate.
- Partition the current holder, restore each site's SPELL database to an older
  point, and prove no restored authority tuple can pass the effect boundary.
- Restore the SAA ledger to an older backup and prove issuance remains disabled
  until the non-rollback anchor receipts a fresh generation greater than all
  retained evidence. Lose or corrupt the anchor response at each allocation
  step and prove no generation is reused or exposed prematurely.
- Delay an old driver RPC until after cutover and prove the final effect boundary
  rejects its old incarnation, generation, workload key, and grant revision.
- Revoke a grant during queued and in-flight operations and measure denial at
  every verifier against the qualified revocation-latency bound.
- Race the linearizable SAA consume against assignment disable/revocation and
  the PostgreSQL consume against lease renewal, release, expiry, revocation,
  handover, forced takeover, leader replacement, and deadline. Prove the two
  ordered linearization points, abandonment of an SAA permit after local
  rollback, and that a locally committed attempt is never erased or resent.
- Adopt a pre-SAA legacy path with multiple credentials, sessions, endpoints,
  egress routes, queues, and operators; omit each in turn and prove replacement
  activation remains blocked.
- Remove SAA quorum and prove no site promotes itself, renews past expiry, or
  silently extends cached authority.
- Make the old GCS path unreachable but not externally fenceable and prove the
  recovery candidate remains read-only.
- Inject forged, replayed, stale, wrong-audience, wrong-satellite, malformed,
  unknown-key, and future-dated grants and prove fail-closed validation.
- Crash after each activation protocol step and prove idempotent recovery never
  reuses a generation or returns an uncommitted active grant.
- Exercise signing-key and trust-bundle rotation with overlap, compromise
  revocation, offline verifier caches, and rollback attempts.
- Reconcile commands spanning the recovery point and prove uncertain effects
  are not automatically resent.
- Verify audit reconstruction can identify the exclusive command path, all
  rejected stale paths, evidence providers, approvers, and exact active period
  for every generation.

## Requirement Allocation

These rows reproduce their atomic requirements from the central catalog. This
document provides their detailed design and does not create a separate
requirement namespace.

| ID | Requirement | Verification | Owner |
| --- | --- | --- | --- |
| ARC-036 | A mission-wide Satellite Assignment Authority shall permit at most one effect-enabled command-authority path for a `SatelliteId` across every cluster, site, and legacy or replacement system, including a path in drain or transition. | T,A | SA |
| ARC-037 | Every activation, cutover, restore, or failback shall use a newly allocated `AuthorityIncarnationId` and assignment generation, externally fence the prior effect path, and issue fresh short-lived dispatch authority before control becomes active. | T,E | MO |
| ARC-038 | Every externally effectful integration shall pass through one approved Effect Authorization Point that exclusively owns the effect credential and egress path and, immediately before effect, uses a fail-closed one-use permit protocol that linearly orders current assignment at the SAA and current leader, controller when required, operation attempt, and integration fences at primary PostgreSQL before journaled dispatch. | T,A | SA |
| ARC-039 | Each assignment generation shall be reserved through a non-rollback authority outside the SAA recovery set; its signed reservation receipt shall commit before the generation or grant becomes observable, and loss or ambiguity of that proof shall block issuance. | T,E | SA |
| ARC-040 | A pre-SAA legacy command path shall have an externally identified adoption record and complete credential, session, endpoint, egress, interlock, and operator inventory; a replacement shall remain non-effecting until every inventoried path is independently fenced. | I,T,E | MO |
| SRV-022 | A domain shall become command-active only while holding a valid mission-wide satellite assignment grant for its `DomainId`, `SatelliteId`, `AuthorityIncarnationId`, and assignment generation. | T,A | SA |
| REL-029 | Restore, failover, cutover, and failback shall allocate authority identity outside restored history and shall remain non-active until the prior integration path is proven fenced and unresolved effects are reconciled. | T,E | MO |
| DEP-025 | Every command-capable deployment shall use the Satellite Assignment Authority across all clusters and sites; inability to reach it or prove the prior path fenced shall prevent activation while permitting explicitly stale or read-only observation. | T,E | SA |

Owner abbreviations follow the central catalog: `SA` is System Architect, `DA`
is Driver Authority, and `MO` is Mission Operations Authority. Verification
methods are inspection (`I`), test (`T`), analysis (`A`), and exercise (`E`).

## Open Approval Inputs

The approved baseline must assign, per mission and adapter:

- SAA quorum topology and independent failure domains;
- non-rollback generation-anchor implementation, key, receipt schema, and
  recovery lineage;
- EAP placement, database role, effect credential, egress, permit deadline,
  attempt limits, and reconciliation adapter;
- maximum grant lifetime, renewal lead, revocation latency, and clock
  uncertainty;
- effect-boundary identity and its exact grant-validation capability;
- acceptable external fence providers and evidence schemas;
- legacy adoption inventory, accountable owner, and fence dispositions;
- manual isolation authority when automated fencing is impossible;
- activation, revocation, break-glass, and dual-approval roles;
- signing algorithms, key custody, rotation, compromise, and trust-bundle rules;
- evidence retention, audit export, RPO, RTO, and capacity objectives; and
- the qualified behavior of in-flight effects during drain, expiry, and
  revocation.

No default in this draft authorizes a real satellite command path.
