# SPELL Security Architecture

## Document status

| Field | Value |
| --- | --- |
| Status | Implementation baseline; approval required before production authorization |
| Scope | Next-generation SPELL platform and its supporting services |
| Primary owners | System Owner, Security Officer, Platform Engineering |
| Normative requirements | `SEC-*`, `REL-*`, and `OPS-*` in [System Requirements](../requirements/SYSTEM_REQUIREMENTS.md) |

## Purpose

This document defines the security architecture for a SPELL deployment. It does not declare that a deployment is compliant with NIST SP 800-171. Compliance depends on the deployed system boundary, organization-defined parameters, contracts, operating procedures, personnel, facilities, evidence, assessment, and accepted risk.

The architecture protects five outcomes in priority order:

1. A command is issued only by an authenticated and authorized controller through the currently fenced control authority.
2. A procedure cannot cross its satellite, mission, execution, driver, or data boundary.
3. An operator can determine what happened, who caused it, and which software and procedure versions were used.
4. Loss or compromise of a browser, worker, integration, or replica does not silently create command authority.
5. Confidentiality and integrity controls follow the data classification and the approved CUI boundary.

## Security scope and boundary

Each deployment shall maintain a version-controlled boundary diagram and data-flow inventory. The inventory shall identify every component that processes, stores, or transmits CUI and every component that protects those components. At minimum, the assessment shall consider:

- operator workstations and browsers;
- identity provider, multifactor authentication, and privileged access systems;
- web application, API, real-time gateway, and administrative interfaces;
- control-authority service and durable controller lease store;
- mission-wide Satellite Assignment Authority, grant signer, external fence
  verifier, and grant-bound credential broker;
- procedure compiler, scheduler, execution workers, and driver processes;
- command, telemetry, archive, simulation, time, and notification integrations;
- PostgreSQL, object storage, event transport, caches, Git, artifact registry, and backup systems;
- observability, audit, security monitoring, secrets, key management, and recovery services;
- build systems, deployment controllers, management networks, and administrator endpoints.

Components outside the CUI boundary shall not receive CUI. A boundary crossing requires an approved interface, data-flow record, classification decision, authentication, authorization, encryption, validation, logging, and security review. A cache or message broker is not exempt merely because it is described as ephemeral.

## Trust zones

| Zone | Permitted content and behavior | Mandatory controls |
| --- | --- | --- |
| Operator zone | Human interaction through managed browsers | Device posture where required, phishing-resistant MFA, short-lived sessions, no direct database or driver access |
| Web access zone | Static UI, API ingress, WebSocket ingress | TLS, web application firewall policy, request limits, origin validation, token validation, no command credentials at the edge |
| Control zone | Satellite assignment validation, authorization, controller lease, scheduling, committed execution state | Service identity, mTLS, deny-by-default policy, durable multi-layer fencing, synchronous audit admission for critical actions |
| Execution zone | Procedure workers and bounded intermediate representation | Per-execution identity, resource limits, egress allowlists, no inherited operator token, no arbitrary source execution |
| Driver and mission integration zone | Device-facing protocol adapters, the Effect Authorization Point, and command/telemetry links | Out-of-process isolation; only the Effect Authorization Point holds an effect credential and egress route; per-satellite policy, strict schemas, and sequence/idempotency protection |
| Data zone | Authoritative database, immutable bundles, audit sink | Encryption, least privilege, backup, integrity controls, restricted administration |
| Management zone | CI/CD, orchestration, secrets, monitoring, backup | Privileged access management, separate identities, change approval, recorded administrative actions |

No implicit trust shall be granted because two services share a host, cluster, namespace, or network. Network location is a supporting attribute, not an identity.

## Identity and authentication

### Human identities

- Production access shall use an organization-controlled identity provider with unique accounts and multifactor authentication (`SEC-003`). Phishing-resistant authenticators are the preferred baseline for controllers and privileged roles.
- Shared operator or administrator accounts are prohibited. Displayed console or shift names never replace the authenticated subject identifier.
- Authentication assurance, session lifetime, reauthentication interval, inactivity timeout, failed-attempt lockout, and device requirements are organization-defined parameters recorded in the System Security Plan (SSP).
- Local accounts are disabled except for controlled break-glass recovery. Break-glass credentials shall be vaulted, time-limited where possible, independently alerted, reviewed after every use, and tested without exposing the secret (`SEC-003`, `SEC-007`, `SEC-009`).
- Identity lifecycle events from the authoritative directory shall promptly disable SPELL access. Removal from an execution-control role shall invalidate new authorization decisions and prevent lease renewal.

### Workload identities

- Every service, worker, driver, deployment controller, and backup job shall have a unique, attestable workload identity (`SEC-005`).
- Internal service calls shall use mutually authenticated TLS. Certificates shall be short-lived where the platform supports automated issuance and rotation.
- A worker receives only its execution identity, satellite identifier, procedure bundle digest, and narrowly scoped capability. It shall not receive the browser session, database owner credential, Git credential, or reusable driver administrator secret.
- Service identities shall be bound to environment and workload attributes. A development identity cannot authenticate to production.

## Authorization model

Authorization combines role-based permissions with resource and context attributes (`SEC-004`). Every decision shall evaluate the authenticated subject, action, mission, satellite, environment, procedure release, execution, current operating mode, controller lease, and relevant safety policy.

At authenticated startup the authorization service returns effective
capabilities, permitted modes, the selected or selectable initial mode, policy
revision, scope, and decision lifetime. The browser does not translate role
names into permissions. A multi-role principal is evaluated inside the selected
mode; excluded capabilities from a different role or mode are not unioned into
the request. Mode selection never creates a controller lease or Git authority.

| Role | Representative permissions | Explicit exclusions |
| --- | --- | --- |
| Monitor | Read released procedures, execution state, permitted telemetry, logs, and notifications; if separately Controller-eligible, submit, withdraw, or decline one non-authorizing handover request | Cannot acquire control directly, acknowledge prompts, mutate variables, start/stop procedures, or edit source |
| Controller/Executor | Acquire an available eligible controller lease; request or approve secure handover; start, pause, resume, stop, acknowledge, and provide operator input while holding the lease | Cannot approve own procedure release, administer security, bypass command policy, or act before lease transfer |
| Procedure Developer | Create branches, edit source, validate, and submit changes | Cannot promote own change without required review; editing does not alter a running bundle |
| Procedure Reviewer/Release Manager | Review, approve, sign, and promote immutable bundles | Cannot rewrite Git history or replace a promoted digest |
| System Administrator | Operate infrastructure and approved configuration | No automatic execution control; no procedure release approval solely by being an administrator |
| Security Administrator | Manage policy, identity integration, keys, and security monitoring | No automatic execution control; cannot erase audit evidence |
| Auditor | Read security configuration and audit evidence | Read-only; cannot execute, edit, or administer |
| Service identity | Perform one documented machine function | Cannot use human endpoints or obtain broader credentials |

The authorization service shall deny an action when required attributes are missing, stale, ambiguous, or inconsistent. Privileged actions require a fresh policy decision. Cached decisions shall have bounded lifetimes and shall be invalidated on material identity or policy changes.

## Exclusive execution control and fencing

One authenticated human may hold execution control for a SPELL server and its
Satellite Control Domain at a time. The rule is enforced by the server, never
by the UI alone (`SRV-005` through `SRV-010`).

1. The control authority creates a durable lease containing `SatelliteId`, `DomainId`, `AuthorityIncarnationId`, holder subject/session/client-instance proof key, lease revision, monotonically increasing `control_fencing_token`, issue time, expiry, and policy revision.
2. Lease operations are serializable database transitions. A new ownership grant increments `control_fencing_token`; renewal and terminal lease changes increment lease revision without reusing or decreasing the fence.
3. Every mutating execution request carries the current lease ID/revision, control fence, authority incarnation, and request proof. The authoritative command path rejects inactive, expired, superseded, wrong-satellite, wrong-incarnation, wrong-session, or wrong-client tokens.
4. Workers and drivers accept control messages only from the authority and reject a stale authority incarnation, assignment generation, leader epoch, control fence, or driver generation. They never infer authority from WebSocket connectivity.
5. A controller-eligible user in Monitoring Mode may create a named handover
   request, but the request grants no authority and the old lease remains active.
   The current holder must approve that exact request. Only afterward may the
   requester acknowledge the current operational context and controller
   responsibility with a request-bound proof.
6. Responsibility acknowledgement and transfer commit atomically: the old grant
   becomes terminal, one new active grant with a higher fence replaces the
   current pointer, and authoritative mode projections select Execution for the
   new holder and a permitted non-control mode for the former holder. The old
   token is rejected even before either UI receives the event.
7. Loss of heartbeat stops renewal. Reacquisition follows an explicit policy;
   it does not transfer control silently to a monitor.
8. Emergency revocation makes the lease inactive and advances its revision; any replacement grant receives a higher control fence. Both operations record actor and reason and require post-event review.

Read-only monitoring remains available when policy permits, but stale data shall be labeled with the last committed sequence and timestamp. Monitoring scale does not weaken the single-controller invariant.

Every externally effectful request passes through the approved Effect
Authorization Point. Immediately before effect, it locks the primary PostgreSQL
authority, lease, and operation-attempt rows; while those locks are held, it
consumes a one-use attempt permit through a linearizable SAA operation. A failed
SAA consume rolls back locally. A consumed SAA permit whose local commit fails
is abandoned and never reused. The local transaction commits the permit,
journal intent, current leader, applicable controller lease/client proof,
deadline, and driver/execution fences before send. Thus SAA revocation and local
lease changes each have a defined linearization order without claiming one
cross-system ACID transaction. Only the Effect Authorization Point has the
effect credential and network route; direct driver-host egress is denied. Loss
of either quorum, trusted time, or permit integrity denies dispatch.

## Communications security

- External browser and API traffic shall use approved TLS configurations. Plaintext listeners are disabled, including on internal networks (`COM-001`, `SEC-008`).
- Internal service and driver-adapter traffic shall use mTLS unless a documented legacy interface exception provides compensating isolation and integrity controls.
- REST mutation requests require an idempotency key, expected resource revision, authorization decision, and control fencing token when applicable.
- WebSocket connections use short-lived audience-bound credentials, validated `Origin`, explicit subprotocol/version, per-topic authorization, bounded message size/rate, heartbeat, and forced reauthorization on expiry (`COM-003`, `SEC-014`).
- The real-time channel publishes committed state and notifications. It is not an alternate unaudited command channel.
- Protocol schemas are versioned, length-bounded, and validated before deserialization. Unknown fields follow the documented compatibility policy; unsafe polymorphic deserialization is prohibited.
- Egress is deny-by-default from execution and driver zones. Driver hosts have no direct effect route. DNS, time, telemetry, archive, notification, and the Effect Authorization Point's mission link are individually allowlisted.

Cryptographic types and modules shall follow the agency or contract assignments associated with NIST SP 800-171 requirement 03.13.11. FIPS-validated cryptographic modules are the deployment baseline where required by that assignment or other governing policy, and are recommended for U.S. Government CUI deployments. The selected modules, modes, certificates, endpoints, and validation status shall be recorded as deployable evidence rather than asserted from source code alone.

## Secrets and key management

- Secrets shall be stored in an approved secrets manager; private keys shall use a key-management service or hardware security module according to classification and policy (`SEC-009`).
- Repositories, container images, browser bundles, logs, traces, support archives, and procedure source shall contain no plaintext secrets.
- Applications obtain short-lived credentials at runtime through workload identity. Static credentials require an approved exception, a named owner, rotation interval, expiry, and monitoring.
- Keys are separated by environment, mission, satellite, purpose, and cryptographic operation. A backup key cannot sign release artifacts; an audit-signing key cannot issue workload identities. Effect credentials are bound to the approved Effect Authorization Point and cannot be retrieved by a driver host, worker, or public service.
- Rotation shall preserve the ability to verify historical signatures and decrypt records for the approved retention period. Key destruction requires dual authorization and evidence.
- Secret access, policy changes, rotation, export attempts, and failed retrievals are security events.

## Data protection and isolation

All persistent stores shall implement an approved classification, retention, backup, export, and disposal policy (`DATA-007`, `SEC-020`). Data shall be labeled at the mission/satellite boundary and, where applicable, with CUI category and dissemination restrictions.

- PostgreSQL authorization uses separate roles for migrations, applications, read-only reporting, backup, and administration. Application services are not database owners.
- Row filters may provide defense in depth, but resource-scoped service identity and query design remain mandatory. Cross-satellite access tests are release gates.
- Object keys and immutable procedure bundles include mission, satellite applicability, commit, compiler, and content digest. Object-store policies prevent mutable overwrite of promoted bundles.
- Caches contain the minimum data, use short retention, and are treated as boundary components if they receive CUI. Cache loss cannot change command authority or committed execution state.
- Data at rest is encrypted with managed keys. Exports remain classified and encrypted; downloading data does not remove its handling requirements.
- Temporary files are created only in controlled storage, have bounded lifetimes, and are securely removed according to media policy.

## Procedure and command safety controls

- Production executes a reviewed, immutable, signed procedure bundle, not an editable branch or arbitrary Python text (`EXEC-001` through `EXEC-003`, `GIT-004`, `GIT-005`).
- The compiler accepts the documented SPELL language and creates a versioned, data-only intermediate representation. Unsupported dynamic imports, native code, shell access, reflection, and undeclared network/file access are rejected.
- Procedure dependencies are locked by digest and included in the release manifest. Runtime resolution from an untrusted public package registry is prohibited.
- Each execution is isolated with CPU, memory, process, file, and network limits. A resource-limit event is explicit and audited; it cannot be reported as a successful step.
- Command parameters are validated against driver schemas and mission command policy. Operator confirmation, dual authorization, inhibits, or independent safety systems are applied where the hazard analysis requires them.
- On ambiguous transport outcome, SPELL records `EFFECT_UNKNOWN` and requires reconciliation. It shall not automatically resend a potentially effective command (`EXEC-010`, `REL-008`). A retry retains the same `OperationId` and request digest, allocates a new attempt identity bound to the then-current authority and integration tuple only after authoritative `NO_EFFECT` proof, preserves prior-attempt evidence, and passes the final authorization checks again.
- Simulation and production endpoints use different identities, network destinations, banners, and release policies. A simulation bundle cannot silently address a flight endpoint.

## Browser and session controls

The web client is an untrusted presentation tier. The server is authoritative for identity, authorization, mode, lease, revision, input validation, and state transition.

- Use secure, HTTP-only, same-site cookies for browser sessions when compatible with the approved identity flow. Do not store bearer tokens or sensitive execution data in persistent browser storage.
- State-changing HTTP operations use anti-CSRF protections and strict content types. Cross-origin resource sharing is deny-by-default.
- Apply a restrictive Content Security Policy, trusted dependency policy, output encoding, template auto-escaping, frame restrictions, subresource integrity where appropriate, and dependency scanning.
- Server errors return correlation IDs and safe messages. Stack traces, SQL text, credentials, and internal network details are not sent to browsers.
- Session revocation closes or deauthorizes associated WebSockets. Closing a tab does not constitute a reliable lease release; the server expiry and fencing rules remain authoritative.
- Clipboard, download, print, and local caching policy follows data classification and managed-device controls.
- The client omits permanently unauthorized actions and disables temporarily
  invalid actions with an accessible server-derived reason. DOM changes or
  direct endpoint calls cannot bypass server authorization. Monitoring exposes
  only the dedicated non-authorizing handover request to a separately
  Controller-eligible principal; it exposes no runtime write path.

## Audit and accountability

Security audit is separate from diagnostic logging (`SEC-010`, `SEC-011`, `OPS-002`). An action that requires audit admission shall fail closed if the local durable audit handoff cannot accept it, subject to a documented emergency operating mode.

Each source audit event shall include:

- event schema version, event type, outcome, and reason code;
- trusted UTC service event timestamp;
- actor type plus authenticated subject/session/client key or service identity,
  and source device/network attributes allowed by policy, where applicable;
- mission, satellite, procedure release digest, execution, prompt, command, and affected resource identifiers where relevant;
- action, outcome, reason, request ID, correlation ID, and event-applicable
  authorization policy, role/context, controller-fence, and idempotency fields;
- previous and resulting state/revision without recording prohibited secret values;
- software artifact, configuration, and deployment version.

Startup and handover source events also record former-holder and requester
subject/session/client-key identities where applicable; effective roles,
attributes, and policy revision; request, approval,
responsibility-acknowledgement, predecessor, and successor IDs; both lease
revisions and fences; old and new modes; reason, outcome, and correlation. The
independent sink creates a receipt containing its identity and ingestion time,
bound to the source event ID and digest. The acknowledgement body is retained
through an approved safe digest and protected evidence reference rather than
generic plaintext logging.

Audit records shall be append-only at the application interface, integrity-protected in transit and at rest, replicated to a security-controlled sink, and exported to retention-controlled immutable or WORM storage. Hash chaining or signed checkpoints shall make deletion, truncation, and reordering detectable. Time synchronization health and clock corrections are audited. Access to audit content is itself audited.

## Network and platform safeguards

- Segment operator ingress, web access, control, execution, driver, data, management, build, backup, and security monitoring networks (`SEC-012`).
- Enforce policy through both network controls and authenticated service authorization. Security groups or network policies are generated from reviewed configuration and continuously checked for drift.
- Administrative access uses managed endpoints and a privileged access path. Direct public exposure of databases, orchestration APIs, driver ports, Git administration, backup consoles, and metrics endpoints is prohibited.
- Hosts and containers use approved hardened baselines, read-only filesystems where feasible, dropped capabilities, non-root identities, controlled system calls, image signature verification, and timely patching.
- Production configuration is deployed from reviewed version control. Emergency changes are time-limited, recorded, reconciled to source, and independently reviewed (`SEC-015`).

## Integrity monitoring and response

The platform shall verify signed release artifacts, container images, procedure bundles, migrations, and configuration before use (`SEC-016`, `SEC-017`). Runtime detections shall cover unexpected process execution, image drift, privilege escalation, secret access anomalies, audit interruption, repeated authorization failure, cross-satellite access attempts, lease conflicts, policy bypass attempts, and unauthorized egress (`SEC-019`).

Security alerts integrate with the incident response process. Automated containment may revoke sessions, fence a controller, quarantine a worker, block an artifact, or isolate an integration only where the response playbook analyzes mission safety. Automation shall not issue, repeat, or cancel a spacecraft command merely as a generic cybersecurity response.

## Security acceptance criteria

A production release is not security-ready until the responsible approvers can produce:

1. approved boundary and data-flow diagrams, asset inventory, data classification, and external interface inventory;
2. threat model with dispositioned high risks and mission hazard references;
3. authorization matrix, organization-defined parameters, cryptographic policy, configuration baselines, and privileged access procedure;
4. SSP, assessment plan, assessment evidence, findings, and Plan of Action and Milestones where required;
5. penetration, authorization, satellite-isolation, lease-fencing, malformed protocol, recovery, and audit-integrity test results;
6. signed software and procedure release manifests, SBOMs, provenance, vulnerability disposition, and deployment attestations;
7. operating, incident, key recovery, backup, restore, and disaster-recovery runbooks with exercise records.

Detailed NIST alignment is maintained in [NIST SP 800-171 Alignment](NIST_SP_800_171_ALIGNMENT.md). Threats and abuse cases are defined in [Threat Model](THREAT_MODEL.md).
