# Glossary

| Term | Definition |
| --- | --- |
| Active controller | Authenticated human session and client instance that hold the current valid controller lease for a Satellite Control Domain. |
| As-run record | Canonical, append-only reconstruction of procedure source identity, inputs, states, operations, prompts, operator actions, outputs, and terminal disposition. |
| Capability descriptor | Versioned declaration of a driver service, method, modifier, schema, limits, mutability, and supported behavior. |
| Command acknowledgment | Durable state describing acceptance, dispatch, external acknowledgment, rejection, timeout, or uncertain effect of an operation. |
| Committed event | Event persisted by the authoritative control plane before it is eligible for real-time publication. |
| Controller lease | Durable, time-bounded grant allowing one principal to issue interactive execution-control commands for a Satellite Control Domain. |
| Controlled Unclassified Information (CUI) | Information requiring safeguarding or dissemination controls under applicable U.S. law, regulation, or government-wide policy; scope is determined by the responsible organization and contract, not by this repository. |
| Cursor | Integrity-protected resumable position scoped to domain stream or authorization projection epoch, policy revision, filter digest, schema, and expiry. |
| Driver gateway | Supervisor-owned typed boundary between execution services and an isolated driver host. |
| Driver host | Out-of-process component that implements approved GCS-independent capabilities for one or more controlled bindings. |
| Edit Mode | Web mode for authorized procedure repository operations, analysis, validation, review, and promotion; it has no implicit runtime control authority. |
| Effect Authorization Point | Sole component permitted to hold an effect credential and egress route; immediately before effect, it consumes a one-use SAA attempt permit while transactionally locking and validating current PostgreSQL authority and attempt state, then commits the permit receipt and journal intent before send. This is an ordered fail-closed protocol, not a cross-system ACID transaction. |
| Effect certainty | Canonical effect-bearing-operation classification: `NO_EFFECT`, `EFFECT_CONFIRMED`, `EFFECT_POSSIBLE`, or `EFFECT_UNKNOWN`. It is not applicable to `effect_class=NONE`, and no fifth enum value is created. |
| Execution | One durable instance of one immutable procedure bundle with stable identity, revision, state, variables, operations, and audit history. |
| Execution Mode | Web mode exposing interactive procedure control to the valid controller and read-only state to other authorized viewers. |
| Control fencing token | Monotonically increasing ownership generation allocated on each new controller grant; current active lease state and the token are both required. |
| GCS | Ground Control System integrated through an approved driver adapter. |
| Immutable procedure bundle | Validated, content-addressed package containing exact procedure source, dependency graph, schemas, configuration references, compiler/profile versions, and provenance. |
| Intermediate representation (IR) | Versioned, data-only executable model produced by parsing an approved SPELL language profile; it contains no arbitrary executable objects or imports. |
| Leader epoch | Monotonically increasing generation identifying the only authoritative writer for a Satellite Control Domain. |
| Monitoring Mode | Server-enforced read-only web mode for real-time and historical observation. |
| ODP | Organization-defined parameter whose value is assigned by an authorized organization or agency when tailoring a security requirement. |
| Operation | Durable logical interaction identified by `OperationId`; an authorized retry retains the operation and request digest, increments `AttemptNumber`, and creates a new opaque `AttemptId` bound to the then-current authority and integration tuple only after `NO_EFFECT` proof, while prior attempts remain immutable. |
| POA&M | Plan of Action and Milestones used to track remediation of identified security weaknesses. |
| Procedure catalog | Authorized projection of promoted immutable bundles and their folder, label, permission, and lifecycle metadata. |
| Procedure source identity | Git repository, commit, path, content digest, bundle digest, language profile, compiler version, and dependency closure identifying executed code exactly. |
| Satellite Control Domain | Unit of command authority, execution, state, audit, isolation, recovery, and scaling that is bound to exactly one satellite. Sometimes called a SPELL server instance at the product boundary. |
| Satellite Assignment Authority | Mission-wide linearizable service that permits at most one effect-enabled command path for a satellite across clusters, sites, and legacy/new systems. |
| Snapshot | Revisioned consistent representation of current domain or execution state used for initial load and stream resynchronization. |
| SSP | System Security Plan describing the system boundary, environment, requirements implementation, relationships, and planned safeguards. |
| Stale | Client-visible condition indicating that state freshness cannot be guaranteed because heartbeat, cursor, or snapshot constraints were exceeded. |
| Telecommand (TC) | Command intent constructed and handled through an approved driver capability; its side effects require explicit authorization and certainty tracking. |
| Telemetry (TM) | Time-associated observation acquired through an approved driver capability with value, units, quality, validity, source, sequence, and freshness metadata. |
| Working tree | Editable Git checkout. It is never an execution artifact or production source of truth. |

## Stable Identifier Vocabulary

| Identifier | Purpose |
| --- | --- |
| `MissionId` | Administrative mission boundary. |
| `SatelliteId` | Stable satellite identity independent of deployment. |
| `DomainId` | Stable Satellite Control Domain identity bound to one `SatelliteId`. |
| `AuthorityIncarnationId` / `AssignmentGeneration` | Identify one non-restorable command-authority activation and its externally anchored mission-wide monotonic satellite assignment. |
| `LeaderEpoch` | Fences stale authoritative writers. |
| `ControllerLeaseId` / `ControlLeaseRevision` / `ControlFencingToken` | Identify controller authority, revision every lease change, and fence ownership grants. |
| `ClientInstanceId` | Identifies the tab-local proof-of-possession key bound to a controller lease. |
| `ExecutionId` / `ExecutionRevision` | Identify an execution and protect mutations with optimistic concurrency. |
| `ProcedureId` / `BundleDigest` | Identify logical procedure and exact promoted contents. |
| `DriverBindingId` / `DriverHostGeneration` | Identify a configured driver binding and host lifetime. |
| `OperationId` / `AttemptId` / `IdempotencyKey` | Identify one logical operation, one journaled attempt within it, and a deduplicated request. |
| `PromptId` / `PromptRevision` | Identify one durable prompt settlement race. |
| `DomainStreamEpoch` / `DomainEventPosition` | Identify one authority-incarnation journal namespace and its commit-ordered position; positions are comparable only within the same epoch. |
| `ProjectionEpoch` / `ProjectionSequence` / `DeliverySequence` / `Cursor` | Identify an authorization-scoped projection, its durable authorized position, contiguous subscription delivery, and resumable signed position without exposing unauthorized base-journal metadata. |
| `PrincipalId` / `SessionId` | Attribute authenticated human or service actions. |
| `CorrelationId` / `TraceId` | Relate API, execution, driver, audit, and observability evidence. |
