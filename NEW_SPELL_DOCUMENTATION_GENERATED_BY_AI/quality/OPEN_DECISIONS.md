# Open Decisions

## Use

No entry below may be closed by inserting a convenient value in implementation.
The named owner shall record alternatives, evidence, selected value, rationale,
affected requirements, approvers, date, and baseline. Until then, the safe default
applies and the listed gate remains blocked.

| ID | Decision | Owner | Due gate | Safe default while open |
| --- | --- | --- | --- | --- |
| OD-001 | Map this modernization roadmap to product versions, including whether the candidate typed driver/context foundation remains v0.4. | PO | Phase 0 | No release renumbering and no new product-scope claim |
| OD-002 | Record the governing agency/contract/program applicability basis and operated-on-behalf determination, then define CUI categories, flows, system boundary, connected systems, and applicable contracts. | GA/SY/SO | Phase 0 / any protected deployment | Treat candidate protected data as restricted; no compliance claim |
| OD-003 | Assign every applicable NIST SP 800-171 Rev. 3 ODP and control implementation/evidence owner under the governing authority. | GA/SY/SO | Security qualification | No requirement is claimed satisfied when its parameter is unset |
| OD-004 | Select enterprise IdP, authenticator/MFA policy, session duration, revocation and break-glass governance. | SO | Phase 1 | Local development identities only; no production access |
| OD-005 | Select cryptographic types/modules, trust roots, certificate/key lifetimes, rotation and recovery consistent with agency/contract policy. | SO | Phase 1 | Approved modern TLS at all boundaries; no claim of contract/FIPS satisfaction |
| OD-006 | Define controller lease TTL/renewal, handover approvals, emergency revocation, unattended behavior and dual-control actions. | MO | Phase 1 | No automatic handover; effects denied without current lease/fence |
| OD-007 | Define per-domain concurrency, exclusive resources, priority, fairness, queueing, deadlock and overload policy. | MO | Phase 2 | Conservative bounded concurrency; reject unresolved resource conflict |
| OD-008 | Resolve detailed Language Reference ambiguities/errata and approve the Python 3 compatibility profile. | LA | Before each Phase 2 feature | Reject ambiguous or unsupported construct with stable diagnostic |
| OD-009 | Resolve detailed Driver Manual ambiguities and approve typed method/capability schemas. | DA | Before each Phase 2/5/6 service | Capability unavailable; no silent fallback |
| OD-010 | Approve workload profile and latency, freshness, availability, capacity, RPO, RTO and failover targets per environment. | PO/SA | Before qualification | No scalability/HA target claim; non-operational single-node only |
| OD-011 | Approve data classification, retention, audit/WORM export, backup, deletion, legal-hold and support-bundle policy. | SO | Phase 1 | Minimize collection; restrict export; retain only controlled test data |
| OD-012 | Select PostgreSQL HA, backup/PITR, connection management, partitioning and per-domain data-isolation topology. | SA | Phase 1 production design | PostgreSQL single writer in non-operational environment |
| OD-013 | Decide whether a durable broker is justified by measured fan-out/stream load and select its bounded role. | SA | Phase 3 capacity design | PostgreSQL committed-event outbox/projection; no broker dependency |
| OD-014 | Decide whether high-rate telemetry needs a separate time-series/analytical store and define authoritative evidence retention. | SA/DA | Phase 5 | Store procedure-consumed/audit samples in PostgreSQL; bounded simulator rate |
| OD-015 | Select deployment platform, sites/failure domains, network zones, object store, secrets/KMS/HSM, observability and Git service. | SA/SO | Phase 1/7 | Local isolated non-operational deployment only |
| OD-016 | Approve supported browsers, viewports, accessibility baseline, operator workflow budgets and display/time-zone conventions. | MO | Phase 3 | Standards-based current browsers in test only; UTC canonical display available |
| OD-017 | Approve Git branching, review count, signing, sensitive-category, emergency-change, promotion and rollback policy. | CM/MO | Phase 4 | No runtime catalog promotion |
| OD-018 | Select first GCS/simulator adapter and explicitly authorize read and effect capability sets. | DA/MO | Phase 5/6 | Deterministic simulator only; no real GCS endpoint or credential |
| OD-019 | Decide whether specified critical actions require two-person approval and how loss of the second approver is handled. | MO/SO | Before Phase 6 | Deny actions designated critical until policy is approved |
| OD-020 | Record whether the federal agency/contract selects any SP 800-172 Rev. 3 enhanced requirements for critical-program or high-value-asset CUI; internal risk may motivate voluntary controls but not NIST applicability. | GA/SY/SO | Security architecture approval | SP 800-171 Rev. 3 baseline only; no enhanced-profile claim |
| OD-021 | Approve redistribution/licensing treatment for the supplied legacy PDFs and any future vendored evidence. | PO/CM | Documentation publication | Keep PDFs external and hash referenced; do not redistribute |
| OD-022 | The assessment sponsor shall select the authorized assessor/test roles, required independence, depth/coverage, evidence repository and finding/POA&M workflow under governing policy. | AS/SO/QL | Security qualification | No compliance/certification statement |
| OD-023 | Assign named people to every repository approval role and define delegation, absence, conflict-of-interest, and signature rules. | PO/CM | Phase 0 | Repository remains Draft and no role is treated as approved by title alone |
| OD-024 | Select the Satellite Assignment Authority implementation, quorum/failure domains, mandatory non-rollback generation anchor, grant/renewal/revocation timing, legacy-adoption inventory and fence providers, Effect Authorization Point topology and ordered SAA/PostgreSQL permit, rollback, and reconciliation semantics, signing/key custody, and cutover evidence. | SA/MO/SO/DA | Before any command-capable Phase 6 environment | Simulator-only assignment and effect-authorization emulators; no real GCS credential, egress route, or command activation |

## G0 Phase-Entry Closure Set

The current G0 readiness review treats `OD-001`, `OD-002`, `OD-004`, `OD-005`,
`OD-006`, `OD-010`, `OD-011`, `OD-012`, `OD-015`, and `OD-023` as blocking
Phase 1. `OD-010` is included because Phase 0 explicitly delivers an approved
workload profile, even though full qualification occurs later. This closure set
is stricter than using the `Due gate` column as a schedule alone because G0 exit
requires that no safety, security, state, protocol, deployment, or workload
value needed by the next phase remain implicit.

The exact values, alternatives, evidence, impacts, and required signatures are
listed in [`G0_READINESS_PACKAGE.md`](G0_READINESS_PACKAGE.md). None is closed
by that package. `OD-019` may remain open only while forced takeover remains
disabled.

## Closure Record Template

```text
Decision ID:
Selected option/value:
Alternatives evaluated:
Evidence and analysis:
Rationale:
Requirements/ADRs affected:
Security, safety, compatibility and operational impact:
Migration/rollback:
Approvers and dates:
Effective baseline/tag:
Review/expiry date:
```
