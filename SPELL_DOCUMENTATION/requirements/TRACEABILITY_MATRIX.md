# Traceability Matrix

## Objective Traceability

| Initiative objective | Requirement coverage | Primary design records | Acceptance evidence |
| --- | --- | --- | --- |
| Preserve language definition | DOC-003, EXEC-001 through EXEC-015, COMP-001 through COMP-022 | `preserved/LANGUAGE_REFERENCE_AUTHORITY.md`, `procedures/COMPATIBILITY_AND_MIGRATION.md` | Reconciled compatibility ledger, parser/semantic corpus, manual-example results |
| Preserve driver definition | DOC-004, EXEC-009 through EXEC-012, EXEC-020 through EXEC-024, COM-009 through COM-012, COM-022 through COM-023, COMP-007, COMP-021 | `preserved/DRIVER_MANUAL_AUTHORITY.md`, `architecture/SERVER_AND_EXECUTION.md` | Driver conformance harness, simulator and lifecycle/fault results |
| Modern server architecture | ARC-001 through ARC-040, SRV-001 through SRV-022 | `architecture/SYSTEM_CONTEXT.md`, `architecture/LOGICAL_ARCHITECTURE.md` | Architecture review, contract tests, domain-isolation tests |
| One satellite per server/domain | ARC-001 through ARC-003, ARC-026 through ARC-027, ARC-036 through ARC-040, SRV-001, SRV-013, SRV-022, DEP-003, DEP-012, DEP-025 | ADR-002, satellite assignment authority, and deployment specification | Configuration, mission-wide assignment, legacy adoption, generation-anchor, final-effect authorization, old-path fencing, and cross-domain isolation tests |
| Concurrent procedures | SRV-002 through SRV-004, SRV-013 through SRV-022, EXEC-004 through EXEC-028 | `architecture/SERVER_AND_EXECUTION.md`, machine-readable state models | Admission, conflict, resource, race and recovery tests |
| Multiple satellites | ARC-002, ARC-003, ARC-027, ARC-036 through ARC-040, SRV-022, DEP-003, DEP-004, DEP-014, DEP-025 | System context, satellite assignment authority, and deployment specification | Multi-domain load, assignment race, isolation, fault and authorization qualification |
| Real-time browser communication | COM-001 through COM-027, WEB-002 through WEB-007, WEB-029 through WEB-037 | Real-time communications and web real-time state specifications | Snapshot/cursor/gap/reconnect and browser-stream qualification |
| Execution Mode and one controller | SRV-005 through SRV-010, SRV-014 through SRV-017, SRV-021 through SRV-022, MODE-001 through MODE-003, MODE-013 through MODE-017, MODE-021 through MODE-027 | Operating modes, state models, and ADR-003 | Lease/fence/client-proof model tests, startup-policy tests, handover races, and failover demonstrations |
| Read-only scalable monitoring | MODE-003 through MODE-005, MODE-009, MODE-018 through MODE-020, MODE-023 through MODE-025, DEP-002, DEP-006, DEP-017 | Operating modes and deployment specification | Authorization-negative tests, non-authorizing request tests, and qualified fan-out workload |
| Role-based startup and secure handover | MODE-001, MODE-008, MODE-013 through MODE-016, MODE-021 through MODE-027, SEC-003 through SEC-007, SEC-010 through SEC-011, WEB-002, WEB-005, WEB-013, WEB-017 | Operating modes, web application, security architecture, and controller-lease state model | Single-role and multi-role startup matrix; request/approval/acknowledgement races; atomic transfer, automatic mode-switch, stale-fence, and audit-schema tests |
| Git-backed Edit Mode | MODE-006 through MODE-008, MODE-019, GIT-001 through GIT-024 | Authoring/Git specification and ADR-005 | Repository policy tests, deterministic build, promotion/rollback demo |
| Hierarchical procedure navigation | MODE-010 through MODE-012, WEB-023 through WEB-028, GIT-023 through GIT-024 | Procedure navigation specification | Permission, search, folder, favorite and recent workflow tests |
| PostgreSQL evaluation | DATA-001 through DATA-003, DATA-005, DATA-013 through DATA-029 | Data architecture and ADR-001 | Transaction/invariant, commit-order, promotion, telemetry-evidence, migration, HA and capacity results |
| Reliability and graceful degradation | REL-001 through REL-029, OPS-001 through OPS-010 | Reliability/recovery and operations specifications | Fault injection, failover, restore, DR and degraded-mode exercises |
| NIST SP 800-171 support | SEC-001 through SEC-023 | NIST alignment, objective-level assessment template, security architecture, threat model, secure SDLC | Applicability basis, SSP, ODPs, reconciled requirement/determination matrix, assessment results, evidence index, POA&M |
| Secure deployment and supply chain | DEP-001 through DEP-025, SEC-012 through SEC-020 | Deployment and secure SDLC specifications | Signed provenance, SBOM, policy, vulnerability and deployment evidence |
| Implementation-ready delivery and GUI guidance | DOC-001 through DOC-011, VNV-001 through VNV-012 | Document control, allocation register, GUI User Manual source/PDF, V&V plan, roadmap, open decisions | Approved baseline tag, complete links, rendered-page review, manual workflow coverage, closed entry decisions, gate record |

## Requirement Group Traceability

| Requirement set | Normative source | Architecture or process allocation | Verification owner/evidence |
| --- | --- | --- | --- |
| DOC-001..DOC-011 | `requirements/SYSTEM_REQUIREMENTS.md` | `DOCUMENT_CONTROL.md`, `SOURCE_AUTHORITY.md`, GUI User Manual, document allocation | Configuration manager and quality lead; manifest, manual/PDF checks, approvals, repository checks |
| ARC-001..ARC-040 | Same | System context, logical architecture, satellite assignment, deployment | Architect/security officer; review, legacy-adoption, generation-anchor, final-effect, and isolation evidence |
| SRV-001..SRV-022 | Same | Server/execution, state models, operating modes, ADR-002/003 | Architect/mission operations; state, lease and failover tests |
| EXEC-001..EXEC-028 | Same | Server/execution, state models, compatibility/migration | Language/driver authorities; runtime conformance and recovery |
| COM-001..COM-027 | Same | Real-time communications, real-time web state, ADR-004 | Architect/security officer; protocol and fault tests |
| DATA-001..DATA-029 | Same | Data architecture, ADR-001, backup/DR | Architect/configuration manager; invariant, restore and migration tests |
| WEB-001..WEB-037 | Same | Web application and real-time state | Mission operations/quality; browser, human factors and accessibility evidence |
| MODE-001..MODE-027 | Same | Operating modes, web application, controller-lease state model, security architecture, and procedure navigation | Mission operations/security; startup policy, role, negative, handover, and workflow tests |
| GIT-001..GIT-024 | Same | Authoring/Git, ADR-005, secure SDLC | Configuration manager/security; policy, build and provenance evidence |
| REL-001..REL-029 | Same | Reliability/recovery, deployment, operations, backup/DR | Architect/quality; failure, failover and exercise evidence |
| SEC-001..SEC-023 | Same | Security architecture, NIST alignment, objective-level assessment template, threat model, SDLC | Governing authority, System Owner, security officer, sponsor and assessor; applicability, SSP, assessment evidence and POA&M |
| OPS-001..OPS-010 | Same | Operations/observability and backup/DR | Product/mission/security owners; runbook and recovery exercises |
| COMP-001..COMP-022 | Same | Compatibility ledger and migration specification | Language/driver/quality; reconciled rows and conformance vectors |
| DEP-001..DEP-025 | Same | Deployment/scalability, satellite assignment, and secure SDLC | Architect/configuration/security; deployment qualification |
| VNV-001..VNV-012 | Same | Verification/validation plan and roadmap | Quality lead; release evidence and signed gate decision |

## Per-Requirement Implementation Allocation

The candidate per-ID relation required by `NG-WP-00` is generated as
[`IMPLEMENTATION_ALLOCATION.csv`](IMPLEMENTATION_ALLOCATION.csv) from
[`IMPLEMENTATION_ALLOCATION_RULES.json`](IMPLEMENTATION_ALLOCATION_RULES.json).
It expands all 366 central IDs and records the canonical requirement-record digest,
registered and accountable owner, required approvers, verification method,
primary design, one primary and any supporting work packages, phase, G0 entry,
later acceptance gate, stable planned test/result targets, and approval
relation. The validator proves that each primary design is allocated the exact
central ID rather than merely checking that the document exists.

The current registry is structurally complete and retained as broader-program
traceability. Every row is explicitly outside the bounded local v0.4 gate, so
its organization-role approval state is informational for that gate:

| Measure | Current value |
| --- | ---: |
| Central requirements | 366 |
| Allocation rows | 366 |
| Duplicate, missing, extra, or non-contiguous central IDs | 0 |
| Missing required allocation fields | 0 |
| Approved allocation rows | 0 |
| Rows `OUTSIDE_LOCAL_V04_GATE` | 366 |
| Local v0.4 pending organization-approval rows | 0 |
| Composite owner rows requiring one accountable owner | 6 |

`NGV-<RequirementId>` and `NGR-<RequirementId>` are planned identifiers, not
executed tests or accepted results. See the
[`G0_READINESS_PACKAGE`](../quality/G0_READINESS_PACKAGE.md) and generated
[`G0_READINESS_REPORT.json`](../quality/G0_READINESS_REPORT.json) for the
current local technical blockers. A later broader-specification approval may
bind these rows to named people, dates, findings, and its selected baseline;
that workflow is not a local v0.4 Gate 0 requirement.

## Bidirectional Implementation Rule

Implementation repositories shall maintain a machine-readable relation with at
least these fields:

```text
RequirementId -> DesignSection -> InterfaceOrSchema -> SourceComponent
              -> TestId -> ResultArtifactDigest -> FindingOrException
              -> BaselineTag -> Approval
```

CI shall fail when an implemented requirement lacks a test, a test cites an
unknown requirement, an approved requirement changes without review, or release
evidence does not match the candidate digest. Manual evidence may be used where
automation is inappropriate, but it shall still have an identifier, procedure,
result, reviewer, date, environment, and artifact digest.
