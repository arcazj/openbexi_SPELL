# Secure SDLC and Software Supply Chain

## Purpose

This document defines the minimum engineering controls for SPELL application code, infrastructure, configuration, database migrations, drivers, web assets, and procedure-tooling components. It supports `SEC-014` through `SEC-017`, `GIT-*`, and `VNV-007`. Procedure source has an additional promotion workflow because it can cause mission effects.

Security is enforced through protected systems and verifiable artifacts. A checklist without branch protection, isolated builds, signature verification, test evidence, and accountable exceptions does not satisfy this process.

## Roles and separation of duties

| Role | Responsibility | Prohibited combination without approved exception |
| --- | --- | --- |
| Contributor | Authors change and tests | Sole approver and release signer for own material change |
| Code/Procedure Reviewer | Reviews semantics, security, tests, compatibility | Silent approval after content changes |
| Product Security | Threat modeling, security test strategy, vulnerability disposition | Unilateral acceptance of mission-safety risk |
| Mission/Driver Owner | Validates command, telemetry, and operational semantics | Bypassing security or independent review |
| Release Manager | Promotes verified digest through environments | Editing promoted artifact |
| Build Service | Produces artifacts, SBOM, provenance, signatures under policy | Interactive human use of build signing identity |
| Platform Operator | Deploys an approved digest and configuration | Rebuilding or modifying artifact during deployment |
| Authorized Risk Owner or Authorizing Official | Accepts residual risk within delegated authority | Delegating acceptance to change author, scanner, or Security Officer alone |

Repository owners shall enforce protected branches, mandatory current reviews, required status checks, signed or strongly authenticated actions, force-push restrictions, and immutable release tags or equivalent release records.

## Lifecycle gates

### 1. Plan and classify

Every change shall identify:

- affected requirements, interfaces, trust boundaries, data classifications, satellites/missions, and deployment environments;
- whether it changes language/driver compatibility, command semantics, authorization, cryptography, audit, recovery, or the CUI boundary;
- security and safety reviewers required by the change class;
- tests and evidence needed for acceptance;
- migration, rollback, and irreversibility considerations.

A high-impact change updates the threat model before implementation. Examples include a new driver, protocol, external integration, authentication flow, controller lease behavior, compiler construct, privilege, cryptographic module, persistent store, build service, or supplier.

### 2. Design

Design review shall resolve:

- trust boundaries and authenticated identities at every hop;
- authorization subject, action, resource, context, and deny behavior;
- data ownership, classification, validation, retention, audit, and recovery;
- timeout, retry, idempotency, ordering, duplicate, and ambiguous-outcome behavior;
- availability, overload, partition, failover, and degradation behavior;
- dependency and supplier choices, maintenance horizon, and exit strategy;
- abuse cases and verification hooks.

Protocol and persistent-schema changes require versioning and backward/forward compatibility plans. Destructive migrations shall include tested recovery and a decision on rollback feasibility.

### 3. Implement

- Use memory-safe or strongly managed runtimes for new components unless a documented requirement justifies otherwise.
- Enforce formatters, linters, type checking, schema validation, and compiler warnings defined by the language baseline.
- Use parameterized database access, centralized authorization, structured logging/redaction, approved cryptographic APIs, safe parsing, bounded inputs, and explicit timeouts.
- Prohibit embedded credentials, unreviewed dynamic code execution, unsafe deserialization, shell construction from input, and unrestricted server-side requests.
- Tests shall include negative authorization, malformed input, concurrency, cancellation, retry, recovery, and cross-satellite isolation, not only successful flows.
- Security-relevant code comments explain an invariant or non-obvious tradeoff; they do not substitute for an enforced control.

### 4. Build

Production artifacts shall be built by an isolated, ephemeral, non-interactive build service from a reviewed source revision. The build shall:

1. resolve dependencies only through approved, integrity-checked repositories;
2. use lock files or equivalent exact dependency resolution;
3. record source revision, build definition, builder identity, toolchain, platform, dependency digests, and build time;
4. run required unit, integration, static analysis, secret, license, dependency, and artifact scans;
5. generate an SBOM in SPDX or CycloneDX format for each deployable artifact;
6. emit signed provenance binding inputs, process, and output digest;
7. sign the immutable artifact by organization PKI or an approved signing service;
8. publish by digest to a restricted registry without mutable production tags as the deployment selector.

Reproducible builds are required where practical. Where byte-for-byte reproducibility is not available, an independent rebuild shall compare declared source, dependencies, toolchain, generated contents, and functional identity for high-impact releases.

### 5. Verify

Required verification scales with impact but cannot omit controls affected by the change:

- unit, contract, integration, end-to-end, failure-injection, load, recovery, and upgrade tests;
- static application security, software composition, secret, infrastructure, container, and configuration analysis;
- dynamic API/web security tests and fuzzing of parsers, protocol adapters, compilers, and drivers;
- role/action matrix, session, controller-fencing, audit, and satellite-isolation tests;
- migration from every supported upgrade source and restore from supported backup formats;
- independent penetration testing before initial authorization and after material boundary/security changes;
- driver simulation or hardware-in-the-loop qualification for operational interfaces.

Scanner results require human triage. Suppression records shall identify the finding, affected digest, technical rationale, compensating control, owner, approver, expiry, and retest trigger.

### 6. Release

The release manifest shall bind:

- source revision and repository;
- artifact, image, SBOM, provenance, migration, configuration-schema, and policy digests;
- supported platform and compatibility versions;
- security test evidence and vulnerability disposition;
- release approvals and signing identity;
- known risks, required mitigations, upgrade sequence, rollback constraints, and support end date.

The registry shall make replacement of a released digest impossible through normal application privileges. Revocation status is checked before promotion and deployment.

### 7. Deploy and operate

- Deployment admission verifies artifact signature, provenance policy, approved source/release, vulnerability policy, target environment, and configuration schema.
- Production uses reviewed infrastructure and configuration from version control. Interactive modification is disabled where practical.
- Progressive deployment shall prevent a mixed-version command path unless its compatibility is explicitly tested.
- Health and security signals determine promotion or rollback. Rollback shall not automatically reverse an irreversible database change or resend an external effect.
- Deployment evidence records who approved and initiated the change, exact digests, environment, time, migration result, configuration revision, and verification result.

## Procedure source promotion

Procedure editing and runtime execution are deliberately separated.

1. A developer edits a Git branch and receives local/editor validation against an explicit SPELL compatibility profile.
2. CI parses source, rejects unsupported constructs, resolves declared dependencies by digest, checks syntax/semantics, and runs tests in an isolated non-production environment.
3. Reviewers compare the exact normalized source and generated intermediate representation that will be released. Hazardous procedure changes receive the independent review required by mission policy.
4. Promotion creates an immutable procedure bundle containing source bytes, data-only IR, dependency digests, compatibility target, compiler version, validation evidence, target mission/satellite constraints, and approvals.
5. The release service signs the bundle manifest. Runtime admission verifies signature, digest, target, compiler/IR compatibility, revocation, and release state.
6. An execution pins the bundle digest for its lifetime. Branch updates, rebases, tag moves, and editor autosave cannot change it.
7. Rollback is a new promotion of a previously verified digest, with current vulnerability and compatibility checks. It is not a mutable rewrite of the active release.

Import processing shall reject path traversal, symlink escape, special-device files, case-collision ambiguity, archive bombs, oversized content, unsupported encodings, and undeclared generated artifacts. Source normalization must not change authoritative SPELL semantics; the release manifest retains the exact reviewed bytes.

## Driver release controls

Drivers are separately versioned deployable artifacts and shall include:

- authoritative interface compatibility version and supported server range;
- command and telemetry schemas, error taxonomy, timeout/retry/deduplication behavior, and privilege requirements;
- test corpus for malformed frames, boundary values, disconnects, restarts, concurrency, and ambiguous acknowledgments;
- simulation or hardware-in-the-loop evidence for the target protocol/device version;
- SBOM, provenance, signature, vulnerability disposition, and support owner;
- deployment constraints for mission, satellite, environment, endpoint, and credential policy.

A driver upgrade cannot be combined with a production command-path change without an explicit integration and rollback plan. The platform shall support fencing or disabling one faulty driver without granting another driver automatic command ownership.

## Dependency and supplier management

The Supply Chain Risk Manager shall maintain a tiered inventory of software, services, hardware, build tools, base images, registries, and critical data providers (`SEC-016`, `SEC-017`). Tiers consider command-path privilege, CUI access, build/signing authority, substitutability, maintenance health, geopolitical/ownership concerns where required, and incident notification capability.

For each critical supplier or dependency, record:

- supplier, component, version, source, license, owner, purpose, and transitive dependencies;
- privileges, data access, network access, and affected trust boundaries;
- update channel, signature/provenance mechanism, vulnerability disclosure, and support/end-of-life dates;
- evaluation evidence and known risks;
- approved alternatives, removal plan, and continuity strategy;
- contractual security, notification, evidence, access, data return/destruction, and support terms where applicable.

Typosquatting protection, package namespace controls, repository allowlists, dependency confusion prevention, and integrity verification shall be enabled. Production builds shall not download unpinned dependencies from public registries.

## Vulnerability management

Sources include vendor notices, CISA or agency directives, SBOM correlation, scanners, penetration tests, bug reports, incidents, and threat intelligence. Every actionable finding receives an owner, affected digests/deployments, exploitability analysis, CUI/mission impact, treatment, due date, verification, and disposition.

Unless an agency, contract, or approved risk policy is stricter, the proposed maximum remediation windows are:

| Condition | Containment/decision | Remediation target |
| --- | --- | --- |
| Known exploitation or credible command/CUI compromise path | Immediate triage; containment decision within 24 hours | As soon as safely testable, target 7 calendar days |
| Critical severity, reachable in deployment | 2 business days | 15 calendar days |
| High severity, reachable in deployment | 5 business days | 30 calendar days |
| Medium severity | 15 business days | 90 calendar days |
| Low severity | Next scheduled maintenance planning | 180 calendar days or documented lifecycle plan |

These are starting policy values, not automatic risk acceptance. Mission safety may make an immediate patch more dangerous than isolation or compensating control; the accountable Risk Owner documents the decision. Overdue exceptions expire, alert, and return to review.

## Secrets, signing, and build identities

- Build, release, and deployment identities are separate and non-human.
- Signing keys are non-exportable where the approved key service supports it, scoped by artifact class and environment, rotated, monitored, and recoverable under dual control.
- CI jobs receive short-lived credentials only after repository, workflow, revision, and environment policy checks.
- Pull requests from untrusted forks or contributors cannot access production secrets or signing identities.
- Logs and build artifacts are scanned and redacted, but redaction is not relied on to make secret injection acceptable.
- Key compromise triggers signature revocation, artifact impact analysis, rebuild/resign, deployment inventory queries, and incident response.

## Configuration and infrastructure as code

Network policy, identity roles, authorization policy, database grants, orchestration, secrets metadata, observability rules, backup policy, and hardened baselines shall be version-controlled and reviewed (`SEC-015`). Generated plans are attached to review. Apply identities may deploy only approved plans to their intended environment.

Drift monitoring compares deployed state with the approved revision. An emergency change shall have a reason, accountable actor, bounded scope, expiry where possible, security/mission notification, validation, and prompt reconciliation back into source. Unexplained drift is a security event.

## Evidence and retention

The engineering evidence package shall include:

- review and approval record tied to final source digest;
- threat-model/change-impact record;
- test result manifests and logs with tool versions;
- SBOM, provenance, signatures, scan results, suppressions, and vulnerability disposition;
- procedure/driver compatibility and qualification evidence where applicable;
- release manifest and revocation state;
- deployment and post-deployment verification records;
- exceptions, risk approvals, expiry, and closure evidence.

Evidence is retained according to the SSP, contract, records schedule, incident/legal hold, and software support lifetime. Evidence that contains CUI or sensitive security details stays in an authorized evidence store; this repository contains only approved references.

## Process metrics

Product Security reports at least:

- percent of deployable artifacts with verified SBOM, provenance, and signature;
- dependency age/end-of-life exposure and critical supplier coverage;
- findings by severity, exploitability, age, exception, and affected deployment;
- mean time to triage, contain, remediate, verify, and revoke;
- protected-branch/review policy bypasses and emergency changes;
- release admission failures and deployed drift duration;
- security test coverage for authorization, fencing, isolation, protocols, recovery, and audit;
- procedure and driver releases lacking current compatibility or qualification evidence.

Metrics shall not reward premature closure or scanner suppression. A finding closes only after the affected artifact/deployment is remediated or an authorized, unexpired residual-risk decision is in force.
