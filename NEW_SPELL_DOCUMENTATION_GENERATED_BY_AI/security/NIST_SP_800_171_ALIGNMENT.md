# NIST SP 800-171 Alignment

## Alignment statement

SPELL is designed to provide technical capabilities and evidence that support an organization's protection of Controlled Unclassified Information (CUI). This document is not a certification, attestation, or statement that every requirement is satisfied. NIST SP 800-171 is intended for use through federal-agency contractual vehicles for nonfederal systems and organizations that process, store, or transmit CUI. It does not govern a nonfederal system operated on behalf of a federal agency; that system is handled under the agency's federal-system authorization requirements. Applicability is established by the governing agency, contract, or program authority. After applicability is established, the requirements apply to the CUI-processing components and the components that protect them. The final determination depends on the deployed boundary and the organization's policies, people, facilities, contracts, parameter assignments, assessment, and operation.

The baseline for this documentation is [NIST SP 800-171 Revision 3, Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/171/r3/final), final May 14, 2024. Assessment planning uses [NIST SP 800-171A Revision 3](https://csrc.nist.gov/pubs/sp/800/171/a/r3/final), also final May 14, 2024. The publication versions and errata shall be checked at each security baseline review.

[NIST's CUI publications page](https://csrc.nist.gov/Projects/protecting-controlled-unclassified-information/publications) is the source for related publications. [NIST SP 800-172 Revision 3](https://csrc.nist.gov/pubs/sp/800/172/r3/final) enhanced requirements apply only when a federal agency selects and requires them for CUI associated with a critical program or high-value asset; the agency need not select every enhanced requirement. An internal risk assessment may motivate voluntary adoption but does not establish NIST applicability. Enhanced requirements are not silently added to this baseline.

## Scope decisions required per deployment

Before assessing requirements, the governing authority shall record the agency,
contract, or program applicability basis and whether the system is operated on
behalf of an agency. The System Owner shall then approve:

| Decision | Required record |
| --- | --- |
| Governing applicability | Agency/contract/program citation, selected baseline/overlays, operated-on-behalf determination, decision owner and date |
| CUI categories and handling | Data classification and marking guide |
| Authorization boundary | Versioned boundary diagram and component inventory |
| CUI data flows | Source, destination, purpose, protocol, protection, retention, and owner |
| External systems | Interconnection agreement, responsibility, trust basis, and evidence exchange |
| Component disposition | In-boundary CUI component, security protection component, isolated non-CUI component, or out of scope with justification |
| Deployment environments | Development, integration, simulation, training, staging, production, recovery, and their permitted data |
| Shared responsibility | Requirement objectives assigned to organization, platform, product, facility, cloud/service provider, or external mission system |
| Applicable overlays | Agency, contract, CUI category, export, records, privacy, and enhanced-security obligations |

An architectural diagram alone does not establish scope. The inventory shall include identity, endpoint, network, time, DNS, monitoring, build, secrets, backup, Git, artifact registry, orchestration, and administrative systems that protect the CUI environment.

## Governance artifacts

The authorization package shall contain, at minimum:

- a System Security Plan for requirement 03.15.02 (`SEC-002`);
- an objective-level matrix instantiated from [NIST Requirement and Assessment Matrix Template](NIST_REQUIREMENT_ASSESSMENT_MATRIX.md), with every official requirement and determination statement reconciled;
- an Organization-Defined Parameter (ODP) register recording agency or contract assignments and approved organizational assignments;
- policies and procedures referenced by the SSP;
- evidence index with location, custodian, collection period, integrity metadata, and sensitivity;
- assessment plan and results based on SP 800-171A Revision 3;
- a risk register and Plan of Action and Milestones for requirement 03.12.02;
- approved exceptions, compensating controls, expiration dates, and residual-risk acceptance;
- change-impact assessments and continuous-monitoring reports.

The SSP shall describe the system as operated, not an intended future design. Planned capabilities are identified as planned and tracked to delivery and verification.

## Organization-defined parameters

An ODP is not filled in by product source code. The Security Officer shall maintain a controlled register with these fields:

| Field | Meaning |
| --- | --- |
| Requirement/parameter | NIST identifier and parameter label |
| Source | Agency, contract, law, policy, or approved organization assignment |
| Value | Exact frequency, duration, event, role, technology, or threshold |
| Scope | Boundary, environment, data class, role, and component applicability |
| Rationale | Risk and operational basis |
| Approver/effective date | Accountable authority and activation date |
| Implementation references | Policy, configuration, test, and evidence locations |
| Review trigger | Scheduled review and events that force reassessment |

If the agency or contract has not supplied a required value, the organization shall assign and approve it before authorization. SPELL configuration shall consume approved values where technically applicable and shall never invent a value at runtime.

## Family-level capability and evidence map

This table is an architectural allocation, not a completed control assessment. Every family requires a more detailed objective-level record derived from SP 800-171A.

| Rev. 3 family | SPELL/platform capabilities | Typical evidence | Accountable evidence owners |
| --- | --- | --- | --- |
| Access Control | Deny-by-default API policy; RBAC plus mission, satellite, environment, procedure, execution, mode, and lease attributes; server-enforced monitor read-only behavior; single-controller lease and fencing; network egress restrictions | Role/action matrix, policy bundles, access reviews, denied-action tests, lease-race tests, network rules | System Owner, IAM Owner, Application Owner, Network Owner |
| Awareness and Training | Role-specific training requirements and in-product acknowledgement hooks; no product substitution for organizational training | Training plan, course content, completion and refresher records, controller qualification | Training Manager, Security Officer, Mission Operations Manager |
| Audit and Accountability | Structured security audit separate from diagnostics; subject/action/resource/outcome correlation; append-only ingestion, signed checkpoints, immutable export, time health | Audit schema, sample records, access logs, integrity verification, alert and retention tests | Security Operations, Application Owner, Records Owner |
| Security Assessment and Monitoring | Assessment-ready configuration/evidence export; continuous security metrics; findings and POA&M workflow integration | SSP, SP 800-171A assessment plan/results, scan and test records, POA&M, monitoring reports | System Owner, Security Officer, Assessment Sponsor, Authorized Assessor |
| Configuration Management | Version-controlled baselines; signed artifacts; reviewed infrastructure and policy; drift detection; emergency-change reconciliation | Baseline inventory, approvals, diffs, deployment attestations, drift alerts, change tickets | Configuration Manager, Platform Owner, Security Officer |
| Identification and Authentication | Federated unique identities, MFA, workload identities, mTLS, credential lifecycle, break-glass controls | Identity-provider policy, authenticator inventory, certificate logs, account lifecycle tests, access reviews | IAM Owner, PKI Owner, Security Officer |
| Incident Response | Security detection, classified incident routing, mission-aware containment, evidence preservation, exercised playbooks | Incident plan, contact roster, alert-to-case records, exercise reports, lessons and corrective actions | Incident Commander, Security Operations, Mission Operations |
| Maintenance | Authorized maintenance paths, managed tools/endpoints, time-limited vendor access, recorded sessions where policy requires, post-maintenance validation | Maintenance policy, tool inventory, approvals, session/access records, verification results | Platform Owner, Facility/Hardware Owner, Security Officer |
| Media Protection | CUI-aware export, encryption, removable-media restrictions, secure disposal, controlled backup media | Media inventory, transfer approvals, encryption evidence, sanitization certificates, export logs | Media Custodian, Records Owner, Security Officer |
| Physical Protection | Product supports no standalone physical control; deployment requires protected facilities, consoles, media, network equipment, and visitor controls | Facility plan, access logs, visitor records, physical risk assessment | Facility Security Officer, System Owner |
| Planning | Boundary/data-flow documentation, SSP content, operating concept, architecture, rules of behavior inputs | Approved SSP, architecture, boundary inventory, rules of behavior, review records | System Owner, Security Officer, Architecture Owner |
| Personnel Security | Unique identity and prompt deprovisioning integration; organization conducts screening, transfer, termination, and sanctions | Screening attestations, onboarding/transfer/offboarding records, access revocation tests | Human Resources, Personnel Security, IAM Owner |
| Risk Assessment | Threat model, dependency and vulnerability data, risk register, mission hazard linkage, periodic reassessment | Risk methodology, threat model, vulnerability scans, risk decisions, reassessment reports | Risk Owner, Security Officer, Mission Safety Owner |
| System and Services Acquisition | Security requirements in procurement and development; secure SDLC; supplier controls; SBOM, provenance, support and end-of-life planning | Acquisition clauses, design reviews, SBOMs, attestations, supplier assessments, lifecycle plan | Acquisition Owner, Product Owner, Supply Chain Risk Manager |
| System and Communications Protection | Segmentation, TLS/mTLS, cryptographic key management, boundary protections, secure sessions, service isolation | Diagrams, firewall/network policies, certificate and module inventory, protocol tests, configuration scans | Network Owner, PKI Owner, Platform Owner |
| System and Information Integrity | Signed artifacts and bundles, image admission, malware and vulnerability controls, integrity monitoring, patching, security alerts | Signature verification, scans, patch reports, detection alerts, incident records | Security Operations, Product Security, Platform Owner |
| Supply Chain Risk Management | Supplier inventory/tiering, dependency pinning, protected build, SBOM, provenance, artifact signing, supplier change and vulnerability monitoring | SCRM plan, supplier assessments, dependency inventory, SBOM/provenance, exceptions, incident notices | Supply Chain Risk Manager, Acquisition Owner, Product Security |

## Selected high-impact requirement implementations

These examples clarify responsibility. The complete assessment matrix shall include every applicable requirement and every SP 800-171A determination statement.

### 03.15.02 System Security Plan

The organization owns and approves the SSP. SPELL provides the architecture, component inventory inputs, interface definitions, security capability descriptions, configuration exports, and evidence references. The deployment SSP shall identify the authorization boundary, operating environment, implementation status of each requirement, connections, inherited controls, ODPs, and planned remediation. A generic product document cannot replace it.

### 03.12.02 Plan of Action and Milestones

Each unsatisfied or partially satisfied requirement shall be evaluated under governing policy. Where a POA&M is permitted, it records the weakness, affected assets, risk, source, owner, milestones, resources, target dates, dependencies, validation method, status, and closure evidence. A POA&M is not approval to leave an unsafe command path operating. Findings that violate a safety invariant or create uncontrolled CUI exposure require containment or an explicit authorization decision.

### 03.13.11 Cryptographic Protection

The deployment cryptographic standard shall identify the organization-defined types of CUI requiring protection and the cryptographic mechanisms approved for each data state and interface. It shall inventory protocol versions, cipher policy, modules, validation certificates where applicable, key lengths, key custody, rotation, revocation, recovery, and exceptions. FIPS-validated cryptography is mandatory when assigned by the agency/contract or another governing requirement and is the recommended baseline for U.S. Government CUI deployments. Validation belongs to the precise module/version/operational environment, not to a marketing claim about an algorithm.

## SP 800-171A assessment method

The assessment sponsor or customer, in coordination with the authorized assessor, shall approve assessment purpose, scope, depth, coverage, sampling, and methods while preserving every applicable determination objective. SP 800-171A supports internal, independent, third-party, and government-sponsored assessments; assessor independence is required only when governing policy or contract requires it. Assessment activities use the methods of examine, interview, and test.

| Method | SPELL examples |
| --- | --- |
| Examine | Source and build manifests, architecture, configuration, policy, access matrix, audit samples, SBOM, certificate inventory, backup records |
| Interview | Controllers, monitors, procedure developers, reviewers, administrators, security responders, records custodians, facility staff |
| Test | Authentication and revocation; role denial; cross-satellite isolation; controller lease races; stale fencing rejection; WebSocket authorization; audit integrity; restore; incident alerting; signed artifact admission |

Each assessment record shall include requirement and objective identifiers, scope, method, assessor, date, sample, expected result, actual result, evidence link and digest, finding, and disposition. Evidence containing CUI or sensitive security information remains inside its authorized repository; the index may reference it without copying it into the documentation repository.

## Evidence collection architecture

Evidence shall be reproducible and tied to deployed versions:

1. CI emits source revision, build identity, dependency lock digest, SBOM digest, test results, signed provenance, and artifact digest.
2. Deployment admission verifies signatures and records environment, configuration revision, migration revision, policy revision, image/bundle digests, and approver.
3. Runtime exports identity configuration metadata, access policy version, certificate/key metadata without secrets, machine-verifiable baseline configuration and drift-check results, security events, audit checkpoints, backup status, and monitoring coverage. These records are assessment evidence, not a compliance determination.
4. The evidence index binds artifacts to requirement objectives, owner, collection period, integrity hash, storage location, classification, and retention.
5. Assessment snapshots are immutable and do not rely on mutable dashboards as historical evidence.

The [NIST Cybersecurity and Privacy Reference Tool](https://csrc.nist.gov/projects/cprt/catalog) may be used to obtain machine-readable control catalogs and support traceability. Imported catalogs shall record their source publication, revision, retrieval date, and digest.

## Continuous monitoring and change impact

The following changes require security impact review before or immediately under an approved emergency process:

- authorization boundary, CUI flow, satellite/mission topology, or external connection;
- identity provider, authenticator, authorization policy, controller lease, or privileged role;
- command path, driver, procedure compiler, execution isolation, or safety policy;
- cryptographic module, protocol, certificate authority, secret/key store, or key custody;
- database, object store, event transport, observability, audit, backup, or recovery architecture;
- hosting provider, region, facility, supplier, build service, base image, or critical dependency;
- a new vulnerability, threat, incident, or contract requirement that invalidates an assumption.

The review shall update the SSP, boundary/data-flow inventory, ODP register, threat model, requirement matrix, evidence plan, tests, risk register, and POA&M as affected.

## Approval gates

An alignment statement shall identify its governing applicability basis and use qualified wording approved by the System Owner and Security Officer. A compliance or authorization determination remains with the governing authority and authorized Risk Owner or Authorizing Official. Prior to authorization, the accountable roles shall confirm:

- all applicable objectives are mapped and assessed, not only the 17 family rows above;
- the governing applicability basis and operated-on-behalf determination are recorded;
- inherited and external controls have current provider evidence and clear responsibility;
- all ODPs are assigned and implemented;
- test samples cover each production topology and satellite-isolation model;
- findings are remediated, formally accepted, or placed on an authorized POA&M;
- technical evidence matches the exact production artifact and configuration;
- operational, personnel, facility, media, incident, and training controls are represented;
- assessment results and claims have an explicit validity period and change triggers.
