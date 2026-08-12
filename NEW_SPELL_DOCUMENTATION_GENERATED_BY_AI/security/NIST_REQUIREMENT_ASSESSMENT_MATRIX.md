# NIST Requirement And Assessment Matrix Template

## Purpose

This is the mandatory deployment template for objective-level NIST SP 800-171
Rev. 3 traceability. The family allocation in
[NIST_SP_800_171_ALIGNMENT.md](NIST_SP_800_171_ALIGNMENT.md) is an architecture
summary; it cannot be used as a requirement-by-requirement assessment.

Each deployment evidence repository shall instantiate this template from the
official [SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
and [SP 800-171A Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/a/r3/final)
catalogs. The matrix belongs inside the authorized evidence boundary because
implementation descriptions, findings, and evidence may contain CUI or
security-sensitive information. This documentation repository stores only the
template.

## Applicability Gate

The governing federal agency, contract, or program authority shall establish
whether SP 800-171 applies. The System Owner shall then define the component
boundary and information flows. Boundary selection scopes the assessment after
applicability is established; it does not establish applicability by itself.

The master register shall account for every requirement in the pinned official
catalog with exactly one controlled status:

| `ApplicabilityStatus` | Permitted basis |
| --- | --- |
| `APPLICABLE` | Governing scope includes the requirement and deployment |
| `NOT_APPLICABLE` | Explicit governing scope, authorized tailoring, or agency/contract decision supports exclusion |
| `UNRESOLVED` | Applicability is not yet decided; authorization and compliance claims are blocked |

`INHERITED` and `SHARED` are responsibility allocations for an `APPLICABLE`
requirement, never applicability statuses. They do not remove any ODP,
implementation, evidence, assessment, finding, or review duty. A separately
identified selectable overlay such as SP 800-172 uses a distinct
`OverlaySelectionStatus` of `SELECTED`, `NOT_SELECTED`, or `UNRESOLVED`, with the
selection authority, date, scope, and rationale recorded. `NOT_SELECTED` shall
not appear on a base SP 800-171 requirement row.

An implementation team shall not mark a requirement non-applicable solely
because the product lacks a feature, the evidence is difficult to obtain, or
the organization prefers a compensating control.

## Catalog Initialization

1. Record publication title, revision, publication date, retrieval date, source
   URL, machine-readable catalog version, and content digest.
2. Import one master row for every official `03.xx.xx` requirement.
3. Import one child row for every official SP 800-171A determination statement,
   preserving its exact identifier and parent requirement relationship.
4. Reconcile imported counts by family and total to the pinned official source.
5. Prevent deletion of a source row; use status and supersession fields.
6. Require change-impact review when NIST issues an update or erratum or when
   boundary, contract, ODP, provider, implementation, or evidence changes.

The [NIST Cybersecurity and Privacy Reference Tool](https://csrc.nist.gov/projects/cprt/catalog)
may supply machine-readable source material. The deployment shall pin and hash
the retrieved catalog rather than depend on a mutable online response during an
assessment.

## Requirement Register Schema

Maintain one row per official requirement with these fields:

| Field | Required content |
| --- | --- |
| `CatalogVersion` | Exact SP 800-171 revision/catalog digest |
| `RequirementId` | Official `03.xx.xx` identifier |
| `Family` / `Title` | Official family and requirement title reference |
| `ApplicabilityStatus` | `APPLICABLE`, `NOT_APPLICABLE`, or `UNRESOLVED` from the table above |
| `OverlaySelectionStatus` | For a separately identified selectable-overlay row only: `SELECTED`, `NOT_SELECTED`, or `UNRESOLVED`, with governing selection authority |
| `ApplicabilityAuthority` | Agency, contract, program, law/policy, or approved tailoring citation |
| `ApplicabilityDecision` | Decision owner, date, rationale, scope, review trigger |
| `BoundaryComponents` | Components and flows to which the row applies |
| `ODPAssignments` | Each parameter, source, exact value, scope, approver, effective date |
| `Allocation` | Responsibility model (`DIRECT`, `INHERITED`, or `SHARED`) plus the exact product, platform, organization, facility, provider, or external mission system duties |
| `Implementation` | Implemented behavior as operated, not future intent |
| `ConfigurationReferences` | Baseline/policy/configuration IDs and digests |
| `EvidenceOwners` | Accountable owner and evidence custodian |
| `AssessmentStatus` | Not assessed, satisfied, other-than-satisfied, or sponsor-approved vocabulary |
| `Findings` | Finding IDs, severity/risk, affected assets and current containment |
| `POAM` | Authorized POA&M reference, milestones, owner, dates, validation |
| `RiskDecision` | Authorized risk owner, decision, conditions, expiry/review |
| `LastAssessment` / `NextReview` | Assessment identity/date and required reassessment trigger |

## Determination Statement Schema

Maintain one row per SP 800-171A determination statement:

| Field | Required content |
| --- | --- |
| `RequirementId` | Parent SP 800-171 requirement |
| `DeterminationId` | Exact official SP 800-171A determination identifier |
| `ObjectiveReference` | Catalog reference to the determination text; avoid uncontrolled copies |
| `Applicability` | Exact applicability inherited from the parent requirement; a determination statement cannot independently change it |
| `ResponsibilityAllocation` | Direct, inherited, or shared assessor/evidence responsibility and the exact implementing parties, inherited from or consistent with the parent allocation |
| `Method` | Examine, interview, test, or approved combination |
| `Objects` | Specifications, mechanisms, activities, records, people, and components examined |
| `Depth` / `Coverage` | Sponsor-approved values and rationale |
| `Sample` | Population, sampling method, size, period, environment, exclusions |
| `Procedure` | Reproducible assessment procedure or test identifier/version |
| `ExpectedResult` / `ActualResult` | Objective result and recorded observation |
| `Evidence` | Authorized URI, digest, classification, custodian, collection time, retention |
| `Assessor` | Assessor identity, organization, role and required independence status |
| `Result` | Satisfied, other-than-satisfied, not assessed, or sponsor-approved vocabulary |
| `Finding` / `POAM` | Linked finding and remediation/risk disposition |
| `ArtifactBaseline` | Exact software, procedure, configuration and deployment digests assessed |

## Shared Responsibility

For inherited or shared controls, the matrix shall identify who implements,
operates, monitors, assesses, supplies evidence, remediates findings, and accepts
residual risk. A provider assertion without current scope-matched evidence does
not satisfy the row. Product capability marked `AVAILABLE` is not equivalent to
deployment configuration marked `IMPLEMENTED` or assessment marked `SATISFIED`.

## Quality Queries

The deployment evidence pipeline shall fail its authorization gate when any of
these queries returns a row:

- official source requirement or determination ID has no matrix row;
- matrix row references an ID absent from the pinned catalog;
- applicable requirement, including one allocated `INHERITED` or `SHARED`, has
  an unassigned ODP, owner, operated implementation, evidence duty, assessment
  disposition, or determination statement;
- non-applicable base row lacks governing authority and rationale;
- separately identified `NOT_SELECTED` overlay row lacks selection authority,
  scope, and rationale, or a `SELECTED` row lacks full applicable-row coverage;
- inherited or shared applicable row lacks exact provider responsibility,
  scope-matched current evidence, assessment responsibility, or remediation duty;
- assessment result lacks exact artifact/configuration identity or evidence;
- other-than-satisfied result lacks containment and authorized disposition;
- POA&M milestone is overdue or closure lacks validation evidence;
- risk acceptance or exception is expired;
- material change occurred after the last valid assessment.

## Assessment Approval

The assessment sponsor or customer approves purpose, scope, methods, depth,
coverage, sampling, assessor qualifications, and any required independence in
coordination with the authorized assessor. SP 800-171A supports internal,
independent, third-party, and government-sponsored uses; independence is
required only when governing policy or contract requires it.

Completing this matrix creates assessment evidence. It does not by itself create
a certification, authorization, or compliance determination.
