# Document Control

## Baseline Identity

| Field | Value |
| --- | --- |
| Repository | `NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI` |
| Specification | Next-Generation SPELL Design Specification |
| Version | `0.1.0-draft.1` |
| Prepared | 2026-07-18 |
| Status | Draft for human review |
| Project-declared AI assistance tool | ChatGPT 5.6 SOL |
| Supersedes | None |
| Product code delivered | None |
| Operational authorization | None |
| `NG-WP-00` readiness | Local v0.4 Gate G0 `PASS`; bounded Candidate A implementation authorized; broader specification remains Draft |

The specification version is independent of product releases, the legacy SPELL
2.4.4 manuals, later legacy binaries, procedure repositories, driver versions,
and deployment configuration versions.

## Normative Language

- **Shall** or **shall not** expresses a mandatory, testable requirement.
- **Should** or **should not** expresses a recommendation whose exception must be
  justified and recorded.
- **May** expresses a permitted option, not a promise of implementation.
- **Target** expresses a value that is not binding until its owner approves it.
- **TBD** is an unresolved decision and must point to an entry in
  `quality/OPEN_DECISIONS.md`.

Descriptive diagrams, examples, notes, and rationale do not override a `shall`
requirement. A conflict is resolved using `SOURCE_AUTHORITY.md`, then recorded as
a controlled change.

Every document under the parent repository's `SPELL_DOCUMENTATION/` directory
is a mandatory source-reference input. This generated specification is a
controlled interpretation of that source baseline. A requirement or
descriptive document may modernize an implementation mechanism or establish a
safe incompatibility only when the source identity, conflict, disposition, and
verification evidence are recorded together.

`requirements/SYSTEM_REQUIREMENTS.md` is the sole atomic product-requirement
register. Detailed documents may use `shall` to elaborate an allocated central
requirement, but that wording cannot create a new obligation. Every normative
document is mapped in `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`; a new
obligation requires a central ID, owner, verification method, and trace target
in the same change.

## Approval Roles

| Role | Required decision |
| --- | --- |
| Product owner | Scope, priorities, operating modes, and product acceptance |
| Mission operations authority | Operator workflows, hazard controls, degraded behavior, and operational acceptance |
| System architect | Boundaries, protocols, data ownership, concurrency, HA, and technology decisions |
| Language authority | Language compatibility, errata, diagnostics, and migration dispositions |
| Driver authority | Driver service contracts, capability negotiation, and adapter conformance |
| Governing agency/contract/program authority | SP 800-171/172 applicability, contractual selection, and operated-on-behalf determination |
| System Owner | CUI/system boundary, SSP approval, control allocation, system operation, and authorization package |
| Security officer | Coordinates security architecture, ODP register, safeguard implementation, evidence, continuous monitoring, assessment support, and POA&M; advises but does not solely accept risk |
| Risk Owner or Authorizing Official | Accepts, rejects, or conditions residual security risk within delegated authority |
| Assessment sponsor/customer | Defines assessment purpose, scope, depth, coverage, sampling, assessor qualifications, and required independence |
| Quality lead | Traceability, verification sufficiency, release evidence, and independent test findings |
| Configuration manager | Baselines, signed releases, retention, reproducibility, and change records |

ChatGPT 5.6 SOL is the project-declared AI assistance tool used to draft,
analyze, and check this repository. AI assistance cannot fill any approval
role, accept risk, determine CUI scope, authorize operations, or certify
compliance. Accountable humans remain responsible for source verification,
technical review, decisions, approvals, and use of the resulting specification.

## Document States

| State | Meaning | Permitted use |
| --- | --- | --- |
| Draft | Authored but not reviewed by every accountable role | Design discussion and prototype planning only |
| Reviewed | Technical review findings are resolved or explicitly open | Bounded implementation behind unapproved interfaces |
| Approved | Required roles signed the baseline and all entry gates passed | Normative implementation baseline |
| Superseded | A newer approved baseline identifies the replacement | Historical evidence only |
| Withdrawn | The content is invalid or unsafe and has no replacement | Do not implement |

The repository is currently **Draft**. Individual documents cannot silently claim
a stronger state than this repository baseline.

## Versioning

Use semantic document versions:

- Major: incompatible requirement, interface, authority, or safety-model change.
- Minor: backward-compatible requirement or document addition.
- Patch: clarification, correction, or traceability improvement with no changed
  observable requirement.
- Pre-release suffix: draft or release-candidate state.

An approved baseline shall be represented by a signed Git tag and a generated
manifest containing every tracked path and SHA-256 digest. The tag, source
authority hashes, requirement snapshot, decision states, and assessment evidence
shall be retained together.

The Draft broader-spec allocation registry, candidate exhaustive local v0.4
compatibility disposition catalog, project-owner record, and readiness report
are controlled evidence. A structurally successful validator result alone does
not change this repository's state, verify a signature, authorize a broader
work package, or make an operational or compliance claim.

### Local v0.4 Gate Profile

For the local-only, synthetic non-CUI Candidate A engineering gate, JC Arcaz is
the sole required approval role. The direct owner instruction approves the
Candidate A scope, its exclusions, budgets, and test plan. Organization,
mission, protected-data, assessment, deployment, authorizing-official, proposed
ADR, and other role-based approvals are outside this local gate.

Gate 0 binds the exact local gate files with a deterministic SHA-256 manifest.
That manifest is change-detection evidence, not a signature or signed tag. The
owner's scope-disposition policy assigns source artifacts to Candidate A or
Deferred/`EXCLUDE`; deterministic validation and independent review, rather
than a claim of row-by-row owner source review, establish technical catalog
correctness. This profile does not approve the broader Draft specification or
alter later release, connected-scope, deployment, operational, or compliance
decision requirements.

## Change Workflow

1. Open a change record with reason, affected stakeholders, requirements, and
   hazard/security impact.
2. Update normative requirement rows before or with descriptive documents.
3. Add or amend an Architecture Decision Record (ADR) when the change affects a
   cross-system choice.
4. Update compatibility disposition, traceability, tests, migration, rollback,
   and operational procedures.
5. Run documentation and requirement consistency checks.
6. Obtain approval from every role affected by the change.
7. Merge through protected Git workflow and issue a signed baseline tag.

Emergency changes shall use the same evidence model. They may use an expedited
approval path defined by the organization, but they shall be retrospectively
reviewed within an organization-defined interval.

## Review Cadence

| Trigger | Required review |
| --- | --- |
| Every planned product increment | Requirements, ADRs, compatibility, verification, and open decisions |
| New GCS or driver | Driver authority, threat model, capability and failure contracts |
| New satellite or mission | Domain isolation, workload, hazards, retention, RPO/RTO, and authorization |
| Security baseline or contract change | CUI boundary, SSP, ODPs, assessment objectives, POA&M, and evidence |
| Major dependency or platform change | Architecture, supply chain, performance, recovery, and rollback |
| Incident or failed recovery exercise | Hazard assumptions, runbooks, controls, tests, and accepted risks |

## Repository Quality Rules

- Every normative requirement shall have a stable ID, verification method, owner
  role, and trace target.
- Every detailed normative clause shall be covered by the document allocation
  register and shall not expand its allocated central requirements silently.
- Every external authority shall have an exact title, version, location, and
  integrity reference where locally available.
- All relative links shall resolve in the approved baseline.
- Examples shall be labeled non-normative unless they are conformance vectors.
- Secrets, access tokens, CUI, production endpoints, and proprietary legacy code
  shall not be committed to this repository.
- Generated diagrams shall have a text equivalent.
- The approved baseline shall contain no unresolved placeholder that can change
  safety, security, interoperability, or externally visible behavior.
