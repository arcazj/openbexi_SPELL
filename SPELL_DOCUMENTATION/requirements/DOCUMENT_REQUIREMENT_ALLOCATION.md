# Document Requirement Allocation

## Purpose And Authority

`SYSTEM_REQUIREMENTS.md` is the sole register of atomic SPELL product and
documentation requirements. It owns every stable requirement ID, normative
requirement statement, verification method, and accountable owner. A normative
clause in any other document may only elaborate, constrain, allocate, or provide
verification detail for the central IDs assigned to that document below. It
cannot create an additional obligation, weaken a central requirement, change its
owner, or change its verification method.

If a detailed clause cannot be traced without stretching the meaning of an
allocated ID, the change must add or revise a row in `SYSTEM_REQUIREMENTS.md`
first and update this allocation, traceability, verification, migration,
rollback, and approvals in the same controlled change. Document allocation is a
semantic boundary, not a substitute for clause-level engineering review.

This allocation covers every Markdown document in the candidate baseline,
including administrative records, authority records, proposed ADRs, evidence
templates, and quality gates. A document with no current mandatory clause is
listed so that future normative text cannot enter it without an allocation.

The approval-role columns below belong to the broader next-generation Draft.
They are retained for future connected, mission, protected-data, deployment,
and organization-governed work. They are not approval requirements for the
bounded local-only, synthetic non-CUI Candidate A v0.4 engineering gate, whose
only human approval role is project owner JC Arcaz. This separation makes no
operational authorization or compliance determination.

## Allocation Vocabulary

| Function | Meaning |
| --- | --- |
| Normative design | Elaborates implementation or externally observable behavior within the allocated central IDs. |
| Authority record | Preserves or identifies an external authority; quoted authority content is handled by the exception rules below. |
| Decision record | Records a proposed or approved architectural choice that implements the allocated IDs; context, alternatives, and rationale are non-normative. |
| Evidence or gate | Defines evidence structure, review, or acceptance activity for the allocated IDs; it does not create product behavior. |
| Control or index | Controls the specification or navigates to normative content; summaries never override their sources. |

Role abbreviations are: PO, Product Owner; MO, Mission Operations Authority;
SA, System Architect; LA, Language Authority; DA, Driver Authority; GA,
Governing Agency/Contract/Program Authority; SY, System Owner; SO, Security
Officer; RO, Risk Owner or Authorizing Official; AS, Assessment
Sponsor/Customer; QL, Quality Lead; and CM, Configuration Manager. The
verification role checks the document and its evidence. Approval roles approve
the document's technical allocation; repository-level approval still follows
`DOCUMENT_CONTROL.md` and the acceptance checklist.

## Control, Authority, And Requirements

| Document | Function | Allocated central IDs | Verification role | Required technical approval |
| --- | --- | --- | --- | --- |
| `README.md` | Control or index | DOC-001..DOC-002, DOC-006..DOC-007, DOC-009..DOC-011 | QL, CM | PO, SA, QL, CM |
| `DOCUMENT_CONTROL.md` | Control or index | DOC-001..DOC-002, DOC-005..DOC-010; VNV-012 | CM, QL | PO, MO, SA, LA, DA, GA, SY, SO, RO, AS, QL, CM |
| `SOURCE_AUTHORITY.md` | Authority record | DOC-003..DOC-005, DOC-008; COMP-001, COMP-003, COMP-013 | CM | LA, DA, CM |
| `GLOSSARY.md` | Control or index | DOC-002, DOC-006, DOC-009..DOC-010 | QL | SA, LA, DA, SO, QL |
| `CHANGELOG.md` | Control or index | DOC-001, DOC-006, DOC-009 | CM | QL, CM |
| `requirements/SYSTEM_REQUIREMENTS.md` | Atomic requirements register | DOC-001..DOC-011; ARC-001..ARC-040; SRV-001..SRV-022; EXEC-001..EXEC-028; COM-001..COM-027; DATA-001..DATA-029; WEB-001..WEB-037; MODE-001..MODE-027; GIT-001..GIT-024; REL-001..REL-029; SEC-001..SEC-023; OPS-001..OPS-010; COMP-001..COMP-022; DEP-001..DEP-025; VNV-001..VNV-012 | QL plus each row owner | Every accountable owner for changed rows |
| `requirements/TRACEABILITY_MATRIX.md` | Evidence or gate | DOC-002, DOC-006, DOC-009..DOC-011; VNV-001..VNV-002, VNV-012 | QL | SA, LA, DA, SO, QL, CM |
| `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md` | Control or index | DOC-001..DOC-002, DOC-006, DOC-009..DOC-010; VNV-002, VNV-012 | QL | SA, QL, CM |
| `requirements/COMPATIBILITY_LEDGER.md` | Evidence or gate | DOC-003..DOC-006; COMP-001..COMP-022; VNV-003..VNV-004, VNV-011..VNV-012 | QL | LA, DA, MO, QL, CM |
| `preserved/LANGUAGE_REFERENCE_AUTHORITY.md` | Authority record | DOC-003, DOC-005..DOC-006; COMP-001..COMP-006, COMP-008, COMP-013..COMP-020, COMP-022; VNV-003 | CM, QL | LA, CM |
| `preserved/DRIVER_MANUAL_AUTHORITY.md` | Authority record | DOC-004..DOC-006; EXEC-009..EXEC-012, EXEC-020..EXEC-024; COMP-001..COMP-005, COMP-007, COMP-013..COMP-014, COMP-017..COMP-022; VNV-004 | CM, QL | DA, CM |

## Architecture And Decisions

| Document | Function | Allocated central IDs | Verification role | Required technical approval |
| --- | --- | --- | --- | --- |
| `architecture/SYSTEM_CONTEXT.md` | Normative design | ARC-001..ARC-010, ARC-024, ARC-026..ARC-040; SRV-001, SRV-005..SRV-010, SRV-022; DEP-002..DEP-004, DEP-012, DEP-014, DEP-025 | SA, SO | PO, MO, SA, SO |
| `architecture/SATELLITE_ASSIGNMENT_AUTHORITY.md` | Normative design | ARC-006, ARC-009, ARC-021, ARC-026..ARC-040; SRV-010, SRV-015, SRV-020, SRV-022; COM-001, COM-009, COM-023..COM-024; DATA-007, DATA-010, DATA-021, DATA-025; REL-018, REL-021, REL-024..REL-025, REL-029; SEC-003..SEC-012, SEC-015, SEC-019; OPS-001, OPS-004..OPS-006; DEP-019..DEP-020, DEP-025; VNV-005..VNV-006, VNV-010 | SA, QL | GA, SY, MO, SA, DA, SO, CM |
| `architecture/LOGICAL_ARCHITECTURE.md` | Normative design | ARC-004..ARC-025, ARC-027, ARC-029, ARC-031..ARC-040; SRV-010; EXEC-011, EXEC-014, EXEC-018, EXEC-028; COM-009, COM-022; DATA-001, DATA-005, DATA-013, DATA-019, DATA-024; REL-017; DEP-002..DEP-004, DEP-013..DEP-015 | SA | SA, SO, LA, DA |
| `architecture/SERVER_AND_EXECUTION.md` | Normative design | ARC-026..ARC-030, ARC-034..ARC-040; SRV-001..SRV-022; EXEC-001..EXEC-028; MODE-014..MODE-017, MODE-021..MODE-022; DATA-015, DATA-027..DATA-029; REL-018, REL-020..REL-022, REL-024..REL-025, REL-027, REL-029 | SA, QL | MO, SA, LA, DA, SO |
| `architecture/STATE_MACHINES.md` | Normative design | ARC-037..ARC-039; SRV-005, SRV-007..SRV-008, SRV-014..SRV-016, SRV-020..SRV-021; EXEC-004..EXEC-012, EXEC-015..EXEC-017, EXEC-019..EXEC-027; MODE-015..MODE-017, MODE-021..MODE-022, MODE-025..MODE-027; REL-020..REL-022, REL-027, REL-029; VNV-005..VNV-006 | QL | MO, SA, LA, DA |
| `architecture/REAL_TIME_COMMUNICATIONS.md` | Normative design | ARC-016, ARC-023, ARC-032; COM-001..COM-027; DATA-014, DATA-027; WEB-029..WEB-037 | SA, QL | SA, SO, MO |
| `architecture/DATA_ARCHITECTURE.md` | Normative design | ARC-016..ARC-017, ARC-031, ARC-038..ARC-039; DATA-001..DATA-029; MODE-025..MODE-027; REL-024..REL-025, REL-029; SEC-008..SEC-011, SEC-020 | SA, CM | SA, DA, SO, CM |
| `architecture/RELIABILITY_AND_RECOVERY.md` | Normative design | ARC-013, ARC-022, ARC-029..ARC-040; SRV-009..SRV-011, SRV-014..SRV-022; EXEC-009..EXEC-012, EXEC-016, EXEC-020..EXEC-027; DATA-025; REL-001..REL-029; DEP-019, DEP-025 | SA, QL | MO, SA, DA, SO, CM |
| `architecture/DEPLOYMENT_AND_SCALABILITY.md` | Normative design | ARC-002..ARC-003, ARC-008, ARC-025, ARC-027, ARC-036..ARC-040; REL-003..REL-014, REL-024..REL-029; SEC-008..SEC-021; DEP-001..DEP-025 | SA, QL | PO, MO, SA, SO, CM |
| `architecture/decisions/README.md` | Control or index | DOC-006, DOC-009..DOC-010; VNV-002, VNV-012 | QL, CM | SA, CM |
| `architecture/decisions/ADR-001-postgresql-as-system-of-record.md` | Decision record | ARC-016..ARC-017, ARC-031, ARC-036..ARC-040; DATA-001..DATA-005, DATA-013..DATA-019, DATA-023..DATA-028; REL-003..REL-005, REL-024..REL-025; DEP-005, DEP-019 | SA, CM | SA, SO, CM |
| `architecture/decisions/ADR-002-one-satellite-control-domain.md` | Decision record | ARC-001..ARC-003, ARC-024, ARC-026..ARC-028, ARC-036..ARC-040; SRV-001..SRV-004, SRV-013, SRV-022; DEP-002..DEP-004, DEP-012, DEP-014, DEP-025 | SA | PO, MO, SA, SO |
| `architecture/decisions/ADR-003-single-writer-ha-and-fencing.md` | Decision record | ARC-013, ARC-022, ARC-029..ARC-030, ARC-035..ARC-040; SRV-005..SRV-010, SRV-014..SRV-017, SRV-020..SRV-022; MODE-014..MODE-017, MODE-021..MODE-022; REL-003..REL-005, REL-018..REL-025, REL-029; DEP-012, DEP-019, DEP-025 | SA, QL | MO, SA, DA, SO |
| `architecture/decisions/ADR-004-rest-websocket-grpc.md` | Decision record | ARC-021..ARC-023, ARC-032; COM-001..COM-027; DATA-027; WEB-029..WEB-037 | SA, QL | MO, SA, SO |
| `architecture/decisions/ADR-005-git-promotion-and-immutable-bundles.md` | Decision record | ARC-019..ARC-020, ARC-034; DATA-004, DATA-017..DATA-018, DATA-028; WEB-024, WEB-027..WEB-028; GIT-001..GIT-024; COMP-016, COMP-019 | CM, QL | PO, LA, SO, CM |

## Web And Procedure Engineering

| Document | Function | Allocated central IDs | Verification role | Required technical approval |
| --- | --- | --- | --- | --- |
| `web/WEB_APPLICATION.md` | Normative design | COM-002..COM-008, COM-011, COM-013..COM-016, COM-023..COM-024; WEB-001..WEB-022; MODE-001..MODE-009, MODE-013, MODE-018..MODE-027 | QL, MO | PO, MO, SO, QL |
| `web/OPERATING_MODES.md` | Normative design | SRV-005..SRV-009, SRV-014..SRV-017, SRV-021..SRV-022; EXEC-023, EXEC-027; MODE-001..MODE-009, MODE-013..MODE-027 | MO, QL | PO, MO, SA, SO |
| `web/SPELL_GUI_USER_MANUAL.md` | Control or index and user guidance | DOC-007, DOC-011; ARC-001..ARC-003, ARC-010, ARC-023; SRV-001..SRV-010; COM-002..COM-008; WEB-001..WEB-037; MODE-001..MODE-027; GIT-001..GIT-024; REL-001..REL-014; SEC-003..SEC-011; OPS-001..OPS-010 | QL, MO | PO, MO, SA, SO, QL, CM |
| `web/PROCEDURE_NAVIGATION.md` | Normative design | WEB-023..WEB-028; MODE-010..MODE-012; GIT-001, GIT-007, GIT-010, GIT-023..GIT-024 | QL | PO, MO, SO, CM |
| `web/REAL_TIME_STATE.md` | Normative design | EXEC-007, EXEC-019, EXEC-022; COM-003..COM-008, COM-011..COM-021, COM-023..COM-027; DATA-014, DATA-027; WEB-002..WEB-007, WEB-016, WEB-018, WEB-029..WEB-037; MODE-023, MODE-025..MODE-027 | QL | MO, SA, SO |
| `procedures/AUTHORING_AND_GIT.md` | Normative design | ARC-019..ARC-020, ARC-034; EXEC-001..EXEC-003; DATA-004, DATA-017..DATA-018, DATA-028; MODE-006..MODE-008, MODE-019; GIT-001..GIT-024; COMP-015..COMP-019 | CM, QL | PO, LA, SO, CM |
| `procedures/COMPATIBILITY_AND_MIGRATION.md` | Normative design | DOC-003..DOC-005; EXEC-001..EXEC-015, EXEC-020..EXEC-024; COM-009..COM-012, COM-022..COM-025; DATA-017; GIT-003..GIT-005, GIT-013..GIT-018; COMP-001..COMP-022; VNV-003..VNV-004, VNV-011 | QL | MO, LA, DA, SO, QL |

## Security And Operations

| Document | Function | Allocated central IDs | Verification role | Required technical approval |
| --- | --- | --- | --- | --- |
| `security/SECURITY_ARCHITECTURE.md` | Normative design | ARC-004..ARC-010, ARC-019, ARC-021, ARC-024..ARC-025, ARC-033, ARC-036..ARC-040; SRV-005..SRV-010, SRV-020..SRV-022; EXEC-001, EXEC-003, EXEC-009..EXEC-010, EXEC-018, EXEC-020..EXEC-021, EXEC-028; COM-001, COM-003, COM-009, COM-013..COM-015, COM-022, COM-024; DATA-007..DATA-009, DATA-021, DATA-024; MODE-023..MODE-027; GIT-004..GIT-005, GIT-008..GIT-009, GIT-021; REL-008, REL-018; SEC-001..SEC-021; OPS-002 | SO, QL | GA, SY, RO, MO, SA, SO |
| `security/NIST_SP_800_171_ALIGNMENT.md` | Normative design | DOC-007; SEC-001..SEC-023; VNV-007, VNV-012 | SO, AS | GA, SY, RO, AS, SO |
| `security/NIST_REQUIREMENT_ASSESSMENT_MATRIX.md` | Evidence or gate | DOC-007; SEC-001..SEC-002, SEC-022..SEC-023; VNV-001..VNV-002, VNV-007, VNV-012 | AS, QL | GA, SY, RO, AS, SO |
| `security/THREAT_MODEL.md` | Normative design | ARC-004..ARC-010, ARC-033, ARC-036..ARC-040; EXEC-003, EXEC-009..EXEC-010, EXEC-018, EXEC-020..EXEC-021, EXEC-028; COM-001, COM-024; DATA-007..DATA-009, DATA-021, DATA-024; MODE-025..MODE-027; GIT-008..GIT-009, GIT-021; REL-008, REL-018, REL-021; SEC-003..SEC-021; VNV-006..VNV-007 | SO, QL | SY, RO, MO, SA, SO |
| `security/SECURE_SDLC_AND_SUPPLY_CHAIN.md` | Normative design | DOC-008; GIT-001..GIT-024; SEC-006, SEC-009, SEC-014..SEC-020; DEP-001, DEP-008..DEP-011, DEP-020..DEP-023; VNV-001..VNV-002, VNV-007, VNV-011..VNV-012 | SO, CM, QL | SY, SO, CM, QL |
| `operations/OPERATIONS_AND_OBSERVABILITY.md` | Normative design | DATA-007, DATA-020, DATA-022, DATA-026; REL-001..REL-014, REL-023, REL-026..REL-029; SEC-010..SEC-011, SEC-017..SEC-020; OPS-001..OPS-010; DEP-016..DEP-017, DEP-023..DEP-025 | MO, QL | PO, MO, SA, SO |
| `operations/BACKUP_RESTORE_AND_DR.md` | Normative design | ARC-037..ARC-039; DATA-004, DATA-007..DATA-010, DATA-018, DATA-021..DATA-027; REL-002..REL-014, REL-020..REL-029; SEC-008..SEC-011, SEC-018, SEC-020; OPS-001, OPS-004..OPS-010; DEP-005, DEP-019, DEP-022..DEP-025; VNV-006, VNV-010 | CM, QL | MO, SA, SY, SO, CM |

## Delivery And Assurance

| Document | Function | Allocated central IDs | Verification role | Required technical approval |
| --- | --- | --- | --- | --- |
| `quality/VERIFICATION_AND_VALIDATION.md` | Evidence or gate | DOC-002, DOC-005..DOC-011; SEC-022..SEC-023; COMP-001..COMP-022; VNV-001..VNV-012. All other central IDs are verification targets, not additional clauses allocated to this document. | QL | MO, SA, LA, DA, SO, QL, CM |
| `quality/IMPLEMENTATION_ROADMAP.md` | Evidence or gate | DOC-006..DOC-007, DOC-009..DOC-011; VNV-011..VNV-012. Phase coverage references other IDs but does not redefine them. | QL, CM | PO, MO, SA, SO, QL, CM |
| `quality/G0_READINESS_PACKAGE.md` | Evidence or gate | DOC-001..DOC-002, DOC-006..DOC-011; MODE-023..MODE-027; SEC-003..SEC-006, SEC-010; VNV-001..VNV-002, VNV-012. Candidate policy values and verification targets are approval inputs, not approved requirements or evidence. | QL, CM | PO, MO, SA, GA, SY, SO, RO, QL, CM plus each affected decision owner |
| `quality/OPEN_DECISIONS.md` | Evidence or gate | DOC-006, DOC-009..DOC-010; VNV-012 | QL, CM | Owner and approvers named by each decision |
| `quality/DOCUMENT_ACCEPTANCE_CHECKLIST.md` | Evidence or gate | DOC-001..DOC-011; SEC-001..SEC-023; COMP-001..COMP-022; VNV-001..VNV-012. Other central IDs are inspection subjects, not additional checklist requirements. | QL | PO, MO, SA, LA, DA, GA, SY, SO, RO, AS, QL, CM |

## Machine-Readable Gate Artifacts

| Artifact | Function | Governing source | Validation and approval state |
| --- | --- | --- | --- |
| `requirements/IMPLEMENTATION_ALLOCATION_RULES.json` | Controlled candidate expansion rules | `SYSTEM_REQUIREMENTS.md`, this allocation, and `quality/IMPLEMENTATION_ROADMAP.md` | Approved input for the bounded local Candidate A gate; all 366 broader-spec rows are retained as `OUTSIDE_LOCAL_V04_GATE` |
| `requirements/IMPLEMENTATION_ALLOCATION.csv` | Expanded per-ID canonical record digest, registered owner, design, package, phase, method, test/result, gate, and broader approval relation | Generated from the rules and central requirement records | 366 structurally tracked broader-spec rows; organization-only row approvals are not local v0.4 gate requirements |
| `requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json` | Source-bound exhaustive local disposition inventory | `SOURCE_AUTHORITY.md` and `requirements/COMPATIBILITY_LEDGER.md` | Seven source records, complete page coverage, all 195 exact Language Reference examples, and every artifact assigned to v0.4 or Deferred/`EXCLUDE`; final technical review pins pass |
| `requirements/compatibility/COMPATIBILITY_LEDGER.json` | Canonical 25-field detailed compatibility rows | Source inventory and exact local scope | Every row has a source span, technical rationale, effect/ambiguity disposition, unique planned-only test identity, and owner-approved Candidate A scope disposition; no implementation or test-result claim |
| `requirements/compatibility/scopes/v0.4.json` | Exact bounded seven-source local membership and dispositions | Owner-approved v0.4 pre-implementation gate | Candidate A rows are in scope; all other rows are Deferred/`EXCLUDE` and not advertised by v0.4 |
| `requirements/compatibility/COMPATIBILITY_RECONCILIATION.json` | Digest-bound inventory, ledger, and scope equality record | `quality/tools/validate_compatibility.py` | Regenerated only after all independent source reviews and exact digest pins pass |
| `quality/G0_HUMAN_APPROVAL_LEDGER.json` | Baseline-bound project-owner scope decision and bounded claims | Direct JC Arcaz instruction plus the local acceptance checklist | Candidate A, exclusions, budgets, and test plan approved for the local synthetic non-CUI gate; deterministic file binding verified; no signature, operational, or compliance claim |
| `quality/G0_READINESS_REPORT.json` | Deterministic digest-bound structural result and technical blocker report | `quality/tools/validate_g0.py` | `PASS` under pinned Python 3.13 with zero structural errors and zero technical blockers; authorizes product engineering but not release, operational use, or compliance |
| `quality/tools/validate_compatibility.py` | Exhaustive compatibility freshness and structural validator | `COMP-001`, `VNV-003..VNV-004`, `VNV-012` | Enforces source/page/count/digest/disposition/nonclaim and independent-review bindings; it does not claim implementation or runtime conformance |
| `quality/tools/test_validate_compatibility.py` | Compatibility-validator adversarial coverage | Same | Twenty-one deterministic and adversarial tests |
| `quality/tools/validate_g0.py` | Local Gate 0 generator and validator | `DOC-002`, `DOC-005`, `DOC-009..DOC-010`, `VNV-002`, `VNV-012` | Must pass under pinned Python 3.13; reports authorization only when every retained technical entry condition passes |
| `quality/tools/test_validate_g0.py` | Validator unit coverage | Same | Seventeen deterministic and adversarial tests |

## Normative Clause Rules

1. `[DOC-002, DOC-009]` A mandatory clause outside
   `SYSTEM_REQUIREMENTS.md` shall cite one or more allocated central IDs inline,
   in an adjacent requirements table, or through this document-level allocation.
   Document-level allocation is the minimum accepted trace for this draft; a
   safety-, security-, interoperability-, or externally visible clause requires
   clause-level trace before approval.
2. `[DOC-002, DOC-009]` An ID cited as authority for a normative clause shall
   exist in `SYSTEM_REQUIREMENTS.md`, and the document path shall be allocated
   that exact ID or an inclusive range containing it.
3. `[DOC-006, DOC-009]` A clause that creates a new actor obligation,
   externally visible behavior, state transition, invariant, limit, failure
   response, evidence duty, or approval gate shall be represented by a new or
   revised central row before merge.
4. `[DOC-006, DOC-010]` A change to central or detailed normative text shall
   update affected allocation, traceability, ADRs, compatibility dispositions,
   tests, migration, rollback, and approval evidence in the same change.
5. `[DOC-002, VNV-002]` Requirement-range syntax shall be expanded during lint;
   unknown IDs, reversed ranges, cross-prefix ranges, duplicate central IDs, and
   normative clause citations outside a document's allocation shall fail the
   documentation check.
6. `[DOC-002, VNV-002]` Copying a central requirement into a design document
   shall preserve it exactly. An elaboration may narrow implementation choices
   or add verifiable detail, but it shall not reduce the behavior, evidence,
   owner authority, or verification method required by the central row.
7. `[DOC-006, VNV-012]` An open decision, placeholder, example, recommendation,
   or ADR in `Proposed` state shall not override an allocated requirement. A
   conflict blocks the applicable gate until resolved by controlled change.
8. `[DOC-001, DOC-006, VNV-002]` CI shall inventory all Markdown paths and fail
   when a path containing normative language is absent from this allocation.
   Renames, additions, and deletions shall update this table in the same change.

## Source And Evidence Exceptions

- Text quoted from the Language Reference or Driver Development Manual is an
  external authority statement under DOC-003 or DOC-004, not a newly minted
  SPELL requirement. Implementing that behavior still requires a populated
  COMP-001..COMP-022 disposition and its conformance evidence. A lint exception
  applies only to an exact block quote or fenced extract carrying source title,
  version, digest, and page location; an unattributed or paraphrased clause is
  not exempt.
- Official NIST requirement and determination-statement text in the deployment
  assessment template remains external authority. SEC-001..SEC-002 and
  SEC-022..SEC-023 govern applicability, implementation allocation, assessment,
  findings, and evidence; the official identifiers must not be replaced by
  locally invented SPELL requirement IDs.
- Source titles, hashes, page references, historical observations, and faithful
  quotations are evidence under DOC-003..DOC-005. They become product
  obligations only through a central requirement and, where applicable, a
  compatibility disposition.
- Rationale, alternatives, diagrams, examples, and notes are non-normative
  unless explicitly labeled as a conformance vector. A conformance vector is
  evidence for its allocated requirement, not an additional requirement.
- Checklists, roadmap gates, assessment rows, and test procedures instantiate
  VNV or SEC evidence duties. A failed item blocks the defined gate; it cannot
  silently redefine product behavior.
- Allocation declarations, traceability indexes, and explicitly labeled
  verification-target references may name central IDs outside the document's
  own normative allocation. Such a reference creates a relation to the central
  row; it does not authorize a local normative elaboration of that row.
- The machine-readable `architecture/state-machines.json` artifact is governed
  by the same allocation as `architecture/STATE_MACHINES.md`. Its schema and
  transitions must validate against that document and the cited central IDs;
  JSON content does not create a separate requirement namespace.

## Change And Lint Checklist

- Confirm every central ID is unique and matches `^[A-Z]+-[0-9]{3}$`.
- Expand every allocated range and confirm both endpoints and every member exist.
- Inventory every Markdown path and classify any new file before it is merged.
- Scan changed mandatory clauses and confirm semantic fit with their allocated
  IDs; add clause-level references for high-consequence behavior.
- Confirm an elaboration does not weaken central language or conflict with a
  different detailed document allocated the same ID.
- Update bidirectional design, implementation, test, result, finding, baseline,
  and approval relations required by VNV-002.
- Require the central row owner and every affected document approval role to
  review a normative change.
- Reject the baseline if quoted authority text, proposed decisions, or evidence
  templates are being used to bypass the atomic requirements register.
