# OpenBEXI SPELL Project Roadmap

Updated 2026-10-03. **v0.18.0 is accepted and published.** This roadmap covers
the remaining work through a complete **v1.0.0 local simulator**, followed by
the additional gates for a connected deployment if that scope is selected.

Future versions are **planning targets**, not delivered features or guaranteed
dates. A milestone may require several releases. Update its scope and target
when the entry review finds additional work; completion depends on the exit
evidence. **v0.30.0 is the planned full SPELL 2.4.4 language qualification
milestone; v1.0.0 is the planned complete local-product release.** Neither claim
is valid before its acceptance gate passes.

## Current Baseline

| Item | Accepted v0.18.0 baseline |
| --- | --- |
| Procedure execution | Bounded core language and native Prompt/Display compose with simulator BuildTC/Send; other service profiles remain separately bounded. |
| Operator UI | Compact GUI-manual workspace, automatic local connection at `http://127.0.0.1:8080/`, execution views and durable operator controls. |
| Development | Existing project editing, checks, history, immutable bundles and simulator promotion; newer language authoring/promotion coverage still needs alignment. |
| Language evidence | 128 cases: 95 direct-source checks and 33 expected rejections; 195 adaptations retain 257 variants. |
| Remaining coverage | 763 inventory entries: 195 ADAPTED, 79 PARTIAL and 489 GAP. A GAP can mean missing implementation, missing proof or a manual conflict. |
| Qualification | 5,146 passed test executions; 24 environment-selected skips resolved by complementary runs; 395 candidate checks; four matching package builds. |

The [accepted release record](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.18_Implementation.md#accepted-release-binding)
owns exact bindings and evidence. Earlier delivery is retained in the
[release index](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md) and
[version timeline](VERSION_TIMELINE.md).

## Definition Of Project Done

The local project is complete at v1.0.0 only when all of these conditions pass:

- Every required SPELL Language Reference 2.4.4 construct, public function,
  method, type, operator, constant, modifier, default, outcome and example has
  implementation and independent conformance evidence. Required language gaps
  and unresolved manual conflicts are zero.
- All required simulator driver services and complete procedures work together,
  including errors, interruption, persistence, restart and recovery. Effect
  uncertainty never causes an automatic duplicate command.
- Every required GUI User Manual workflow has a tested implementation or an
  explicitly accepted browser equivalent. The compact layout and direct local
  connection remain the default local experience.
- Every approved requirement for the local product has an owner, implementation,
  test, actual result and acceptance disposition. Required work cannot be moved
  to an exclusion merely to declare completion.
- Installation, supported upgrades, rollback, backup/restore, declared capacity,
  security, documentation and support handoff pass against the exact release.
- The accepted source, evidence, reproducible package, annotated tag and public
  downloads agree; current documentation identifies that release.

If a required language family remains excluded, publish a clearly bounded
product instead of claiming full SPELL 2.4.4 support. Simulator conformance and
acceptance of a connected system have separate completion criteria.

## Planning Baseline Before v0.19

Map every remaining inventory entry and approved requirement to a milestone,
owner, dependency, source reference, test oracle and completion check. Reconcile
the original manuals with the generated design and record each conflict or
Python 3 compatibility decision before implementing the affected behavior.

Use [all supplied SPELL references](SPELL_DOCUMENTATION/), the
[language coverage matrix](contracts/v18/language_coverage.json), the
[system requirements](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/SYSTEM_REQUIREMENTS.md),
and the [open decisions](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/OPEN_DECISIONS.md).
The broader design remains Draft until its applicable decisions and requirements
are accepted. This proposed version mapping does not close those decisions.
Resolve the Draft visual-layout and navigation-start conflicts against the
accepted [UI profile](contracts/v16/ui_profile.json) before closing those GUI
requirements; preserve the owner's compact layout and Enter/double-click starts.

## Language And Simulator Milestones

Each target extends and qualifies existing capabilities. Earlier accepted IR
and procedure behavior must remain covered by regression tests. Keep editor
profiles, completion, highlighting, checks, bundle creation and promotion aligned
with each language increment; qualify authoring through execution rather than
waiting until the final development milestone.

Qualify the relevant limit semantics before v0.27 command tests, and all
language-required simulator service contracts before the v0.30 gate. Bring
these prerequisites forward from v0.28/v0.31 as needed.

| Planned target | Deliverables | Exit evidence |
| --- | --- | --- |
| **v0.19.0: Observation-to-command workflows** | Combine existing bounded GetTM, Verify and WaitFor with native prompts, expressions, branches and BuildTC/Send. Retain current literal service identifiers and command operands. | Complete read/check/wait/decision/command procedures; authoritative typed results and command guards; stale/missing/bad-quality data, timeout, abort and recovery tests. |
| **v0.20.0: Complete values and collections** | Documented scalar conversions, arithmetic, math and strings; lists, dictionaries, tuples, indexing, slicing, unpacking and mutation; typed value serialization. | Type/coercion and aliasing rules, expression results, persistence, malformed input and bounded memory/size tests. |
| **v0.21.0: Functions, loops and libraries** | Function parameters, defaults, returns and scope; documented for/while, break and continue; immutable procedure libraries, modules and qualified names. | Call/scope/import semantics, dependency pinning, source maps and declared execution/resource limits; no arbitrary host-code execution. |
| **v0.22.0: Time, defaults and error handling** | Complete TIME parsing, formats and arithmetic; ChangeLanguageConfig and configuration precedence; DriverException and documented exception handling; result/failure actions and silent execution. | Every relevant default, modifier, timeout, return and error path has direct proof; manual ambiguities have recorded resolutions. |
| **v0.23.0: Databases and shared procedure data** | Spacecraft, ground, procedure, manoeuvre and user dictionaries; create/load/save/revert and formats; DataContainer, Var, ARGS/IVARS and scoped shared data/test-and-set. | Native/service composition, types, ownership, revisions, concurrent access, atomic updates, persistence and restart tests. |
| **v0.24.0: Procedure lifecycle and composition** | StartProc arguments/results, priorities, blocking, visibility and automatic modes; steps/labels/Goto, DisplayStep, Pause/Abort/Finish and user actions. | Immutable child dependencies, scoped jumps, parent/child results, cancellation, control loss, recovery and prevention of repeated effects. |
| **v0.25.0: Files, environment and resources** | Full documented File methods and path composition; open/read/write/close/directory/delete; approved environment and resource access. | Virtual-root containment, encoding, quotas, permissions, atomicity, revision conflicts, error behavior and recovery. |
| **v0.26.0: Complete observation semantics** | Native GetTM signatures, RAW/ENG and extended items; Verify comparisons, composite conditions, tolerance/case/retry/delay; WaitFor relative/absolute/condition waits, progress and interrupt/skip/step. | Direct proof for every required documented signature, item property, modifier, default and outcome, including time/quality/snapshot policy and cancellation. |
| **v0.27.0: Complete command semantics** | Typed dynamic selectors/arguments, TC items and metadata, sequences/groups/blocks, time tags, load-only, confirmation, release timing, verification and limit adjustment. | Per-command precedence and stage outcomes; independent confirmation, immutable dependencies, authorization, cancellation and uncertain-effect reconciliation. |
| **v0.28.0: Limits, alarms and operator services** | Limit definitions/query/change/load/restore, alarms and ground-parameter injection; complete Display/Notify/Event/Prompt behavior; display/workspace open, close and print intents. | Independent read/effect capability tests, durable presentation, prompt outcomes, alarm transitions, unsupported-capability reporting and recovery. |
| **v0.29.0: Specialized services** | Ranging enable/start/stop/configuration/calibration/status; antenna/baseband catalogs; memory reports, comparison and lookup; TM/TC database lookup. | Deterministic simulator models, typed contracts, realistic failures and independent conformance for each capability. |
| **v0.30.0: Full language qualification gate** | Close the complete reference inventory and remaining cross-family combinations; qualify real procedure libraries and the full reference runner. | Every required row, source section, alias, erratum, default and outcome is closed with direct evidence; all mandatory cross-family and regression gates pass. |

### Full SPELL 2.4.4 Acceptance Rule

The v0.30 target accounts for the current 763 entries and any later inventory
additions. Every applicable entry must trace from source semantics to code,
an independent oracle and actual worker/service results. Validate all 195
examples: execute valid source directly, and identify translations, pseudocode,
output-only or intentionally invalid material explicitly. Retain the 257
adaptations as adaptation evidence; neither an adaptation nor a correct
unsupported-syntax rejection establishes implemented language support.

Qualify combinations, defaults and boundary behavior as well as individual
calls. Required GAP/PARTIAL rows, missing proof and unresolved source conflicts
block the full-support claim. Publish the exact Python compatibility profile,
resource limits and platform-specific behavior with the result.

## Product Completion Milestones

These packages can progress alongside language work once their prerequisites
are stable. Final acceptance requires the complete combined product.

| Planned target | Deliverables | Exit evidence |
| --- | --- | --- |
| **v0.31.0: Complete simulator driver platform** | Reconcile the Driver Manual; finish selected typed services, capability negotiation, adapter SDK and independent conformance tools. | Every required simulator capability has schema, semantics, quality/time rules, faults, cancellation and restart proof; read and effect capabilities remain explicit. |
| **v0.32.0: Roles, modes and control ownership** | Extend existing sessions, execution leases and handover to the approved role/mode/domain profile; signed startup, revocation, two-party handover and audited recovery. | Complete allow/deny/startup/mode and competing-tab matrix; distinct actors where required; atomic ownership/fence transitions reject stale or replayed decisions. |
| **v0.33.0: Complete manual operator workspace** | Close GUI-manual gaps: catalog hierarchy/preferences, global status, Master/procedure Code/Data/Result views, prompts/logs, inspection, monitoring/alarms, read-only replay, printing/export and Help. | Manual-to-build traceability; compact desktop/tablet/mobile, keyboard, screen-reader, zoom/reflow and accessibility checks; snapshot/cursor convergence, stale/offline interlocks, declared load budgets and operator review. |
| **v0.34.0: Complete development and Git workflows** | Extend existing authoring with language services, dependencies, review, protected promotion, rollback, Git branches/remotes, collaboration and retention. | Malicious-source/repository tests, reproducible immutable bundles, enforced permissions and review policy; running/historical executions retain exact source identities. |
| **v0.35.0: Reliability and supported deployment** | Fresh installation, supported upgrade/rollback, whole-service backup/restore, storage/database/network/clock failure handling, declared concurrency/capacity and support tooling. | Fault and load matrices meet selected limits; restore preserves audit and effect uncertainty; tested runbooks, diagnostics and maintenance procedures. |
| **v0.36.0: Release candidate and final documentation** | Integrated regression and representative migrated-procedure corpus; final GUI manual source/PDF, development/procedure guides, language/driver reference, installation, migration and support documentation. | All approved local requirements and critical workflows trace to passing results on one frozen build; screenshots/manual match that build; no unresolved mandatory finding. |
| **v1.0.0: Complete local product** | Accept and publish the complete language-qualified simulator, manual operator UI, development environment and supported deployment profile. | The entire Definition Of Project Done passes; independent clean-tag validation, four matching package builds and public asset verification complete. |

Preserve the original GUI layout intent and automatic local access. Record
browser adaptations and resolve design/manual conflicts explicitly, including
navigation-start gestures, detached windows and the legacy Python Shell. An
excluded required workflow must remain visible and cannot count as full GUI
parity. Publish the final [GUI manual source](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/web/SPELL_GUI_USER_MANUAL.md)
and PDF against the accepted build. Existing narrow browser tests do not replace
complete workflow and accessibility acceptance.

## Connected Deployment Completion, If Selected

This track extends v1.0 acceptance to a named environment, procedure set and
capability scope. Its dependencies and external inputs have no fixed release
dates. Complete these gates before declaring the connected project done.

| Gate | Deliverables and dependencies | Completion check |
| --- | --- | --- |
| **D0: Deployment scope and owners** | Select mission/domain, data boundary, permitted capabilities, identity provider, topology, workload, security obligations and named approval/support roles. | Applicable open decisions and requirement allocation are accepted; scope, ownership and measurable targets are explicit. |
| **D1: Secure deployed platform** | Enterprise identity/session policy, service identity, secrets/keys, segmentation, durable audit/export and selected storage/deployment infrastructure. | Authorization/revocation, key rotation, audit continuity, isolation and installation/upgrade/rollback pass for the actual configuration. |
| **D2: Real read-only adapters and migration** | Independent capability contracts, recorded/golden traces, read-only shadow comparison and candidate-procedure conversion; operator familiarization. | Schema/quality/time, faults, disconnect/restart, stream loss/backpressure and comparison results pass without granting command authority. |
| **D3: Controlled effect laboratory** | Qualify one effect class at a time; independent old-path fencing, mission-wide assignment authority, non-rollback generation anchoring and the sole effect authorization point. | Duplicate/partial/timeout/uncertain effects, permit/lease races, cancellation and reconciliation pass in the approved isolated lab before production activation. |
| **D4: Selected availability and disaster recovery** | Approved single-site or multi-site topology, PostgreSQL HA/PITR, capacity protection, backup, failover/failback, site restore and rolling upgrades. | Measured RPO/RTO, availability, freshness, latency and capacity meet the selected profile; restore cannot recreate stale effect authority. |
| **D5: Operational acceptance and handoff** | Integrated V&V, required security assessment, exact-build GUI manual, training, monitoring, incident/support coverage and rehearsed cutover/rollback. | Designated owners accept the exact system and residual findings; mandatory gates close before capability-scoped activation. Legacy retirement has its own recorded decision. |

If the governing authority requires a NIST assessment, reconcile the applicable
requirements, determination statements, parameters, evidence owners and findings
under the selected standard/profile. Software tests alone do not establish
compliance or operational authorization. The
[governed design roadmap](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/IMPLEMENTATION_ROADMAP.md)
and [security assessment matrix](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/security/NIST_REQUIREMENT_ASSESSMENT_MATRIX.md)
retain the detailed program obligations.

## Work-Package Coverage

| Governed package | Roadmap allocation |
| --- | --- |
| NG-WP-00: Specification and traceability | Planning baseline; every release entry review; D0. |
| NG-WP-01: Role-based startup | v0.32; D1. |
| NG-WP-02: Backend and data | v0.19-v0.31 and v0.35; D1-D4. |
| NG-WP-03: Web UI and Edit/Git | Authoring alignment with every language release; v0.33-v0.34; D2/D5 operator validation. |
| NG-WP-04: Handover and audit | v0.32; D1/D3/D4. |
| NG-WP-05: Final GUI manual | v0.36/v1.0; updated exact-deployment manual at D5. |
| NG-WP-06: Security implementation evidence | Applicable local technical controls across releases; selected organizational assessment at D0/D1/D5. |
| NG-WP-07: Reliability and operations | v0.35; D4/D5. |
| NG-WP-08: Integrated V&V and acceptance | Every release; v0.36/v1.0; D5. |

Regenerate allocation from the approved requirement register. No required ID
may remain ownerless, mapped only to prose, or backed by another version's proof.

## Rules For Every Release

1. Record source references, scope, dependencies, requirements, compatibility
   decisions, test identities and completion checks before implementation.
2. Implement and add direct reference cases plus runnable testing procedures.
   Keep `language_reference_244.spell.py`, coverage and expected outcomes current.
3. Update affected README, UI/procedure guides, API contracts, migration and
   recovery instructions. Keep summaries concise and link detailed evidence.
4. Freeze a clean candidate and run all applicable canonical gates: SQLite,
   PostgreSQL/migrations, Compose/isolation, frontend/build, real browsers,
   documentation, tooling, reference checks, replay/soaks and image/supply chain.
5. Resolve every mandatory failure and missing proof. Environment skips require
   complementary passing evidence; unresolved High/Critical findings block release.
6. Bind evidence to one source, build four identical packages across two
   independent exports, validate the annotated tag from a clean checkout, push,
   publish and verify every public asset. Record actual counts and limitations.
7. Update current acceptance summaries and leave the qualified local stack
   running at its documented URL. Preserve prior tags, manuals and evidence.

Track each target as **Planned**, **In progress**, **Blocked** or **Accepted**,
with its actual release/evidence link. After v1.0 and any selected deployment
track are accepted, hand off maintenance, security updates and support;
new capabilities receive a new scope and roadmap.
