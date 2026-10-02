# OpenBEXI SPELL Project Roadmap

Updated 2026-10-01. **v0.16.0 is in implementation and qualification**;
**v0.15.0 remains the accepted predecessor**. Release acceptance is determined
by independently validated annotated tags and their committed evidence.

This roadmap describes local simulator engineering. It does not authorize live
GCS/spacecraft connectivity, deployment or operational use. All documents under
`SPELL_DOCUMENTATION/` remain mandatory source references; the broader generated
specification `0.1.0-draft.1` remains Draft.

## v0.16.0 - Current Work

The owner authorized execution and publication of the
[v0.16 entry scope](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.16_Pre-Implementation.md).
The [implementation record](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.16_Implementation.md)
tracks actual results.

| Work | Completion criteria |
| --- | --- |
| Language coverage | Inventory the complete 2.4.4 reference, distinguish direct/partial/adapted/gap evidence, and retain explicit unsupported behavior |
| Direct language increment | Inferred scalar assignment and documented Display severity, with real parser/worker assertions and negative tests |
| Reference procedure | Preserve all 195 example choices and 257 adaptations; add direct-case selection and automated complete-suite execution |
| GUI-manual workspace | Compact navigation/utilities, Master and procedure tabs, tabular Code/Data/Result, lower controls/prompts/logs; visual and browser verification |
| Automatic simulator access | Open the loopback URL directly as a local operator; finite credentials, renewal/reconnect/retry, strict origin/ingress boundary and no automatic administrator grant |
| Concise documentation | Current instructions in the READMEs/operator guide; one canonical source for detailed contracts and evidence |
| Release | Frozen-source candidate and Final checks, all selected environments, browser evidence, audits/SBOMs, four reproducible builds and validated annotated tag |

A complete reference inventory is different from complete language support.
The [coverage matrix](contracts/v16/language_coverage.json) must retain missing
semantics as gaps. Expected rejection tests and example adaptations cannot be
counted as successful full-language conformance.

## Delivered Releases

Detailed gates, immutable bindings and results live in the
[release index](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md).

| Release | Accepted local scope |
| --- | --- |
| v0.1 | Planning baseline; no product release claim |
| v0.2.0 | Simulator vertical slice |
| v0.3.0 | Isolation, security, recovery and bounded language foundation |
| v0.4.0 | Typed out-of-process synthetic driver lifecycle |
| v0.5.0 | Existing IR validation hardening |
| v0.6.0 | Durable operator workspace and procedure composition |
| v0.7.0 | Read-only observations, conditions and limits |
| v0.8.0 | Revisioned data services and fixed virtual storage |
| v0.9.0 | Separate web development environment and immutable promotion |
| v0.10.0 | 195 reference examples represented by 257 semantic adaptations |
| v0.11.0 | Closed simulator BuildTC/Send semantics and effect certainty |
| v0.11.1 | Documentation restoration; runtime remained v0.11.0 |
| v0.12.0 | Synthetic observation replay, comparison and fallback |
| v0.13.0 | Fenced procedure control and confirmed return to read-only |
| v0.14.0 | Bounded read-only GetTM adapter |
| v0.15.0 | Local shadow-pilot review, incidents, rollback and report restore |

The accepted v0.15.0 tag object is
`8c72974f6a0a5deee766d6358fb219b73eab91ef`, pointing to release commit
`b7bceaf2489156271c91a939d897d040caeb0be1`. Exact durations are in
[VERSION_TIMELINE.md](VERSION_TIMELINE.md). Historical planning, including
v0.3.1 and the original v0.4 alternatives, is preserved in the
[roadmap snapshot through v0.15](https://github.com/arcazj/openbexi_SPELL/blob/8b3c4b2facc0be2184201dbcbf98f4879f78c334/PROJECT_ROADMAP.md)
and version-specific records; it is not repeated as current work here.

## Remaining Work

| Area | Next evidence required |
| --- | --- |
| Full SPELL 2.4.4 language support | Close every applicable coverage gap with direct source behavior, defaults/modifiers/outcomes and per-family oracles; no complete-support release number is committed yet |
| Real legacy observations and control | An explicitly approved isolated environment, exact capability contracts, golden traces, faults, credentials and rollback; synthetic releases do not qualify a real system |
| Additional driver capabilities | Independent capability-specific qualification; read-only evidence does not authorize effects |
| Broader GUI and development design | Approved feature scope, build-bound user documentation, complete workflows and operator review |
| Enterprise identity and policy | Named deployment owners, identity provider, role policy and environment-specific evidence |
| Whole-service recovery and availability | Approved workload/topology, failure budgets, backup/PITR/restore and recovery evidence; pilot report restoration is a narrower feature |
| Operational readiness | Separate organizational, safety, security, deployment and mission authority |

The broader governed work packages and phase dependencies remain in
[the design roadmap](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/IMPLEMENTATION_ROADMAP.md).
Their Draft requirements do not become approved or implemented merely because
an overlapping local simulator feature has shipped.

## Release Rules

Record scope and tests before implementation; preserve source-manual traceability
and explicit compatibility decisions. Freeze one clean candidate, execute all
mandatory tests, and retain raw evidence. Do not waive unresolved critical or
high defects, missing proof, or mandatory environment skips. Publish only after
package and tag validation. Update current summaries concisely and retain
historical evidence without rewriting earlier acceptance decisions.
