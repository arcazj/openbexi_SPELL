# ADR-005: Git Promotion and Immutable Procedure Bundles

## Status

Proposed for the next-generation design baseline on 2026-07-18. It becomes
accepted only when the repository baseline is approved.

## Context

Legacy SPELL development workflows provide projects, files, dictionaries,
validation, version-control operations, and editable runtime-adjacent paths.
Those concepts are useful for authors, but a mission runtime cannot safely
execute a mutable branch, network working copy, editor buffer, or server
filesystem path.

The next-generation platform needs:

- Git history, branching, review, change tracking, and rollback;
- deterministic validation of the exact source that will run;
- separation of developer and operator authority;
- provenance from as-run execution to source, dependencies, tools, approvals,
  and configuration;
- safe promotion across development, test, and operational environments;
- recovery and rollback without silently changing active executions.

## Decision

Git is the source of truth for editable procedure source. A protected,
signature-verified Git commit and signed release tag are inputs to a hermetic
bundle build. The builder emits a deterministic, signed, content-addressed
procedure bundle containing bounded data-only IR, source maps, declared
dependencies, and a complete manifest.

The artifact repository stores the bundle immutably by cryptographic digest.
The authoritative PostgreSQL promotion registry maps an environment and
catalog entry to an approved digest through revisioned, idempotent, audited
transactions and publishes changes through the outbox. The runtime loads only
a digest that passes signature, provenance, compatibility, schema, capability,
and environment policy.

A running execution and every schedule are pinned to their selected digest when
created. A later Git commit or catalog promotion has no implicit effect on
either resource.

This decision implements `GIT-013` through `GIT-022` and `COMP-016`.

## Detailed Rules

1. Protected Git history requires required checks, code-owner review, verified
   signatures, and no force-push.
2. Browser Edit Mode uses a server-managed workspace and never exposes a
   repository credential or operational filesystem.
3. Build inputs are a clean exact commit, signed tag, pinned toolchain,
   dependency locks, catalog snapshots, language profile, and compatibility
   ledger version.
4. Build output is canonical. Any source, metadata, dependency, catalog,
   toolchain, profile, or IR change produces a new digest.
5. Artifacts are write-once by digest. Promotion does not rebuild or overwrite
   an artifact.
6. Promotion is a separately authorized, signed, audited decision. Production
   policy may require independent approvers and recent authentication.
7. Runtime startup records repository, commit, tag, bundle digest, manifest,
   language/IR profile, configuration digest, and approvals.
8. Dependencies resolve entirely inside the bundle or to immutable
   digest-pinned platform capabilities. Runtime network fetch is prohibited.
9. Withdrawal blocks new starts but does not erase evidence or silently stop an
   active execution.
10. Rollback is a new promotion decision that references a previously approved
    digest. It never rewrites Git or mutates a running execution.

## Affected Requirements (Non-Normative Traceability)

This relationship list identifies central requirements potentially affected by
the decision; it does not allocate normative authority to this ADR. The
authoritative allocation is `requirements/DOCUMENT_REQUIREMENT_ALLOCATION.md`.

`ARC-019` through `ARC-020`, `DATA-004`, `DATA-017` through `DATA-018`,
`DATA-028`, `GIT-001` through `GIT-024`, and `COMP-011`, `COMP-016`.

## Migration And Rollback

Import legacy procedure releases as immutable bundles only after validation and
provenance capture. Seed promotion rows transactionally, pin every existing
schedule before activation, and compare the generated runtime catalog. Rollback
is a new audited promotion to a retained approved digest; active executions and
schedules remain pinned unless their explicit state-machine operation changes
them.

## Approval

Pending Gate G0 approval under `OD-023` by the Product Owner, Configuration
Manager, Language Authority, Mission Operations Authority, System Owner,
Security Officer, and Quality Lead.

## Bundle Trust Chain

The verifier shall establish:

`mission trust root -> signer identity -> protected commit/tag -> hermetic build provenance -> bundle signature/digest -> promotion approval -> execution record`.

Each link is independently verifiable after the execution. Trust-root and
signing-key rotation preserve historical verification evidence. A signature
that is syntactically valid but outside its trusted identity, purpose,
repository, environment, or validity policy is rejected.

## Failure Behavior

The runtime fails closed when:

- a digest is absent, mismatched, withdrawn, or overwritten;
- a signature, approval, provenance, or protected-ref policy cannot be
  verified;
- schemas, language/IR profiles, catalogs, or required driver capabilities are
  incompatible;
- a dependency is mutable, missing, or not represented in the manifest;
- the promotion points at a different byte sequence than the verified digest.

An availability problem in Git shall not stop an already loaded execution
because runtime authority is the verified bundle and retained evidence. An
artifact or promotion-registry outage shall prevent unverified new loads and
reloads; it shall not cause fallback to a working tree.

## Consequences

### Positive

- Every execution is reproducible and attributable to reviewed source.
- Developers can use familiar Git collaboration without holding runtime
  authority.
- Promotion and rollback are small, auditable changes of immutable references.
- Historical executions remain explainable after branches move or disappear.
- Runtime attack surface excludes Git clients, compilers, and arbitrary source
  loading.

### Costs

- Artifact, signing, provenance, trust-store, retention, and promotion services
  must be operated.
- Developers cannot test an unsaved editor buffer in an operational runtime;
  even simulation uses a built candidate bundle.
- Emergency changes still require a predefined expedited build and approval
  path.
- Storage retains multiple source and bundle versions, though deduplication by
  digest may reduce physical cost.

## Alternatives Rejected

| Alternative | Reason rejected |
| --- | --- |
| Execute directly from the default Git branch | Branch heads are mutable and do not bind complete dependencies, validation, or approval |
| Execute from an operator-selected commit checkout | A checkout remains mutable and introduces Git/tooling into the runtime boundary |
| Copy approved files into a shared runtime directory | Copy state lacks reliable provenance, atomicity, dependency closure, and tamper evidence |
| Build during procedure start | Adds compilers and network/dependency uncertainty to a critical operation and makes runs non-reproducible |
| Store source only in a database editor | Loses standard Git review and interoperability and does not itself solve immutable runtime packaging |
| Automatically update active executions after promotion | Changes running semantics without an explicit safe state transition or operator decision |
| Roll back by rewriting or force-pushing Git history | Destroys provenance and does not address already built or running artifacts |

## Verification

Acceptance requires:

- concurrent and adversarial protected-branch tests;
- invalid, expired, revoked, and wrong-purpose signature tests;
- two independent reproducible builds with identical digest;
- mutation attempts against stored artifacts;
- promotion/rollback authorization and separation-of-duties tests;
- runtime tests proving working trees and branches are unreachable;
- active-execution tests proving later promotion and withdrawal do not alter
  pinned bytes;
- restore tests proving old executions retain verifiable source, bundle,
  approvals, and provenance.

## Related Documents

- [Procedure Authoring and Git Governance](../../procedures/AUTHORING_AND_GIT.md)
- [SPELL Compatibility and Migration](../../procedures/COMPATIBILITY_AND_MIGRATION.md)
- [Procedure Navigation and Catalog](../../web/PROCEDURE_NAVIGATION.md)
