# ADR-005: Git Promotion and Immutable Procedure Bundles

## Status

Accepted on 2026-08-18 only for the bounded
`LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT` v0.9 profile authorized by
`V09-GATE-0A`. That decision covers provider-neutral local history, a
server-managed authoring workspace, deterministic unsigned content-addressed
bundles, authenticated approval, and local simulator promotion/rollback.

Remote Git providers and credentials, protected remote branches, verified
commit/tag or bundle signatures, production artifact repositories, operational
environments, and mission trust roots remain Proposed for the broader
next-generation design. This ADR makes no cryptographic-signature, deployment,
compliance, mission, or operational-authorization claim.

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

For bounded v0.9, a provider-neutral server-managed local repository is the
source of truth for editable procedure source. An exact reviewed repository
revision and pinned inputs feed a hermetic bundle build. The builder emits a
deterministic, content-addressed procedure bundle containing bounded data-only
IR, source maps, declared dependencies, and a complete manifest. Source and
templates are never executed.

The local artifact service stores each bundle immutably by cryptographic
digest. A revisioned, idempotent, audited SQLite/PostgreSQL promotion registry
maps the local simulator catalog entry to an authenticated approved digest and
publishes changes through the outbox. The runtime loads only a digest that
passes provenance, compatibility, schema, capability, and local simulator
policy. v0.9 does not claim that these local authenticated approvals or digest
checks are cryptographic signatures.

A running execution and every schedule are pinned to their selected digest when
created. A later Git commit or catalog promotion has no implicit effect on
either resource.

This bounded decision implements the v0.9 allocations of `GIT-013` through
`GIT-022` and `COMP-016`. Requirements for remote protected history,
cryptographic signing, or operational environments remain proposed and
unimplemented.

## Detailed Rules

1. Local provider-neutral history is immutable once referenced by a bundle;
   revision conflicts fail visibly and do not overwrite another author.
2. Browser Edit Mode uses a server-managed workspace and never exposes a
   repository credential or operational filesystem.
3. Build inputs are a clean exact repository revision, pinned toolchain,
   dependency locks, catalog snapshots, language profile, and compatibility
   ledger version.
4. Build output is canonical. Any source, metadata, dependency, catalog,
   toolchain, profile, or IR change produces a new digest.
5. Artifacts are write-once by digest. Promotion does not rebuild or overwrite
   an artifact.
6. Promotion is a separately authenticated and audited local simulator
   decision. One subject cannot author and also review, approve, or promote the
   same change. No signing claim is made.
7. Runtime startup records repository, revision, bundle digest, manifest,
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

The project owner accepted the bounded local synthetic v0.9 decision through
`V09-GATE-0A` on 2026-08-18. Broader remote, signed, production, or operational
design remains pending Gate G0 approval under `OD-023` by the Product Owner,
Configuration Manager, Language Authority, Mission Operations Authority,
System Owner, Security Officer, and Quality Lead.

## Proposed Broader Bundle Trust Chain

For a later separately approved signed profile, the verifier would establish:

`mission trust root -> signer identity -> protected commit/tag -> hermetic build provenance -> bundle signature/digest -> promotion approval -> execution record`.

Each link is independently verifiable after the execution. Trust-root and
signing-key rotation preserve historical verification evidence. A signature
that is syntactically valid but outside its trusted identity, purpose,
repository, environment, or validity policy is rejected.

## Failure Behavior

The bounded local runtime fails closed when:

- a digest is absent, mismatched, withdrawn, or overwritten;
- an approval, provenance, revision, or applicable local policy cannot be
  verified;
- schemas, language/IR profiles, catalogs, or required driver capabilities are
  incompatible;
- a dependency is mutable, missing, or not represented in the manifest;
- the promotion points at a different byte sequence than the verified digest.

An availability problem in the authoring repository shall not stop an already loaded execution
because runtime authority is the verified bundle and retained evidence. An
artifact or promotion-registry outage shall prevent unverified new loads and
reloads; it shall not cause fallback to a working tree.

## Consequences

### Positive

- Every execution is reproducible and attributable to reviewed source.
- Developers can use provider-neutral local history and collaboration without
  holding runtime authority.
- Promotion and rollback are small, auditable changes of immutable references.
- Historical executions remain explainable after branches move or disappear.
- Runtime attack surface excludes Git clients, compilers, and arbitrary source
  loading.

### Costs

- Artifact, provenance, retention, and promotion services must be operated;
  broader profiles also require signing and trust-store services.
- Developers cannot test an unsaved editor buffer in an operational runtime;
  even simulation uses a built candidate bundle.
- Emergency changes still require a predefined expedited build and approval
  path.
- Storage retains multiple source and bundle versions, though deduplication by
  digest may reduce physical cost.

## Alternatives Rejected

| Alternative | Reason rejected |
| --- | --- |
| Execute directly from an editable branch or revision head | Editable heads are mutable and do not bind complete dependencies, validation, or approval |
| Execute from an operator-selected commit checkout | A checkout remains mutable and introduces Git/tooling into the runtime boundary |
| Copy approved files into a shared runtime directory | Copy state lacks reliable provenance, atomicity, dependency closure, and tamper evidence |
| Build during procedure start | Adds compilers and network/dependency uncertainty to a critical operation and makes runs non-reproducible |
| Store source only in a database editor | Loses standard Git review and interoperability and does not itself solve immutable runtime packaging |
| Automatically update active executions after promotion | Changes running semantics without an explicit safe state transition or operator decision |
| Roll back by rewriting repository history | Destroys provenance and does not address already built or running artifacts |

## Verification

Acceptance requires:

- concurrent and adversarial workspace/revision tests;
- invalid, expired, revoked, and wrong-purpose authorization tests;
- two independent reproducible builds with identical digest;
- mutation attempts against stored artifacts;
- promotion/rollback authorization and separation-of-duties tests;
- runtime tests proving working trees and branches are unreachable;
- active-execution tests proving later promotion and withdrawal do not alter
  pinned bytes;
- restore tests proving old executions retain verifiable source, bundle,
  approvals, and provenance.

Protected-branch and cryptographic-signature tests are required only if a later
gate accepts the broader remote/signed profile.

## Related Documents

- [Procedure Authoring and Git Governance](../../procedures/AUTHORING_AND_GIT.md)
- [SPELL Compatibility and Migration](../../procedures/COMPATIBILITY_AND_MIGRATION.md)
- [Procedure Navigation and Catalog](../../web/PROCEDURE_NAVIGATION.md)
