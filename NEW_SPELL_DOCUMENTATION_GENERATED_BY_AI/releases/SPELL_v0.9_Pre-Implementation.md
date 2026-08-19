# SPELL v0.9 Pre-Implementation Gate 0A

## Document Control

| Field | Value |
| --- | --- |
| Version target | SPELL v0.9.0 |
| Gate | `V09-GATE-0A` |
| Gate status | `PASS`; `V09-DEV-001` through `V09-DEV-009` are authorized |
| Proposal date | 2026-08-18 |
| Owner approval date | 2026-08-18 |
| Owner request | `start and complete asap V0.9` |
| Accepted product baseline | Annotated tag `v0.8.0`; release commit `d6e01222de3bf52013279e48a099b6ae7ded121d` |
| Baseline tag object | `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae` (`tag`, not a lightweight tag) |
| Proposed work packages | `V09-DEV-001` through `V09-DEV-009` |
| Authorized work packages | `V09-DEV-001` through `V09-DEV-009` |
| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT` |
| Scope qualifier confirmation | `LOCAL_SYNTHETIC_NON_CUI_ONLY` |
| Development entry path | `/development.html` in the existing frontend image |
| Product implementation at this gate | Authorized but not implemented or accepted by this gate |
| Operational authorization or compliance determination | None |
| Project owner | JC Arcaz |

V09-GATE-0A OWNER-APPROVAL: APPROVED

This record is the Gate 0A entry decision for the bounded v0.9 program. The
owner explicitly authorizes the nine work packages below against the exact
contract and proof inventory. This gate claims no implemented construct or
artifact, does not accept v0.9.0, and does not authorize deployment or
operational use.

## Objective And Boundary

The v0.9 increment adds a browser-based development environment on the separate
logical `/development.html` surface: server-managed projects, non-executing
language services, dictionary and catalog authoring, semantic checks, safe
import and export, provider-neutral local history, immutable procedure bundles,
and local-simulator promotion. The established operator console remains at
`/index.html`; the two surfaces do not share mutable frontend state or runtime
control components.

The development surface runs in the existing frontend image. Its parser and
static compiler are pure capability-isolated modules inside the existing
backend and qualification image. Gate 0A adds no process or container and
preserves the exact four-image SBOM boundary: `backend`, `driver`, `frontend`,
and `proxy`. Qualification covers Chromium Desktop Chrome and Chromium Pixel 7
on the Windows host with pinned Linux containers.

An operator authors workspace revisions. A distinct admin subject reviews the
immutable history revision and separately approves and promotes its generated
candidate bundle. Bundles are immutable database-backed blobs identified by
SHA-256; no cryptographic-signature claim is made. Promotion is limited to the
local simulator and applies only to `v0.9_authoring_managed_procedures`.
Accepted v0.8 bundled simulator fixtures retain their inherited admission path
until a separately gated migration.

## Authorized Work Packages

| ID | Proposed bounded result | Required proof identities |
| --- | --- | --- |
| `V09-DEV-001` | Server-managed project workspace on the separate development web surface with revision-safe lifecycle and resource operations | `CONTRACT`, `PROJECT-LIFECYCLE`, `WORKSPACE-RACE`, `BROWSER`, `SECURITY` |
| `V09-DEV-002` | Deterministic editor, parser, outline, completion, formatting, and diagnostics without source execution | `PARSER-GOLDEN`, `EDITOR`, `COMPLETION`, `NON-EXECUTION`, `DETERMINISM` |
| `V09-DEV-003` | Versioned dictionary and pinned catalog authoring with data-only references and text-only snippet generation | `SCHEMA`, `DICTIONARY`, `CATALOG`, `REFERENCE`, `SECURITY` |
| `V09-DEV-004` | Bounded cancellable semantic checks with revision-bound durable Problems projections | `UNIT`, `PROJECT-CHECK`, `CANCELLATION`, `PROBLEMS`, `RECOVERY` |
| `V09-DEV-005` | Quarantined browser import, canonical browser export, provenance, and explicit external-change, rename, and case-conflict handling | `IMPORT-EXPORT`, `EXTERNAL-CHANGE`, `CASE-CONFLICT`, `PATH-SECURITY`, `PROVENANCE` |
| `V09-DEV-006` | Provider-neutral server-managed local history, bounded diff, explicit conflict resolution, and advisory collaboration presence | `HISTORY`, `DIFF`, `CONFLICT`, `COLLABORATION-RACE`, `SECURITY` |
| `V09-DEV-007` | Reproducible immutable validated procedure bundles stored in the database and identified by SHA-256 | `CANONICALIZATION`, `REPRODUCIBILITY`, `TAMPER`, `RETENTION`, `SECURITY` |
| `V09-DEV-008` | Audited local-simulator candidate approval, promotion, rollback, withdrawal, and immutable digest pinning | `STATE-MACHINE`, `AUTHORIZATION`, `TRANSACTION-AUDIT`, `ROLLBACK-WITHDRAWAL`, `PINNING` |
| `V09-DEV-009` | Cross-feature development acceptance on the exact browser, host, container, offline-package, and recovery matrix | `SEMANTIC-GOLDEN`, `INTEGRATION`, `BROWSER-MATRIX`, `OFFLINE-PACKAGE`, `FAULT-RECOVERY` |

Every row has status `IMPLEMENTATION_AUTHORIZED`. The machine scope lists the
exact 45 planned proof identities in package order. Wildcards, aliases, mapped
skips, renamed identities, and additional identities are not authorized by
this gate.

## Compatibility Review

All 164 unique `CMP-DEV244-*` rows from the Development Environment Manual
inventory were reviewed and mapped to `V09-DEV-001` through `V09-DEV-006`.
The group counts are 37, 35, 17, 34, 11, and 30. The globally sorted,
LF-terminated reviewed list has SHA-256
`3de9055f35bffc1f7065f2dad452dcbb32e937a0335bdf6ff129c69869ed738e`.

Twenty reviewed rows are negative-only: interpreter and `PYTHONPATH`
configuration, desktop launchers, broad TEAM actions, arbitrary host project
deletion, remote SVN checkout, and four source-errata rows. Their sorted-list
SHA-256 is
`f1f199ea5a8facbed6bf8226578665c22f6b1de9cfdb4004e72cb167249f7bcb`.
The remaining 144 rows are implementation-authorized; their group counts are
27, 31, 17, 34, 10, and 25 and their sorted-list SHA-256 is
`22138ab7f4895da9a71af310f85722cff200b7b7693b2f3e0833758fa34fa270`.

Import, history, diff, and conflict behaviors are authorized only as the
provider-neutral strengthened equivalents in the machine scope: bounded
browser transport, immutable local server history, bounded server-computed
diff, and revision-bound explicit conflict resolution followed by validation.
They do not authorize Git, SVN, CVS, remote credentials, checkout, push, pull,
or network access.

## Cross-Package Invariants

- Workspace, history, editor-buffer, and raw v0.9 source changes cannot alter
  runtime behavior. A v0.9-authored procedure remains unavailable to runtime
  until an immutable bundle digest is promoted.
- Language services parse and compile statically as data. They cannot execute
  procedure source or imports, evaluate expressions, launch host processes,
  access the network, or import worker, supervisor, driver, or GCS capability.
- Dictionary and catalog inputs are pinned local snapshots. Editing and
  snippet generation cannot publish runtime catalogs, send telecommands, or
  contact a live GCS.
- Import accepts bounded authenticated browser uploads into server quarantine;
  export is a bounded browser download. Caller host paths, remote URLs,
  traversal, symlink or reparse escape, device paths, nested archives, and
  partial mutation fail closed.
- History revisions are immutable and provider neutral. Conflict resolution is
  explicit, revision bound, digest checked, and revalidated; presence and file
  locks are advisory only.
- Bundle construction starts from an exact immutable validated history
  revision with a distinct-subject admin review. Exact bundle bytes contain a
  canonical payload manifest that omits its own digest; the atomic database
  envelope stores `bundle_digest = SHA256(exact bundle bytes)`. The resulting
  bundle enters `CANDIDATE`; approval and promotion are later separate admin
  decisions.
- Local-simulator promotion is database backed, revision checked, idempotent,
  transactional with audit and outbox evidence, and pinned by bundle digest.
  Rollback is a new audited promotion, never a rewrite.

## Explicit Exclusions

Gate 0A does not authorize or claim:

- scope beyond `V09-DEV-001` through `V09-DEV-009`;
- an operator-console tab, shared runtime-control store, or change to the
  accepted `/index.html` operator surface;
- Python interpreter or `PYTHONPATH` configuration, a desktop launcher,
  executable imports, or arbitrary source, expression, template, snippet,
  hook, shell, native, bytecode, pickle, or module execution;
- Git, SVN, CVS, a remote provider, repository credentials, checkout, push,
  pull, network access, broad TEAM actions, or source-errata implementation;
- caller-selected host paths, arbitrary host deletion, traversal, symlink or
  reparse escape, device paths, or unbounded file authority;
- a live GCS, spacecraft, mission network, live telemetry or telecommand,
  driver mutation, or another external-effect route;
- runtime loading from a mutable workspace, history head, editor buffer, or raw
  v0.9 procedure source;
- promotion beyond the local simulator or migration of inherited v0.8 bundled
  simulator fixtures;
- a new container image or change to the four-image SBOM boundary;
- same-subject author and review, approval, or promotion decisions;
- a cryptographic signature, signed commit, signed tag, or external artifact
  repository; or
- implementation completion, release acceptance, deployment approval,
  operational authorization, or a compliance determination.

## Accepted Baseline Evidence

The machine-readable scope is
[`v0.9-gate-0a.json`](../requirements/compatibility/scopes/v0.9-gate-0a.json).
It binds the accepted v0.8.0 release through immutable Git objects rather than
mutable working files:

| Baseline item | Bound value |
| --- | --- |
| Tag ref | `refs/tags/v0.8.0` |
| Tag object type and ID | `tag`; `0dcf4f539fd1a9036fe4db4bc159cde04c35cfae` |
| Raw tag-object SHA-256 | `c609c25cb8987222df0b143f71aa792140171acffd454e31a760c16fb263eede` |
| Raw tag-object bytes | `954` |
| Peeled release commit | `d6e01222de3bf52013279e48a099b6ae7ded121d` |
| Release tree | `9f89c60e59711a6555e67e6ab81bfe74c3b29c41` |
| Qualified source commit | `d80c4d43969018633bc17650a23412b7274e58ea` |
| Qualified source parent | `02c35e063125715703922494daa42bbfb7b7154b` |
| Candidate implementation commit | `f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c` |
| Accepted `artifacts/v0.8` tree | `899dd791fbfd5aa8720c3ce836d5cc2208bac6b9` |
| Source fingerprint SHA-256 | `6eafe23737e266f0038930703656eb569b5e321d718dfef218a1448c3b2f5268` |
| Evidence fingerprint SHA-256 | `6a8f5446aeee9084ef58c9ec2323d6e1d2f8e957cb07e21f46ab9300fab5b1ae` |
| Product package SHA-256 | `c6f835a5fcc6289408493e68d866493b882bf00139a83ea3709283745a1a4554` |
| Work-package evidence SHA-256 | `5fdfa848edf1bdfa8b3b2a161e4dc2c1a356a95cfc424e0e079e5719b1d046d7` |
| Accepted archive SHA-256 | `87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb` |
| Accepted sidecar SHA-256 | `1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817` |

The validator requires the exact annotated tag bytes, tag message, peel,
release structure, ancestry, artifact tree, tagged blob IDs and bytes, and
archive/sidecar pair. It reads accepted bytes from Git object storage and
byte-compares the workspace artifact pair. The annotated tag is not a
cryptographic signature and this gate makes no signature claim.

## Source Authority Bindings

The compatibility authorization remains tied to the exact Development
Environment Manual and Language Reference bytes plus the accepted source
inventory, ledger, reconciliation, technical review, requirements, and
authoring architecture records. Source-authority drift fails closed.

| Authority | SHA-256 |
| --- | --- |
| `SPELL-DOCUMENTATION/SPELL - Development Environment Manual - 2.4.4.pdf` | `cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81` |
| `SPELL-DOCUMENTATION/SPELL - Language Reference - 2.4.4.pdf` | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` |
| Compatibility source inventory | `5c51f1b06f45003cadfe417e9bffc559b381f1e8a20e2bc9c6f7fc160c09c0b7` |
| Compatibility ledger | `f1d4e20383c81a1109e93b39e2aac04f04b2366e91eae613170488a6acf8458f` |
| Compatibility reconciliation | `62c8ad5f678ba313330c35d437d0821c5b097955712860a7e7de697d5327bb85` |

## Authorization Contract Bindings

Exactly nine authorization files are admitted: one manifest and eight matrices
under `contracts/v09`. Their raw SHA-256 values are recorded in the scope and
compiled independently into the validator. Missing, additional, symlinked,
oversized, non-strict JSON, or byte-mutated files fail closed.

<!-- V09_CONTRACT_BINDINGS_BEGIN -->

| Authorization contract | SHA-256 |
| --- | --- |
| `contracts/v09/collaboration_history.json` | `fd7c0b5d6ee82ed57b9d23ac816428503987482ff6a53d29a941099b2308ed32` |
| `contracts/v09/dictionary_catalog_authoring.json` | `30976e5b93d40437ed42b2e38371b39603ae81b82be3a703e453083d30b5a090` |
| `contracts/v09/immutable_bundles.json` | `232ab4a2094db8ee1a7bf840401a153b297f9c6e5d3c1924cb0c44e63889637e` |
| `contracts/v09/import_export_external_changes.json` | `6faf3897cdd2baecf193320c42f273c925e783acfeec9bc8fffcda3af039efbd` |
| `contracts/v09/language_services.json` | `628abeade69458149217bd30f5fff8f5810c708fc11eb08ba0d3a1c4379cf97a` |
| `contracts/v09/manifest.json` | `ce27b6b7d84ffbb3663ebee85befa89d1a765adfe2fc5fab7de24401e0d6c6de` |
| `contracts/v09/project_workspace.json` | `1972deab80d78fde2760004fd0a545b62dd2cbc530ea2a12ee29f2d81f32745c` |
| `contracts/v09/promotion_registry.json` | `1e98e28770047af36899c1db6b4db1355f70503ffd030f155f1de680d83f6972` |
| `contracts/v09/semantic_checks.json` | `8cb4fc54b147e54a77d615bd3070068de2f70729d9887664df26557bbf8b8a66` |

<!-- V09_CONTRACT_BINDINGS_END -->

## Gate Result

The independent validator must emit exactly:

```text
gate=PASS authorized_work_packages=9 proposed_work_packages=9 claimed_constructs=0 claimed_artifacts=0
```

`V09-GATE-0A PASS` authorizes implementation of exactly `V09-DEV-001` through
`V09-DEV-009`. It claims zero implemented constructs and zero implemented
product artifacts. Gate 0B, final qualification, release acceptance,
deployment approval, operational authorization, compliance determination, and
cryptographic-signature verification remain separate decisions.
