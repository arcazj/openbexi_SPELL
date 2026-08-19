# SPELL Release Provenance and Dependency Review

## Record Status

This record retains the bounded SPELL v0.5.0 through v0.8.0 provenance, records
the accepted v0.9.0 release, and distinguishes historical v0.9 Gate/source-
freeze claims from the later immutable release endpoint. SPELL v0.9.0 is the
accepted predecessor to the reconstructed v0.10 candidate at
annotated tag `v0.9.0`, tag object
`b47ee98429841afd7d91c928f3a314d6ac7f348c`, and release commit
`a8caa957179f8df301f9863e421e3fd7127e5318`. v0.10 product candidate
`8377760be59033b3372512ad812c43cd6d2f7e29` is independently qualified and
accepted only if its committed package evidence and annotated `v0.10.0` tag
pass the version-scoped validator.

The v0.10 reference-example adapter is independently authored against the
existing clean-room compatibility inventory for `SPELL - Language Reference -
2.4.4`. The external authority is identified by SHA-256
`ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3`;
the PDF and extracted example bodies are not copied into product source or the
backend image. The tracked matrix retains titles, page references, source-span
hashes, compatibility identities, ambiguity decisions, independently authored
adaptations, and executable oracles. Runtime code never evaluates or imports
reference text. Simulator projections remain local and non-operational, and
telecommand adaptations record `live_dispatch=false`. This establishes
traceable semantic-adaptation evidence only, not copyright ownership, verbatim
source compatibility, arbitrary Python support, operational authorization, or
general SPELL 2.4.4 conformance.

The v0.10 release policy pins all eight mandatory source-reference files under
`SPELL_DOCUMENTATION/`, including the legacy source ZIP as read-only evidence.
Those bytes are versioned for traceability but excluded from backend images and
the deterministic product package. Generated documentation is derived context,
not a replacement source authority. No legacy implementation is copied.

v0.11 is future simulator-telecommand scope only in this release tree. There is
no `contracts/v11`, v0.11 IR/runtime, v0.11 evidence, package, or release record
to which v0.10 provenance can attach. Any later v0.11 implementation must be
new first-party work based on accepted v0.10 and separately requalified against
the mandatory references.

For v0.6, candidate commit `0ea26105e72d7830de4a265989ed7d9074ffbe09`
is bound to canonical work-package evidence SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`.
All ten candidate suites and all 45 identities PASS, all nine work packages are
`IMPLEMENTED_AND_QUALIFIED`, and `V06-GATE-0B PASS` authorized release
closeout. Final qualification, four v0.6 SBOMs, supply-chain evidence,
deterministic packaging, release-evidence validation, and annotated tagging
passed with no accepted exceptions. The final archive SHA-256 is
`b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c`.

`V07-GATE-0A PASS` authorized only the nine `V07-OBS-001` through
`V07-OBS-009` packages and their 45 planned proof identities. Candidate
`82b497227aff097db9d4c3ff56adf56d76d892ca`, tree
`2f553c152ce103c7ded70af811f2f84257f7c1b5`, is bound to canonical evidence
SHA-256
`04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20`.
Its candidate source fingerprint is
`c1e6ee8cce92f6a86da117646ec4643f78398b7a5d448f9ae22d2607e797d035`,
and its candidate product fingerprint is
`3c90c205adef1daf8dcf9b60528b90d349c2d62ddf4568fc71b135398384bfb2`.
Ten suites and all 45 mapped identities PASS; the 2,070-test aggregate contains
2,051 passes, 19 explicit suite-level platform skips, 36 subtests, and zero
failures or errors, while mapped identity skips, accepted failures, and waivers
are zero.
All nine packages are `IMPLEMENTED_AND_QUALIFIED`, and `V07-GATE-0B PASS`
authorized release closeout. Qualified source
`6ac43c5be7670ead09de821578cc6c6a680af109` has source fingerprint
`a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb` and
product fingerprint
`fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633`.
Final qualification passed nine suite captures, 2,041 tests, 2,034 passes,
seven exact SQLite environment skips, 36 subtests, and zero failures or errors.
Four image-bound SBOMs, supply-chain evidence, deterministic packaging, and
release-evidence validation passed. Release-manifest SHA-256
`e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a`
binds evidence fingerprint
`7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718`.
Final archive SHA-256
`90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2`
and strict annotated-tag validation complete acceptance with no accepted
exceptions.

`V08-GATE-0A PASS` authorizes only the nine `V08-DATA-001` through
`V08-DATA-009` packages and their 45 proof identities under
`LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE`. The gate itself claimed zero product
constructs and zero runtime artifacts. Subsequent first-party work implemented
the bounded data models, migrations, repositories and mutation coordinator,
dictionary exchange, virtual-file runtime, authenticated API, procedure data
operations, frontend Data Service workspace, and v0.8 qualification/release
tooling. Candidate `f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c` and all 45
mapped identities passed; `V08-GATE-0B PASS` authorized closeout. Qualified
source `d80c4d43969018633bc17650a23412b7274e58ea`, Final qualification, four
SBOMs, supply-chain evidence, reproducible packaging, release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`, and strict annotated tag
`v0.8.0` validation passed with no accepted exceptions. The release evidence
fingerprint is
`6a8f5446aeee9084ef58c9ec2323d6e1d2f8e957cb07e21f46ab9300fab5b1ae`, and
the final archive SHA-256 is
`87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb`.

The owner request `start and complete asap V0.9` and `V09-GATE-0A PASS`
authorize only `V09-DEV-001` through `V09-DEV-009` and 45 planned proof
identities under `LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT`. That gate
claims zero implementation or runtime artifacts at its authorization-time
boundary. At candidate source freeze, the bounded first-party implementation,
version-scoped tooling, and exact product inventory were frozen together.
Canonical candidate qualification had not yet run, so no Gate 0B, package,
release, deployment, cryptographic-signature, compliance, mission, or
operational provenance is claimed for v0.9.

The owner-approved local-session JWT exception is configuration provenance, not
release evidence: one effectively long-lived, loopback-only token with a finite
`exp` may be created by a one-shot transient issuer and stored only in an
ignored local file under `var/`, while token issuance remains disabled in every
running service. Issuer configuration and the signing secret stay in the
ignored local `.env`; the issued token does not. Default and qualification
tokens remain short-lived. Token and signing-secret bytes must never be printed,
logged, committed, packaged, or included in evidence, and secret rotation
invalidates the local token.

Before v0.8 qualification, Docker Scout identified 18 High findings in the
pinned `postgresql18=18.4-r0` local image package. v0.8 updated that exact pin
to patched `18.6-r0`; the complete supply-chain qualification then passed with
zero High or Critical findings and no vulnerability waiver or accepted
exception.

## AI Assistance Record

The project owner identifies **ChatGPT 5.6 SOL** as the AI assistance tool used
to help build and document this project. AI assistance does not replace source
verification or the project owner's eventual release decision. Its use does not
establish a compliance determination or operational authorization.

## Clean-Room Boundary

The accepted v0.4, v0.5, v0.6, v0.7, and v0.8 baselines and their bounded implementations
are new first-party work. The three legacy archives are read-only behavioral
and historical references; no legacy implementation may be compiled,
imported, linked, copied into generated sources, loaded at runtime, or shipped
by the backend, driver, frontend, proxy, or release package.

The archives are explicitly ignored and excluded from the reproducible package:

| Read-only reference | SHA-256 |
| --- | --- |
| `SPELL2.6.10-src.zip` | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` |
| `SPELL-COTS-2.6.10.zip` | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` |

A v0.2 SHA-256 comparison found no exact match between a new first-party source
file and an archive entry. That mechanical check supports but does not by itself
prove clean-room authorship. The accepted v0.4 through v0.8 releases and the
v0.9 planning contracts retain the same source boundary.

### Manual Reference Boundary

Every document under `SPELL_DOCUMENTATION/` is a mandatory read-only source
reference for future analysis, implementation scope, tests, and delivery. The
page-complete review and compatibility ledger classify concepts, conflicts,
errata, Candidate A applicability, safety strengthening, and explicit
exclusions. The manuals are not implementation source, redistributable product
content, a version-exact executable oracle, or proof that an excluded legacy
capability exists. Generated documentation and new first-party code must trace
their applicable behavior and deliberate incompatibilities back to these
references.

| External evidence set | Stated version | Pages | Packaging disposition |
| --- | --- | ---: | --- |
| Build Manual | 2.4.4 | 16 | Excluded |
| Development Environment Manual | 2.4.4 | 57 | Excluded |
| Driver Development Manual | 2.4.4 | 45 | Excluded |
| GUI User Manual | 2.4.4 | 54 | Excluded |
| Language Reference | 2.4.4 | 118 | Excluded |
| Server Manual | 2.4.4 | 11 | Excluded |
| GUI Build Instructions | 4.0.2 | 3 | Excluded |

The controlled filenames and SHA-256 values are recorded in
[`SPELL_DOCUMENTATION_REVIEW.md`](SPELL_DOCUMENTATION_REVIEW.md). Supplied PDFs,
extracted manual text, and legacy archives must be absent from product images
and the v0.4 package. The Candidate A typed contract deliberately does not copy
the manuals' weakly typed, in-process, or insecure legacy wire designs.

## Dependency Integrity

Python direct inputs and accepted distribution hashes are separated by trust
boundary and fixed in these requirement/lock pairs:

- `backend/requirements.txt` and `backend/requirements.hashes.lock`;
- `driver_host/requirements.txt` and `driver_host/requirements.hashes.lock`;
- `driver_host/pki-requirements.txt` and
  `driver_host/pki-requirements.hashes.lock`;
- `contracts/generator-requirements.txt` and
  `contracts/generator-requirements.hashes.lock`;
- `scripts/supply-chain-requirements.txt` and
  `scripts/supply-chain-requirements.hashes.lock`.

Release installation uses `pip --require-hashes`. Node versions and registry
integrity values are fixed in `frontend/package-lock.json`, and container builds
use `npm ci --ignore-scripts`. Protobuf and gRPC direct versions are identical
across the control plane, driver host, and offline generator inputs.

| Direct dependency group | License family |
| --- | --- |
| FastAPI, SQLAlchemy, Pydantic, pytest | MIT |
| Uvicorn, HTTPX, python-dotenv | BSD-3-Clause |
| Psycopg | LGPL-3.0-only |
| gRPC and gRPC tools | Apache-2.0 |
| Protobuf | BSD-3-Clause |
| Cryptography | Apache-2.0 or BSD-3-Clause |
| React, Redux Toolkit, React Redux, Vite, Vitest, jsdom, Testing Library | MIT |
| Apache ECharts, Playwright, TypeScript | Apache-2.0 |
| Lucide React | ISC |

Transitive packages remain governed by their upstream licenses. The accepted
v0.4 Gate 5 publication contains four distinct, source-bound CycloneDX
inventories and their checksum manifest:

| Image boundary | Reserved v0.4 evidence path | Required subject |
| --- | --- | --- |
| Backend runtime | `artifacts/v0.4/sbom/backend.cdx.json` | `openbexi_spell-backend:0.4` |
| Driver runtime | `artifacts/v0.4/sbom/driver.cdx.json` | `openbexi_spell-driver:0.4` |
| Frontend build | `artifacts/v0.4/sbom/frontend.cdx.json` | `openbexi_spell-frontend:0.4` |
| Reverse-proxy runtime | `artifacts/v0.4/sbom/proxy.cdx.json` | `openbexi_spell-proxy:0.4` |

The paths above are immutable accepted v0.4 evidence. The v0.4 evidence
validator requires `artifacts/v0.4/sbom/SHA256SUMS` to match their exact bytes
and rejects a duplicate or unbound image identity.

## Licensing Status

New OpenBEXI SPELL implementation and documentation are licensed under Apache
License 2.0 through `LICENSE` and `NOTICE`. That license does not relicense or
alter redistribution restrictions of the excluded legacy archives, supplied
manuals, or third-party packages. This provenance record is not legal advice.

## Accepted v0.4 Security Evidence

The v0.4 Gate 5 workflow validated every hash lock and pinned container input,
ran Python and Node dependency audits, inspected the four image identities, and
rejected unresolved Critical or High findings. It also inspected source,
package bytes, and product-bearing image paths for credentials, private keys,
supplied/generated PDFs, manual text, legacy archives, generated journals, and
runtime contract-generator tooling.

`scripts/release-toolchain-v04.json` binds the Windows/Docker Desktop release
CLI and plugins by version and file SHA-256. The current workflow requires Docker
SBOM 0.6.0 with Syft v0.43.0 for CycloneDX generation and binds each inventory
to both the source fingerprint and immutable scanned-image identity. These
controls are local engineering evidence only. Their presence or successful
execution would not establish production PKI suitability, compliance, shared
deployment approval, or operational security accreditation.

## v0.5 Inherited Controls And Accepted Release Evidence

The v0.5 increment introduces no dependency or driver implementation change.
It deliberately inherits the accepted digest-pinned
`scripts/release-toolchain-v04.json`, the existing hash-lock pairs, and the
accepted `spell.driver.v1` contract. The bundled driver keeps implementation
identity and default `0.4.0`; changing that handshake without a driver change
would misrepresent compatibility and invalidate existing persistence and
regression evidence. The v0.5 product image containing that unchanged driver
may carry the v0.5 package/SBOM subject while the runtime driver handshake
continues to report `0.4.0`.

The canonical candidate evidence at
`artifacts/v0.5/work-package/qualification.json` independently validates
candidate `aefa658ce01d49a7879d0471b50425ac3bcf9e2d` against qualification
correction/source `ef26e53f5ecccabef1fff03ec86d71b0c93edd2b`. Its SHA-256 is
`86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9`, with
four suites, six identities, and 949 concrete tests. The `ef26e53` delta is a
test-only correction to Docker inspection timeout metadata and introduces no
product, dependency, driver, or runtime behavior change. Live Gate 0B
validation passes with exact marker
`gate=PASS work_packages=1 identities=6 failed=0 skipped=0 claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED`.

The v0.5 closeout independently generated four source- and image-bound
inventories under `artifacts/v0.5/sbom`, validated their checksum manifest,
re-ran the current-source dependency audit, found zero unresolved High or
Critical findings and zero unlocked inputs, and proved accepted
`artifacts/v0.4` bytes were not modified. Final qualification passed eight
suites, 1,096 concrete tests, 1,090 passes, six exact approved SQLite
environment skips, 36 subtests, and zero failures or errors. The product
package fingerprint is
`e5b5b69c5951c1ec7fe7023293f0584471fed98d144a97afde12323d78fd7901`,
and the final deterministic archive SHA-256 is
`cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241`.

The release evidence fingerprint is
`c3df31909b8c16f57c80ab3db906e3d25df72c91a855019022098ddd46aab0bd`.
Annotated tag `v0.5.0` verified over release commit
`e7b6bb9428833437e0160040541eb840deee7cca` and activated the conditional
acceptance. This post-tag reconciliation does not imply that the immutable tag
contains a later documentation commit.

## Release Evidence Integrity

The accepted v0.4 qualification runner staged built-in and environment-bound results
under `artifacts/v0.4/.qualification`. `plan`, `run` or `collect`, and `status`
do not accept a release. `publish` must atomically validate the exact planned
Gate 1-5 test catalog, semantic assertions, source fingerprint, four SBOMs, and
five gate reports before canonical evidence appears under `artifacts/v0.4`.
Missing, skipped, stale, source-mismatched, or acceptance-claiming collector
results fail closed.

The accepted v0.4 package workflow validated canonical evidence, built from an
immutable package-input image more than once, compared exact SHA-256 values, and
rechecked the source context before publishing
`artifacts/v0.4/openbexi-spell-v0.4.tar.gz` and its external `.sha256` sidecar.
Generated browser screenshots, private material, runtime journals, manual/PDF
evidence, legacy archives, and v0.3 evidence are excluded; required product
visual assets and deterministic generated contract artifacts remain included.
Retained `artifacts/v0.3` evidence must not be read as v0.4 evidence or modified
by v0.4 qualification and packaging.

The v0.5 closeout binds exact audit results, image identities, evidence
fingerprints, package hashes, exceptions, and the project-owner decision in
canonical artifacts and [`SPELL_v0.5_Release.md`](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.5_Release.md).
The verified annotated `v0.5.0` tag activated the conditional owner acceptance
recorded in the release commit; no post-tag documentation commit was required.

The approved v0.6 Gate 0A scope inherits this clean-room boundary.
`V06-GATE-0A PASS` authorizes only `V06-OP-001` through `V06-OP-009`; it does
not itself qualify or accept an implementation. Candidate commit
`0ea26105e72d7830de4a265989ed7d9074ffbe09` adds
internal opt-in IR 0.6, the local operator API/UI, and migration 0004 while
pinning accepted IR 0.3 bytes, adding no runtime dependency, and retaining the
bundled simulator driver implementation/default at `0.4.0`.

Canonical work-package evidence SHA-256
`16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538`
binds that candidate. All ten suites and all 45 identities PASS with zero
mapped skips, failures, accepted failures, or waivers. `V06-GATE-0B PASS`
records all nine work packages as `IMPLEMENTED_AND_QUALIFIED` and authorizes
release closeout. Final qualification then passed nine suite captures with
1,626 concrete tests, 1,620 passes, six exact SQLite environment skips, 36
subtests, and zero failures or errors. Four image-bound SBOMs, supply-chain
evidence, deterministic packaging, and release-evidence validation passed.
Annotated tag `v0.6.0` verified over release commit
`05ec783a6e54a76e0548bdd536c18538f6bff51b` and activated the conditional
acceptance with no accepted exceptions. None of that evidence reuses or
rewrites canonical v0.5 evidence.

The approved v0.7 Gate 0A record independently binds the accepted v0.6.0 tag,
tagged release evidence and archive/sidecar bytes, and all seven files under
`contracts/v07`. Those contracts are bounded, declarative, simulator-only,
read-only planning inputs. They authorize implementation of exactly
`V07-OBS-001` through `V07-OBS-009`, but do not establish that any v0.7 source,
API, schema, migration, dependency, driver behavior, runtime artifact, test
result, or release exists.

The qualified v0.7 candidate implements only those nine approved
simulator-only, read-only packages. New source remains project-authored and
dependency-locked; the driver observation service, backend projections,
condition runtime, APIs, and frontend use synthetic local data only. Canonical
candidate evidence now binds the exact source revision and proves all 45
identities with zero mapped skips. Gate 0B authorized release closeout; Final
qualification, four SBOMs, supply-chain validation, deterministic packaging,
release-evidence validation, and annotated tag `v0.7.0` later passed. Tag object
`70e4d46a46d158dee3c63ec37a5d1922b3b61668` fixes release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864` and accepted provenance with no
accepted exceptions. No live GCS, spacecraft, mission-network, classified,
CUI, or production data was introduced.

The approved v0.8 Gate 0A record independently binds the accepted v0.7.0 tag
and nine declarative planning-contract files under `contracts/v08`. It
authorizes bounded implementation entry for `V08-DATA-001` through
`V08-DATA-009`; at gate time it established no source, API, schema, migration,
dependency, runtime artifact, qualification, or release provenance. The later
accepted release implements only that bounded scope using new project-authored
source, locked dependencies, synthetic local test data, and no legacy runtime
content. Canonical candidate, Gate 0B, Final, SBOM/supply-chain, package,
release, and tag provenance passed and is fixed by annotated tag `v0.8.0`.

The approved v0.9 Gate 0A record independently binds accepted v0.8.0 through
raw Git tag and tagged artifact bytes and binds nine declarative planning
contracts under `contracts/v09`. It authorizes bounded implementation entry
for `V09-DEV-001` through `V09-DEV-009` only. No v0.9 product source,
dependency, migration, runtime artifact, executed product result, bundle,
promotion, qualification, release, or cryptographic-signature provenance is
claimed at Gate 0A.

Subsequent new project-authored source freezes the bounded development API,
migration, separate `/development.html` frontend, v0.9 qualification/release
tooling, and exact product inventory together for one candidate commit. This is
source-freeze provenance only. Canonical candidate qualification had not yet
run, and it established no Gate 0B decision, Final result, package, release
commit, or tag provenance. Any later acceptance is authoritative only through
the strictly validated annotated tag and committed evidence.
