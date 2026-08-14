# SPELL v0.5 Release Provenance and Dependency Review

## Record Status

This record applies to the bounded SPELL v0.5.0 release closeout. SPELL v0.4.0
is the accepted local-only, synthetic, non-CUI simulator engineering baseline.
`V05-GATE-0B PASS` authorizes release closeout for `V05-IR-001` only. Canonical
candidate qualification integration and live Gate 0B validation now pass;
Final validation, SBOM/supply-chain evidence, the release commit, deterministic
package, and annotated `v0.5.0` tag remain pending. This document makes no
compliance, deployment, mission, or operational authorization claim.

## AI Assistance Record

The project owner identifies **ChatGPT 5.6 SOL** as the AI assistance tool used
to help build and document this project. AI assistance does not replace source
verification or the project owner's eventual release decision. Its use does not
establish a compliance determination or operational authorization.

## Clean-Room Boundary

The accepted v0.4 baseline and the bounded v0.5 IR-hardening implementation are
new first-party work. The three legacy archives are read-only behavioral and
historical references; no legacy implementation may be compiled, imported,
linked, copied into generated sources, loaded at runtime, or shipped by the
backend, driver, frontend, proxy, or release package.

The archives are explicitly ignored and excluded from the reproducible package:

| Read-only reference | SHA-256 |
| --- | --- |
| `SPELL2.6.10-src.zip` | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` |
| `SPELL-COTS-2.6.10.zip` | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` |

A v0.2 SHA-256 comparison found no exact match between a new first-party source
file and an archive entry. That mechanical check supports but does not by itself
prove clean-room authorship. The accepted v0.4 release and v0.5 candidate
retain the same source boundary.

### Manual Evidence Boundary

The seven supplied manuals and build instructions are read-only external
evidence. Their page-complete review and compatibility ledger classify concepts,
conflicts, errata, Candidate A applicability, and explicit exclusions. They are
not implementation source, redistributable product content, a version-exact
executable oracle, or proof that an excluded legacy capability exists.

| External evidence set | Stated version | Pages | Packaging disposition |
| --- | --- | ---: | --- |
| Build Manual | 2.4.4 | 16 | Excluded |
| Development Environment Manual | 2.4.4 | 57 | Excluded |
| Driver Development Manual | 2.4.4 | 45 | Excluded |
| GUI User Manual | 2.4.4 | 54 | Excluded |
| Language Reference | 2.4.4 | 118 | Excluded |
| Server Manual | 2.4.4 | 11 | Excluded |
| GUI Build Instructions | 4.0.2 | 3 | Excluded |

The authoritative filenames and SHA-256 values are recorded in
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

## v0.5 Inherited Controls, Candidate Evidence, And Pending Release Evidence

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

The v0.5 closeout must independently generate four source- and image-bound
inventories under `artifacts/v0.5/sbom`, validate their checksum manifest,
re-run the current-source dependency audit, reject unresolved Critical/High
findings, and prove accepted `artifacts/v0.4` bytes were not modified. Those
release-level artifacts are not yet integrated; the canonical candidate record
does not imply their result. No v0.5 SBOM, supply-chain, package, or Final pass
is claimed.

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

The v0.5 closeout must similarly bind exact audit results, image identities,
evidence fingerprints, package hashes, exceptions, and the project-owner
decision in canonical artifacts and [`SPELL_v0.5_Release.md`](SPELL_v0.5_Release.md).
Until those fields are populated and Final validation passes, SPELL v0.4.0
remains the accepted release and no v0.5 tag or final acceptance is claimed.
If all release conditions pass, the verified annotated `v0.5.0` tag activates
the conditional owner acceptance recorded in the release commit; no post-tag
documentation commit is required.
