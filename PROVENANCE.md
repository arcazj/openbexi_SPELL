# SPELL v0.4 Candidate Provenance and Dependency Review

## Record Status

This record applies to the bounded SPELL v0.4.0 Candidate A engineering scope.
SPELL v0.3.0 remains the accepted baseline. The v0.4 scope is local-only,
synthetic, non-CUI simulator engineering; this document does not record a v0.4
release decision and makes no compliance, deployment, mission, or operational
authorization claim.

## AI Assistance Record

The project owner identifies **ChatGPT 5.6 SOL** as the AI assistance tool used
to help build and document this project. AI assistance does not replace source
verification or the project owner's eventual release decision. Its use does not
establish a compliance determination or operational authorization.

## Clean-Room Boundary

The accepted v0.3 baseline and the v0.4 Candidate A implementation are new
first-party work. The three legacy archives are read-only behavioral and
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
prove clean-room authorship. The v0.4 candidate retains the same source
boundary.

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

Transitive packages remain governed by their upstream licenses. A successful
Gate 5 publication must contain exactly four distinct, source-bound CycloneDX
inventories and their checksum manifest:

| Image boundary | Reserved v0.4 evidence path | Required subject |
| --- | --- | --- |
| Backend runtime | `artifacts/v0.4/sbom/backend.cdx.json` | `openbexi_spell-backend:0.4` |
| Driver runtime | `artifacts/v0.4/sbom/driver.cdx.json` | `openbexi_spell-driver:0.4` |
| Frontend build | `artifacts/v0.4/sbom/frontend.cdx.json` | `openbexi_spell-frontend:0.4` |
| Reverse-proxy runtime | `artifacts/v0.4/sbom/proxy.cdx.json` | `openbexi_spell-proxy:0.4` |

The paths above reserve the required evidence contract; they are not an assertion
that the inventories have been generated or validated. The v0.4 evidence
validator also requires `artifacts/v0.4/sbom/SHA256SUMS` to match their exact
bytes and rejects a duplicate or unbound image identity.

## Licensing Status

New OpenBEXI SPELL implementation and documentation are licensed under Apache
License 2.0 through `LICENSE` and `NOTICE`. That license does not relicense or
alter redistribution restrictions of the excluded legacy archives, supplied
manuals, or third-party packages. This provenance record is not legal advice.

## Candidate Security Review Workflow

The v0.4 Gate 5 workflow must validate every hash lock and pinned container
input, run Python and Node dependency audits, inspect the four image identities,
and reject unresolved Critical or High findings. It must also inspect source,
candidate-package bytes, and product-bearing image paths for credentials,
private keys, supplied/generated PDFs, manual text, legacy archives, generated
journals, and runtime contract-generator tooling.

`scripts/release-toolchain-v04.json` binds the Windows/Docker Desktop release
CLI and plugins by version and file SHA-256. The current workflow requires Docker
SBOM 0.6.0 with Syft v0.43.0 for CycloneDX generation and binds each inventory
to both the source fingerprint and immutable scanned-image identity. These
controls are local engineering evidence only. Their presence or successful
execution would not establish production PKI suitability, compliance, shared
deployment approval, or operational security accreditation.

## Release Evidence Integrity

The v0.4 qualification runner stages built-in and environment-bound results
under `artifacts/v0.4/.qualification`. `plan`, `run` or `collect`, and `status`
do not accept a release. `publish` must atomically validate the exact planned
Gate 1-5 test catalog, semantic assertions, source fingerprint, four SBOMs, and
five gate reports before canonical evidence appears under `artifacts/v0.4`.
Missing, skipped, stale, source-mismatched, or acceptance-claiming collector
results fail closed.

The v0.4 package workflow must validate the canonical evidence, build from an
immutable package-input image more than once, compare exact SHA-256 values, and
recheck the current source context before publishing
`artifacts/v0.4/openbexi-spell-v0.4.tar.gz` and its external `.sha256` sidecar.
Generated browser screenshots, private material, runtime journals, manual/PDF
evidence, legacy archives, and v0.3 evidence are excluded; required product
visual assets and deterministic generated contract artifacts remain included.
Retained `artifacts/v0.3` evidence must not be read as v0.4 evidence or modified
by v0.4 qualification and packaging.

Exact audit results, image identities, evidence fingerprints, package hashes,
exceptions, and the project-owner decision belong in the as-run Gate 5 evidence
and `SPELL_v0.4_Release.md`. Until those fields are populated from executed
evidence, no v0.4 pass or acceptance is claimed here.
