# SPELL v0.3 Provenance and Dependency Review

## Clean-Room Boundary

SPELL v0.3 is a new simulator-only implementation. The three legacy archives
are read-only behavioral and documentation references; no legacy implementation
is compiled, imported, linked, or shipped by the backend, frontend, proxy, or
release package.

The archives are explicitly ignored and excluded from the reproducible package:

| Read-only reference | SHA-256 |
| --- | --- |
| `SPELL2.6.10-src.zip` | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` |
| `SPELL-COTS-2.6.10.zip` | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` |

A v0.2 SHA-256 comparison found no exact match between a new first-party source
file and an archive entry. That mechanical check supports but does not by itself
prove clean-room authorship. Version 0.3 continues the same source boundary.

## Dependency Integrity

Python versions and accepted distribution hashes are fixed in
`backend/requirements.hashes.lock`; release installation uses
`pip --require-hashes`. Node versions and registry integrity values are fixed in
`frontend/package-lock.json`; container builds use `npm ci --ignore-scripts`.

| Direct Python dependency | License family |
| --- | --- |
| FastAPI, SQLAlchemy, Pydantic, pytest | MIT |
| Uvicorn, HTTPX2, python-dotenv | BSD-3-Clause |
| Psycopg | LGPL-3.0-only |

| Direct web dependency | License family |
| --- | --- |
| React, Redux Toolkit, React Redux, Vite, Vitest, jsdom, Testing Library | MIT |
| Apache ECharts, Playwright, TypeScript | Apache-2.0 |
| Lucide React | ISC |

Transitive packages remain governed by their upstream licenses. CycloneDX
inventories are generated independently for each release image:

| Image boundary | Inventory |
| --- | --- |
| Backend | [`artifacts/sbom/backend.cdx.json`](artifacts/sbom/backend.cdx.json) |
| Reverse proxy | [`artifacts/sbom/proxy.cdx.json`](artifacts/sbom/proxy.cdx.json) |
| Frontend build | [`artifacts/sbom/frontend.cdx.json`](artifacts/sbom/frontend.cdx.json) |

Their digests are recorded together in
[`artifacts/sbom/SHA256SUMS`](artifacts/sbom/SHA256SUMS). The frontend inventory
is produced from its dedicated builder image rather than inferred from the
runtime proxy image.

## Licensing Status

New OpenBEXI SPELL implementation and documentation are licensed under Apache
License 2.0 through `LICENSE` and `NOTICE`. That license does not
relicense or alter redistribution restrictions of the excluded legacy archives
or third-party packages. This provenance record is not legal advice.

## Security Review

The v0.3 release gates run `pip-audit==2.10.0` against the hash-locked Python set
and `npm audit` against the Node lock. They report zero known product dependency
vulnerabilities. The audit tool's own bootstrap transitive dependencies are
installed by pip and are not hash-locked; they are release tooling, are not
shipped in a product image, and remain a documented reproducibility limitation.
The upgraded FastAPI/Starlette/HTTP client set is not affected by the five
Starlette advisories accepted in v0.2, and the repository policy test confirms
that none of their vulnerable version ranges or application surfaces remain.

The SBOM generator requires Docker SBOM 0.6.0 with Syft v0.43.0 and scans
immutable image IDs. Its scan-input builds disable BuildKit's nondeterministic
provenance-attestation wrapper so repeated builds resolve to the same runtime
manifest ID; the generated CycloneDX inventories and checksum manifest provide
the release evidence for those images. JSON and the checksum manifest are
written with canonical LF line endings so Git checkout cannot alter their
recorded hashes. The scanner emits warnings when its conversion layer cannot
retain some file-level package relationships. It still produces valid component
inventories and checksums; the warning is a tooling fidelity limitation, not a
waiver of dependency audit results.

No claim is made that dependency audit, SBOM generation, or local isolation is
an operational security accreditation. Shared or operational deployment remains
out of scope.

## Release Evidence Integrity

Quick, soak, and real-browser qualification reports are bound to the same
shared source fingerprint. The browser gate uses two independent Chromium
processes, and a separate composer recomputes report identity, required gates,
and integrity before packaging accepts the evidence. Reproducible packaging
excludes only generated screenshot files under `artifacts/v0.3`; it does not
exclude product PNG or other visual assets by extension alone.
