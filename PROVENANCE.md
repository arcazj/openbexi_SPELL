# SPELL v0.2 Provenance and Dependency Review

## Clean-Room Boundary

SPELL v0.2 is a new simulator-only implementation. The legacy archives are
read-only behavioral and documentation references; no legacy implementation is
compiled, imported, linked, or shipped by the v0.2 backend or frontend.

New first-party implementation is limited to `backend/`, `frontend/src/`,
`frontend/e2e/`, and `procedures/`. A SHA-256 comparison performed on
2026-07-12 found no exact match between a new source file and any entry in the
three reference archives. This mechanical check supports, but does not by
itself prove, clean-room authorship.

| Read-only reference | SHA-256 |
| --- | --- |
| `SPELL2.6.10-src.zip` | `2176E198F04C3F2EC99EE6F740871D9368997E3FD1E33D6734CB8E163CB6A0ED` |
| `SPELL-COTS-2.6.10.zip` | `29E4639E15244308907FDCBA607F55F8A3A5FD3E2A49D631B6F996B33EA35558` |
| `SPELL_GUI_4.0.12-win32.win32.x86.zip` | `751BAE952B3928BE3D5BA7CBD6D4EADD84BCBBA1248EA2707EABFDE75E493E10` |

## Direct Dependencies

Versions are fixed by `backend/requirements.lock` and
`frontend/package-lock.json`. Transitive package licenses remain governed by
their upstream packages and lock-file inventory.

| Python dependency | License |
| --- | --- |
| FastAPI, SQLAlchemy, Pydantic, pytest | MIT |
| Uvicorn, HTTPX, python-dotenv | BSD-3-Clause |
| Psycopg | LGPL-3.0-only |

| Web dependency | License |
| --- | --- |
| React, Redux Toolkit, React Redux, Vite, Vitest, jsdom, Testing Library | MIT |
| Apache ECharts, Playwright, TypeScript | Apache-2.0 |
| Lucide React | ISC |

The Node lock records registry integrity hashes. The Python lock records exact
versions but not artifact hashes; hash-locked Python wheelhouse generation is a
future supply-chain hardening item.

CycloneDX inventories generated for the release are stored in
[`artifacts/v0.2/python-sbom.cdx.json`](artifacts/v0.2/python-sbom.cdx.json) and
[`artifacts/v0.2/node-sbom.cdx.json`](artifacts/v0.2/node-sbom.cdx.json).

## Licensing Status

The new OpenBEXI SPELL implementation is licensed under the Apache License,
Version 2.0. See `LICENSE` and `NOTICE`. This project license does not change
the licenses or redistribution restrictions of the excluded legacy archives or
third-party dependencies, and this review is not legal advice.

## Security Review Status

The frontend full dependency audit reported zero known vulnerabilities on
2026-07-12. Python test and dotenv advisories were removed by the v0.2 secure
pins. The remaining Starlette advisories require versions not currently
compatible with the latest available FastAPI release; v0.2 mitigates the
applicable Host-header risk with trusted-host validation, binds services to
loopback, and does not use the affected static-file, form, or endpoint-class
surfaces. This disposition is valid only for the local simulator slice and must
be revisited before any shared or operational deployment.

The accepted local-release residuals are `PYSEC-2026-161`, `PYSEC-2026-248`,
`PYSEC-2026-249`, `GHSA-wqp7-x3pw-xc5r`, and `GHSA-x746-7m8f-x49c`. They are
listed with upstream references and the release restrictions in
[`SPELL_v0.2_Release.md`](SPELL_v0.2_Release.md).
