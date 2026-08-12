# SPELL v0.4 Release Record

## Record Status

This is the pre-freeze release-record skeleton for SPELL v0.4.0 Candidate A.
It reserves the fields required for an as-run decision but does not record Gate
1-5 completion, release acceptance, a package digest, or an annotated tag.

| Field | Value |
| --- | --- |
| Version | 0.4.0 |
| Release name | Typed Simulator Driver and Context Foundation |
| Accepted baseline | `v0.3.0` (`7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`) |
| Scope profile | Local-only, synthetic non-CUI simulator engineering |
| Candidate source commit | Pending source freeze |
| Qualification source fingerprint | Pending canonical as-run evidence |
| Evidence identity | Canonical machine evidence and annotated tag; no self-derived digest is embedded in this packaged record |
| Final archive SHA-256 | External `.sha256` sidecar and annotated tag only; never embedded in this packaged record |
| Decision date | Pending project-owner decision |
| Release status | Candidate; decision not yet recorded |
| Annotated tag | Selected externally after committed evidence validates; never self-embedded |
| Compliance determination | None claimed |
| Operational authorization | None |

## Candidate Scope

The owner-approved Candidate A scope is defined by
[`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md) and its
test allocation in [`Test_and_Integration.md`](Test_and_Integration.md). The
candidate is limited to:

- one typed, versioned `spell.driver.v1` infrastructure-lifecycle contract;
- one bundled deterministic simulator driver in a separate local host;
- control-plane-owned context, attachment, operation, audit, and reconciliation
  state with no automatic resend of an uncertain effect;
- mutually authenticated local service identity with no insecure fallback;
- authenticated read-only REST/WebSocket and console driver projections; and
- version-scoped qualification, four-image SBOM, inspection, install-lifecycle,
  and reproducible source-package workflows.

Existing v0.3 procedure semantics and schema identifiers remain compatibility
contracts and do not route through the driver. This section describes approved
candidate scope, not delivered or accepted release behavior.

## As-Run Gate Results

Populate this table from one complete preliminary source-bound pass, then
freeze this record and rerun every content-sensitive qualification step. The
values become final only when `scripts/qualify_v04.py publish` validates and
publishes the complete rerun against the frozen record. Do not edit the record
after that final pass.

| Gate | Evidence path | As-run result | Exceptions or limitations |
| --- | --- | --- | --- |
| Gate 1: contract, configuration, lifecycle, persistence, migration | `artifacts/v0.4/gate-1.json` | Pending | Pending |
| Gate 2: isolation, identity, faults, recovery, certainty | `artifacts/v0.4/gate-2.json` | Pending | Pending |
| Gate 3: API, console, accessibility, v0.3 regression | `artifacts/v0.4/gate-3.json` | Pending | Pending |
| Gate 4: local performance and soak budgets | `artifacts/v0.4/gate-4.json` | Pending | Pending |
| Gate 5: dependency, SBOM, package, lifecycle, platform | `artifacts/v0.4/gate-5.json` | Pending | Pending |

## Gate 5 Environment Prerequisite

The Windows-amd64 SC006 lifecycle controller requires the CPython 3.13.14
embeddable runtime provisioned during this qualification run from
`https://www.python.org/ftp/python/3.13.14/python-3.13.14-embeddable-amd64.zip`.
The official archive identity recorded in `scripts/release-toolchain-v04.json`
is SHA-256
`90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907`.
This host-side controller is qualification tooling, not a claim about the
product runtime.

Before any Gate 5 collector runs, `scripts/assert_release_toolchain_v04.ps1`
must verify the archive digest, the locked `python.exe` digest and version, and
the exact extracted runtime file set and bytes against that archive. A missing,
modified, additional, or reparse-point runtime file fails the gate closed. The
runtime remains outside the repository and is not a release-package input.

## As-Run Evidence Reservation

| Evidence | Reserved location | Recorded identity or result |
| --- | --- | --- |
| Per-test evidence | `artifacts/v0.4/tests/` | Pending |
| Backend SBOM | `artifacts/v0.4/sbom/backend.cdx.json` | Pending |
| Driver SBOM | `artifacts/v0.4/sbom/driver.cdx.json` | Pending |
| Frontend-build SBOM | `artifacts/v0.4/sbom/frontend.cdx.json` | Pending |
| Proxy SBOM | `artifacts/v0.4/sbom/proxy.cdx.json` | Pending |
| SBOM checksum manifest | `artifacts/v0.4/sbom/SHA256SUMS` | Pending |
| Source release package | `artifacts/v0.4/openbexi-spell-v0.4.tar.gz` | Pending |
| External package sidecar | `artifacts/v0.4/openbexi-spell-v0.4.tar.gz.sha256` | Pending |
| Desktop browser image | `artifacts/v0.4/driver-projection-desktop.png` | Pending |
| Mobile browser image | `artifacts/v0.4/driver-projection-mobile.png` | Pending |

The final record must state the exact test environment, counts, budgets,
measurements, image identities, dependency-audit dispositions, qualification
source fingerprint, reproducibility comparison, candidate source commit, and
any retained limitation. Planned values must not be rewritten as executed
results. The exact evidence fingerprint and SC004 product/package-input binding
remain in canonical machine evidence and are copied into the annotated tag,
not into this packaged record.

This record is itself a product-package input. Embedding any digest derived
from SC004 or the canonical evidence would change the record, which would
change SC004 and the evidence fingerprint in turn. Embedding the final release
archive digest would likewise change the archive. Those self-derived values
are therefore published only after the packaged record and archive bytes are
fixed: the package SHA-256 goes in
`openbexi-spell-v0.4.tar.gz.sha256`, and the annotated tag records the exact
evidence fingerprint, SC004 product/package-input binding, package SHA-256,
and release commit it identifies. SC003 and SC004 bind and drift-check the
inspected product inputs, immutable image identities, generated contract, and
reproducible product-only package bytes. The release-evidence validator and
final reproducible package builder separately validate and bind the canonical
evidence inputs into the final archive. No packaged field purports to identify
bytes that include that same field.

The annotated `v0.4.0` tag message is the final project-owner acceptance
record. It must state, as separate unambiguous fields, the owner and decision,
candidate source commit, qualification source fingerprint, evidence
fingerprint, SC004 product-package SHA-256, final archive SHA-256, release
commit, scope profile, accepted exceptions, and the explicit absence of a
compliance determination or operational authorization. The tag is created only
after those values independently validate against the committed evidence and
external package sidecar.

The approved SBOM subject set remains exactly backend, driver, frontend-build,
and proxy. The one-shot `pki-init` image and digest-pinned PostgreSQL image are
Compose dependencies rather than additional SBOM subjects; Gate 5 records
their exact local image identities and scans/audits them separately. The
`pki-init` root execution is limited to network-none credential initialization
with the explicit Compose capability allowlist; it is not a runtime-driver
non-root exception.

Each of the four SBOMs must also pass the matching bundled CycloneDX JSON
schema through the hash-locked `cyclonedx-python-lib` 11.11.0
`JsonStrictValidator` in a network-none container. Missing optional validation
dependencies fail the collector. The validator must accept its valid control
document and reject a schema-invalid tampered control document before SC002
can report success.

## Explicit Exclusions

Version 0.4 does not add telemetry, telecommand, event, resource, task, time,
ranging, memory, PCS, database, subscription, or other driver data services. It
does not route procedure source, restricted IR, or existing procedure steps
through the driver and does not add browser driver mutations.

Live, legacy, test-range, non-operational, or operational GCS adapters;
spacecraft connectivity; mission networks; arbitrary endpoints; operational
identifiers; externally effective commands; production PKI or identity;
high-availability or multi-node deployment; Kubernetes; operational SLOs;
accreditation; deployment approval; compliance claims; and mission authority
remain outside the candidate.

Legacy implementation archives, supplied manuals/PDFs, extracted manual text,
credentials, private keys, generated journals, generated browser evidence, and
retained v0.3 evidence are not product-package inputs. Their exclusion does not
assert rights to redistribute them.

## Measurement And Claim Boundaries

Any recorded latency, throughput, restart, soak, browser, migration, isolation,
or package result is a bounded local engineering measurement in its exact
as-run environment. It is not an operational SLO, production qualification,
compliance assessment, deployment approval, or mission authorization.

## Project-Owner Decision

Populate the non-self-referential decision fields after a complete preliminary
validation and before the final SC004/package-binding run. The decision becomes
effective only when every mandatory canonical gate validates and the project
owner's annotated `v0.4.0` tag is created over the fixed release commit. The tag
therefore records the exact identities that cannot be embedded here.

| Decision field | As-run value |
| --- | --- |
| Decision | Pending |
| Decision basis | Pending canonical Gates 1-5 and annotated-tag identity |
| Accepted exceptions | Pending; none inferred |
| Blocking defects | Pending final defect review |
| Deciding project owner | Pending recorded decision |
| Decision timestamp | Pending |
| Release commit | Selected by the annotated tag; never self-embedded |
| Annotated tag | Selected externally after committed evidence validates; never self-embedded |

No other section of this skeleton constitutes the project-owner release
decision.
