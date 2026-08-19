# SPELL v0.4 Release Record

## Record Status

This frozen release record captures the complete source-bound Preliminary
qualification of SPELL v0.4.0 Candidate A and the project owner's conditional
acceptance decision. The decision becomes effective only if the unchanged
record passes the complete Final 74/74 qualification and the project owner
creates the annotated `v0.4.0` tag over the fixed release commit.

| Field | Value |
| --- | --- |
| Version | 0.4.0 |
| Release name | Typed Simulator Driver and Context Foundation |
| Accepted baseline | `v0.3.0` (`7bccbb4eb096b22d0d1f2f765d5172f6dde244f1`) |
| Scope profile | Local-only, synthetic non-CUI simulator engineering |
| Candidate source commit | `aadc697f99a0bcad413143883c49d90fe9dce7a2` |
| Qualification source fingerprint | `c5673a16be3ac82f7d5d6c29c197bb144b1769c696727c0a6d60da752e2fb183` |
| Evidence identity | Canonical machine evidence and annotated tag; no self-derived digest is embedded in this packaged record |
| Final archive SHA-256 | External `.sha256` sidecar and annotated tag only; never embedded in this packaged record |
| Decision date | 2026-08-12 |
| Release status | Conditionally accepted; effective only after the frozen-record Final 74/74 validation and annotated `v0.4.0` tag |
| Annotated tag | Selected externally after committed evidence validates; never self-embedded |
| Compliance determination | None claimed |
| Operational authorization | None |

## Candidate Scope

The owner-approved Candidate A scope is defined by
[`SPELL_v0.4_Pre-Implementation.md`](SPELL_v0.4_Pre-Implementation.md) and its
test allocation in [`Test_and_Integration.md`](../../Test_and_Integration.md). The
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

One canonical source-bound Preliminary pass ran from
`2026-08-12T10:09:54.035249Z` through `2026-08-12T10:55:00.255291Z`.
All 74 tests and all 209 assertions passed, with zero failures, skips, errors,
waivers, or open Critical or High findings. These Preliminary results freeze
the record; they are not final acceptance. The unchanged record must pass the
complete Final rerun before the conditional decision can become effective.

| Gate | Evidence path | As-run result | Exceptions or limitations |
| --- | --- | --- | --- |
| Gate 1: contract, configuration, lifecycle, persistence, migration | `artifacts/v0.4/gate-1.json` | PASS; 28/28 tests and 50/50 assertions passed; 0 failed, skipped, or errored | No waiver or gate-specific exception; retained release-wide claim boundaries apply. |
| Gate 2: isolation, identity, faults, recovery, certainty | `artifacts/v0.4/gate-2.json` | PASS; 28/28 tests and 55/55 assertions passed; 0 failed, skipped, or errored | No waiver or gate-specific exception; retained release-wide claim boundaries apply. |
| Gate 3: API, console, accessibility, v0.3 regression | `artifacts/v0.4/gate-3.json` | PASS; 8/8 tests and 39/39 assertions passed; 0 failed, skipped, or errored | No waiver or gate-specific exception; retained release-wide claim boundaries apply. |
| Gate 4: local performance and soak budgets | `artifacts/v0.4/gate-4.json` | PASS; 4/4 tests and 25/25 assertions passed; 0 failed, skipped, or errored | No waiver or gate-specific exception; retained release-wide claim boundaries apply. |
| Gate 5: dependency, SBOM, package, lifecycle, platform | `artifacts/v0.4/gate-5.json` | PASS; 6/6 tests and 40/40 assertions passed; 0 failed, skipped, or errored | No waiver or gate-specific exception; retained release-wide claim boundaries apply. |

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
| Per-test evidence | `artifacts/v0.4/tests/` | PASS; 74 canonical source-bound evidence files; 209/209 assertions passed |
| Backend SBOM | `artifacts/v0.4/sbom/backend.cdx.json` | PASS; 121-component CycloneDX inventory bound to image `sha256:85e78385989195f50c9c6f5a17371fc749175044de956e92b5e5d0853de2a1bd` |
| Driver SBOM | `artifacts/v0.4/sbom/driver.cdx.json` | PASS; 91-component CycloneDX inventory bound to image `sha256:85d8f6ffd513faa520b3c1b2ce8778e5f625f2e58777fc8ed542fb0b237fc2a7` |
| Frontend-build SBOM | `artifacts/v0.4/sbom/frontend.cdx.json` | PASS; 44-component CycloneDX inventory bound to image `sha256:649a51b7d8e05eea917b162d6b8e4ef03d0896fdb920dee1c36f80c02037218a` |
| Proxy SBOM | `artifacts/v0.4/sbom/proxy.cdx.json` | PASS; 65-component CycloneDX inventory bound to image `sha256:918b351353f4100048c91769f2a71afba4a97cf25486a243a9b9316b987d0ce4` |
| SBOM checksum manifest | `artifacts/v0.4/sbom/SHA256SUMS` | PASS; 4/4 distinct image-bound inventories, 321 components, 4/4 strict schema validations, and negative-tamper rejection; file identities recorded in the manifest |
| Source release package | `artifacts/v0.4/openbexi-spell-v0.4.tar.gz` | Preliminary reproducibility PASS: two independent generation builds and two independent package builds were byte-identical; final archive deferred until frozen-record Final qualification |
| External package sidecar | `artifacts/v0.4/openbexi-spell-v0.4.tar.gz.sha256` | Deferred; emitted externally only after the final archive |
| Browser storage inventory | `artifacts/v0.4/browser-storage.json` | PASS; 630 bytes; SHA-256 `12b3976087c090af5833cc8adfc7e627370b48aede785ec9f8a79c7e0a31986b`; local/session storage empty after ephemeral-token removal and service-secret canary matches 0 |
| Desktop browser image | `artifacts/v0.4/driver-projection-desktop.png` | PASS; 1280x720; 81,947 bytes; SHA-256 `3be965394ec1763a5be93e9c390de34699d052c8bda5f9c006a9ccdccb78cfe5` |
| Mobile browser image | `artifacts/v0.4/driver-projection-mobile.png` | PASS; 412x839; 551,118 bytes; SHA-256 `1e30298449fc3cea6f16cc1175dc495f43d9fba2c35439d237ace47e3657b634` |

### Qualification Environment

The canonical Preliminary ran on Microsoft Windows 11 Pro 10.0.26200
(build 26200), 64-bit, on an Intel Core i7-9700 at 3.00 GHz with
34,155,577,344 bytes of visible memory. Host tooling was locked CPython
3.13.14, Windows PowerShell 5.1.26100.8894, Docker Desktop 4.86.0 with
Engine/CLI 29.7.2, and Docker Compose v5.3.1. The exercised container profile
was Linux/amd64 with PostgreSQL 18.4. Browser qualification used Node
v24.13.0, npm 11.6.2, Playwright 1.61.1, and Chromium 149.0.7827.55.
Canonical test records identify `scripts/qualify_v04.py` under both Windows
and Linux with Python 3.13.14.

The source-bound qualification image was
`sha256:53563912a8053855fd153cae686cc835d1de3fd90176d2ee9ee01a98181886ab`.
The four audited product images are the image identities recorded with the
SBOM rows above. The separately audited Compose dependencies were `pki-init`
`sha256:c07ec31348ed08dfaf46e448b86bf9e7d7f1e8412e5e88835e63105d203c61ab`
and PostgreSQL
`sha256:71b1e70b15989da9f27af7741380b6aad4ea45efbbc542ebe899c9e86368d605`.

### Counts, Compatibility, And Safety Measurements

The Preliminary aggregate was 74/74 tests and 209/209 assertions. Regression
qualification passed all 22 accepted-v0.3 semantic suites with zero failures
and zero changed defaults. Accepted-tag coverage comprised 98 Python tests,
13 frontend unit tests, and 8 browser tests. Current-candidate accounting
comprised 72 SQLite, 72 PostgreSQL, 26 tooling, 4 mocked-browser, and 4
real-browser tests.

The scoped telemetry probe accepted one execution and observed one correlated
telemetry event with zero execution, context, binding, operation, or journal
delta. Driver isolation injected pause and kill faults, observed two degraded
projections, and completed two recoveries with zero non-driver liveness,
worker-progress, or recovery failures. Migration qualification exercised two
dialects, one PostgreSQL backup/restore, six truth states, two unsafe rollback
refusals, and one safe rollback; all PostgreSQL, SQLite, and v0.3 snapshot
comparisons matched and duplicate effects remained zero. Recovery exercised
three outage phases and three operation cases; each settled in one journal
attempt with zero duplicate effects, resends, unreconstructable outcomes,
audit/outbox mismatches, or commit/publish violations.

Browser qualification exercised one desktop and one mobile viewport. Axe
Critical and Serious findings were 0/0, as were keyboard and overflow
failures. The retained browser evidence showed only loopback traffic, no
direct driver connection, and no mutation control.

### Performance Measurements And Budgets

| Test | Approved local budget | Preliminary measurement |
| --- | --- | --- |
| `V04-PERF-001` | At least 1,000 samples at 100/s; p95 at most 50 ms; max at most 250 ms | 1,000 samples in 9.516233 s at 105.084/s; p95 3.169 ms; max 5.713 ms; 0 errors |
| `V04-PERF-002` | At least 1,000 operations at 20/s; acceptance p95 at most 250 ms; terminal p95 at most 500 ms | 1,000 operations in 48.735625 s at 20.519/s; acceptance p95 4.000 ms; terminal p95/max 8.703/11.531 ms; 0 duplicates, stuck operations, or errors |
| `V04-PERF-003` | At least 100 cancellations with p95/max at most 500/1,000 ms; at least 25 restarts with readiness and reconciliation max at most 5,000 ms | 100 cancellations and 25 restarts; cancel p95/max 17.094/17.699 ms; readiness max 10.971 ms; reconciliation max 12.708 ms; 0 duplicates, stuck operations, or errors |
| `V04-PERF-004` | At least 600 s and 12,000 operations at 20/s; growth at most 32 MiB; slope at most 2 MiB/min; zero loss, duplicate, stuck, or crash | 12,120 operations in 600.000992 s at 20.2/s; post-warmup growth 1.066 MiB and slope 0.129 MiB/min; 0 loss, duplicate, stuck, crash, error, or residual child process |

These are bounded local engineering measurements, not operational SLOs.

### Supply Chain And Reproducibility

Dependency audit covered 22 locked inputs with zero unlocked inputs, four
audit tools, 91 Python packages, and 232 Node packages. npm audit under Node
v22.23.1 and npm 10.9.8 found zero total vulnerabilities across the 232 Node
packages. All five pip-audit inventories under Python 3.13.14 and pip-audit
2.10.0 had empty vulnerability sets. Docker Scout 1.24.0 returned zero results
for all four product images and both Compose dependency images, and the
Starlette exposure policy reported zero violations. Open Critical and High
findings were 0/0.

The four SBOMs were distinct, licensed, image-bound inventories and all passed
the bundled CycloneDX strict validator, including a negative tamper control.
Inspection covered six images, 56 layers, and 28,371 files across image,
source, and candidate-package inputs. It found zero hardening or layer-scan
failures and zero secret files, PDFs, manual text files, legacy archives,
runtime generators, or runtime journals across the applicable inspected
inputs.

Two independent generation builds and two independent package builds produced
byte-identical outputs in distinct build processes. The Linux/amd64 lifecycle
matrix executed 60 transitions across 15 unique projects: 15 installs, 12
enables, 12 disables, 12 upgrades, 12 rollbacks, and 12 uninstalls, including
10 terminal cases and 50 unsafe refusals, with zero failed cases.

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

Each of the four SBOMs passed the matching bundled CycloneDX JSON schema
through the hash-locked `cyclonedx-python-lib` 11.11.0
`JsonStrictValidator` in a network-none container. The validator accepted its
valid control document and rejected a schema-invalid tampered control document.

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

The accepted boundary remains local synthetic non-CUI use with the
deterministic simulator, a Windows-amd64 host lifecycle controller, and one
Linux/amd64 runtime profile. There is no GCS, spacecraft, mission-network, or
external-command target. The Gate 0 shared-route worker residual risk remains
accepted within this bounded engineering profile. This record makes no
compliance determination and grants no operational authorization.

## Project-Owner Decision

The project owner recorded this conditional decision after the complete
canonical Preliminary validation and before the frozen-record complete Final
rerun and final package publication. It becomes effective only when every
mandatory canonical gate validates in the unchanged Final rerun and the
project owner's annotated `v0.4.0` tag is created over the fixed release
commit. The tag records the exact identities that cannot be embedded here.

| Decision field | As-run value |
| --- | --- |
| Decision | Conditionally accept SPELL v0.4.0 Candidate A for the local synthetic non-CUI simulator engineering scope. |
| Decision basis | Canonical Preliminary qualification for candidate source commit `aadc697f99a0bcad413143883c49d90fe9dce7a2` and qualification source fingerprint `c5673a16be3ac82f7d5d6c29c197bb144b1769c696727c0a6d60da752e2fb183` passed 74/74 tests and 209/209 assertions with zero failures, skips, errors, waivers, open Critical/High findings, or blocking defects; all four image-bound SBOMs passed validation. Acceptance becomes effective only after the frozen-record complete Final rerun passes, the final archive and external sidecar validate, and the annotated `v0.4.0` tag is created. |
| Accepted exceptions | None. |
| Blocking defects | None. |
| Deciding project owner | JC Arcaz |
| Decision timestamp | `2026-08-12T10:57:38.378Z` |
| Release commit | Selected by the annotated tag; never self-embedded |
| Annotated tag | Selected externally after committed evidence validates; never self-embedded |

No acceptance is effective unless the Final validation and annotated-tag
conditions above are satisfied.
