# OpenBEXI SPELL

OpenBEXI SPELL is a local simulator for developing and executing bounded
satellite procedures, with a Python control plane, isolated workers,
PostgreSQL storage and a compact web operator workspace.

**v0.19.0 implementation is in qualification** for bounded observation-to-command workflows. The [v0.19 record](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.19_Implementation.md) describes the new behavior and limits. v0.18.0 remains the accepted predecessor until all release gates pass.

Every document under `SPELL_DOCUMENTATION/` is a required source reference for
future SPELL work. Derived specifications cannot silently replace its behavior.
The simulator has no live GCS or spacecraft connection and no operational
approval. Full SPELL Language Reference 2.4.4 compatibility is not claimed.

## Quick Start

Install Git and Docker with Compose v2, then run:

```powershell
git clone https://github.com/arcazj/openbexi_SPELL.git
Set-Location openbexi_SPELL
Copy-Item .env.example .env
```

Set private local values in `.env`:

```dotenv
SPELL_DB_PASSWORD=<URL-safe-random-value>
SPELL_JWT_HS256_SECRET=<at-least-32-random-bytes>
SPELL_DRIVER_ENABLED=true
```

Start the stack and check health:

```powershell
docker compose --profile driver up --build -d --wait
docker compose --profile driver exec -T backend python /app/scripts/seed_observation_v07.py `
  --confirm LOCAL_SYNTHETIC_NON_CUI_ONLY --context-id simulator
Invoke-RestMethod http://127.0.0.1:8080/api/v1/health
```

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/). The local profile connects
as a simulator operator automatically; no Session access screen or pasted token
is needed. Health reports `0.19.0`, `simulator-only` and
`operational_use: false`. Keep `.env` private and untracked.

The initialization command opens the real bundled simulator observation context
and waits for committed GOOD/FRESH telemetry. It injects no test samples. Local
session connection alone does not initialize a driver context. This command is
for a fresh local simulator setup; it refuses a context bound to an older host
generation. Use the driver lifecycle/recovery workflow for generation changes.

The [development workspace](http://127.0.0.1:8080/development.html) provides
project editing, checks, history, immutable bundles and simulator promotion.
The [console guide](frontend/README.md) covers the current interface and roles.

Stop the stack while retaining its database volumes:

```powershell
docker compose down
```

## Operator Workspace

The original [GUI User Manual 2.4.4](SPELL_DOCUMENTATION/SPELL%20-%20GUI%20User%20Manual%20-%202.4.4.pdf)
defines the workspace: Navigation and utility views on the left, Master and
procedure tabs in the center, Code/Data/Result source rows, and execution,
prompt and log controls below. Driver and data services remain available as
secondary views. Browser tabs and responsive layouts replace native desktop
window management; unrestricted Python Shell execution is excluded.

Automatic sessions use finite signed operator credentials and a stable local
browser identity. The bootstrap is restricted to the explicitly enabled local
profile and its loopback origin. Backend defaults outside that profile remain
disabled. Administrator permissions are never granted automatically.

## Language Reference Runner

Find **Language Reference 244** (`language_reference_244`) in the catalog and start
[language_reference_244.spell.py](procedures/language_reference_244.spell.py).
Its choices include 195 adapted examples, 112 direct source checks, 36 expected
rejection checks, and **Run all language checks**. The v0.19 additions cover
GetTM/Verify/WaitFor decisions, native prompts and literal simulator commands.
The inventory covers 763 reference entries.

The language inventory distinguishes missing implementation, missing direct
proof and manual conflicts. Bounded passing checks do not establish support for
an entire manual entry. The inherited 195 numbered examples
and 257 variants are independently authored adaptations; they are not proof
that arbitrary manual snippets or Python programs execute unchanged. A correct
rejection of unsupported syntax does not count as language support.

See the [v0.19 scope](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.19_Pre-Implementation.md)
and [language coverage](contracts/v19/language_coverage.json) for exact bounds.

The [procedure guide](procedures/README.md) lists the reference runner, prompt
walkthrough and seven testing procedures with inputs and expected outcomes.

## Architecture

```text
Browser -> loopback proxy -> FastAPI control plane -> PostgreSQL
                                  |        |
                                  |        +-> isolated procedure workers
                                  +----------> networkless bundle builders
Optional driver profile: internal mTLS -> synthetic driver host
```

Only the proxy publishes a loopback port. Backend, database and driver services
stay on internal networks; bundle builders have no network access. There is
no browser-to-driver command path.

## Development

For frontend work, run from `frontend/` while the Compose proxy is available:

```powershell
npm ci
npm run dev -- --host 127.0.0.1
npm test
npm run build
npm run test:e2e
```

See [frontend/README.md](frontend/README.md) for local-origin configuration and
mocked versus real-browser testing. Release work uses the exact tools in
[scripts/release-toolchain-v19.json](scripts/release-toolchain-v19.json).
Python dependencies are hash-locked; see
[backend/requirements.hashes.lock](backend/requirements.hashes.lock).

## Release Qualification

The canonical producer is `scripts.qualify_next`; the validator and packager
are `scripts.release_next`. The active
[release policy](contracts/v19/release_policy.json) freezes exact test identities
and references. Required gates include SQLite/PostgreSQL/Compose regression,
frontend/build/browser checks, language results, documentation rendering,
soaks, image checks, four SBOMs, vulnerability review and four identical package
builds from two independent source exports.

After acceptance, validate a clean checkout of the annotated `v0.19.0` tag:

```powershell
.\scripts\run_release_next.ps1 -Module scripts.release_next `
  -Arguments @('validate', '--require-tag')
```

Later documentation commits have different source fingerprints. Validate the
exact tagged tree, and use each historical release's own policy and evidence.
[Test_and_Integration.md](Test_and_Integration.md) records executed results.

## Documentation And Repository Map

| Topic | Canonical location |
| --- | --- |
| Current operator workflows | [Console guide](frontend/README.md) |
| Scope and remaining work | [Project roadmap](PROJECT_ROADMAP.md) |
| Release history and evidence | [Release index](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md), [timeline](VERSION_TIMELINE.md), [test record](Test_and_Integration.md) |
| Source authority and provenance | [Documentation review](SPELL_DOCUMENTATION_REVIEW.md), [provenance](PROVENANCE.md) |
| Broader Draft design | [Generated specification](NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/README.md) |
| Control plane, runtime, migrations | `backend/`, `spell/` |
| Web interface and browser tests | `frontend/`, `proxy/` |
| Synthetic driver service | `driver_host/` |
| Procedures, contracts and release tools | `procedures/`, `contracts/`, `scripts/` |
| Immutable qualification artifacts | `artifacts/` |
| Original read-only manuals | `SPELL_DOCUMENTATION/` |
| Separate legacy procedure auditor | [tools/README.md](tools/README.md) |

The generated design specification and its Draft GUI manual have their own
approval status. They do not establish product, operational or full-language
acceptance. Original manuals and legacy archives are excluded from product
images and release packages.

## License And Notices

New first-party code is licensed under [Apache License 2.0](LICENSE).
[NOTICE](NOTICE) and [PROVENANCE.md](PROVENANCE.md) describe source and
dependency boundaries. That license does not relicense the original manuals,
legacy source archives or third-party dependencies.
