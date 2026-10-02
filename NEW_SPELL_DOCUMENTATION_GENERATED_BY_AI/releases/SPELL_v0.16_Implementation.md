# SPELL v0.16 Language Coverage And Manual Workspace

Accepted at annotated `v0.16.0` on 2026-10-01 after independent clean-tag
validation. The [approved entry gate](SPELL_v0.16_Pre-Implementation.md)
defines the local simulator scope; the accepted predecessor is v0.15.0.

## Release Scope

- A compact workspace based on the original GUI User Manual: Navigation and
  utility views, central Master/procedure tabs, source Code/Data/Result rows,
  execution controls, prompts and logs.
- Automatic finite local operator sessions at `http://127.0.0.1:8080/`, with
  reload, renewal and reconnection handling and no manual token-entry screen.
- Complete Language Reference inventory, explicit coverage gaps, direct source
  conformance cases and individual/all-suite choices in
  `procedures/language_reference_244.spell.py`.
- Concise current user instructions and version-specific release evidence.

The language inventory contains 763 artifacts: 195 adapted examples, 59 partial
entries and 509 gaps. The runner offers 195 individual adaptations, 32 direct
or rejection checks, and an all-suite choice. The 32 checks comprise 16 direct
cases and 16 expected parser rejections; the adaptations retain 257 variants.
These counts describe different forms of evidence and must not be combined
into a language support percentage.

New direct syntax covers top-level fixed scalar inference and `Display` with
default, positional or keyword severity. A bounded IR 0.16 selection executes
the fixed registry in seven instructions; its case hash, result bounds and
checkpoint recovery are validated. Older IR versions retain their contracts.
The release producer independently compares the direct cases with isolated
worker results. Dynamic types, collections, unrestricted Python and unqualified
service/default combinations remain gaps; 20 default combinations are unqualified.

The automatic local profile grants only operator access. It renews finite
credentials while retaining the local browser identity and controller binding;
administrator review still requires a separately authorized identity. The
bootstrap requires the loopback proxy origin and is disabled by default outside
the Compose simulator profile.

The coverage inventory and successful semantic adaptations do not establish
full SPELL 2.4.4 compatibility. Unsupported behavior must remain visible in
coverage and execution results. The simulator has no live GCS or spacecraft
connection and no operational authorization.

## Accepted Release Binding

The annotated tag was created at **2026-10-01 23:15:47 EDT**
(`America/New_York`). Master and the tag were pushed and verified remotely.
The [GitHub release](https://github.com/arcazj/openbexi_SPELL/releases/tag/v0.16.0)
was published at 23:18:03 EDT with four verified assets; the downloaded package
matches the digest below.

| Binding | Accepted value |
| --- | --- |
| Scope | `LOCAL_SIMULATOR_LANGUAGE_AND_MANUAL_WORKSPACE` |
| Annotated tag object | `d28022996f9b5d6216c15c289024905cb1a21f38` |
| Release commit | `1b0aa8e582cb13b9d6aa5196fd66fc56d9d3ad10` |
| Qualified source | `f9bb4defc6fef0a6034c5783c1bef107162d24e1` |
| Source fingerprint | `ccc1cdf5097208a9ed1635b4dff1562d022ff900fa1f75008fd11fe473fcc76f` |
| Package SHA-256 | `91624bc7eb64901f7d7637df0029a488e6e7d34d21e209244396ec0b7bd2c6fc` |
| Qualification SHA-256 | `cc22286bc264e74f9eafcbe3cca33c517caf221b07566fd699cdbc77d2169620` |
| Package / exceptions | 777 files; no accepted exceptions |

| Final gate | Cases | Passed | Environment skips |
| --- | ---: | ---: | ---: |
| Browser | 18 | 18 | 0 |
| Compose | 3 | 3 | 0 |
| Documentation | 18 | 18 | 0 |
| Frontend | 146 | 146 | 0 |
| PostgreSQL | 1,826 | 1,823 | 3 |
| SQLite | 1,908 | 1,887 | 21 |
| Tooling | 81 | 81 | 0 |
| **Total executions** | **4,000** | **3,976** | **24** |

All 24 environment skips were resolved by the exact complementary PostgreSQL
and Compose suites. The candidate gate separately passed 159 cases. All 32
language checks and 195 adaptations/257 variants passed; the language report
correctly retains `full_compatibility: false`. Desktop/mobile browser evidence
covers the compact manual workspace, automatic sessions and recovery.

The replay soak completed 93,401 iterations in 60 seconds. The adapter soak
completed 8,631 batches of eight reads in 60.007 seconds (maximum 10.537 ms,
budget 500 ms). The pilot soak completed 60 review, incident, rollback and
restore drills in 60.827 seconds, retaining 120 runs and 300 events; every drill
met its 10-second budget.

The frontend production build, image isolation/contract probes, four strict
SBOMs and Python/npm audits passed. No unresolved Critical/High finding remains;
the raw GCC-header advisory retains its evidence-bound `NOT_AFFECTED` resolution,
and lower severities have recorded review deadlines. Four package builds across
two independent exports produced identical bytes.

See the [release manifest](../../artifacts/v0.16/release-manifest.json),
[qualification and raw evidence](../../artifacts/v0.16/qualification.json), and
[reproducibility proof](../../artifacts/v0.16/reproducibility.json).
Strict validation on a clean `v0.16.0` checkout is
`python -m scripts.release_next validate --require-tag`.

## Corrections Before Acceptance

The first candidate passed focused and browser checks, but image auditing found
`CVE-2026-103111` in proxy PCRE2 10.48. It was not released. Pinning PCRE2
10.49-r0 removed the advisory without an exception.

The next PostgreSQL run exposed a test scheduling race: a 100 ms broker request
could expire before its worker entered the build. The test now advances a shared
clock after worker entry and always releases and joins the worker. The deadline,
error and late-output cleanup assertions were preserved. Failed captures remain
in ignored local `.qualification/v16/attempt-*` directories, separate from the
published release evidence. The revised source passed fresh candidate and complete
Final qualification before acceptance.
