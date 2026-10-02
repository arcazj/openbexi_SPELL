# SPELL v0.16 Language Coverage And Manual Workspace

Status: implementation in progress under the
[approved entry gate](SPELL_v0.16_Pre-Implementation.md). The accepted
predecessor is v0.15.0. This record does not claim release acceptance until its
immutable qualification and annotated-tag bindings are recorded.

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
service/default combinations remain gaps.

The automatic local profile grants only operator access. It renews finite
credentials while retaining the local browser identity and controller binding;
administrator review still requires a separately authorized identity. The
bootstrap requires the loopback proxy origin and is disabled by default outside
the Compose simulator profile.

The coverage inventory and successful semantic adaptations do not establish
full SPELL 2.4.4 compatibility. Unsupported behavior must remain visible in
coverage and execution results. The simulator has no live GCS or spacecraft
connection and no operational authorization.

## Verification

Qualification will bind one frozen source to exact test identities, raw
SQLite/PostgreSQL/Compose results, frontend and browser evidence, complete
language coverage/results, documentation checks, soaks, image/SBOM/audit
evidence and four identical package builds. Actual results and limitations
will be recorded here after execution; no planned check is counted as passed.
