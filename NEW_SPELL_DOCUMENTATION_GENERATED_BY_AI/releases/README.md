# SPELL Release Records

This directory is the canonical location for version-specific SPELL planning,
gate, implementation, and release records. Cross-version project records such
as `PROJECT_ROADMAP.md`, `VERSION_TIMELINE.md`, `Test_and_Integration.md`, and
`PROVENANCE.md` remain at the repository root.

| Version | Planning And Gates | Implementation And Release |
| --- | --- | --- |
| v0.1 | [Pre-Implementation](SPELL_v0.1_Pre-Implementation.md) | Not recorded separately |
| v0.2 | Not recorded separately | [Release](SPELL_v0.2_Release.md) |
| v0.3 | [Pre-Implementation](SPELL_v0.3_Pre-Implementation.md) | [Release](SPELL_v0.3_Release.md) |
| v0.4 | [Pre-Implementation](SPELL_v0.4_Pre-Implementation.md) | [Release](SPELL_v0.4_Release.md) |
| v0.5 | [Pre-Implementation](SPELL_v0.5_Pre-Implementation.md), [Gate 0B](SPELL_v0.5_Gate_0B.md) | [Release](SPELL_v0.5_Release.md) |
| v0.6 | [Pre-Implementation](SPELL_v0.6_Pre-Implementation.md), [Gate 0B](SPELL_v0.6_Gate_0B.md) | [Release](SPELL_v0.6_Release.md) |
| v0.7 | [Pre-Implementation](SPELL_v0.7_Pre-Implementation.md), [Gate 0B](SPELL_v0.7_Gate_0B.md) | [Release](SPELL_v0.7_Release.md) |
| v0.8 | [Pre-Implementation](SPELL_v0.8_Pre-Implementation.md), [Gate 0B](SPELL_v0.8_Gate_0B.md) | [Release](SPELL_v0.8_Release.md) |
| v0.9 | [Pre-Implementation](SPELL_v0.9_Pre-Implementation.md), [Gate 0B](SPELL_v0.9_Gate_0B.md) | [Release](SPELL_v0.9_Release.md) |
| v0.10 | Release policy in `contracts/v10/release_policy.json` | [Implementation and accepted release record](SPELL_v0.10_Implementation.md); accepted at `v0.10.0` |
| v0.11 | [Pre-Implementation](SPELL_v0.11_Pre-Implementation.md), release policy in `contracts/v11/release_policy.json` | [Implementation and accepted release record](SPELL_v0.11_Implementation.md); accepted at `v0.11.0` |
| v0.11.1 | [Pre-Implementation](SPELL_v0.11.1_Pre-Implementation.md) | [Documentation maintenance](SPELL_v0.11.1_Release.md); runtime remains v0.11.0 |
| v0.12 | [Pre-Implementation](SPELL_v0.12_Pre-Implementation.md) | [Implementation and release](SPELL_v0.12_Implementation.md); local synthetic replay profile |
| v0.13 | [Pre-Implementation](SPELL_v0.13_Pre-Implementation.md) | [Accepted `v0.13.0`](SPELL_v0.13_Implementation.md); fenced synthetic procedure control |
| v0.14 | [Pre-Implementation](SPELL_v0.14_Pre-Implementation.md) | [Accepted `v0.14.0`](SPELL_v0.14_Implementation.md); bounded read-only `GetTM` adapter |
| v0.15 | [Pre-Implementation](SPELL_v0.15_Pre-Implementation.md) | [Accepted `v0.15.0`](SPELL_v0.15_Implementation.md); local shadow-pilot review and recovery |
| v0.16 | [Pre-Implementation](SPELL_v0.16_Pre-Implementation.md) | [Implementation and qualification](SPELL_v0.16_Implementation.md); language coverage, compact manual workspace and automatic local sessions |

**v0.16.0** is in implementation and qualification; **v0.15.0** remains the
accepted predecessor. The
[console guide](../../frontend/README.md) describes its operator workflows.
These local synthetic releases do not establish full SPELL 2.4.4 language
compatibility, real legacy-system qualification, or operational authorization.

The accepted release status and immutable tag identities remain authoritative
in the individual records and in the root `VERSION_TIMELINE.md`. Moving these
working-tree documents does not alter paths stored in historical Git tags,
signed evidence, or hash manifests.
