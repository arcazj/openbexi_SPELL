# SPELL v0.13 Local Procedure Control

The v0.13 profile adapts Run, Step, Pause, Abort and Return to read-only to the
existing simulator supervisor. Operations retain their UUID, source digest,
actor, reason, revision and controller proof in the durable command ledger.
Readback returns the authoritative command outcome after reconnect. Returning
to read-only requests a safe stop and remains pending until settlement.

Real-worker qualification found that the existing operator projection omitted
the worker's `waiting` state and displayed it as `ERROR`. The release maps that
state to `WAITING`, preserving the documented pause/abort controls. Regression
tests verify the projection and exercise real worker settlement. Only fenced
IR profiles 0.6, 0.7, 0.8, 0.10 and 0.11 are admitted by the new facade.

The backend image includes the control profile and the image probe loads it
from the actual runtime filesystem. The fresh GCC source-package advisory is
resolved through [component applicability evidence](GCC_CVE-2026-102010_Applicability.md);
the unmodified scan and exact runtime file inventory remain in release evidence.

The console's **Compatibility control** panel uses the selected execution and
its existing controller lease. A missing or expired lease, disconnected stream,
stale revision, wrong source or unsupported operation prevents control.

See [the entry gate](SPELL_v0.13_Pre-Implementation.md) for source references,
scope and the failure matrix. Real legacy-system qualification and full SPELL
2.4.4 compatibility are not claimed. Acceptance is determined by committed
evidence under `artifacts/v0.13` and strict annotated-tag validation on the
clean `v0.13.0` checkout, not by this source-freeze record.

## Accepted Release Binding

Accepted 2026-10-01 after independent clean-tag validation. Annotated tag object
`9f982937fc81e6d18e34b7a55ca228f346ad610a` peels to release commit `9bcb55e665a663a9fcb58a1c1d29936837731fe3`.
Qualified source: `0f85a4a8efb86edb3625b66c31de9762db0f63c9`; source fingerprint:
`2597f4f7fe4ff19a1c4afea6e95f98dcaf159645de4621a625b1337877d864ef`. Package SHA-256:
`ba415fc5fdda5d9754ae961a7f11255d654927e11bdd767c5c2d5563eb1dad8a` (730 packaged files).

| Gate | Cases | Passed | Environment skips |
| --- | ---: | ---: | ---: |
| browser | 6 | 6 | 0 |
| compose | 3 | 3 | 0 |
| documentation | 18 | 18 | 0 |
| frontend | 119 | 119 | 0 |
| postgresql | 1648 | 1645 | 3 |
| sqlite | 1730 | 1711 | 19 |
| tooling | 42 | 42 | 0 |

All 22 environment skips were resolved by the exact complementary suites.
Frontend production build, all 195 reference examples and 257 variants, the
60-second replay soak, image isolation and contract probes, four strict SBOMs,
Python/npm audits and independent deterministic packaging passed. The raw GCC
header advisory remains visible with its evidence-bound NOT_AFFECTED resolution;
there are no unresolved Critical/High findings. Lower severities have recorded
review deadlines. No exceptions were accepted.

Raw evidence and package bindings are in [the version artifacts](../../artifacts/v0.13/qualification.json)
and [reproducibility proof](../../artifacts/v0.13/reproducibility.json).
Reproduce strict validation on the clean `v0.13.0` checkout with
`scripts/release_next.py validate --require-tag`. The retained evidence qualifies
only the declared local synthetic profile; a release tag grants no operational
authority, real legacy environment acceptance or full language compatibility.
