# SPELL v0.14 Read-Only Telemetry Adapter

The local synthetic telemetry capability provides current and next GetTM reads,
RAW/ENG selection, immutable extended metadata, typed failure outcomes and a
full two-source differential trace. It reads the pinned v0.12 reference and
simulator fixtures; no network or mutation service is introduced.

Open **Driver foundation → Telemetry adapter** to inspect current or next
recorded samples, compare both sources, or explicitly select the simulator
fallback. UInt64 values remain decimal strings. Failure clears the previous
value, and switching source discards its cursor and late responses. Recorded
time and synthetic provenance remain visible; Timeout never implies waiting on
a live system. The profile is loaded from each built backend image during
qualification.

See [the entry gate](SPELL_v0.14_Pre-Implementation.md) for the exact modifier,
capacity, safety and compatibility decisions. The new REST capability is a
bounded adapter tranche; it does not expand procedure parser support or claim
full SPELL 2.4.4 language/driver compatibility. Real legacy-system and
operational qualification remain outstanding. Acceptance requires the
annotated v0.14.0 tag and its source-bound evidence, not this implementation
record alone.

## Accepted Release Binding

Accepted 2026-10-01 after independent clean-tag validation. Annotated tag object
`c3f5b8ec7ec01cf4e89e9b49c63bbb40412b1dad` peels to release commit `4adec1be10eae1aa4fac0293db47e7bbf692b243`.
Qualified source: `4951cad2d9948135411c1de1a45a840ed1672ef0`; source fingerprint:
`e9f486731dde22760b4b2080577d4cc7f812c12bc0aaee0ca6018c689c0dc987`. Package SHA-256:
`4a617e920f6266928d8c6c98e448cbee8e32f5a71ae12cd41329b9484c69cbaa` (740 packaged files).

| Gate | Cases | Passed | Environment skips |
| --- | ---: | ---: | ---: |
| browser | 8 | 8 | 0 |
| compose | 3 | 3 | 0 |
| documentation | 18 | 18 | 0 |
| frontend | 124 | 124 | 0 |
| postgresql | 1684 | 1681 | 3 |
| sqlite | 1766 | 1747 | 19 |
| tooling | 49 | 49 | 0 |

The adapter soak completed 8,558 batches of 8 reads in 60.006 seconds, with every batch below 500 ms.

All 22 environment skips were resolved by the exact complementary suites.
Frontend production build, all 195 reference examples and 257 variants, the
60-second replay soak, image isolation and contract probes, four strict SBOMs,
Python/npm audits and independent deterministic packaging passed. The raw GCC
header advisory remains visible with its evidence-bound NOT_AFFECTED resolution;
there are no unresolved Critical/High findings. Lower severities have recorded
review deadlines. No exceptions were accepted.

Raw evidence and package bindings are in [the version artifacts](../../artifacts/v0.14/qualification.json)
and [reproducibility proof](../../artifacts/v0.14/reproducibility.json).
Reproduce strict validation on the clean `v0.14.0` checkout with
`scripts/release_next.py validate --require-tag`. The retained evidence qualifies
only the declared local synthetic profile; a release tag grants no operational
authority, real legacy environment acceptance or full language compatibility.
