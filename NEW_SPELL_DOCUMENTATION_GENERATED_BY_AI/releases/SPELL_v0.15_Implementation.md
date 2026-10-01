# SPELL v0.15 Local Shadow-Pilot Readiness

The **Driver foundation → Shadow pilot readiness** workspace runs bounded
synthetic comparisons and retains every source-bound differential result,
workload measurement, owner, operation UUID, reason and state revision.
Successful comparisons can receive a local review record from a different
authenticated administrator. This software workflow is not independent human
acceptance and grants no operational permission.

Incidents revoke readiness and retain a simulator/read-only disposition.
Rollback is explicit and audited; a reviewed, incident or restored run cannot
silently start another run. Unconfirmed requests retain their exact identity
across reload and support authoritative readback or an explicit identical retry.
Long report identities and audit text wrap within the mobile workspace; the
browser gate checks the report hash directly for horizontal clipping.

Backup export returns bounded data-only JSON with a canonical digest. Restore
checks report hashes, source identities, every differential trace and declared
budgets, then creates a new `RESTORED_READ_ONLY` record. Imported history is
marked untrusted provenance. A digest is an integrity check, not a signature.
Restored approval is never authoritative, and a fresh run and separate review
are required. The drill recovers engineering reports; it does not claim
production database disaster recovery or availability guarantees.

Migration `0010_shadow_pilot` adds immutable report and operation-ledger tables.
Fresh/prior/repeated/failed upgrade tests cover SQLite and PostgreSQL. The
candidate gate executes the network-disabled feature matrix; its two declared
PostgreSQL-only migration cases execute in the mandatory Final PostgreSQL suite.
Audit revisions are unique per run and determine event order even when the wall
clock moves backward. Report and ledger readback use one consistent database
snapshot so concurrent actions cannot mix revisions in an exported backup.

See [the entry gate](SPELL_v0.15_Pre-Implementation.md) for exact capability,
capacity and review boundaries. Release acceptance requires committed raw
evidence and independent validation of annotated v0.15.0. A real legacy pilot,
organizational approval, production deployment and full SPELL 2.4.4 language
support remain separate outstanding work.

## Accepted Release Binding

Accepted 2026-10-01 after independent clean-tag validation. Annotated tag object
`8c72974f6a0a5deee766d6358fb219b73eab91ef` peels to release commit `b7bceaf2489156271c91a939d897d040caeb0be1`.
Qualified source: `fe33fafd6fdd46ae84d1817aba54131afbb3d6fe`; source fingerprint:
`5deba7feda167affc5f2f0777b736ea0975714db936f7b6891eab9d03030aa59`. Package SHA-256:
`b6eb564d5ae62f451bec50956a81ec31727811bafa84f1626d9f9331bbf7679b` (751 packaged files).

| Gate | Cases | Passed | Environment skips |
| --- | ---: | ---: | ---: |
| browser | 10 | 10 | 0 |
| compose | 3 | 3 | 0 |
| documentation | 18 | 18 | 0 |
| frontend | 128 | 128 | 0 |
| postgresql | 1730 | 1727 | 3 |
| sqlite | 1812 | 1791 | 21 |
| tooling | 55 | 55 | 0 |

The adapter soak completed 8,545 batches of 8 reads in 60.001 seconds, with every batch below 500 ms.

The shadow-pilot soak completed 59 full review, incident, rollback and restore drills in 60.062 seconds, retaining 118 runs and 295 audit events. Every drill completed below 10 seconds.

Initial local preparation stopped because Docker's default network address pools were exhausted. Removing the stopped v0.13 and v0.14 project containers and networks freed capacity; their data volumes were preserved. Preparation then passed without a source change. The failed local setup logs were retained separately from accepted evidence.

Visual review of the initial browser captures found a clipped mobile report hash despite passing page-level checks. That [candidate was retained](../../artifacts/v0.15-candidate-history/ea2b5b2/gate-0b.json), text wrapping was corrected, and the browser gate gained a direct hash-overflow check. Candidate and Final qualification were rerun from the new frozen source; earlier captures do not satisfy this release.

All 24 environment skips were resolved by the exact complementary suites.
Frontend production build, all 195 reference examples and 257 variants, the
60-second replay soak, image isolation and contract probes, four strict SBOMs,
Python/npm audits and independent deterministic packaging passed. The raw GCC
header advisory remains visible with its evidence-bound NOT_AFFECTED resolution;
there are no unresolved Critical/High findings. Lower severities have recorded
review deadlines. No exceptions were accepted.

Raw evidence and package bindings are in [the version artifacts](../../artifacts/v0.15/qualification.json)
and [reproducibility proof](../../artifacts/v0.15/reproducibility.json).
Reproduce strict validation on the clean `v0.15.0` checkout with
`scripts/release_next.py validate --require-tag`. The retained evidence qualifies
only the declared local synthetic profile; a release tag grants no operational
authority, real legacy environment acceptance or full language compatibility.
