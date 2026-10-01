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
