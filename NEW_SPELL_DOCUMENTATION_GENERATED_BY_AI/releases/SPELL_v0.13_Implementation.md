# SPELL v0.13 Local Procedure Control

The v0.13 profile adapts Run, Step, Pause, Abort and Return to read-only to the
existing simulator supervisor. Operations retain their UUID, source digest,
actor, reason, revision and controller proof in the durable command ledger.
Readback returns the authoritative command outcome after reconnect. Returning
to read-only requests a safe stop and remains pending until settlement.

The console's **Compatibility control** panel uses the selected execution and
its existing controller lease. A missing or expired lease, disconnected stream,
stale revision, wrong source or unsupported operation prevents control.

See [the entry gate](SPELL_v0.13_Pre-Implementation.md) for source references,
scope and the failure matrix. Real legacy-system qualification and full SPELL
2.4.4 compatibility are not claimed. Acceptance is determined by committed
evidence under `artifacts/v0.13` and strict annotated-tag validation on the
clean `v0.13.0` checkout, not by this source-freeze record.
