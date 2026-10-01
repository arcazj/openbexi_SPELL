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
