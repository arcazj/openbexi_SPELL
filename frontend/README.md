# SPELL v0.15 Operations Console

React and strict TypeScript console for the accepted OpenBEXI SPELL v0.15.0
local synthetic simulator. It includes procedure execution, Data Service,
the separate development workspace, and the control, telemetry, and pilot
workflows described below. The console uses Redux Toolkit, native WebSocket
reconnect and resynchronization, ECharts, and Lucide icons.

The [root quick start](../README.md#quick-start) covers the complete local
stack. The [release index](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md)
links the accepted scope and evidence for each version. Full SPELL 2.4.4
language compatibility and real legacy-system qualification remain outstanding.

## Local Access And Development

The normal deployment is built and served by the loopback reverse proxy at
`http://127.0.0.1:8080`. The development workspace is at
`http://127.0.0.1:8080/development.html`; it provides project resources,
semantic checks, history, immutable bundles, review, and simulator promotion.

For frontend development, run these commands from `frontend/`:

```powershell
npm ci
npm run dev -- --host 127.0.0.1
```

Vite serves `http://127.0.0.1:5173` and proxies `/api` and WebSocket traffic to
the Compose proxy. Use the repository's pinned toolchain for release work.

Generate a short-lived signed token using the root quick start, then enter it
in the session-access form. The token is held in browser session storage and
is not compiled into the frontend. The server rechecks JWT expiry after a
WebSocket is established and closes an expired connection with code `4401`.
Logout closes the socket and erases the token; a `4401` close also erases it
and returns the console to session access.

## Compatibility Control

The v0.13 **Compatibility control** panel acts on the selected execution using
the existing controller lease. An operator or administrator supplies a reason
for a supported control action. The server checks the execution revision,
lease revision, fencing token, actor, and stable operation identity.

Use **Return to read-only** to request a stop and inspect the recorded outcome.
A pending rollback is not complete until the execution reaches its confirmed
stop state. If a response is lost, use **Refresh operation** or **Retry same
operation** to resolve the original operation; do not assume that a missing
response means no action occurred. The panel controls only the bounded
simulator procedure profile.

The [v0.13 implementation record](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.13_Implementation.md)
and [control profile](../contracts/v13/control_profile.json) define the supported
commands, IR versions, and failure cases.

## Telemetry Adapter

Open **Driver foundation** and use **Telemetry adapter**:

1. Choose **Reference capture** (`reference`) or **Simulator fallback**
   (`simulator`), an item, and `RAW` or `ENG` format. Enable **Extended metadata**
   when quality and source details are needed.
2. Use **Read current** for the current recorded value, or **Read next recorded
   sample** to advance from the recorded cursor. Waiting uses the logical
   recorded clock within the adapter timeout; it is not a live telemetry feed.
3. Use **Compare both sources** to inspect classification, quality, and values.
   A non-good sample is not treated as an equivalent valid value.
4. Select **Simulator fallback** explicitly when falling back, and use
   **Refresh adapter catalog** to refresh available items.

This v0.14 profile provides authenticated, read-only `GetTM` access. Unsupported
modifiers are rejected, and each request selects its source explicitly. See
the [telemetry profile](../contracts/v14/telemetry_profile.json) and
[v0.14 release record](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.14_Implementation.md).

## Shadow Pilot Readiness

Under **Driver foundation**, the v0.15 **Shadow pilot readiness** panel records
local comparisons and recovery evidence:

1. As an operator or administrator, enter one to eight unique catalog item
   names separated by commas, one to four repetitions, a value format, and a
   reason. Select **Run read-only shadow**. The available catalog can contain
   fewer than eight items.
2. Inspect **Recent shadow runs** and **Differential trace and audit**. Use
   **Refresh shadow reports** to obtain current server state.
3. A different administrator can **Record independent review** only when all
   comparisons are equivalent and within the declared budgets. The creator
   cannot review their own run. Review records local readiness; it grants no
   operational authority.
4. The owner or an administrator can **Record incident** and **Roll back to
   simulator**. A new run is needed to establish readiness after rollback.
5. Use **Prepare backup** for the selected report. In **Backup and restore
   drill**, an administrator can paste the backup JSON and **Restore as
   read-only**. The input limit is 256 KiB. The restored report is a new
   `RESTORED_READ_ONLY` record; prior review and authority are not restored.
   Imported history is untrusted provenance, and the digest checks integrity
   rather than authenticating its author.

If a run response is uncertain, use **Read recorded pilot run** or **Retry same
pilot request**. The exact pending request identity survives a page reload in
session storage, allowing a retry without creating a replacement request.

All pilot reports remain read-only. This backup workflow covers pilot reports;
it does not restore the complete database or qualify disaster recovery. The
[pilot profile](../contracts/v15/pilot_profile.json) and
[v0.15 implementation record](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.15_Implementation.md)
define roles, bounds, state transitions, and the accepted local scope.

## Frontend Verification

Run from `frontend/`:

```powershell
npm test
npm run build
npm run test:e2e
```

The mocked browser suite runs without a backend. Real integration requires a
fresh local Compose stack, `SPELL_REAL_BACKEND=1`, `SPELL_E2E_BASE_URL` set to
its loopback proxy URL, and `SPELL_E2E_TOKEN` containing a valid signed operator
or administrator JWT. The v0.15 pilot test also requires
`SPELL_E2E_REVIEW_TOKEN`, a valid administrator JWT for a different subject.
Supply these credentials privately; do not commit them or place them in test
evidence. The canonical qualification producer issues short-lived test
identities for these roles.

Accepted v0.15 evidence includes 128 frontend tests and 10 real-browser cases
across desktop and mobile projects, including keyboard and accessibility
checks. Frontend checks alone do not qualify a release. Use the
[root release qualification instructions](../README.md#release-qualification)
and the clean annotated tag for complete validation. Historical v0.4-v0.12
tools and evidence remain specific to those releases.
