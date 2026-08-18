# SPELL v0.8 Operations Console

React and strict TypeScript real-time 2D console for the bounded OpenBEXI SPELL
local synthetic non-CUI simulator. SPELL v0.8.0 is the accepted product
baseline at annotated tag `v0.8.0`, tag object
`0dcf4f539fd1a9036fe4db4bc159cde04c35cfae`, and release commit
`d6e01222de3bf52013279e48a099b6ae7ded121d`.

The accepted v0.8 Data and Local Service Compatibility increment preserves the
authenticated simulator-driver projection,
operator workspace, and read-only observation surface while adding the bounded
Data Service workspace for revisioned catalogs, dictionaries, containers,
shared data, and virtual-root files. Browser driver mutations, direct
browser-to-driver access, generic database access, host-filesystem access, and
unrestricted data mutation remain outside scope.

Canonical candidate and Final frontend unit, production-build, mocked-browser,
and real-browser evidence passed as part of accepted v0.8.0. `V09-GATE-0A
PASS` authorizes a separate local development-environment web surface under
`V09-DEV-001` through `V09-DEV-009`; that surface is not yet implemented or
qualified and is not part of the accepted v0.8 console.

The console uses Redux Toolkit for authoritative UI state, native WebSocket
reconnect and resynchronization, ECharts for numeric telemetry, and Lucide
icons.

The normal deployment is built and served by the loopback reverse proxy at
`http://127.0.0.1:8080`. For frontend development, Vite runs on
`http://127.0.0.1:5173` and proxies `/api` and WebSocket traffic to that proxy.

```powershell
npm ci
npm run dev -- --host 127.0.0.1
```

Generate a short-lived signed token with `scripts/issue_dev_token.py`, then
enter it in the console session-access form. The token is held only in browser
session storage and is not compiled into the frontend. The server rechecks JWT
expiry after a WebSocket is established and closes an expired connection with
code `4401`. Logout closes the socket and erases the token; a `4401` close also
erases it and returns the console to session access.

```powershell
npm test
npm run build
npm run test:e2e
```

The mocked browser suite runs without a backend. Real integration requires the
local Compose stack plus `SPELL_REAL_BACKEND=1`, `SPELL_E2E_BASE_URL` set to its
loopback proxy URL, and `SPELL_E2E_TOKEN` set to a currently valid signed JWT.

The retained `python scripts/qualify_v04.py plan` and associated Gate 1-5
commands document the historical v0.4 workflow only. The accepted v0.8 evidence
chain is owned by `scripts/qualify_candidate_v08.ps1`,
`scripts/qualify_release_v08.ps1`, and the v0.8 validators. The reserved v0.9
candidate and release tool names in `PROMPT_Instructions.md` describe a future
required flow and are not implemented evidence. Successful frontend tests alone
do not qualify or accept v0.9 and do not establish an operational or compliance
claim.
