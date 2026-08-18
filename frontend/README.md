# SPELL v0.8 Operations Console Candidate Preparation

React and strict TypeScript real-time 2D console for the bounded OpenBEXI SPELL
local synthetic non-CUI simulator. SPELL v0.7.0 is the accepted product
baseline at annotated tag `v0.7.0`, tag object
`70e4d46a46d158dee3c63ec37a5d1922b3b61668`, and release commit
`cf18e9d887ba0476cbcc3d8194e321332a3ae864`.

The latest implemented worktree increment is v0.8 Data and Local Service
Compatibility. It preserves the authenticated simulator-driver projection,
operator workspace, and read-only observation surface while adding the bounded
Data Service workspace for revisioned catalogs, dictionaries, containers,
shared data, and virtual-root files. Browser driver mutations, direct
browser-to-driver access, generic database access, host-filesystem access, and
unrestricted data mutation remain outside scope.

Frontend unit tests and the production build passed during pre-candidate
verification. Source freeze, canonical candidate and browser qualification,
Gate 0B, Final qualification, packaging, the release commit, and annotated tag
`v0.8.0` remain pending. v0.9 has been requested but is not gated or
implemented.

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
commands document the historical v0.4 workflow only. The current v0.8 evidence
chain is owned by `scripts/qualify_candidate_v08.ps1`,
`scripts/qualify_release_v08.ps1`, and the v0.8 validators. Successful frontend
tests alone do not qualify or accept v0.8 and do not establish an operational or
compliance claim.
