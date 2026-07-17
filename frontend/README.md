# SPELL Operations Console

React and strict TypeScript real-time 2D console for the OpenBEXI SPELL v0.3
simulator. It uses Redux Toolkit for authoritative UI state, native WebSocket
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
local Compose stack plus `SPELL_REAL_BACKEND=1` and `SPELL_E2E_TOKEN` set to a
currently valid signed JWT.

From the repository root, `scripts/qualify_release.ps1` runs the canonical
fingerprint-bound stream gate in two independent Chromium processes, and
`scripts/build_v03.ps1` runs the complete release verification and packaging
workflow.
