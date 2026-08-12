# SPELL v0.4 Candidate Operations Console

React and strict TypeScript real-time 2D console for the bounded OpenBEXI SPELL
v0.4 local-only, synthetic non-CUI simulator candidate. It retains the accepted
v0.3 execution and restricted-IR schema contracts and adds an authenticated,
read-only projection of the bundled simulator driver foundation. Browser driver
mutations and direct browser-to-driver access are outside the v0.4 scope.

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

From the repository root, `python scripts/qualify_v04.py plan` displays the
version-scoped Gate 1-5 catalog. Built-in and environment-bound browser results
are staged with its `run` and `collect` commands, checked with `status`, and only
become canonical v0.4 evidence after `publish` validates the complete shared
source fingerprint. Supply-chain and package commands are documented in
`PROMPT_Instructions.md`; successful frontend tests alone do not accept the
candidate or establish an operational or compliance claim.
