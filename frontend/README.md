# SPELL Operations Console

React and TypeScript operator console for the SPELL v0.2 simulator-only vertical slice. The frontend uses Redux Toolkit for authoritative UI state, native WebSocket reconnect/resynchronization, ECharts for numeric telemetry, and Lucide icons.

The console is not approved for live spacecraft or Ground Control System operations.

## Run

The backend is expected on `http://127.0.0.1:8000`; Vite proxies `/api` and WebSocket traffic.

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Verify

```powershell
npm run build
npm test
npx playwright install chromium
npm run test:e2e
```

The default Playwright matrix runs the initial console at desktop and mobile viewports and fails on serious or critical accessibility findings.

With the simulator backend running, execute the real REST and WebSocket workflow:

```powershell
$env:SPELL_REAL_BACKEND = "1"
npx playwright test e2e/integration.spec.ts --project=chromium
```

Set `VITE_SPELL_TOKEN` only when the simulator backend uses a development token other than `spell-dev-token`.
