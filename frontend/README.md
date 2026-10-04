# SPELL v0.19 Console

The v0.19 source changes are implemented; release qualification and publication
are pending. See the [current release record](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.19_Implementation.md).

Open `http://127.0.0.1:8080/` to connect directly to the local OpenBEXI SPELL
simulator. No token entry is needed. If the backend is unavailable, use
**Retry connection**; **System > Reconnect simulator** refreshes the connection.
The server retains permissions and finite sessions; the browser renews its local
operator session automatically.

The [root quick start](../README.md#quick-start) starts the complete stack.
[Release records](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/README.md)
identify qualified scope and evidence. This is a simulator, with explicit
remaining language gaps and no operational authorization.

## Console Workspace

The layout follows the original GUI User Manual 2.4.4:

- **Navigation** lists procedures. Select one and press **Enter**, double-click,
  or choose **Start procedure**. **Validate source** checks without starting.
- **Master** lists execution instances. Open an instance to select its procedure
  tab; Master remains available beside it.
- **Tabular** shows numbered source, execution coverage and **Data / Result**.
  Data and Result appear only for explicitly correlated notifications;
  line coverage alone is not success. **Text**, **As-run** and **Support log**
  show committed messages and history.
- **Outline**, **Variables** and **Call stack** occupy the left utility area.
  Outline selects a source line while paused. Variables links to audited typed
  inspection. Call stack shows committed procedure relationships.
- Execution controls and any input prompt appear below source. Controller
  ownership and connection checks remain enforced. Read-only monitors cannot
  command or answer prompts. **Enter command** accepts the listed control names;
  it uses the same button checks and abort confirmation, without evaluating code.
- Click **Telemetry**, **Events**, **Logs**, **Inspect**, **Schedules**,
  **Actions**, **Relations** or **As-run** to expand the lower dock. Its **-**
  button collapses it. **Procedure flow** is an optional disclosure.
- Use arrow keys, Home and End within view tabs; Escape closes application menus.

**System** opens Data services, Driver foundation and the separate
[development workspace](http://127.0.0.1:8080/development.html). **Procedures**
opens or validates a selection and refreshes the catalog. **Execution** returns
to controls or opens prompt settings.

**System > DSS satellite simulator** opens the compact [DSS page](http://127.0.0.1:8080/dss/).
It shows bus/payload/core state and packet-backed telemetry. Pause to step or
review a database command, enter typed arguments and confirm separately.
Commands use the same binary TC ingress as SPELL. An uncertain receipt locks
further UI commands for that scenario; it is never retried automatically.
Telemetry shows raw and engineering values, quality, packet identity and Kafka
publication status. Physical ticks stop while the bounded outbox is full.
Automatic frames integrate ten 100 ms physics steps and publish once per second;
manual steps and command effects publish immediately.

Browser differences are recorded in the [UI profile](../contracts/v16/ui_profile.json):
panes stack on narrow screens, native detached windows are unavailable, and the
unrestricted legacy Python Shell remains excluded. Original manuals are unchanged.

## Testing Procedures

Navigation includes the reference runner, prompt and command examples, and
**Observation Command V19**, **Observation Decision V19** and
**Observation Wait V19**. See the [procedure guide](../procedures/README.md) for
inputs and expected results. A native prompt answer never replaces a required
command confirmation; aborting stops the procedure.

Observation examples require the driver-enabled stack and the explicit simulator
context setup in the [root quick start](../README.md#quick-start). That setup
opens the real local driver context and waits for committed samples; it injects
no values. Automatic browser login alone does not open an observation context.

The observation workflow commits a typed `GetTM` value, a `Verify` result and
a `WaitFor` outcome before asking whether to send. Only an explicit successful
branch can request a command. `FALSE`, native **NO**, **Abort prompt** and a
wait timeout do not send. Values are recorded observations; they are not
automatically read again at command time. Correlated **Data / Result** rows
show the recorded item, value and outcome, including failure outcomes.

For these composed workflows, **Skip** and **Goto** are unavailable. Other
controls follow the server's allowed actions, current connection and control
lease; stale action permissions are cleared while state refreshes.

## Author A Local Workflow

Open **System > Development workspace**, then **Create project**. The default
language profile is `spell-lrm244-conformance/0.19`; choose
`spell-restricted-ast/0.9` explicitly for a legacy project. New procedure headers,
completion, highlighting and snippets follow the selected project profile.
The bounded profile supports native prompts, observations and literal simulator
commands; it does not permit arbitrary Python or full SPELL 2.4.4.

Save, run **Run semantic check**, then **Commit all changes** in **History**.
A different authorized reviewer approves the revision. Build the bundle, obtain
bundle approval and promote it from **Bundles and promotion**. Runtime admission
uses that exact source and bundle digest. Checks do not execute procedures.
Existing project profiles remain unchanged; incompatible older bundles require
rebuilding and renewed review under the current toolchain. See the
[authoring guide](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/procedures/AUTHORING_AND_GIT.md#current-local-v019-authoring).

## Native Language Prompts

Start **Prompt Workflow V17** from Navigation to try the local LIST,
automatic numeric default, text and OK/CANCEL examples.

Native `Prompt` calls provide fixed answers, text, numbers, dates or list
selection. **Reset draft** clears the current input. **CANCEL**, when offered as
an answer, is returned to the procedure; **Abort prompt** stops the native call
and its execution without inventing a result.

A positive `Timeout` with `Default` selects that answer when time expires.
Without `Default`, expiry gives a visible warning and the prompt keeps waiting.
Zero or omitted `Timeout` waits indefinitely. Reconnecting retains the original
deadline. This follows Language Reference section 4.12 where its Appendix B
summary differs. Existing lowercase project prompt options keep their behavior.

NUM returns a finite number; DATE returns validated ISO text in this simulator.
Full legacy date-object compatibility is not claimed. See the
[compatibility guide](../NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/procedures/COMPATIBILITY_AND_MIGRATION.md#v017-direct-language-increment)
for argument and size limits.

## Compatibility Control

Expand **Compatibility control** for the selected execution. Supply a reason,
then use a supported action or **Return to read-only**. A stop request is complete
only after its recorded result confirms it. For an uncertain response, use
**Refresh operation** or **Retry same operation** with the retained identity.
See the [control profile](../contracts/v13/control_profile.json).

## Telemetry Adapter

Under **Driver foundation > Telemetry adapter**, select Reference capture or
Simulator fallback, an item and RAW/ENG. **Read current**, **Read next recorded
sample** and **Compare both sources** operate on bounded recorded data.
Waiting uses a logical recorded clock. Fallback is explicit, and non-good values
are not treated as equivalent valid telemetry.
See the [telemetry profile](../contracts/v14/telemetry_profile.json).

## Shadow Pilot Readiness

Under **Driver foundation > Shadow pilot readiness**, enter catalog items,
repetitions and a reason, then **Run read-only shadow**. Inspect the comparison
trace and audit. **Record incident** and **Roll back to simulator** retain history.
A different administrator is required for independent review; the default local
operator cannot grant themselves that role.

**Prepare backup** exports a pilot report. An administrator may **Restore as
read-only** from at most 256 KiB of JSON. Restores create a new read-only report;
review and authority are not restored. This does not restore the whole database.
For an uncertain run, use **Read recorded pilot run** or **Retry same pilot
request**. See the [pilot profile](../contracts/v15/pilot_profile.json).

## Local Access And Development

Run these commands from `frontend/` with the pinned release toolchain:

```powershell
npm ci
npm run dev -- --host 127.0.0.1
```

Vite uses port 5173 and proxies APIs to port 8080. Automatic session bootstrap is
restricted to the published proxy origin; use port 8080 for the normal workflow.
Vite integration tests need a privately supplied short-lived signed credential.
Never place credentials in source, screenshots, reports or frontend builds.

## Frontend Verification

```powershell
npm test
npm run build
npm run test:e2e
```

Mocked browser tests run without a backend. Real cases require
`SPELL_REAL_BACKEND=1` and `SPELL_E2E_BASE_URL` pointing to a fresh local stack.
The v0.16 manual/session cases exercise automatic connection. Historical feature
cases use private `SPELL_E2E_TOKEN`; pilot review also needs a different
administrator's `SPELL_E2E_REVIEW_TOKEN`. The canonical producer supplies those
identities. See [release qualification](../README.md#release-qualification)
for complete source-bound checks; frontend tests alone do not qualify a release.
