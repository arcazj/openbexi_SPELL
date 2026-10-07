# Local simulator procedures

Open <http://127.0.0.1:8080/>, select a procedure in the catalog, then choose **Start procedure**. The local operator session connects automatically. Answer prompts with **Commit response**; **Abort prompt** stops the procedure.

For the three observation demos, start the default DSS stack and initialize its
`simulator` context using the [quick-start commands](../README.md#quick-start).
Missing or stale driver context fails the read; automatic session connection
alone does not grant observation readiness.

For `language_reference_244`, enable [isolated reference testing](../README.md#language-reference-runner).
Its cases reset shared satellite state and finish paused; run them without other procedures.

| Procedure | What to try | Expected result |
|---|---|---|
| `dss_command_catalog_v19` | Start and inspect the typed setpoint and SAFE/NOMINAL stages. | TCNAME executes once; mode enters SAFE then NOMINAL. All three command effects are observable in received telemetry. |
| `language_reference_244` | Select an example, direct check, gap check or run-all. | Original 195 adaptations remain available. Configured DSS checks use isolated workers with parent-brokered actual CMD/TLM; durable inner-case evidence records packet correlation. Local adaptations remain explicitly bounded; full SPELL support is incomplete. |
| `observation_command_v19` | Read voltage, verify the bounded condition, wait briefly, answer YES, then approve separate command confirmation. | GOOD/FRESH/VALID/COMPLETE data plus TRUE and both decisions execute one command. NO executes none. |
| `observation_decision_v19` | Start with the deliberately unreachable voltage condition. | Verify overwrites prior TRUE with FALSE; no command is requested. |
| `observation_wait_v19` | Start and inspect the timeout result. | The condition wait times out; the following command is never requested. |
| `native_command_branch_v18` | Choose NO, then rerun with YES and approve the separate command confirmation. | NO requests no command. YES plus confirmation executes one deterministic simulator command. |
| `native_command_default_v18` | Wait five seconds, or explicitly choose YES. | The default NO requests no command. YES executes one simulator command. |
| `prompt_workflow_v17` | Choose a route, observe the numeric default, enter a note, then choose OK or CANCEL. | Typed answers are stored. CANCEL is an ordinary answer; Abort stops without a result. |
| `telecommand_modes_v18` | Start and inspect the command results. | Direct and built commands execute; the final command is loaded only. Its execution-success flag remains false. |
| `test_Python` | Enable the Python runtime below, select **Test Python**, and start it. | The exact updated Python script runs all 39 topics. Output and errors appear in Messages; successful completion stores `python_completed=True` and `python_exit_code=0`. |
| `test_python_core` | Select **Test Python Core**, start it, and inspect the result variables. | Six bounded SPELL core checks pass with `checks_passed=6` and `all_checks_passed=True`. |
| `tutorial_core_v18` | Start and inspect variables and messages. | `total=12`, `power=32`, `mask=3`, plus empty and ordinary Display messages. No commands or prompts. |

These examples use the existing local deterministic simulator. Native answers may control whether a literal command runs; command names, arguments and modifiers remain fixed in the source. v0.19 combines bounded target-based observation services with native core and literal commands. GetTM needs acceptable current evidence; Verify stores an explicit outcome and command guards compare it with `"TRUE"`. A wait or prompt does not refresh stored values. Reread telemetry when a fresh decision is required. SKIP/GOTO are unavailable for this profile. Data, file and environment mixtures, dynamic command operands and full native observation signatures remain outside it.

The [DSS scenario inventory](../contracts/dss/procedure_scenarios_v19.json)
declares initial state, responses, expected outcomes and execution bounds.
Each independent case resets or isolates satellite state. Delivery requires
every case to match its declared outcome through actual binary TC and decoded
Kafka TM; unexpected errors, missing cases and unexplained skips fail the gate.

## Python feature reference

[`test_Python.py`](test_Python.py) runs checked examples across 39 Python topics,
including classes, imports, temporary files, SQLite, compression, subprocesses,
multiprocessing, loopback sockets, async code, diagnostics and modern syntax.
The executor uses CPython 3.13.14 with its standard library. To enable it, use your
usual environment file, Compose project name and profiles consistently:

```powershell
docker compose -f compose.yaml -f compose.procedures.yaml -f compose.python.yaml build backend
docker compose -f compose.yaml -f compose.procedures.yaml -f compose.python.yaml build proxy python-runtime
docker compose -f compose.yaml -f compose.procedures.yaml -f compose.python.yaml up -d --wait
```

Apply this when no procedures are running. Refresh the operator page, select
**Test Python**, then choose **Start procedure**. The optional overlay uses
separate local images and two dedicated protocol volumes. It does not replace
the accepted v0.19.0 release images. The procedure is also runnable directly:

```powershell
python procedures/test_Python.py
python procedures/test_Python.py --list
python procedures/test_Python.py --section functions --section classes
```

Version-specific capabilities are reported as optional skips on older Python
interpreters. File examples use temporary directories that are cleaned up.
Failed checks raise an error and exit unsuccessfully, including with `-O`.

The full script opts in with `# @language-profile python-stdlib/3.13` and is
represented as one source-bound `python/1` step. Plain `.py` files without that
header are omitted from the catalog. Validation parses source without running
it. The runner executes the captured UTF-8 bytes and records their SHA-256,
stdout, stderr and exit status. Nonzero exits fail without a success checkpoint.

Run/Pause and Abort/Stop control the actual Python process and its descendants.
The UI disables line stepping, navigation, background execution and replay.
Python objects are not inspectable/editable or recoverable checkpoints; after an
interruption, explicitly start a new execution. Summary variables and Messages
remain available. [`test_python_core.spell.py`](test_python_core.spell.py) retains
the six-check example for the existing bounded SPELL runtime.

The Python child runs as UID 20000 in an immutable chroot containing CPython,
standard-library modules and shared libraries. It receives an inert environment,
no service credentials, backend packages, Docker socket, service files or `/proc`.
Docker network isolation permits loopback communication inside the runner and
blocks external/service connections. Per-job temporary storage is 32 MiB, each
file is capped at 16 MiB, address space at 768 MiB and child processes/threads at
32; the service caps resident memory at 512 MiB and CPU allocation at 0.5 cores.
Active runtime is limited to 30 seconds, total lifetime including pauses to
300 seconds, and output to 256 KiB/1,000 lines. Worker loss cancels the job after
three seconds. Jobs run serially; a runner restart never replays a claimed script.

This is an explicit local CPython extension. SPELL APIs such as `Send`, `GetTM`
and operator `Prompt` require the existing `.spell.py` profiles. The extension
does not claim full SPELL Language Reference compatibility or a new accepted
release.

Docker images contain the catalog from their build. For local procedure changes,
use the read-only catalog overlay with your usual environment file and Compose
project name:

```powershell
docker compose -f compose.yaml -f compose.procedures.yaml up -d --no-deps --wait backend
```

This recreates the backend once to attach the repository's `procedures/` folder.
Apply it when no procedures are running. Refresh the operator page to reload the
catalog; subsequent valid procedure edits in that folder need only a page refresh.
Rebuild the backend image to include the catalog without the local overlay.
