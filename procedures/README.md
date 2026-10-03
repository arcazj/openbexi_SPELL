# Local simulator procedures

Open <http://127.0.0.1:8080/>, select a procedure in the catalog, then choose **Start procedure**. The local operator session connects automatically. Answer prompts with **Commit response**; **Abort prompt** stops the procedure.

For the three observation demos, enable the driver profile and initialize its
`simulator` context using the [quick-start commands](../README.md#quick-start).
Missing or stale driver context fails the read; automatic session connection
alone does not grant observation readiness.

| Procedure | What to try | Expected result |
|---|---|---|
| `language_reference_244` | Select an example, direct check, gap check or run-all. | Original 195 adaptations remain available. Direct source and boundary results identify their scope; full SPELL support remains incomplete. Command checks here use isolated helpers and never send commands from the outer procedure. |
| `observation_command_v19` | Read voltage, verify the bounded condition, wait briefly, answer YES, then approve separate command confirmation. | GOOD/FRESH/VALID/COMPLETE data plus TRUE and both decisions execute one command. NO executes none. |
| `observation_decision_v19` | Start with the deliberately unreachable voltage condition. | Verify overwrites prior TRUE with FALSE; no command is requested. |
| `observation_wait_v19` | Start and inspect the timeout result. | The condition wait times out; the following command is never requested. |
| `native_command_branch_v18` | Choose NO, then rerun with YES and approve the separate command confirmation. | NO requests no command. YES plus confirmation executes one deterministic simulator command. |
| `native_command_default_v18` | Wait five seconds, or explicitly choose YES. | The default NO requests no command. YES executes one simulator command. |
| `prompt_workflow_v17` | Choose a route, observe the numeric default, enter a note, then choose OK or CANCEL. | Typed answers are stored. CANCEL is an ordinary answer; Abort stops without a result. |
| `telecommand_modes_v18` | Start and inspect the command results. | Direct and built commands execute; the final command is loaded only. Its execution-success flag remains false. |
| `tutorial_core_v18` | Start and inspect variables and messages. | `total=12`, `power=32`, `mask=3`, plus empty and ordinary Display messages. No commands or prompts. |

These examples use the existing local deterministic simulator. Native answers may control whether a literal command runs; command names, arguments and modifiers remain fixed in the source. v0.19 combines bounded target-based observation services with native core and literal commands. GetTM needs acceptable current evidence; Verify stores an explicit outcome and command guards compare it with `"TRUE"`. A wait or prompt does not refresh stored values. Reread telemetry when a fresh decision is required. SKIP/GOTO are unavailable for this profile. Data, file and environment mixtures, dynamic command operands and full native observation signatures remain outside it.
