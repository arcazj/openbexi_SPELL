# @procedure observation_command_v19
# @description Read and verify a local sample before native and command confirmation
# @language-profile spell-lrm244-conformance/0.19
reading: float = 0.0
status: str = ""
answer: str = ""
GetTM('TM.POWER.BUS_VOLTAGE', target=reading, scalar_type="float")
Verify(condition={'condition_plan_id': 'language-v19-voltage-ge-0.0', 'root': {'type': 'PREDICATE', 'node_id': 'voltage-acceptable', 'operator': 'GE', 'left': {'kind': 'TELEMETRY', 'item_id': 'TM.POWER.BUS_VOLTAGE', 'catalog_digest': '5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94', 'scalar_type': 'FINITE_DOUBLE', 'value_field': 'ENGINEERING'}, 'right': {'kind': 'LITERAL', 'value': {'type': 'FINITE_DOUBLE', 'value': 0.0}}}}, target=status, timeout=1)
WaitFor(seconds=0.05)
answer = Prompt("Run the observed simulator command?", YES_NO)
if status == "TRUE" and reading >= 0.0 and answer == "YES":
    Send(command="CMDNAME", Confirm=True)
    Display("Observed simulator command completed")
else:
    Display("No command requested")
