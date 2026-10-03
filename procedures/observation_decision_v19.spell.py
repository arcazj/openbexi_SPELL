# @procedure observation_decision_v19
# @description False verification overwrites prior TRUE and requests no command
# @language-profile spell-lrm244-conformance/0.19
status: str = "TRUE"
Verify(condition={'condition_plan_id': 'language-v19-voltage-ge-999.0', 'root': {'type': 'PREDICATE', 'node_id': 'voltage-acceptable', 'operator': 'GE', 'left': {'kind': 'TELEMETRY', 'item_id': 'TM.POWER.BUS_VOLTAGE', 'catalog_digest': '5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94', 'scalar_type': 'FINITE_DOUBLE', 'value_field': 'ENGINEERING'}, 'right': {'kind': 'LITERAL', 'value': {'type': 'FINITE_DOUBLE', 'value': 999.0}}}}, target=status, timeout=1)
if status == "TRUE":
    Send(command="CMDNAME")
else:
    Display("Condition not met; no command requested")
