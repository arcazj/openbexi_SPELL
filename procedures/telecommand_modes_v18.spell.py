# @procedure telecommand_modes_v18
# @description Existing direct, built and load-only deterministic simulator commands
# @language-profile spell-telecommand-simulator/0.11
"""Run two local commands, then load a third without executing it."""

Send(command="CMDNAME")
Display("Direct command completed")
command = BuildTC("CMDNAME", args=[["ARG1", 1.0]])
Send(command=command)
Display("Built command completed")
Send(command="CMDNAME", LoadOnly=True)
Display("Final command loaded only; not executed")
