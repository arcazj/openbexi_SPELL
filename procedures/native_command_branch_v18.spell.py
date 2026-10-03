# @procedure native_command_branch_v18
# @description Native answer and integer guard control a confirmed simulator command
# @language-profile spell-native-telecommand-simulator/0.18
"""Choose YES to request one confirmed local command; NO requests none."""

command = BuildTC("CMDNAME")
mask = 2 ** 3 | 1
answer = Prompt("Run the simulated command?", YES_NO)
if answer == "YES" and mask & 1 == 1:
    Send(command=command, Confirm=True)
    Display("Simulated command completed")
else:
    Display("No command requested")
