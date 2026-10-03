# @procedure native_command_default_v18
# @description A native NO default skips the simulator command
# @language-profile spell-native-telecommand-simulator/0.18
"""Wait five seconds for NO, or explicitly choose YES to send one local command."""

answer = Prompt("Send only with YES", YES_NO, Default="NO", Timeout=5*SECOND)
if answer == "YES":
    Send(command="CMDNAME")
    Display("Simulated command completed")
else:
    Display("No command requested")
