# @procedure dss_command_catalog_v19
# @description Exercise typed TCNAME and SAFE/NOMINAL mode transitions through actual DSS CMD/TLM
# @language-profile spell-telecommand-simulator/0.11
"""Complete the physical satellite command catalog used by delivery validation."""

setpoint = BuildTC("TCNAME", args=[["ARG1", 1.25], ["ARG2", 9]])
Send(command=setpoint)
safe = BuildTC("TC.SIMULATOR.SET_MODE", args=[["MODE", "SAFE"]])
Send(command=safe)
nominal = BuildTC("TC.SIMULATOR.SET_MODE", args=[["MODE", "NOMINAL"]])
Send(command=nominal)
Display("Satellite catalog commands completed")
