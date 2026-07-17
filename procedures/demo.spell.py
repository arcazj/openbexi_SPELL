"""Simulator-only baseline procedure demonstrating every supported step."""

Log("Starting simulated power-system check")
Telemetry("sim.power.bus_voltage", value=28.4, unit="V")
Wait(1.5)
Prompt("Acknowledge the simulated checkpoint?", choices=["acknowledge"], default="acknowledge")
Telemetry("sim.power.battery_soc", value=87.5, unit="percent")
Log("Simulated power-system check complete")
