"""Simulator-only v0.3 typed state and control-flow demonstration."""

voltage: float = 28.1
minimum_voltage: float = 27.5
sample_count: int = 3
bus_ready: bool = voltage >= minimum_voltage
status: str = "nominal"


def report_bus():
    Telemetry("sim.power.bus_voltage", value=voltage, unit="V")
    Log(status)


if bus_ready:
    Call(report_bus)
else:
    status = "below limit"
    Log(status, level="warning")

Telemetry("sim.power.planned_samples", value=sample_count, unit="count")
for sample_index in range(0, 3, 1):
    voltage = voltage + 0.1
    Telemetry("sim.power.bus_voltage", value=voltage, unit="V")

Prompt("Accept the simulated readings?", choices=["accept", "abort"], default="accept")
Log("Typed procedure complete")
