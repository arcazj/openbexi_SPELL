# SPELL v0.14 Read-Only Telemetry Adapter

The local synthetic telemetry capability provides current and next GetTM reads,
RAW/ENG selection, immutable extended metadata, typed failure outcomes and a
full two-source differential trace. It reads the pinned v0.12 reference and
simulator fixtures; no network or mutation service is introduced.

Open **Driver foundation → Telemetry adapter** to inspect current or next
recorded samples, compare both sources, or explicitly select the simulator
fallback. UInt64 values remain decimal strings. Failure clears the previous
value, and switching source discards its cursor and late responses. Recorded
time and synthetic provenance remain visible; Timeout never implies waiting on
a live system. The profile is loaded from each built backend image during
qualification.

See [the entry gate](SPELL_v0.14_Pre-Implementation.md) for the exact modifier,
capacity, safety and compatibility decisions. The new REST capability is a
bounded adapter tranche; it does not expand procedure parser support or claim
full SPELL 2.4.4 language/driver compatibility. Real legacy-system and
operational qualification remain outstanding. Acceptance requires the
annotated v0.14.0 tag and its source-bound evidence, not this implementation
record alone.
