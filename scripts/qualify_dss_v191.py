"""DSS release inventory extends the inherited oracles with both Python procedures."""
from scripts import qualify_dss_v19 as base
from scripts.validate_dss_delivery import ROOT, MANIFEST_SCHEMA, canonical, sha256, source_inventory

RELEASE = "v0.19.1"
MANIFEST = ROOT / "contracts/dss/procedure_scenarios_v191.json"
REFERENCE_MAPPING = ROOT / "contracts/dss/reference_adapters_v191.json"


def scenario_definitions():
    from backend.dss_scenarios import procedure_execution_spec
    rows = base.scenario_definitions()
    native = {"id":"native-python-full", "subject":"procedure:procedures/test_Python.py",
        "inputs":{"observation_input":"nominal", "execution_spec":procedure_execution_spec([{"action":"run"}],{})},
        "operator_actions":[{"action":"run"}],
        "expected":{"terminal":"completed", "variables":{"python_completed":True, "python_exit_code":0,
            "python_stdout_lines":345, "python_stderr_lines":0},
            "summary":["All runtime checks passed: 261 check(s), 39 topic(s), 0 optional capability check(s) skipped."],
            "stdout_lines":345, "stderr_lines":0, "outer_executed_commands":0,
            "outer_loaded_unexecuted_commands":0, "observations":[]}}
    native["definition_sha256"] = sha256(canonical(native))
    core = base._scenario("python-core-full", "test_python_core", [],
        base._expect(variables={"checks_passed":6, "all_checks_passed":True}, logs=[
            "Test Python: checks for the current SPELL executor", "PASS: typed int, float, bool and string values",
            "PASS: arithmetic + - * / // %", "PASS: integer power and bitwise AND/OR",
            "PASS: chained comparisons and boolean operators", "PASS: bounded range loop and augmented assignment",
            "PASS: zero-argument local function through Call", "All 6 supported Python core checks passed",
            "Full collections, imports, classes, async and thread examples run in test_Python.py with Python"]))
    # The inherited final scenario restores a paused, fault-free DSS after both additions.
    return [*rows[:-1], native, core, rows[-1]]


def build_manifest():
    inventory = source_inventory(RELEASE)
    return {"schema_version":MANIFEST_SCHEMA, "release":RELEASE, "inventory":inventory,
        "inventory_sha256":sha256(canonical(inventory)), "scenarios":scenario_definitions()}


def reference_mapping():
    return {**base.reference_mapping(), "release": RELEASE}


class DeliveryQualifier(base.DeliveryQualifier):
    release = RELEASE


def main():
    return base.main(release=RELEASE, manifest=MANIFEST, mapping=REFERENCE_MAPPING,
        build=build_manifest, reference=reference_mapping, qualifier_type=DeliveryQualifier)


if __name__ == "__main__":
    raise SystemExit(main())
