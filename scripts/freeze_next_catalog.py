"""Freeze exact collected test identities before committing a release candidate."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from scripts.release_next import ROOT, POLICY, MINOR, junit, require, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pytest-json", type=Path, required=True)
    parser.add_argument("--frontend-junit", type=Path, required=True)
    parser.add_argument("--browser-json", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads(args.pytest_json.read_bytes())
    config = json.loads((ROOT / POLICY).read_bytes())
    require(len({r["identity"] for r in rows}) == len(rows), "duplicate collection identity")
    def gate(selected, skipped=None):
        identities = sorted(r["identity"] for r in selected)
        require(bool(identities), "empty collected gate")
        return {"tests": len(identities), "identities": identities,
                "skipped": sorted(skipped if skipped is not None else [r["identity"] for r in selected if r["skip"]])}
    backend = [r for r in rows if r["identity"].startswith("backend.tests.")]
    driver = [r for r in rows if r["identity"].startswith("driver_host.tests.")]
    compose = config["gates"]["compose"]["identities"]
    tools = [r for r in rows if r["identity"].startswith(("scripts.tests.test_release_v12::",
             "scripts.tests.test_release_next::", "scripts.tests.test_spell_auditor_tool::",
             "scripts.tests.test_gcc_aligned_new_applicability::"))]
    docs = [r for r in rows if r["identity"].startswith(("scripts.tests.test_markdown_preview_v09::",
            "scripts.tests.test_documentation_tree_layout::"))]
    config["gates"]["sqlite"] = gate(backend + driver)
    config["gates"]["postgresql"] = gate(backend, compose)
    config["gates"]["tooling"] = gate(tools)
    config["gates"]["documentation"] = gate(docs)
    frontend = junit(args.frontend_junit)
    require(not frontend["skipped"], "frontend catalog contains skips")
    config["gates"]["frontend"] = {k: v for k, v in frontend.items() if k != "passed"}
    raw = args.browser_json.read_bytes()
    browser = json.loads(raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw)
    require(not browser.get("errors"), "browser collection failed")
    identities = []
    def visit(suite, ancestors=()):
        for spec in suite.get("specs", []):
            title = " ".join((*ancestors, spec["title"]))
            for item in spec["tests"]:
                identities.append(f"{spec['file']}::[{item['projectName']}] {title}")
        for child in suite.get("suites", []):
            visit(child, (*ancestors, child["title"]))
    for suite in browser["suites"]:
        visit(suite)
    require(len(identities) == len(set(identities)) == config["browser_screenshots"], "browser catalog differs")
    config["gates"]["browser"] = {"tests": len(identities), "identities": sorted(identities), "skipped": []}
    features = {13: ["synthetic_control_v13"], 14: ["telemetry_adapter_v14"],
                15: ["shadow_pilot_v15"], 16: ["language_conformance_v16", "local_session_v16"],
                17: ["language_core_v17", "prompt_v17", "worker_prompt_v17", "prompt_runtime_v17",
                     "prompt_api_v17", "language_conformance_v17"],
                18: ["native_telecommand_ir_v18", "worker_composition_v18", "supervisor_composition_v18",
                     "prompt_telecommand_api_v18", "operator_composition_v18", "language_conformance_v18",
                     "catalog_procedures_v18", "composition_security_v18"],
                19: ["observation_composition_ir_v19", "worker_observation_composition_v19",
                     "supervisor_observation_command_v19", "operator_observation_command_v19",
                     "observation_command_api_v19", "development_profile_v19",
                     "language_conformance_v19", "catalog_procedures_v19"]}[MINOR]
    config["candidate_files"] = [f"backend/tests/test_{feature}.py" for feature in features] + ["scripts/tests/test_release_next.py"]
    prefixes = tuple(f"backend.tests.test_{feature}::" for feature in features) + ("scripts.tests.test_release_next::",)
    if MINOR >= 18:
        config["candidate_files"].append("scripts/tests/test_gcc_aligned_new_applicability.py")
        prefixes += ("scripts.tests.test_gcc_aligned_new_applicability::",)
    config["candidate_identities"] = sorted(r["identity"] for r in rows if r["identity"].startswith(prefixes))
    if MINOR == 15:
        postgres_only = [f"backend.tests.test_shadow_pilot_v15::test_postgresql_prior_upgrade_failure_and_repeat[{value}]" for value in ("False", "True")]
        require({r["identity"] for r in rows if r["identity"].startswith("backend.tests.test_shadow_pilot_v15::") and r["skip"]} == set(postgres_only), "candidate environment inventory differs")
        config["candidate_deselections"] = [name.replace("backend.tests.test_shadow_pilot_v15", "backend/tests/test_shadow_pilot_v15.py") for name in postgres_only]
        config["candidate_identities"] = [name for name in config["candidate_identities"] if name not in postgres_only]
    require(len(config["candidate_identities"]) > 17, "feature candidate inventory missing")
    if MINOR >= 16:
        require(not any(r["skip"] for r in rows if r["identity"].startswith(prefixes)), "candidate contains an unresolved environment skip")
        config["catalog_frozen"] = True
    write_json(ROOT / POLICY, config)
    print({name: value["tests"] for name, value in config["gates"].items()})
    print("Candidate cases:", len(config["candidate_identities"]))


if __name__ == "__main__":
    main()
