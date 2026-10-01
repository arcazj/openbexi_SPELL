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
             "scripts.tests.test_release_next::", "scripts.tests.test_spell_auditor_tool::"))]
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
    feature = {13: "synthetic_control_v13", 14: "telemetry_adapter_v14", 15: "shadow_pilot_v15"}[MINOR]
    config["candidate_files"] = [f"backend/tests/test_{feature}.py", "scripts/tests/test_release_next.py"]
    config["candidate_identities"] = sorted(r["identity"] for r in rows if r["identity"].startswith(
        (f"backend.tests.test_{feature}::", "scripts.tests.test_release_next::")))
    require(len(config["candidate_identities"]) > 17, "feature candidate inventory missing")
    write_json(ROOT / POLICY, config)
    print({name: value["tests"] for name, value in config["gates"].items()})
    print("Candidate cases:", len(config["candidate_identities"]))


if __name__ == "__main__":
    main()
