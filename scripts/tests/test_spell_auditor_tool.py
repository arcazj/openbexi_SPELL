from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools import spell_auditor


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def test_header_rules_are_loaded_from_the_declared_policy() -> None:
    assert spell_auditor.load_header_rules(str(TOOLS / "header_rules.json")) == {
        "required_keys": ["NAME", "DESCRIPTION", "FILE", "SPACECRAFT"],
        "file_must_match": True,
        "spacecraft_check": True,
    }


@pytest.mark.parametrize(
    ("case_name", "expected_status"),
    [
        ("proc_test_all_functions.spell", "PASS"),
        ("proc_test_all_bad_functions.spell", "FAIL"),
    ],
)
def test_auditor_cli_honors_the_runner_header_rules_contract(
    case_name: str,
    expected_status: str,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(TOOLS / "spell_auditor.py"),
            str(TOOLS / "cases" / case_name),
            "--json",
            "--header-rules",
            str(TOOLS / "header_rules.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["overall_compliance"]["status"] == expected_status
    assert "error" not in report
