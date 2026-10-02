"""Generate the cumulative bounded SPELL 2.4.4 language-check procedure."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from backend.language_conformance_v16 import CASES

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/v10/language_reference_example_matrix.json"
OUTPUT = ROOT / "procedures/language_reference_244.spell.py"
DIRECT_CASES = CASES
ALL_INDEX = 195 + len(CASES)
MENU_COUNT = ALL_INDEX + 1


def render(contract_path: Path = CONTRACT) -> str:
    examples = json.loads(contract_path.read_text(encoding="utf-8")).get("examples")
    if not isinstance(examples, list) or len(examples) != 195:
        raise ValueError("v0.10 reference contract must contain exactly 195 examples")
    numbers = [row.get("example_number") for row in examples]
    if numbers != list(range(1, 196)):
        raise ValueError("v0.10 reference examples must be ordered exactly 1 through 195")
    choices = []
    for number, row in zip(numbers, examples):
        title, prefix = row["display_title"], f"Example {number}: "
        if not isinstance(title, str) or not title.startswith(prefix):
            raise ValueError(f"example {number} display title is not canonical")
        choices.append(f"Example {number:03d} - {title.removeprefix(prefix)}")
    choices.extend(("Gap check - " if case["expected_diagnostic"] else "Direct - ") + case["id"] for case in CASES)
    choices.append("Run all language checks and adaptations; report gaps")
    choice_lines = "\n".join(f"        {json.dumps(choice, ensure_ascii=True)}," for choice in choices)
    return (
        "# @procedure language_reference_244\n"
        "# @display-name SPELL 2.4.4 language checks\n"
        "# @description Select an adaptation, direct source or rejection check; gaps remain explicit\n"
        "# @language-profile spell-lrm244-conformance/0.16\n"
        '"""SPELL 2.4.4 coverage: 763 artifacts. Full language support remains incomplete."""\n\n'
        "selected_index: int = 0\n"
        "example_number: int = 1\n"
        'result: str = "not run"\n\n'
        "Prompt(\n"
        '    "Select a SPELL 2.4.4 reference example",\n'
        '    type="LIST",\n'
        "    choices=[\n" + choice_lines + "\n    ],\n"
        '    list_mode="INDEX",\n'
        "    default=0,\n"
        "    target=selected_index,\n"
        ")\n"
        "example_number = selected_index + 1\n"
        "LanguageCheck(selected_index, target=result)\n"
        "Log(result)\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = render().encode("ascii")
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != encoded:
            raise SystemExit("generated SPELL reference runner is stale")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(encoded)
    print(f"reference-runner=PASS examples=195 checks={len(CASES)} mode={'check' if args.check else 'write'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
