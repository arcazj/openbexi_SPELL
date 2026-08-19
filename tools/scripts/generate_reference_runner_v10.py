"""Generate the single bundled v0.10 SPELL reference-example procedure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "v10" / "language_reference_example_matrix.json"
OUTPUT = ROOT / "procedures" / "language_reference_244.spell.py"


def render(contract_path: Path = CONTRACT) -> str:
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    examples = payload.get("examples")
    if not isinstance(examples, list) or len(examples) != 195:
        raise ValueError("v0.10 reference contract must contain exactly 195 examples")
    numbers = [row.get("example_number") for row in examples]
    if numbers != list(range(1, 196)):
        raise ValueError("v0.10 reference examples must be ordered exactly 1 through 195")
    choices = []
    for number, row in zip(numbers, examples):
        title = row["display_title"]
        prefix = f"Example {number}: "
        if not isinstance(title, str) or not title.startswith(prefix):
            raise ValueError(f"example {number} display title is not canonical")
        choices.append(f"Example {number:03d} - {title.removeprefix(prefix)}")
    choice_lines = "\n".join(
        f"        {json.dumps(choice, ensure_ascii=True)}," for choice in choices
    )
    return (
        "# @procedure language_reference_244\n"
        "# @display-name SPELL 2.4.4 reference examples\n"
        "# @description Select and execute one of the 195 deterministic semantic adaptations\n"
        "# @language-profile spell-lrm244-adapter/0.10\n"
        '"""Run one bounded simulator adaptation from the SPELL 2.4.4 reference."""\n\n'
        "selected_index: int = 0\n"
        "example_number: int = 1\n"
        'result: str = "not run"\n\n'
        "Prompt(\n"
        '    "Select a SPELL 2.4.4 reference example",\n'
        '    type="LIST",\n'
        "    choices=[\n"
        f"{choice_lines}\n"
        "    ],\n"
        '    list_mode="INDEX",\n'
        "    default=0,\n"
        "    target=selected_index,\n"
        ")\n"
        "example_number = selected_index + 1\n"
        "ReferenceExample(example_number, target=result)\n"
        "Log(result)\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = render()
    encoded = generated.encode("ascii")
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != encoded:
            raise SystemExit("generated v0.10 reference runner is stale")
        print("v0.10-reference-runner=PASS examples=195 mode=check")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(encoded)
    print("v0.10-reference-runner=PASS examples=195 mode=write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
