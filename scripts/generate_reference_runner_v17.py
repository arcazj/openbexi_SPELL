"""Generate the current runner while preserving the v0.16 source generator."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.language_conformance_v17 import CASES, ALL_SELECTION
from scripts.generate_reference_runner_v10 import CONTRACT, OUTPUT, render as render_v16
from backend.language_conformance_v16 import CASES as V16_CASES

DIRECT_CASES = CASES
ALL_INDEX = ALL_SELECTION
MENU_COUNT = ALL_INDEX + 1


def _choices(cases: tuple) -> str:
    return "\n".join("        " + json.dumps(("Gap check - " if case["expected_diagnostic"] else "Direct - ") + case["id"], ensure_ascii=True) + "," for case in cases)


def render(contract_path: Path = CONTRACT) -> str:
    source = render_v16(contract_path)
    old_choices = _choices(V16_CASES)
    if source.count(old_choices) != 1 or CASES[:len(V16_CASES)] != V16_CASES:
        raise ValueError("inherited v0.16 runner identities changed")
    return source.replace(old_choices, _choices(CASES)).replace(
        "# @language-profile spell-lrm244-conformance/0.16", "# @language-profile spell-lrm244-conformance/0.17").replace(
        "LanguageCheck(selected_index, target=result)", 'LanguageCheck(selected_index, profile="0.17", target=result)')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = render().encode("ascii")
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != encoded:
            raise SystemExit("generated SPELL reference runner is stale")
    else:
        OUTPUT.write_bytes(encoded)
    print(f"reference-runner=PASS examples=195 checks={len(CASES)} mode={'check' if args.check else 'write'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
