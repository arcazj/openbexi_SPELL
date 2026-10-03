"""Generate the v0.18 closed runner without rewriting historical generators."""
from __future__ import annotations

import argparse
from pathlib import Path

from backend.language_conformance_v18 import CASES, ALL_SELECTION
from backend.language_conformance_v17 import CASES as V17_CASES
from scripts.generate_reference_runner_v17 import CONTRACT, OUTPUT, _choices, render as render_v17

DIRECT_CASES = CASES
ALL_INDEX = ALL_SELECTION
MENU_COUNT = ALL_INDEX + 1


def render(contract_path: Path = CONTRACT) -> str:
    source = render_v17(contract_path)
    old = _choices(V17_CASES)
    if source.count(old) != 1 or CASES[:len(V17_CASES)] != V17_CASES:
        raise ValueError("inherited v0.17 source identities changed")
    return source.replace(old, _choices(CASES)).replace(
        "# @language-profile spell-lrm244-conformance/0.17", "# @language-profile spell-lrm244-conformance/0.18").replace(
        'LanguageCheck(selected_index, profile="0.17", target=result)',
        'LanguageCheck(selected_index, profile="0.18", target=result)')


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
