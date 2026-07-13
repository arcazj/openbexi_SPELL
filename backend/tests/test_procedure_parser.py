from pathlib import Path

import pytest

from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


def test_parser_creates_ir_without_executing_source(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    procedure = tmp_path / "safe.spell.py"
    procedure.write_text(
        '"""Safe test."""\nLog("hello")\nTelemetry("sim.x", value=3)\nWait(0)\nPrompt("OK?")\n',
        encoding="utf-8",
    )

    parsed = ProcedureCatalog(tmp_path).get("safe")

    assert [step["type"] for step in parsed.steps] == ["log", "telemetry", "wait", "prompt"]
    assert parsed.steps[-1]["choices"] == ["continue"]
    assert not marker.exists()


@pytest.mark.parametrize(
    "source",
    [
        "import os\nLog('x')\n",
        "value = 3\nLog('x')\n",
        "Log(str(3))\n",
        "open('unsafe')\n",
        "Log('x', unexpected=True)\n",
    ],
)
def test_parser_rejects_non_whitelisted_syntax(tmp_path: Path, source: str) -> None:
    path = tmp_path / "unsafe.spell.py"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(ProcedureValidationError):
        ProcedureCatalog(tmp_path).parse(path)
