import hashlib
from pathlib import Path

import pytest

from backend.procedure_parser import IR_VERSION, ProcedureCatalog, ProcedureValidationError


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
    assert parsed.ir_version == IR_VERSION
    assert parsed.source == procedure.read_bytes().decode("utf-8")
    assert parsed.sha256 == hashlib.sha256(parsed.source.encode("utf-8")).hexdigest()
    assert not marker.exists()


def test_v03_compiles_typed_control_flow_and_local_calls_to_flat_ir(tmp_path: Path) -> None:
    source = '''"""Typed procedure."""
value: float = 2
limit: float = 2.5
enabled: bool = value < limit
message: str = "ready"

def emit():
    Log(message)
    Telemetry("sim.value", value=value)

if enabled:
    Call(emit)
else:
    message = "disabled"

for sample in range(2):
    value = value + 0.5
    Telemetry("sim.value", value=value)
'''

    parsed = ProcedureCatalog(tmp_path).validate_source(source)

    assert parsed.id == "submitted"
    assert all("index" in step and "line" in step and "column" in step for step in parsed.steps)
    assert [step["index"] for step in parsed.steps] == list(range(len(parsed.steps)))
    assert not any(step["type"] in {"if", "for", "call"} for step in parsed.steps)
    assert any(step.get("internal") for step in parsed.steps)
    assert sum(step["type"] == "telemetry" for step in parsed.steps) == 3
    guarded_logs = [step for step in parsed.steps if step["type"] == "log"]
    assert guarded_logs[0]["guard"]["expr"] == "variable"
    loop_values = [
        step["expression"]["value"]
        for step in parsed.steps
        if step["type"] == "variable_set" and step["name"] == "sample"
    ]
    assert loop_values == [0, 1]


def test_validation_error_exposes_structured_diagnostic(tmp_path: Path) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source("value: bytes = 1\nLog('x')\n", "upload.spell.py")

    error = raised.value
    assert error.source_name == "upload.spell.py"
    assert error.diagnostics[0].as_dict() == {
        "code": "SPELL303",
        "message": "unsupported type bytes",
        "line": 1,
        "column": 8,
        "severity": "error",
    }


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("def recurse():\n    Call(recurse)\nCall(recurse)\n", "SPELL405"),
        ("for item in range(1001):\n    Log('x')\n", "SPELL606"),
        ("count: int = 1\ncount = 'wrong'\nLog('x')\n", "SPELL310"),
        ("flag: bool = True\nif 1:\n    Log('x')\n", "SPELL501"),
        ("for item in range(unknown):\n    Log('x')\n", "SPELL604"),
        ("for item in range(0):\n    import os\n", "SPELL607"),
        ("def unused():\n    Log('x')\nLog('main')\n", "SPELL203"),
        ("for item in range(0, 999999999999999999999999999):\n    Log('x')\n", "SPELL606"),
        (f"for item in range({1 << 4096}):\n    Log('x')\n", "SPELL714"),
        ("value: float = 1e999\nLog('x')\n", "SPELL714"),
        ("__spell_branch_0: bool = True\nLog('x')\n", "SPELL309"),
        (f"Prompt('Continue?', choices=['{'x' * 201}'])\n", "SPELL715"),
        ("Prompt('Continue?', choices=['yes', 'yes'])\n", "SPELL708"),
        (f"Prompt('Continue?', choices=['yes'], default='{'x' * 201}')\n", "SPELL715"),
    ],
)
def test_v03_rejects_unsafe_or_unbounded_constructs(
    tmp_path: Path, source: str, code: str
) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)
    assert raised.value.diagnostics[0].code == code


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


@pytest.mark.parametrize(
    "source",
    [
        "for item in range(1):\n    Telemetry('item', value=item)\nTelemetry('item', value=item)\n",
        (
            "enabled: bool = True\n"
            "if enabled:\n"
            "    for item in range(1):\n"
            "        Telemetry('item', value=item)\n"
            "else:\n"
            "    Telemetry('item', value=item)\n"
        ),
    ],
)
def test_implicit_loop_targets_do_not_escape_their_loop(
    tmp_path: Path, source: str
) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)

    assert raised.value.diagnostics[0].code == "SPELL308"


def test_predeclared_loop_target_remains_definite_after_a_guarded_loop(
    tmp_path: Path,
) -> None:
    source = (
        "item: int = 7\n"
        "enabled: bool = False\n"
        "if enabled:\n"
        "    for item in range(1):\n"
        "        Telemetry('item', value=item)\n"
        "Telemetry('item', value=item)\n"
    )

    parsed = ProcedureCatalog(tmp_path).validate_source(source)

    assert parsed.steps[-1]["type"] == "telemetry"
    assert parsed.steps[-1]["value"] == {"expr": "variable", "name": "item"}


def test_deep_expression_returns_a_structured_complexity_diagnostic(tmp_path: Path) -> None:
    source = "value: int = " + "1+" * 1_500 + "1\nLog('ok')\n"

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source, "deep.spell.py")

    diagnostic = raised.value.diagnostics[0]
    assert diagnostic.code == "SPELL003"
    assert diagnostic.severity == "error"


def test_unpaired_unicode_surrogate_returns_a_structured_diagnostic(tmp_path: Path) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source("Log('\ud800')\n", "unicode.spell.py")

    diagnostic = raised.value.diagnostics[0]
    assert diagnostic.code == "SPELL004"
    assert diagnostic.line == 1
    assert diagnostic.column == 6


def test_parser_enforces_the_source_byte_limit(tmp_path: Path) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source("#" * 100_001)

    assert raised.value.diagnostics[0].code == "SPELL005"


def test_catalog_rejects_an_oversized_file_before_reading_it(tmp_path: Path) -> None:
    procedure = tmp_path / "oversized.spell.py"
    with procedure.open("wb") as output:
        output.seek(100_000)
        output.write(b"x")

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).parse(procedure)

    assert raised.value.diagnostics[0].code == "SPELL005"


def test_catalog_returns_a_structured_error_for_invalid_utf8(tmp_path: Path) -> None:
    procedure = tmp_path / "invalid-utf8.spell.py"
    procedure.write_bytes(b"Log('\xed\xa0\x80')\n")

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).parse(procedure)

    assert raised.value.diagnostics[0].code == "SPELL004"


@pytest.mark.parametrize(
    "source",
    [
        r"Log('\ud800')" + "\n",
        r"Log('\x00')" + "\n",
        r"Prompt('Continue?', choices=['\ud800'])" + "\n",
        r'"""\ud800"""' + "\nLog('ok')\n",
    ],
)
def test_ast_decoded_strings_must_be_persistable(tmp_path: Path, source: str) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)

    assert raised.value.diagnostics[0].code == "SPELL716"


def test_range_is_a_reserved_local_function_name(tmp_path: Path) -> None:
    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(
            "def range():\n    Log('ambiguous')\nrange()\n"
        )

    assert raised.value.diagnostics[0].code == "SPELL201"


def test_nested_loop_fanout_is_stopped_at_the_ir_limit(tmp_path: Path) -> None:
    source = (
        "for outer in range(1000):\n"
        "    for inner in range(1000):\n"
        "        Log('bounded')\n"
    )

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)

    assert raised.value.diagnostics[0].code == "SPELL102"


def test_repeated_large_ir_payload_is_stopped_at_the_serialized_limit(
    tmp_path: Path,
) -> None:
    payload = "x" * 20_000
    source = (
        "def emit():\n"
        f"    Log({payload!r})\n"
        "for item in range(1000):\n"
        "    Call(emit)\n"
    )

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)

    assert raised.value.diagnostics[0].code == "SPELL104"


def test_repeated_wide_expression_is_stopped_at_the_serialized_limit(
    tmp_path: Path,
) -> None:
    condition = " and ".join(["True"] * 5_000)
    source = (
        f"def emit():\n    if {condition}:\n        Log('bounded')\n"
        "for item in range(1000):\n    Call(emit)\n"
    )

    with pytest.raises(ProcedureValidationError) as raised:
        ProcedureCatalog(tmp_path).validate_source(source)

    assert raised.value.diagnostics[0].code == "SPELL104"
