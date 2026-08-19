from __future__ import annotations

import copy

import pytest

from backend.ir_v08 import (
    V08ValidationError,
    canonicalize_data_result,
    data_request_for_step,
    file_handle_reference,
    resolve_data_parameters,
    validate_data_result,
    validate_ir_v08,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


def _parse(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "v08.spell.py"
    )


def test_parser_selects_v08_and_preserves_legacy_version_selection() -> None:
    procedure = _parse(
        "DataContainer('CONTAINER.A', schema_revision=1)\n"
        "Var('CONTAINER.A', 'COUNT', variable_id='COUNT', "
        "declared_type='LONG', value={'schema_version': 'spell.data.value/1', "
        "'type': 'INT64', 'value': '7'}, expected_revision=1)\n"
    )

    assert procedure.ir_version == "0.8"
    assert [step["operation"] for step in procedure.steps] == [
        "CREATE_CONTAINER",
        "SET_VARIABLE",
    ]
    assert _parse('Log("legacy")\n').ir_version == "0.3"
    assert _parse('Prompt("typed", type="OK")\n').ir_version == "0.6"


def test_args_declaration_is_closed_and_bound_into_the_first_ir_step() -> None:
    procedure = _parse(
        "ARGS(enabled='bool', count='int', ratio='float', label='str', "
        "timestamp='DATETIME', delay='RELTIME')\n"
        "DataContainer('CONTAINER.A', schema_revision=1)\n"
    )

    assert procedure.steps[0]["argument_declarations"] == {
        "count": "int",
        "delay": "RELTIME",
        "enabled": "bool",
        "label": "str",
        "ratio": "float",
        "timestamp": "DATETIME",
    }

    for source in (
        "ARGS('str')\nDataContainer('CONTAINER.A')\n",
        "ARGS(value='bytes')\nDataContainer('CONTAINER.A')\n",
        "ARGS(value='str')\nARGS(value='str')\nDataContainer('CONTAINER.A')\n",
        "def local():\n    ARGS(value='str')\nlocal()\nDataContainer('CONTAINER.A')\n",
    ):
        with pytest.raises(ProcedureValidationError):
            _parse(source)


def test_ambiguous_singular_shared_scope_alias_remains_rejected() -> None:
    with pytest.raises(ProcedureValidationError):
        _parse("ClearSharedDataScope('scope', expected_namespace_revision=1)\n")


def test_data_request_and_result_are_exact_digest_bound_and_replayable() -> None:
    procedure = _parse(
        "value: str = ''\n"
        "GetSharedData('scope', 'key', target=value, scalar_type='str')\n"
    )
    step = procedure.steps[1]
    first = data_request_for_step("execution-1", step)
    second = data_request_for_step("execution-1", copy.deepcopy(step))

    assert first == second
    assert first["operation"] == "SHARED_GET"
    assert len(first["request_digest"]) == 64
    result = canonicalize_data_result(
        first, {"outcome": "OK", "value": "bounded", "revision": 2}
    )
    assert result["result_kind"] == "VALUE"
    assert result["revision"] == "2"
    assert validate_data_result(first, result) == result

    changed = dict(result, value="changed")
    with pytest.raises(V08ValidationError, match="digest mismatch"):
        validate_data_result(first, changed)

    changed_kind = dict(result, result_kind="EFFECT")
    with pytest.raises(V08ValidationError, match="not canonical"):
        validate_data_result(first, changed_kind)

    with pytest.raises(V08ValidationError, match="cannot carry a value"):
        canonicalize_data_result(first, {"outcome": "NOT_FOUND", "value": "leak"})

    effect_request = data_request_for_step(
        "execution-1",
        _parse(
            "SaveDictionary('DICT.A', root_id='PROJECT_DATA', "
            "virtual_path='dicts/a.db', dictionary_revision=1, "
            "expected_file_revision=0)\n"
        ).steps[0],
    )
    with pytest.raises(V08ValidationError, match="effect-only"):
        canonicalize_data_result(
            effect_request,
            {"outcome": "OK", "value": True, "revision": 1},
        )


@pytest.mark.parametrize(
    "source",
    [
        "DataContainer('../escape')\n",
        "File('root', '../escape', target='not-a-variable')\n",
        "WriteFile(root_id='root', virtual_path='x', content=float('nan'))\n",
        "CreateDictionary('dictionary', format='PYTHON')\n",
        "ClearSharedDataScopes('scope')\n",
    ],
)
def test_parser_rejects_unsafe_or_incomplete_data_calls(source: str) -> None:
    with pytest.raises(ProcedureValidationError):
        _parse(source)


def test_v08_can_reuse_v07_observation_without_changing_its_step() -> None:
    procedure = _parse(
        "reading: int = 0\n"
        "GetTM('TM.COUNT', target=reading, scalar_type='int')\n"
        "DataContainer('CONTAINER.A', schema_revision=1)\n"
    )
    assert procedure.ir_version == "0.8"
    assert procedure.steps[1]["type"] == "get_tm"
    assert procedure.steps[2]["operation"] == "CREATE_CONTAINER"


def test_file_properties_are_closed_scalar_data_operations() -> None:
    procedure = _parse(
        "name: str = ''\n"
        "readable: bool = False\n"
        "File('PROJECT_DATA', 'folder/item.txt', property='basename', target=name)\n"
        "File('PROJECT_DATA', 'folder/item.txt', property='canRead', target=readable)\n"
    )

    assert [step["operation"] for step in procedure.steps[2:]] == [
        "FILE_PROPERTY",
        "FILE_PROPERTY",
    ]
    assert procedure.steps[2]["target_type"] == "str"
    assert procedure.steps[3]["target_type"] == "bool"

    with pytest.raises(ProcedureValidationError):
        _parse(
            "value: str = ''\n"
            "File('PROJECT_DATA', 'x', property='hostPath', target=value)\n"
        )


def test_dictionary_and_container_handles_are_opaque_scalar_targets() -> None:
    procedure = _parse(
        "dictionary: str = ''\n"
        "container: str = ''\n"
        "CreateDictionary('DICT.A', target=dictionary)\n"
        "DataContainer('CONTAINER.A', target=container)\n"
        "SaveDictionary('DICT.A', root_id='PROJECT_DATA', "
        "virtual_path='dicts/a.db', dictionary_revision=1, "
        "expected_file_revision=0)\n"
    )

    assert procedure.steps[2]["operation"] == "CREATE_DICTIONARY"
    assert procedure.steps[2]["target_type"] == "str"
    assert procedure.steps[3]["operation"] == "CREATE_CONTAINER"
    assert procedure.steps[3]["target_type"] == "str"
    assert "target" not in procedure.steps[4]

    handle_request = data_request_for_step("execution-1", procedure.steps[2])
    handle_result = canonicalize_data_result(
        handle_request,
        {"outcome": "OK", "value": "spell-data-handle-v1.token", "revision": 1},
    )
    assert handle_result["result_kind"] == "HANDLE"


def test_file_handle_variable_references_are_closed_typed_and_resolved() -> None:
    procedure = _parse(
        "handle: str = ''\n"
        "content: str = ''\n"
        "OpenFile('PROJECT_DATA', 'item.txt', mode='READ', revision=1, target=handle)\n"
        "ReadFile(handle=handle, target=content)\n"
        "CloseFile(handle)\n"
    )
    reference = {
        "kind": "variable_ref",
        "name": "handle",
        "value_type": "FileHandle",
    }
    assert procedure.steps[3]["parameters"]["handle"] == reference
    assert procedure.steps[4]["parameters"]["handle"] == reference
    marker = file_handle_reference(
        "opaque-file-handle",
        execution_id="execution-1",
        worker_generation=4,
        creator_request_id=data_request_for_step(
            "execution-1", procedure.steps[2]
        )["request_id"],
    )
    variables = {"handle": marker, "content": ""}
    assert resolve_data_parameters(
        procedure.steps[3],
        variables,
        execution_id="execution-1",
        worker_generation=4,
    )["handle"] == marker
    request = data_request_for_step(
        "execution-1",
        procedure.steps[3],
        variables=variables,
        worker_generation=4,
    )
    assert request["parameters"]["handle"] == marker

    with pytest.raises(V08ValidationError, match="requires worker variables"):
        data_request_for_step("execution-1", procedure.steps[3])

    tampered = copy.deepcopy(list(procedure.steps))
    tampered[3]["parameters"]["handle"]["value_type"] = "str"
    with pytest.raises(V08ValidationError, match="variable reference is invalid"):
        validate_ir_v08("0.8", tampered)

    for invalid in (
        "handle: str = ''\ncontent: str = ''\nReadFile(handle=handle, target=content)\n",
        "handle: str = ''\nCloseFile('literal-token')\n",
        "handle: str = ''\nOpenFile('PROJECT_DATA', 'x', target=handle)\nCloseFile(handle + '')\n",
    ):
        with pytest.raises(ProcedureValidationError):
            _parse(invalid)

    for leak in (
        "Log(handle)\n",
        "handle = 'leak'\n",
        "copied: str = handle\n",
    ):
        with pytest.raises(ProcedureValidationError):
            _parse(
                "handle: str = ''\n"
                "OpenFile('PROJECT_DATA', 'x', target=handle)\n"
                + leak
            )


def test_file_handle_lifetime_transitions_must_be_unconditional() -> None:
    unsafe_sources = (
        (
            "flag: bool = False\n"
            "handle: str = ''\n"
            "if flag:\n"
            "    OpenFile('PROJECT_DATA', 'x', target=handle)\n"
            "CloseFile(handle)\n"
        ),
        (
            "flag: bool = True\n"
            "handle: str = ''\n"
            "OpenFile('PROJECT_DATA', 'x', target=handle)\n"
            "if flag:\n"
            "    CloseFile(handle)\n"
            "OpenFile('PROJECT_DATA', 'y', target=handle)\n"
        ),
    )
    for source in unsafe_sources:
        with pytest.raises(
            ProcedureValidationError,
            match="FileHandle lifetime transitions must be unconditional",
        ):
            _parse(source)

    procedure = _parse(
        "flag: bool = True\n"
        "handle: str = ''\n"
        "OpenFile('PROJECT_DATA', 'x', target=handle)\n"
        "CloseFile(handle)\n"
    )
    guard = {"expr": "variable", "name": "flag"}
    for step_index in (2, 3):
        tampered = copy.deepcopy(list(procedure.steps))
        tampered[step_index]["guard"] = guard
        with pytest.raises(
            V08ValidationError,
            match="FileHandle lifetime transitions must be unconditional",
        ):
            validate_ir_v08("0.8", tampered)


def test_guarded_handle_consumers_are_valid_between_unconditional_transitions() -> None:
    procedure = _parse(
        "enabled: bool = True\n"
        "handle: str = ''\n"
        "content: str = ''\n"
        "OpenFile('PROJECT_DATA', 'item.txt', mode='READ_WRITE', revision=1, "
        "target=handle)\n"
        "if enabled:\n"
        "    ReadFile(handle=handle, target=content)\n"
        "    WriteFile(handle=handle, content='updated')\n"
        "CloseFile(handle)\n"
    )

    data_steps = [
        step for step in procedure.steps if step["type"] == "data_operation"
    ]
    assert [step["operation"] for step in data_steps] == [
        "OPEN_FILE",
        "READ_FILE",
        "WRITE_FILE",
        "CLOSE_FILE",
    ]
    assert "guard" not in data_steps[0]
    assert "guard" in data_steps[1]
    assert "guard" in data_steps[2]
    assert "guard" not in data_steps[3]


def test_ir_independently_preserves_typed_handle_checkpoint_and_rejects_leak() -> None:
    procedure = _parse(
        "handle: str = ''\n"
        "OpenFile('PROJECT_DATA', 'x', target=handle)\n"
        "Log('safe')\n"
        "CloseFile(handle)\n"
    )
    marker = file_handle_reference(
        "transient-token",
        execution_id="execution-ir-checkpoint",
        worker_generation=3,
        creator_request_id=data_request_for_step(
            "execution-ir-checkpoint", procedure.steps[1]
        )["request_id"],
    )
    resumed = validate_ir_v08(
        "0.8",
        list(procedure.steps),
        start_step=2,
        checkpoint_variables={"handle": marker},
    )
    assert resumed.checkpoint_variables == {"handle": marker}

    leaked = copy.deepcopy(list(procedure.steps))
    leaked[2]["message"] = {"expr": "variable", "name": "handle"}
    with pytest.raises(V08ValidationError, match="cannot be used as a scalar"):
        validate_ir_v08("0.8", leaked)


def test_procedure_shared_owner_is_implicit_and_scope_is_execution_only() -> None:
    procedure = _parse(
        "scopes: str = ''\n"
        "AddSharedDataScope('runtime-scope')\n"
        "GetSharedDataScopes(target=scopes)\n"
    )
    assert procedure.steps[1]["parameters"] == {
        "acl_revision": 1,
        "namespace_id": "runtime-scope",
        "scope": "EXECUTION",
    }
    assert procedure.steps[2]["parameters"] == {}

    for invalid in (
        "AddSharedDataScope('runtime-scope', scope='PROJECT')\n",
        "AddSharedDataScope('runtime-scope', owner_id='fabricated')\n",
        "scopes: str = ''\nGetSharedDataScopes('fabricated', target=scopes)\n",
    ):
        with pytest.raises(ProcedureValidationError):
            _parse(invalid)
