from __future__ import annotations

import hashlib

import pytest

from backend.ir_v06 import (
    COMMAND_ALLOWED_STATES,
    EXECUTION_STATES,
    IR_VERSION,
    ResolvedProcedure,
    V06ValidationError,
    normalize_prompt_value,
    resolve_procedure_reference,
    validate_ir_v06,
    validate_operator_command,
    validate_prompt_declaration,
    validate_safe_point,
    validate_startproc_declaration,
    validate_startproc_graph,
    validate_user_action,
    validate_user_action_block,
    validate_user_action_invocation,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError


DIGEST_A = hashlib.sha256(b"a").hexdigest()
DIGEST_B = hashlib.sha256(b"b").hexdigest()


def test_command_policy_is_total_and_kill_is_explicitly_rejected() -> None:
    assert set(COMMAND_ALLOWED_STATES) == {
        "RUN",
        "STEP",
        "STEP_OVER",
        "PAUSE",
        "SKIP",
        "GOTO",
        "RELOAD",
        "BACKGROUND",
        "STOP",
        "ABORT",
        "RECOVER",
        "KILL",
    }
    for command, allowed in COMMAND_ALLOWED_STATES.items():
        assert allowed <= EXECUTION_STATES
        for state in EXECUTION_STATES:
            if command == "KILL":
                with pytest.raises(V06ValidationError, match="KILL_UNSUPPORTED"):
                    validate_operator_command(command, state)
            elif state not in allowed:
                with pytest.raises(V06ValidationError, match="COMMAND_NOT_ALLOWED_IN_STATE"):
                    validate_operator_command(command, state)


def test_parser_pins_nested_frame_boundaries_and_frame_scoped_labels() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    procedure = catalog.validate_source(
        'def inner():\n'
        '    Label("inside")\n'
        '    Log("inner one")\n'
        '    Log("inner two")\n'
        'def outer():\n'
        '    Call(inner)\n'
        '    Log("outer")\n'
        'Label("entry")\n'
        'Call(outer)\n'
        'Prompt("done", type="OK")\n',
        "frames.spell.py",
    )
    assert procedure.ir_version == "0.6"
    first, second, third, final = procedure.steps
    assert first["lexical_frame_path"][0] == "root"
    assert len(first["lexical_frame_path"]) == 3
    assert first["lexical_frame_id"] == first["lexical_frame_path"][-1]
    assert first["call_boundary_id"] == first["lexical_frame_path"][1]
    assert first["step_over_target"] == 3
    assert second["step_over_target"] == 2
    assert third["step_over_target"] == 3
    assert final["lexical_frame_id"] == "root"
    assert final["step_over_target"] == 4
    assert {item["name"] for item in first["labels"]} == {"entry", "inside"}
    assert len({step["reachability_id"] for step in procedure.steps}) == 4


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ('Label("same")\nLabel("same")\nLog("x")\n', "SPELL805"),
        ('Log("x")\nLabel("end")\n', "SPELL806"),
    ],
)
def test_parser_rejects_duplicate_or_unbound_static_labels(
    source: str, code: str
) -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    with pytest.raises(ProcedureValidationError, match=code):
        catalog.validate_source(source, "labels.spell.py")


def test_operator_command_targets_and_external_effect_guards() -> None:
    step = validate_operator_command("STEP", "PAUSED")
    assert step.run_budget == 1
    assert step.safe_point_policy == "REQUIRED"

    skip = validate_operator_command(
        "SKIP", "INTERRUPTED", current_step=3, total_steps=7
    )
    assert skip.target_step == 4
    goto = validate_operator_command(
        "GOTO", "PAUSED", current_step=3, total_steps=7, target_step=1
    )
    assert goto.target_step == 1
    with pytest.raises(V06ValidationError, match="UNRESOLVED_EXTERNAL_EFFECT"):
        validate_operator_command("RUN", "PAUSED", effect_certainty="EFFECT_UNKNOWN")
    with pytest.raises(V06ValidationError, match="BACKGROUND_INTERACTIVE"):
        validate_operator_command(
            "BACKGROUND", "RUNNING", background_allowed=True, prompt_open=True
        )


def test_safe_point_identity_is_stable_and_validated() -> None:
    payload = {
        "kind": "BEFORE_STATEMENT",
        "step_index": 2,
        "line": 9,
        "source_digest": DIGEST_A,
        "execution_revision": 7,
        "effect_certainty": "NO_EFFECT",
    }
    first = validate_safe_point(payload)
    second = validate_safe_point(dict(reversed(list(payload.items()))))
    assert first.id == second.id
    with pytest.raises(V06ValidationError, match="SAFE_POINT_INVALID"):
        validate_safe_point({**payload, "kind": "ARBITRARY"})


@pytest.mark.parametrize(
    ("prompt_type", "answer", "expected"),
    [
        ("OK", "OK", "OK"),
        ("CANCEL", "CANCEL", "CANCEL"),
        ("OK_CANCEL", "CANCEL", "CANCEL"),
        ("YES", "YES", "YES"),
        ("NO", "NO", "NO"),
        ("YES_NO", "NO", "NO"),
        ("ALPHA", "operator text", "operator text"),
        ("NUM", "1.230", "1.230"),
        ("DATE", "2028-02-29", "2028-02-29"),
    ],
)
def test_typed_prompt_family_normalizes_data_only_values(
    prompt_type: str, answer: object, expected: object
) -> None:
    spec = validate_prompt_declaration("Question", prompt_type=prompt_type)
    assert normalize_prompt_value(
        prompt_type, answer, choices=spec.choices, list_mode=spec.list_mode
    ) == expected


@pytest.mark.parametrize(
    ("prompt_type", "expected"),
    [
        ("OK", None),
        ("CANCEL", None),
        ("OK_CANCEL", None),
        ("YES", None),
        ("NO", None),
        ("YES_NO", None),
        ("ALPHA", None),
        ("NUM", None),
        ("DATE", None),
    ],
)
def test_typed_prompt_defaults_are_canonical(
    prompt_type: str, expected: object
) -> None:
    assert validate_prompt_declaration("Question", prompt_type=prompt_type).default == expected


def test_list_prompt_modes_and_default_share_the_same_validation() -> None:
    key = validate_prompt_declaration(
        "Choose",
        prompt_type="LIST",
        list_mode="KEY",
        choices=[{"key": "one", "label": "One"}, {"key": "two", "label": "Two"}],
        default="two",
        response_timeout_seconds=0,
    )
    assert key.default == "two"
    assert key.response_timeout_seconds is None

    index = validate_prompt_declaration(
        "Choose", prompt_type="LIST", list_mode="INDEX", choices=["One", "Two"], default=1
    )
    assert index.default == 1

    value = validate_prompt_declaration(
        "Choose",
        prompt_type="LIST",
        list_mode="VALUE",
        choices=[{"value": {"enabled": True}, "label": "Enabled"}],
        default={"enabled": True},
    )
    assert value.default == {"enabled": True}

    with pytest.raises(V06ValidationError, match="PROMPT_OPTIONS_INVALID"):
        validate_prompt_declaration(
            "Choose",
            prompt_type="LIST",
            list_mode="KEY",
            choices=[{"key": "same", "label": "A"}, {"key": "same", "label": "B"}],
        )


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("warning_delay_seconds", 86_400),
        ("response_timeout_seconds", 604_800),
        ("no_controller_grace_seconds", 604_800),
    ],
)
def test_prompt_duration_limits_match_durable_service_policy(
    field: str, maximum: int
) -> None:
    accepted = validate_prompt_declaration("Question", **{field: maximum})
    assert getattr(accepted, field) == float(maximum)
    with pytest.raises(V06ValidationError) as captured:
        validate_prompt_declaration("Question", **{field: maximum + 0.001})
    assert captured.value.code == "PROMPT_SETTING_INVALID"


@pytest.mark.parametrize("value", ["1 + 1", "NaN", "Infinity", True, object()])
def test_number_prompt_rejects_expressions_nonfinite_and_nondata(value: object) -> None:
    with pytest.raises(V06ValidationError, match="PROMPT_VALUE_INVALID"):
        normalize_prompt_value("NUM", value)


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN PRIVATE KEY-----\nredacted",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.signaturevalue",
        "password=plaintext-value",
        "https://operator:plaintext@example.invalid/path",
        "github_pat_abcdefghijklmnopqrstuvwxyz123456",
    ],
)
def test_prompt_secret_material_is_rejected_without_echo(secret: str) -> None:
    with pytest.raises(V06ValidationError) as captured:
        validate_prompt_declaration(
            "Do not persist credentials",
            prompt_type="ALPHA",
            default=secret,
        )
    assert captured.value.code == "PROMPT_SECRET_MATERIAL_REJECTED"
    assert secret not in str(captured.value)

    with pytest.raises(V06ValidationError) as captured:
        normalize_prompt_value("ALPHA", secret)
    assert captured.value.code == "PROMPT_SECRET_MATERIAL_REJECTED"
    assert secret not in str(captured.value)


def test_prompt_secret_named_list_fields_are_rejected() -> None:
    with pytest.raises(V06ValidationError, match="PROMPT_SECRET_MATERIAL_REJECTED"):
        validate_prompt_declaration(
            "Choose",
            prompt_type="LIST",
            list_mode="VALUE",
            choices=[{"value": {"access_token": "plaintext"}, "label": "bad"}],
        )


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN PRIVATE KEY-----\nredacted",
        "AKIAABCDEFGHIJKLMNOP",
        "postgresql://operator:plaintext@example.invalid/app",
        "github_pat_abcdefghijklmnopqrstuvwxyz123456",
    ],
)
def test_action_and_startproc_secrets_are_rejected_without_echo(
    secret: str,
) -> None:
    validators = [
        lambda: validate_user_action_block(
            [{"op": "LOG", "message": secret, "severity": "info"}]
        ),
        lambda: validate_user_action_block(
            [
                {
                    "op": "SET_LITERAL",
                    "name": "note",
                    "declared_type": "str",
                    "value": secret,
                }
            ]
        ),
        lambda: validate_startproc_declaration(
            "ops/child", arguments={"value": secret}
        ),
    ]
    for validate in validators:
        with pytest.raises(V06ValidationError) as captured:
            validate()
        assert captured.value.code == "PROMPT_SECRET_MATERIAL_REJECTED"
        assert secret not in str(captured.value)


def test_action_and_startproc_ordinary_strings_remain_valid() -> None:
    operations = validate_user_action_block(
        [
            {
                "op": "LOG",
                "message": "credential rotation completed",
                "severity": "info",
            },
            {
                "op": "SET_LITERAL",
                "name": "note",
                "declared_type": "str",
                "value": "ordinary value",
            },
        ]
    )
    declaration = validate_startproc_declaration(
        "ops/child",
        arguments={"message": "ordinary value", "token_count": 2},
    )
    assert len(operations) == 2
    assert declaration.arguments == {
        "message": "ordinary value",
        "token_count": 2,
    }


def test_parser_rejects_secret_bearing_static_declarations_without_echo() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    secret = "github_pat_abcdefghijklmnopqrstuvwxyz123456"
    sources = [
        f'StartProc("ops/child", args={{"value": {secret!r}}})\n',
        (
            'UserAction("ack", "Acknowledge", handler=['
            f'{{"op": "LOG", "message": {secret!r}, "severity": "info"}}])\n'
            'Log("never")\n'
        ),
    ]
    for source in sources:
        with pytest.raises(ProcedureValidationError) as captured:
            catalog.validate_source(source, "secret.spell.py")
        assert secret not in str(captured.value)


def test_user_actions_require_pinned_handlers_and_bounded_ir_operations() -> None:
    action = validate_user_action(
        action_id="ack",
        action_revision=1,
        name="ack",
        label="Acknowledge",
        severity="WARNING",
        handler_id="handler.ack",
        enabled=True,
        source_digest=DIGEST_A,
        allowlisted_handlers={"handler.ack"},
    )
    validate_user_action_invocation(action, execution_state="PROMPT", source_digest=DIGEST_A)
    block = validate_user_action_block(
        [
            {"op": "LOG", "message": "acknowledged", "severity": "info"},
            {"op": "SET_LITERAL", "name": "accepted", "declared_type": "bool", "value": True},
        ]
    )
    assert [item.operation for item in block] == ["LOG", "SET_LITERAL"]
    with pytest.raises(V06ValidationError, match="USER_ACTION_BLOCK_INVALID"):
        validate_user_action_block([{"op": "CALL", "module": "os", "name": "system"}])
    with pytest.raises(V06ValidationError, match="USER_ACTION_STALE"):
        validate_user_action_invocation(action, execution_state="PAUSED", source_digest=DIGEST_B)


def test_startproc_resolution_pins_unique_highest_priority_bundle() -> None:
    spec = validate_startproc_declaration(
        "ops/child",
        arguments={"count": 2, "flags": [True, False]},
        blocking=True,
        visible=False,
        automatic=False,
    )
    assert spec.arguments_digest == hashlib.sha256(
        b'{"count":2,"flags":[true,false]}'
    ).hexdigest()
    child = resolve_procedure_reference(
        spec.child_reference,
        [
            {
                "procedure_catalog_id": "catalog.child",
                "qualified_name": "ops/child",
                "bundle_digest": DIGEST_A,
                "priority": 9,
            },
            {
                "procedure_catalog_id": "catalog.other",
                "qualified_name": "other/child",
                "bundle_digest": DIGEST_B,
                "priority": 10,
            },
        ],
        library_revision="library.1",
    )
    assert child.procedure_catalog_id == "catalog.child"
    assert validate_startproc_graph(
        child, parent_depth=2, ancestor_identities=[], active_children=0
    ) == 3


def test_startproc_rejects_ambiguity_cycles_depth_and_traversal() -> None:
    candidates = [
        {
            "procedure_catalog_id": f"catalog.{index}",
            "qualified_name": f"{index}/child",
            "bundle_digest": digest,
            "priority": 1,
        }
        for index, digest in enumerate((DIGEST_A, DIGEST_B), start=1)
    ]
    with pytest.raises(V06ValidationError, match="AMBIGUOUS_PROCEDURE_REFERENCE"):
        resolve_procedure_reference("child", candidates, library_revision="library.1")
    with pytest.raises(V06ValidationError, match="IMMUTABLE_BUNDLE_REQUIRED"):
        validate_startproc_declaration("../child")

    child = ResolvedProcedure("catalog.child", "child", "library.1", DIGEST_A, 1)
    with pytest.raises(V06ValidationError, match="STARTPROC_DIRECT_CYCLE"):
        validate_startproc_graph(
            child,
            parent_depth=1,
            ancestor_identities=[("catalog.child", DIGEST_A)],
            active_children=0,
        )
    with pytest.raises(V06ValidationError, match="STARTPROC_DEPTH_EXCEEDED"):
        validate_startproc_graph(child, parent_depth=8, ancestor_identities=[], active_children=0)


def test_parser_preserves_v03_and_opts_new_constructs_into_v06() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    legacy = catalog.validate_source('Log("legacy")\n', "legacy.spell.py")
    assert legacy.ir_version == "0.3"

    typed = catalog.validate_source(
        'Prompt("Confirm", type="YES_NO", default="YES", response_timeout=30)\n',
        "typed.spell.py",
    )
    assert typed.ir_version == IR_VERSION
    assert typed.steps[0]["prompt_type"] == "YES_NO"

    parent = catalog.validate_source(
        'StartProc("ops/child", args={"count": 2}, blocking=True, visible=False)\n',
        "parent.spell.py",
    )
    assert parent.ir_version == IR_VERSION
    assert parent.steps[0]["type"] == "startproc"
    validate_ir_v06(IR_VERSION, list(parent.steps))


def test_parser_compiles_static_user_actions_out_of_executable_steps() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    procedure = catalog.validate_source(
        'accepted: bool = False\n'
        'UserAction("ack", "Acknowledge", handler=['
        '{"op": "LOG", "message": "acknowledged", "severity": "info"},'
        '{"op": "SET_LITERAL", "name": "accepted", '
        '"declared_type": "bool", "value": True}'
        '], severity="WARNING")\n'
        'Prompt("Confirm", type="OK")\n',
        "actions.spell.py",
    )

    assert procedure.ir_version == IR_VERSION
    assert all(step["type"] != "user_action" for step in procedure.steps)
    assert procedure.user_actions == (
        {
            "name": "ack",
            "label": "Acknowledge",
            "severity": "WARNING",
            "handler_id": "bundle.ack",
            "handler": [
                {"op": "LOG", "message": "acknowledged", "severity": "info"},
                {
                    "op": "SET_LITERAL",
                    "name": "accepted",
                    "declared_type": "bool",
                    "value": True,
                },
            ],
            "enabled": True,
            "revision": 1,
            "source_digest": procedure.sha256,
        },
    )


@pytest.mark.parametrize(
    "declaration",
    [
        'UserAction("bad", "Bad", handler=[{"op": "CALL"}])',
        (
            'UserAction("bad", "Bad", handler=['
            '{"op": "SET_LITERAL", "name": "missing", '
            '"declared_type": "bool", "value": True}])'
        ),
        'UserAction("bad", "Bad", handler=get_handler())',
    ],
)
def test_parser_rejects_unbounded_or_unpinned_user_actions(
    declaration: str,
) -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    with pytest.raises(ProcedureValidationError, match="SPELL803|SPELL717"):
        catalog.validate_source(f'{declaration}\nLog("still executable")\n')


def test_v06_ir_rejects_tampered_startproc_argument_digest() -> None:
    catalog = ProcedureCatalog.__new__(ProcedureCatalog)
    parent = catalog.validate_source('StartProc("child", args={"count": 2})\n', "p.spell.py")
    steps = [dict(parent.steps[0])]
    steps[0]["arguments_digest"] = DIGEST_A
    with pytest.raises(V06ValidationError, match="INVALID_ARGUMENTS"):
        validate_ir_v06(IR_VERSION, steps)
