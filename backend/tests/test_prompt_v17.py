from __future__ import annotations

import pytest

from backend.ir_v06 import V06ValidationError
from backend.prompt_v17 import (
    native_prompt_result, normalize_native_prompt_declaration,
    normalize_native_prompt_response, validate_native_prompt_step,
)


@pytest.mark.parametrize("kind,choices,response,expected", [
    ("OK", None, "OK", "OK"), ("CANCEL", None, "CANCEL", "CANCEL"),
    ("OK_CANCEL", None, "CANCEL", "CANCEL"), ("YES", None, "YES", "YES"),
    ("NO", None, "NO", "NO"), ("YES_NO", None, "NO", "NO"),
    ("ALPHA", None, "nominal", "nominal"), ("NUM", None, "2.50", 2.5),
    ("DATE", None, "2024-02-29", "2024-02-29"),
    ("LIST", ["A :Primary", "B:Backup"], "B", "B"),
    ("LIST|NUM", ["Primary", "Backup"], 1, 1),
    ("LIST|ALPHA", ["Primary", "Backup"], "Backup", "Backup"),
])
def test_native_prompt_result_types(kind, choices, response, expected):
    fields = normalize_native_prompt_declaration("Input", prompt_type=kind, choices=choices)
    assert validate_native_prompt_step(fields) == fields
    result = native_prompt_result(fields, {"outcome": "ANSWERED", "response": response})
    assert type(result) is type(expected) and result == expected


@pytest.mark.parametrize("timeout,default,warning,deadline,effective", [
    (None, None, None, None, None), (0, "YES", None, None, None),
    (None, "YES", None, None, None), (60, None, 60.0, None, None),
    (60, "YES", None, 60.0, "YES"), (604800, None, 604800.0, None, None),
])
def test_native_timeout_specific_section_and_zero_policy(timeout, default, warning, deadline, effective):
    fields = normalize_native_prompt_declaration("Input", prompt_type="YES_NO", default=default, timeout_seconds=timeout)
    assert fields["default"] == effective
    assert fields["warning_delay_seconds"] == warning
    assert fields["response_timeout_seconds"] == deadline
    assert validate_native_prompt_step(fields) == fields


@pytest.mark.parametrize("kind,response", [
    ("NUM", True), ("NUM", "1e10"), ("NUM", "NaN"), ("NUM", "Infinity"),
    ("NUM", "1" * 129), ("NUM", float("inf")), ("DATE", "2026-02-29"),
    ("DATE", "02/10/2026"), ("ALPHA", ""), ("ALPHA", "invalid\ninput"),
    ("YES_NO", "yes"),
])
def test_native_answer_rejections_are_bounded_and_nonexecuting(kind, response):
    fields = normalize_native_prompt_declaration("Input", prompt_type=kind)
    with pytest.raises(V06ValidationError):
        normalize_native_prompt_response(fields, response)


@pytest.mark.parametrize("choices", [[], ["no separator"], [":missing key"], ["A:one", " A:two"], ["A:"]])
def test_native_key_list_rejects_ambiguous_or_missing_identity(choices):
    with pytest.raises(V06ValidationError):
        normalize_native_prompt_declaration("Input", prompt_type="LIST", choices=choices)


def test_native_cancellation_is_not_an_answer_or_default():
    fields = normalize_native_prompt_declaration("Input", prompt_type="OK_CANCEL", default="OK", timeout_seconds=30)
    assert native_prompt_result(fields, {"outcome": "ANSWERED", "response": "CANCEL"}) == "CANCEL"
    for outcome in ("CANCELLED", "TIMED_OUT", "NO_CONTROLLER", "EXECUTION_TERMINATED", "ERROR"):
        with pytest.raises(V06ValidationError):
            native_prompt_result(fields, {"outcome": outcome, "response": "OK"})


def test_native_ir_rejects_timer_or_profile_tampering():
    fields = normalize_native_prompt_declaration("Input", prompt_type="YES_NO", timeout_seconds=30)
    for patch in ({"prompt_profile": "other"}, {"default": "YES"},
                  {"response_timeout_seconds": 30.0}, {"warning_delay_seconds": 604801.0},
                  {"warning_delay_seconds": True}, {"warning_delay_seconds": 1 << 4095},
                  {"no_controller_grace_seconds": 30.0}):
        with pytest.raises(V06ValidationError):
            validate_native_prompt_step({**fields, **patch})


def test_native_numeric_wire_is_stable_or_rejected_before_settlement():
    fields = normalize_native_prompt_declaration("Number", prompt_type="NUM")
    for value in (1e200, 10**200, 1e-200, "1e200"):
        with pytest.raises(V06ValidationError):
            normalize_native_prompt_response(fields, value)
    for value in (1e20, 0, -2.5, "2.500"):
        canonical = normalize_native_prompt_response(fields, value)
        assert normalize_native_prompt_response(fields, canonical) == canonical
