"""Build the v0.10 Language Reference example traceability matrix.

The generated contract intentionally contains hashes and metadata, not copied
example bodies. A runnable adaptation is a separate artifact from the source
span and must satisfy the declared semantic oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


AUTHORITY_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
FIXTURE_PROFILE = "V10-LRM244-DETERMINISTIC-SIMULATOR-1"


def numbers(*parts: int | range) -> set[int]:
    result: set[int] = set()
    for part in parts:
        if isinstance(part, range):
            result.update(part)
        else:
            result.add(part)
    return result


FAMILIES: list[tuple[range, str]] = [
    (range(1, 2), "python.indentation"),
    (range(2, 5), "python.line_continuation"),
    (range(5, 7), "python.comments"),
    (range(7, 9), "python.values_and_containers"),
    (range(9, 13), "python.expressions"),
    (range(13, 16), "python.control_flow"),
    (range(16, 18), "python.local_functions"),
    (range(18, 19), "python.procedure_import"),
    (range(19, 26), "spell.modifiers_and_recovery"),
    (range(26, 30), "spell.time"),
    (range(30, 35), "telemetry.acquisition"),
    (range(35, 55), "telemetry.verification"),
    (range(55, 57), "telemetry.condition_composition"),
    (range(57, 60), "commanding.build"),
    (range(60, 78), "commanding.send"),
    (range(78, 84), "wait.conditions"),
    (range(84, 85), "ground.parameter"),
    (range(85, 94), "limits.query"),
    (range(94, 107), "limits.mutation"),
    (range(107, 108), "alarms.query"),
    (range(108, 111), "ui.messages"),
    (range(111, 114), "resources.state"),
    (range(114, 119), "ui.prompt"),
    (range(119, 128), "ui.display_workspace"),
    (range(128, 135), "procedure.control"),
    (range(135, 138), "database.spacecraft"),
    (range(138, 151), "database.dictionary"),
    (range(151, 162), "procedure.child_execution"),
    (range(162, 169), "filesystem.virtual"),
    (range(169, 177), "ranging.simulator"),
    (range(177, 191), "shared_data.state"),
    (range(191, 195), "memory.simulator"),
    (range(195, 196), "catalog.tm_tc_lookup"),
]


# Defaults are semantic requirements for every example in a family. The
# generated JSON expands these values into every row; consumers never infer a
# missing capability or oracle from a range.
FAMILY_DEFAULTS: dict[str, dict[str, Any]] = {
    "python.indentation": {
        "capabilities": ["python.assignment", "python.if_else"],
        "effects": ["BRANCH_SELECTED", "VARIABLE_VALUE_ASSERTED"],
        "mode": "pure_state_assertion",
        "criteria": "The selected branch and the values assigned after the branch match the reference semantics.",
    },
    "python.line_continuation": {
        "capabilities": ["python.expression_continuation"],
        "effects": ["MULTILINE_EXPRESSION_EVALUATED"],
        "mode": "pure_state_assertion",
        "criteria": "The normalized multiline expression produces the same value as its single-line form.",
    },
    "python.comments": {
        "capabilities": ["python.comment"],
        "effects": ["COMMENT_IGNORED", "EXECUTABLE_STATEMENT_PRESERVED"],
        "mode": "pure_state_assertion",
        "criteria": "Comments have no runtime effect and adjacent executable statements retain their values.",
    },
    "python.values_and_containers": {
        "capabilities": ["python.dynamic_value", "python.container"],
        "effects": ["CONTAINER_VALUE_ASSERTED", "VALUE_TYPE_ASSERTED"],
        "mode": "pure_state_assertion",
        "criteria": "The adapted values, container members, and resulting types match the reference behavior.",
    },
    "python.expressions": {
        "capabilities": ["python.expression"],
        "effects": ["EXPRESSION_RESULT_ASSERTED"],
        "mode": "pure_state_assertion",
        "criteria": "Each adapted expression evaluates deterministically to its declared result.",
    },
    "python.control_flow": {
        "capabilities": ["python.bounded_control_flow"],
        "effects": ["CONTROL_FLOW_PATH_ASSERTED", "ITERATION_BOUND_ASSERTED"],
        "mode": "pure_state_assertion",
        "criteria": "The expected branch or bounded iteration path completes with the declared state.",
    },
    "python.local_functions": {
        "capabilities": ["python.local_function"],
        "effects": ["FUNCTION_RESULT_ASSERTED"],
        "mode": "pure_state_assertion",
        "criteria": "The local function call, argument behavior, and result match the adapted reference case.",
    },
    "python.procedure_import": {
        "capabilities": ["python.bounded_import"],
        "effects": ["IMPORTED_SYMBOL_RESOLVED"],
        "mode": "pure_state_assertion",
        "criteria": "An allowlisted procedure-library symbol resolves and executes without unrestricted import access.",
    },
    "spell.modifiers_and_recovery": {
        "capabilities": ["spell.call_modifier"],
        "effects": ["MODIFIER_BEHAVIOR_ASSERTED"],
        "mode": "simulator_trace_assertion",
        "criteria": "The simulator trace records the modifier-specific behavior and the declared recovery outcome.",
    },
    "spell.time": {
        "capabilities": ["spell.deterministic_time"],
        "effects": ["TIME_VALUE_ASSERTED"],
        "mode": "virtual_clock_assertion",
        "criteria": "The fixed virtual clock produces the declared parsing, formatting, comparison, or arithmetic result.",
    },
    "telemetry.acquisition": {
        "capabilities": ["telemetry.get"],
        "effects": ["TELEMETRY_VALUE_ACQUIRED"],
        "mode": "simulator_query_assertion",
        "criteria": "GetTM returns the expected fixture value and requested representation from the simulator.",
    },
    "telemetry.verification": {
        "capabilities": ["telemetry.verify"],
        "effects": ["TELEMETRY_CONDITION_EVALUATED"],
        "mode": "simulator_query_assertion",
        "criteria": "Verify evaluates the adapted condition and exposes the expected result and trace evidence.",
    },
    "telemetry.condition_composition": {
        "capabilities": ["telemetry.condition_composition", "telemetry.verify"],
        "effects": ["COMPOSITE_CONDITION_EVALUATED"],
        "mode": "simulator_query_assertion",
        "criteria": "Nested AND/OR conditions evaluate to the declared result against fixed telemetry fixtures.",
    },
    "commanding.build": {
        "capabilities": ["command.build"],
        "effects": ["COMMAND_ITEM_BUILT"],
        "mode": "simulator_state_assertion",
        "criteria": "BuildTC produces a command item with the expected identifier, arguments, and encodings.",
    },
    "commanding.send": {
        "capabilities": ["command.send"],
        "effects": ["COMMAND_TRACE_RECORDED"],
        "mode": "simulator_trace_assertion",
        "criteria": "The simulator command trace records the adapted command and all requested send semantics.",
    },
    "wait.conditions": {
        "capabilities": ["wait.for"],
        "effects": ["WAIT_CONDITION_SATISFIED"],
        "mode": "virtual_clock_assertion",
        "criteria": "WaitFor completes against the fixed clock or telemetry schedule with the declared timing result.",
    },
    "ground.parameter": {
        "capabilities": ["ground_parameter.set"],
        "effects": ["GROUND_PARAMETER_UPDATED"],
        "mode": "simulator_state_assertion",
        "criteria": "The synthetic ground parameter is updated and its readback equals the injected value.",
    },
    "limits.query": {
        "capabilities": ["limits.get"],
        "effects": ["LIMIT_DEFINITION_QUERIED"],
        "mode": "simulator_query_assertion",
        "criteria": "GetLimits returns the expected deterministic definition or selected field.",
    },
    "limits.mutation": {
        "capabilities": ["limits.mutate"],
        "effects": ["LIMIT_STATE_UPDATED"],
        "mode": "simulator_state_assertion",
        "criteria": "The requested synthetic limit mutation is visible in readback and unrelated fields remain stable.",
    },
    "alarms.query": {
        "capabilities": ["alarm.query"],
        "effects": ["ALARM_STATE_ASSERTED"],
        "mode": "simulator_query_assertion",
        "criteria": "IsAlarmed returns the expected state for the fixed telemetry and limit fixture.",
    },
    "ui.messages": {
        "capabilities": ["ui.message"],
        "effects": ["MESSAGE_TRACE_RECORDED"],
        "mode": "simulator_trace_assertion",
        "criteria": "The emitted message trace preserves text, severity, and status fields.",
    },
    "resources.state": {
        "capabilities": ["resource.read_write"],
        "effects": ["RESOURCE_VALUE_ASSERTED"],
        "mode": "simulator_state_assertion",
        "criteria": "The allowlisted synthetic resource is written or read with the declared mapped value.",
    },
    "ui.prompt": {
        "capabilities": ["prompt.deterministic_response"],
        "effects": ["PROMPT_RESPONSE_ASSERTED"],
        "mode": "scripted_prompt_assertion",
        "criteria": "The prompt model, options, default, and scripted response produce the declared value without operator timing dependence.",
    },
    "ui.display_workspace": {
        "capabilities": ["display_workspace.lifecycle"],
        "effects": ["DISPLAY_WORKSPACE_TRACE_RECORDED"],
        "mode": "simulator_trace_assertion",
        "criteria": "The synthetic display or workspace trace records the requested lifecycle operation and modifiers.",
    },
    "procedure.control": {
        "capabilities": ["procedure.control"],
        "effects": ["PROCEDURE_CONTROL_TRACE_RECORDED"],
        "mode": "isolated_control_flow_assertion",
        "criteria": "The isolated control-flow probe records the requested step, action, or terminal state without escaping the case harness.",
    },
    "database.spacecraft": {
        "capabilities": ["database.scdb"],
        "effects": ["SPACECRAFT_DATABASE_VALUE_ASSERTED"],
        "mode": "simulator_query_assertion",
        "criteria": "The synthetic spacecraft database supports the declared lookup, iteration, or membership behavior.",
    },
    "database.dictionary": {
        "capabilities": ["database.dictionary"],
        "effects": ["DICTIONARY_STATE_ASSERTED"],
        "mode": "simulator_state_assertion",
        "criteria": "The adapted database or data-container operation produces the declared deterministic state.",
    },
    "procedure.child_execution": {
        "capabilities": ["procedure.child_fixture"],
        "effects": ["CHILD_EXECUTION_STATE_ASSERTED"],
        "mode": "embedded_child_fixture_assertion",
        "criteria": "The non-catalog embedded child fixture resolves with the declared priority, mode, arguments, and state.",
    },
    "filesystem.virtual": {
        "capabilities": ["filesystem.virtual"],
        "effects": ["VIRTUAL_FILESYSTEM_STATE_ASSERTED"],
        "mode": "virtual_filesystem_assertion",
        "criteria": "The sandboxed virtual filesystem records the requested operation and expected content or listing.",
    },
    "ranging.simulator": {
        "capabilities": ["ranging.simulator"],
        "effects": ["RANGING_STATE_ASSERTED"],
        "mode": "simulator_state_assertion",
        "criteria": "The deterministic ranging state and configuration match the requested operation.",
    },
    "shared_data.state": {
        "capabilities": ["shared_data.state"],
        "effects": ["SHARED_DATA_STATE_ASSERTED"],
        "mode": "simulator_state_assertion",
        "criteria": "The scoped shared-data operation returns the expected value and leaves the declared state.",
    },
    "memory.simulator": {
        "capabilities": ["memory.simulator"],
        "effects": ["MEMORY_OPERATION_RESULT_ASSERTED"],
        "mode": "simulator_state_assertion",
        "criteria": "The synthetic memory operation returns the expected report, comparison, or selected values.",
    },
    "catalog.tm_tc_lookup": {
        "capabilities": ["catalog.tm_tc_lookup"],
        "effects": ["TM_TC_CATALOG_VALUES_EXTRACTED", "TM_TC_CATALOG_PROVENANCE_ASSERTED"],
        "mode": "simulator_catalog_query_assertion",
        "criteria": "TMTCLookup returns fixture-backed TM/TC records matching every supplied filter, with stable identifiers, values, types, and provenance.",
    },
}


EXTRA_CAPABILITIES: dict[str, set[int]] = {
    "python.string_concatenation": numbers(2, 11),
    "python.call_keyword_arguments": numbers(3, 19),
    "python.backslash_continuation": numbers(4),
    "python.docstring": numbers(6),
    "python.list": numbers(7, 8, 14, 47, 48, 49, 50, 54, 58, 66, 68, 69, 70, 71, 77, 83, 85, 87, 88, 90, 91, 93, 101, 115, 116, 117, 118, 164, 165, 166, 171, 173, 174, 179, 183, 185, 187, 192),
    "python.dictionary": numbers(7, 8, 40, 48, 49, 58, 73, 77, 85, 86, 87, 88, 89, 90, 94, 95, 96, 97, 113, 135, 139, 140, 142, 143, 144, 145, 146, 147, 148, 149, 150, 161, 191, 194, 195),
    "python.math_builtins": numbers(9),
    "python.boolean_operators": numbers(10, 55, 56),
    "python.string_slice": numbers(12),
    "python.if_elif_else": numbers(13),
    "python.for_loop": numbers(14, 26, 27, 40, 136),
    "python.while_loop": numbers(15),
    "python.function_return": numbers(16),
    "python.argument_rebinding": numbers(17),
    "spell.language_config": numbers(20),
    "spell.failure_action": numbers(21, 22),
    "spell.false_result_action": numbers(23, 39, 42, 43, 44),
    "spell.guarded_exception": numbers(24),
    "spell.verbosity_notification": numbers(25),
    "spell.time_now": numbers(26, 27),
    "spell.time_format": numbers(28),
    "spell.time_parse_arithmetic": numbers(29),
    "telemetry.wait_for_update": numbers(31, 32, 37),
    "spell.timeout": numbers(32, 37, 72, 118),
    "telemetry.raw_value": numbers(33, 36, 48, 49, 50),
    "telemetry.extended_item": numbers(34, 51, 53, 54),
    "telemetry.tolerance": numbers(38),
    "telemetry.verification_result": numbers(39, 40, 41),
    "telemetry.retry": numbers(44),
    "telemetry.delay": numbers(45),
    "telemetry.ignore_case": numbers(46),
    "telemetry.multiple_conditions": numbers(47, 48, 49, 50, 54, 55, 56),
    "telemetry.expected_value_list": numbers(50),
    "telemetry.item_comparison": numbers(51, 53, 54),
    "telemetry.literal_expected_value": numbers(52),
    "command.arguments": numbers(58, 59, 66, 69, 70, 71, 73, 74, 75, 76, 77),
    "command.time_tag": numbers(61),
    "command.release_time": numbers(62),
    "command.load_only": numbers(63),
    "command.confirm": numbers(64),
    "command.confirm_critical": numbers(65),
    "command.sequence": numbers(67),
    "command.group": numbers(68, 69, 70, 71, 74),
    "command.block": numbers(71),
    "command.additional_info": numbers(73),
    "command.send_delay": numbers(74),
    "command.post_verify": numbers(75, 76, 77),
    "command.adjust_limits": numbers(76, 77),
    "wait.relative_time": numbers(78, 82, 83),
    "wait.absolute_time": numbers(79),
    "wait.telemetry_condition": numbers(80, 81),
    "wait.maximum_delay": numbers(81),
    "wait.progress_interval": numbers(82, 83),
    "limits.select_all": numbers(85, 100),
    "limits.hardsoft": numbers(85, 86, 88, 89, 92, 94, 95, 96, 99, 103),
    "limits.status": numbers(87, 90, 91, 97, 98, 104),
    "limits.field_selection": numbers(91, 92, 93),
    "limits.set_definition": numbers(94, 95, 96, 97, 98, 99, 100, 101),
    "limits.alarm_enable_disable": numbers(102),
    "limits.auto_adjust": numbers(103, 104),
    "limits.load": numbers(105),
    "limits.restore": numbers(106),
    "ui.display_message": numbers(108),
    "ui.notification": numbers(109),
    "ui.event": numbers(110),
    "resource.mapping": numbers(113, 139, 140, 141),
    "prompt.list": numbers(114, 115, 116, 117, 118),
    "prompt.index_mode": numbers(116),
    "prompt.value_mode": numbers(115, 117),
    "prompt.default": numbers(118),
    "display.open": numbers(119, 121, 122, 123),
    "workspace.open": numbers(120, 121, 122),
    "display.host": numbers(121),
    "display.monitor": numbers(122),
    "display.time_span": numbers(123),
    "display.print": numbers(124, 125),
    "display.close": numbers(126),
    "workspace.close": numbers(127),
    "procedure.step": numbers(128, 129, 130),
    "procedure.goto": numbers(129),
    "procedure.lifecycle": numbers(131),
    "procedure.user_action": numbers(132, 133, 134),
    "database.iteration": numbers(136),
    "database.membership": numbers(137),
    "database.load": numbers(138, 143),
    "database.gdb_mapping": numbers(139, 140, 141),
    "database.proc_state": numbers(142),
    "database.create": numbers(144),
    "database.save": numbers(145),
    "database.mutate": numbers(146),
    "database.parse_fixture": numbers(147, 148),
    "database.data_container": numbers(149, 150),
    "procedure.library_resolution": numbers(151, 152, 153, 154, 155),
    "procedure.nonblocking": numbers(156, 159),
    "procedure.visibility": numbers(157, 159),
    "procedure.manual_mode": numbers(158, 159),
    "procedure.arguments": numbers(160, 161),
    "filesystem.open": numbers(162),
    "filesystem.close": numbers(163),
    "filesystem.write": numbers(164),
    "filesystem.read": numbers(165),
    "filesystem.list_directory": numbers(166),
    "filesystem.file_object": numbers(167),
    "filesystem.delete": numbers(168),
    "ranging.enable_disable": numbers(169),
    "ranging.start": numbers(170, 171),
    "ranging.dual": numbers(171),
    "ranging.abort": numbers(172),
    "ranging.baseband_config": numbers(173),
    "ranging.inventory": numbers(174),
    "ranging.calibrate": numbers(175),
    "ranging.status": numbers(176),
    "shared_data.set": numbers(177, 178, 179, 180, 182, 183),
    "shared_data.scope": numbers(180, 181, 186, 187, 189, 190),
    "shared_data.compare_and_set": numbers(182, 183),
    "shared_data.get": numbers(184, 185, 186),
    "shared_data.introspect": numbers(187),
    "shared_data.clear": numbers(188, 189, 190),
    "memory.report": numbers(191),
    "memory.compare": numbers(192, 193),
    "memory.range_filter": numbers(193, 194, 195),
    "memory.lookup": numbers(194),
    "catalog.filter": numbers(195),
    "catalog.provenance": numbers(195),
}


EXTRA_EFFECTS: dict[str, set[int]] = {
    "RAW_VALUE_ASSERTED": numbers(33, 34, 36, 48, 49, 50),
    "UPDATE_WAIT_ASSERTED": numbers(31, 32, 37),
    "TIMEOUT_BOUND_ASSERTED": numbers(32, 37, 72, 118),
    "NEGATIVE_LITERAL_SEMANTICS_ASSERTED": numbers(52),
    "COMMAND_ARGUMENTS_ASSERTED": numbers(58, 59, 66, 69, 70, 71, 73, 74, 75, 76, 77),
    "COMMAND_ORDER_ASSERTED": numbers(67, 68, 69, 70, 71, 74, 77),
    "POST_COMMAND_TELEMETRY_ASSERTED": numbers(75, 76, 77),
    "LIMIT_READBACK_ASSERTED": numbers(range(94, 107)),
    "PROMPT_DEFAULT_ASSERTED": numbers(118),
    "PROCEDURE_TERMINAL_STATE_ISOLATED": numbers(131),
    "CHILD_ARGUMENT_ASSERTED": numbers(160, 161),
    "FILE_CONTENT_ASSERTED": numbers(164, 165),
    "DIRECTORY_LISTING_ASSERTED": numbers(166),
    "COMPARE_AND_SET_ATOMICITY_ASSERTED": numbers(182, 183),
    "FILTER_BOUNDARIES_ASSERTED": numbers(193, 194, 195),
}


AMBIGUITY_GROUPS: dict[str, set[int]] = {
    "PLACEHOLDER_OR_ELLIPSIS": numbers(13, 14, 15, 18, 19, 21, 23, 39, 47, 55, 56, 58, 59, 66, 77, 85, 109, 129, 137, 150, 164, 165, 166, 169, 170, 172, 175, 176, 177, 178, 179, 180, 182, 183, 184, 185, 186, 187, 191, 192, 193, 194, 195),
    "ILLUSTRATIVE_OUTPUT_MIXED_WITH_CODE": numbers(12, 41, 85, 88, 89, 90, 91, 92, 93, 139, 147, 148, 167),
    "OUTPUT_OR_DATA_ONLY": numbers(41, 86, 87, 139, 147, 152, 153),
    "SOURCE_SYNTAX_ANOMALY": numbers(25, 37, 83, 86, 87, 163, 179, 183, 191, 192),
    "LEGACY_PYTHON_SYNTAX": numbers(24, 137),
    "NEGATIVE_DEMONSTRATION": numbers(52),
    "MULTIPLE_VARIANTS_IN_ONE_EXAMPLE": numbers(29, 56, 60, 61, 62, 66, 68, 70, 74, 78, 82, 83, 85, 91, 92, 93, 96, 102, 108, 110, 114, 121, 122, 124, 131, 132, 133, 152, 153, 159, 162, 164, 166, 167, 168, 169, 173, 174, 177, 179, 182, 183, 187, 188, 189, 192),
    "TERMINAL_OPERATIONS_COLOCATED": numbers(131),
    "TITLE_BODY_MISMATCH": numbers(163),
}


def family_for(number: int) -> str:
    matches = [family for span, family in FAMILIES if number in span]
    if len(matches) != 1:
        raise ValueError(f"example {number} has {len(matches)} semantic families")
    return matches[0]


def selected(mapping: dict[str, set[int]], number: int) -> list[str]:
    return sorted(name for name, members in mapping.items() if number in members)


def adaptation_actions(ambiguity_codes: Iterable[str]) -> list[str]:
    codes = set(ambiguity_codes)
    actions = {"BIND_DETERMINISTIC_FIXTURES", "WRAP_WITH_SEMANTIC_ASSERTIONS"}
    if "PLACEHOLDER_OR_ELLIPSIS" in codes:
        actions.add("REPLACE_PLACEHOLDERS_WITH_TYPED_FIXTURES")
    if "ILLUSTRATIVE_OUTPUT_MIXED_WITH_CODE" in codes or "OUTPUT_OR_DATA_ONLY" in codes:
        actions.add("TURN_ILLUSTRATION_INTO_ASSERTED_EXPECTATION")
    if "SOURCE_SYNTAX_ANOMALY" in codes:
        actions.add("NORMALIZE_SOURCE_SYNTAX_WITH_TRACE")
    if "LEGACY_PYTHON_SYNTAX" in codes:
        actions.add("PORT_TO_BOUNDED_PYTHON3_PROFILE")
    if "NEGATIVE_DEMONSTRATION" in codes:
        actions.add("PRESERVE_NEGATIVE_SEMANTICS_AS_POSITIVE_ORACLE")
    if "MULTIPLE_VARIANTS_IN_ONE_EXAMPLE" in codes:
        actions.add("SPLIT_VARIANTS_INTO_ASSERTED_SUBCASES")
    if "TERMINAL_OPERATIONS_COLOCATED" in codes:
        actions.add("ISOLATE_TERMINAL_OPERATIONS")
    if "TITLE_BODY_MISMATCH" in codes:
        actions.add("FOLLOW_BODY_OPERATION_AND_RECORD_TITLE_MISMATCH")
    return sorted(actions)


def binding_digest(examples: list[dict[str, Any]]) -> str:
    bindings = [
        {
            "example_number": row["example_number"],
            "compatibility_artifact_id": row["compatibility_artifact_id"],
            "page": row["source"]["page"],
            "body_sha256": row["source"]["body_sha256"],
            "normalized_span_sha256": row["source"]["normalized_span_sha256"],
            "semantic_family": row["semantic_family"],
            "adaptation_id": row["adaptation"]["adaptation_id"],
            "oracle_id": row["oracle"]["oracle_id"],
        }
        for row in examples
    ]
    encoded = json.dumps(
        bindings, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def build(raw_path: Path, inventory_path: Path, ledger_path: Path) -> dict[str, Any]:
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if raw.get("source_sha256") != AUTHORITY_SHA256:
        raise ValueError("raw extraction is not bound to the approved LRM 2.4.4 hash")

    sources = [source for source in inventory["sources"] if source["source_code"] == "LRM244"]
    if len(sources) != 1:
        raise ValueError("expected exactly one LRM244 source inventory record")
    authority = sources[0]
    if authority["source_hash"] != AUTHORITY_SHA256:
        raise ValueError("source inventory LRM244 hash does not match the approved authority")

    inventory_examples = {
        int(re.fullmatch(r"CMP-LRM244-EXAMPLE-(\d{3})", item["ArtifactId"]).group(1)): item
        for item in authority["artifacts"]
        if item["Kind"] == "Example"
    }
    extracted = {item["number"]: item for item in raw["examples"]}
    expected_numbers = set(range(1, 196))
    if set(inventory_examples) != expected_numbers or set(extracted) != expected_numbers:
        raise ValueError("both inputs must contain exactly examples 1 through 195")
    ledger_examples = {
        int(re.fullmatch(r"CMP-LRM244-EXAMPLE-(\d{3})", item["ArtifactId"]).group(1)): item
        for item in ledger["rows"]
        if re.fullmatch(r"CMP-LRM244-EXAMPLE-\d{3}", item["ArtifactId"])
    }
    if set(ledger_examples) != expected_numbers:
        raise ValueError("compatibility ledger must contain exactly examples 1 through 195")

    examples: list[dict[str, Any]] = []
    for number in range(1, 196):
        source_row = extracted[number]
        inventory_row = inventory_examples[number]
        ledger_row = ledger_examples[number]
        expected_public_name = f"Example {number}: {source_row['title']}"
        if inventory_row["PublicName"] != expected_public_name:
            raise ValueError(f"example {number} title differs between extraction and inventory")
        if inventory_row["Pages"] != str(source_row["page"]):
            raise ValueError(f"example {number} page differs between extraction and inventory")
        span_match = re.search(
            r"source-span-sha256=([0-9a-f]{64})", ledger_row["SignatureOrGrammar"]
        )
        if span_match is None:
            raise ValueError(f"example {number} has no normalized source-span hash")

        family = family_for(number)
        defaults = FAMILY_DEFAULTS[family]
        ambiguity_codes = selected(AMBIGUITY_GROUPS, number)
        capabilities = sorted(
            set(defaults["capabilities"]) | set(selected(EXTRA_CAPABILITIES, number))
        )
        effects = sorted(set(defaults["effects"]) | set(selected(EXTRA_EFFECTS, number)))
        examples.append(
            {
                "example_number": number,
                "compatibility_artifact_id": inventory_row["ArtifactId"],
                "display_title": inventory_row["PublicName"],
                "semantic_family": family,
                "required_capabilities": capabilities,
                "source": {
                    "title": inventory_row["PublicName"],
                    "page": source_row["page"],
                    "body_sha256": source_row["body_sha256"],
                    "normalized_span_sha256": span_match.group(1),
                    "body_included": False,
                },
                "adaptation": {
                    "adaptation_id": f"V10-LRM244-EXAMPLE-{number:03d}-ADAPTATION",
                    "disposition": "EXECUTABLE_SEMANTIC_ADAPTATION_REQUIRED",
                    "fixture_profile": FIXTURE_PROFILE,
                    "raw_snippet_executable_claim": False,
                    "normalization_actions": adaptation_actions(ambiguity_codes),
                },
                "ambiguity": {
                    "present": bool(ambiguity_codes),
                    "codes": ambiguity_codes,
                    "resolution": (
                        "Resolve only through the recorded normalization actions; preserve the source span hash and assert the documented semantic effect."
                        if ambiguity_codes
                        else "No source ambiguity identified; add only deterministic fixtures and semantic assertions."
                    ),
                },
                "oracle": {
                    "oracle_id": f"V10-LRM244-EXAMPLE-{number:03d}-ORACLE",
                    "mode": defaults["mode"],
                    "expected_effects": effects,
                    "required_assertion_count": len(effects),
                    "success_criteria": defaults["criteria"],
                },
            }
        )

    return {
        "schema_version": "spell.v10.language-reference-example-matrix/1",
        "contract_id": "V10-LRM244-EXAMPLE-MATRIX",
        "release": "v0.10.0",
        "status": "implementation_and_qualification_input",
        "implementation_claim": False,
        "qualification_result_claim": "NOT_RECORDED_IN_THIS_CONTRACT",
        "purpose": "Bind each numbered Language Reference example to a deterministic executable adaptation and a semantic oracle without claiming that extracted documentation text is standalone executable code.",
        "authority": {
            "source_code": authority["source_code"],
            "title": authority["source_title"],
            "version": authority["source_version"],
            "sha256": authority["source_hash"],
            "page_count": authority["page_count"],
            "reviewed_pages": authority["reviewed_page_slices"],
            "compatibility_inventory_id": inventory["inventory_id"],
            "body_hash_scope": "UTF-8 SHA-256 of the raw extracted per-example layout-text body, including its example heading",
            "normalized_span_hash_scope": "UTF-8 SHA-256 of normalized pypdf-layout text from the exact example body heading to the next example or numbered-section heading on the cited page",
            "body_text_embedded": False,
        },
        "adaptation_policy": {
            "fixture_profile": FIXTURE_PROFILE,
            "raw_examples_executable_claim": False,
            "source_semantics_must_be_preserved": True,
            "source_corrections_require_trace": True,
            "one_result_per_example_required": True,
            "allowed_result_states": ["PASS", "FAIL"],
            "delivery_gate": {
                "required_pass": 195,
                "allowed_fail": 0,
                "allowed_skip": 0,
                "allowed_xfail": 0,
                "allowed_unresolved": 0,
            },
        },
        "example_count": len(examples),
        "example_bindings_sha256": binding_digest(examples),
        "examples": examples,
    }


def encode_contract(payload: dict[str, Any]) -> bytes:
    """Serialize the checked-in contract with platform-independent LF endings."""

    return (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = encode_contract(build(args.raw, args.inventory, args.ledger))
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            raise SystemExit("generated v0.10 reference contract is stale")
        print("v0.10-reference-contract=PASS examples=195 mode=check")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print("v0.10-reference-contract=PASS examples=195 mode=write")


if __name__ == "__main__":
    main()
