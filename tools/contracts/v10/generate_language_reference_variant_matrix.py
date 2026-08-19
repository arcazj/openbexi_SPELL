"""Generate the v0.10 Language Reference variant traceability contract.

The ignored extraction inputs are generation authorities only.  The generated
contract deliberately stores hashes and short classifications, not the manual
bodies or executable source claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


AUTHORITY_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
RAW_EXTRACTION_SHA256 = "543f2c52487aeba19c07710aa4de49eaea39ee8e6697920ea7d3e909158afb73"
EXAMPLE_CHUNKS_SHA256 = "6a551e3ce2f669f1927be2e2c94a230bae66d91203cd87c8d2ca378ae1957283"
MULTIPLE_VARIANT_CODE = "MULTIPLE_VARIANTS_IN_ONE_EXAMPLE"


def variant(
    slug: str,
    classification: str,
    anchor: str,
    trace_operation: str,
) -> tuple[str, str, str, str]:
    return slug, classification, anchor, trace_operation


# These are concise source anchors and classifications, not copies of the
# manual examples.  Each anchor is verified against the pinned raw extraction.
MULTIPLE_VARIANTS: dict[int, tuple[tuple[str, str, str, str], ...]] = {
    29: (
        variant("absolute-time", "DOCUMENTED_VALUE_FORM", "mytime1 = TIME('2006/04/02 20:32:34')", "TimeArithmetic"),
        variant("relative-time", "DOCUMENTED_VALUE_FORM", "mytime2 = TIME('+00:00:30')", "TimeArithmetic"),
        variant("time-fields", "DOCUMENTED_ACCESS_FORM", "mytime1.julianDay()", "TimeArithmetic"),
        variant("time-arithmetic", "DOCUMENTED_EXPRESSION_FORM", "t2 = NOW + 3*HOUR + 20*SECOND", "TimeArithmetic"),
    ),
    56: (
        variant("and-condition", "DOCUMENTED_CALL_FORM", "Verify( AND(", "AND_OR"),
        variant("or-condition", "DOCUMENTED_CALL_FORM", "Verify( OR(", "AND_OR"),
        variant("nested-condition", "DOCUMENTED_CALL_FORM", "OR( ['tm2',eq,-1]", "NestedCondition"),
    ),
    60: (
        variant("command-name", "DOCUMENTED_ARGUMENT_FORM", "Send( command = 'CMDNAME' )", "Send"),
        variant("command-item", "DOCUMENTED_ARGUMENT_FORM", "Send( command = tc_item )", "Send"),
    ),
    61: (
        variant("time-expression", "DOCUMENTED_MODIFIER_FORM", "Time=NOW + 30*MINUTE", "Send"),
        variant("time-string", "DOCUMENTED_MODIFIER_FORM", "Time='2008/04/10 10:30:00'", "Send"),
    ),
    62: (
        variant("release-expression", "DOCUMENTED_MODIFIER_FORM", "ReleaseTime=NOW+30*MINUTE", "Send"),
        variant("release-string", "DOCUMENTED_MODIFIER_FORM", "ReleaseTime='2008/04/10 10:30:00'", "Send"),
    ),
    66: (
        variant("item-embedded-arguments", "DOCUMENTED_ARGUMENT_FORM", "Send( command= tc_item )", "Send"),
        variant("name-explicit-arguments", "PLACEHOLDER_SEMANTIC_ADAPTATION", "Send( command= 'CMDNAME', args=", "Send"),
    ),
    68: (
        variant("string-name-group", "DOCUMENTED_ARGUMENT_FORM", "group = ['CMD1','CMD2','CMD3']", "Send"),
        variant("sequential-monitoring", "DOCUMENTED_BEHAVIOR_SUBCASE", "sent and verified one by one", "Send"),
    ),
    70: (
        variant("command-item-list", "DOCUMENTED_ARGUMENT_FORM", "group = [tc_item1, tc_item2, tc_item3]", "Send"),
        variant("group-modifier", "DOCUMENTED_MODIFIER_FORM", "Group=True", "Send"),
    ),
    74: (
        variant("single-command-delay", "DOCUMENTED_CALL_FORM", "command = tc_item, SendDelay=1*MINUTE", "Send"),
        variant("group-command-delay", "DOCUMENTED_CALL_FORM", "group = [tc_item1,tc_item2,tc_item3]", "Send"),
    ),
    78: (
        variant("numeric-seconds", "DOCUMENTED_ARGUMENT_FORM", "WaitFor( 2 )", "WaitFor"),
        variant("time-unit-expression", "DOCUMENTED_ARGUMENT_FORM", "WaitFor( 2*SECOND )", "WaitFor"),
        variant("relative-time-string", "DOCUMENTED_ARGUMENT_FORM", "WaitFor( '+00:00:02' )", "WaitFor"),
    ),
    82: (
        variant("scalar-interval", "DOCUMENTED_MODIFIER_FORM", "Interval=1*MINUTE", "WaitProgressIntervals"),
        variant("interval-list", "DOCUMENTED_PROSE_VARIANT", "a list of times can be used", "WaitProgressIntervals"),
    ),
    83: (
        variant("hour-interval", "DOCUMENTED_LIST_MEMBER", "1*HOUR", "WaitProgressIntervals"),
        variant("minute-interval", "DOCUMENTED_LIST_MEMBER", "5*MINUTE", "WaitProgressIntervals"),
        variant("second-interval", "DOCUMENTED_LIST_MEMBER", "1*SECOND", "WaitProgressIntervals"),
    ),
    85: (
        variant("select-all-query", "DOCUMENTED_CALL_FORM", "GetLimits( 'PARAM', Select = ALL )", "GetLimits"),
        variant("nested-definition-result", "ILLUSTRATIVE_OUTPUT_ORACLE", "'ID2': {LoRed:y1", "GetLimits"),
    ),
    91: (
        variant("error-field-query", "DOCUMENTED_CALL_FORM", "Value=Error", "GetLimits"),
        variant("error-list-result", "ILLUSTRATIVE_OUTPUT_ORACLE", "[v5,v6,v7]", "GetLimits"),
    ),
    92: (
        variant("lower-red-query", "DOCUMENTED_CALL_FORM", "Value=LoRed", "GetLimits"),
        variant("scalar-result", "ILLUSTRATIVE_OUTPUT_ORACLE", "0.567", "GetLimits"),
    ),
    93: (
        variant("delta-field", "DOCUMENTED_CALL_FORM", "Value=Delta", "GetLimits"),
        variant("midpoint-field", "DOCUMENTED_CALL_FORM", "Value=Midpoint", "GetLimits"),
        variant("tolerance-field", "DOCUMENTED_CALL_FORM", "Value=Tolerance", "GetLimits"),
    ),
    96: (
        variant("active-selection", "DOCUMENTED_MODIFIER_FORM", "Select=ACTIVE", "SetLimits"),
        variant("implicit-selection", "DOCUMENTED_CALL_FORM", "SetLimits( 'PARAM', Definition=mydef )", "SetLimits"),
    ),
    102: (
        variant("enable-alarm", "DOCUMENTED_CALL_FORM", "EnableAlarm( 'PARAM' )", "EnableDisableAlarm"),
        variant("disable-alarm", "DOCUMENTED_CALL_FORM", "DisableAlarm( 'PARAM' )", "EnableDisableAlarm"),
    ),
    108: (
        variant("default-severity", "DOCUMENTED_CALL_FORM", "Display( 'Message' )", "Display"),
        variant("positional-severity", "DOCUMENTED_ARGUMENT_FORM", "Display( 'Message', WARNING )", "Display"),
        variant("keyword-severity", "DOCUMENTED_MODIFIER_FORM", "Severity = ERROR", "Display"),
    ),
    110: (
        variant("default-severity", "DOCUMENTED_CALL_FORM", "Event( 'Message' )", "Event"),
        variant("positional-severity", "DOCUMENTED_ARGUMENT_FORM", "Event( 'Message', WARNING )", "Event"),
        variant("keyword-severity", "DOCUMENTED_MODIFIER_FORM", "Severity = ERROR", "Event"),
    ),
    114: (
        variant("ok-prompt", "DOCUMENTED_CALL_FORM", "Prompt( 'Message', OK )", "Prompt"),
        variant("list-prompt", "DOCUMENTED_PROSE_VARIANT", "custom list of options", "Prompt"),
    ),
    121: (
        variant("display-host", "DOCUMENTED_CALL_FORM", "OpenDisplay( 'Display name', Host='hostname' )", "OpenDisplay"),
        variant("workspace-host", "DOCUMENTED_CALL_FORM", "OpenWorkspace( 'Workspace name', Host='hostname' )", "OpenWorkspace"),
    ),
    122: (
        variant("display-monitor", "DOCUMENTED_CALL_FORM", "OpenDisplay( 'Display name', Monitor=1 )", "OpenDisplay"),
        variant("workspace-monitor", "DOCUMENTED_CALL_FORM", "OpenWorkspace( 'Workspace name', Monitor=1 )", "OpenWorkspace"),
    ),
    124: (
        variant("printer-selection", "DOCUMENTED_MODIFIER_FORM", "Printer='name'", "PrintDisplay"),
        variant("format-selection", "DOCUMENTED_PROSE_VARIANT", "Format modifier", "PrintDisplay"),
    ),
    131: (
        variant("pause", "TERMINAL_OPERATION_ISOLATED_ADAPTATION", "Pause()", "ProcedureControlStates"),
        variant("abort", "TERMINAL_OPERATION_ISOLATED_ADAPTATION", "Abort('Aborting the procedure')", "ProcedureControlStates"),
        variant("finish", "TERMINAL_OPERATION_ISOLATED_ADAPTATION", "Finish('Procedure finished successfully')", "ProcedureControlStates"),
    ),
    132: (
        variant("default-severity", "DOCUMENTED_CALL_FORM", "SetUserAction(function, 'Label')", "SetUserAction"),
        variant("warning-severity", "DOCUMENTED_MODIFIER_FORM", "Severity=WARNING", "SetUserAction"),
    ),
    133: (
        variant("enable-action", "DOCUMENTED_CALL_FORM", "EnableUserAction()", "EnableDisableUserAction"),
        variant("disable-action", "DOCUMENTED_CALL_FORM", "DisableUserAction()", "EnableDisableUserAction"),
    ),
    152: (
        variant("bus-priority", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Bus/", "ProcedureLibrary"),
        variant("payload-priority", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Payload/", "ProcedureLibrary"),
        variant("validation-priority", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Validation/", "ProcedureLibrary"),
    ),
    153: (
        variant("bus-candidate", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Bus/", "ProcedureLibrary"),
        variant("validation-winner", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Validation/procedure", "ProcedureLibrary"),
    ),
    159: (
        variant("manual-mode", "DOCUMENTED_MODIFIER_FORM", "Automatic=False", "StartProc"),
        variant("visible-mode", "DOCUMENTED_MODIFIER_FORM", "Visible=True", "StartProc"),
        variant("nonblocking-mode", "DOCUMENTED_MODIFIER_FORM", "Blocking=False", "StartProc"),
    ),
    162: (
        variant("read-write-mode", "PLACEHOLDER_SEMANTIC_ADAPTATION", "Mode=READ_WRITE", "OpenFile"),
        variant("relative-sandbox-path", "DOCUMENTED_BEHAVIOR_SUBCASE", "file path shall be relative", "OpenFile"),
    ),
    164: (
        variant("single-string", "PSEUDOCODE_SEMANTIC_ADAPTATION", "WriteFile( handle, 'string' )", "WriteFile"),
        variant("string-list", "PSEUDOCODE_SEMANTIC_ADAPTATION", "WriteFile( handle, ['string1','string2'] )", "WriteFile"),
    ),
    166: (
        variant("directory-handle", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ReadDirectory( handle )", "ReadDirectory"),
        variant("directory-string", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ReadDirectory( string )", "ReadDirectory"),
    ),
    167: (
        variant("file-constructor", "DOCUMENTED_CALL_FORM", "f = File( 'path' )", "File"),
        variant("file-introspection", "ILLUSTRATIVE_OUTPUT_ORACLE", "f.filename()", "File"),
    ),
    168: (
        variant("path-delete", "DOCUMENTED_ARGUMENT_FORM", "DeleteFile( 'path' )", "DeleteFile"),
        variant("file-object-delete", "PLACEHOLDER_SEMANTIC_ADAPTATION", "DeleteFile( <file object> )", "DeleteFile"),
    ),
    169: (
        variant("enable-ranging", "PSEUDOCODE_SEMANTIC_ADAPTATION", "EnableRanging()", "EnableDisableRanging"),
        variant("disable-ranging", "PSEUDOCODE_SEMANTIC_ADAPTATION", "DisableRanging()", "EnableDisableRanging"),
    ),
    173: (
        variant("single-config-set", "PSEUDOCODE_SEMANTIC_ADAPTATION", "SetBasebandConfig( 'BBE', 'NAME', 'VALUE')", "SetGetBasebandConfig"),
        variant("config-list-set", "PSEUDOCODE_SEMANTIC_ADAPTATION", "SetBasebandConfig( 'BBE',", "SetGetBasebandConfig"),
        variant("config-get", "PSEUDOCODE_SEMANTIC_ADAPTATION", "GetBasebandConfig( 'BBE', 'NAME'", "SetGetBasebandConfig"),
    ),
    174: (
        variant("baseband-names", "PSEUDOCODE_SEMANTIC_ADAPTATION", "GetBasebandNames()", "GetRangingEquipment"),
        variant("antenna-names", "PSEUDOCODE_SEMANTIC_ADAPTATION", "GetAntennaNames()", "GetRangingEquipment"),
    ),
    177: (
        variant("pair-list", "PLACEHOLDER_SEMANTIC_ADAPTATION", "SetSharedData( ['NAME', <value>] )", "SetSharedData"),
        variant("modifier-form", "DOCUMENTED_PROSE_VARIANT", "syntax based on modifiers", "SetSharedData"),
    ),
    179: (
        variant("first-list-item", "PSEUDOCODE_SEMANTIC_ADAPTATION", "SetSharedData( [[ 'NAME', <value> ]", "SetSharedData"),
        variant("multiple-results", "ILLUSTRATIVE_OUTPUT_ORACLE", "[True/False", "SetSharedData"),
    ),
    182: (
        variant("positional-test-set", "PLACEHOLDER_SEMANTIC_ADAPTATION", "SetSharedData( ['NAME', <value>, <expected>] )", "TestAndSetSharedData"),
        variant("modifier-test-set", "PLACEHOLDER_SEMANTIC_ADAPTATION", "Expected=<expected>", "TestAndSetSharedData"),
    ),
    183: (
        variant("successful-item", "PSEUDOCODE_SEMANTIC_ADAPTATION", "SetSharedData( [[ 'NAME', <value>, <expected> ]", "TestAndSetSharedData"),
        variant("failed-item", "DOCUMENTED_BEHAVIOR_SUBCASE", "flag is set to False", "TestAndSetSharedData"),
    ),
    187: (
        variant("scoped-keys", "PSEUDOCODE_SEMANTIC_ADAPTATION", "GetSharedDataKeys( Scope='scope' )", "GetSharedDataInformation"),
        variant("scope-list", "PSEUDOCODE_SEMANTIC_ADAPTATION", "GetSharedDataScopes()", "GetSharedDataInformation"),
    ),
    188: (
        variant("clear-global", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedData()", "ClearSharedData"),
        variant("clear-name", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedData( 'NAME' )", "ClearSharedData"),
        variant("clear-name-list", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedData( ['NAME','NAME'", "ClearSharedData"),
        variant("clear-scoped-name", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedData( 'NAME', Scope='scope' )", "ClearSharedData"),
        variant("clear-scoped-all", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedData( Scope='scope' )", "ClearSharedData"),
    ),
    189: (
        variant("clear-all-scopes", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedDataScopes()", "ClearSharedDataScopes"),
        variant("positional-scope", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedDataScopes( 'scope' )", "ClearSharedDataScopes"),
        variant("keyword-scope", "PSEUDOCODE_SEMANTIC_ADAPTATION", "ClearSharedDataScopes( Scope='scope' )", "ClearSharedDataScopes"),
    ),
    192: (
        variant("complete-image-comparison", "PSEUDOCODE_SEMANTIC_ADAPTATION", "Image = ['image1','image2']", "CompareMemoryImages"),
        variant("filtered-comparison", "DOCUMENTED_PROSE_VARIANT", "modifiers Type, Source, Begin and End", "CompareMemoryImages"),
    ),
}


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def default_classification(ambiguity_codes: Iterable[str]) -> str:
    codes = set(ambiguity_codes)
    if "NEGATIVE_DEMONSTRATION" in codes:
        return "NEGATIVE_DEMONSTRATION_ADAPTATION"
    if "OUTPUT_OR_DATA_ONLY" in codes or "ILLUSTRATIVE_OUTPUT_MIXED_WITH_CODE" in codes:
        return "ILLUSTRATIVE_OUTPUT_ORACLE"
    if codes & {"PLACEHOLDER_OR_ELLIPSIS", "SOURCE_SYNTAX_ANOMALY", "LEGACY_PYTHON_SYNTAX"}:
        return "SEMANTIC_ADAPTATION"
    return "DOCUMENTED_SEMANTIC_CASE"


def binding_digest(rows: list[dict[str, Any]]) -> str:
    bindings = []
    for row in rows:
        bindings.append(
            {
                "example_number": row["example_number"],
                "artifact_id": row["artifact_id"],
                "body_sha256": row["source"]["body_sha256"],
                "normalized_span_sha256": row["source"]["normalized_span_sha256"],
                "classification": row["classification"],
                "variants": row["variants"],
            }
        )
    return digest(json.dumps(bindings, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


def build(raw_path: Path, chunks_path: Path, example_matrix_path: Path) -> dict[str, Any]:
    raw_bytes = raw_path.read_bytes()
    chunks_bytes = chunks_path.read_bytes()
    if hashlib.sha256(raw_bytes).hexdigest() != RAW_EXTRACTION_SHA256:
        raise ValueError("raw extraction bytes differ from the pinned generation authority")
    if hashlib.sha256(chunks_bytes).hexdigest() != EXAMPLE_CHUNKS_SHA256:
        raise ValueError("example chunk bytes differ from the pinned generation authority")
    raw = json.loads(raw_bytes.decode("utf-8"))
    matrix = json.loads(example_matrix_path.read_text(encoding="utf-8"))
    if raw.get("source_sha256") != AUTHORITY_SHA256:
        raise ValueError("raw extraction is not bound to the approved LRM 2.4.4 hash")
    if matrix.get("authority", {}).get("sha256") != AUTHORITY_SHA256:
        raise ValueError("example matrix is not bound to the approved LRM 2.4.4 hash")
    raw_rows = {row["number"]: row for row in raw.get("examples", [])}
    matrix_rows = {row["example_number"]: row for row in matrix.get("examples", [])}
    expected = set(range(1, 196))
    if set(raw_rows) != expected or set(matrix_rows) != expected:
        raise ValueError("variant inputs must contain exactly examples 1 through 195")
    multiple_in_matrix = {
        number
        for number, row in matrix_rows.items()
        if MULTIPLE_VARIANT_CODE in row["ambiguity"]["codes"]
    }
    if multiple_in_matrix != set(MULTIPLE_VARIANTS) or len(multiple_in_matrix) != 46:
        raise ValueError("variant definitions must match the 46 source-classified examples")
    chunks = chunks_bytes.decode("utf-8")

    rows: list[dict[str, Any]] = []
    total_variants = 0
    for number in range(1, 196):
        source = raw_rows[number]
        contract = matrix_rows[number]
        body = source["body"]
        normalized_body = normalize(body)
        if digest(body) != source["body_sha256"]:
            raise ValueError(f"example {number} raw body hash is invalid")
        if source["body_sha256"] != contract["source"]["body_sha256"]:
            raise ValueError(f"example {number} body hash differs from the example matrix")
        if f"===== {number} =====" not in chunks or f"Example {number}:" not in chunks:
            raise ValueError(f"example {number} is absent from the chunk authority")

        ambiguity_codes = contract["ambiguity"]["codes"]
        definitions = MULTIPLE_VARIANTS.get(number)
        if definitions is None:
            definitions = (
                (
                    "semantic-case",
                    default_classification(ambiguity_codes),
                    f"Example {number}: {source['title']}",
                    "PRIMARY_SEMANTIC_TRACE",
                ),
            )
        variants: list[dict[str, Any]] = []
        for ordinal, (slug, classification, anchor, trace_operation) in enumerate(definitions, 1):
            normalized_anchor = normalize(anchor)
            occurrences = normalized_body.count(normalized_anchor)
            if occurrences < 1:
                raise ValueError(
                    f"example {number} variant {ordinal} anchor is absent from the raw body"
                )
            prefix = f"V10-LRM244-EXAMPLE-{number:03d}-VARIANT-{ordinal:02d}"
            variants.append(
                {
                    "variant_id": prefix,
                    "subcase_id": f"V10-LRM244-EXAMPLE-{number:03d}-SUBCASE-{ordinal:02d}",
                    "slug": slug,
                    "classification": classification,
                    "source_anchor_sha256": digest(normalized_anchor),
                    "source_anchor_occurrences": occurrences,
                    "raw_snippet_executable_claim": False,
                    "adapter_id": f"{prefix}-ADAPTER",
                    "oracle_id": f"{prefix}-ORACLE",
                    "test_id": f"{prefix}-TEST",
                    "required_assertion_id": f"variant.example_{number:03d}.subcase_{ordinal:02d}",
                    "required_trace_operation": trace_operation,
                }
            )
        total_variants += len(variants)
        rows.append(
            {
                "example_number": number,
                "artifact_id": contract["compatibility_artifact_id"],
                "classification": (
                    "MULTIPLE_DOCUMENTED_VARIANTS"
                    if number in MULTIPLE_VARIANTS
                    else "SINGLE_DOCUMENTED_SEMANTIC_CASE"
                ),
                "source": {
                    "page": source["page"],
                    "body_sha256": source["body_sha256"],
                    "normalized_span_sha256": contract["source"]["normalized_span_sha256"],
                    "body_included": False,
                },
                "adaptation_id": contract["adaptation"]["adaptation_id"],
                "example_oracle_id": contract["oracle"]["oracle_id"],
                "ambiguity_codes": ambiguity_codes,
                "variant_count": len(variants),
                "variants": variants,
            }
        )

    return {
        "schema_version": "spell.v10.language-reference-variant-matrix/1",
        "contract_id": "V10-LRM244-VARIANT-MATRIX",
        "release": "v0.10.0",
        "authority": {
            "source_sha256": AUTHORITY_SHA256,
            "raw_extraction_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "example_chunks_sha256": hashlib.sha256(chunks_bytes).hexdigest(),
            "body_text_embedded": False,
        },
        "execution_policy": {
            "raw_snippet_execution_claim": False,
            "semantic_adaptation_required": True,
            "passed_assertion_per_variant_required": True,
            "trace_event_per_variant_required": True,
            "distinct_evidence_within_multiple_variant_examples_required": True,
        },
        "example_count": len(rows),
        "multiple_variant_example_count": len(MULTIPLE_VARIANTS),
        "variant_count": total_variants,
        "variant_bindings_sha256": binding_digest(rows),
        "examples": rows,
    }


def encode_contract(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--chunks", type=Path, required=True)
    parser.add_argument("--example-matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = encode_contract(build(args.raw, args.chunks, args.example_matrix))
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            raise SystemExit("generated v0.10 variant contract is stale")
        print("v0.10-variant-contract=PASS examples=195 multiple=46 mode=check")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print("v0.10-variant-contract=PASS examples=195 multiple=46 mode=write")


if __name__ == "__main__":
    main()
