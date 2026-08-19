from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pypdf
from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[3]
CATALOG = ROOT / "var" / "compat_catalog" / "lrm244.json"
PDF = ROOT / "SPELL-DOCUMENTATION" / "SPELL - Language Reference - 2.4.4.pdf"
PDF_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
PYPDF_VERSION = "6.14.2"
SOURCE_TITLE = "SPELL Language Reference"
SOURCE_VERSION = "2.4.4"

REQUIRED_COLUMNS = [
    "ArtifactId", "Kind", "PublicName", "SourceTitle", "SourceVersion",
    "SourceHash", "Pages", "SignatureOrGrammar", "LegacyInputs",
    "LegacyResult", "LegacyOrdering", "LegacyErrors", "EffectClass",
    "ModernBehavior", "Disposition", "Diagnostic", "DriverCapability",
    "Persistence", "Recovery", "SecurityConstraints", "TargetIncrement",
    "TestVectors", "Decision", "Approvers", "Status",
]

ALLOWED_EFFECTS = {
    "NONE", "READ", "EXTERNAL_EFFECT", "LOCAL_MUTATION", "CONTROL_STATE",
    "OPERATOR_DECISION", "PRESENTATION", "CONFIGURATION", "UNCLASSIFIED",
}

APPENDIX_MODIFIERS = {
    "AdjLimits", "Automatic", "Begin", "Block", "Blocking", "Confirm",
    "Default", "Delay", "End", "Extended", "Expected", "HandleError",
    "HiBoth", "HiRed", "HiYel", "Host", "IgnoreCase", "Image", "Interval",
    "LoadOnly", "LoBoth", "LoRed", "LoYel", "Message", "Midpoint", "Mode",
    "Monitor", "Name", "Notify", "OnFailure", "OnTrue", "OnFalse",
    "Printer", "PromptUser", "Range", "Radix", "Retries", "SendDelay",
    "Severity", "Source", "Time", "Timeout", "Tolerance", "Type", "Units",
    "Until", "Value", "ValueFormat", "ValueType", "Visible", "Wait",
    "FailureCode", "PromptFailure",
}

AMBIGUOUS_IDS = {
    "LRM244-FUNCTION-CANDIDATE-COMPAREMEMORYIMAGES",
    "LRM244-FUNCTION-CANDIDATE-CLEARSHAREDDATASCOPE",
}

APPENDIX_SECTION_ERRATA = {
    "DisplayStep": "Appendix A cites nonexistent section 1.1.1; the body documents DisplayStep under 4.14 on page 76.",
    "DisableAlarm": "Appendix A cites section 0; the body documents DisableAlarm under 4.8.6 on page 66.",
    "EnableAlarm": "Appendix A cites section 0; the body documents EnableAlarm under 4.8.6 on page 66.",
    "CloseFile": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "DeleteFile": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "OpenFile": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "ReadDirectory": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "ReadFile": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "WriteFile": "Appendix A cites 4.18; the body documents file operations under 4.17.",
    "AbortRanging": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "DisableRanging": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "EnableRanging": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "GetAntennaNames": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "GetBasebandConfig": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "GetBasebandNames": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "GetRangingStatus": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "SetBasebandConfig": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "StartRangingCalibration": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "StartRanging": "Appendix A cites 4.19; the body documents ranging under 4.18.",
    "AddSharedDataScope": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "ClearSharedData": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "ClearSharedDataScopes": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "GetSharedData": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "GetSharedDataKeys": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "GetSharedDataScopes": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "SetSharedData": "Appendix A cites 4.20; the body documents shared data under 4.19.",
    "CompareMemoryImage": "Appendix A cites 4.21 and a singular name; the body documents CompareMemoryImages under 4.20.",
    "GenerateMemoryReport": "Appendix A cites 4.21; the body documents memory operations under 4.20.",
    "MemoryLookup": "Appendix A cites 4.21; the body documents memory operations under 4.20.",
    "TMTCLookup": "Appendix A cites nonexistent 4.22; the body documents TMTCLookup under 4.21.",
}

EXAMPLE_ERRATA = {
    4: "The page 15 narrative says slash while the title and code use backslash.",
    7: "The page 17 prose calls the final list value a text-file object.",
    26: "The page 33 comment says a value assigned from NOW before the loop changes each iteration; example 27 presents the opposite workaround.",
    27: "The NOW-loop explanation on page 33 conflicts with example 26 and needs an oracle before future adoption.",
    55: "The title says command construction, but the body introduces AND telemetry expressions.",
    56: "The title says command construction, but the body contains AND/OR Verify expressions.",
    163: "The title says opening a file, but the body calls CloseFile.",
    189: "The prose names singular ClearSharedDataScope while the example calls plural ClearSharedDataScopes.",
}

TYPE_RENAMES = {
    "LRM244-TYPE-TELEMETRYITEM": ("telemetry item object", "Extended GetTM telemetry item object; the source states no public class name"),
    "LRM244-TYPE-VERIFYRESULT": ("Verify composite object", "Verify composite dictionary-like result; the source states no public class name"),
    "LRM244-TYPE-TELECOMMANDITEM": ("TC item", "BuildTC telecommand item; the source states no public class name"),
    "LRM244-TYPE-HANDLEEXCEPTION": ("Handle exception object", "Procedure-level Handle exception object named by Appendix D"),
    "LRM244-TYPE-FILEHANDLE": ("file handler", "File handler returned by OpenFile; the source states no public class name"),
    "LRM244-TYPE-DATABASEDICTIONARY": ("Python dictionary database", "Database represented as a normal Python dictionary"),
    "LRM244-TYPE-PRIMITIVESHAREDVALUE": ("primitive shared-data value", "Primitive value accepted by the shared-data service"),
    "LRM244-TYPE-LIMITDEFINITION": ("OOL definition dictionary", "Dictionary representation of an out-of-limit definition"),
    "LRM244-TYPE-PROMPTRESULT": ("Prompt return value", "Prompt answer or default value; the source states no distinct result class"),
}

CONTEXTUAL_CONSTANT_NAMES = {
    "LRM244-CONSTANT-ACTION-CANCEL": "CANCEL (action)",
    "LRM244-CONSTANT-PROMPT-TYPE-CANCEL": "CANCEL (prompt type)",
    "LRM244-CONSTANT-SEVERITY-ERROR": "ERROR (severity)",
    "LRM244-CONSTANT-RANGING-STATE-ERROR": "ERROR (ranging state)",
}

TECHNICAL_CANDIDATE_APPROVER = (
    "TECHNICAL_SOURCE_CANDIDATE; no artifact-row approval claimed or required."
)

REMOVED_ARTIFACT_IDS = {
    "LRM244-CONSTANT-EXECUTION-STATE-PAUSED",
    "LRM244-CONSTANT-EXECUTION-STATE-RUNNING",
    "LRM244-CONSTANT-SCOPE-ARGS",
    "LRM244-CONSTANT-SCOPE-GDB",
    "LRM244-CONSTANT-SCOPE-INPUT-DATA",
    "LRM244-CONSTANT-SCOPE-IVARS",
    "LRM244-CONSTANT-SCOPE-OUTPUT-DATA",
    "LRM244-CONSTANT-SCOPE-PROC",
    "LRM244-CONSTANT-SCOPE-SCDB",
    "LRM244-TYPE-PROCEDUREHANDLE",
}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_text(value: str) -> str:
    return " ".join(value.split())


def parse_pages(spec: str) -> list[int]:
    pages: list[int] = []
    for token in (part.strip() for part in spec.split(",")):
        if "-" in token:
            start, end = (int(part) for part in token.split("-", 1))
            if start > end:
                raise ValueError(f"descending page range: {token}")
            pages.extend(range(start, end + 1))
        else:
            pages.append(int(token))
    return pages


def page_set_digest(layout_pages: list[str], spec: str) -> str:
    normalized = "\f".join(normalize_text(layout_pages[page - 1]) for page in parse_pages(spec))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def example_span(layout_pages: list[str], number: int, page: int, expected_title: str) -> tuple[str, str]:
    text = layout_pages[page - 1]
    marker = re.compile(rf"^[ \t]*Example\s+{number}:\s*(.*?)[ \t]*$", re.MULTILINE)
    matches = list(marker.finditer(text))
    if len(matches) != 1:
        raise ValueError(f"Example {number}: expected one page-{page} body marker, found {len(matches)}")
    found_title = normalize_text(matches[0].group(1))
    if found_title != expected_title:
        raise ValueError(f"Example {number}: body title {found_title!r} != {expected_title!r}")
    next_boundary = re.compile(r"^[ \t]*(?:Example\s+\d+:|\d+(?:\.\d+)+\s+\S)", re.MULTILINE)
    boundary = next_boundary.search(text, matches[0].end())
    end = boundary.start() if boundary else len(text)
    normalized = normalize_text(text[matches[0].start():end])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest(), found_title


def standard_row(
    artifact_id: str,
    kind: str,
    public_name: str,
    pages: str,
    signature: str,
    legacy_inputs: str,
    legacy_result: str,
    effect: str,
    decision: str,
) -> dict[str, str]:
    row = {
        "ArtifactId": artifact_id,
        "Kind": kind,
        "PublicName": public_name,
        "SourceTitle": SOURCE_TITLE,
        "SourceVersion": SOURCE_VERSION,
        "SourceHash": PDF_SHA256,
        "Pages": pages,
        "SignatureOrGrammar": signature,
        "LegacyInputs": legacy_inputs,
        "LegacyResult": legacy_result,
        "LegacyOrdering": "Source order is cited but has not been exercised by a controlled fixture.",
        "LegacyErrors": "Failure and edge semantics remain source-decomposition work under OD-008; no fixture result exists.",
        "EffectClass": effect,
        "ModernBehavior": "Excluded from the v0.4 Candidate A simulator gate; no new v0.4 language behavior is authorized. Any future behavior needs a separately approved compatibility gate.",
        "Disposition": "EXCLUDE",
        "Diagnostic": "SPELL-V04-LANGUAGE-DEFERRED",
        "DriverCapability": f"NOT_ADVERTISED_V0.4; future={artifact_id.lower()}",
        "Persistence": "Candidate catalog metadata only; no new v0.4 runtime or durable state.",
        "Recovery": "No new v0.4 recovery behavior is authorized by this row.",
        "SecurityConstraints": "Procedure source and derived language IR must not enter the v0.4 synthetic simulator driver boundary.",
        "TargetIncrement": "Deferred",
        "TestVectors": f"LRM244-TV-{artifact_id.removeprefix('LRM244-')}; planned-only; no fixture execution or result recorded.",
        "Decision": decision,
        "Approvers": TECHNICAL_CANDIDATE_APPROVER,
        "Status": "Decomposed",
    }
    assert list(row) == REQUIRED_COLUMNS
    return row


def added_rows() -> list[dict[str, str]]:
    rows = [
        standard_row(
            "LRM244-METHOD-DICTIONARY-HAS-KEY", "Method", "dict.has_key", "79",
            "Python dictionary has_key(key) method",
            "A database dictionary and candidate key.",
            "Returns whether the key exists; this is legacy Python syntax and remains deferred.",
            "READ", "OD-008: page 79 and example 137 source the legacy has_key method; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-CONSTANT-EXECUTION-STATE-ERROR", "Constant", "ERROR (child-procedure state)", "88",
            "Child-procedure terminal state ERROR",
            "A blocking StartProc child reaches an error terminal state.",
            "The parent resumes and StartProc fails/prompts as described on page 88.",
            "CONTROL_STATE", "OD-008: contextual ERROR state is distinct from severity and ranging ERROR tokens; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OPERATOR-STRING-CONCAT", "Operator", "string + string", "21",
            "String concatenation operator +", "Two strings.", "Concatenated string.", "NONE",
            "OD-008: source-grounded operator overload; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OPERATOR-TIME-ADD", "Operator", "TIME + TIME", "34-35",
            "TIME addition operator +", "Two compatible TIME values.", "A TIME result.", "NONE",
            "OD-008: source-grounded operator overload; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OPERATOR-TIME-SUBTRACT", "Operator", "TIME - TIME", "34-35",
            "TIME subtraction operator -", "Two compatible TIME values.", "A TIME result.", "NONE",
            "OD-008: source-grounded operator overload; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OPERATOR-TIME-MULTIPLY", "Operator", "TIME * integer", "34-35",
            "Relative TIME multiplication operator *", "A relative TIME and integer.", "A relative TIME result.", "NONE",
            "OD-008: source-grounded operator overload; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OPERATOR-FILE-PATH-APPEND", "Operator", "File + path", "92",
            "File path-append operator +", "A File object and relative path component.", "An updated File object.", "NONE",
            "OD-008: source-grounded File overload; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-URI-LIMITS", "Syntax", "limits://name_of_file", "67",
            "URI grammar=limits://name_of_file", "A configured limits resource name.", "A source-owned limits resource locator.", "CONFIGURATION",
            "OD-008: source-grounded URI grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-URI-MMD", "Syntax", "mmd://folder/name", "79",
            "URI grammar=mmd://folder/name", "A manoeuvre database folder and name.", "A source-owned manoeuvre database locator.", "READ",
            "OD-008: source-grounded URI grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-URI-USR", "Syntax", "usr://folder/name", "81-82",
            "URI grammar=usr://folder/name", "A user-database folder and name.", "A source-owned user database locator.", "LOCAL_MUTATION",
            "OD-008: source-grounded URI grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-URI-MEM", "Syntax", "mem://report", "100",
            "URI grammar=mem://report", "A memory-report destination name.", "A source-owned memory-report locator.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded URI grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OUTCOME-STARTPROC-TRUE", "Outcome", "StartProc returns True", "89",
            "StartProc Boolean return outcome", "A child is successfully executed in blocking mode or loaded in non-blocking mode.",
            "True.", "CONTROL_STATE",
            "OD-008: page 89 contradicts any inferred procedure-handle result; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-TYPE-TELEMETRY-EXPRESSION", "Type", "telemetry expression object", "46-47",
            "AND/OR telemetry expression object; the source states no public class name",
            "Nested AND/OR telemetry conditions.", "An expression object accepted by Verify.", "NONE",
            "OD-008: descriptive source category only, not an inferred public class; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-INTEGER-HEXADECIMAL", "Syntax", "0xFF", "83",
            "Hexadecimal integer grammar=0x...", "Hexadecimal digits.", "A Python integer value.", "NONE",
            "OD-008: source-grounded database literal grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-INTEGER-OCTAL", "Syntax", "035", "83",
            "Legacy octal integer grammar=0...", "Octal digits.", "A Python integer value.", "NONE",
            "OD-008: source-grounded legacy database literal grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-SYNTAX-INTEGER-BINARY", "Syntax", "0b101001", "83-84",
            "Binary integer grammar=0b...", "Binary digits.", "A Python integer value.", "NONE",
            "OD-008: source-grounded database literal grammar; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-CONSTANT-LIMIT-TYPE-STEP", "Constant", "STEP (limit type)", "61, 66",
            "Limit-type symbolic value STEP",
            "A limit-definition operation whose Type or model is STEP.",
            "Selects the source-described step limit model.", "CONFIGURATION",
            "OD-008: STEP is a limit-type token on pages 61 and 66, distinct from the WaitFor STEP command and PROC key; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-CONTROL-WAITFOR-INTERRUPT", "Control", "INTERRUPT", "57",
            "WaitFor command button INTERRUPT",
            "A procedure executing a WaitFor statement.",
            "Interrupts the WaitFor statement and places the procedure in INTERRUPTED state.", "CONTROL_STATE",
            "OD-008: source-grounded WaitFor operator control; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-CONTROL-WAITFOR-STEP", "Control", "STEP (WaitFor command)", "57",
            "STEP command from INTERRUPTED WaitFor state",
            "A WaitFor statement in INTERRUPTED state.",
            "Resumes the countdown or telemetry check.", "CONTROL_STATE",
            "OD-008: contextual WaitFor STEP command is distinct from the STEP limit type and PROC key; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-CONTROL-WAITFOR-SKIP", "Control", "SKIP (WaitFor command)", "57",
            "SKIP command from INTERRUPTED WaitFor state",
            "A WaitFor statement in INTERRUPTED state.",
            "Aborts the countdown or telemetry check; the source says the procedure ends in PAUSE state.", "CONTROL_STATE",
            "OD-008: contextual WaitFor SKIP command is distinct from the SKIP result-action token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-STATE-WAITFOR-INTERRUPTED", "State", "INTERRUPTED", "57",
            "WaitFor execution state INTERRUPTED",
            "A WaitFor statement interrupted with the INTERRUPT command.",
            "Telemetry checks or the time countdown are held pending STEP or SKIP.", "CONTROL_STATE",
            "OD-008: source-grounded WaitFor state; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-STATE-WAITFOR-PAUSE", "State", "PAUSE", "57",
            "WaitFor terminal state PAUSE",
            "A WaitFor statement has been interrupted, followed by any documented user action.",
            "The source says the procedure ends in PAUSE state.", "CONTROL_STATE",
            "OD-008: source-grounded WaitFor state; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-STATE-WAITFOR-WAITING", "State", "WAITING", "58",
            "WaitFor execution state WAITING",
            "An interrupted WaitFor procedure is put into WAITING state again.",
            "Resumes the condition check without changing the original target time.", "CONTROL_STATE",
            "OD-008: source-grounded WaitFor state; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-OUTCOME-WAIT-ABORT", "Outcome", "WaitFor interrupted then skipped", "57",
            "WaitFor transition=INTERRUPT -> INTERRUPTED -> SKIP -> PAUSE",
            "An active WaitFor is interrupted and the SKIP command is selected.",
            "Aborts the countdown or telemetry check; the source says the procedure ends in PAUSE state.", "CONTROL_STATE",
            "OD-008: source-grounded WaitFor control outcome; no OnFalse behavior is inferred; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-ARGS", "KeywordArgument", "args", "48, 51, 55, 89",
            "Lower-case keyword forms BuildTC(..., args=[...]), Send(..., args=[...]), and StartProc(..., args=[...])",
            "A source-described list of telecommand or child-procedure argument definitions.",
            "Configures arguments for the named call; cross-call runtime semantics remain unaccepted.", "CONFIGURATION",
            "OD-008: source-grounded lower-case keyword argument; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-COMMAND", "KeywordArgument", "command", "49-55",
            "Lower-case Send(command=command-name-or-item, ...) form",
            "A command name string or telecommand item.",
            "Selects the single command passed to Send.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded named Send form; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-SEQUENCE", "KeywordArgument", "sequence", "51",
            "Lower-case Send(sequence=sequence-name) form",
            "A command-sequence name.",
            "Selects the sequence passed to Send.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded named Send form; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-GROUP", "KeywordArgument", "group", "51-53",
            "Lower-case Send(group=[command-or-item, ...], ...) form",
            "A list of command names or telecommand items; distinct from the uppercase Group modifier.",
            "Selects the command list passed to Send.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded named Send form distinct from Group; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-ADDINFO", "KeywordArgument", "addInfo", "53",
            "Lower-case Send(..., addInfo={...}) form",
            "A Python dictionary containing arbitrary driver-dependent information required by the GCS.",
            "Passes platform-specific command-injection information to the driver boundary.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded driver-specific named Send argument; contents are not generalized or accepted; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-KEYWORD-ARGUMENT-VERIFY", "KeywordArgument", "verify", "54-55",
            "Lower-case Send(..., verify=[telemetry-condition, ...]) form",
            "A source-described telemetry verification condition list.",
            "Requests telemetry verification after command execution within Send.", "EXTERNAL_EFFECT",
            "OD-008: source-grounded named Send form; EXCLUDE/Deferred review remains pending.",
        ),
    ]
    time_directives = [
        ("DAY", "%d", "days"),
        ("MONTH-ABBREVIATED", "%b", "months in three-letter representation"),
        ("MONTH-NUMERIC", "%m", "months in two-digit representation"),
        ("YEAR", "%Y", "years in four-digit representation"),
        ("HOUR", "%H", "hours in two-digit representation"),
        ("MINUTE", "%M", "minutes in two-digit representation"),
        ("SECOND", "%S", "seconds in two-digit representation"),
    ]
    for suffix, directive, description in time_directives:
        rows.append(standard_row(
            f"LRM244-SYNTAX-TIME-OUTPUT-{suffix}", "Syntax", directive, "35",
            f"TIME output-format directive {directive}",
            "A TIME output format string.", description, "NONE",
            "OD-008: source-grounded TIME output directive; EXCLUDE/Deferred review remains pending.",
        ))
    rows.extend([
        standard_row(
            "LRM244-DATA-CONTAINER-ARGS", "DataContainer", "ARGS", "86, 89",
            "Predefined global data container ARGS",
            "Procedure arguments supplied to StartProc through args.",
            "A source-described editable typed-variable container for procedure arguments.", "LOCAL_MUTATION",
            "OD-008: ARGS is a predefined global data container, not a scope token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-DATA-CONTAINER-IVARS", "DataContainer", "IVARS", "86",
            "Predefined global data container IVARS",
            "Internal typed variables for the executing procedure.",
            "A source-described editable typed-variable container.", "LOCAL_MUTATION",
            "OD-008: IVARS is a predefined global data container, not a scope token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-DATABASE-GDB", "Database", "GDB", "69, 80",
            "Global ground-system mapping database GDB",
            "A generic GCS configuration name used as a dictionary key.",
            "Returns the mapped GCS name or value used by procedure code.", "READ",
            "OD-008: GDB is a ground-system mapping database, not a scope token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-DATABASE-PROC", "Database", "PROC", "81, 90",
            "Global procedure dictionary PROC",
            "Procedure-local keys and values, including predefined path keys.",
            "Provides mutable nonpersistent procedure data and predefined procedure metadata.", "LOCAL_MUTATION",
            "OD-008: PROC is a global procedure dictionary, not a scope token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-DATABASE-SCDB", "Database", "SCDB", "78-79",
            "Global read-only spacecraft database dictionary SCDB",
            "A spacecraft-database key.",
            "Returns source-described spacecraft database values; the database is read only.", "READ",
            "OD-008: SCDB is a read-only spacecraft database, not a scope token; EXCLUDE/Deferred review remains pending.",
        ),
        standard_row(
            "LRM244-ERRATUM-HANDLEERROR-DEFAULT", "SourceErratum", "HandleError default conflict", "30, 114",
            "Body default=True; Appendix-C default=False",
            "Conflicting HandleError default statements in the cited source.",
            "No HandleError default is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 30 says HandleError defaults True for all calls while Appendix C page 114 lists False; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-VERIFY-ONFALSE-DEFAULT", "SourceErratum", "Verify OnFalse default conflict", "41, 114",
            "Body default includes RECHECK; Appendix-C default includes REPEAT",
            "Conflicting Verify OnFalse action lists in the cited source.",
            "No Verify OnFalse default is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 41 lists RECHECK while Appendix C page 114 lists REPEAT for Verify OnFalse; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-VERIFY-FALSE-ACTION-MODIFIER", "SourceErratum", "Verify false-action modifier conflict", "42-43",
            "Section 4.3.6 false-result actions end with an OnFailure reference despite the surrounding OnFalse mechanism",
            "A Verify false-result action configuration.",
            "No OnFalse/OnFailure spelling resolution is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 43 names OnFailure for changing false-result actions although the surrounding mechanism is OnFalse; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-USER-ACTION-DISABLE", "SourceErratum", "User-action disable callable conflict", "77-78",
            "Prose names DismissUserAction for disable; example uses DisableUserAction; DismissUserAction is then documented for removal",
            "A configured user-action trigger.",
            "No callable-name correction is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 77 prose conflicts with its example/API over DisableUserAction versus DismissUserAction; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-ADJUSTLIMITS-NAME", "SourceErratum", "Condition-based limit-adjustment callable conflict", "66",
            "Section 4.8.7 prose names SetLimits; example/API calls AdjustLimits",
            "A condition-based telemetry limit adjustment.",
            "No callable-name correction is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 66 prose names SetLimits while its condition-based example/API calls AdjustLimits; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-PROMPT-FAILURE-MODIFIERS", "SourceErratum", "Operation-failure modifier conflict", "111, 116-117",
            "Appendix-B uses PromptUser/OnTrue/OnFalse for failure; Appendix-D uses PromptFailure/OnFailure",
            "Operation-failure prompting and action selection.",
            "No modifier mapping is selected by this excluded row.", "NONE",
            "OD-008 erratum: Appendix B page 111 conflicts with Appendix D pages 116-117 over operation-failure prompting/action modifiers; EXCLUDE/Deferred and unresolved.",
        ),
        standard_row(
            "LRM244-ERRATUM-LIMIT-KEY-LOHIGH", "SourceErratum", "LoHigh/LoYel limit-key conflict", "61",
            "Page 61 prose says LoHigh after examples and definitions use LoYel",
            "A low warning-limit dictionary key.",
            "No key spelling correction is selected by this excluded row.", "NONE",
            "OD-008 erratum: page 61 says LoHigh although its defined low-warning key is LoYel; EXCLUDE/Deferred and unresolved.",
        ),
    ])
    proc_keys = [
        ("NAME", 'PROC["NAME"]', "procedure name"),
        ("ARGS", 'PROC["ARGS"]', "argument dictionary"),
        ("STEP", 'PROC["STEP"]', "current step name"),
        ("PREV-STEP", 'PROC["PREV_STEP"]', "previous step name"),
        ("INPUT-DATA", "PROC[INPUT_DATA]", "procedure input-data path"),
        ("OUTPUT-DATA", "PROC[OUTPUT_DATA]", "procedure output-data path"),
        ("PARENT", 'PROC["PARENT"]', "parent procedure name and instance identifier"),
    ]
    for suffix, name, result in proc_keys:
        decision = "OD-008: source-grounded predefined PROC key; EXCLUDE/Deferred review remains pending."
        if suffix == "INPUT-DATA":
            decision = "OD-008: page 81 calls INPUT_DATA an output path while page 90 identifies it as the input path; EXCLUDE/Deferred errata review remains pending."
        rows.append(standard_row(
            f"LRM244-CONSTANT-PROC-KEY-{suffix}", "Constant", name, "81" if suffix not in {"INPUT-DATA", "OUTPUT-DATA"} else "81, 90",
            f"Predefined procedure database key {name}", "The global PROC dictionary.", result, "LOCAL_MUTATION", decision,
        ))
    return rows


def example_effect(number: int) -> str:
    if number in {26, 27, 136}:
        return "PRESENTATION"
    if number == 28:
        return "CONFIGURATION"
    if number == 55:
        return "NONE"
    if number == 113:
        return "EXTERNAL_EFFECT"
    if number <= 19 or 26 <= number <= 29 or 57 <= number <= 59 or number in {113, 139, 147, 152, 153, 167}:
        return "NONE"
    if number in {20, 21}:
        return "CONFIGURATION"
    if 22 <= number <= 24 or 78 <= number <= 83 or 128 <= number <= 129 or number == 131 or number == 151 or 154 <= number <= 160:
        return "CONTROL_STATE"
    if number == 25 or 108 <= number <= 109 or 119 <= number <= 127 or number == 130:
        return "PRESENTATION"
    if 30 <= number <= 56 or 85 <= number <= 93 or number in {107, 112, 135, 136, 137, 138, 143, 148, 161, 165, 166, 174, 176} or 184 <= number <= 187 or 192 <= number <= 195:
        return "READ"
    if 60 <= number <= 77 or number in {84, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 110, 111, 140, 141} or 169 <= number <= 175 or number == 191:
        return "EXTERNAL_EFFECT"
    if 114 <= number <= 118 or 132 <= number <= 134:
        return "OPERATOR_DECISION"
    if number in {142, 144, 145, 146, 149, 150, 162, 163, 164, 168} or 177 <= number <= 183 or 188 <= number <= 190:
        return "LOCAL_MUTATION"
    raise ValueError(f"Example {number}: no effect classification")


def section_effect(public_name: str) -> str:
    section, title = public_name.split(" ", 1)
    within = lambda root: section == root or section.startswith(root + ".")
    if within("2"):
        return "NONE"
    if section in {"3.1", "3.2", "3.2.1"}:
        return "CONFIGURATION"
    if section in {"3.3", "3.4", "3.5"}:
        return "OPERATOR_DECISION"
    if section == "3.6":
        return "PRESENTATION"
    if section == "4.1.1":
        return "CONFIGURATION"
    if within("4.1"):
        return "NONE"
    if within("4.2") or within("4.3"):
        return "READ"
    if within("4.4"):
        return "NONE"
    if within("4.5") or section == "4.7" or within("4.10"):
        return "EXTERNAL_EFFECT"
    if within("4.6"):
        return "CONTROL_STATE"
    if within("4.8"):
        if section in {"4.8.4", "4.8.10"}:
            return "READ"
        if section in {"4.8.5", "4.8.6", "4.8.7", "4.8.8", "4.8.9"}:
            return "EXTERNAL_EFFECT"
        return "CONFIGURATION"
    if within("4.9") or within("4.13"):
        return "PRESENTATION"
    if within("4.11"):
        return "CONFIGURATION"
    if within("4.12"):
        return "OPERATOR_DECISION"
    if within("4.14.4"):
        return "OPERATOR_DECISION"
    if within("4.14") or within("4.16"):
        return "CONTROL_STATE"
    if within("4.15.1") or within("4.15.2"):
        return "READ"
    if within("4.15.4") or within("4.15.5"):
        return "LOCAL_MUTATION"
    if within("4.15"):
        return "CONFIGURATION"
    if section == "1.2":
        return "LOCAL_MUTATION"
    if within("4.17"):
        return "LOCAL_MUTATION" if "Read" not in title else "READ"
    if within("4.18.4"):
        return "READ"
    if within("4.18"):
        return "EXTERNAL_EFFECT"
    if within("4.19.3"):
        return "READ"
    if within("4.19"):
        return "LOCAL_MUTATION"
    if within("4.20.2") or within("4.20.3"):
        return "READ"
    if within("4.20"):
        return "EXTERNAL_EFFECT"
    if within("4.21"):
        return "READ"
    raise ValueError(f"{public_name}: no section effect classification")


def function_effect(name: str) -> str:
    if name in {"Abort", "Finish", "Pause", "StartProc", "WaitFor", "Step", "Goto"}:
        return "CONTROL_STATE"
    if name in {"Display", "DisplayStep", "Notify", "OpenDisplay", "OpenWorkspace", "CloseDisplay", "CloseWorkspace", "PrintDisplay"}:
        return "PRESENTATION"
    if name in {"Prompt", "SetUserAction", "EnableUserAction", "DisableUserAction", "DismissUserAction"}:
        return "OPERATOR_DECISION"
    if name.startswith("Get") or name in {"IsAlarmed", "MemoryLookup", "ReadDirectory", "ReadFile", "TMTCLookup", "Verify", "LoadDictionary", "CompareMemoryImage", "CompareMemoryImages"}:
        return "READ"
    if name in {"BuildTC", "AND", "OR", "File"}:
        return "NONE"
    if name in {"ChangeLanguageConfig"}:
        return "CONFIGURATION"
    if name in {"CreateDictionary", "SaveDictionary", "OpenFile", "CloseFile", "WriteFile", "DeleteFile", "SetSharedData", "ClearSharedData", "ClearSharedDataScopes", "AddSharedDataScope", "ClearSharedDataScope"}:
        return "LOCAL_MUTATION"
    return "EXTERNAL_EFFECT"


def normalize_catalog(payload: dict[str, Any], layout_pages: list[str]) -> None:
    rows: list[dict[str, str]] = payload["rows"]
    rows[:] = [row for row in rows if row["ArtifactId"] not in REMOVED_ARTIFACT_IDS]
    by_id = {row["ArtifactId"]: row for row in rows}
    for row in added_rows():
        by_id[row["ArtifactId"]] = row
    rows[:] = list(by_id.values())

    payload["scope"]["non_claims"] = [
        "This technical source fragment is not the canonical compatibility ledger or v0.4 acceptance evidence.",
        "Candidate A scope approval is bound only by the canonical merge; this fragment asserts no separate artifact-row approval prerequisite.",
        "No fixture, oracle, runtime behavior, driver capability, operational property, or compliance property is claimed as executed or implemented.",
        "Source spelling conflicts remain explicit technical errata and are not semantically resolved here.",
    ]

    for row in rows:
        artifact_id = row["ArtifactId"]
        row["ModernBehavior"] = "Excluded from the v0.4 Candidate A simulator gate; no new v0.4 language behavior is authorized. Any future behavior needs a separately approved compatibility gate."
        row["Recovery"] = "No new v0.4 recovery behavior is authorized by this row."
        row["Disposition"] = "EXCLUDE"
        row["TargetIncrement"] = "Deferred"
        row["Approvers"] = TECHNICAL_CANDIDATE_APPROVER
        row["Status"] = "Decomposed"
        if "planned-only" not in row["TestVectors"]:
            row["TestVectors"] += "; planned-only; no fixture execution or result recorded."

        if row["Kind"] == "Example":
            match = re.fullmatch(r"Example (\d+): (.*)", row["PublicName"])
            if not match:
                raise ValueError(f"{artifact_id}: malformed example identity")
            number = int(match.group(1))
            digest, _ = example_span(layout_pages, number, int(row["Pages"]), match.group(2))
            row["SignatureOrGrammar"] = (
                "Indexed example source span; algorithm=normalized pypdf-layout text from exact body heading "
                "to next example or numbered-section heading on the cited page; "
                f"source-span-sha256={digest}; marker=located"
            )
            row["EffectClass"] = example_effect(number)
            row["Decision"] = "OD-008: source identity/effect and EXCLUDE/Deferred disposition decomposed; artifact-row and semantic acceptance remain pending."
            if number in EXAMPLE_ERRATA:
                row["Decision"] += f" Source erratum: {EXAMPLE_ERRATA[number]}"
        elif row["Kind"] == "SourceSection":
            row["EffectClass"] = section_effect(row["PublicName"])
            row["Decision"] = "OD-008: source section/effect and EXCLUDE/Deferred disposition decomposed; artifact-row and semantic acceptance remain pending."
            if artifact_id == "LRM244-SECTION-1-2-106":
                row["Decision"] += " Source erratum: both the table of contents and page 84 number Data containers as 1.2 inside chapter 4."
        elif row["Kind"] in {"Function", "FunctionAliasCandidate"}:
            row["EffectClass"] = function_effect(row["PublicName"])
            if artifact_id not in AMBIGUOUS_IDS and row["Kind"] == "FunctionAliasCandidate":
                row["Kind"] = "Function"
                row["SignatureOrGrammar"] = row["SignatureOrGrammar"].replace("Body-only or conflicting callable identity", "Body-documented callable identity")
            row["Decision"] = "OD-008: source callable/effect and EXCLUDE/Deferred disposition decomposed; artifact-row and semantic acceptance remain pending."
            if row["PublicName"] in APPENDIX_SECTION_ERRATA:
                row["Decision"] += f" Source erratum: {APPENDIX_SECTION_ERRATA[row['PublicName']]}"
            if artifact_id in AMBIGUOUS_IDS:
                row["EffectClass"] = "UNCLASSIFIED"
                row["Decision"] = "OD-008 ambiguity: source singular/plural callable spelling conflicts require future technical errata resolution; EXCLUDE/Deferred remains pending."
        elif artifact_id in TYPE_RENAMES:
            public_name, result = TYPE_RENAMES[artifact_id]
            row["PublicName"] = public_name
            row["LegacyResult"] = result
            row["SignatureOrGrammar"] = "Source-described object/result category; the source does not state a distinct public class name"
            row["Decision"] = "OD-008: descriptive source category only, not an inferred public class; EXCLUDE/Deferred review remains pending."

        if artifact_id in CONTEXTUAL_CONSTANT_NAMES:
            row["PublicName"] = CONTEXTUAL_CONSTANT_NAMES[artifact_id]
        if artifact_id.startswith("LRM244-CONSTANT-EXECUTION-STATE-"):
            row["EffectClass"] = "CONTROL_STATE"

        if artifact_id == "LRM244-OPERATOR-VERIFY-BW":
            row["Pages"] = "39, 45"
            row["Decision"] = "OD-008 erratum: page 39 documents bw while page 45 says btw; EXCLUDE/Deferred spelling disposition remains pending."
        if artifact_id == "LRM244-CONSTANT-ACTION-SKIP":
            row["Pages"] = "28-30, 38, 41-43, 110-111, 114, 116-117"
            row["Decision"] = "OD-008: SKIP result-action token is separated from the page 57 WaitFor command; EXCLUDE/Deferred review remains pending."
        if artifact_id == "LRM244-METHOD-TIME-FMT":
            row["EffectClass"] = "CONFIGURATION"
            row["Decision"] = "OD-008: static TIME.fmt changes subsequent TIME string output formatting; EXCLUDE/Deferred review remains pending."
        if artifact_id == "LRM244-SYNTAX-SHARED-TEST-AND-SET":
            row["EffectClass"] = "LOCAL_MUTATION"
            row["Decision"] = "OD-008: source-grounded conditional shared-data update form; EXCLUDE/Deferred review remains pending."
        if artifact_id in {
            "LRM244-MODIFIER-ERROR", "LRM244-MODIFIER-FORMAT",
            "LRM244-MODIFIER-IGNORE", "LRM244-MODIFIER-LIMITS",
        }:
            row["SignatureOrGrammar"] = row["SignatureOrGrammar"].replace("Keyword modifier (Appendix B/D)", "Keyword modifier (body-only; omitted from Appendix B/D)")

    method_prefixes = {
        "LRM244-METHOD-MATH-": "",
        "LRM244-METHOD-CONVERSION-": "",
        "LRM244-METHOD-STRING-": "str.",
        "LRM244-METHOD-TELEMETRY-ITEM-": "telemetry-item.",
        "LRM244-METHOD-FILE-": "File.",
        "LRM244-METHOD-DICTIONARY-": "dict.",
    }
    for row in rows:
        for prefix, public_prefix in method_prefixes.items():
            if row["ArtifactId"].startswith(prefix):
                suffix = row["PublicName"].split(".")[-1]
                row["PublicName"] = public_prefix + suffix
                break

    for row in rows:
        if row["Kind"] != "Example":
            signature = re.sub(
                r"(?:page-local-context|occurrence-context|table/context|heading-context|source-context|context|source-pages-normalized-layout)-sha256=[0-9a-f]{64}",
                "",
                row["SignatureOrGrammar"],
            ).strip().rstrip(";")
            digest = page_set_digest(layout_pages, row["Pages"])
            row["SignatureOrGrammar"] = f"{signature}; source-pages-normalized-layout-sha256={digest}"

    rows.sort(key=lambda row: row["ArtifactId"])
    kinds = collections.Counter(row["Kind"] for row in rows)
    payload["counts"] = {
        "rows_total": len(rows),
        "by_kind": dict(sorted(kinds.items())),
        "examples": kinds["Example"],
        "appendix_a_functions": sum("Appendix-A function" in row["SignatureOrGrammar"] for row in rows),
        "appendix_b_d_unique_modifiers": len(APPENDIX_MODIFIERS),
        "body_only_modifiers": sum("body-only" in row["SignatureOrGrammar"] for row in rows if row["Kind"] == "Modifier"),
        "numbered_source_section_anchors": kinds["SourceSection"],
        "unclassified_genuine_ambiguities": sum(row["EffectClass"] == "UNCLASSIFIED" for row in rows),
    }
    payload["extraction_method"].update({
        "normalizer": "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/normalize_lrm244.py",
        "example_span_hash": "SHA-256 of whitespace-normalized pypdf layout text from the exact body heading through the next example or numbered-section heading on the cited page.",
        "other_row_page_hash": "SHA-256 of whitespace-normalized pypdf layout text for the cited page set, joined in page order with form-feed separators.",
        "artifact_sentinels": "Exact source-token and row-field assertions cover WaitFor controls/states, lower-case call keywords, TIME directives, contextual data objects, effect corrections, and unresolved errata.",
    })
    payload["gaps"] = [
        "OD-008 semantic acceptance and source-errata resolutions remain deferred; no additional human or organization approval prerequisite is asserted by this technical fragment.",
        "Example fixture inputs, expected outputs, ordering oracles, negative cases, and controlled execution results have not been authored or run.",
        "CompareMemoryImage/CompareMemoryImages and ClearSharedDataScope/ClearSharedDataScopes source spellings remain explicitly UNCLASSIFIED pending an errata decision.",
        "The source-described result/object category rows do not infer public class names that the manual does not state.",
        "Appendix C values remain source-described typical, spacecraft-dependent examples and are not runtime defaults.",
        "No operational-readiness or compliance conclusion can be derived from this catalog.",
    ]


def table_examples(layout_pages: list[str]) -> list[tuple[int, str, int]]:
    text = "\n".join(layout_pages[4:11])
    pattern = re.compile(r"Example\s+(\d+):\s*(.*?)\s*\.{3,}\s*(\d+)", re.IGNORECASE)
    return [(int(number), normalize_text(title), int(page)) for number, title, page in pattern.findall(text)]


def appendix_functions(layout_pages: list[str]) -> list[tuple[str, str, str, int]]:
    entries: list[tuple[str, str, str, int]] = []
    for page in range(104, 108):
        for line in layout_pages[page - 1].splitlines():
            parts = [part.strip() for part in re.split(r"\s{2,}", line.strip()) if part.strip()]
            if len(parts) >= 3 and re.match(r"^[A-Z][A-Za-z]+$", parts[0]) and re.match(r"^\d", parts[-1]):
                entries.append((parts[0], parts[1], parts[-1], page))
    return entries


def source_sections(layout_pages: list[str]) -> list[tuple[str, str, int]]:
    sections: list[tuple[str, str, int]] = []
    for page in range(14, 104):
        for line in layout_pages[page - 1].splitlines():
            match = re.match(r"^\s*(\d+(?:\.\d+)+)\s+(.+?)\s*$", line)
            if match:
                sections.append((match.group(1), normalize_text(match.group(2)), page))
    return sections


def validate(payload: dict[str, Any], layout_pages: list[str]) -> None:
    errors: list[str] = []
    rows: list[dict[str, str]] = payload["rows"]
    if file_sha256(PDF) != PDF_SHA256:
        errors.append("PDF SHA-256 mismatch")
    if pypdf.__version__ != PYPDF_VERSION:
        errors.append(f"pypdf {pypdf.__version__} != pinned extraction version {PYPDF_VERSION}")
    if len(layout_pages) != 118 or any(not page.strip() for page in layout_pages):
        errors.append("expected non-empty text on 118 PDF pages")
    if any(list(row) != REQUIRED_COLUMNS for row in rows):
        errors.append("row field order/schema mismatch")
    if any(not str(value).strip() for row in rows for value in row.values()):
        errors.append("empty row field")
    for row in rows:
        try:
            pages = parse_pages(row["Pages"])
        except ValueError as exc:
            errors.append(f"{row['ArtifactId']}: {exc}")
            continue
        if not pages or min(pages) < 1 or max(pages) > 118:
            errors.append(f"{row['ArtifactId']}: page out of range")
        if row["EffectClass"] not in ALLOWED_EFFECTS:
            errors.append(f"{row['ArtifactId']}: invalid effect")
        if row["Disposition"] != "EXCLUDE" or row["TargetIncrement"] != "Deferred":
            errors.append(f"{row['ArtifactId']}: outside candidate disposition")
        if row["Status"] in {"Approved", "Implemented", "Verified"}:
            errors.append(f"{row['ArtifactId']}: unsupported status claim")
        if row["Approvers"] != TECHNICAL_CANDIDATE_APPROVER:
            errors.append(f"{row['ArtifactId']}: unsupported approval state")
        if "planned-only" not in row["TestVectors"]:
            errors.append(f"{row['ArtifactId']}: test vector is not marked planned-only")
        if row["Kind"] != "Example" and row["SignatureOrGrammar"].count("source-pages-normalized-layout-sha256=") != 1:
            errors.append(f"{row['ArtifactId']}: expected exactly one reproducible source-page digest")

    for key in ("ArtifactId", "TestVectors"):
        values = [row[key].split(";", 1)[0] for row in rows]
        if len(values) != len(set(values)):
            errors.append(f"duplicate {key}")
    kind_names = [(row["Kind"], row["PublicName"]) for row in rows]
    if len(kind_names) != len(set(kind_names)):
        errors.append("duplicate Kind/PublicName identity")

    examples = sorted(
        (int(re.match(r"Example (\d+):", row["PublicName"]).group(1)), row)
        for row in rows if row["Kind"] == "Example"
    )
    toe = table_examples(layout_pages)
    if [number for number, _ in examples] != list(range(1, 196)):
        errors.append("example sequence is not exactly 1..195")
    json_toe = [(number, row["PublicName"].split(": ", 1)[1], int(row["Pages"])) for number, row in examples]
    if json_toe != toe:
        errors.append("example identity/title/page differs from Table of Examples")
    for number, row in examples:
        expected, _ = example_span(layout_pages, number, int(row["Pages"]), row["PublicName"].split(": ", 1)[1])
        if f"source-span-sha256={expected}" not in row["SignatureOrGrammar"]:
            errors.append(f"{row['ArtifactId']}: example span digest mismatch")

    functions = appendix_functions(layout_pages)
    appendix_rows = {
        row["PublicName"]: row for row in rows if "Appendix-A function" in row["SignatureOrGrammar"]
    }
    if len(functions) != 64 or len(appendix_rows) != 64:
        errors.append("Appendix A function count is not 64")
    for name, description, section, page in functions:
        row = appendix_rows.get(name)
        if not row:
            errors.append(f"missing Appendix A function {name}")
        elif description.lower() not in row["LegacyResult"].lower() or f"indexed-section={section}" not in row["SignatureOrGrammar"]:
            errors.append(f"{row['ArtifactId']}: Appendix A description/section mismatch")

    modifier_names = {row["PublicName"] for row in rows if row["Kind"] == "Modifier"}
    if not APPENDIX_MODIFIERS <= modifier_names:
        errors.append(f"missing Appendix B/D modifiers: {sorted(APPENDIX_MODIFIERS - modifier_names)}")
    sections = source_sections(layout_pages)
    section_rows = {
        (row["PublicName"].split(" ", 1)[0], row["PublicName"].split(" ", 1)[1], int(row["Pages"]))
        for row in rows if row["Kind"] == "SourceSection"
    }
    if len(sections) != 140 or section_rows != set(sections):
        errors.append("numbered source-section anchors do not match the 140 body headings")

    required_ids = {row["ArtifactId"] for row in added_rows()}
    present_ids = {row["ArtifactId"] for row in rows}
    if not required_ids <= present_ids:
        errors.append(f"missing source-grounded additions: {sorted(required_ids - present_ids)}")
    forbidden_ids = REMOVED_ARTIFACT_IDS & present_ids
    if forbidden_ids:
        errors.append(f"removed unsupported artifacts remain: {sorted(forbidden_ids)}")

    row_by_id = {row["ArtifactId"]: row for row in rows}
    row_sentinels = {
        "LRM244-CONSTANT-LIMIT-TYPE-STEP": ("Constant", "STEP (limit type)", "61, 66", "CONFIGURATION"),
        "LRM244-CONTROL-WAITFOR-INTERRUPT": ("Control", "INTERRUPT", "57", "CONTROL_STATE"),
        "LRM244-CONTROL-WAITFOR-STEP": ("Control", "STEP (WaitFor command)", "57", "CONTROL_STATE"),
        "LRM244-CONTROL-WAITFOR-SKIP": ("Control", "SKIP (WaitFor command)", "57", "CONTROL_STATE"),
        "LRM244-STATE-WAITFOR-INTERRUPTED": ("State", "INTERRUPTED", "57", "CONTROL_STATE"),
        "LRM244-STATE-WAITFOR-PAUSE": ("State", "PAUSE", "57", "CONTROL_STATE"),
        "LRM244-STATE-WAITFOR-WAITING": ("State", "WAITING", "58", "CONTROL_STATE"),
        "LRM244-OUTCOME-WAIT-ABORT": ("Outcome", "WaitFor interrupted then skipped", "57", "CONTROL_STATE"),
        "LRM244-KEYWORD-ARGUMENT-ARGS": ("KeywordArgument", "args", "48, 51, 55, 89", "CONFIGURATION"),
        "LRM244-KEYWORD-ARGUMENT-COMMAND": ("KeywordArgument", "command", "49-55", "EXTERNAL_EFFECT"),
        "LRM244-KEYWORD-ARGUMENT-SEQUENCE": ("KeywordArgument", "sequence", "51", "EXTERNAL_EFFECT"),
        "LRM244-KEYWORD-ARGUMENT-GROUP": ("KeywordArgument", "group", "51-53", "EXTERNAL_EFFECT"),
        "LRM244-KEYWORD-ARGUMENT-ADDINFO": ("KeywordArgument", "addInfo", "53", "EXTERNAL_EFFECT"),
        "LRM244-KEYWORD-ARGUMENT-VERIFY": ("KeywordArgument", "verify", "54-55", "EXTERNAL_EFFECT"),
        "LRM244-DATA-CONTAINER-ARGS": ("DataContainer", "ARGS", "86, 89", "LOCAL_MUTATION"),
        "LRM244-DATA-CONTAINER-IVARS": ("DataContainer", "IVARS", "86", "LOCAL_MUTATION"),
        "LRM244-DATABASE-GDB": ("Database", "GDB", "69, 80", "READ"),
        "LRM244-DATABASE-PROC": ("Database", "PROC", "81, 90", "LOCAL_MUTATION"),
        "LRM244-DATABASE-SCDB": ("Database", "SCDB", "78-79", "READ"),
    }
    for artifact_id, expected in row_sentinels.items():
        row = row_by_id.get(artifact_id)
        actual = None if row is None else (
            row["Kind"], row["PublicName"], row["Pages"], row["EffectClass"]
        )
        if actual != expected:
            errors.append(f"{artifact_id}: sentinel {actual!r} != {expected!r}")

    source_sentinels = {
        35: ("%d", "%b", "%m", "%Y", "%H", "%M", "%S"),
        53: ("addInfo keyword argument",),
        57: ("INTERRUPT", "INTERRUPTED", "STEP", "SKIP", "PAUSE"),
        58: ("WAITING",),
    }
    for page, tokens in source_sentinels.items():
        normalized_page = normalize_text(layout_pages[page - 1])
        for token in tokens:
            if token not in normalized_page:
                errors.append(f"page {page}: missing source sentinel {token!r}")

    expected_example_effects = {
        "LRM244-EXAMPLE-026": "PRESENTATION",
        "LRM244-EXAMPLE-027": "PRESENTATION",
        "LRM244-EXAMPLE-028": "CONFIGURATION",
        "LRM244-EXAMPLE-055": "NONE",
        "LRM244-EXAMPLE-113": "EXTERNAL_EFFECT",
        "LRM244-EXAMPLE-136": "PRESENTATION",
    }
    for artifact_id, expected_effect in expected_example_effects.items():
        row = row_by_id.get(artifact_id)
        if row is None or row["EffectClass"] != expected_effect:
            errors.append(f"{artifact_id}: expected effect {expected_effect}")
    required_effects = {
        "LRM244-METHOD-TIME-FMT": "CONFIGURATION",
        "LRM244-SECTION-4-1-1-023": "CONFIGURATION",
        "LRM244-SYNTAX-SHARED-TEST-AND-SET": "LOCAL_MUTATION",
    }
    for artifact_id, expected_effect in required_effects.items():
        row = row_by_id.get(artifact_id)
        if row is None or row["EffectClass"] != expected_effect:
            errors.append(f"{artifact_id}: expected effect {expected_effect}")

    erratum_ids = {
        "LRM244-ERRATUM-HANDLEERROR-DEFAULT",
        "LRM244-ERRATUM-VERIFY-ONFALSE-DEFAULT",
        "LRM244-ERRATUM-VERIFY-FALSE-ACTION-MODIFIER",
        "LRM244-ERRATUM-USER-ACTION-DISABLE",
        "LRM244-ERRATUM-ADJUSTLIMITS-NAME",
        "LRM244-ERRATUM-PROMPT-FAILURE-MODIFIERS",
        "LRM244-ERRATUM-LIMIT-KEY-LOHIGH",
    }
    for artifact_id in erratum_ids:
        row = row_by_id.get(artifact_id)
        if row is None or not row["Decision"].startswith("OD-008 erratum:"):
            errors.append(f"{artifact_id}: missing explicit unresolved erratum disposition")
    example_four = row_by_id.get("LRM244-EXAMPLE-004")
    if example_four is None or "page 15 narrative says slash" not in example_four["Decision"]:
        errors.append("LRM244-EXAMPLE-004: slash/backslash erratum page sentinel mismatch")
    wait_outcome = row_by_id.get("LRM244-OUTCOME-WAIT-ABORT")
    if wait_outcome is None or "OnFalse" in wait_outcome["LegacyResult"]:
        errors.append("LRM244-OUTCOME-WAIT-ABORT: unsupported OnFalse inference remains")
    inaccurate_scope_rows = {
        row["ArtifactId"] for row in rows
        if row["PublicName"] in {"ARGS", "GDB", "INPUT_DATA", "IVARS", "OUTPUT_DATA", "PROC", "SCDB"}
        and "scope symbolic value" in (row["SignatureOrGrammar"] + " " + row["LegacyInputs"]).lower()
    }
    if inaccurate_scope_rows:
        errors.append(f"inaccurate scope-token claims remain: {sorted(inaccurate_scope_rows)}")
    unclassified = {row["ArtifactId"] for row in rows if row["EffectClass"] == "UNCLASSIFIED"}
    if unclassified != AMBIGUOUS_IDS:
        errors.append(f"unexpected UNCLASSIFIED rows: {sorted(unclassified ^ AMBIGUOUS_IDS)}")
    if any(row["PublicName"] in {"PAUSED", "RUNNING"} and row["Pages"] == "76" for row in rows):
        errors.append("unsupported uppercase p76 execution-state inference remains")

    payload["validation"] = {
        "method": "Independent deterministic source checks in NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/normalize_lrm244.py; no runtime compatibility fixture was executed.",
        "checks": {
            "pdf_sha256_matches": file_sha256(PDF) == PDF_SHA256,
            "pypdf_version_6_14_2": pypdf.__version__ == PYPDF_VERSION,
            "pdf_page_count_118": len(layout_pages) == 118,
            "all_pages_have_text": all(page.strip() for page in layout_pages),
            "examples_195_exact_table_and_body_identity": len(examples) == 195 and json_toe == toe,
            "example_span_hashes_reproducible": not any("example span digest mismatch" in error for error in errors),
            "appendix_functions_64": len(functions) == len(appendix_rows) == 64,
            "appendix_modifiers_53_covered": APPENDIX_MODIFIERS <= modifier_names,
            "source_sections_140_exact": len(sections) == 140 and section_rows == set(sections),
            "artifact_ids_unique": len(rows) == len({row["ArtifactId"] for row in rows}),
            "planned_test_ids_unique": len(rows) == len({row["TestVectors"].split(";", 1)[0] for row in rows}),
            "all_25_fields_present_in_order": all(list(row) == REQUIRED_COLUMNS for row in rows),
            "all_fields_nonempty": all(str(value).strip() for row in rows for value in row.values()),
            "all_page_specs_parse_and_bound": not any("page" in error and "Example" not in error for error in errors),
            "all_dispositions_exclude": all(row["Disposition"] == "EXCLUDE" for row in rows),
            "all_targets_deferred": all(row["TargetIncrement"] == "Deferred" for row in rows),
            "only_genuine_source_conflicts_unclassified": unclassified == AMBIGUOUS_IDS,
            "no_approved_implemented_or_verified_status": all(row["Status"] not in {"Approved", "Implemented", "Verified"} for row in rows),
            "technical_fragment_has_no_pending_human_approval_claim": all(row["Approvers"] == TECHNICAL_CANDIDATE_APPROVER for row in rows),
            "no_executed_fixture_claim": all("planned-only" in row["TestVectors"] for row in rows),
            "critical_artifact_sentinels_exact": not any("sentinel" in error for error in errors),
            "unsupported_artifact_ids_absent": not forbidden_ids,
            "explicit_unresolved_errata_present": not any("erratum disposition" in error for error in errors),
        },
        "result": "STRUCTURAL_CANDIDATE_PASS" if not errors else "STRUCTURAL_CANDIDATE_FAIL",
        "canonical_acceptance": "NOT_EVALUATED_AND_NOT_CLAIMED",
        "errors": errors,
    }
    if errors:
        raise ValueError("\n".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Normalize the candidate before validating it.")
    args = parser.parse_args()
    payload = json.loads(CATALOG.read_text(encoding="utf-8"))
    reader = PdfReader(PDF)
    layout_pages = [page.extract_text(extraction_mode="layout") or "" for page in reader.pages]
    if args.write:
        normalize_catalog(payload, layout_pages)
    validate(payload, layout_pages)
    if args.write:
        CATALOG.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": payload["validation"]["result"],
        "rows": len(payload["rows"]),
        "counts": payload["counts"],
    }, indent=2))


if __name__ == "__main__":
    main()
