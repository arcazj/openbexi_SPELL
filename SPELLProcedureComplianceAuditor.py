#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SPELL Procedure Compliance Auditor (Manual v2.0.1-focused)

Usage:
  python spell_auditor.py /path/to/procedure.spell [--manual-version 2.0.1] [--header-rules path.json]

- Arg 1 (positional): path to the SPELL procedure text file to audit.
- --manual-version: override the manual version string in output (default 2.0.1).
- --header-rules: optional JSON file specifying mandatory header fields & regex formats
                  to replace/augment heuristics (see example at bottom of this file).

Output: prints ONLY the JSON object defined in your schema to stdout.

Scope (per user request):
1) Header requirements (heuristic unless --header-rules provided)
2) Command sending (Send/BuildTC syntax, Time/ReleaseTime absolute)
3) Telemetry verification (Verify/WaitFor/GetTM syntax; operators; tolerances; confirm each TC has a check)

Manual grounding (SPELL Language Manual v2.0.1):
- 4.4 BuildTC & 4.5 Send: 'command' keyword mandatory; time-tag and release time must be absolute
- 4.3 Verify: operators eq|ge|gt|lt|le|neq|bw|nbw; Tolerance/ValueFormat; Wait/Timeout semantics for Verify
- 4.6 WaitFor: accepts time or telemetry condition (Verify-style list); Delay vs Timeout semantics
- 4.2 GetTM: Wait/Timeout usage patterns
"""

import argparse
import json
import os
import re
from typing import List, Dict, Any, Optional, Tuple

# -----------------------------
# Helpers
# -----------------------------

FINDING = Dict[str, Any]

ALLOWED_VERIFY_OPS = {"eq", "ge", "gt", "lt", "le", "neq", "bw", "nbw"}
ALLOWED_VALUEFORMAT = {"RAW", "ENG"}

# Heuristic header fields if no explicit header rules are provided.
# These are common in many SPELL shops but NOT strictly defined in v2.0.1 manual.
HEURISTIC_HEADER_RULES = {
    "mandatory": [
        {"name": "PROC", "pattern": r'^\s*(PROC|PROC_NAME|PROCEDURE|NAME)\s*=\s*["\']?.+?["\']?\s*$',
         "desc": "Procedure name"},
        {"name": "VERSION", "pattern": r'^\s*(VER|VERSION)\s*=\s*["\']?\d+(\.\d+)*["\']?\s*$',
         "desc": "Version number"},
        {"name": "AUTHOR", "pattern": r'^\s*(AUTHOR|OWNER)\s*=\s*["\']?.+?["\']?\s*$', "desc": "Author"},
        {"name": "PURPOSE", "pattern": r'^\s*(PURPOSE|DESC|DESCRIPTION)\s*=\s*["\']?.+?["\']?\s*$',
         "desc": "Purpose/description"},
        {"name": "DATE",
         "pattern": r'^\s*(DATE|CREATION_DATE|LAST_UPDATE)\s*=\s*["\']?\d{4}[-/]\d{2}[-/]\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?["\']?\s*$',
         "desc": "ISO-like date"},
    ],
    "formatting": {
        "header_window_lines": 80  # Only scan the first N lines for header
    }
}

# Manual snippets (for embedding into findings)
MANUAL_QUOTES = {
    "4.5.1-command-keyword": "The keyword command is mandatory. It accepts a command name (string) or a command item.",
    "4.5.2-time-absolute": "To time-tag a command, the Time modifier shall be used... The passed time shall be absolute.",
    "4.5.3-releasetime-absolute": "A release time can be specified... The passed time shall be absolute.",
    "4.3.1-operators": "Available comparison operators: eq, ge, gt, lt, le, neq, bw, nbw.",
    "4.3.2-wait-timeout": "Verify may use Wait and Timeout; it will wait at most Timeout for the next sample.",
    "4.3.3-tolerance": "A tolerance value may be provided using Tolerance; applicable to numeric values only.",
    "4.6.3-waitfor-verify-style": "WaitFor may accept the same arguments as Verify; behavior: wait until all verification conditions are fulfilled.",
    "4.2-gettm": "GetTM may use Wait=True and an optional Timeout; Timeout accepts seconds, TIME objects, or time strings."
}

# Regexes for core constructs
RE_SEND_CALL = re.compile(r'^\s*Send\s*\(', re.IGNORECASE)
RE_BUILDTC = re.compile(r'BuildTC\s*\(', re.IGNORECASE)
RE_VERIFY = re.compile(r'^\s*Verify\s*\(', re.IGNORECASE)
RE_WAITFOR = re.compile(r'^\s*WaitFor\s*\(', re.IGNORECASE)
RE_GETTM = re.compile(r'^\s*GetTM\s*\(', re.IGNORECASE)

# Extract keyword args inside a function call in a best-effort manner
KWARG_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)(?:(?=,\s*[A-Za-z_][A-Za-z0-9_]*\s*=)|\))', re.DOTALL)


def load_text(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read().splitlines()


def load_header_rules(path: Optional[str]) -> Dict[str, Any]:
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return HEURISTIC_HEADER_RULES


def trim_snippet(s: str, maxlen: int = 140) -> str:
    s = s.strip().replace("\t", " ")
    return (s[:maxlen] + "…") if len(s) > maxlen else s


def find_function_blocks(lines: List[str], predicate) -> List[Tuple[int, str]]:
    hits = []
    for idx, line in enumerate(lines, start=1):
        if predicate(line):
            hits.append((idx, line))
    return hits


def parse_kwargs(call_line: str) -> Dict[str, str]:
    out = {}
    # Normalize until last ')'
    try:
        head = call_line[call_line.index('('):]
    except ValueError:
        return out
    # Ensure a closing parenthesis for regex
    if not head.endswith(')'):
        head = head + ')'
    for k, v in KWARG_PAIR.findall(head):
        out[k] = v.strip()
    return out


def is_string_literal(expr: str) -> bool:
    return bool(re.match(r"^[\"'].*[\"']$", expr.strip()))


def looks_absolute_time(expr: str) -> bool:
    # Accept absolute date strings like 'YYYY/MM/DD HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS'
    # or expressions containing NOW (treated as absolute reference in Send examples)
    e = expr.strip()
    if "NOW" in e:
        return True
    if is_string_literal(e):
        val = e.strip()[1:-1]
        if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}(:\d{2})?$', val):
            return True
        if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}$', val):
            # Date without time is questionable; treat as NOT absolute for Send time-tags.
            return False
        if val.startswith('+'):  # relative pattern (e.g., +00:00:05)
            return False
    # Also treat plain TIME(...) as potentially absolute if it wraps an absolute-like string
    if e.startswith("TIME("):
        if re.search(r'\d{4}[-/]\d{2}[-/]\d{2}', e):
            return True
    return False


def extract_verify_core(expr: str) -> List[Tuple[str, str, List[str]]]:
    """
    Attempt to extract Verify conditions like:
      Verify(['TMparam', eq, 123], ValueFormat=RAW, Tolerance=0.5)
    Returns list of tuples: (param, op, [values...])
    """
    results = []
    # naive parse: find [...] blocks inside Verify(...)
    lists = re.findall(r'\[(.*?)\]', expr, flags=re.DOTALL)
    for lst in lists:
        parts = [p.strip() for p in lst.split(',')]
        if len(parts) >= 3:
            param = parts[0]
            op = parts[1].strip().lower()
            rhs = parts[2:]
            # Normalize quotes around param
            if is_string_literal(param):
                param = param[1:-1]
            results.append((param, op, rhs))
    return results


def verify_has_tm_condition_in_waitfor(expr: str) -> bool:
    # WaitFor([ 'TMparam', eq, 23 ], Delay=20)
    return bool(re.search(r'\[.*?\]', expr, flags=re.DOTALL))


def within_range(a: int, b: int, dist: int) -> bool:
    return abs(a - b) <= dist


# -----------------------------
# Audit logic
# -----------------------------

def audit(procedure_lines: List[str],
          manual_version: str,
          header_rules: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[FINDING] = []

    # 1) HEADER
    header_window = header_rules.get("formatting", {}).get("header_window_lines", 80)
    header_slice = procedure_lines[:max(1, header_window)]
    header_text = "\n".join(header_slice)

    # Evaluate mandatory fields (if provided or heuristic)
    for rule in header_rules.get("mandatory", []):
        name = rule["name"]
        patt = re.compile(rule["pattern"], re.IGNORECASE)
        matched_line = None
        for idx, line in enumerate(header_slice, start=1):
            if patt.search(line):
                matched_line = idx
                break
        if matched_line is None:
            findings.append({
                "rule_id": f"HEADER:{name}",
                "category": "HEADER",
                "severity": "MAJOR",
                "location": {"line_start": None, "line_end": None},
                "evidence": "",
                "explanation": f"Missing mandatory header field heuristic '{name}' ({rule['desc']}). "
                               f"If your organization mandates different tags, pass --header-rules to define them.",
                "manual_quote": "The v2.0.1 Language Manual does not normatively specify a header schema; "
                                "this check uses site conventions (heuristics).",
                "status": "VIOLATION",
                "suggested_fix": f"Add {name} field near top of file, e.g., {name} = \"...\""
            })
        else:
            findings.append({
                "rule_id": f"HEADER:{name}",
                "category": "HEADER",
                "severity": "MINOR",
                "location": {"line_start": matched_line, "line_end": matched_line},
                "evidence": trim_snippet(header_slice[matched_line - 1]),
                "explanation": f"Header field '{name}' found.",
                "manual_quote": "Heuristic header rule (manual v2.0.1 lacks a normative header section).",
                "status": "OK",
                "suggested_fix": ""
            })

    # 2) COMMAND SENDING
    send_calls = find_function_blocks(procedure_lines, lambda l: RE_SEND_CALL.search(l) is not None)

    # Keep BuildTC occurrences for context
    buildtc_lines = {i for (i, l) in find_function_blocks(procedure_lines, lambda l: RE_BUILDTC.search(l) is not None)}

    for (ln, line) in send_calls:
        kwargs = parse_kwargs(line)
        # 4.5.1: 'command' keyword is mandatory
        if "command" not in (k.lower() for k in kwargs.keys()):
            findings.append({
                "rule_id": "4.5.1",
                "category": "COMMAND",
                "severity": "MAJOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Send() without 'command=' keyword. Manual states the 'command' keyword is mandatory.",
                "manual_quote": MANUAL_QUOTES["4.5.1-command-keyword"],
                "status": "VIOLATION",
                "suggested_fix": "Use: Send(command='CMDNAME') or Send(command=tc_item)"
            })
        else:
            # check command value looks plausible (string literal or variable)
            # not failing if variable; just recording OK
            findings.append({
                "rule_id": "4.5.1",
                "category": "COMMAND",
                "severity": "MINOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Send() uses 'command=' per manual.",
                "manual_quote": MANUAL_QUOTES["4.5.1-command-keyword"],
                "status": "OK",
                "suggested_fix": ""
            })

        # 4.5.2 & 4.5.3: Time and ReleaseTime must be absolute
        for time_kw, rid in (("Time", "4.5.2"), ("ReleaseTime", "4.5.3")):
            val = None
            for k, v in kwargs.items():
                if k.lower() == time_kw.lower():
                    val = v
                    break
            if val is not None:
                if looks_absolute_time(val):
                    findings.append({
                        "rule_id": rid,
                        "category": "COMMAND",
                        "severity": "MINOR",
                        "location": {"line_start": ln, "line_end": ln},
                        "evidence": f"{time_kw}={trim_snippet(val)}",
                        "explanation": f"{time_kw} appears absolute, which complies with the manual.",
                        "manual_quote": MANUAL_QUOTES["4.5.2-time-absolute"] if time_kw == "Time" else MANUAL_QUOTES[
                            "4.5.3-releasetime-absolute"],
                        "status": "OK",
                        "suggested_fix": ""
                    })
                else:
                    findings.append({
                        "rule_id": rid,
                        "category": "COMMAND",
                        "severity": "MAJOR",
                        "location": {"line_start": ln, "line_end": ln},
                        "evidence": f"{time_kw}={trim_snippet(val)}",
                        "explanation": f"{time_kw} must be an absolute time per manual (date/time string or absolute TIME).",
                        "manual_quote": MANUAL_QUOTES["4.5.2-time-absolute"] if time_kw == "Time" else MANUAL_QUOTES[
                            "4.5.3-releasetime-absolute"],
                        "status": "VIOLATION",
                        "suggested_fix": f"Use absolute time: {time_kw}='YYYY/MM/DD HH:MM:SS' or {time_kw}=NOW + 30*MINUTE"
                    })

        # Flag clearly deprecated/forbidden forms (heuristic): positional Send('CMD')
        if re.search(r'\bSend\s*\(\s*[\'"]', line) and 'command=' not in line:
            findings.append({
                "rule_id": "4.5.1-positional",
                "category": "COMMAND",
                "severity": "MAJOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Positional command string used in Send(); manual mandates 'command=' keyword.",
                "manual_quote": MANUAL_QUOTES["4.5.1-command-keyword"],
                "status": "VIOLATION",
                "suggested_fix": "Change to Send(command='CMDNAME')"
            })

        # Heuristic: discourage all-caps SEND(
        if re.search(r'^\s*SEND\s*\(', procedure_lines[ln - 1]):
            findings.append({
                "rule_id": "STYLE-SEND-UPPER",
                "category": "COMMAND",
                "severity": "MINOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Non-canonical casing 'SEND(' (manual examples use 'Send(').",
                "manual_quote": "Manual examples consistently use 'Send(' with capital S.",
                "status": "VIOLATION",
                "suggested_fix": "Use 'Send('"
            })

    # 3) TELEMETRY VERIFICATION
    verify_calls = find_function_blocks(procedure_lines, lambda l: RE_VERIFY.search(l) is not None)
    waitfor_calls = find_function_blocks(procedure_lines, lambda l: RE_WAITFOR.search(l) is not None)
    gettm_calls = find_function_blocks(procedure_lines, lambda l: RE_GETTM.search(l) is not None)

    # Verify syntax/operator checks
    for (ln, line) in verify_calls:
        # Extract operators and RHS
        conds = extract_verify_core(line)
        if not conds:
            findings.append({
                "rule_id": "4.3.1",
                "category": "TELEMETRY",
                "severity": "MAJOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Could not parse any TM verification list inside Verify(...). Expected ['TM', op, value].",
                "manual_quote": MANUAL_QUOTES["4.3.1-operators"],
                "status": "VIOLATION",
                "suggested_fix": "Use e.g., Verify(['TMparam', eq, 23])"
            })
            continue

        ops_ok = True
        for (param, op, rhs_values) in conds:
            if op not in ALLOWED_VERIFY_OPS:
                ops_ok = False
                findings.append({
                    "rule_id": "4.3.1",
                    "category": "TELEMETRY",
                    "severity": "MAJOR",
                    "location": {"line_start": ln, "line_end": ln},
                    "evidence": trim_snippet(line),
                    "explanation": f"Operator '{op}' not in allowed set {sorted(ALLOWED_VERIFY_OPS)}.",
                    "manual_quote": MANUAL_QUOTES["4.3.1-operators"],
                    "status": "VIOLATION",
                    "suggested_fix": "Use one of: eq, ge, gt, lt, le, neq, bw, nbw"
                })
            # For bw/nbw need two RHS values
            if op in {"bw", "nbw"} and len(rhs_values) < 2:
                ops_ok = False
                findings.append({
                    "rule_id": "4.3.1-bw-arity",
                    "category": "TELEMETRY",
                    "severity": "MAJOR",
                    "location": {"line_start": ln, "line_end": ln},
                    "evidence": trim_snippet(line),
                    "explanation": f"Ternary operator '{op}' requires two values on right side.",
                    "manual_quote": "Ternary operators require two values on the right side of the verification.",
                    "status": "VIOLATION",
                    "suggested_fix": "Example: Verify(['TM', bw, low, high])"
                })

        if ops_ok:
            findings.append({
                "rule_id": "4.3.1",
                "category": "TELEMETRY",
                "severity": "MINOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Verify() operators appear valid.",
                "manual_quote": MANUAL_QUOTES["4.3.1-operators"],
                "status": "OK",
                "suggested_fix": ""
            })

        # Modifiers sanity: ValueFormat must be RAW or ENG if present
        kwargs = parse_kwargs(line)
        for k, v in kwargs.items():
            if k.lower() == "valueformat":
                vv = v.strip().strip("'\"")
                if vv.upper() not in ALLOWED_VALUEFORMAT:
                    findings.append({
                        "rule_id": "4.3.1-valueformat",
                        "category": "TELEMETRY",
                        "severity": "MAJOR",
                        "location": {"line_start": ln, "line_end": ln},
                        "evidence": f"ValueFormat={trim_snippet(v)}",
                        "explanation": "ValueFormat must be RAW or ENG.",
                        "manual_quote": "ValueFormat may be used to use engineering or raw value for comparisons.",
                        "status": "VIOLATION",
                        "suggested_fix": "Set ValueFormat=RAW or ValueFormat=ENG"
                    })

        # Tolerance noted (cannot fully validate numeric type statically)
        if any(k.lower() == "tolerance" for k in kwargs.keys()):
            findings.append({
                "rule_id": "4.3.3",
                "category": "TELEMETRY",
                "severity": "MINOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "Tolerance modifier present (numeric comparisons only).",
                "manual_quote": MANUAL_QUOTES["4.3.3-tolerance"],
                "status": "OK",
                "suggested_fix": ""
            })

    # WaitFor used with telemetry condition
    for (ln, line) in waitfor_calls:
        if verify_has_tm_condition_in_waitfor(line):
            findings.append({
                "rule_id": "4.6.3",
                "category": "TELEMETRY",
                "severity": "MINOR",
                "location": {"line_start": ln, "line_end": ln},
                "evidence": trim_snippet(line),
                "explanation": "WaitFor used with telemetry condition (Verify-style), which is valid.",
                "manual_quote": MANUAL_QUOTES["4.6.3-waitfor-verify-style"],
                "status": "OK",
                "suggested_fix": ""
            })

    # Heuristic linkage: each Send should be followed by a telemetry check (Verify/WaitFor/GetTM)
    # within the next N lines
    LINK_WINDOW = 25
    tm_lines = sorted([ln for (ln, _) in verify_calls + waitfor_calls + gettm_calls])
    for (sln, sline) in send_calls:
        has_following_check = any((tln > sln and (tln - sln) <= LINK_WINDOW) for tln in tm_lines)
        if has_following_check:
            findings.append({
                "rule_id": "TELEMETRY-LINK",
                "category": "TELEMETRY",
                "severity": "MINOR",
                "location": {"line_start": sln, "line_end": sln},
                "evidence": trim_snippet(sline),
                "explanation": f"Found telemetry check within {LINK_WINDOW} lines after Send().",
                "manual_quote": "Good practice: verify that commanded action achieved expected telemetry.",
                "status": "OK",
                "suggested_fix": ""
            })
        else:
            findings.append({
                "rule_id": "TELEMETRY-LINK",
                "category": "TELEMETRY",
                "severity": "MAJOR",
                "location": {"line_start": sln, "line_end": sln},
                "evidence": trim_snippet(sline),
                "explanation": f"No telemetry verification found within {LINK_WINDOW} lines after Send().",
                "manual_quote": "While not spelled out as a MUST in the language manual, operational conventions require post-TC verification.",
                "status": "VIOLATION",
                "suggested_fix": "Add Verify([...]) or WaitFor([...]) to confirm the effect of the command."
            })

    # -----------------------------
    # Compute score per policy:
    # (# MUST rules satisfied / # MUST rules applicable) * 100
    #
    # We define MUST as:
    # - COMMAND: 4.5.1 keyword 'command' (MUST)
    # - COMMAND: 4.5.2 Time absolute (if Time present) (MUST)
    # - COMMAND: 4.5.3 ReleaseTime absolute (if present) (MUST)
    # - TELEMETRY: 4.3.1 operator validity (MUST when Verify is present)
    # - TELEMETRY: TELEMETRY-LINK after Send (treat as MUST per user's emphasis)
    # Header rules are heuristics -> NOT MUST unless explicit header rules are provided
    # (if user supplies --header-rules, we upgrade HEADER to MUST).
    # -----------------------------
    must_ids = set(["4.5.1", "4.5.2", "4.5.3", "4.3.1", "TELEMETRY-LINK"])
    header_explicit = (header_rules is not HEURISTIC_HEADER_RULES)
    if header_explicit:
        # Treat provided header mandatory fields as MUST
        for rule in header_rules.get("mandatory", []):
            must_ids.add(f"HEADER:{rule['name']}")

    applicable = 0
    satisfied = 0
    for f in findings:
        rid = f["rule_id"]
        status = f["status"]
        # A rule is applicable if it exists in must_ids AND its preconditions are met:
        # For 4.5.2/4.5.3 only if Time/ReleaseTime was present (we already created either OK or VIOLATION).
        if rid in must_ids:
            applicable += 1
            if status == "OK":
                satisfied += 1

    score = 100 if applicable == 0 else round(100.0 * satisfied / applicable, 2)
    overall_status = "PASS" if (score >= 95 and not any(
        f["severity"] == "CRITICAL" and f["status"] == "VIOLATION" for f in findings)) else "FAIL"

    # Summary
    hdr_issues = any(f["category"] == "HEADER" and f["status"] == "VIOLATION" for f in findings)
    cmd_issues = any(f["category"] == "COMMAND" and f["status"] == "VIOLATION" for f in findings)
    tm_issues = any(f["category"] == "TELEMETRY" and f["status"] == "VIOLATION" for f in findings)
    summary = (
        f"Header {'OK' if not hdr_issues else 'has issues'}; "
        f"command sending {'OK' if not cmd_issues else 'has issues'}; "
        f"telemetry verification {'OK' if not tm_issues else 'has issues'}."
    )

    result = {
        "manual_version": manual_version,
        "overall_compliance": {
            "status": overall_status,
            "score_percent": score
        },
        "summary": summary,
        "findings": findings
    }
    return result


# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="SPELL v2.0.1 compliance auditor (header/command/telemetry)")
    parser.add_argument("procedure_path", help="Path to the SPELL procedure file")
    parser.add_argument("--manual-version", default="2.0.1", help="Manual version string for output")
    parser.add_argument("--header-rules", default=None,
                        help="Optional JSON file with mandatory header rules & patterns")
    args = parser.parse_args()

    if not os.path.exists(args.procedure_path):
        print(json.dumps({
            "manual_version": args.manual_version,
            "overall_compliance": {"status": "UNDETERMINED", "score_percent": 0},
            "summary": "Procedure file not found.",
            "findings": []
        }, ensure_ascii=False))
        return

    lines = load_text(args.procedure_path)
    header_rules = load_header_rules(args.header_rules)
    result = audit(lines, args.manual_version, header_rules)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

"""
Example --header-rules JSON if your organization mandates explicit tags:

{
  "mandatory": [
    {"name": "PROC",    "pattern": "^\\s*PROC\\s*=\\s*\"[^\"]+\"\\s*$", "desc": "Procedure name"},
    {"name": "VERSION", "pattern": "^\\s*VERSION\\s*=\\s*\"\\d+(\\.\\d+)*\"\\s*$", "desc": "Version"},
    {"name": "AUTHOR",  "pattern": "^\\s*AUTHOR\\s*=\\s*\"[^\"]+\"\\s*$", "desc": "Author"},
    {"name": "PURPOSE", "pattern": "^\\s*PURPOSE\\s*=\\s*\"[^\"]+\"\\s*$", "desc": "Purpose"},
    {"name": "DATE",    "pattern": "^\\s*DATE\\s*=\\s*\"\\d{4}-\\d{2}-\\d{2}( \\d{2}:\\d{2}(:\\d{2})?)?\"\\s*$", "desc": "Date"}
  ],
  "formatting": { "header_window_lines": 80 }
}
"""
