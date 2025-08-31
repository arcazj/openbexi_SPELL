#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPELL Procedure Compliance Auditor
# - Focus on header, command sending, telemetry verification
# - Appendix A function arity/type checks (core subset + extensions)
# - Updated to enforce ONLY commented header (no legacy fields anywhere).
#
# CLI:
#   python3 spell_auditor.py <procedure.spell> [--json] [--header-rules header_rules.json]

import argparse, json, re, sys, os
from typing import Any, Dict, List, Tuple, Optional

# ---------------- Operators & helpers ----------------
ALLOWED_VERIFY_OPS = {"eq", "ge", "gt", "lt", "le", "neq", "bw", "nbw"}

HEADER_BANNER = "#" * 80
HEADER_LINE_RE = re.compile(r"^\s*#\s*([A-Z_]+)\s*:\s*(.+?)\s*$")

REQUIRED_COMMENT_KEYS_DEFAULT = ("NAME", "DESCRIPTION", "FILE", "SPACECRAFT")

# Used to expose the path inside audit() without changing signature
CURRENT_PROCEDURE_PATH: Optional[str] = None

FUNC_NAME_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(')

KWARG_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^,]+?)(?=(?:,|$))')

def _strip_comment(s: str) -> str:
    in_s = False; in_d = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == '#' and not in_s and not in_d:
            return s[:i]
    return s

def _call_args_text(line: str) -> str:
    try:
        line = _strip_comment(line)
        start = line.index('(') + 1
        end = line.rfind(')')
        return line[start:end].strip()
    except ValueError:
        return ""

def _split_top_level_args(args_text: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    in_sq = False
    in_dq = False
    i = 0
    while i < len(args_text):
        ch = args_text[i]
        if ch == "'" and not in_dq:
            in_sq = not in_sq; buf.append(ch)
        elif ch == '"' and not in_sq:
            in_dq = not in_dq; buf.append(ch)
        elif ch in '([{':
            if not in_sq and not in_dq:
                depth += 1
            buf.append(ch)
        elif ch in ')]}':
            if not in_sq and not in_dq:
                depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ',' and depth == 0 and not in_sq and not in_dq:
            part = ''.join(buf).strip()
            if part: parts.append(part)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = ''.join(buf).strip()
    if tail: parts.append(tail)
    pos = [p for p in parts if '=' not in p]
    return pos

def _is_string_literal_token(tok: str) -> bool:
    tok = tok.strip()
    return len(tok) >= 2 and tok[0] in ('"', "'") and tok[-1] == tok[0]

def _is_number_literal(tok: str) -> bool:
    tok = tok.strip()
    return bool(re.match(r'^[-+]?\d+(?:\.\d+)?$', tok))

def _is_list_like(tok: str) -> bool:
    tok = tok.strip()
    return tok.startswith('[') and tok.endswith(']')

def _is_index_expr(tok: str) -> bool:
    s = tok.strip()
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*\[.+\]\s*$", s))

def _is_iso_datetime(tok: str) -> bool:
    t = tok.strip().strip("'\"")
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$", t))

def _is_time_expr(tok: str) -> bool:
    tok = tok.strip().strip("'\"")
    if re.match(r'^\s*NOW\s*([+-]\s*\d+(?:\.\d+)?\s*\*\s*[A-Za-z_][A-Za-z0-9_]*)?\s*$', tok):  # NOW +/- N*UNIT
        return True
    if re.match(r'^[-+]?\d+(?:\.\d+)?\s*(?:\*\s*[A-Za-z_][A-Za-z0-9_]*)?$', tok):
        return True
    return False

def _is_time_string(tok: str) -> bool:
    t = tok.strip().strip("'\"")
    if re.match(r'^\+?\d{1,2}:\d{2}:\d{2}$', t): return True
    if re.match(r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}$', t): return True
    if re.match(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$', t): return True
    return False

def _is_time_like(tok: str) -> bool:
    s = tok.strip()
    if _is_number_literal(s): return True
    if _is_time_expr(s): return True
    if _is_string_literal_token(s) and _is_time_string(s): return True
    return False

def _is_list_of_time_like(tok: str) -> bool:
    s = tok.strip()
    if not _is_list_like(s): return False
    inner = s[1:-1].strip()
    if not inner: return False
    parts = _split_top_level_args(inner)
    if not parts:
        parts = [p.strip() for p in inner.split(",")]
    return all(_is_time_like(p) for p in parts)

def _is_ident(tok: str) -> bool:
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', tok.strip()))

def _is_enum_set(tok: str, allowed: set) -> bool:
    s = tok.strip().strip("'\"")
    if s == "NOACTION":
        return "NOACTION" in allowed or True
    parts = [p.strip() for p in s.split('|') if p.strip()]
    return all(p in allowed for p in parts) and len(parts) > 0

def _is_flag_set(tok: str, allowed: set) -> bool:
    s = tok.strip().strip("'\"")
    parts = [p.strip() for p in s.split('|') if p.strip()]
    return all(p in allowed for p in parts) and len(parts) > 0

def _is_string_bool_time(tok: str) -> bool:
    s = tok.strip()
    if _is_string_literal_token(s): return True
    if re.match(r'^(True|False|true|false|1|0)$', s.strip("'\"") or s): return True
    return _is_time_like(s)

def _infer_pos_type(tok: str) -> str:
    if _is_string_literal_token(tok): return 'string'
    if _is_number_literal(tok): return 'number'
    if _is_list_like(tok): return 'list'
    if _is_index_expr(tok): return 'index'
    if _is_ident(tok): return 'ident'
    return 'other'

def parse_kwargs(line: str) -> Dict[str, str]:
    call = _call_args_text(line)
    kwargs: Dict[str, str] = {}
    if not call: return kwargs
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    i = 0
    in_sq = False
    in_dq = False
    while i < len(call):
        ch = call[i]
        if ch in '([{':
            if not in_sq and not in_dq:
                depth += 1
            buf.append(ch)
        elif ch in ')]}':
            if not in_sq and not in_dq:
                depth = max(0, depth - 1)
            buf.append(ch)
        elif ch in ('"', "'"):
            q = ch
            buf.append(ch)
            i += 1
            while i < len(call):
                buf.append(call[i])
                if call[i] == q and call[i-1] != '\\':
                    break
                i += 1
        elif ch == ',' and depth == 0 and not in_sq and not in_dq:
            part = ''.join(buf).strip()
            if part: parts.append(part)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = ''.join(buf).strip()
    if tail: parts.append(tail)
    for part in parts:
        if '=' in part:
            k, v = part.split('=', 1)
            kwargs[k.strip()] = v.strip()

    # Comma-recovery: split embedded " KEY=" inside a value (e.g., Interval=[...] Message='Hi')
    def split_embedded(v: str):
        m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", v)
        if not m:
            return v, {}
        head = v[:m.start()].rstrip()
        tail = v[m.start():].lstrip()
        if '=' in tail:
            k2, v2 = tail.split('=', 1)
            return head.strip().rstrip(','), {k2.strip(): v2.strip()}
        return v, {}

    augmented = {}
    for k, v in list(kwargs.items()):
        new_v, extra = split_embedded(v)
        if extra:
            kwargs[k] = new_v
            augmented.update(extra)
    kwargs.update(augmented)
    return kwargs

def extract_verify_core(line: str):
    if '[[' in line:
        return ('MULTI', 'OK', [])
    m = re.search(r"Verify\s*\(\s*\[(.*?)\]\s*(?:,|\))", line, flags=re.DOTALL)
    if not m: return None
    inner = m.group(1)
    parts = re.split(r"\s*,\s*", inner)
    if len(parts) < 3: return None
    param = parts[0].strip().strip("'\"")
    op = parts[1].strip()
    rhs = [p.strip().strip("'\"") for p in parts[2:]]
    return (param, op, rhs)

# ---------------- Function spec ----------------
FUNCTION_SPEC: Dict[str, Dict[str, Any]] = {
    "Send": {
        "allowed_kw": ["command", "sequence", "group", "args", "verify",
                       "Time", "ReleaseTime", "Queue", "Mode", "Block", "Comments", "Retries",
                       "Wait", "Timeout", "ValueFormat", "Group", "Confirm", "Delay", "SendDelay",
                       "AdjLimits", "OnFailure", "PromptUser", "Tolerance", "LoadOnly"],
        "positional_forbidden": True, "max_pos_args": 0,
        "kw_types": {
            "command": "string_or_ident", "sequence": "string_or_ident", "group": "list", "args": "list",
            "verify": "list",
            "Time": "time_like", "ReleaseTime": "time_like", "Queue": "string", "Mode": "string",
            "Block": "bool", "Comments": "string",
            "Retries": "number", "Wait": "bool", "Timeout": "time_like",
            "ValueFormat": "string_or_ident", "Group": "bool", "Confirm": "bool",
            "Delay": "time_like", "SendDelay": "time_like", "AdjLimits": "bool",
            "OnFailure": "enum_set", "PromptUser": "bool", "Tolerance": "number",
            "LoadOnly": "bool"
        },
        "kw_enums": {"OnFailure": ["ABORT", "REPEAT", "SKIP", "CANCEL"], "ValueFormat": ["RAW", "ENG"]}
    },
    "BuildTC": {
        "allowed_kw": ["command", "Comments", "Retries", "Queue", "Mode", "args"],
        "max_pos_args": 1,
        "pos_types": ["string"],
        "kw_types": {"Comments": "string", "Retries": "number", "Queue": "string", "Mode": "string", "args": "list"}
    },
    "Verify": {
        "requires_tm_list": True,
        "allowed_kw": ["Timeout", "Wait", "Tolerance", "ValueFormat", "Delay", "OnFalse", "OnTrue",
                       "PromptUser", "Retries", "OnFailure", "AdjLimits"],
        "max_pos_args": 1, "pos_types": ["list"],
        "kw_types": {
            "Timeout": "time_like", "Wait": "bool", "Tolerance": "number",
            "ValueFormat": "string_or_ident", "Delay": "time_expr",
            "OnFalse": "enum_set", "OnTrue": "enum_set",
            "PromptUser": "bool", "Retries": "number", "OnFailure": "enum_set", "AdjLimits": "bool"
        },
        "kw_enums": {
            "OnFailure": ["ABORT", "REPEAT", "SKIP", "CANCEL"],
            "OnFalse": ["ABORT", "REPEAT", "SKIP", "CANCEL", "NOACTION"],
            "OnTrue":  ["ABORT", "REPEAT", "SKIP", "CANCEL", "NOACTION"],
            "ValueFormat": ["RAW", "ENG"]
        }
    },
    "WaitFor": {
        "requires_tm_list_or_time": True,
        "allowed_kw": ["Timeout", "Wait", "Delay", "Interval", "Message",
                       "ValueFormat", "OnFailure", "PromptUser", "Retries",
                       "Tolerance", "AdjLimits"],
        "max_pos_args": 1, "pos_types": [["list", "number", "string"]],
        "kw_types": {
            "Timeout": "time_like", "Wait": "bool", "Delay": "time_like",
            "Interval": "time_like_or_time_list", "Message": "string",
            "ValueFormat": "string_or_ident", "OnFailure": "enum_set", "PromptUser": "bool",
            "Retries": "number", "Tolerance": "number", "AdjLimits": "bool"
        },
        "kw_enums": {"OnFailure": ["ABORT", "REPEAT", "SKIP", "CANCEL"], "ValueFormat": ["RAW", "ENG"]}
    },
    "GetTM": {
        "allowed_kw": ["Wait", "Timeout", "ValueFormat", "Extended", "OnFailure", "PromptUser"],
        "kw_types": {"Wait": "bool", "Timeout": "time_like", "ValueFormat": "string_or_ident", "Extended": "bool",
                     "OnFailure": "enum_set", "PromptUser": "bool"},
        "kw_enums": {"OnFailure": ["ABORT", "REPEAT", "SKIP", "CANCEL"], "ValueFormat": ["RAW", "ENG"]},
        "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]
    },
    "Prompt": {"min_args": 1, "max_pos_args": 2, "pos_types": ["string", ["list", "other"]],
               "allowed_kw": ["Type", "Default", "Timeout"],
               "kw_types": {"Type": "flag_set", "Default": "string_bool_time", "Timeout": "time_like"}},
    "PromptUser": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "Display": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "Event": {
        "positional_requires_string": True, "min_args": 1, "max_pos_args": 2, "pos_types": ["string", "ident"],
        "allowed_kw": ["Severity"], "kw_types": {"Severity": "enum_ident"},
        "kw_enums": {"Severity": ["INFO", "WARNING", "ERROR", "CRITICAL"]}
    },
    "Step": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "StartProc": {"positional_requires_string": True, "alt_required_kw": ["proc"], "max_pos_args": 1,
                  "pos_types": ["string"], "kw_types": {"proc": "string", "Blocking": "bool", "Automatic": "bool"},
                  "allowed_kw": ["proc", "Blocking", "Automatic"]},
    "Finish": {"zero_args_ok": True, "max_pos_args": 0},
    "Abort": {"zero_args_ok": True, "max_pos_args": 0},
    "SetLimits": {"positional_requires_string": True, "min_args": 2, "max_pos_args": 2,
                  "pos_types": ["string", ["string", "ident"]], "allowed_kw": ["Select"],
                  "kw_types": {"Select": "string_or_ident"}},
    "GetLimits": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"],
                  "allowed_kw": ["Select"], "kw_types": {"Select": "string_or_ident"}},
    "IsAlarmed": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "EnableAlarm": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "DisableAlarm": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "EnableUserAction": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "DisableUserAction": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "DismissUserAction": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "SetUserAction": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "SetResource": {"positional_requires_string": True, "min_args": 2, "max_pos_args": 2,
                    "pos_types": [["string","ident","index"], ["string","number","ident","index"]]},
    "SetGroundParameter": {"positional_requires_string": True, "min_args": 2, "max_pos_args": 2,
                           "pos_types": [["string","ident","index"], ["string","number","ident","index"]]},
    "GetResource": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "ReleaseResource": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "CreateDictionary": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "SaveDictionary": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "LoadDictionary": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "ChangeLanguageConfig": {"require_any_kw_in": ["Interface", "Database", "URIs"], "max_pos_args": 0,
                             "kw_types": {"Interface": "string", "Database": "string", "URIs": "string"}},
    "OpenDisplay": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"],
                    "allowed_kw": ["Host"], "kw_types": {"Host": "string"}},
    "CloseDisplay": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "ShowDisplay": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "HideDisplay": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "PrintDisplay": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"],
                     "required_kw": ["Printer"], "kw_types": {"Printer": "string"}},
    "Include": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "Call": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "Select": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]},
    "Pause": {"min_args": 1, "max_pos_args": 1, "pos_types": ["number"]},
    "Delay": {"min_args": 1, "max_pos_args": 1, "pos_types": ["number"]},
    "Log": {"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"],
            "allowed_kw": ["Level"], "kw_types": {"Level": "string"}}
}

def derive_spec_for(lname: str) -> Dict[str, Any]:
    spec: Dict[str, Any] = {}
    if any(key in lname for key in ("Prompt", "Display", "Event", "Step")) and lname != "PrintDisplay":
        spec.update({"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]})
    if any(lname.startswith(p) for p in ("Enable", "Disable", "Dismiss")):
        spec.update({"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]})
    if lname.startswith("Set") and lname not in FUNCTION_SPEC:
        spec.update({"positional_requires_string": True, "min_args": 1, "max_pos_args": 2, "pos_types": ["string", "any"]})
    if lname.startswith("Get") and lname not in FUNCTION_SPEC:
        spec.update({"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]})
    if lname in ("Include", "Call", "Select", "OpenDisplay", "CloseDisplay", "ShowDisplay", "HideDisplay",
                 "GetResource", "ReleaseResource", "LoadDictionary"):
        spec.update({"positional_requires_string": True, "min_args": 1, "max_pos_args": 1, "pos_types": ["string"]})
    return spec

# --------------- Header rules loading (optional) ----------------
def load_header_rules(path: Optional[str]) -> Dict[str, Any]:
    if not path: 
        return {"required_keys": list(REQUIRED_COMMENT_KEYS_DEFAULT), "file_must_match": True, "spacecraft_check": True}
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
        req = data.get("required_keys") or list(REQUIRED_COMMENT_KEYS_DEFAULT)
        return {
            "required_keys": [k.upper() for k in req],
            "file_must_match": bool(data.get("file_must_match", True)),
            "spacecraft_check": bool(data.get("spacecraft_check", True)),
        }
    except Exception:
        return {"required_keys": list(REQUIRED_COMMENT_KEYS_DEFAULT), "file_must_match": True, "spacecraft_check": True}

def _parse_commented_header(lines: List[str]) -> Tuple[Dict[str,str], int]:
    mapping: Dict[str,str] = {}
    if not lines: return mapping, 0
    if not lines[0].strip().startswith(HEADER_BANNER):
        return mapping, 0
    end = 0
    for idx, ln in enumerate(lines, start=1):
        if idx == 1: 
            continue
        if ln.strip().startswith(HEADER_BANNER):
            end = idx
            break
        m = HEADER_LINE_RE.match(ln)
        if m:
            mapping[m.group(1).upper()] = m.group(2).strip()
    return mapping, end

# ------------------- Core audit -------------------
def audit(procedure_text: str, only_json: bool, header_rules: Dict[str, Any]) -> Dict[str, Any]:
    lines = procedure_text.splitlines()

    # Expand lines by ';' so multiple calls on one line are seen
    expanded = []
    for ln in lines:
        if ';' in ln:
            expanded.extend([seg for seg in ln.split(';') if seg.strip()])
        else:
            expanded.append(ln)
    lines = expanded

    findings: List[Dict[str, Any]] = []

    # ---------- Commented header policy (no legacy fields) ----------
    header_map, header_end = _parse_commented_header(lines)
    req_keys = header_rules.get("required_keys", list(REQUIRED_COMMENT_KEYS_DEFAULT))

    for key in req_keys:
        if key not in header_map or not header_map[key]:
            findings.append({
                "rule_id": f"HEADER_COMMENTED:{key}",
                "category": "HEADER",
                "severity": "MAJOR",
                "location": {"line_start": 1, "line_end": max(1, header_end)},
                "evidence": "",
                "explanation": f"Missing mandatory commented header field #{key} :",
                "manual_quote": "Commented header must include # NAME, # DESCRIPTION, # FILE, # SPACECRAFT.",
                "status": "VIOLATION",
                "suggested_fix": f'Add "# {key} : ..." inside the top banner'
            })

    if header_rules.get("file_must_match", True) and CURRENT_PROCEDURE_PATH and header_map.get("FILE"):
        actual = os.path.basename(CURRENT_PROCEDURE_PATH)
        if header_map["FILE"].strip() != actual:
            findings.append({
                "rule_id": "HEADER_COMMENTED:FILE_MATCH",
                "category": "HEADER",
                "severity": "MAJOR",
                "location": {"line_start": 1, "line_end": max(1, header_end)},
                "evidence": f'# FILE : {header_map["FILE"]}',
                "explanation": f'# FILE must match procedure filename: expected "{actual}".',
                "manual_quote": "FILE must be the procedure filename with .spell/.py extension.",
                "status": "VIOLATION",
                "suggested_fix": f'Change "# FILE : {header_map["FILE"]}" to "# FILE : {actual}"'
            })

    if header_rules.get("spacecraft_check", True):
        scv = header_map.get("SPACECRAFT")
        if scv:
            tokens = [t.strip() for t in scv.split(",") if t.strip()]
            bad = []
            for t in tokens:
                if not (re.fullmatch(r"[A-Za-z0-9_\-]+", t) or re.fullmatch(r"\d+", t)):
                    bad.append(t)
            if not tokens or bad:
                findings.append({
                    "rule_id": "HEADER_COMMENTED:SPACECRAFT_FORMAT",
                    "category": "HEADER",
                    "severity": "MAJOR",
                    "location": {"line_start": 1, "line_end": max(1, header_end)},
                    "evidence": f"# SPACECRAFT : {scv}",
                    "explanation": "SPACECRAFT must be a single value or CSV of numeric IDs or simple names.",
                    "manual_quote": "SPACECRAFT: single or list of satellites separated by comma; values are numbers or simple strings.",
                    "status": "VIOLATION",
                    "suggested_fix": 'Example: "# SPACECRAFT  : SAT_A, 1111"'
                })
        else:
            # Already marked missing by required_keys loop if needed
            pass

    send_lines = []
    verify_like_after_send = False

    for idx, line in enumerate(lines, start=1):
        sline = line.strip()
        if not sline or sline.startswith('#'):
            continue

        if re.match(r'^\s*Send\s*\(', sline):
            send_lines.append(idx)
        # Verify-like after send or inline verify
        if send_lines and (re.search(r'^\s*(Verify|WaitFor|GetTM)\s*\(', sline)):
            verify_like_after_send = True

        # Send positional checks & keywords presence
        if re.match(r'^\s*Send\s*\(', sline):
            kwargs = parse_kwargs(sline)
            args_text = _call_args_text(sline)
            lowkeys = {k.lower(): v for k, v in kwargs.items()}
            if 'verify' in lowkeys:
                verify_like_after_send = True
            if not any(k in lowkeys for k in ('command', 'sequence', 'group')):
                if '"' in args_text or "'" in args_text or '[' in args_text:
                    findings.append({
                        "rule_id": "4.5.1",
                        "category": "COMMAND",
                        "severity": "MAJOR",
                        "location": {"line_start": idx, "line_end": idx},
                        "evidence": sline,
                        "explanation": "Send() requires one of: command=, sequence=, or group=. Positional not allowed.",
                        "manual_quote": "Send: use keywords to identify command/sequence/group.",
                        "status": "VIOLATION",
                        "suggested_fix": "Use Send(command='CMD', ...) or Send(sequence='SEQ') or Send(group=[...])"
                    })

        # GetTM: Timeout without Wait=True is meaningless
        if re.match(r'^\s*GetTM\s*\(', sline):
            kwargs = parse_kwargs(sline)
            low = {k.lower(): kwargs[k] for k in kwargs}
            if 'timeout' in low and ( 'wait' not in low or low['wait'].strip().strip("'\"").lower() not in ('true', '1')):
                findings.append({
                    "rule_id": "4.2.TIMEOUT_WITHOUT_WAIT",
                    "category": "TELEMETRY",
                    "severity": "MINOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": "Timeout is only meaningful when Wait=True; otherwise it is ignored.",
                    "manual_quote": "Timeout shall be used with Wait=True; otherwise ignored.",
                    "status": "VIOLATION",
                    "suggested_fix": "Add Wait=True or remove Timeout."
                })

        # Verify: operator check
        if re.match(r'^\s*Verify\s*\(', sline):
            if '[[' not in sline:
                core = extract_verify_core(sline)
                if not core:
                    findings.append({
                        "rule_id": "4.3.1",
                        "category": "TELEMETRY",
                        "severity": "MAJOR",
                        "location": {"line_start": idx, "line_end": idx},
                        "evidence": sline,
                        "explanation": "Could not parse TM verify list format.",
                        "manual_quote": "Verify takes a list: ['TM', op, value].",
                        "status": "VIOLATION",
                        "suggested_fix": "Use Verify(['TM_NAME', eq, 1], Timeout=...)"
                    })
                else:
                    (_param, op, _rhs) = core
                    if op not in ALLOWED_VERIFY_OPS:
                        findings.append({
                            "rule_id": "4.3.1.OP",
                            "category": "TELEMETRY",
                            "severity": "MAJOR",
                            "location": {"line_start": idx, "line_end": idx},
                            "evidence": sline,
                            "explanation": f"Operator {op} is not allowed.",
                            "manual_quote": "Allowed: eq, ge, gt, lt, le, neq, bw, nbw.",
                            "status": "VIOLATION",
                            "suggested_fix": "Use a valid operator (e.g., eq)."
                        })

        # Appendix-A enforcement
        mname = FUNC_NAME_RE.search(sline)
        if not mname:
            continue
        lname = mname.group(1)
        if lname in ('if', 'for', 'while', 'def', 'class', 'try', 'except', 'with', 'return', 'elif', 'else'):
            continue

        spec = FUNCTION_SPEC.get(lname, {}) or derive_spec_for(lname)
        kwargs = parse_kwargs(sline)
        args_text = _call_args_text(sline)
        pos_args = _split_top_level_args(args_text)

        # Special SetLimits forms
        setlimits_list_form = False
        setlimits_uri_form = False
        if lname == "SetLimits" and pos_args:
            first = pos_args[0].strip()
            if first.startswith('[[') and first.endswith(']]'):
                setlimits_list_form = True
            if (first.startswith("'") and first.endswith("'")) or (first.startswith('"') and first.endswith('"')):
                inner = first[1:-1]
                if inner.startswith('limits://'):
                    setlimits_uri_form = True

        # Required keywords
        for rk in spec.get("required_kw", []):
            if not any(rk.lower() == k.lower() for k in kwargs.keys()):
                findings.append({
                    "rule_id": f"A.{lname}.REQKW",
                    "category": "COMMAND" if lname in ("Send", "BuildTC") else "TELEMETRY",
                    "severity": "MAJOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": f"{lname}() missing required keyword '{rk}'.",
                    "manual_quote": f"{lname}: required keyword '{rk}'.",
                    "status": "VIOLATION",
                    "suggested_fix": f"Add {rk}=..."
                })

        # BuildTC: must have either positional CMD or command=
        if lname == "BuildTC":
            if len(pos_args) == 0 and not any(k.lower() == "command" for k in kwargs.keys()):
                findings.append({
                    "rule_id": f"A.{lname}.REQKW",
                    "category": "COMMAND",
                    "severity": "MAJOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": f"{lname}() requires a positional command name or command='NAME'.",
                    "manual_quote": f"{lname}: accepts positional 'CMD' or keyword command='CMD'.",
                    "status": "VIOLATION",
                    "suggested_fix": f"{lname}('CMD') or {lname}(command='CMD')"
                })

        # Positional forbidden
        if spec.get("positional_forbidden", False) and pos_args:
            findings.append({
                "rule_id": f"A.{lname}.POSITIONAL",
                "category": "COMMAND",
                "severity": "MAJOR",
                "location": {"line_start": idx, "line_end": idx},
                "evidence": sline,
                "explanation": f"Positional arguments not allowed in {lname}().",
                "manual_quote": f"{lname}: use keyword arguments only.",
                "status": "VIOLATION",
                "suggested_fix": f"Use {lname}(key=value, ...)"
            })

        # First positional must be string for message/name functions
        if spec.get("positional_requires_string"):
            if not (lname == "SetLimits" and (setlimits_list_form or setlimits_uri_form)):
                if not pos_args or not _is_string_literal_token(pos_args[0]):
                    if not (lname == "StartProc" and any(k.lower() == "proc" for k in kwargs.keys())):
                        findings.append({
                            "rule_id": f"A.{lname}.POSSTR",
                            "category": "TELEMETRY",
                            "severity": "MAJOR",
                            "location": {"line_start": idx, "line_end": idx},
                            "evidence": sline,
                            "explanation": f"{lname}() expects first positional argument as a quoted string.",
                            "manual_quote": f"{lname}: examples show first arg is a string.",
                            "status": "VIOLATION",
                            "suggested_fix": f"Use {lname}('name or message', ...)"
                        })

        # Max/min positional args with SetLimits alternatives handled
        if lname == 'SetLimits' and (setlimits_list_form or setlimits_uri_form):
            if len(pos_args) > 1:
                findings.append({
                    "rule_id": f"A.{lname}.ARGS_MAX",
                    "category": "TELEMETRY",
                    "severity": "MAJOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": f"{lname}() alternative form allows exactly 1 positional argument.",
                    "manual_quote": f"{lname}: list-of-lists or URI form takes a single argument.",
                    "status": "VIOLATION",
                    "suggested_fix": "Remove extra positionals; keep only the single form."
                })
        else:
            if 'max_pos_args' in spec and len(pos_args) > spec['max_pos_args']:
                findings.append({
                    "rule_id": f"A.{lname}.ARGS_MAX",
                    "category": "TELEMETRY" if lname.startswith(("Get","Set")) else "COMMAND",
                    "severity": "MAJOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": f"{lname}() allows at most {spec['max_pos_args']} positional argument(s).",
                    "manual_quote": f"{lname}: see Appendix A signature.",
                    "status": "VIOLATION",
                    "suggested_fix": "Remove extra positional args; use keywords."
                })

        if "min_args" in spec:
            eff_min = spec["min_args"]
            if lname == "StartProc" and any(k.lower() == "proc" for k in kwargs.keys()): 
                eff_min = 0
            if lname == "SetLimits" and (setlimits_list_form or setlimits_uri_form):
                eff_min = 1
            if len(pos_args) < eff_min:
                findings.append({
                    "rule_id": f"A.{lname}.ARGS_MIN",
                    "category": "TELEMETRY" if lname.startswith(("Get","Set")) else "COMMAND",
                    "severity": "MAJOR",
                    "location": {"line_start": idx, "line_end": idx},
                    "evidence": sline,
                    "explanation": f"{lname}() expects at least {spec['min_args']} positional argument(s); found {len(pos_args)}.",
                    "manual_quote": f"{lname}: see Appendix A signature.",
                    "status": "VIOLATION",
                    "suggested_fix": f"Provide required positional arguments to {lname}()."
                })

        # Positional type checks
        if 'pos_types' in spec and pos_args and not (lname == 'SetLimits' and (setlimits_list_form or setlimits_uri_form)):
            allowed_list = spec['pos_types']
            for i, tok in enumerate(pos_args):
                if i >= len(allowed_list): break
                allowed = allowed_list[i]; allowed = [allowed] if isinstance(allowed, str) else allowed
                actual = _infer_pos_type(tok)
                if lname == 'WaitFor' and _is_time_like(tok):
                    pass
                elif 'any' not in allowed and actual not in allowed:
                    findings.append({
                        "rule_id": f"A.{lname}.POSTYPE",
                        "category": "COMMAND" if lname in ('Send', 'BuildTC') else "TELEMETRY",
                        "severity": "MAJOR",
                        "location": {"line_start": idx, "line_end": idx},
                        "evidence": sline,
                        "explanation": f"Positional argument {i + 1} for {lname}() must be of type {allowed}, found {actual}.",
                        "manual_quote": f"{lname}: see Appendix A signature and examples.",
                        "status": "VIOLATION",
                        "suggested_fix": "Use the correct literal type (e.g., quoted string, numeric, or list)."
                    })

        # Keyword types
        for kw_name, kw_type in (spec.get("kw_types") or {}).items():
            for k in list(kwargs.keys()):
                if k == kw_name:
                    v = kwargs[k].strip()
                    ok = True
                    if kw_type == 'bool':
                        ok = bool(re.match(r'^(True|False|true|false|1|0)$', v.strip("'\"")))
                    elif kw_type == 'string':
                        ok = _is_string_literal_token(v)
                    elif kw_type == 'number':
                        ok = bool(re.match(r"^[-+]?\d+(?:\.\d+)?$", v.strip("'\"")))
                    elif kw_type == 'string_or_ident':
                        ok = _is_string_literal_token(v) or _is_ident(v)
                    elif kw_type == 'enum_ident':
                        enums = (spec.get('kw_enums') or {}).get(kw_name, [])
                        val = v.strip().strip('"\'')
                        ok = val in enums
                    elif kw_type == 'enum_set':
                        enums = set((spec.get('kw_enums') or {}).get(kw_name, []))
                        ok = _is_enum_set(v, enums)
                    elif kw_type == 'flag_set':
                        allowed = {"OK", "YESNO", "LIST", "NUM", "ALPHA"}
                        ok = _is_flag_set(v, allowed)
                    elif kw_type == 'time_expr':
                        ok = _is_time_expr(v)
                    elif kw_type == 'time_like':
                        ok = _is_time_like(v)
                    elif kw_type == 'time_like_or_time_list':
                        ok = _is_time_like(v) or _is_list_of_time_like(v)
                    elif kw_type == 'string_bool_time':
                        ok = _is_string_bool_time(v)
                    elif kw_type == 'list':
                        ok = _is_list_like(v)
                    else:
                        ok = True
                    if not ok:
                        findings.append({
                            "rule_id": f"A.{lname}.KWTYPE",
                            "category": "TELEMETRY" if lname.startswith(("Get","Set","Wait","Verify")) else "COMMAND",
                            "severity": "MAJOR",
                            "location": {"line_start": idx, "line_end": idx},
                            "evidence": f"{k}={kwargs[k]}",
                            "explanation": f"Keyword '{kw_name}' for {lname}() should be {kw_type}.",
                            "manual_quote": f"{lname}: '{kw_name}' type expectation.",
                            "status": "VIOLATION",
                            "suggested_fix": f"Set {kw_name} to a valid {kw_type}."
                        })

        # Unknown keywords (soft) if schema exists
        allowed_union = set([*(FUNCTION_SPEC.get(lname, {}).get("allowed_kw") or []),
                             *(FUNCTION_SPEC.get(lname, {}).get("required_kw") or []),
                             *(FUNCTION_SPEC.get(lname, {}).get("require_any_kw_in") or []),
                             *(FUNCTION_SPEC.get(lname, {}).get("alt_required_kw") or []),
                             *list((FUNCTION_SPEC.get(lname, {}).get("kw_types") or {}).keys())])
        if allowed_union:
            for k in kwargs.keys():
                if k not in allowed_union:
                    findings.append({
                        "rule_id": f"A.{lname}.KW",
                        "category": "COMMAND" if lname in ("Send", "BuildTC") else "TELEMETRY",
                        "severity": "MINOR",
                        "location": {"line_start": idx, "line_end": idx},
                        "evidence": sline,
                        "explanation": f"Unknown keyword '{k}' for {lname}().",
                        "manual_quote": "Appendix B: Modifiers table.",
                        "status": "VIOLATION",
                        "suggested_fix": "Remove or replace unknown keyword."
                    })

    # Telemetry link for Send
    if send_lines and not verify_like_after_send:
        first = send_lines[0]
        findings.append({
            "rule_id": "TELEMETRY-LINK",
            "category": "TELEMETRY",
            "severity": "MINOR",
            "location": {"line_start": first, "line_end": first},
            "evidence": "Send(...) without subsequent Verify/WaitFor/GetTM or inline verify",
            "explanation": "Telecommand should be followed by a telemetry confirmation check.",
            "manual_quote": "Each critical command requires confirmation.",
            "status": "VIOLATION",
            "suggested_fix": "Add a Verify/WaitFor/GetTM or inline verify=[...] after Send()."
        })

    # Final pass: ensure GetTM Extended is boolean even when embedded in assignments
    for idx2, line2 in enumerate(lines, start=1):
        s = _strip_comment(line2).strip()
        if not s or s.startswith('#'):
            continue
        if 'GetTM' in s and 'Extended' in s:
            m = re.search(r'GetTM\s*\((.*)\)', s)
            if m:
                inner = m.group(1)
                m2 = re.search(r'\bExtended\s*=\s*([^,\)\s]+)', inner)
                if m2:
                    val = m2.group(1).strip("'\"")
                    if not re.fullmatch(r'(True|False|true|false|1|0)', val):
                        findings.append({
                            "rule_id": "A.GetTM.KWTYPE",
                            "category": "TELEMETRY",
                            "severity": "MAJOR",
                            "location": {"line_start": idx2, "line_end": idx2},
                            "evidence": s,
                            "explanation": "Keyword 'Extended' for GetTM() should be bool.",
                            "manual_quote": "GetTM: 'Extended' expects boolean (True/False).",
                            "status": "VIOLATION",
                            "suggested_fix": "Set Extended to True or False."
                        })

    # Scoring
    must_ids = set(["4.5.1", "4.3.1"])
    for f in list(findings):
        if str(f.get('rule_id', '')).startswith("HEADER_COMMENTED:"):
            must_ids.add(f['rule_id'])
        if str(f.get('rule_id', '')).startswith("A.") and f.get('severity') in ("MAJOR", "CRITICAL"):
            must_ids.add(f['rule_id'])
    applicable = len(must_ids)
    violated = set([f['rule_id'] for f in findings if f['status'] == "VIOLATION" and f['rule_id'] in must_ids])
    satisfied = applicable - len(violated)
    score = 0 if applicable == 0 else round(100.0 * satisfied / applicable, 2)
    status = "PASS" if score >= 95 and not any(
        f['severity'] == "CRITICAL" for f in findings if f['status'] == "VIOLATION") else "FAIL"

    return {
        "manual_version": "2.0.1",
        "overall_compliance": {"status": status, "score_percent": score},
        "summary": "Header (commented only), command send, and telemetry checks per v2.0.1 with expanded time and function coverage.",
        "findings": findings
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("procedure_path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--header-rules", help="Optional JSON file to override required header keys and checks")
    args = ap.parse_args()

    global CURRENT_PROCEDURE_PATH
    CURRENT_PROCEDURE_PATH = args.procedure_path

    try:
        text = open(args.procedure_path, "r", encoding="utf-8").read()
    except Exception as e:
        err = {"error": str(e), "manual_version": "2.0.1"}
        print(json.dumps(err, indent=2) if args.json else f"[ERROR] {e}")
        sys.exit(1)

    header_rules = load_header_rules(args.header_rules)
    res = audit(text, args.json, header_rules)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Manual: {res['manual_version']} | Status: {res['overall_compliance']['status']} | Score: {res['overall_compliance']['score_percent']}%")
        for f in res["findings"]:
            if f["status"] != "VIOLATION": continue
            loc = f["location"]; locs = f"lines {loc['line_start']}-{loc['line_end']}" if loc["line_start"] else "header"
            print(f"\\n[{f['severity']}] {f['rule_id']} ({f['category']}) @ {locs}\\nEvidence: {f['evidence']}\\nWhy: {f['explanation']}\\nManual: {f['manual_quote']}\\nFix: {f['suggested_fix']}")

if __name__ == "__main__":
    main()
