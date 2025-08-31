#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_tests.py — robust runner for the SPELL Procedure Compliance Auditor

Writes:
  json/results_details.json
  json/results_summary.csv

Handles:
- PyCharm debugger noise on stdout (extracts embedded JSON block).
- Flexible MANIFEST.json:
    {"cases":[ "a.spell", {"file":"b.spell"}, "*.spell", "**/*.spell" ]},
    {"positive":[...], "negative":[...]},
    {"all":[...]},
    or a flat list [...]
- Globs relative to cases/
- Paths with/without the cases/ prefix
"""

from __future__ import annotations
import csv
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

ROOT = Path(__file__).resolve().parent

AUDITOR = ROOT / "spell_auditor.py"               # auditor CLI in repo root
HDR      = ROOT / "header_rules.json"             # active header rules
HDR_FALLBACK = ROOT / "header_rules_default.json" # fallback if HDR missing
CASES    = ROOT / "cases"                         # test cases directory
OUTDIR   = ROOT / "json"                          # where results are written
OUT_JSON = OUTDIR / "results_details.json"
OUT_CSV  = OUTDIR / "results_summary.csv"
MANIFEST = ROOT / "MANIFEST.json"                 # optional selector


# ---------- Interpreter resolution ----------

def _cmd_ok(cmd: List[str]) -> bool:
    try:
        proc = subprocess.run(cmd + ["-c", "print(1)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode == 0 and "1" in proc.stdout
    except Exception:
        return False

def resolve_python() -> List[str]:
    """
    Return a command list for a working Python interpreter.
    Tries sys.executable, local venvs, and common aliases (py -3, python3, python).
    """
    candidates: List[List[str]] = []

    # 1) Current interpreter
    if sys.executable:
        candidates.append([sys.executable])

    # 2) Local virtualenvs
    candidates += [
        [str(ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python"))],
        [str(ROOT / "venv"  / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python"))],
    ]

    # 3) Common aliases
    if os.name == "nt":
        candidates += [["py", "-3"], ["py"], ["python3"], ["python"]]
    else:
        candidates += [["python3"], ["python"]]

    for cmd in candidates:
        if _cmd_ok(cmd):
            return cmd

    msg = "Could not locate a working Python interpreter. Tried:\n" + \
          "\n".join("  " + " ".join(shlex.quote(x) for x in c) for c in candidates)
    print("[ERROR] " + msg, file=sys.stderr)
    sys.exit(2)

PY = resolve_python()
print(f"[INFO] Using interpreter: {' '.join(PY)}", file=sys.stderr)


# ---------- Manifest handling ----------

def _expand_entry(entry) -> list[Path]:
    # Dict entry support: {"file": "x"}, {"path": "x"}, {"name": "x"}
    if isinstance(entry, dict):
        entry = entry.get("file") or entry.get("path") or entry.get("name")
        if not entry:
            return []
    entry = str(entry)

    # Glob? expand relative to CASES (supports **)
    if any(ch in entry for ch in "*?[]"):
        return [p.resolve() for p in CASES.glob(entry) if p.suffix.lower() == ".spell"]

    # Otherwise: absolute or relative to CASES
    p = Path(entry)
    if p.is_absolute():
        return [p] if p.suffix.lower() == ".spell" and p.exists() else []
    cand = (CASES / p)
    return [cand.resolve()] if cand.suffix.lower() == ".spell" and cand.exists() else []

def load_case_list() -> list[Path]:
    if MANIFEST.exists():
        try:
            data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] Failed to parse MANIFEST.json: {e} — falling back to discovery", file=sys.stderr)
            return sorted(CASES.rglob("*.spell"))

        entries: list = []
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            # accept multiple common keys
            for key in ("all", "cases", "positive", "negative"):
                vals = data.get(key, [])
                if isinstance(vals, list):
                    entries.extend(vals)

        if not entries:
            print("[WARN] MANIFEST.json had no usable keys (all/cases/positive/negative) — falling back to discovery",
                  file=sys.stderr)
            return sorted(CASES.rglob("*.spell"))

        resolved: list[Path] = []
        for e in entries:
            resolved.extend(_expand_entry(e))

        # De-dup, filter, ensure existence
        uniq, seen = [], set()
        for p in resolved:
            rp = p.resolve()
            if rp not in seen and rp.suffix.lower() == ".spell" and rp.exists():
                seen.add(rp)
                uniq.append(rp)

        if not uniq:
            print("[WARN] MANIFEST entries matched no files — falling back to discovery", file=sys.stderr)
            return sorted(CASES.rglob("*.spell"))

        return sorted(uniq)

    # No manifest → discover everything
    return sorted(CASES.rglob("*.spell"))


# ---------- Header rules ----------

def choose_header_rules() -> Path:
    if HDR.exists():
        return HDR
    if HDR_FALLBACK.exists():
        print(f"[INFO] Using fallback header rules: {HDR_FALLBACK.name}", file=sys.stderr)
        return HDR_FALLBACK
    print(f"[ERROR] Neither {HDR.name} nor {HDR_FALLBACK.name} found.", file=sys.stderr)
    sys.exit(2)


# ---------- JSON sanitizer ----------

def _find_json_block(s: str) -> Optional[str]:
    """
    Extract the first well-formed top-level JSON object/array from a mixed string.
    Handles debugger banners like 'Connected to pydev debugger...' preceding JSON.
    """
    def extract(start_idx: int, open_ch: str, close_ch: str) -> Optional[str]:
        depth = 0
        in_s = False
        in_d = False
        esc = False
        for i in range(start_idx, len(s)):
            ch = s[i]
            if esc:
                esc = False
                continue
            if ch == '\\':
                if in_s or in_d:
                    esc = True
                continue
            if ch == "'" and not in_d:
                in_s = not in_s
                continue
            if ch == '"' and not in_s:
                in_d = not in_d
                continue
            if in_s or in_d:
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return s[start_idx:i+1]
        return None

    # try object then array
    start = s.find("{")
    if start != -1:
        block = extract(start, "{", "}")
        if block:
            return block
    start = s.find("[")
    if start != -1:
        block = extract(start, "[", "]")
        if block:
            return block
    return None


# ---------- Runner ----------

def run_case(case_path: Path, hdr_path: Path) -> dict:
    cmd = PY + [str(AUDITOR), str(case_path), "--json", "--header-rules", str(hdr_path)]
    # Prevent debugger auto-attach inheriting into child (best effort)
    env = os.environ.copy()
    env.pop("PYDEVD_LOAD_VALUES_ASYNC", None)
    env.pop("PYCHARM_HOSTED", None)

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    out = proc.stdout

    # Fast path: direct JSON
    try:
        return json.loads(out)
    except Exception:
        pass

    # Try to extract a JSON block from noisy output
    block = _find_json_block(out)
    if block:
        try:
            data = json.loads(block)
            data["_note"] = "sanitized_output"
            return data
        except Exception:
            pass

    # Give back the raw output on failure
    return {"error": "JSON_DECODE_FAILED", "raw": out}

def main() -> None:
    if not AUDITOR.exists():
        print(f"[ERROR] Auditor not found at {AUDITOR}", file=sys.stderr)
        sys.exit(2)
    if not CASES.exists():
        print(f"[ERROR] Cases folder not found at {CASES}", file=sys.stderr)
        sys.exit(2)

    hdr_path = choose_header_rules()
    OUTDIR.mkdir(parents=True, exist_ok=True)

    cases = load_case_list()
    if not cases:
        print(f"[ERROR] No .spell files found to test under {CASES}", file=sys.stderr)
        sys.exit(3)

    print(f"[INFO] Running {len(cases)} case(s)", file=sys.stderr)

    results = {}
    for path in cases:
        rel = path.relative_to(ROOT) if ROOT in path.parents else path.name
        data = run_case(path, hdr_path)
        results[str(rel)] = data

    # Write JSON details
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Write CSV summary
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["filename", "status", "score_percent", "violations"])
        for name, r in sorted(results.items()):
            if isinstance(r, dict) and "overall_compliance" in r:
                status = r["overall_compliance"]["status"]
                score  = r["overall_compliance"]["score_percent"]
                vcount = sum(1 for x in r.get("findings", []) if x.get("status") == "VIOLATION")
            else:
                status, score, vcount = "ERROR", "", ""
            w.writerow([name, status, score, vcount])

    print(f"Wrote {OUT_JSON.relative_to(ROOT)} and {OUT_CSV.relative_to(ROOT)}")

if __name__ == "__main__":
    main()
