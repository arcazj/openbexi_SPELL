# SPELL Procedure Compliance Auditor

A static analyzer for SPELL procedures that checks compliance with the SPELL Language Manual (v2.0.1).
It Validates the syntax of commented headers, telecommand sending (e.g., Send, BuildTC), and telemetry functions (e.g., Verify, WaitFor, GetTM) according the SPELL Language Manual.

SPELL is a free, open-source suite for developing and executing automated satellite procedures.
It can run procedures across different Ground Control Systems and for any spacecraft.

Learn more about SPELL: https://sourceforge.net/p/spell-sat/wiki/Home/

---

## Features

- **Commented header policy** (`header_rules.json`)
    - Required commented fields: `# NAME`, `# DESCRIPTION`, `# FILE`, `# SPACECRAFT`
    - `# FILE` must equal the actual filename (`.spell` / `.py`)
    - `# SPACECRAFT` supports a single value or CSV list of IDs/names
- **Strict body checks**
    - **Send**: keywords only; validates `command/sequence/group`; `Time` / `ReleaseTime` (`NOW±N*UNIT`, `+HH:MM:SS`, `YYYY/MM/DD HH:MM:SS`, `YYYY-MM-DD HH:MM:SS`); `LoadOnly`, etc.
    - **BuildTC**: positional `'CMD'` **or** `command='CMD'`
    - **Verify**: list form (single & multi); ops `{eq,ge,gt,lt,le,neq,bw,nbw}`; tolerances; `ValueFormat`; delays; `OnFalse`/`OnTrue`
    - **WaitFor**: `Interval` (time-like or list of time-likes) and `Message` (string)
    - **GetTM**: `Extended` must be **bool**; `Timeout` meaningful only with `Wait=True`
    - **PrintDisplay**: exactly **1** positional (display name) and required `Printer='…'`
    - **Event**: only these forms are valid:
        - `Event('Message')`
        - `Event('Message', WARNING)`
        - `Event('Message', Severity=ERROR)`
    - **SetLimits**: classic `(param, def)`, **list-of-lists** form, and **URI** `'limits://…'`
    - **SetResource** / **SetGroundParameter**: string/number/ident and index expressions like `GDB['DECODER']`

---

## Repository layout

```
.
├─ cases/                      # test procedures (.spell / .py)
├─ json/                       # test artifacts (results JSON/CSV)
├─ header_rules.json           # active header policy (used by the auditor)
├─ header_rules_default.json   # template/fallback for CI or local
├─ MANIFEST.json               # optional: explicit case list for the runner
├─ run_tests.py                # runs the auditor across cases -> json/
├─ spell_auditor.py            # auditor CLI
├─ LICENSE
└─ README.md
```

> The runner writes `json/results_details.json` and `json/results_summary.csv`.

---

## Requirements

- Python **3.9+** recommended

---

## Quick start

Audit a single procedure:

```bash
python3 spell_auditor.py cases/proc_test_all_functions.spell --json --header-rules header_rules.json
python3 spell_auditor.py cases/proc_test_all_bad_functions.spell --json --header-rules header_rules.json
```

PowerShell:

```powershell
python .\spell_auditor.py .\cases\proc_test_all_functions.spell --json --header-rules .\header_rules.json
```

Output modes:
- `--json` → machine-readable JSON (full schema below)
- *(default)* → human-friendly text report

---

## Run all regression tests

```bash
python3 run_tests.py
```

This:
- loads cases from **`MANIFEST.json`** (if present) or discovers `cases/**/*.spell`
- runs the auditor with `--header-rules header_rules.json` (falls back to `header_rules_default.json` if missing)
- writes:
    - `json/results_details.json` (all raw auditor outputs by file)
    - `json/results_summary.csv` (filename, status, score, violation count)

### `MANIFEST.json` shapes supported by `run_tests.py`


> Paths may include or omit the `cases/` prefix. Only files ending with `.spell` are considered.

### PyCharm debugger note
If your IDE injects a banner like “Connected to pydev debugger…”, the runner extracts the first valid JSON block from the mixed output and marks the object with `"_note": "sanitized_output"`.

---

## Header policy (enforced)

Example of a **valid commented header**:

```
################################################################################
#
# NAME        : proc_ok
# DESCRIPTION : This task covers operations related to performing something.
#
# FILE        : proc_ok.spell
# SPACECRAFT  : SAT_A, 1111
#
# DEVELOPED   : Converted using XML to SPELL Converter Tool on June 23, 2025
# VALIDATED   :
#
# REVISION HISTORY :
# DATE          REV   AUTHOR      DESCRIPTION
# ===========   ===   =========   ==============================================
# 18 May 2025   I11   AXIOM       Release for Rev A Delivery
#
################################################################################

```

## JSON output schema (abridged)

```json
{
  "manual_version": "2.0.1",
  "overall_compliance": { "status": "PASS|FAIL", "score_percent": 0.0 },
  "summary": "1-2 sentence overview",
  "findings": [
    {
      "rule_id": "A.Send.KWTYPE",
      "category": "HEADER|COMMAND|TELEMETRY",
      "severity": "CRITICAL|MAJOR|MINOR",
      "location": { "line_start": 12, "line_end": 12 },
      "evidence": "Minimal snippet",
      "explanation": "Why it violates/satisfies the rule",
      "manual_quote": "Relevant excerpt",
      "status": "VIOLATION|OK|NOT_APPLICABLE",
      "suggested_fix": "Concrete SPELL correction"
    }
  ]
}
```

**Scoring & PASS**
- `score = (# satisfied MUST rules / # applicable MUST rules) * 100`
- `PASS` if `score ≥ 95` **and** no `CRITICAL` violations

---

## License

MIT — see `LICENSE`.

```
Copyright (c) 2025 Jean-Christophe Arcaz
```
