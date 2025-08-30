# SPELL Procedure Compliance Auditor

A strict compliance auditor for **ESA SPELL (Satellite Procedure Execution Language and Library)** procedures.  
This tool evaluates whether a given SPELL procedure complies with the **SPELL Language Manual — Software version 2.0.1**, focusing on:

1. **Header requirements**
    - Mandatory header fields (e.g., PROC name, version, author, purpose, date).
    - Correct formatting and syntax.
    - No missing or malformed fields.

2. **Command sending**
    - Proper use of `Send` or `BuildTC` constructs for telecommands.
    - Syntax correctness (`command=` keyword, time arguments must be absolute).
    - Deprecated/forbidden forms flagged.

3. **Telemetry verification**
    - Correct use of `Verify`, `WaitFor`, and `GetTM`.
    - Valid operators, tolerances, value formats.
    - Each telecommand followed by a corresponding telemetry check.

---

## Features

- Regex-based header validation (heuristic by default, can be replaced with strict rules).
- Verifies telecommand syntax (`Send(command=...)`).
- Enforces telemetry verification with valid operators (`eq, gt, le, bw, …`).
- Produces structured **JSON-only** output compliant with the schema.
- Computes a compliance score and PASS/FAIL status.

---

## Installation

Clone the repo and ensure you have Python 3.8+:

```bash
git clone https://github.com/your-org/spell-auditor.git
cd spell-auditor

