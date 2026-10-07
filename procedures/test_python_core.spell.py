# @procedure test_python_core
# @description Python core checks supported by the local SPELL executor
# @language-profile spell-lrm244-conformance/0.17
"""Check supported Python core features; the full reference is test_Python.py."""

checks_passed: int = 0
integer: int = 7
floating: float = 2.5
enabled: bool = True
text: str = "Python"
types_ok: bool = False
arithmetic_ok: bool = False
integer_operators_ok: bool = False
logic_ok: bool = False
total: int = 0
loop_ok: bool = False
function_calls: int = 0
function_ok: bool = False
all_checks_passed: bool = False

Display("Test Python: checks for the current SPELL executor")
types_ok = integer == 7 and floating == 2.5 and enabled and text == "Python"
if types_ok:
    checks_passed += 1
    Display("PASS: typed int, float, bool and string values")
else:
    Display("FAIL: typed values", Severity=ERROR)

arithmetic_ok = (7 + 2 == 9 and 7 - 2 == 5 and 7 * 2 == 14
                       and 7 / 2 == 3.5 and 7 // 2 == 3 and 7 % 2 == 1)
if arithmetic_ok:
    checks_passed += 1
    Display("PASS: arithmetic + - * / // %")
else:
    Display("FAIL: arithmetic", Severity=ERROR)

integer_operators_ok = 7 ** 2 == 49 and (6 & 3) == 2 and (6 | 3) == 7
if integer_operators_ok:
    checks_passed += 1
    Display("PASS: integer power and bitwise AND/OR")
else:
    Display("FAIL: integer operators", Severity=ERROR)

logic_ok = 1 < integer <= 10 and not False and (False or enabled)
if logic_ok:
    checks_passed += 1
    Display("PASS: chained comparisons and boolean operators")
else:
    Display("FAIL: comparisons and boolean operators", Severity=ERROR)

for number in range(1, 5):
    total += number
loop_ok = total == 10
if loop_ok:
    checks_passed += 1
    Display("PASS: bounded range loop and augmented assignment")
else:
    Display("FAIL: bounded loop", Severity=ERROR)

def local_example():
    function_calls += 1

Call(local_example)
function_ok = function_calls == 1
if function_ok:
    checks_passed += 1
    Display("PASS: zero-argument local function through Call")
else:
    Display("FAIL: local function", Severity=ERROR)

all_checks_passed = checks_passed == 6
if all_checks_passed:
    Display("All 6 supported Python core checks passed")
else:
    Display("Python core checks failed; inspect the result variables", Severity=ERROR)

Display("Full collections, imports, classes, async and thread examples run in test_Python.py with Python")
