# @procedure tutorial_core_v18
# @description Typed scalars, bounded range, branches, integer operators and Display
# @language-profile spell-lrm244-conformance/0.17
"""Finish with total=12, power=32, mask=3 and label=core checks passed."""

total: int = 0
label: str = "core checks pending"
for item in range(2, 8, 2):
    total += item
power = 2 ** 5
mask = 7 & 3
if total == 12 and power == 32 and mask == 3:
    label = "core checks passed"
Display(label)
Display("")
Display("Whitespace is preserved:  ", Severity=INFORMATION)
