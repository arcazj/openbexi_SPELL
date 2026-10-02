# @procedure prompt_workflow_v17
# @display-name Prompt Workflow V17
# @description Local Prompt reset, warning, default, typed returns and cancellation
# @language-profile spell-lrm244-conformance/0.17
"""Local simulator demonstration of the bounded SPELL 2.4.4 Prompt profile."""

route = Prompt("Choose a route", ["A:Primary", "B:Backup"], Type=LIST, Timeout=1*SECOND)
Display(route)
rate = Prompt("Default numeric rate", NUM, Default=2.5, Timeout=1*SECOND)
Display("Numeric default committed")
note = Prompt("Record a note", ALPHA)
Display(note)
answer = Prompt("Finish walkthrough", OK_CANCEL)
Display(answer)
