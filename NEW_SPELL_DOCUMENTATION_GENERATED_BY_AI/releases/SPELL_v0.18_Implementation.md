# SPELL v0.18 Native Telecommand Workflows

Implementation and qualification are in progress under the
[entry gate](SPELL_v0.18_Pre-Implementation.md). v0.17.0 remains the accepted
predecessor until the new source, evidence, package and annotated tag validate.

## Scope

- Native Prompt results and bounded expressions select branches containing
  existing simulator BuildTC/Send calls, followed by Display.
- Durable prompt answers, command confirmation, command intent and recovery
  retain their distinct authority and outcomes.
- The reference runner retains all earlier cases and adaptations and adds
  direct source checks for supported command behavior and native integration.
- Four additional [testing procedures](../../procedures/README.md) provide
  branch, default, command-mode and core-language walkthroughs.

IR 0.18 permits literal catalog command names or immutable BuildTC items;
arguments stay literal and modifiers retain closed constant/temporal forms.
Older IR 0.11 string-variable selectors remain unchanged in their earlier
profile. Native Prompt does not
replace required command confirmation. Abort cannot produce a later Send;
possible or unknown command effects cannot trigger automatic resend.
Earlier IR contracts remain unchanged. IR 0.18 does not add the v0.8 data,
argument, file or environment profiles or direct observation instructions to
native telecommand procedures. Collections, general function arguments/returns,
live connections and operational authorization remain outside scope.

The compact manual workspace and automatic local connection remain in place.
Full SPELL 2.4.4 compatibility is not claimed. Adapted examples, correct
rejections and bounded source tests remain distinct forms of evidence.

## Verification

Gate 0A passed for seven requirements and eight pinned source inputs before
product edits. Candidate and final results will be recorded after execution.
Qualification includes actual worker/supervisor/API command paths, authority
and crash-recovery checks, every new procedure, both browser viewports and all
inherited release gates. No planned check is recorded as a passed result.
