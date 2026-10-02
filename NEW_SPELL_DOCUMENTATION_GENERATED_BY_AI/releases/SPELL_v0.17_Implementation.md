# SPELL v0.17 Direct Language Conformance

Implementation and qualification are in progress under the
[approved entry gate](SPELL_v0.17_Pre-Implementation.md). v0.16.0 remains the
accepted predecessor. This record does not claim release acceptance before
the frozen source, evidence, reproducible package and annotated tag validate.

## Scope

- Direct scalar, operator, conditional and range evidence, including empty
  ranges and bounded integer power/bitwise operations.
- Native Display and Prompt syntax, typed answers and explicit default,
  timeout, cancellation and recovery behavior.
- Complete source inventory with separate missing-implementation,
  missing-proof and manual-conflict reasons.
- Expanded 292-choice reference runner: 195 adaptations, 96 direct/rejection
  cases and an all-suite choice. All 257 adapted variants and earlier direct-case
  identities are retained.
- Concise user documentation and complete source-bound qualification.

The local profile retains fixed types, finite numeric values, resource bounds,
controller permissions and source non-execution. Collections, general function
arguments/returns, exceptions, real legacy connectivity and operational
authorization remain outside this release. Passing bounded cases does not
establish full SPELL 2.4.4 compatibility.

## Compatibility Decisions

The dedicated Prompt section (Language Reference 2.4.4 page 72) governs the
conflicting page-112 timeout summary: a positive timeout without Default warns
once and remains open. Timeout zero waits indefinitely. Default automatically
settles only with a positive timeout. Native Cancel answers remain answers;
local Abort ends execution without fabricating a result. Earlier stored IR and
explicit lowercase prompt forms retain their contracts.

New bare Prompt calls use the documented default OK type. Native string/date
answers, finite numeric answers and list key/index/value results use the typed,
bounded profile recorded by the implementation; legacy date-object equivalence
is not claimed. Dynamic Display values accept bounded empty strings in IR 0.17.

New native features cannot be mixed with the earlier data/argument, file,
environment or telecommand service profiles. Those profiles retain their
existing nonempty Display/log behavior and authoritative runtime paths.
Unsupported combinations are rejected explicitly; their support remains a gap.

Native assignments require the exact Prompt result type. LIST is limited to
1-1000 choices; literal ranges to 1000 iterations. Numeric answers must be finite
and fit the 128-character decimal representation used by the worker. Timeout
is limited to seven days.

## Verification

Gate 0A passed for seven requirements and eight pinned source inputs before
product changes. Focused tests, the frozen catalog and final gate results will
be recorded after execution. No planned or adapted check is counted as complete
language support. Earlier release artifacts remain immutable.
