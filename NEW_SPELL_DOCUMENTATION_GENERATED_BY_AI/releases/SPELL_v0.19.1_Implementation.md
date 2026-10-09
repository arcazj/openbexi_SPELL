# SPELL v0.19.1 Implementation

This candidate packages the inherited v0.19 local DSS product with the isolated
Python runtime and source-line debugger. The annotated tag and its independently
validated committed qualification, manifest and reproducibility records under
`artifacts/v0.19.1/` govern acceptance. A mutable worktree or this document alone
does not establish a passing release.

## Python Runtime And Controls

The explicit `python-stdlib/3.13` profile runs captured source in a networkless
service. The trusted launcher drops the child to an unprivileged identity inside
a private chroot containing only CPython, its standard library and required
shared libraries. The child receives no service credentials. Source digests,
output and exit status are bound to the request, generation and execution.

Console jobs load paused before their first executable line. Permanent
breakpoints stop before execution and repeat on later loop visits. Step enters
functions; Step Over stops in the caller unless an inner breakpoint is reached.
Run to Line uses a temporary target. Traced pauses stop all descendants. Signal
Pause can interrupt a C call and clears the unavailable exact source highlight.
Abort/Stop fence cleanup of the entire process family. Paused source position
and complete bounded output survive refresh and reopening.

Line debugging covers the captured script's main thread, including its functions
and async work on that thread. Imported modules, other filenames, threads and
subprocesses are outside line tracing. Evaluation, object editing, SKIP/GOTO,
background execution and replay are unavailable. Source metadata is bounded and
compiled only for static executable-line discovery; it is never executed by the
control plane. Existing closed SPELL profiles retain their validators.

Completion stores summary variables only after every output event is durable
and the actual process exits successfully. Python objects are not recovery
checkpoints. Interrupted source must be explicitly admitted as a new execution.
All pauses count toward the job lifetime. Setup and exact bounds are documented
in the [procedure guide](../../procedures/README.md#python-feature-reference).

## Qualification Contract

The [entry record](SPELL_v0.19.1_Pre-Implementation.md) requires source, isolation,
debugger, durability, procedure, DSS, browser and release proofs. The collected
test identities are frozen in `contracts/v19.1/release_policy.json` before
candidate and final qualification. PostgreSQL/Compose runs must resolve every
environment-selected SQLite skip. The actual runner participates in both
database suites and the candidate suite.

The automatic DSS inventory includes all 12 procedure files and every inherited
language case, adaptation, variant and menu selection: 956 identities and
32 declared scenarios. Native Test Python must finish all 261 checks over
39 topics without optional skips; Test Python Core must finish all six checks.
Native Python scenarios also prove no spacecraft command dispatch. The inherited
DSS scenarios retain actual correlated binary CCSDS TC and decoded Kafka TM,
fault outcomes and a final paused, fault-free state.

Seven distinct image identities require inspected runtime boundaries, CycloneDX
SBOMs and vulnerability disposition: backend, driver, DSS, Kafka, frontend build,
proxy and Python runner. Release publication requires all canonical gates,
four identical packages across two independent source exports, and validation
of the clean annotated tag. Earlier accepted evidence remains immutable.

This is a local simulator. Full SPELL 2.4.4 language conformance, real legacy
system qualification and operational authority are not claimed.
