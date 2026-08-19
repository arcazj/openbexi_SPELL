# SPELL Compatibility and Migration

## 1. Purpose

This document defines how next-generation SPELL preserves documented language,
driver, procedure, and operator behavior while replacing unsafe or obsolete
implementation mechanisms. Compatibility is an observable contract, not a
requirement to reproduce Python 2, in-process drivers, desktop Java/Eclipse,
custom unauthenticated IPC, or unrestricted source execution.

## 2. Normative Authorities

The following supplied documents remain the authoritative definitions of the
legacy public language and driver interfaces:

| Authority | Version | SHA-256 |
| --- | --- | --- |
| `SPELL - Language Reference - 2.4.4.pdf` | 2.4.4 | `ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3` |
| `SPELL - Driver Development Manual - 2.4.4.pdf` | 2.4.4 | `057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5` |

The source bytes remain at `../../SPELL-DOCUMENTATION/` and are not copied
into this repository without distribution clearance. Hash mismatch is a
document-control failure.

Modern documents may clarify implementation, typing, security, persistence,
concurrency, and recovery. They shall not silently redefine an authority's
public name, input, result, modifier, action, service responsibility, or
observable behavior. An unavoidable change is recorded in the compatibility
ledger and approved as a deviation.

The other reviewed manuals provide workflow and architecture evidence, not a
stronger semantic authority than these two documents. Version-specific
approved traces may resolve a documented ambiguity but must identify the tested
artifact version.

## 3. Compatibility Dispositions

Every inventoried artifact receives exactly one disposition:

| Disposition | Meaning |
| --- | --- |
| Exact observable compatibility | Name, input, output, ordering, and visible behavior are preserved |
| Equivalent with safety strengthening | Observable intent is preserved with stronger authorization, typing, persistence, isolation, or recovery |
| Legacy syntax translated | Source form is accepted and deterministically lowered to the modern bounded profile |
| Optional adapter capability | Behavior exists only when an approved driver advertises the required typed capability |
| Deliberately unsupported | Unsafe or non-deterministic behavior fails with a stable diagnostic and documented replacement |
| Documentation ambiguity | Implementation is blocked pending an approved semantic decision and test oracle |

Silence is not a disposition. Partial services shall return typed
`UNSUPPORTED_CAPABILITY` or a more specific stable result; they shall not
warn and continue as if an effect succeeded.

## 4. Required Compatibility Inventory

The machine-readable ledger shall inventory:

- each language construct, operator, public function, modifier, constant,
  return type, exception, failure outcome, and action;
- every example in the Language Reference, including errata classification;
- each driver service, lifecycle callback, method, parameter, result, status,
  configuration field, and capability;
- procedure state, control action, prompt type, data scope, source/log view,
  and relevant operator workflow;
- development project, dictionary, validation, import/export, history, diff,
  and conflict workflow;
- server/context/executor identity, lifecycle, configuration, and capacity
  behavior.

Counts shall reconcile to per-document source inventories. A family-level row
is insufficient when individual names or examples can behave differently.

## 5. Bounded Python 3 Compatibility Profile

Procedure source retains a familiar Python-shaped syntax but is parsed, checked,
and lowered without executing it.

### 5.1 Permitted Foundation

The initial profile may include, only where fully specified:

- indentation-based blocks, comments, literals, lists, dictionaries, tuples,
  and declared typed values;
- bounded arithmetic, Boolean, comparison, indexing, and safe string
  expressions;
- assignment and explicit local, argument, and approved shared scopes;
- `if`/`elif`/`else`, bounded `for`, policy-bounded `while`, and
  approved local function calls;
- statically resolved steps, gotos, procedure imports, and `StartProc`;
- public SPELL functions and modifiers admitted by the selected compatibility
  profile;
- imports from immutable allowlisted procedure libraries in the same resolved
  bundle.

Limits for loop iterations, recursion/call depth, collection size, expression
cost, procedure nesting, and total runtime are explicit profile inputs.

### 5.2 Prohibited Mechanisms

The parser shall reject:

- `eval`, `exec`, dynamic compilation, arbitrary reflection, monkey
  patching, metaclasses, descriptors, and uncontrolled exception hooks;
- arbitrary Python standard-library, native-extension, package, network,
  subprocess, shell, environment, device, or filesystem access;
- runtime package installation or dependency fetch;
- direct database, worker, driver, GCS, broker, or credential access;
- dynamic imports or source paths not resolved in the immutable bundle;
- object serialization capable of code execution;
- text evaluation used as an inspection console or data conversion mechanism.

A prohibited construct yields a stable diagnostic with exact source span,
profile, reason, and supported replacement when one exists.

### 5.3 Intermediate Representation

Accepted source lowers to a versioned data-only intermediate representation
(IR) containing:

- typed operations and expressions;
- statically resolved control-flow graph and source map;
- explicit calls, effects, waits, prompts, deadlines, and failure actions;
- declared variables, scopes, schemas, and dependency identities;
- required driver capability and mutability labels;
- safe-point and checkpoint metadata;
- deterministic resource and cost bounds.

The IR is schema-validated, signed as part of the bundle, and interpreted by an
isolated worker. It cannot embed executable Python bytecode, pickle data,
native code, or unresolved imports.

## 6. Language Behavior Preservation

The compatibility program shall cover the documented families:

- common configuration, modifiers, `OnFailure`, `OnTrue`, `OnFalse`,
  `PromptFailure`, `PromptUser`, `HandleError`, and documented actions;
- time values and constants;
- `GetTM`, `Verify`, command construction and `Send`, `WaitFor`;
- limits, alarms, operator output, resources, and prompts;
- display intent, flow control, user actions, and subprocedures;
- spacecraft/global/procedure/user dictionaries and data containers;
- virtualized files and shared data;
- optional ranging, memory, lookup, and other adapter capabilities.

Defaults are pinned by language-profile version and recorded with each
execution. The implementation distinguishes valid false, operation failure,
operator override, timeout, cancellation, execution-control outcome, and
unknown external effect. Compatibility tests shall not reduce these outcomes
to generic exceptions or Boolean values.

Legacy Python 2-shaped spelling accepted by a compatibility parser is
translated to the approved Python 3 profile before semantic analysis. The
source is retained unchanged for provenance; diagnostics and source maps point
to the original source. Translation that cannot be proven semantics-preserving
is an error or approved deviation, never a best-effort rewrite.

## 7. Driver Interface Preservation

The Driver Development Manual remains authoritative for GCS-independent service
responsibilities and lifecycle intent. The modern boundary is out of process,
typed, versioned, authenticated, and capability-negotiated.

The compatibility inventory shall cover `TM`, `TC`, `EV`, `TIME`,
`RSC`, `CIF`, `MEM`, `CTX`, and `EXEC`, plus unresolved or optional
services such as task, ranging, PCS, database, and subscription behavior.
`CIF`, `CTX`, and `EXEC` responsibilities remain available through the
supervisor architecture, but a driver cannot invoke an arbitrary browser
callback or prompt.

Shared-context setup occurs before execution attachment setup. Attachment
cleanup occurs when an execution finishes, aborts, reloads, or unloads;
context cleanup follows after attachments are removed. Cleanup is best effort
but returns a typed audited outcome rather than suppressing failure.

Capability descriptors state service, method, modifiers, schemas, mutability,
stream behavior, capacity, deadlines, idempotency, and effect reconciliation.
Transport modernization does not justify changing documented values or result
meaning.

## 8. Operator and Development Compatibility

The web application shall preserve safety-relevant observable concepts:

- catalog/context selection and multiple independent procedure instances;
- current and executed source position, nested procedure navigation, scoped
  variables, timestamps, as-run and support logs;
- documented procedure states and explicit mapping to the modern state model;
- controller versus strictly read-only monitor ownership;
- durable validated prompts and documented response types;
- run, step, step-over, pause, resume, stop, skip, goto, reload, abort,
  recover, take/release control, scheduling, and user actions, each with an
  approved modern disposition;
- projects, folders, procedure/dictionary editors, outline, catalog references,
  Problems view, offline semantic checks, history, diff, conflict, import, and
  export.

Visual layout and legacy toolkit behavior are not compatibility requirements.
Arbitrary procedure-scope shells, unsafe kill, direct workstation/printer
control, direct endpoint entry, and mutable runtime files require an explicit
unsupported or safety-strengthened disposition.

## 9. Deviation Ledger

Each ledger row shall include:

- stable ledger ID and artifact kind;
- authority title, version, SHA-256, pages, and source item/example identity;
- public name, signature, modifier/default, result, exception, and state/action
  where applicable;
- legacy preconditions, ordering, side effects, persistence, and recovery;
- effect class and required driver capability;
- modern profile and behavior;
- one disposition and rationale;
- security or reliability strengthening;
- migration diagnostic and operator/developer impact;
- test IDs, trace oracle, target release, owner, reviewer, and approval record.

Changes to an approved row require versioned review. Documentation ambiguity
rows block implementation of that item. Unsupported rows block promotion of a
procedure that uses the item unless a separately approved translation removes
it.

## 10. Migration Workflow

| Stage | Required output | Exit condition |
| --- | --- | --- |
| Discover | Exact source repository, commit/archive identity, dependencies, configuration, catalogs, expected platform | Inputs are readable, hashed, and owned |
| Inventory | Parser inventory and compatibility ledger coverage report | Every construct maps to one ledger row |
| Analyze | Syntax, semantics, dependencies, data use, effects, prompts, driver capabilities, and unsafe feature report | No unclassified construct or effect |
| Translate | Deterministic source-to-source compatibility transforms where approved | Diff, source map, and diagnostics reviewed |
| Build | Immutable candidate bundle and provenance | Reproducible digest and signatures verified |
| Simulate | Deterministic normal, failure, prompt, restart, abort, timeout, and recovery scenarios | Expected traces and state invariants pass |
| Compare | Approved legacy trace versus modern trace at semantic checkpoints | Differences have approved ledger dispositions |
| Operational review | Procedure owner and controller review arguments, displays, effects, alarms, and recovery | Signed acceptance for target environment |
| Promote | Candidate promoted through [Authoring and Git](AUTHORING_AND_GIT.md) | Catalog points to approved digest |

Migration tooling shall never execute legacy source merely to discover its
structure. Dynamic legacy behavior requires controlled evidence collection in
an isolated approved legacy test environment.

## 11. Coexistence and Cutover

Legacy and modern systems may observe the same recorded or simulated inputs for
comparison. They shall not both hold command authority over the same satellite.
Live dual-write or automatic command mirroring is prohibited.

Cutover requires:

- complete compatibility coverage for every promoted procedure and required
  driver capability;
- approved data, configuration, identity, audit, recovery, and rollback plans;
- rehearsal with representative load and fault injection;
- a fresh externally anchored target generation and incarnation reserved as
  effect-disabled before final legacy fence evidence is collected;
- one unambiguous control authority and complete independent legacy fence
  evidence bound to that reserved target before replacement activation;
- explicit go/no-go, rollback trigger, and post-cutover observation window.

Rollback restores an approved prior system/bundle under the same exclusive
authority rules. It does not assume that an uncertain external effect can be
replayed.

## 12. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `COMP-013` | Authority manifests verify the exact Language Reference and Driver Manual hashes before compatibility work or release. |
| `COMP-014` | Every documented public item and example has one populated, reviewed disposition with reconciling source counts. |
| `COMP-015` | Source parsing, translation, validation, and compilation never execute procedure code or resolve uncontrolled resources. |
| `COMP-016` | Runtime loads only signed, schema-valid, data-only IR from an immutable approved bundle. |
| `COMP-017` | Unsupported and ambiguous behavior fails with stable diagnostics; partial driver support never silently succeeds. |
| `COMP-018` | Golden tests distinguish all documented results, defaults, ordering, actions, and failure/uncertainty outcomes. |
| `COMP-019` | Every promoted procedure passes deterministic simulation and approved trace comparison for all used ledger rows. |
| `COMP-020` | Legacy and modern command authority cannot be active for the same satellite during comparison or cutover. |
| `COMP-021` | Driver lifecycle ordering and advertised capability semantics pass contract and fault-injection tests. |
| `COMP-022` | Any semantic deviation identifies owner, rationale, security/reliability impact, test oracle, approval, and user-visible migration guidance. |

## 13. Known Evidence Limits

The reviewed manuals are version 2.4.4, while other recovered product artifacts
have later version labels. The manuals therefore define the requested
authority baseline but do not prove every later binary behavior. Missing
proprietary drivers, ambiguous manual statements, and unobserved failure paths
remain explicit evidence gaps until an approved source or trace resolves them.
