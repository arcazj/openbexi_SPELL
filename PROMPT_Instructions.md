# General Execution Prompt

This file defines the durable project context and execution rules for
`openbexi_spell`. It applies to all future analysis, documentation, development,
testing, integration, and release work unless a more specific approved project
document overrides it.

Keep this file focused on stable project rules. Record release-specific requests,
versions, dates, and verification results in dedicated history or release
documents after those documents have been introduced. Do not invent supporting
files, commands, or workflows that are not present in the repository.

## Project Mission

SPELL is the Satellite Procedure Execution Language and Library. It is an open
framework for developing and executing automated satellite procedures through
different Ground Control Systems and for different spacecraft platforms.

The goals of `openbexi_spell` are to support the evolution, integration, and use
of SPELL while preserving these principles:

- Provide a powerful and readable satellite-operations language.
- Make procedures shareable across satellite operators and manufacturers.
- Reduce operational risk, human error, and procedure maintenance cost.
- Execute procedures in a repeatable, reliable, observable, and auditable way.
- Keep shared automation independent of a particular spacecraft or Ground
  Control System.
- Preserve well-defined integration boundaries so deployments can be adapted
  without changing common procedure behavior.

This is operational software. Reliability, traceability, compatibility, and
explicit failure handling take priority over convenience or cosmetic refactoring.

## Current Project Baseline

The repository begins with three upstream distribution archives and this project
guidance. Treat the archives as inputs and reference material until an approved
task establishes the working source layout:

- `SPELL2.6.10-src.zip` contains the SPELL 2.6.10 core source baseline. The
  verified source uses C++, Python, Unix shell tooling, GNU Autotools, XML
  configuration, and protobuf/gRPC interfaces.
- `SPELL-COTS-2.6.10.zip` is a third-party dependency bundle. It is vendored
  material, not ordinary application source.
- `SPELL_GUI_4.0.12-win32.win32.x86.zip` is a prebuilt 32-bit Windows Eclipse
  RCP/SWT GUI distribution. It is not GUI source code.

Core SPELL and SPELL GUI have separate version series. Do not force them to use
one version number or assume that similarly named packages have identical
release procedures.

Before changing any artifact, classify it as first-party source, generated code,
configuration, procedure content, optional integration code, vendored dependency,
or binary distribution. Preserve that ownership boundary throughout the change.

## SPELL Architecture

The upstream SPELL suite identifies five application families. Their exact
availability and version in `openbexi_spell` must be confirmed from the local
source and documentation before work begins:

- **SPELL Server** provides the real-time procedure execution environment and
  integration with Ground Control Systems.
- **SPELL Library** extends Python with language elements and runtime services
  for satellite operations.
- **SPELL Shell** provides a command-line interface to SPELL capabilities.
- **SPELL GUI** is the Eclipse RCP/SWT operator application used to connect to
  an execution environment and control procedures.
- **SPELL Development Environment** is the Eclipse-based environment used to
  develop, check, version, and maintain procedures.

The core source baseline also contains contexts, executors, services, listeners,
configuration services, procedure support, spacecraft database access, IPC, and
driver interfaces. Ground Control System behavior belongs behind the driver and
service abstractions. Do not assume that optional or proprietary driver
implementations referenced by build files are included in the repository.

Configuration and interface contracts include XML files, protobuf/gRPC schemas,
socket or IPC protocols, Python procedure APIs, and driver interfaces. These are
cross-component contracts and must be treated as compatibility-sensitive.

Deployment material in the source archive includes container, Kubernetes,
Kustomize, Helm, and CI definitions. Their presence does not prove that every
deployment target is currently supported or reproducible in this repository.

## Operational Safety Rules

- Never connect tests or exploratory changes to a live Ground Control System or
  spacecraft unless the task explicitly authorizes it and provides an approved
  environment and procedure.
- Default to isolated, simulated, recorded, stubbed, or otherwise non-operational
  data sources for development and verification.
- Keep mission-specific and Ground Control System-specific behavior out of shared
  execution, language, and procedure components. Implement such behavior through
  documented configuration, databases, adapters, or drivers.
- Make command submission, acknowledgement, timeout, cancellation, retry, abort,
  and recovery behavior explicit. Never add an automatic telecommand retry
  without proving that the operation is safe and approved for repetition.
- Preserve operator prompts, holds, confirmations, overrides, and abort paths.
  Do not silently weaken an existing safety barrier.
- Validate telemetry identity, units, timestamps, freshness, validity, limits,
  and quality before using it to make an operational decision.
- Preserve chronological logs, procedure status, command and telemetry evidence,
  user actions, and as-run records needed to reconstruct an execution.
- Treat disconnection, partial responses, stale data, restart, warm-start, and
  interrupted execution as normal failure cases that require defined behavior.
- Fail clearly when a required driver, service, schema, database, procedure,
  dependency, or configuration is missing or incompatible.

## Compatibility Rules

- Preserve Ground Control System and spacecraft-platform independence in common
  code and procedure APIs.
- Maintain existing public APIs, procedure semantics, configuration structure,
  message fields, and persisted data unless the task explicitly approves a
  breaking change and its migration plan.
- The core baseline supports both Python 2 and Python 3 build paths. Do not remove
  either path, modernize syntax globally, or replace runtime assumptions until
  the supported compatibility matrix has been explicitly changed.
- Regenerate all affected bindings after an approved protobuf or other generated
  interface change. Never edit generated bindings as the source of truth.
- Keep schema evolution backward-compatible where feasible. Document field,
  default, enum, unit, timing, and error-semantics changes.
- Preserve XML element names, attributes, identifiers, encodings, and lookup
  behavior unless migration and compatibility are part of the task.
- Treat optional drivers and deployment integrations as optional. A missing
  proprietary implementation must not be replaced with invented behavior.
- Verify platform claims independently. The current core build instructions are
  POSIX-oriented, while the supplied GUI is a Windows x86 binary distribution.

## Repository and Dependency Rules

- Do not modify or replace the original ZIP archives unless the user explicitly
  requests an archive-management task.
- Do not edit vendored COTS source to implement application behavior. Prefer an
  upstream fix, a documented patch, or an application-side integration change.
- Do not commit build outputs, extracted binary distributions, caches, local IDE
  state, credentials, private certificates, tokens, or machine-specific paths.
- Some archived deployment files may reference private registries, proxies, or
  internal infrastructure. Treat those values as sensitive and never reproduce
  them in new public documentation or configuration.
- Verify the license of each component before copying, redistributing, linking,
  or changing it. The core source is GPL-licensed, while upstream SPELL
  components and Eclipse-based components may use different compatible licenses.
- Keep changes narrowly scoped. Do not combine dependency upgrades, formatting,
  generated-file churn, protocol changes, and functional work without a concrete
  need.
- Preserve unrelated user changes and untracked files. Never discard or rewrite
  them to obtain a clean working tree.

## Before Starting a Task

1. Read this file and all existing repository documentation relevant to the task.
2. Inspect the current repository state and determine whether the required source
   has been extracted, generated, or added since this baseline was written.
3. Read the component's local `README`, `INSTALL`, `LICENSE`, release notes,
   configuration examples, build definitions, and tests before proposing changes.
4. Identify affected execution paths, procedure APIs, drivers, schemas,
   configurations, deployment targets, and operator workflows.
5. State any safety, compatibility, licensing, dependency, or platform risk that
   materially affects the work.
6. Establish the best available build and test baseline. If the environment lacks
   required dependencies, record that limitation instead of inventing a result.
7. Define acceptance criteria that cover expected behavior and relevant failure
   and recovery cases.

Do not assume that instructions from another OpenBEXI project apply here. In
particular, browser-only, Three.js, satellite.js, npm, and Earth-visualization
rules are not part of `openbexi_spell` unless this repository later introduces
and documents such a component.

## Making Changes

- Follow the structure, naming, ownership boundaries, error conventions, and
  build patterns already used by the affected SPELL component.
- Prefer small, reviewable changes with clear behavior over broad rewrites of the
  imported baseline.
- Keep common language and execution behavior separate from mission databases,
  environment configuration, and driver implementations.
- Use structured parsers and generators for XML, protobuf, and other structured
  formats. Do not manipulate them with fragile text replacement.
- Preserve procedure readability. Operational intent, conditions, timeouts,
  expected responses, and recovery behavior must remain apparent to reviewers
  and operators.
- Add concise comments only where safety intent, protocol behavior, or a
  non-obvious compatibility constraint would otherwise be unclear.
- Update documentation and examples when setup, configuration, procedure syntax,
  interfaces, supported environments, or operator behavior changes.
- Do not claim support for a platform, Ground Control System, spacecraft, driver,
  or deployment until it has been verified at the appropriate level.

## Build and Verification

Use the build instructions shipped with the actual source being changed. For the
initial core 2.6.10 baseline, the verified build system is GNU Autotools with an
out-of-tree configure and make workflow. Dependency locations may be supplied
through `SPELL_COTS`, compiler and linker flags, `PATH`, and
`LD_LIBRARY_PATH`. Do not hard-code local dependency paths into tracked files.

Verification must scale with the affected surface and should include the
applicable items below:

- Configure and build the affected native components with the supported toolchain.
- Run available native unit tests when the CppUnit test option and dependencies
  are available.
- Validate affected Python modules and procedures under every supported Python
  runtime that the change touches.
- Parse and validate changed XML configuration and exercise invalid-input cases.
- Regenerate and validate protobuf/gRPC artifacts when schemas change, including
  compatibility with existing peers where possible.
- Test Ground Control System drivers against approved stubs, simulators, recorded
  data, or non-operational integration environments.
- Exercise success, timeout, cancellation, disconnect, restart, recovery, and
  partial-failure behavior when those paths are affected.
- Validate container and deployment definitions with their native tools when they
  change, without publishing images or applying to a cluster unless authorized.
- Treat the supplied GUI binary as a reference and smoke-test target only. GUI
  source changes require an actual GUI source baseline and its documented build
  environment.
- Check that logs and as-run evidence remain complete and do not expose secrets.

Report exactly what was run, what passed, what failed, and what could not be run.
Do not describe an unexecuted test, unavailable driver, or missing platform as
verified.

## Release and Documentation Rules

- Keep this file limited to stable project-wide guidance. Do not accumulate
  release logs or one-time implementation requests here.
- Use the component's real version sources and release documentation. Discover
  all version surfaces from the extracted repository before changing any of them.
- Keep independent component versions independent unless the project adopts and
  documents a unified release scheme.
- Update existing setup, architecture, integration, testing, API, procedure, and
  operator documentation whenever the corresponding behavior changes.
- When new project documents are introduced, define their ownership clearly and
  link them from the appropriate index rather than duplicating conflicting rules.
- Do not add agent-specific commit attribution. Create commits, tags, releases,
  or published artifacts only when the user explicitly requests them.

## Authoritative References

Use local source, build, license, and release files as the authority for the
specific version being changed. Use the upstream SPELL material for historical
and architectural context:

- SPELL Wiki: `https://sourceforge.net/p/spell-sat/wiki/Home/`
- SPELL project summary: `https://sourceforge.net/projects/spell-sat/`
- SPELL getting started: `https://sourceforge.net/p/spell-sat/wiki/Start%20using%20SPELL/`
- SPELL licensing overview: `https://sourceforge.net/p/spell-sat/wiki/Licensing/`

If local artifacts and website documentation disagree, document the discrepancy
and follow the local version-specific material unless the task explicitly adopts
a newer upstream baseline.
