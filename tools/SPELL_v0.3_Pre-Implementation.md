# SPELL v0.3 Pre-Implementation Gate

## Release Objective

SPELL v0.3 is the simulator hardening and restricted-language foundation
release. It closes the known v0.2 engineering exceptions that are prerequisites
for later driver work, expands the procedure language without executing Python
source, and adds a transient validation workflow to the web console.

The release remains local and simulator-only. It provides no GCS, spacecraft,
telecommand, proprietary driver, operational deployment, or operational
authorization.

## Approved Scope

1. Replace runtime `create_all` initialization with versioned database
   migrations that support fresh and existing SQLite and PostgreSQL stores.
2. Add signed JWT authentication with issuer, audience, expiry, subject, and
   server-enforced role claims. A clearly gated loopback development issuer may
   support the local console.
3. Put the backend and PostgreSQL on an internal Docker network and expose the
   API through a constrained loopback reverse proxy so the backend has no
   general outbound route.
4. Produce hash-locked Python dependencies, reproducible backend/frontend
   packages, updated CycloneDX inventories, and a policy with zero unreviewed
   dependency advisories.
5. Formally eliminate exposure to the accepted v0.2 Starlette advisories or
   upgrade them when a compatible upstream release exists.
6. Expand the non-executing restricted AST/IR with typed variables, safe
   expressions, conditions, bounded loops, and reusable procedure calls.
7. Persist interpreter variables at atomic checkpoints so worker recovery does
   not lose or duplicate language effects.
8. Add a validation-only REST resource and console workflow that returns typed
   diagnostics, normalized IR, subset version, and content hash without saving
   or executing submitted source.
9. Add concurrent command/prompt, worker, database, restart, migration,
   isolation, replay, accessibility, performance, and soak verification.

## Architecture Decisions

- Procedure text is parsed but never imported, evaluated, compiled, or passed
  to the worker. The worker receives normalized data-only IR.
- Expressions use an explicit allowlist and a data interpreter. Attribute
  access, imports, comprehensions, asynchronous syntax, exceptions, filesystem,
  network, database, subprocess, reflection, and arbitrary calls remain
  forbidden.
- Structured control flow compiles to checkpointable flat IR. Reusable local
  procedure calls are expanded with bounded depth during validation.
- One process remains authoritative for an execution in v0.3. The database is
  authoritative for commands, events, prompts, variables, checkpoints, and
  audit evidence.
- Development identity issuance is a separately enabled local facility, not a
  production identity provider.
- Driver-host and GCS contracts remain v0.4 work and cannot be introduced by a
  v0.3 configuration option.

## Release Constraints

- Apache License 2.0 applies to the new implementation through `LICENSE` and
  `NOTICE`; legacy archive licensing remains separate.
- The legacy ZIP files remain read-only, ignored, and excluded from source and
  binary packages.
- No performance result is an operational SLO.
- Any unresolved Critical or High safety, durability, identity, isolation, or
  migration defect blocks v0.3.
- The exact executed evidence and exceptions must be recorded in
  `Test_and_Integration.md` and `SPELL_v0.3_Release.md` before tagging v0.3.0.

## Deferred Scope

- Full legacy SPELL or Python 2 compatibility.
- Arbitrary Python execution or third-party procedure imports.
- Persistent procedure authoring or a complete development environment.
- Live, legacy, or non-operational GCS integration.
- Spacecraft connections and externally effective commands.
- Driver hosts, gRPC driver services, high availability, Kubernetes, and
  operational identity-provider deployment.
