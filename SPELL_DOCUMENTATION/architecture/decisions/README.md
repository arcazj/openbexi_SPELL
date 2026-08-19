# Architecture Decisions

Architecture Decision Records (ADRs) capture choices that affect more than one
component or create a long-lived constraint. An ADR is not a substitute for a
normative requirement.

## States

- `Proposed`: analysis is ready for review but not binding.
- `Accepted`: required approvers accepted the decision for the identified
  specification baseline.
- `Superseded`: a later ADR replaces it and links both directions.
- `Rejected`: considered but not selected; rationale is retained.

Every ADR shall identify context, decision, alternatives, consequences, risks,
verification, migration/rollback, affected requirements, and approvers. Draft
repository ADRs may describe the recommended target, but none is operationally
authorized until the repository baseline is approved.

## Index

- [ADR-001: PostgreSQL as system of record](ADR-001-postgresql-as-system-of-record.md)
- [ADR-002: One-satellite control domain](ADR-002-one-satellite-control-domain.md)
- [ADR-003: Single-writer HA and fencing](ADR-003-single-writer-ha-and-fencing.md)
- [ADR-004: REST, WebSocket, and gRPC](ADR-004-rest-websocket-grpc.md)
- [ADR-005: Git promotion and immutable bundles](ADR-005-git-promotion-and-immutable-bundles.md)
