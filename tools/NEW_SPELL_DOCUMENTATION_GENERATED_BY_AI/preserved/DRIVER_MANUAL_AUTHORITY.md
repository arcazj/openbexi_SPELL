# Driver Development Manual Authority Record

## Immutable Authority

| Field | Value |
| --- | --- |
| Title | SPELL - Driver Development Manual - Version 2.4.4 |
| Local evidence | [SPELL - Driver Development Manual - 2.4.4.pdf](../../SPELL-DOCUMENTATION/SPELL%20-%20Driver%20Development%20Manual%20-%202.4.4.pdf) |
| Pages reviewed | 45 of 45 |
| SHA-256 | `057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5` |
| Authority domain | GCS-independent services, lifecycle intent, configuration, telemetry, telecommand, events, resources, time, and related interface vocabulary |
| Editorial state | Unchanged external evidence |
| Redistribution | Not decided by this repository |

This PDF remains the authoritative functional driver reference. The generated
documentation preserves its service intent while modernizing typing, process
isolation, transport security, authorization, concurrency, failure reporting,
recovery, and capability negotiation.

## Preserved Concepts

- Driver abstraction isolates procedures from a specific GCS.
- Host, context, execution attachment, operation, configuration, and cleanup are
  distinct lifecycle concerns.
- Telemetry, telecommand, event, time, resource, configuration, memory, context,
  and executor services retain their public intent.
- Optional or incomplete services are explicit capabilities, never silent no-op
  methods.

## Replaced Mechanisms

Legacy in-process Python inheritance, Python 2 assumptions, weakly typed generic
payloads, browser callbacks, direct secret distribution, ambiguous capacity, and
insecure channels are not target constraints. The target uses versioned schemas,
out-of-process hosts, mutually authenticated transport, supervisor-owned prompts,
stable operation identities, typed outcomes, bounded deadlines, backpressure,
and explicit effect certainty.

Each method and modifier shall eventually reconcile to a row in
[`../requirements/COMPATIBILITY_LEDGER.md`](../requirements/COMPATIBILITY_LEDGER.md)
and a driver conformance vector before an adapter is promoted.

## Change Protection

- The referenced bytes shall not be modified or re-saved.
- A replacement source version requires a new authority record and full review.
- Interface ambiguity shall be decided in an ADR or compatibility row rather
  than inferred in driver code.
- No real GCS capability is authorized by this record; each adapter and effect
  class requires separate integration and operational acceptance.
