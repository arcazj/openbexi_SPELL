# GENERIC DSS contract

DSS is the shared local satellite simulator for SPELL CMD and TLM. Start it with
`docker compose up --build -d --wait`; open `http://127.0.0.1:8080/dss/`.
Pause before reviewing a command or stepping the dynamics. The command page uses
the same binary TCP ingress as SPELL and requires a separate confirmation.

The proxy refreshes backend and DSS service addresses through Docker DNS with a
one-second cache so container replacement does not retain the previous address.

`satellite_database.json` binds commands, arguments, telemetry and the fixed
100 ms bus/payload dynamics. Its exact file SHA-256 accompanies every packet,
driver receipt and delivery report. Simulator and dynamics versions are `0.1.0`.
The model couples electrical load, battery energy, temperature and payload data.
It supplies deterministic procedure tests; it does not model spacecraft orbits.
Normal running integrates ten 100 ms physics ticks each second and publishes one
periodic telemetry frame. Commands and manual STEP publish telemetry immediately.

Kafka keeps the pinned Apache 4.3.1 broker. Its derived image replaces vulnerable
runtime libraries with exact signed Alpine packages and checksum-bound Maven
artifacts from their primary repositories. [The dependency lock](kafka_dependency_lock.json)
and generated image recipe record these inputs; all six images still require
actual vulnerability scans before delivery.

## Packet paths

CMD resolves typed arguments through this database and sends binary CCSDS TC to
`dss:3080`. Loading and release are separate. Stage receipts preserve procedure,
execution, plan, element, operation and database identities. Repeated identical
requests retrieve committed receipts; changed identities, stale epochs and
conflicting definitions fail. A lost acknowledgement remains uncertain and does
not authorize an automatic resend.
Durable ingress counts distinguish repeated delivery from deduplicated command
effects. Evidence pagination fences physical changes, replays and publication
updates. A paused scenario with unreleased commands requires an explicit,
state-bound test-case retirement acknowledgement before reset; prior evidence
remains durable and the retired epoch rejects further commands.

DSS commits state changes, command receipts and a telemetry outbox together.
Kafka publishes those exact packet bytes on `openbexi.GENERIC.tm` and command
receipts on `openbexi.GENERIC.ack`. TLM validates and decodes packets before
committing its ledger and consumer offset. It exposes engineering/raw values,
units, acquisition time, model time, source epoch/sequence, validity, quality,
freshness and database identity. Commands are verified through received TLM.
Retired epochs, gaps and mismatched quality policies cannot become GOOD samples.
Logical NEXT reads use an eight-packet live window. A cursor behind that window
receives an explicit gap with available bounds; CURRENT resynchronizes to the
latest received sample. The full packet ledger remains available for audit and
command-effect evidence.

The DSS collector groups up to 128 OK telemetry replies for one context and
physical epoch in one transaction. Each sample retains its checks, cursor,
alarm and event history. A conflict rolls back the cohort; its clock is admitted
only after telemetry commits.

DSS clock observations bind to the exact decoded telemetry packet and its epoch.
A reset retires the current clock head; historical observations remain available.
The new clock becomes visible after telemetry admits the new epoch. Time must
still move forward within each epoch.
Declared stale-sample scenarios leave the clock unavailable and must produce
their expected telemetry rejection or indeterminate verification result.

An unavailable broker retains committed packets. Automatic dynamics stop at
256 pending packets and expose backpressure; packets are never discarded to
report a healthy simulator. Historical scenarios remain durable.

## Binary encoding

The six-octet primary header follows [CCSDS Space Packet Protocol 133.0-B-2](https://ccsds.org/Pubs/133x0b2e2.pdf):
version 0, secondary header present, unsegmented sequence flags and a 14-bit
sequence count. APIDs are TC 100, TM 101 and acknowledgement 102. The length
field is data-field octets minus one. TCP reads use the header length and a
bounded aggregate deadline, including fragmented/coalesced packets.

The project secondary header is bytes `44 53 53 01`. The application field is a
canonical binary typed map, followed by CRC-16/CCITT with initial value `ffff`.
Type tags are null 0, boolean 1, signed-negative integer 2, unsigned integer 3,
float64 4, UTF-8 string 5, byte string 6, list 7 and map 8. Integers, lengths and
float64 use big endian order; maps sort keys and reject duplicates. The codec
limits nesting, collection lengths and packet size. This application format is
a project convention, not a claim of a standardized spacecraft command codec.

## Mandatory delivery gate

Cases resume normal dynamics during execution and pause before final evidence
capture. Received binary telemetry proves the running and paused phases.
Scenarios can vary sample acquisition uncertainty and driver-time uncertainty
separately. A readable sample can therefore produce an indeterminate clock-based
verification without changing its value or freshness.

`procedure_scenarios_v19.json` inventories every procedure, embedded case,
reference adaptation, variant and menu choice from source. Scenarios declare
initial state, operator responses, expected outcomes and execution bounds.
Reference mappings explicitly distinguish local adaptations from native SPELL
support; the native RESET signature remains FORCE-only.

`scripts.qualify_dss_v19` executes the real installed workers, CMD and TLM;
`scripts.validate_dss_delivery` independently checks inventory, exact source and
six image identities, database digest, expected negative outcomes and correlated
raw packets. Missing cases, unexpected failures/timeouts, skips or an unavailable
environment block delivery. A declared accelerated-time scenario advances the
physical model explicitly; it never claims that wall-clock time elapsed.

Reproduce the complete gate from clean committed source with
`scripts/run_release_next.ps1 -Module scripts.qualify_next -Arguments @('dss-validation')`
after the canonical `prepare` and candidate gates. Private operator credentials
remain in a temporary local token file and are excluded from reports.
If authority is lost during an in-flight reference subject, its durable intent
remains unresolved. Resume or recovery cannot authorize an automatic resend;
completed subjects retain their committed results.
