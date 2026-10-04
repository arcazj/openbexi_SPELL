from spell.driver.v1 import driver_pb2 as _driver_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HealthRequest(_message.Message):
    __slots__ = ("identity",)
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    identity: _driver_pb2.ObservationRequestIdentity
    def __init__(self, identity: _Optional[_Union[_driver_pb2.ObservationRequestIdentity, _Mapping]] = ...) -> None: ...

class ClockEvidenceResponse(_message.Message):
    __slots__ = ("time_response", "telemetry_packet", "packet_sha256")
    TIME_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    TELEMETRY_PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_SHA256_FIELD_NUMBER: _ClassVar[int]
    time_response: _driver_pb2.GetTimeResponse
    telemetry_packet: bytes
    packet_sha256: str
    def __init__(self, time_response: _Optional[_Union[_driver_pb2.GetTimeResponse, _Mapping]] = ..., telemetry_packet: _Optional[bytes] = ..., packet_sha256: _Optional[str] = ...) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("ready", "database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "state_revision", "tm_sequence", "status", "simulation_time_ns", "clock_epoch_unix_ns", "dynamics_tick")
    READY_FIELD_NUMBER: _ClassVar[int]
    DATABASE_REVISION_FIELD_NUMBER: _ClassVar[int]
    DATABASE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    SATELLITE_ID_FIELD_NUMBER: _ClassVar[int]
    SATELLITE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SCENARIO_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    TM_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SIMULATION_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    CLOCK_EPOCH_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    DYNAMICS_TICK_FIELD_NUMBER: _ClassVar[int]
    ready: bool
    database_revision: str
    database_digest: str
    satellite_id: str
    satellite_epoch: str
    scenario_id: str
    state_revision: int
    tm_sequence: int
    status: str
    simulation_time_ns: int
    clock_epoch_unix_ns: int
    dynamics_tick: int
    def __init__(self, ready: _Optional[bool] = ..., database_revision: _Optional[str] = ..., database_digest: _Optional[str] = ..., satellite_id: _Optional[str] = ..., satellite_epoch: _Optional[str] = ..., scenario_id: _Optional[str] = ..., state_revision: _Optional[int] = ..., tm_sequence: _Optional[int] = ..., status: _Optional[str] = ..., simulation_time_ns: _Optional[int] = ..., clock_epoch_unix_ns: _Optional[int] = ..., dynamics_tick: _Optional[int] = ...) -> None: ...

class Argument(_message.Message):
    __slots__ = ("name", "value_type", "value_format", "radix", "encoded", "integer_value", "float_value", "boolean_value", "string_value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FORMAT_FIELD_NUMBER: _ClassVar[int]
    RADIX_FIELD_NUMBER: _ClassVar[int]
    ENCODED_FIELD_NUMBER: _ClassVar[int]
    INTEGER_VALUE_FIELD_NUMBER: _ClassVar[int]
    FLOAT_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value_type: str
    value_format: str
    radix: str
    encoded: str
    integer_value: int
    float_value: float
    boolean_value: bool
    string_value: str
    def __init__(self, name: _Optional[str] = ..., value_type: _Optional[str] = ..., value_format: _Optional[str] = ..., radix: _Optional[str] = ..., encoded: _Optional[str] = ..., integer_value: _Optional[int] = ..., float_value: _Optional[float] = ..., boolean_value: _Optional[bool] = ..., string_value: _Optional[str] = ...) -> None: ...

class CommandStageRequest(_message.Message):
    __slots__ = ("identity", "database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "operation_id", "procedure_id", "execution_id", "plan_id", "element_id", "stage", "command_name", "arguments", "command_digest", "elements", "verification", "tolerance", "scheduling")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    DATABASE_REVISION_FIELD_NUMBER: _ClassVar[int]
    DATABASE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    SATELLITE_ID_FIELD_NUMBER: _ClassVar[int]
    SATELLITE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SCENARIO_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    PROCEDURE_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    PLAN_ID_FIELD_NUMBER: _ClassVar[int]
    ELEMENT_ID_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    COMMAND_NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    COMMAND_DIGEST_FIELD_NUMBER: _ClassVar[int]
    ELEMENTS_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    TOLERANCE_FIELD_NUMBER: _ClassVar[int]
    SCHEDULING_FIELD_NUMBER: _ClassVar[int]
    identity: _driver_pb2.ObservationRequestIdentity
    database_revision: str
    database_digest: str
    satellite_id: str
    satellite_epoch: str
    scenario_id: str
    operation_id: str
    procedure_id: str
    execution_id: str
    plan_id: str
    element_id: str
    stage: str
    command_name: str
    arguments: _containers.RepeatedCompositeFieldContainer[Argument]
    command_digest: str
    elements: _containers.RepeatedCompositeFieldContainer[CommandElement]
    verification: _containers.RepeatedCompositeFieldContainer[Verification]
    tolerance: float
    scheduling: Scheduling
    def __init__(self, identity: _Optional[_Union[_driver_pb2.ObservationRequestIdentity, _Mapping]] = ..., database_revision: _Optional[str] = ..., database_digest: _Optional[str] = ..., satellite_id: _Optional[str] = ..., satellite_epoch: _Optional[str] = ..., scenario_id: _Optional[str] = ..., operation_id: _Optional[str] = ..., procedure_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., plan_id: _Optional[str] = ..., element_id: _Optional[str] = ..., stage: _Optional[str] = ..., command_name: _Optional[str] = ..., arguments: _Optional[_Iterable[_Union[Argument, _Mapping]]] = ..., command_digest: _Optional[str] = ..., elements: _Optional[_Iterable[_Union[CommandElement, _Mapping]]] = ..., verification: _Optional[_Iterable[_Union[Verification, _Mapping]]] = ..., tolerance: _Optional[float] = ..., scheduling: _Optional[_Union[Scheduling, _Mapping]] = ...) -> None: ...

class Scheduling(_message.Message):
    __slots__ = ("target_sim_time_ns", "anchor_sim_time_ns", "clock_epoch_unix_ns", "time", "release_time", "send_delay_ms", "delay_ms")
    TARGET_SIM_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    ANCHOR_SIM_TIME_NS_FIELD_NUMBER: _ClassVar[int]
    CLOCK_EPOCH_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    RELEASE_TIME_FIELD_NUMBER: _ClassVar[int]
    SEND_DELAY_MS_FIELD_NUMBER: _ClassVar[int]
    DELAY_MS_FIELD_NUMBER: _ClassVar[int]
    target_sim_time_ns: int
    anchor_sim_time_ns: int
    clock_epoch_unix_ns: int
    time: str
    release_time: str
    send_delay_ms: int
    delay_ms: int
    def __init__(self, target_sim_time_ns: _Optional[int] = ..., anchor_sim_time_ns: _Optional[int] = ..., clock_epoch_unix_ns: _Optional[int] = ..., time: _Optional[str] = ..., release_time: _Optional[str] = ..., send_delay_ms: _Optional[int] = ..., delay_ms: _Optional[int] = ...) -> None: ...

class CommandElement(_message.Message):
    __slots__ = ("element_id", "command_name", "arguments", "command_digest")
    ELEMENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    COMMAND_DIGEST_FIELD_NUMBER: _ClassVar[int]
    element_id: str
    command_name: str
    arguments: _containers.RepeatedCompositeFieldContainer[Argument]
    command_digest: str
    def __init__(self, element_id: _Optional[str] = ..., command_name: _Optional[str] = ..., arguments: _Optional[_Iterable[_Union[Argument, _Mapping]]] = ..., command_digest: _Optional[str] = ...) -> None: ...

class Verification(_message.Message):
    __slots__ = ("channel", "operator", "expected", "tolerance", "timeout_ms")
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_FIELD_NUMBER: _ClassVar[int]
    TOLERANCE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    channel: str
    operator: str
    expected: Argument
    tolerance: float
    timeout_ms: int
    def __init__(self, channel: _Optional[str] = ..., operator: _Optional[str] = ..., expected: _Optional[_Union[Argument, _Mapping]] = ..., tolerance: _Optional[float] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class CommandStageResponse(_message.Message):
    __slots__ = ("acknowledgement_packet", "command_packet_sha256", "acknowledgement_packet_sha256", "status")
    ACKNOWLEDGEMENT_PACKET_FIELD_NUMBER: _ClassVar[int]
    COMMAND_PACKET_SHA256_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGEMENT_PACKET_SHA256_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    acknowledgement_packet: bytes
    command_packet_sha256: str
    acknowledgement_packet_sha256: str
    status: str
    def __init__(self, acknowledgement_packet: _Optional[bytes] = ..., command_packet_sha256: _Optional[str] = ..., acknowledgement_packet_sha256: _Optional[str] = ..., status: _Optional[str] = ...) -> None: ...

class PacketEvidenceRequest(_message.Message):
    __slots__ = ("identity", "satellite_epoch", "sequence", "operation_id", "packet_sha256")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    SATELLITE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    PACKET_SHA256_FIELD_NUMBER: _ClassVar[int]
    identity: _driver_pb2.ObservationRequestIdentity
    satellite_epoch: str
    sequence: int
    operation_id: str
    packet_sha256: str
    def __init__(self, identity: _Optional[_Union[_driver_pb2.ObservationRequestIdentity, _Mapping]] = ..., satellite_epoch: _Optional[str] = ..., sequence: _Optional[int] = ..., operation_id: _Optional[str] = ..., packet_sha256: _Optional[str] = ...) -> None: ...

class PacketEvidence(_message.Message):
    __slots__ = ("packet", "packet_sha256", "topic", "partition", "offset", "received_unix_ns")
    PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_SHA256_FIELD_NUMBER: _ClassVar[int]
    TOPIC_FIELD_NUMBER: _ClassVar[int]
    PARTITION_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    packet: bytes
    packet_sha256: str
    topic: str
    partition: int
    offset: int
    received_unix_ns: int
    def __init__(self, packet: _Optional[bytes] = ..., packet_sha256: _Optional[str] = ..., topic: _Optional[str] = ..., partition: _Optional[int] = ..., offset: _Optional[int] = ..., received_unix_ns: _Optional[int] = ...) -> None: ...

class PacketEvidenceResponse(_message.Message):
    __slots__ = ("packets", "status")
    PACKETS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    packets: _containers.RepeatedCompositeFieldContainer[PacketEvidence]
    status: str
    def __init__(self, packets: _Optional[_Iterable[_Union[PacketEvidence, _Mapping]]] = ..., status: _Optional[str] = ...) -> None: ...
