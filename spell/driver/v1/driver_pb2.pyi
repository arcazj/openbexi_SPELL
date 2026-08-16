from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RpcMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RPC_METHOD_UNSPECIFIED: _ClassVar[RpcMethod]
    RPC_METHOD_HANDSHAKE: _ClassVar[RpcMethod]
    RPC_METHOD_HEALTH: _ClassVar[RpcMethod]
    RPC_METHOD_OPEN_CONTEXT: _ClassVar[RpcMethod]
    RPC_METHOD_CLOSE_CONTEXT: _ClassVar[RpcMethod]
    RPC_METHOD_ATTACH_EXECUTION: _ClassVar[RpcMethod]
    RPC_METHOD_DETACH_EXECUTION: _ClassVar[RpcMethod]
    RPC_METHOD_CANCEL_LIFECYCLE_OPERATION: _ClassVar[RpcMethod]
    RPC_METHOD_DRAIN_HOST: _ClassVar[RpcMethod]
    RPC_METHOD_GET_OPERATION: _ClassVar[RpcMethod]

class InfrastructureService(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INFRASTRUCTURE_SERVICE_UNSPECIFIED: _ClassVar[InfrastructureService]
    INFRASTRUCTURE_SERVICE_HOST: _ClassVar[InfrastructureService]
    INFRASTRUCTURE_SERVICE_CONTEXT_LIFECYCLE: _ClassVar[InfrastructureService]
    INFRASTRUCTURE_SERVICE_EXECUTION_LIFECYCLE: _ClassVar[InfrastructureService]
    INFRASTRUCTURE_SERVICE_OPERATION_RECONCILIATION: _ClassVar[InfrastructureService]

class CapabilityModifier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_MODIFIER_UNSPECIFIED: _ClassVar[CapabilityModifier]
    CAPABILITY_MODIFIER_NONE: _ClassVar[CapabilityModifier]
    CAPABILITY_MODIFIER_COOPERATIVE_CANCELLATION: _ClassVar[CapabilityModifier]
    CAPABILITY_MODIFIER_DETERMINISTIC_FAULT_POINT: _ClassVar[CapabilityModifier]

class CapabilityFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_FORMAT_UNSPECIFIED: _ClassVar[CapabilityFormat]
    CAPABILITY_FORMAT_PROTOBUF_BINARY: _ClassVar[CapabilityFormat]

class Mutability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MUTABILITY_UNSPECIFIED: _ClassVar[Mutability]
    MUTABILITY_READ_ONLY: _ClassVar[Mutability]
    MUTABILITY_LIFECYCLE: _ClassVar[Mutability]

class StreamSupport(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STREAM_SUPPORT_UNSPECIFIED: _ClassVar[StreamSupport]
    STREAM_SUPPORT_NONE: _ClassVar[StreamSupport]

class HostState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOST_STATE_UNSPECIFIED: _ClassVar[HostState]
    HOST_STATE_STARTING: _ClassVar[HostState]
    HOST_STATE_READY: _ClassVar[HostState]
    HOST_STATE_DEGRADED: _ClassVar[HostState]
    HOST_STATE_DRAINING: _ClassVar[HostState]
    HOST_STATE_CLOSED: _ClassVar[HostState]
    HOST_STATE_FAILED: _ClassVar[HostState]

class ContextState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTEXT_STATE_UNSPECIFIED: _ClassVar[ContextState]
    CONTEXT_STATE_OPENING: _ClassVar[ContextState]
    CONTEXT_STATE_ACTIVE: _ClassVar[ContextState]
    CONTEXT_STATE_DEGRADED: _ClassVar[ContextState]
    CONTEXT_STATE_CLOSING: _ClassVar[ContextState]
    CONTEXT_STATE_CLOSED: _ClassVar[ContextState]
    CONTEXT_STATE_FAILED: _ClassVar[ContextState]

class AttachmentState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ATTACHMENT_STATE_UNSPECIFIED: _ClassVar[AttachmentState]
    ATTACHMENT_STATE_ATTACHING: _ClassVar[AttachmentState]
    ATTACHMENT_STATE_ATTACHED: _ClassVar[AttachmentState]
    ATTACHMENT_STATE_DETACHING: _ClassVar[AttachmentState]
    ATTACHMENT_STATE_DETACHED: _ClassVar[AttachmentState]
    ATTACHMENT_STATE_FAILED: _ClassVar[AttachmentState]

class OperationStage(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OPERATION_STAGE_UNSPECIFIED: _ClassVar[OperationStage]
    OPERATION_STAGE_REQUESTED: _ClassVar[OperationStage]
    OPERATION_STAGE_ACCEPTED: _ClassVar[OperationStage]
    OPERATION_STAGE_DISPATCHED: _ClassVar[OperationStage]
    OPERATION_STAGE_RECONCILING: _ClassVar[OperationStage]
    OPERATION_STAGE_SETTLED: _ClassVar[OperationStage]

class EffectClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EFFECT_CLASS_UNSPECIFIED: _ClassVar[EffectClass]
    EFFECT_CLASS_NONE: _ClassVar[EffectClass]
    EFFECT_CLASS_CONTEXT_OPEN: _ClassVar[EffectClass]
    EFFECT_CLASS_CONTEXT_CLOSE: _ClassVar[EffectClass]
    EFFECT_CLASS_EXECUTION_ATTACH: _ClassVar[EffectClass]
    EFFECT_CLASS_EXECUTION_DETACH: _ClassVar[EffectClass]
    EFFECT_CLASS_LIFECYCLE_CANCEL: _ClassVar[EffectClass]
    EFFECT_CLASS_HOST_DRAIN: _ClassVar[EffectClass]

class EffectCertainty(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EFFECT_CERTAINTY_UNSPECIFIED: _ClassVar[EffectCertainty]
    EFFECT_CERTAINTY_NO_EFFECT: _ClassVar[EffectCertainty]
    EFFECT_CERTAINTY_CONFIRMED: _ClassVar[EffectCertainty]
    EFFECT_CERTAINTY_POSSIBLE: _ClassVar[EffectCertainty]
    EFFECT_CERTAINTY_UNKNOWN: _ClassVar[EffectCertainty]

class ResultCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESULT_CODE_UNSPECIFIED: _ClassVar[ResultCode]
    RESULT_CODE_OK: _ClassVar[ResultCode]
    RESULT_CODE_INVALID_ARGUMENT: _ClassVar[ResultCode]
    RESULT_CODE_UNAUTHENTICATED: _ClassVar[ResultCode]
    RESULT_CODE_PERMISSION_DENIED: _ClassVar[ResultCode]
    RESULT_CODE_UNSUPPORTED: _ClassVar[ResultCode]
    RESULT_CODE_CONFLICT: _ClassVar[ResultCode]
    RESULT_CODE_CAPACITY_EXHAUSTED: _ClassVar[ResultCode]
    RESULT_CODE_DEADLINE_EXCEEDED: _ClassVar[ResultCode]
    RESULT_CODE_CANCELLED: _ClassVar[ResultCode]
    RESULT_CODE_ALREADY_SETTLED: _ClassVar[ResultCode]
    RESULT_CODE_STALE_GENERATION: _ClassVar[ResultCode]
    RESULT_CODE_JOURNAL_UNAVAILABLE: _ClassVar[ResultCode]
    RESULT_CODE_RECONCILIATION_REQUIRED: _ClassVar[ResultCode]
    RESULT_CODE_INTERNAL: _ClassVar[ResultCode]

class SafeErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SAFE_ERROR_CODE_UNSPECIFIED: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_NONE: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_VALIDATION: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_VERSION_MISMATCH: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_IDENTITY_MISMATCH: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_GENERATION_MISMATCH: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_DIGEST_MISMATCH: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_UNSUPPORTED: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_CAPACITY: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_DEADLINE: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_CANCELLED: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_CONFLICT: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_JOURNAL: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_HOOK: _ClassVar[SafeErrorCode]
    SAFE_ERROR_CODE_INTERNAL: _ClassVar[SafeErrorCode]

class HookLayer(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOOK_LAYER_UNSPECIFIED: _ClassVar[HookLayer]
    HOOK_LAYER_CONTEXT_CONFIGURATION: _ClassVar[HookLayer]
    HOOK_LAYER_CONTEXT_FIXTURE: _ClassVar[HookLayer]
    HOOK_LAYER_ATTACHMENT_CONFIGURATION: _ClassVar[HookLayer]
    HOOK_LAYER_ATTACHMENT_FIXTURE: _ClassVar[HookLayer]
    HOOK_LAYER_HOST: _ClassVar[HookLayer]

class HookAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOOK_ACTION_UNSPECIFIED: _ClassVar[HookAction]
    HOOK_ACTION_SETUP: _ClassVar[HookAction]
    HOOK_ACTION_CLEANUP: _ClassVar[HookAction]
    HOOK_ACTION_COMPENSATE: _ClassVar[HookAction]

class HookResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOOK_RESULT_UNSPECIFIED: _ClassVar[HookResult]
    HOOK_RESULT_COMPLETED: _ClassVar[HookResult]
    HOOK_RESULT_FAILED: _ClassVar[HookResult]
    HOOK_RESULT_CANCELLED: _ClassVar[HookResult]
    HOOK_RESULT_SKIPPED: _ClassVar[HookResult]

class AttachmentReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ATTACHMENT_REASON_UNSPECIFIED: _ClassVar[AttachmentReason]
    ATTACHMENT_REASON_INITIAL_LOAD: _ClassVar[AttachmentReason]
    ATTACHMENT_REASON_RELOAD: _ClassVar[AttachmentReason]

class DetachmentReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DETACHMENT_REASON_UNSPECIFIED: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_FINISHED: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_ABORTED: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_RELOAD: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_EXPLICIT_UNLOAD: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_CONTEXT_CLOSE: _ClassVar[DetachmentReason]
    DETACHMENT_REASON_HOST_DRAIN: _ClassVar[DetachmentReason]

class ObservationResultCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBSERVATION_RESULT_CODE_UNSPECIFIED: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_OK: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_NOT_FOUND: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_NOT_AVAILABLE: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_CANCELLED: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_GAP: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_STALE_GENERATION: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_CLOCK_UNCERTAIN: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_CONTRACT_MISMATCH: _ClassVar[ObservationResultCode]
    OBSERVATION_RESULT_CODE_INTERNAL: _ClassVar[ObservationResultCode]

class ClockSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CLOCK_SOURCE_UNSPECIFIED: _ClassVar[ClockSource]
    CLOCK_SOURCE_SIMULATOR_GCS_TIME: _ClassVar[ClockSource]
    CLOCK_SOURCE_SIMULATOR: _ClassVar[ClockSource]
    CLOCK_SOURCE_HOST_FALLBACK: _ClassVar[ClockSource]

class ObservationValidity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBSERVATION_VALIDITY_UNSPECIFIED: _ClassVar[ObservationValidity]
    OBSERVATION_VALIDITY_VALID: _ClassVar[ObservationValidity]
    OBSERVATION_VALIDITY_INVALID: _ClassVar[ObservationValidity]
    OBSERVATION_VALIDITY_UNKNOWN: _ClassVar[ObservationValidity]

class ObservationQuality(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBSERVATION_QUALITY_UNSPECIFIED: _ClassVar[ObservationQuality]
    OBSERVATION_QUALITY_GOOD: _ClassVar[ObservationQuality]
    OBSERVATION_QUALITY_SUSPECT: _ClassVar[ObservationQuality]
    OBSERVATION_QUALITY_BAD: _ClassVar[ObservationQuality]
    OBSERVATION_QUALITY_UNKNOWN: _ClassVar[ObservationQuality]

class ScalarKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCALAR_KIND_UNSPECIFIED: _ClassVar[ScalarKind]
    SCALAR_KIND_BOOLEAN: _ClassVar[ScalarKind]
    SCALAR_KIND_INT64: _ClassVar[ScalarKind]
    SCALAR_KIND_UINT64: _ClassVar[ScalarKind]
    SCALAR_KIND_FINITE_DOUBLE: _ClassVar[ScalarKind]
    SCALAR_KIND_STRING: _ClassVar[ScalarKind]
    SCALAR_KIND_BYTES: _ClassVar[ScalarKind]

class GetTMMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GET_TM_MODE_UNSPECIFIED: _ClassVar[GetTMMode]
    GET_TM_MODE_CURRENT: _ClassVar[GetTMMode]
    GET_TM_MODE_NEXT: _ClassVar[GetTMMode]
RPC_METHOD_UNSPECIFIED: RpcMethod
RPC_METHOD_HANDSHAKE: RpcMethod
RPC_METHOD_HEALTH: RpcMethod
RPC_METHOD_OPEN_CONTEXT: RpcMethod
RPC_METHOD_CLOSE_CONTEXT: RpcMethod
RPC_METHOD_ATTACH_EXECUTION: RpcMethod
RPC_METHOD_DETACH_EXECUTION: RpcMethod
RPC_METHOD_CANCEL_LIFECYCLE_OPERATION: RpcMethod
RPC_METHOD_DRAIN_HOST: RpcMethod
RPC_METHOD_GET_OPERATION: RpcMethod
INFRASTRUCTURE_SERVICE_UNSPECIFIED: InfrastructureService
INFRASTRUCTURE_SERVICE_HOST: InfrastructureService
INFRASTRUCTURE_SERVICE_CONTEXT_LIFECYCLE: InfrastructureService
INFRASTRUCTURE_SERVICE_EXECUTION_LIFECYCLE: InfrastructureService
INFRASTRUCTURE_SERVICE_OPERATION_RECONCILIATION: InfrastructureService
CAPABILITY_MODIFIER_UNSPECIFIED: CapabilityModifier
CAPABILITY_MODIFIER_NONE: CapabilityModifier
CAPABILITY_MODIFIER_COOPERATIVE_CANCELLATION: CapabilityModifier
CAPABILITY_MODIFIER_DETERMINISTIC_FAULT_POINT: CapabilityModifier
CAPABILITY_FORMAT_UNSPECIFIED: CapabilityFormat
CAPABILITY_FORMAT_PROTOBUF_BINARY: CapabilityFormat
MUTABILITY_UNSPECIFIED: Mutability
MUTABILITY_READ_ONLY: Mutability
MUTABILITY_LIFECYCLE: Mutability
STREAM_SUPPORT_UNSPECIFIED: StreamSupport
STREAM_SUPPORT_NONE: StreamSupport
HOST_STATE_UNSPECIFIED: HostState
HOST_STATE_STARTING: HostState
HOST_STATE_READY: HostState
HOST_STATE_DEGRADED: HostState
HOST_STATE_DRAINING: HostState
HOST_STATE_CLOSED: HostState
HOST_STATE_FAILED: HostState
CONTEXT_STATE_UNSPECIFIED: ContextState
CONTEXT_STATE_OPENING: ContextState
CONTEXT_STATE_ACTIVE: ContextState
CONTEXT_STATE_DEGRADED: ContextState
CONTEXT_STATE_CLOSING: ContextState
CONTEXT_STATE_CLOSED: ContextState
CONTEXT_STATE_FAILED: ContextState
ATTACHMENT_STATE_UNSPECIFIED: AttachmentState
ATTACHMENT_STATE_ATTACHING: AttachmentState
ATTACHMENT_STATE_ATTACHED: AttachmentState
ATTACHMENT_STATE_DETACHING: AttachmentState
ATTACHMENT_STATE_DETACHED: AttachmentState
ATTACHMENT_STATE_FAILED: AttachmentState
OPERATION_STAGE_UNSPECIFIED: OperationStage
OPERATION_STAGE_REQUESTED: OperationStage
OPERATION_STAGE_ACCEPTED: OperationStage
OPERATION_STAGE_DISPATCHED: OperationStage
OPERATION_STAGE_RECONCILING: OperationStage
OPERATION_STAGE_SETTLED: OperationStage
EFFECT_CLASS_UNSPECIFIED: EffectClass
EFFECT_CLASS_NONE: EffectClass
EFFECT_CLASS_CONTEXT_OPEN: EffectClass
EFFECT_CLASS_CONTEXT_CLOSE: EffectClass
EFFECT_CLASS_EXECUTION_ATTACH: EffectClass
EFFECT_CLASS_EXECUTION_DETACH: EffectClass
EFFECT_CLASS_LIFECYCLE_CANCEL: EffectClass
EFFECT_CLASS_HOST_DRAIN: EffectClass
EFFECT_CERTAINTY_UNSPECIFIED: EffectCertainty
EFFECT_CERTAINTY_NO_EFFECT: EffectCertainty
EFFECT_CERTAINTY_CONFIRMED: EffectCertainty
EFFECT_CERTAINTY_POSSIBLE: EffectCertainty
EFFECT_CERTAINTY_UNKNOWN: EffectCertainty
RESULT_CODE_UNSPECIFIED: ResultCode
RESULT_CODE_OK: ResultCode
RESULT_CODE_INVALID_ARGUMENT: ResultCode
RESULT_CODE_UNAUTHENTICATED: ResultCode
RESULT_CODE_PERMISSION_DENIED: ResultCode
RESULT_CODE_UNSUPPORTED: ResultCode
RESULT_CODE_CONFLICT: ResultCode
RESULT_CODE_CAPACITY_EXHAUSTED: ResultCode
RESULT_CODE_DEADLINE_EXCEEDED: ResultCode
RESULT_CODE_CANCELLED: ResultCode
RESULT_CODE_ALREADY_SETTLED: ResultCode
RESULT_CODE_STALE_GENERATION: ResultCode
RESULT_CODE_JOURNAL_UNAVAILABLE: ResultCode
RESULT_CODE_RECONCILIATION_REQUIRED: ResultCode
RESULT_CODE_INTERNAL: ResultCode
SAFE_ERROR_CODE_UNSPECIFIED: SafeErrorCode
SAFE_ERROR_CODE_NONE: SafeErrorCode
SAFE_ERROR_CODE_VALIDATION: SafeErrorCode
SAFE_ERROR_CODE_VERSION_MISMATCH: SafeErrorCode
SAFE_ERROR_CODE_IDENTITY_MISMATCH: SafeErrorCode
SAFE_ERROR_CODE_GENERATION_MISMATCH: SafeErrorCode
SAFE_ERROR_CODE_DIGEST_MISMATCH: SafeErrorCode
SAFE_ERROR_CODE_UNSUPPORTED: SafeErrorCode
SAFE_ERROR_CODE_CAPACITY: SafeErrorCode
SAFE_ERROR_CODE_DEADLINE: SafeErrorCode
SAFE_ERROR_CODE_CANCELLED: SafeErrorCode
SAFE_ERROR_CODE_CONFLICT: SafeErrorCode
SAFE_ERROR_CODE_JOURNAL: SafeErrorCode
SAFE_ERROR_CODE_HOOK: SafeErrorCode
SAFE_ERROR_CODE_INTERNAL: SafeErrorCode
HOOK_LAYER_UNSPECIFIED: HookLayer
HOOK_LAYER_CONTEXT_CONFIGURATION: HookLayer
HOOK_LAYER_CONTEXT_FIXTURE: HookLayer
HOOK_LAYER_ATTACHMENT_CONFIGURATION: HookLayer
HOOK_LAYER_ATTACHMENT_FIXTURE: HookLayer
HOOK_LAYER_HOST: HookLayer
HOOK_ACTION_UNSPECIFIED: HookAction
HOOK_ACTION_SETUP: HookAction
HOOK_ACTION_CLEANUP: HookAction
HOOK_ACTION_COMPENSATE: HookAction
HOOK_RESULT_UNSPECIFIED: HookResult
HOOK_RESULT_COMPLETED: HookResult
HOOK_RESULT_FAILED: HookResult
HOOK_RESULT_CANCELLED: HookResult
HOOK_RESULT_SKIPPED: HookResult
ATTACHMENT_REASON_UNSPECIFIED: AttachmentReason
ATTACHMENT_REASON_INITIAL_LOAD: AttachmentReason
ATTACHMENT_REASON_RELOAD: AttachmentReason
DETACHMENT_REASON_UNSPECIFIED: DetachmentReason
DETACHMENT_REASON_FINISHED: DetachmentReason
DETACHMENT_REASON_ABORTED: DetachmentReason
DETACHMENT_REASON_RELOAD: DetachmentReason
DETACHMENT_REASON_EXPLICIT_UNLOAD: DetachmentReason
DETACHMENT_REASON_CONTEXT_CLOSE: DetachmentReason
DETACHMENT_REASON_HOST_DRAIN: DetachmentReason
OBSERVATION_RESULT_CODE_UNSPECIFIED: ObservationResultCode
OBSERVATION_RESULT_CODE_OK: ObservationResultCode
OBSERVATION_RESULT_CODE_NOT_FOUND: ObservationResultCode
OBSERVATION_RESULT_CODE_NOT_AVAILABLE: ObservationResultCode
OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED: ObservationResultCode
OBSERVATION_RESULT_CODE_CANCELLED: ObservationResultCode
OBSERVATION_RESULT_CODE_GAP: ObservationResultCode
OBSERVATION_RESULT_CODE_STALE_GENERATION: ObservationResultCode
OBSERVATION_RESULT_CODE_CLOCK_UNCERTAIN: ObservationResultCode
OBSERVATION_RESULT_CODE_CONTRACT_MISMATCH: ObservationResultCode
OBSERVATION_RESULT_CODE_INTERNAL: ObservationResultCode
CLOCK_SOURCE_UNSPECIFIED: ClockSource
CLOCK_SOURCE_SIMULATOR_GCS_TIME: ClockSource
CLOCK_SOURCE_SIMULATOR: ClockSource
CLOCK_SOURCE_HOST_FALLBACK: ClockSource
OBSERVATION_VALIDITY_UNSPECIFIED: ObservationValidity
OBSERVATION_VALIDITY_VALID: ObservationValidity
OBSERVATION_VALIDITY_INVALID: ObservationValidity
OBSERVATION_VALIDITY_UNKNOWN: ObservationValidity
OBSERVATION_QUALITY_UNSPECIFIED: ObservationQuality
OBSERVATION_QUALITY_GOOD: ObservationQuality
OBSERVATION_QUALITY_SUSPECT: ObservationQuality
OBSERVATION_QUALITY_BAD: ObservationQuality
OBSERVATION_QUALITY_UNKNOWN: ObservationQuality
SCALAR_KIND_UNSPECIFIED: ScalarKind
SCALAR_KIND_BOOLEAN: ScalarKind
SCALAR_KIND_INT64: ScalarKind
SCALAR_KIND_UINT64: ScalarKind
SCALAR_KIND_FINITE_DOUBLE: ScalarKind
SCALAR_KIND_STRING: ScalarKind
SCALAR_KIND_BYTES: ScalarKind
GET_TM_MODE_UNSPECIFIED: GetTMMode
GET_TM_MODE_CURRENT: GetTMMode
GET_TM_MODE_NEXT: GetTMMode

class ContractVersion(_message.Message):
    __slots__ = ("major", "minor")
    MAJOR_FIELD_NUMBER: _ClassVar[int]
    MINOR_FIELD_NUMBER: _ClassVar[int]
    major: int
    minor: int
    def __init__(self, major: _Optional[int] = ..., minor: _Optional[int] = ...) -> None: ...

class RequestIdentity(_message.Message):
    __slots__ = ("contract_version", "server_profile_id", "driver_host_generation", "host_profile_digest", "context_id", "context_generation", "context_binding_digest", "execution_id", "execution_attachment_generation", "execution_attachment_digest", "driver_binding_id", "operation_id", "attempt_id", "attempt_number", "correlation_id", "deadline_unix_ms", "credential_epoch")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SERVER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_HOST_GENERATION_FIELD_NUMBER: _ClassVar[int]
    HOST_PROFILE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_ID_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_BINDING_DIGEST_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ATTACHMENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ATTACHMENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    DRIVER_BINDING_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_NUMBER_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    server_profile_id: str
    driver_host_generation: str
    host_profile_digest: str
    context_id: str
    context_generation: str
    context_binding_digest: str
    execution_id: str
    execution_attachment_generation: str
    execution_attachment_digest: str
    driver_binding_id: str
    operation_id: str
    attempt_id: str
    attempt_number: int
    correlation_id: str
    deadline_unix_ms: int
    credential_epoch: int
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., server_profile_id: _Optional[str] = ..., driver_host_generation: _Optional[str] = ..., host_profile_digest: _Optional[str] = ..., context_id: _Optional[str] = ..., context_generation: _Optional[str] = ..., context_binding_digest: _Optional[str] = ..., execution_id: _Optional[str] = ..., execution_attachment_generation: _Optional[str] = ..., execution_attachment_digest: _Optional[str] = ..., driver_binding_id: _Optional[str] = ..., operation_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., attempt_number: _Optional[int] = ..., correlation_id: _Optional[str] = ..., deadline_unix_ms: _Optional[int] = ..., credential_epoch: _Optional[int] = ...) -> None: ...

class SafeError(_message.Message):
    __slots__ = ("code", "safe_message", "retryable")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    code: SafeErrorCode
    safe_message: str
    retryable: bool
    def __init__(self, code: _Optional[_Union[SafeErrorCode, str]] = ..., safe_message: _Optional[str] = ..., retryable: _Optional[bool] = ...) -> None: ...

class CapabilityDescriptor(_message.Message):
    __slots__ = ("service", "method", "modifiers", "formats", "mutability", "stream_support")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    FORMATS_FIELD_NUMBER: _ClassVar[int]
    MUTABILITY_FIELD_NUMBER: _ClassVar[int]
    STREAM_SUPPORT_FIELD_NUMBER: _ClassVar[int]
    service: InfrastructureService
    method: RpcMethod
    modifiers: _containers.RepeatedScalarFieldContainer[CapabilityModifier]
    formats: _containers.RepeatedScalarFieldContainer[CapabilityFormat]
    mutability: Mutability
    stream_support: StreamSupport
    def __init__(self, service: _Optional[_Union[InfrastructureService, str]] = ..., method: _Optional[_Union[RpcMethod, str]] = ..., modifiers: _Optional[_Iterable[_Union[CapabilityModifier, str]]] = ..., formats: _Optional[_Iterable[_Union[CapabilityFormat, str]]] = ..., mutability: _Optional[_Union[Mutability, str]] = ..., stream_support: _Optional[_Union[StreamSupport, str]] = ...) -> None: ...

class CapacityLimits(_message.Message):
    __slots__ = ("max_contexts_per_host", "max_attachments_per_context", "max_lifecycle_operations_per_host", "max_lifecycle_operations_per_context")
    MAX_CONTEXTS_PER_HOST_FIELD_NUMBER: _ClassVar[int]
    MAX_ATTACHMENTS_PER_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    MAX_LIFECYCLE_OPERATIONS_PER_HOST_FIELD_NUMBER: _ClassVar[int]
    MAX_LIFECYCLE_OPERATIONS_PER_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    max_contexts_per_host: int
    max_attachments_per_context: int
    max_lifecycle_operations_per_host: int
    max_lifecycle_operations_per_context: int
    def __init__(self, max_contexts_per_host: _Optional[int] = ..., max_attachments_per_context: _Optional[int] = ..., max_lifecycle_operations_per_host: _Optional[int] = ..., max_lifecycle_operations_per_context: _Optional[int] = ...) -> None: ...

class CapacityUse(_message.Message):
    __slots__ = ("contexts", "attachments", "lifecycle_operations_host", "lifecycle_operations_context")
    CONTEXTS_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_OPERATIONS_HOST_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_OPERATIONS_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    contexts: int
    attachments: int
    lifecycle_operations_host: int
    lifecycle_operations_context: int
    def __init__(self, contexts: _Optional[int] = ..., attachments: _Optional[int] = ..., lifecycle_operations_host: _Optional[int] = ..., lifecycle_operations_context: _Optional[int] = ...) -> None: ...

class DriverIdentity(_message.Message):
    __slots__ = ("logical_driver_id", "implementation_version", "simulator", "server_profile_id", "driver_profile_id", "driver_host_generation", "host_configuration_schema", "host_profile_digest", "credential_epoch")
    LOGICAL_DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    IMPLEMENTATION_VERSION_FIELD_NUMBER: _ClassVar[int]
    SIMULATOR_FIELD_NUMBER: _ClassVar[int]
    SERVER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_HOST_GENERATION_FIELD_NUMBER: _ClassVar[int]
    HOST_CONFIGURATION_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    HOST_PROFILE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    logical_driver_id: str
    implementation_version: str
    simulator: bool
    server_profile_id: str
    driver_profile_id: str
    driver_host_generation: str
    host_configuration_schema: str
    host_profile_digest: str
    credential_epoch: int
    def __init__(self, logical_driver_id: _Optional[str] = ..., implementation_version: _Optional[str] = ..., simulator: _Optional[bool] = ..., server_profile_id: _Optional[str] = ..., driver_profile_id: _Optional[str] = ..., driver_host_generation: _Optional[str] = ..., host_configuration_schema: _Optional[str] = ..., host_profile_digest: _Optional[str] = ..., credential_epoch: _Optional[int] = ...) -> None: ...

class ContextBindingConfiguration(_message.Message):
    __slots__ = ("schema_version", "context_profile_id", "synthetic_context_label", "expected_context_binding_digest")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    SYNTHETIC_CONTEXT_LABEL_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_CONTEXT_BINDING_DIGEST_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    context_profile_id: str
    synthetic_context_label: str
    expected_context_binding_digest: str
    def __init__(self, schema_version: _Optional[str] = ..., context_profile_id: _Optional[str] = ..., synthetic_context_label: _Optional[str] = ..., expected_context_binding_digest: _Optional[str] = ...) -> None: ...

class ExecutionAttachmentConfiguration(_message.Message):
    __slots__ = ("schema_version", "attachment_profile_id", "synthetic_execution_label", "expected_execution_attachment_digest", "reason", "replaced_driver_binding_id")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    SYNTHETIC_EXECUTION_LABEL_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_EXECUTION_ATTACHMENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REPLACED_DRIVER_BINDING_ID_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    attachment_profile_id: str
    synthetic_execution_label: str
    expected_execution_attachment_digest: str
    reason: AttachmentReason
    replaced_driver_binding_id: str
    def __init__(self, schema_version: _Optional[str] = ..., attachment_profile_id: _Optional[str] = ..., synthetic_execution_label: _Optional[str] = ..., expected_execution_attachment_digest: _Optional[str] = ..., reason: _Optional[_Union[AttachmentReason, str]] = ..., replaced_driver_binding_id: _Optional[str] = ...) -> None: ...

class HookTrace(_message.Message):
    __slots__ = ("sequence", "hook_id", "owner_layer", "action", "result", "operation_id", "attempt_id", "started_unix_ms", "completed_unix_ms", "error", "identity", "stage", "certainty_present", "certainty")
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    HOOK_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_LAYER_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    STARTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    CERTAINTY_PRESENT_FIELD_NUMBER: _ClassVar[int]
    CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    sequence: int
    hook_id: str
    owner_layer: HookLayer
    action: HookAction
    result: HookResult
    operation_id: str
    attempt_id: str
    started_unix_ms: int
    completed_unix_ms: int
    error: SafeError
    identity: RequestIdentity
    stage: OperationStage
    certainty_present: bool
    certainty: EffectCertainty
    def __init__(self, sequence: _Optional[int] = ..., hook_id: _Optional[str] = ..., owner_layer: _Optional[_Union[HookLayer, str]] = ..., action: _Optional[_Union[HookAction, str]] = ..., result: _Optional[_Union[HookResult, str]] = ..., operation_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., started_unix_ms: _Optional[int] = ..., completed_unix_ms: _Optional[int] = ..., error: _Optional[_Union[SafeError, _Mapping]] = ..., identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., stage: _Optional[_Union[OperationStage, str]] = ..., certainty_present: _Optional[bool] = ..., certainty: _Optional[_Union[EffectCertainty, str]] = ...) -> None: ...

class OperationAttempt(_message.Message):
    __slots__ = ("attempt_id", "attempt_number", "request_digest", "stage", "effect_class", "certainty_present", "certainty", "result_code", "error", "requested_unix_ms", "accepted_unix_ms", "dispatched_unix_ms", "settled_unix_ms", "hook_traces", "identity", "attachment_reason", "replaced_driver_binding_id")
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_NUMBER_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    EFFECT_CLASS_FIELD_NUMBER: _ClassVar[int]
    CERTAINTY_PRESENT_FIELD_NUMBER: _ClassVar[int]
    CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    RESULT_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DISPATCHED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    SETTLED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    HOOK_TRACES_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_REASON_FIELD_NUMBER: _ClassVar[int]
    REPLACED_DRIVER_BINDING_ID_FIELD_NUMBER: _ClassVar[int]
    attempt_id: str
    attempt_number: int
    request_digest: str
    stage: OperationStage
    effect_class: EffectClass
    certainty_present: bool
    certainty: EffectCertainty
    result_code: ResultCode
    error: SafeError
    requested_unix_ms: int
    accepted_unix_ms: int
    dispatched_unix_ms: int
    settled_unix_ms: int
    hook_traces: _containers.RepeatedCompositeFieldContainer[HookTrace]
    identity: RequestIdentity
    attachment_reason: AttachmentReason
    replaced_driver_binding_id: str
    def __init__(self, attempt_id: _Optional[str] = ..., attempt_number: _Optional[int] = ..., request_digest: _Optional[str] = ..., stage: _Optional[_Union[OperationStage, str]] = ..., effect_class: _Optional[_Union[EffectClass, str]] = ..., certainty_present: _Optional[bool] = ..., certainty: _Optional[_Union[EffectCertainty, str]] = ..., result_code: _Optional[_Union[ResultCode, str]] = ..., error: _Optional[_Union[SafeError, _Mapping]] = ..., requested_unix_ms: _Optional[int] = ..., accepted_unix_ms: _Optional[int] = ..., dispatched_unix_ms: _Optional[int] = ..., settled_unix_ms: _Optional[int] = ..., hook_traces: _Optional[_Iterable[_Union[HookTrace, _Mapping]]] = ..., identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., attachment_reason: _Optional[_Union[AttachmentReason, str]] = ..., replaced_driver_binding_id: _Optional[str] = ...) -> None: ...

class OperationRecord(_message.Message):
    __slots__ = ("operation_id", "method", "identity", "current_attempt_id", "attempts")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    CURRENT_ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    method: RpcMethod
    identity: RequestIdentity
    current_attempt_id: str
    attempts: _containers.RepeatedCompositeFieldContainer[OperationAttempt]
    def __init__(self, operation_id: _Optional[str] = ..., method: _Optional[_Union[RpcMethod, str]] = ..., identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., current_attempt_id: _Optional[str] = ..., attempts: _Optional[_Iterable[_Union[OperationAttempt, _Mapping]]] = ...) -> None: ...

class ContextHealth(_message.Message):
    __slots__ = ("context_id", "context_generation", "context_binding_digest", "state", "ready", "last_observed_unix_ms", "capacity_use")
    CONTEXT_ID_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_BINDING_DIGEST_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    LAST_OBSERVED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_USE_FIELD_NUMBER: _ClassVar[int]
    context_id: str
    context_generation: str
    context_binding_digest: str
    state: ContextState
    ready: bool
    last_observed_unix_ms: int
    capacity_use: CapacityUse
    def __init__(self, context_id: _Optional[str] = ..., context_generation: _Optional[str] = ..., context_binding_digest: _Optional[str] = ..., state: _Optional[_Union[ContextState, str]] = ..., ready: _Optional[bool] = ..., last_observed_unix_ms: _Optional[int] = ..., capacity_use: _Optional[_Union[CapacityUse, _Mapping]] = ...) -> None: ...

class AttachmentHealth(_message.Message):
    __slots__ = ("execution_id", "execution_attachment_generation", "execution_attachment_digest", "driver_binding_id", "state", "last_observed_unix_ms")
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ATTACHMENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ATTACHMENT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    DRIVER_BINDING_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LAST_OBSERVED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    execution_id: str
    execution_attachment_generation: str
    execution_attachment_digest: str
    driver_binding_id: str
    state: AttachmentState
    last_observed_unix_ms: int
    def __init__(self, execution_id: _Optional[str] = ..., execution_attachment_generation: _Optional[str] = ..., execution_attachment_digest: _Optional[str] = ..., driver_binding_id: _Optional[str] = ..., state: _Optional[_Union[AttachmentState, str]] = ..., last_observed_unix_ms: _Optional[int] = ...) -> None: ...

class HandshakeRequest(_message.Message):
    __slots__ = ("identity", "requested_version", "expected_logical_driver_id", "expected_host_profile_digest", "required_capabilities")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_VERSION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LOGICAL_DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HOST_PROFILE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    requested_version: ContractVersion
    expected_logical_driver_id: str
    expected_host_profile_digest: str
    required_capabilities: _containers.RepeatedCompositeFieldContainer[CapabilityDescriptor]
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., requested_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., expected_logical_driver_id: _Optional[str] = ..., expected_host_profile_digest: _Optional[str] = ..., required_capabilities: _Optional[_Iterable[_Union[CapabilityDescriptor, _Mapping]]] = ...) -> None: ...

class HandshakeResponse(_message.Message):
    __slots__ = ("contract_version", "driver", "host_state", "capabilities", "capacity_limits", "capacity_use", "last_observed_unix_ms", "error")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    DRIVER_FIELD_NUMBER: _ClassVar[int]
    HOST_STATE_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_LIMITS_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_USE_FIELD_NUMBER: _ClassVar[int]
    LAST_OBSERVED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    driver: DriverIdentity
    host_state: HostState
    capabilities: _containers.RepeatedCompositeFieldContainer[CapabilityDescriptor]
    capacity_limits: CapacityLimits
    capacity_use: CapacityUse
    last_observed_unix_ms: int
    error: SafeError
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., driver: _Optional[_Union[DriverIdentity, _Mapping]] = ..., host_state: _Optional[_Union[HostState, str]] = ..., capabilities: _Optional[_Iterable[_Union[CapabilityDescriptor, _Mapping]]] = ..., capacity_limits: _Optional[_Union[CapacityLimits, _Mapping]] = ..., capacity_use: _Optional[_Union[CapacityUse, _Mapping]] = ..., last_observed_unix_ms: _Optional[int] = ..., error: _Optional[_Union[SafeError, _Mapping]] = ...) -> None: ...

class HealthRequest(_message.Message):
    __slots__ = ("identity",)
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ...) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("contract_version", "driver", "host_state", "ready", "capacity_limits", "capacity_use", "contexts", "attachments", "last_observed_unix_ms", "error")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    DRIVER_FIELD_NUMBER: _ClassVar[int]
    HOST_STATE_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_LIMITS_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_USE_FIELD_NUMBER: _ClassVar[int]
    CONTEXTS_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    LAST_OBSERVED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    driver: DriverIdentity
    host_state: HostState
    ready: bool
    capacity_limits: CapacityLimits
    capacity_use: CapacityUse
    contexts: _containers.RepeatedCompositeFieldContainer[ContextHealth]
    attachments: _containers.RepeatedCompositeFieldContainer[AttachmentHealth]
    last_observed_unix_ms: int
    error: SafeError
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., driver: _Optional[_Union[DriverIdentity, _Mapping]] = ..., host_state: _Optional[_Union[HostState, str]] = ..., ready: _Optional[bool] = ..., capacity_limits: _Optional[_Union[CapacityLimits, _Mapping]] = ..., capacity_use: _Optional[_Union[CapacityUse, _Mapping]] = ..., contexts: _Optional[_Iterable[_Union[ContextHealth, _Mapping]]] = ..., attachments: _Optional[_Iterable[_Union[AttachmentHealth, _Mapping]]] = ..., last_observed_unix_ms: _Optional[int] = ..., error: _Optional[_Union[SafeError, _Mapping]] = ...) -> None: ...

class OpenContextRequest(_message.Message):
    __slots__ = ("identity", "configuration")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    configuration: ContextBindingConfiguration
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., configuration: _Optional[_Union[ContextBindingConfiguration, _Mapping]] = ...) -> None: ...

class CloseContextRequest(_message.Message):
    __slots__ = ("identity", "detach_settled_attachments")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    DETACH_SETTLED_ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    detach_settled_attachments: bool
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., detach_settled_attachments: _Optional[bool] = ...) -> None: ...

class AttachExecutionRequest(_message.Message):
    __slots__ = ("identity", "configuration")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    configuration: ExecutionAttachmentConfiguration
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., configuration: _Optional[_Union[ExecutionAttachmentConfiguration, _Mapping]] = ...) -> None: ...

class DetachExecutionRequest(_message.Message):
    __slots__ = ("identity", "reason")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    reason: DetachmentReason
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., reason: _Optional[_Union[DetachmentReason, str]] = ...) -> None: ...

class CancelLifecycleOperationRequest(_message.Message):
    __slots__ = ("identity", "target_operation_id", "target_attempt_id")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    TARGET_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    target_operation_id: str
    target_attempt_id: str
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., target_operation_id: _Optional[str] = ..., target_attempt_id: _Optional[str] = ...) -> None: ...

class DrainHostRequest(_message.Message):
    __slots__ = ("identity", "grace_period_ms")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    GRACE_PERIOD_MS_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    grace_period_ms: int
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., grace_period_ms: _Optional[int] = ...) -> None: ...

class LifecycleOperationResponse(_message.Message):
    __slots__ = ("contract_version", "operation")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    operation: OperationRecord
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., operation: _Optional[_Union[OperationRecord, _Mapping]] = ...) -> None: ...

class GetOperationRequest(_message.Message):
    __slots__ = ("identity", "target_operation_id", "target_attempt_id")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    TARGET_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    identity: RequestIdentity
    target_operation_id: str
    target_attempt_id: str
    def __init__(self, identity: _Optional[_Union[RequestIdentity, _Mapping]] = ..., target_operation_id: _Optional[str] = ..., target_attempt_id: _Optional[str] = ...) -> None: ...

class GetOperationResponse(_message.Message):
    __slots__ = ("contract_version", "operation", "error")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    operation: OperationRecord
    error: SafeError
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., operation: _Optional[_Union[OperationRecord, _Mapping]] = ..., error: _Optional[_Union[SafeError, _Mapping]] = ...) -> None: ...

class ObservationRequestIdentity(_message.Message):
    __slots__ = ("contract_version", "server_profile_id", "driver_host_generation", "host_profile_digest", "context_id", "context_generation", "context_binding_digest", "observation_id", "correlation_id", "deadline_unix_ns", "credential_epoch")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SERVER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_HOST_GENERATION_FIELD_NUMBER: _ClassVar[int]
    HOST_PROFILE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_ID_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_BINDING_DIGEST_FIELD_NUMBER: _ClassVar[int]
    OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    server_profile_id: str
    driver_host_generation: str
    host_profile_digest: str
    context_id: str
    context_generation: str
    context_binding_digest: str
    observation_id: str
    correlation_id: str
    deadline_unix_ns: int
    credential_epoch: int
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., server_profile_id: _Optional[str] = ..., driver_host_generation: _Optional[str] = ..., host_profile_digest: _Optional[str] = ..., context_id: _Optional[str] = ..., context_generation: _Optional[str] = ..., context_binding_digest: _Optional[str] = ..., observation_id: _Optional[str] = ..., correlation_id: _Optional[str] = ..., deadline_unix_ns: _Optional[int] = ..., credential_epoch: _Optional[int] = ...) -> None: ...

class ObservationGeneration(_message.Message):
    __slots__ = ("server_profile_id", "driver_host_generation", "host_profile_digest", "context_id", "context_generation", "context_binding_digest")
    SERVER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_HOST_GENERATION_FIELD_NUMBER: _ClassVar[int]
    HOST_PROFILE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_ID_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_BINDING_DIGEST_FIELD_NUMBER: _ClassVar[int]
    server_profile_id: str
    driver_host_generation: str
    host_profile_digest: str
    context_id: str
    context_generation: str
    context_binding_digest: str
    def __init__(self, server_profile_id: _Optional[str] = ..., driver_host_generation: _Optional[str] = ..., host_profile_digest: _Optional[str] = ..., context_id: _Optional[str] = ..., context_generation: _Optional[str] = ..., context_binding_digest: _Optional[str] = ...) -> None: ...

class ObservationError(_message.Message):
    __slots__ = ("code", "safe_message", "retryable")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    code: ObservationResultCode
    safe_message: str
    retryable: bool
    def __init__(self, code: _Optional[_Union[ObservationResultCode, str]] = ..., safe_message: _Optional[str] = ..., retryable: _Optional[bool] = ...) -> None: ...

class ScalarValue(_message.Message):
    __slots__ = ("kind", "boolean_value", "int64_value", "uint64_value", "finite_double_value", "string_value", "bytes_value")
    KIND_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT64_VALUE_FIELD_NUMBER: _ClassVar[int]
    UINT64_VALUE_FIELD_NUMBER: _ClassVar[int]
    FINITE_DOUBLE_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_VALUE_FIELD_NUMBER: _ClassVar[int]
    kind: ScalarKind
    boolean_value: bool
    int64_value: int
    uint64_value: int
    finite_double_value: float
    string_value: str
    bytes_value: bytes
    def __init__(self, kind: _Optional[_Union[ScalarKind, str]] = ..., boolean_value: _Optional[bool] = ..., int64_value: _Optional[int] = ..., uint64_value: _Optional[int] = ..., finite_double_value: _Optional[float] = ..., string_value: _Optional[str] = ..., bytes_value: _Optional[bytes] = ...) -> None: ...

class ItemIdentity(_message.Message):
    __slots__ = ("item_id", "qualified_name", "catalog_digest")
    ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    QUALIFIED_NAME_FIELD_NUMBER: _ClassVar[int]
    CATALOG_DIGEST_FIELD_NUMBER: _ClassVar[int]
    item_id: str
    qualified_name: str
    catalog_digest: str
    def __init__(self, item_id: _Optional[str] = ..., qualified_name: _Optional[str] = ..., catalog_digest: _Optional[str] = ...) -> None: ...

class SampleIdentity(_message.Message):
    __slots__ = ("sample_id", "item_id", "source_id", "source_epoch", "source_sequence")
    SAMPLE_ID_FIELD_NUMBER: _ClassVar[int]
    ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SOURCE_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    sample_id: str
    item_id: str
    source_id: str
    source_epoch: str
    source_sequence: int
    def __init__(self, sample_id: _Optional[str] = ..., item_id: _Optional[str] = ..., source_id: _Optional[str] = ..., source_epoch: _Optional[str] = ..., source_sequence: _Optional[int] = ...) -> None: ...

class DriverTimeObservation(_message.Message):
    __slots__ = ("observation_id", "generation", "time_unix_ns", "acquired_at_unix_ns", "clock_source", "provenance", "uncertainty_ns", "quality", "validity")
    OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    TIME_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    ACQUIRED_AT_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    CLOCK_SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    UNCERTAINTY_NS_FIELD_NUMBER: _ClassVar[int]
    QUALITY_FIELD_NUMBER: _ClassVar[int]
    VALIDITY_FIELD_NUMBER: _ClassVar[int]
    observation_id: str
    generation: ObservationGeneration
    time_unix_ns: int
    acquired_at_unix_ns: int
    clock_source: ClockSource
    provenance: str
    uncertainty_ns: int
    quality: ObservationQuality
    validity: ObservationValidity
    def __init__(self, observation_id: _Optional[str] = ..., generation: _Optional[_Union[ObservationGeneration, _Mapping]] = ..., time_unix_ns: _Optional[int] = ..., acquired_at_unix_ns: _Optional[int] = ..., clock_source: _Optional[_Union[ClockSource, str]] = ..., provenance: _Optional[str] = ..., uncertainty_ns: _Optional[int] = ..., quality: _Optional[_Union[ObservationQuality, str]] = ..., validity: _Optional[_Union[ObservationValidity, str]] = ...) -> None: ...

class DriverTelemetrySample(_message.Message):
    __slots__ = ("observation_id", "generation", "sample_identity", "item_identity", "raw_value", "engineering_value", "description", "unit", "acquired_at_unix_ns", "source", "clock_provenance", "clock_uncertainty_ns", "validity", "quality", "quality_reason")
    OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    ITEM_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    RAW_VALUE_FIELD_NUMBER: _ClassVar[int]
    ENGINEERING_VALUE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    ACQUIRED_AT_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    CLOCK_PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    CLOCK_UNCERTAINTY_NS_FIELD_NUMBER: _ClassVar[int]
    VALIDITY_FIELD_NUMBER: _ClassVar[int]
    QUALITY_FIELD_NUMBER: _ClassVar[int]
    QUALITY_REASON_FIELD_NUMBER: _ClassVar[int]
    observation_id: str
    generation: ObservationGeneration
    sample_identity: SampleIdentity
    item_identity: ItemIdentity
    raw_value: ScalarValue
    engineering_value: ScalarValue
    description: str
    unit: str
    acquired_at_unix_ns: int
    source: str
    clock_provenance: str
    clock_uncertainty_ns: int
    validity: ObservationValidity
    quality: ObservationQuality
    quality_reason: str
    def __init__(self, observation_id: _Optional[str] = ..., generation: _Optional[_Union[ObservationGeneration, _Mapping]] = ..., sample_identity: _Optional[_Union[SampleIdentity, _Mapping]] = ..., item_identity: _Optional[_Union[ItemIdentity, _Mapping]] = ..., raw_value: _Optional[_Union[ScalarValue, _Mapping]] = ..., engineering_value: _Optional[_Union[ScalarValue, _Mapping]] = ..., description: _Optional[str] = ..., unit: _Optional[str] = ..., acquired_at_unix_ns: _Optional[int] = ..., source: _Optional[str] = ..., clock_provenance: _Optional[str] = ..., clock_uncertainty_ns: _Optional[int] = ..., validity: _Optional[_Union[ObservationValidity, str]] = ..., quality: _Optional[_Union[ObservationQuality, str]] = ..., quality_reason: _Optional[str] = ...) -> None: ...

class GapBounds(_message.Message):
    __slots__ = ("source_epoch", "first_available_sequence", "last_available_sequence")
    SOURCE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    FIRST_AVAILABLE_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    LAST_AVAILABLE_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    source_epoch: str
    first_available_sequence: int
    last_available_sequence: int
    def __init__(self, source_epoch: _Optional[str] = ..., first_available_sequence: _Optional[int] = ..., last_available_sequence: _Optional[int] = ...) -> None: ...

class GetTimeRequest(_message.Message):
    __slots__ = ("identity",)
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    identity: ObservationRequestIdentity
    def __init__(self, identity: _Optional[_Union[ObservationRequestIdentity, _Mapping]] = ...) -> None: ...

class GetTimeResponse(_message.Message):
    __slots__ = ("contract_version", "result_code", "observation", "error")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    RESULT_CODE_FIELD_NUMBER: _ClassVar[int]
    OBSERVATION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    result_code: ObservationResultCode
    observation: DriverTimeObservation
    error: ObservationError
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., result_code: _Optional[_Union[ObservationResultCode, str]] = ..., observation: _Optional[_Union[DriverTimeObservation, _Mapping]] = ..., error: _Optional[_Union[ObservationError, _Mapping]] = ...) -> None: ...

class GetTMRequest(_message.Message):
    __slots__ = ("identity", "item_id", "mode", "source_epoch", "after_source_sequence")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    AFTER_SOURCE_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    identity: ObservationRequestIdentity
    item_id: str
    mode: GetTMMode
    source_epoch: str
    after_source_sequence: int
    def __init__(self, identity: _Optional[_Union[ObservationRequestIdentity, _Mapping]] = ..., item_id: _Optional[str] = ..., mode: _Optional[_Union[GetTMMode, str]] = ..., source_epoch: _Optional[str] = ..., after_source_sequence: _Optional[int] = ...) -> None: ...

class GetTMResponse(_message.Message):
    __slots__ = ("contract_version", "result_code", "sample", "gap", "error")
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    RESULT_CODE_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_FIELD_NUMBER: _ClassVar[int]
    GAP_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    contract_version: ContractVersion
    result_code: ObservationResultCode
    sample: DriverTelemetrySample
    gap: GapBounds
    error: ObservationError
    def __init__(self, contract_version: _Optional[_Union[ContractVersion, _Mapping]] = ..., result_code: _Optional[_Union[ObservationResultCode, str]] = ..., sample: _Optional[_Union[DriverTelemetrySample, _Mapping]] = ..., gap: _Optional[_Union[GapBounds, _Mapping]] = ..., error: _Optional[_Union[ObservationError, _Mapping]] = ...) -> None: ...
