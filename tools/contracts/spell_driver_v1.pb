
€«
spell/driver/v1/driver.protospell.driver.v1"=
ContractVersion
major (Rmajor
minor (Rminor"∞
RequestIdentityK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion*
server_profile_id (	RserverProfileId4
driver_host_generation (	RdriverHostGeneration.
host_profile_digest (	RhostProfileDigest

context_id (	R	contextId-
context_generation (	RcontextGeneration4
context_binding_digest (	RcontextBindingDigest!
execution_id (	RexecutionIdF
execution_attachment_generation	 (	RexecutionAttachmentGeneration>
execution_attachment_digest
 (	RexecutionAttachmentDigest*
driver_binding_id (	RdriverBindingId!
operation_id (	RoperationId

attempt_id (	R	attemptId%
attempt_number (RattemptNumber%
correlation_id (	RcorrelationId(
deadline_unix_ms (RdeadlineUnixMs)
credential_epoch (RcredentialEpoch"Ä
	SafeError2
code (2.spell.driver.v1.SafeErrorCodeRcode!
safe_message (	RsafeMessage
	retryable (R	retryable"ê
CapabilityDescriptor@
service (2&.spell.driver.v1.InfrastructureServiceRservice2
method (2.spell.driver.v1.RpcMethodRmethodA
	modifiers (2#.spell.driver.v1.CapabilityModifierR	modifiers;
formats (2!.spell.driver.v1.CapabilityFormatRformats;

mutability (2.spell.driver.v1.MutabilityR
mutabilityE
stream_support (2.spell.driver.v1.StreamSupportRstreamSupport"ú
CapacityLimits1
max_contexts_per_host (RmaxContextsPerHost=
max_attachments_per_context (RmaxAttachmentsPerContextH
!max_lifecycle_operations_per_host (RmaxLifecycleOperationsPerHostN
$max_lifecycle_operations_per_context (R maxLifecycleOperationsPerContext"…
CapacityUse
contexts (Rcontexts 
attachments (Rattachments:
lifecycle_operations_host (RlifecycleOperationsHost@
lifecycle_operations_context (RlifecycleOperationsContext"∂
DriverIdentity*
logical_driver_id (	RlogicalDriverId5
implementation_version (	RimplementationVersion
	simulator (R	simulator*
server_profile_id (	RserverProfileId*
driver_profile_id (	RdriverProfileId4
driver_host_generation (	RdriverHostGeneration:
host_configuration_schema (	RhostConfigurationSchema.
host_profile_digest (	RhostProfileDigest)
credential_epoch	 (RcredentialEpoch"Ò
ContextBindingConfiguration%
schema_version (	RschemaVersion,
context_profile_id (	RcontextProfileId6
synthetic_context_label (	RsyntheticContextLabelE
expected_context_binding_digest (	RexpectedContextBindingDigest"Ç
 ExecutionAttachmentConfiguration%
schema_version (	RschemaVersion2
attachment_profile_id (	RattachmentProfileId:
synthetic_execution_label (	RsyntheticExecutionLabelO
$expected_execution_attachment_digest (	R!expectedExecutionAttachmentDigest9
reason (2!.spell.driver.v1.AttachmentReasonRreason;
replaced_driver_binding_id (	RreplacedDriverBindingId"ë
	HookTrace
sequence (Rsequence
hook_id (	RhookId;
owner_layer (2.spell.driver.v1.HookLayerR
ownerLayer3
action (2.spell.driver.v1.HookActionRaction3
result (2.spell.driver.v1.HookResultRresult!
operation_id (	RoperationId

attempt_id (	R	attemptId&
started_unix_ms (RstartedUnixMs*
completed_unix_ms	 (RcompletedUnixMs0
error
 (2.spell.driver.v1.SafeErrorRerror<
identity (2 .spell.driver.v1.RequestIdentityRidentity5
stage (2.spell.driver.v1.OperationStageRstage+
certainty_present (RcertaintyPresent>
	certainty (2 .spell.driver.v1.EffectCertaintyR	certainty"à
OperationAttempt

attempt_id (	R	attemptId%
attempt_number (RattemptNumber%
request_digest (	RrequestDigest5
stage (2.spell.driver.v1.OperationStageRstage?
effect_class (2.spell.driver.v1.EffectClassReffectClass+
certainty_present (RcertaintyPresent>
	certainty (2 .spell.driver.v1.EffectCertaintyR	certainty<
result_code (2.spell.driver.v1.ResultCodeR
resultCode0
error	 (2.spell.driver.v1.SafeErrorRerror*
requested_unix_ms
 (RrequestedUnixMs(
accepted_unix_ms (RacceptedUnixMs,
dispatched_unix_ms (RdispatchedUnixMs&
settled_unix_ms (RsettledUnixMs;
hook_traces (2.spell.driver.v1.HookTraceR
hookTraces<
identity (2 .spell.driver.v1.RequestIdentityRidentityN
attachment_reason (2!.spell.driver.v1.AttachmentReasonRattachmentReason;
replaced_driver_binding_id (	RreplacedDriverBindingId"ì
OperationRecord!
operation_id (	RoperationId2
method (2.spell.driver.v1.RpcMethodRmethod<
identity (2 .spell.driver.v1.RequestIdentityRidentity,
current_attempt_id (	RcurrentAttemptId=
attempts (2!.spell.driver.v1.OperationAttemptRattempts"“
ContextHealth

context_id (	R	contextId-
context_generation (	RcontextGeneration4
context_binding_digest (	RcontextBindingDigest3
state (2.spell.driver.v1.ContextStateRstate
ready (Rready1
last_observed_unix_ms (RlastObservedUnixMs?
capacity_use (2.spell.driver.v1.CapacityUseRcapacityUse"‘
AttachmentHealth!
execution_id (	RexecutionIdF
execution_attachment_generation (	RexecutionAttachmentGeneration>
execution_attachment_digest (	RexecutionAttachmentDigest*
driver_binding_id (	RdriverBindingId6
state (2 .spell.driver.v1.AttachmentStateRstate1
last_observed_unix_ms (RlastObservedUnixMs"˘
HandshakeRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentityM
requested_version (2 .spell.driver.v1.ContractVersionRrequestedVersion;
expected_logical_driver_id (	RexpectedLogicalDriverId?
expected_host_profile_digest (	RexpectedHostProfileDigestZ
required_capabilities (2%.spell.driver.v1.CapabilityDescriptorRrequiredCapabilities"è
HandshakeResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion7
driver (2.spell.driver.v1.DriverIdentityRdriver9

host_state (2.spell.driver.v1.HostStateR	hostStateI
capabilities (2%.spell.driver.v1.CapabilityDescriptorRcapabilitiesH
capacity_limits (2.spell.driver.v1.CapacityLimitsRcapacityLimits?
capacity_use (2.spell.driver.v1.CapacityUseRcapacityUse1
last_observed_unix_ms (RlastObservedUnixMs0
error (2.spell.driver.v1.SafeErrorRerror"M
HealthRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity"ÿ
HealthResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion7
driver (2.spell.driver.v1.DriverIdentityRdriver9

host_state (2.spell.driver.v1.HostStateR	hostState
ready (RreadyH
capacity_limits (2.spell.driver.v1.CapacityLimitsRcapacityLimits?
capacity_use (2.spell.driver.v1.CapacityUseRcapacityUse:
contexts (2.spell.driver.v1.ContextHealthRcontextsC
attachments (2!.spell.driver.v1.AttachmentHealthRattachments1
last_observed_unix_ms	 (RlastObservedUnixMs0
error
 (2.spell.driver.v1.SafeErrorRerror"¶
OpenContextRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentityR
configuration (2,.spell.driver.v1.ContextBindingConfigurationRconfiguration"ë
CloseContextRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity<
detach_settled_attachments (RdetachSettledAttachments"Ø
AttachExecutionRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentityW
configuration (21.spell.driver.v1.ExecutionAttachmentConfigurationRconfiguration"ë
DetachExecutionRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity9
reason (2!.spell.driver.v1.DetachmentReasonRreason"ª
CancelLifecycleOperationRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity.
target_operation_id (	RtargetOperationId*
target_attempt_id (	RtargetAttemptId"x
DrainHostRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity&
grace_period_ms (RgracePeriodMs"©
LifecycleOperationResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion>
	operation (2 .spell.driver.v1.OperationRecordR	operation"Ø
GetOperationRequest<
identity (2 .spell.driver.v1.RequestIdentityRidentity.
target_operation_id (	RtargetOperationId*
target_attempt_id (	RtargetAttemptId"’
GetOperationResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion>
	operation (2 .spell.driver.v1.OperationRecordR	operation0
error (2.spell.driver.v1.SafeErrorRerror"¢
ObservationRequestIdentityK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersion*
server_profile_id (	RserverProfileId4
driver_host_generation (	RdriverHostGeneration.
host_profile_digest (	RhostProfileDigest

context_id (	R	contextId-
context_generation (	RcontextGeneration4
context_binding_digest (	RcontextBindingDigest%
observation_id (	RobservationId%
correlation_id	 (	RcorrelationId(
deadline_unix_ns
 (RdeadlineUnixNs)
credential_epoch (RcredentialEpoch"≠
ObservationGeneration*
server_profile_id (	RserverProfileId4
driver_host_generation (	RdriverHostGeneration.
host_profile_digest (	RhostProfileDigest

context_id (	R	contextId-
context_generation (	RcontextGeneration4
context_binding_digest (	RcontextBindingDigest"è
ObservationError:
code (2&.spell.driver.v1.ObservationResultCodeRcode!
safe_message (	RsafeMessage
	retryable (R	retryable"∂
ScalarValue/
kind (2.spell.driver.v1.ScalarKindRkind%
boolean_value (H RbooleanValue!
int64_value (H R
int64Value#
uint64_value (H Ruint64Value0
finite_double_value (H RfiniteDoubleValue#
string_value (	H RstringValue!
bytes_value (H R
bytesValueB
typed_value"u
ItemIdentity
item_id (	RitemId%
qualified_name (	RqualifiedName%
catalog_digest (	RcatalogDigest"Ø
SampleIdentity
	sample_id (	RsampleId
item_id (	RitemId
	source_id (	RsourceId!
source_epoch (	RsourceEpoch'
source_sequence (RsourceSequence"‡
DriverTimeObservation%
observation_id (	RobservationIdF

generation (2&.spell.driver.v1.ObservationGenerationR
generation 
time_unix_ns (R
timeUnixNs-
acquired_at_unix_ns (RacquiredAtUnixNs?
clock_source (2.spell.driver.v1.ClockSourceRclockSource

provenance (	R
provenance%
uncertainty_ns (RuncertaintyNs=
quality (2#.spell.driver.v1.ObservationQualityRquality@
validity	 (2$.spell.driver.v1.ObservationValidityRvalidity"ú
DriverTelemetrySample%
observation_id (	RobservationIdF

generation (2&.spell.driver.v1.ObservationGenerationR
generationH
sample_identity (2.spell.driver.v1.SampleIdentityRsampleIdentityB
item_identity (2.spell.driver.v1.ItemIdentityRitemIdentity9
	raw_value (2.spell.driver.v1.ScalarValueRrawValueI
engineering_value (2.spell.driver.v1.ScalarValueRengineeringValue 
description (	Rdescription
unit (	Runit-
acquired_at_unix_ns	 (RacquiredAtUnixNs
source
 (	Rsource)
clock_provenance (	RclockProvenance0
clock_uncertainty_ns (RclockUncertaintyNs@
validity (2$.spell.driver.v1.ObservationValidityRvalidity=
quality (2#.spell.driver.v1.ObservationQualityRquality%
quality_reason (	RqualityReason"†
	GapBounds!
source_epoch (	RsourceEpoch8
first_available_sequence (RfirstAvailableSequence6
last_available_sequence (RlastAvailableSequence"Y
GetTimeRequestG
identity (2+.spell.driver.v1.ObservationRequestIdentityRidentity"™
GetTimeResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersionG
result_code (2&.spell.driver.v1.ObservationResultCodeR
resultCodeH
observation (2&.spell.driver.v1.DriverTimeObservationRobservation7
error (2!.spell.driver.v1.ObservationErrorRerror"˜
GetTMRequestG
identity (2+.spell.driver.v1.ObservationRequestIdentityRidentity
item_id (	RitemId.
mode (2.spell.driver.v1.GetTMModeRmode!
source_epoch (	RsourceEpoch2
after_source_sequence (RafterSourceSequence"Ã
GetTMResponseK
contract_version (2 .spell.driver.v1.ContractVersionRcontractVersionG
result_code (2&.spell.driver.v1.ObservationResultCodeR
resultCode>
sample (2&.spell.driver.v1.DriverTelemetrySampleRsample,
gap (2.spell.driver.v1.GapBoundsRgap7
error (2!.spell.driver.v1.ObservationErrorRerror*π
	RpcMethod
RPC_METHOD_UNSPECIFIED 
RPC_METHOD_HANDSHAKE
RPC_METHOD_HEALTH
RPC_METHOD_OPEN_CONTEXT
RPC_METHOD_CLOSE_CONTEXT
RPC_METHOD_ATTACH_EXECUTION
RPC_METHOD_DETACH_EXECUTION)
%RPC_METHOD_CANCEL_LIFECYCLE_OPERATION
RPC_METHOD_DRAIN_HOST
RPC_METHOD_GET_OPERATION	*Û
InfrastructureService&
"INFRASTRUCTURE_SERVICE_UNSPECIFIED 
INFRASTRUCTURE_SERVICE_HOST,
(INFRASTRUCTURE_SERVICE_CONTEXT_LIFECYCLE.
*INFRASTRUCTURE_SERVICE_EXECUTION_LIFECYCLE3
/INFRASTRUCTURE_SERVICE_OPERATION_RECONCILIATION*º
CapabilityModifier#
CAPABILITY_MODIFIER_UNSPECIFIED 
CAPABILITY_MODIFIER_NONE0
,CAPABILITY_MODIFIER_COOPERATIVE_CANCELLATION1
-CAPABILITY_MODIFIER_DETERMINISTIC_FAULT_POINT*\
CapabilityFormat!
CAPABILITY_FORMAT_UNSPECIFIED %
!CAPABILITY_FORMAT_PROTOBUF_BINARY*\

Mutability
MUTABILITY_UNSPECIFIED 
MUTABILITY_READ_ONLY
MUTABILITY_LIFECYCLE*H
StreamSupport
STREAM_SUPPORT_UNSPECIFIED 
STREAM_SUPPORT_NONE*∂
	HostState
HOST_STATE_UNSPECIFIED 
HOST_STATE_STARTING
HOST_STATE_READY
HOST_STATE_DEGRADED
HOST_STATE_DRAINING
HOST_STATE_CLOSED
HOST_STATE_FAILED*Õ
ContextState
CONTEXT_STATE_UNSPECIFIED 
CONTEXT_STATE_OPENING
CONTEXT_STATE_ACTIVE
CONTEXT_STATE_DEGRADED
CONTEXT_STATE_CLOSING
CONTEXT_STATE_CLOSED
CONTEXT_STATE_FAILED*Œ
AttachmentState 
ATTACHMENT_STATE_UNSPECIFIED 
ATTACHMENT_STATE_ATTACHING
ATTACHMENT_STATE_ATTACHED
ATTACHMENT_STATE_DETACHING
ATTACHMENT_STATE_DETACHED
ATTACHMENT_STATE_FAILED*Ã
OperationStage
OPERATION_STAGE_UNSPECIFIED 
OPERATION_STAGE_REQUESTED
OPERATION_STAGE_ACCEPTED
OPERATION_STAGE_DISPATCHED
OPERATION_STAGE_RECONCILING
OPERATION_STAGE_SETTLED*á
EffectClass
EFFECT_CLASS_UNSPECIFIED 
EFFECT_CLASS_NONE
EFFECT_CLASS_CONTEXT_OPEN
EFFECT_CLASS_CONTEXT_CLOSE!
EFFECT_CLASS_EXECUTION_ATTACH!
EFFECT_CLASS_EXECUTION_DETACH!
EFFECT_CLASS_LIFECYCLE_CANCEL
EFFECT_CLASS_HOST_DRAIN*∞
EffectCertainty 
EFFECT_CERTAINTY_UNSPECIFIED 
EFFECT_CERTAINTY_NO_EFFECT
EFFECT_CERTAINTY_CONFIRMED
EFFECT_CERTAINTY_POSSIBLE
EFFECT_CERTAINTY_UNKNOWN*Á

ResultCode
RESULT_CODE_UNSPECIFIED 
RESULT_CODE_OK 
RESULT_CODE_INVALID_ARGUMENT
RESULT_CODE_UNAUTHENTICATED!
RESULT_CODE_PERMISSION_DENIED
RESULT_CODE_UNSUPPORTED
RESULT_CODE_CONFLICT"
RESULT_CODE_CAPACITY_EXHAUSTED!
RESULT_CODE_DEADLINE_EXCEEDED
RESULT_CODE_CANCELLED	
RESULT_CODE_ALREADY_SETTLED
 
RESULT_CODE_STALE_GENERATION#
RESULT_CODE_JOURNAL_UNAVAILABLE'
#RESULT_CODE_RECONCILIATION_REQUIRED
RESULT_CODE_INTERNAL*Ù
SafeErrorCode
SAFE_ERROR_CODE_UNSPECIFIED 
SAFE_ERROR_CODE_NONE
SAFE_ERROR_CODE_VALIDATION$
 SAFE_ERROR_CODE_VERSION_MISMATCH%
!SAFE_ERROR_CODE_IDENTITY_MISMATCH'
#SAFE_ERROR_CODE_GENERATION_MISMATCH#
SAFE_ERROR_CODE_DIGEST_MISMATCH
SAFE_ERROR_CODE_UNSUPPORTED
SAFE_ERROR_CODE_CAPACITY
SAFE_ERROR_CODE_DEADLINE	
SAFE_ERROR_CODE_CANCELLED

SAFE_ERROR_CODE_CONFLICT
SAFE_ERROR_CODE_JOURNAL
SAFE_ERROR_CODE_HOOK
SAFE_ERROR_CODE_INTERNAL*Œ
	HookLayer
HOOK_LAYER_UNSPECIFIED $
 HOOK_LAYER_CONTEXT_CONFIGURATION
HOOK_LAYER_CONTEXT_FIXTURE'
#HOOK_LAYER_ATTACHMENT_CONFIGURATION!
HOOK_LAYER_ATTACHMENT_FIXTURE
HOOK_LAYER_HOST*u

HookAction
HOOK_ACTION_UNSPECIFIED 
HOOK_ACTION_SETUP
HOOK_ACTION_CLEANUP
HOOK_ACTION_COMPENSATE*ê

HookResult
HOOK_RESULT_UNSPECIFIED 
HOOK_RESULT_COMPLETED
HOOK_RESULT_FAILED
HOOK_RESULT_CANCELLED
HOOK_RESULT_SKIPPED*w
AttachmentReason!
ATTACHMENT_REASON_UNSPECIFIED "
ATTACHMENT_REASON_INITIAL_LOAD
ATTACHMENT_REASON_RELOAD*Ä
DetachmentReason!
DETACHMENT_REASON_UNSPECIFIED 
DETACHMENT_REASON_FINISHED
DETACHMENT_REASON_ABORTED
DETACHMENT_REASON_RELOAD%
!DETACHMENT_REASON_EXPLICIT_UNLOAD#
DETACHMENT_REASON_CONTEXT_CLOSE 
DETACHMENT_REASON_HOST_DRAIN*Ÿ
ObservationResultCode'
#OBSERVATION_RESULT_CODE_UNSPECIFIED 
OBSERVATION_RESULT_CODE_OK%
!OBSERVATION_RESULT_CODE_NOT_FOUND)
%OBSERVATION_RESULT_CODE_NOT_AVAILABLE-
)OBSERVATION_RESULT_CODE_DEADLINE_EXCEEDED%
!OBSERVATION_RESULT_CODE_CANCELLED
OBSERVATION_RESULT_CODE_GAP,
(OBSERVATION_RESULT_CODE_STALE_GENERATION+
'OBSERVATION_RESULT_CODE_CLOCK_UNCERTAIN-
)OBSERVATION_RESULT_CODE_CONTRACT_MISMATCH	$
 OBSERVATION_RESULT_CODE_INTERNAL
*å
ClockSource
CLOCK_SOURCE_UNSPECIFIED #
CLOCK_SOURCE_SIMULATOR_GCS_TIME
CLOCK_SOURCE_SIMULATOR
CLOCK_SOURCE_HOST_FALLBACK*ü
ObservationValidity$
 OBSERVATION_VALIDITY_UNSPECIFIED 
OBSERVATION_VALIDITY_VALID 
OBSERVATION_VALIDITY_INVALID 
OBSERVATION_VALIDITY_UNKNOWN*∂
ObservationQuality#
OBSERVATION_QUALITY_UNSPECIFIED 
OBSERVATION_QUALITY_GOOD
OBSERVATION_QUALITY_SUSPECT
OBSERVATION_QUALITY_BAD
OBSERVATION_QUALITY_UNKNOWN*ø

ScalarKind
SCALAR_KIND_UNSPECIFIED 
SCALAR_KIND_BOOLEAN
SCALAR_KIND_INT64
SCALAR_KIND_UINT64
SCALAR_KIND_FINITE_DOUBLE
SCALAR_KIND_STRING
SCALAR_KIND_BYTES*W
	GetTMMode
GET_TM_MODE_UNSPECIFIED 
GET_TM_MODE_CURRENT
GET_TM_MODE_NEXT2á
DriverInfrastructureServiceR
	Handshake!.spell.driver.v1.HandshakeRequest".spell.driver.v1.HandshakeResponseI
Health.spell.driver.v1.HealthRequest.spell.driver.v1.HealthResponse_
OpenContext#.spell.driver.v1.OpenContextRequest+.spell.driver.v1.LifecycleOperationResponsea
CloseContext$.spell.driver.v1.CloseContextRequest+.spell.driver.v1.LifecycleOperationResponseg
AttachExecution'.spell.driver.v1.AttachExecutionRequest+.spell.driver.v1.LifecycleOperationResponseg
DetachExecution'.spell.driver.v1.DetachExecutionRequest+.spell.driver.v1.LifecycleOperationResponsey
CancelLifecycleOperation0.spell.driver.v1.CancelLifecycleOperationRequest+.spell.driver.v1.LifecycleOperationResponse[
	DrainHost!.spell.driver.v1.DrainHostRequest+.spell.driver.v1.LifecycleOperationResponse[
GetOperation$.spell.driver.v1.GetOperationRequest%.spell.driver.v1.GetOperationResponse2∞
DriverObservationServiceL
GetTime.spell.driver.v1.GetTimeRequest .spell.driver.v1.GetTimeResponseF
GetTM.spell.driver.v1.GetTMRequest.spell.driver.v1.GetTMResponseJˇ±
  ÿ

  

 
ß
  ö The legacy infrastructure lifecycle service retains exactly its original nine
 unary RPCs. The separate read-only observation service below is additive.



 #

  >

  

   

  +<

 5

 

 

 %3

 	K

 	

 	$

 	/I

 
M

 


 
&

 
1K

 S

 

 ,

 7Q

 S

 

 ,

 7Q

 e

 

 >

 Ic

 G

 

  

 +E

 G

 

 &

 1E
¨
 ü The observation service is additive. It does not create lifecycle operations,
 consume lifecycle capacity, or alter the legacy infrastructure capability set.



 

 8

 

 

 '6

2





#0


  $


 

  

  

  

 

 

 

 

 

 

 

 

 

 

 

 

 "

 

  !

  "

  

   !

 !,

 !'

 !*+

 "

 "

 "

 	#

 	#

 	#


& ,


&

 ')

 '$

 ''(

("

(

( !

)/

)*

)-.

*1

*,

*/0

+6

+1

+45


. 3


.

 /&

 /!

 /$%

0

0

0

13

1.

112

24

2/

223


5 8


5

 6$

 6

 6"#

7(

7#

7&'


: >


:

 ;

 ;

 ;

<

<

<

=

=

=


@ C


@

 A!

 A

 A 

B

B

B


E M


E

 F

 F

 F

G

G

G

H

H

H

I

I

I

J

J

J

K

K

K

L

L

L


O W


O

 P 

 P

 P

Q

Q

Q

R

R

R

S

S

S

T

T

T

U

U

U

V

V

V


Y `


Y

 Z#

 Z

 Z!"

[!

[

[ 

\ 

\

\

]!

]

] 

^ 

^

^

_

_

_


	b i


	b

	 c"

	 c

	 c !

	d 

	d

	d

	e

	e

	e

	f!

	f

	f 

	g"

	g

	g !

	h

	h

	h



k t



k


 l


 l


 l


m


m


m


n 


n


n


o!


o


o 


p$


p


p"#


q$


q


q"#


r$


r


r"#


s


s


s


v |


v

 w#

 w

 w!"

x!

x

x 

y!

y

y 

z 

z

z

{

{

{

~ é


~

 

 

 

Ä

Ä

Ä

Å#

Å

Å!"

Ç"

Ç

Ç !

É$

É

É"#

Ñ

Ñ

Ñ

Ö

Ö

Ö

Ü%

Ü 

Ü#$

á$

á

á"#

	à

	à

	à


â#


â


â "

ä$

ä

ä!#

ã'

ã!

ã$&

å+

å%

å(*

ç

ç

ç

ê †

ê

 ë"

 ë

 ë !

í

í

í

ì!

ì

ì 

î'

î"

î%&

ï(

ï#

ï&'

ñ*

ñ%

ñ()

ó&

ó!

ó$%

ò"

ò

ò !

ô

ô

ô

	ö

	ö

	ö


õ!


õ


õ 

ú 

ú

ú

ù

ù

ù

û

û

û

ü 

ü

ü

¢ ©

¢

 £

 £

 £

§'

§"

§%&

•!

•

• 

¶*

¶%

¶()

ß$

ß

ß"#

®

®

®

´ ∞

´

 ¨

 ¨

 ¨

≠

≠

≠

Æ

Æ

Æ

Ø

Ø

Ø

≤ ∏

≤

 ≥

 ≥

 ≥

¥

¥

¥

µ

µ

µ

∂

∂

∂

∑

∑

∑

∫ æ

∫

 ª$

 ª

 ª"#

º%

º 

º#$

Ω

Ω

Ω

¿ »

¿

 ¡$

 ¡

 ¡"#

¬!

¬

¬ 

√ 

√

√

ƒ

ƒ

ƒ

≈(

≈#

≈&'

∆&

∆!

∆$%

«#

«

«!"

   Õ

  

  À

  À

  À	

  À

 Ã

 Ã

 Ã	

 Ã

œ ·

œ

 –'

 –

 –"

 –%&

—

—

—	

—

“$

“

“	

“"#

”!

”

”	

” 

‘

‘

‘	

‘

’ 

’

’	

’

÷$

÷

÷	

÷"#

◊

◊

◊	

◊

ÿ-

ÿ

ÿ	(

ÿ+,

	Ÿ*

	Ÿ

	Ÿ	$

	Ÿ')


⁄ 


⁄


⁄	


⁄

€

€

€	

€

‹

‹

‹	

‹

›

›

›	

›

ﬁ

ﬁ

ﬁ	

ﬁ

ﬂ

ﬂ

ﬂ

ﬂ

‡

‡

‡	

‡

„ Á

„

 ‰

 ‰

 ‰

 ‰

Â

Â

Â	

Â

Ê

Ê

Ê

Ê

È 

È

 Í$

 Í

 Í

 Í"#

Î

Î

Î

Î

Ï,

Ï


Ï

Ï'

Ï*+

Ì(

Ì


Ì

Ì#

Ì&'

Ó

Ó

Ó

Ó

Ô#

Ô

Ô

Ô!"

Ú ˜

Ú

 Û#

 Û

 Û	

 Û!"

Ù)

Ù

Ù	$

Ù'(

ı/

ı

ı	*

ı-.

ˆ2

ˆ

ˆ	-

ˆ01

˘ ˛

˘

 ˙

 ˙

 ˙	

 ˙

˚

˚

˚	

˚

¸'

¸

¸	"

¸%&

˝*

˝

˝	%

˝()

Ä ä

Ä

 Å

 Å

 Å	

 Å

Ç$

Ç

Ç	

Ç"#

É

É

É

É

Ñ

Ñ

Ñ	

Ñ

Ö

Ö

Ö	

Ö

Ü$

Ü

Ü	

Ü"#

á'

á

á	"

á%&

à!

à

à	

à 

â

â

â	

â

å ë

å#

 ç

 ç

 ç	

 ç

é 

é

é	

é

è%

è

è	 

è#$

ê-

ê

ê	(

ê+,

ì ö

ì(

 î

 î

 î	

 î

ï#

ï

ï	

ï!"

ñ'

ñ

ñ	"

ñ%&

ó2

ó

ó	-

ó01

ò

ò

ò

ò

ô(

ô

ô	#

ô&'

	ú ´

	ú

	 ù

	 ù

	 ù	

	 ù

	û

	û

	û	

	û

	ü

	ü

	ü

	ü

	†

	†

	†

	†

	°

	°

	°

	°

	¢

	¢

	¢	

	¢

	£

	£

	£	

	£

	§

	§

	§

	§

	•

	•

	•

	•

		¶

		¶

		¶

		¶

	
ß 

	
ß

	
ß

	
ß

	®

	®

	®

	®

	©

	©

	©

	©

	™!

	™

	™

	™ 


≠ ø


≠


 Æ


 Æ


 Æ	


 Æ


Ø


Ø


Ø	


Ø


∞


∞


∞	


∞


±


±


±


±


≤


≤


≤


≤


≥


≥


≥


≥


¥ 


¥


¥


¥


µ


µ


µ


µ


∂


∂


∂


∂


	∑


	∑


	∑


	∑



∏



∏



∏



∏


π 


π


π


π


∫


∫


∫


∫


ª&


ª



ª


ª 


ª#%


º 


º


º


º


Ω*


Ω


Ω$


Ω')


æ)


æ


æ	#


æ&(

¡ «

¡

 ¬

 ¬

 ¬	

 ¬

√

√

√

√

ƒ

ƒ

ƒ

ƒ

≈ 

≈

≈	

≈

∆)

∆


∆

∆$

∆'(

… —

…

  

  

  	

  

À 

À

À	

À

Ã$

Ã

Ã	

Ã"#

Õ

Õ

Õ

Õ

Œ

Œ

Œ

Œ

œ"

œ

œ

œ !

–

–

–

–

” ⁄

”

 ‘

 ‘

 ‘	

 ‘

’-

’

’	(

’+,

÷)

÷

÷	$

÷'(

◊

◊

◊	

◊

ÿ

ÿ

ÿ

ÿ

Ÿ"

Ÿ

Ÿ

Ÿ !

‹ ‚

‹

 ›

 ›

 ›

 ›

ﬁ(

ﬁ

ﬁ#

ﬁ&'

ﬂ(

ﬂ

ﬂ	#

ﬂ&'

‡*

‡

‡	%

‡()

·:

·


·

· 5

·89

‰ Ì

‰

 Â'

 Â

 Â"

 Â%&

Ê

Ê

Ê

Ê

Á

Á

Á

Á

Ë1

Ë


Ë

Ë ,

Ë/0

È%

È

È 

È#$

Í

Í

Í

Í

Î"

Î

Î

Î !

Ï

Ï

Ï

Ï

Ô Ò

Ô

 

 

 

 

Û ˛

Û

 Ù'

 Ù

 Ù"

 Ù%&

ı

ı

ı

ı

ˆ

ˆ

ˆ

ˆ

˜

˜

˜

˜

¯%

¯

¯ 

¯#$

˘

˘

˘

˘

˙&

˙


˙

˙!

˙$%

˚,

˚


˚

˚'

˚*+

¸"

¸

¸

¸ !

	˝

	˝

	˝

	˝

Ä É

Ä

 Å

 Å

 Å

 Å

Ç0

Ç

Ç+

Ç./

Ö à

Ö

 Ü

 Ü

 Ü

 Ü

á&

á

á!

á$%

ä ç

ä

 ã

 ã

 ã

 ã

å5

å"

å#0

å34

è í

è

 ê

 ê

 ê

 ê

ë

ë

ë

ë

î ò

î'

 ï

 ï

 ï

 ï

ñ!

ñ

ñ	

ñ 

ó

ó

ó	

ó

ö ù

ö

 õ

 õ

 õ

 õ

ú

ú

ú	

ú

ü ¢

ü"

 †'

 †

 †"

 †%&

° 

°

°

°

§ ®

§

 •

 •

 •

 •

¶!

¶

¶	

¶ 

ß

ß

ß	

ß

™ Æ

™

 ´'

 ´

 ´"

 ´%&

¨ 

¨

¨

¨

≠

≠

≠

≠

∞ º

∞

 ±*

 ±%

 ±()

≤!

≤

≤ 

≥(

≥#

≥&'

¥,

¥'

¥*+

µ0

µ+

µ./

∂(

∂#

∂&'

∑"

∑

∑ !

∏/

∏*

∏-.

π.

π)

π,-

	∫0

	∫+

	∫./


ª(


ª"


ª%'

æ √

æ

 ø

 ø

 ø

¿&

¿!

¿$%

¡

¡

¡

¬!

¬

¬ 

≈  

≈

 ∆'

 ∆"

 ∆%&

«!

«

« 

»#

»

»!"

…#

…

…!"

Ã “

Ã

 Õ&

 Õ!

 Õ$%

Œ

Œ

Œ

œ"

œ

œ !

–

–

–

—"

—

— !

‘ ‹

‘

 ’

 ’

 ’

÷

÷

÷

◊

◊

◊

ÿ

ÿ

ÿ

Ÿ 

Ÿ

Ÿ

⁄

⁄

⁄

€

€

€

ﬁ ‚

ﬁ

 ﬂ

 ﬂ

 ﬂ

‡

‡

‡

·

·

·

‰ 

‰"

 Â'

 Â

 Â"

 Â%&

Ê

Ê

Ê	

Ê

Á$

Á

Á	

Á"#

Ë!

Ë

Ë	

Ë 

È

È

È	

È

Í 

Í

Í	

Í

Î$

Î

Î	

Î"#

Ï

Ï

Ï	

Ï

Ì

Ì

Ì	

Ì

	Ó

	Ó

	Ó

	Ó


Ô


Ô


Ô	


Ô

Ú ˘

Ú

 Û

 Û

 Û	

 Û

Ù$

Ù

Ù	

Ù"#

ı!

ı

ı	

ı 

ˆ

ˆ

ˆ	

ˆ

˜ 

˜

˜	

˜

¯$

¯

¯	

¯"#

˚ ˇ

˚

 ¸!

 ¸

 ¸

 ¸ 

˝

˝

˝	

˝

˛

˛

˛

˛

Å ã

Å

 Ç

 Ç

 Ç

 Ç

 Éä

 É

Ñ

Ñ

Ñ	

Ñ

Ö

Ö


Ö

Ö

Ü

Ü


Ü

Ü

á#

á


á

á!"

à

à


à

à

â

â	

â


â

ç ë

ç

 é

 é

 é	

 é

è

è

è	

è

ê

ê

ê	

ê

 ì ô

 ì

  î

  î

  î	

  î

 ï

 ï

 ï	

 ï

 ñ

 ñ

 ñ	

 ñ

 ó

 ó

 ó	

 ó

 ò

 ò

 ò	

 ò

!õ •

!õ

! ú

! ú

! ú	

! ú

!ù'

!ù

!ù"

!ù%&

!û

!û

!û

!û

!ü 

!ü

!ü

!ü

!†

!†

!†

!†

!°

!°

!°	

!°

!¢

!¢

!¢	

!¢

!£!

!£

!£

!£ 

!§#

!§

!§

!§!"

"ß ∑

"ß

" ®

" ®

" ®	

" ®

"©'

"©

"©"

"©%&

"™%

"™

"™ 

"™#$

"´!

"´

"´

"´ 

"¨

"¨

"¨

"¨

"≠$

"≠

"≠

"≠"#

"Æ

"Æ

"Æ	

"Æ

"Ø

"Ø

"Ø	

"Ø

"∞ 

"∞

"∞

"∞

"	±

"	±

"	±	

"	±

"
≤

"
≤

"
≤	

"
≤

"≥#

"≥

"≥	

"≥ "

"¥$

"¥

"¥

"¥!#

"µ"

"µ

"µ

"µ!

"∂

"∂

"∂	

"∂

#π Ω

#π

# ∫

# ∫

# ∫	

# ∫

#ª&

#ª

#ª	!

#ª$%

#º%

#º

#º	 

#º#$

$ø ¡

$ø

$ ¿*

$ ¿

$ ¿%

$ ¿()

%√ »

%√

% ƒ'

% ƒ

% ƒ"

% ƒ%&

%≈(

%≈

%≈#

%≈&'

%∆(

%∆

%∆#

%∆&'

%«

%«

%«

%«

&  –

& 

& À*

& À

& À%

& À()

&Ã

&Ã

&Ã	

&Ã

&Õ

&Õ

&Õ

&Õ

&Œ

&Œ

&Œ	

&Œ

&œ#

&œ

&œ	

&œ!"

'“ ÿ

'“

' ”'

' ”

' ”"

' ”%&

'‘(

'‘

'‘#

'‘&'

'’#

'’

'’

'’!"

'÷

'÷

'÷

'÷

'◊

'◊

'◊

'◊bproto3