//! Transport-neutral values for Daimon's native execution contract.
//!
//! Session handles and correlation identifiers carry no authority. A service
//! binds each session to separately authenticated host facts.

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn new(value: [u8; 16]) -> Self {
                Self(value)
            }

            pub const fn into_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

id!(ExecutionIdV1);
id!(PrincipalIdV1);
id!(HarnessProfileIdV1);
id!(ContextReferenceIdV1);
id!(ToolCapabilityIdV1);
id!(IdempotencyKeyV1);
id!(ArtifactReferenceIdV1);
id!(ProviderProfileIdV1);
id!(AgentSessionIdV1);
id!(AgentTurnIdV1);
id!(AgentPermissionRequestIdV1);
id!(AgentPermissionOptionIdV1);

pub mod agent;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigestV1([u8; 32]);

impl ContentDigestV1 {
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for ContentDigestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ContentDigestV1(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionHandleV1(pub u64);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TaskAttemptRefV1 {
    pub task_key: [u8; 16],
    pub task_incarnation: u64,
    pub attempt_number: u32,
}

impl std::fmt::Debug for TaskAttemptRefV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TaskAttemptRefV1(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudgetV1 {
    pub max_elapsed_millis: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
    pub max_context_bytes: usize,
    pub max_output_bytes: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecuteRequestV1 {
    pub execution_id: ExecutionIdV1,
    pub task_attempt: TaskAttemptRefV1,
    pub principal: PrincipalIdV1,
    pub profile: HarnessProfileIdV1,
    pub idempotency_key: IdempotencyKeyV1,
    pub context: Vec<ContextReferenceIdV1>,
    pub tools: Vec<ToolCapabilityIdV1>,
    pub budget: ExecutionBudgetV1,
}

impl std::fmt::Debug for ExecuteRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecuteRequestV1")
            .field("execution_id", &self.execution_id)
            .field("task_attempt", &self.task_attempt)
            .field("principal", &self.principal)
            .field("profile", &self.profile)
            .field("context_count", &self.context.len())
            .field("tool_count", &self.tools.len())
            .field("budget", &self.budget)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionDispositionV1 {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResultV1 {
    pub execution_id: ExecutionIdV1,
    pub disposition: ExecutionDispositionV1,
    pub produced_artifacts: Vec<ArtifactReferenceIdV1>,
    pub output_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWireProfileV1 {
    OpenAiChatCompletions,
}

/// Credential-free provider selection frozen before external dispatch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderProfileSnapshotV1 {
    pub provider: ProviderProfileIdV1,
    pub harness_profile: HarnessProfileIdV1,
    pub wire: ProviderWireProfileV1,
    pub model: Vec<u8>,
    pub structured_tools: bool,
    pub document_digest: ContentDigestV1,
}

impl std::fmt::Debug for ProviderProfileSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderProfileSnapshotV1")
            .field("provider", &self.provider)
            .field("harness_profile", &self.harness_profile)
            .field("wire", &self.wire)
            .field("model_bytes", &self.model.len())
            .field("structured_tools", &self.structured_tools)
            .field("document_digest", &self.document_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextKindV1 {
    AgoraMessage,
    ChronosWork,
    VellumDocument,
    DendriteGrounding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroundingDepthV1 {
    Ambient,
    Activated,
    Reference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroundingEvidenceV1 {
    pub depth: GroundingDepthV1,
    pub grounding_digest: ContentDigestV1,
    pub surface_digest: ContentDigestV1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContextEvidenceV1 {
    pub reference: ContextReferenceIdV1,
    pub kind: ContextKindV1,
    pub bytes: Vec<u8>,
    pub source_digest: ContentDigestV1,
    pub grounding: Option<GroundingEvidenceV1>,
}

impl std::fmt::Debug for ContextEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContextEvidenceV1")
            .field("reference", &self.reference)
            .field("kind", &self.kind)
            .field("bytes", &self.bytes.len())
            .field("source_digest", &self.source_digest)
            .field("grounding", &self.grounding)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRoleV1 {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelMessageV1 {
    pub role: MessageRoleV1,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelToolResultV1 {
    pub request: [u8; 16],
    pub capability: ToolCapabilityIdV1,
    pub provider_correlation: Vec<u8>,
    pub arguments: Vec<u8>,
    pub evidence_digest: ContentDigestV1,
    pub output_digest: ContentDigestV1,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelContinuationV1 {
    pub source_execution: ExecutionIdV1,
    pub source_output: Vec<u8>,
    pub results: Vec<ModelToolResultV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationV1 {
    pub execution_id: ExecutionIdV1,
    pub provider: ProviderProfileSnapshotV1,
    pub context: Vec<ContextEvidenceV1>,
    pub messages: Vec<ModelMessageV1>,
    pub tools: Vec<ToolCapabilityIdV1>,
    pub continuation: Option<ModelContinuationV1>,
    pub estimated_input_tokens: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgoraMessageProposalV1 {
    pub room: [u8; 16],
    pub reply_to: [u8; 16],
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VellumEditProposalV1 {
    pub workspace: [u8; 16],
    pub document: [u8; 16],
    pub expected_revision: u64,
    pub replacement: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallProposalV1 {
    pub request: [u8; 16],
    pub capability: ToolCapabilityIdV1,
    /// Opaque provider-native correlation needed to submit the matching tool result.
    pub provider_correlation: Vec<u8>,
    pub arguments: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputProposalV1 {
    AgoraMessage(AgoraMessageProposalV1),
    VellumEdit(VellumEditProposalV1),
    ToolCall(ToolCallProposalV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProviderReceiptV1 {
    pub execution_id: ExecutionIdV1,
    pub provider_document_digest: ContentDigestV1,
    pub evidence_digest: ContentDigestV1,
    pub disposition: ExecutionDispositionV1,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub output: Vec<u8>,
    pub proposals: Vec<OutputProposalV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelExecutionResultV1 {
    pub execution_id: ExecutionIdV1,
    pub disposition: ExecutionDispositionV1,
    pub evidence_digest: ContentDigestV1,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub output: Vec<u8>,
    pub proposals: Vec<OutputProposalV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeToolResultV1 {
    pub request: [u8; 16],
    pub evidence_digest: ContentDigestV1,
    pub output_digest: ContentDigestV1,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelCommandV1 {
    Execute {
        request: ExecuteRequestV1,
        now: u64,
    },
    Resume {
        request: ExecuteRequestV1,
        source_execution: ExecutionIdV1,
        results: Vec<ResumeToolResultV1>,
        now: u64,
    },
    Inspect {
        execution_id: ExecutionIdV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelOutcomeV1 {
    Executed(ModelExecutionResultV1),
    OutcomeUnknown {
        execution_id: ExecutionIdV1,
    },
    Status {
        execution_id: ExecutionIdV1,
        phase: ExecutionPhaseV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelReplyV1 {
    Accepted(ModelOutcomeV1),
    Refused(RefusalV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPhaseV1 {
    OutcomeUnknown,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandV1 {
    ReadPresence { limit: u8 },
    Execute { request: ExecuteRequestV1, now: u64 },
    Inspect { execution_id: ExecutionIdV1 },
}

pub const MAX_PRESENCE_ENTRIES: u8 = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PresenceEntryV1 {
    pub agent: [u8; 16],
    pub age_millis: u64,
    pub stale: bool,
}

impl std::fmt::Debug for PresenceEntryV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceEntryV1")
            .field("age_millis", &self.age_millis)
            .field("stale", &self.stale)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeV1 {
    Presence {
        entries: Vec<PresenceEntryV1>,
        truncated: bool,
    },
    Executed(ExecutionResultV1),
    OutcomeUnknown {
        execution_id: ExecutionIdV1,
    },
    Status {
        execution_id: ExecutionIdV1,
        phase: ExecutionPhaseV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalV1 {
    PresenceUnavailable,
    UnknownSession,
    PrincipalMismatch,
    AuthorityDenied,
    AuthorityExpired,
    AttemptDenied,
    IdempotencyConflict,
    ExecutionConflict,
    Capacity,
    InvalidBudget,
    BudgetLimit,
    ToolNotAuthorized,
    ContextLimit,
    ToolLimit,
    ProviderReceiptMismatch,
    ProviderReceiptConflict,
    OutputLimit,
    ArtifactLimit,
    UnknownExecution,
    InvalidInput,
    Exhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyV1 {
    Accepted(OutcomeV1),
    Refused(RefusalV1),
}
