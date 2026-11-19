//! Transport-neutral values for Daimon's native execution contract.
//!
//! Session handles and correlation identifiers carry no authority. A service
//! binds each session to separately authenticated host facts.

use sha2::{Digest, Sha256};

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

/// Content-free identities derived from the exact invocation Daimon retained
/// before provider dispatch. These values support correlation analysis; they
/// do not establish reviewer independence or disclose prompt/context bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelInvocationEvidenceV1 {
    pub provider: ProviderProfileIdV1,
    pub provider_document_digest: ContentDigestV1,
    pub model_digest: ContentDigestV1,
    pub context_manifest_digest: ContentDigestV1,
    pub message_manifest_digest: ContentDigestV1,
    pub evidence_scope_digest: ContentDigestV1,
}

pub fn model_invocation_evidence(invocation: &ModelInvocationV1) -> ModelInvocationEvidenceV1 {
    let model_digest = digest_manifest(b"DAIMON_MODEL_IDENTITY_V1\0", |hash| {
        hash.update((invocation.provider.model.len() as u64).to_be_bytes());
        hash.update(&invocation.provider.model);
    });
    let context_manifest_digest = digest_manifest(b"DAIMON_CONTEXT_MANIFEST_V1\0", |hash| {
        hash.update((invocation.context.len() as u64).to_be_bytes());
        for evidence in &invocation.context {
            hash.update(evidence.reference.into_bytes());
            hash.update([context_kind_tag(evidence.kind)]);
            hash.update(evidence.source_digest.into_bytes());
            hash.update(Sha256::digest(&evidence.bytes));
            match evidence.grounding {
                None => hash.update([0]),
                Some(grounding) => {
                    hash.update([1, grounding_depth_tag(grounding.depth)]);
                    hash.update(grounding.grounding_digest.into_bytes());
                    hash.update(grounding.surface_digest.into_bytes());
                }
            }
        }
    });
    let message_manifest_digest = digest_manifest(b"DAIMON_MESSAGE_MANIFEST_V1\0", |hash| {
        hash.update((invocation.messages.len() as u64).to_be_bytes());
        for message in &invocation.messages {
            hash.update([message_role_tag(message.role)]);
            hash.update((message.content.len() as u64).to_be_bytes());
            hash.update(Sha256::digest(&message.content));
        }
    });
    let evidence_scope_digest = digest_manifest(b"DAIMON_EVIDENCE_SCOPE_V1\0", |hash| {
        let mut entries = invocation
            .context
            .iter()
            .map(|evidence| {
                digest_manifest(b"DAIMON_EVIDENCE_SCOPE_ENTRY_V1\0", |entry| {
                    entry.update([context_kind_tag(evidence.kind)]);
                    entry.update(evidence.source_digest.into_bytes());
                    if let Some(grounding) = evidence.grounding {
                        entry.update([grounding_depth_tag(grounding.depth)]);
                        entry.update(grounding.grounding_digest.into_bytes());
                        entry.update(grounding.surface_digest.into_bytes());
                    }
                })
                .into_bytes()
            })
            .collect::<Vec<_>>();
        if let Some(continuation) = &invocation.continuation {
            entries.extend(continuation.results.iter().map(|result| {
                digest_manifest(b"DAIMON_TOOL_EVIDENCE_SCOPE_ENTRY_V1\0", |entry| {
                    entry.update(result.capability.into_bytes());
                    entry.update(result.evidence_digest.into_bytes());
                    entry.update(result.output_digest.into_bytes());
                })
                .into_bytes()
            }));
        }
        entries.sort_unstable();
        hash.update((entries.len() as u64).to_be_bytes());
        for entry in entries {
            hash.update(entry);
        }
    });
    ModelInvocationEvidenceV1 {
        provider: invocation.provider.provider,
        provider_document_digest: invocation.provider.document_digest,
        model_digest,
        context_manifest_digest,
        message_manifest_digest,
        evidence_scope_digest,
    }
}

fn digest_manifest(domain: &[u8], update: impl FnOnce(&mut Sha256)) -> ContentDigestV1 {
    let mut hash = Sha256::new();
    hash.update(domain);
    update(&mut hash);
    ContentDigestV1::new(hash.finalize().into())
}

const fn context_kind_tag(value: ContextKindV1) -> u8 {
    match value {
        ContextKindV1::AgoraMessage => 0,
        ContextKindV1::ChronosWork => 1,
        ContextKindV1::VellumDocument => 2,
        ContextKindV1::DendriteGrounding => 3,
    }
}

const fn grounding_depth_tag(value: GroundingDepthV1) -> u8 {
    match value {
        GroundingDepthV1::Ambient => 0,
        GroundingDepthV1::Activated => 1,
        GroundingDepthV1::Reference => 2,
    }
}

const fn message_role_tag(value: MessageRoleV1) -> u8 {
    match value {
        MessageRoleV1::System => 0,
        MessageRoleV1::User => 1,
        MessageRoleV1::Assistant => 2,
        MessageRoleV1::Tool => 3,
    }
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
    /// `None` is reserved for legacy V1–V3 wire replies. Current services
    /// always derive and publish this from their retained invocation.
    pub invocation_evidence: Option<Box<ModelInvocationEvidenceV1>>,
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

#[cfg(test)]
mod invocation_evidence_tests {
    use super::*;

    fn invocation() -> ModelInvocationV1 {
        ModelInvocationV1 {
            execution_id: ExecutionIdV1::new([1; 16]),
            provider: ProviderProfileSnapshotV1 {
                provider: ProviderProfileIdV1::new([2; 16]),
                harness_profile: HarnessProfileIdV1::new([3; 16]),
                wire: ProviderWireProfileV1::OpenAiChatCompletions,
                model: b"model-a".to_vec(),
                structured_tools: true,
                document_digest: ContentDigestV1::new([4; 32]),
            },
            context: vec![
                ContextEvidenceV1 {
                    reference: ContextReferenceIdV1::new([5; 16]),
                    kind: ContextKindV1::ChronosWork,
                    bytes: b"work".to_vec(),
                    source_digest: ContentDigestV1::new([6; 32]),
                    grounding: None,
                },
                ContextEvidenceV1 {
                    reference: ContextReferenceIdV1::new([7; 16]),
                    kind: ContextKindV1::DendriteGrounding,
                    bytes: b"grounding".to_vec(),
                    source_digest: ContentDigestV1::new([8; 32]),
                    grounding: Some(GroundingEvidenceV1 {
                        depth: GroundingDepthV1::Activated,
                        grounding_digest: ContentDigestV1::new([9; 32]),
                        surface_digest: ContentDigestV1::new([10; 32]),
                    }),
                },
            ],
            messages: vec![ModelMessageV1 {
                role: MessageRoleV1::User,
                content: b"review this".to_vec(),
            }],
            tools: vec![ToolCapabilityIdV1::new([11; 16])],
            continuation: None,
            estimated_input_tokens: 3,
        }
    }

    #[test]
    fn invocation_dimensions_are_stable_and_separately_sensitive() {
        let original = invocation();
        let evidence = model_invocation_evidence(&original);
        assert_eq!(evidence, model_invocation_evidence(&original));

        let mut changed_model = original.clone();
        changed_model.provider.model = b"model-b".to_vec();
        let changed_model = model_invocation_evidence(&changed_model);
        assert_ne!(changed_model.model_digest, evidence.model_digest);
        assert_eq!(
            changed_model.message_manifest_digest,
            evidence.message_manifest_digest
        );

        let mut reordered_context = original.clone();
        reordered_context.context.reverse();
        let reordered_context = model_invocation_evidence(&reordered_context);
        assert_ne!(
            reordered_context.context_manifest_digest,
            evidence.context_manifest_digest
        );
        assert_eq!(
            reordered_context.evidence_scope_digest,
            evidence.evidence_scope_digest
        );

        let mut changed_message = original;
        changed_message.messages[0].content = b"review that".to_vec();
        let changed_message = model_invocation_evidence(&changed_message);
        assert_ne!(
            changed_message.message_manifest_digest,
            evidence.message_manifest_digest
        );
        assert_eq!(
            changed_message.evidence_scope_digest,
            evidence.evidence_scope_digest
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyV1 {
    Accepted(OutcomeV1),
    Refused(RefusalV1),
}
