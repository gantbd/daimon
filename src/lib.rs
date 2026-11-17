//! Planning vocabulary for the Daimon agent harness boundary.
//!
//! This crate invokes no model, tool, process, or network service.

use std::collections::{BTreeMap, BTreeSet};

pub const PROJECT_STAGE: &str = "deterministic-fake-harness";

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn new(value: [u8; 16]) -> Self {
                Self(value)
            }

            /// Authority-free identity bytes for adapter correlation/codecs.
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

id!(ExecutionId);
id!(TaskAttemptId);
id!(PrincipalId);
id!(HarnessProfileId);
id!(ContextReferenceId);
id!(ToolCapabilityId);
id!(IdempotencyKey);
id!(ArtifactReferenceId);
id!(ProviderProfileId);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalTime(pub u64);

/// Authority-free correlation to an exact Chronos task attempt.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskAttemptRefV1 {
    task_key: [u8; 16],
    task_incarnation: u64,
    attempt_number: u32,
}

impl TaskAttemptRefV1 {
    pub const fn new(task_key: [u8; 16], task_incarnation: u64, attempt_number: u32) -> Self {
        Self {
            task_key,
            task_incarnation,
            attempt_number,
        }
    }

    pub const fn task_key(&self) -> [u8; 16] {
        self.task_key
    }
    pub const fn task_incarnation(&self) -> u64 {
        self.task_incarnation
    }
    pub const fn attempt_number(&self) -> u32 {
        self.attempt_number
    }
}

impl std::fmt::Debug for TaskAttemptRefV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TaskAttemptRefV1(<redacted>)")
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessRequestV1 {
    pub execution_id: ExecutionId,
    pub task_attempt: TaskAttemptRefV1,
    pub principal: PrincipalId,
    pub profile: HarnessProfileId,
    pub idempotency_key: IdempotencyKey,
    pub context: Vec<ContextReferenceId>,
    pub tools: Vec<ToolCapabilityId>,
    pub budget: ExecutionBudgetV1,
}

impl HarnessRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: ExecutionId,
        task_attempt: TaskAttemptRefV1,
        principal: PrincipalId,
        profile: HarnessProfileId,
        idempotency_key: IdempotencyKey,
        context: Vec<ContextReferenceId>,
        tools: Vec<ToolCapabilityId>,
        budget: ExecutionBudgetV1,
    ) -> Self {
        Self {
            execution_id,
            task_attempt,
            principal,
            profile,
            idempotency_key,
            context,
            tools,
            budget,
        }
    }
}

/// Canonical identity of bounded bytes resolved outside the engine.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWireProfileV1 {
    OpenAiChatCompletions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileErrorV1 {
    EmptyModel,
    ModelLimit,
}

/// Admission-frozen, credential-free provider selection.
///
/// Endpoint policy and credentials remain service composition concerns. The
/// canonical digest binds the complete non-secret deployment document retained
/// by that service without importing its representation into the engine.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderProfileSnapshotV1 {
    pub provider: ProviderProfileId,
    pub harness_profile: HarnessProfileId,
    pub wire: ProviderWireProfileV1,
    pub model: Vec<u8>,
    pub structured_tools: bool,
    pub document_digest: ContentDigestV1,
}

impl ProviderProfileSnapshotV1 {
    pub const MAX_MODEL_BYTES: usize = 256;

    pub fn try_new(
        provider: ProviderProfileId,
        harness_profile: HarnessProfileId,
        wire: ProviderWireProfileV1,
        model: Vec<u8>,
        structured_tools: bool,
        document_digest: ContentDigestV1,
    ) -> Result<Self, ProfileErrorV1> {
        if model.is_empty() {
            return Err(ProfileErrorV1::EmptyModel);
        }
        if model.len() > Self::MAX_MODEL_BYTES {
            return Err(ProfileErrorV1::ModelLimit);
        }
        Ok(Self {
            provider,
            harness_profile,
            wire,
            model,
            structured_tools,
            document_digest,
        })
    }
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

/// Exact context bytes plus the identity the resolving adapter verified.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextEvidenceV1 {
    pub reference: ContextReferenceId,
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

/// Dendrite-owned source and surface identities verified by a grounding adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroundingEvidenceV1 {
    pub depth: GroundingDepthV1,
    pub grounding_digest: ContentDigestV1,
    pub surface_digest: ContentDigestV1,
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
    pub capability: ToolCapabilityId,
    pub provider_correlation: Vec<u8>,
    pub arguments: Vec<u8>,
    pub evidence_digest: ContentDigestV1,
    pub output_digest: ContentDigestV1,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelContinuationV1 {
    pub source_execution: ExecutionId,
    pub source_output: Vec<u8>,
    pub source_tools: Vec<ToolCapabilityId>,
    pub results: Vec<ModelToolResultV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationV1 {
    pub execution_id: ExecutionId,
    pub provider: ProviderProfileSnapshotV1,
    pub context: Vec<ContextEvidenceV1>,
    pub messages: Vec<ModelMessageV1>,
    pub tools: Vec<ToolCapabilityId>,
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
    pub capability: ToolCapabilityId,
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

impl OutputProposalV1 {
    fn content_bytes(&self) -> usize {
        match self {
            Self::AgoraMessage(proposal) => proposal.body.len(),
            Self::VellumEdit(proposal) => proposal.replacement.len(),
            Self::ToolCall(proposal) => proposal
                .provider_correlation
                .len()
                .saturating_add(proposal.arguments.len()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCompletionReceiptV1 {
    pub execution_id: ExecutionId,
    pub provider_document_digest: ContentDigestV1,
    pub evidence_digest: ContentDigestV1,
    pub disposition: ExecutionDispositionV1,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub output: Vec<u8>,
    pub proposals: Vec<OutputProposalV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelHarnessResultV1 {
    pub execution_id: ExecutionId,
    pub disposition: ExecutionDispositionV1,
    pub evidence_digest: ContentDigestV1,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub output: Vec<u8>,
    pub proposals: Vec<OutputProposalV1>,
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
pub struct HarnessResultV1 {
    pub execution_id: ExecutionId,
    pub disposition: ExecutionDispositionV1,
    pub produced_artifacts: Vec<ArtifactReferenceId>,
    pub output_bytes: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityEvidenceV1 {
    decision_id: [u8; 16],
    subject: PrincipalId,
    tools: BTreeSet<ToolCapabilityId>,
    expires_at: LogicalTime,
}

impl std::fmt::Debug for AuthorityEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityEvidenceV1")
            .field("decision_id", &"<redacted>")
            .field("subject", &self.subject)
            .field("tool_count", &self.tools.len())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AuthorityEvidenceV1 {
    pub fn new(
        decision_id: [u8; 16],
        subject: PrincipalId,
        tools: impl IntoIterator<Item = ToolCapabilityId>,
        expires_at: LogicalTime,
    ) -> Self {
        Self {
            decision_id,
            subject,
            tools: tools.into_iter().collect(),
            expires_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_in_flight: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_artifacts: usize,
    pub max_elapsed_millis: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
    pub max_context_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_in_flight: 1_024,
            max_context_references: 64,
            max_tools: 64,
            max_artifacts: 64,
            max_elapsed_millis: 86_400_000,
            max_input_tokens: 1_000_000,
            max_output_tokens: 1_000_000,
            max_tool_calls: 10_000,
            max_context_bytes: 16 * 1_024 * 1_024,
            max_output_bytes: 16 * 1_024 * 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitsError {
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefusalV1 {
    IdempotencyConflict,
    ExecutionConflict,
    Capacity,
    AuthorityExpired,
    AuthoritySubjectMismatch,
    ToolNotAuthorized,
    ContextLimit,
    ToolLimit,
    InvalidBudget,
    BudgetLimit,
    UnknownExecution,
    PreparedExecutionMismatch,
    ProviderReceiptMismatch,
    ProviderReceiptConflict,
    OutputLimit,
    ArtifactLimit,
    ProviderProfileMismatch,
    ContextEvidenceMismatch,
    ContextBytesLimit,
    InputTokenLimit,
    OutputTokenLimit,
    ProposalLimit,
    ProposalBytesLimit,
    ToolCallLimit,
    ToolCallMismatch,
    DuplicateToolCall,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreparedExecutionV1 {
    request: HarnessRequestV1,
    authority_decision: [u8; 16],
}

impl std::fmt::Debug for PreparedExecutionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedExecutionV1")
            .field("execution_id", &self.request.execution_id)
            .field("task_attempt", &self.request.task_attempt)
            .field("authority_decision", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReceiptV1 {
    execution_id: ExecutionId,
    disposition: ExecutionDispositionV1,
    output_bytes: usize,
    artifacts: Vec<ArtifactReferenceId>,
}

impl ProviderReceiptV1 {
    pub fn new(
        execution_id: ExecutionId,
        disposition: ExecutionDispositionV1,
        output_bytes: usize,
        artifacts: Vec<ArtifactReferenceId>,
    ) -> Self {
        Self {
            execution_id,
            disposition,
            output_bytes,
            artifacts,
        }
    }
}

struct CompletedExecution {
    receipt: ProviderReceiptV1,
    result: HarnessResultV1,
}

struct CompletedModelExecution {
    receipt: ModelCompletionReceiptV1,
    result: ModelHarnessResultV1,
}

/// Deterministic reference harness. Provider invocation remains an adapter
/// effect represented only by an attributed `ProviderReceiptV1`.
pub struct Engine {
    limits: Limits,
    prepared_by_key: BTreeMap<IdempotencyKey, PreparedExecutionV1>,
    key_by_execution: BTreeMap<ExecutionId, IdempotencyKey>,
    completed: BTreeMap<ExecutionId, CompletedExecution>,
    completed_models: BTreeMap<ExecutionId, CompletedModelExecution>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("in_flight", &self.in_flight())
            .field("completed", &self.completed())
            .finish()
    }
}

impl Engine {
    pub fn try_new(limits: Limits) -> Result<Self, LimitsError> {
        if limits.max_in_flight == 0 {
            return Err(LimitsError::Disabled);
        }
        Ok(Self {
            limits,
            prepared_by_key: BTreeMap::new(),
            key_by_execution: BTreeMap::new(),
            completed: BTreeMap::new(),
            completed_models: BTreeMap::new(),
        })
    }

    pub fn in_flight(&self) -> usize {
        self.prepared_by_key
            .len()
            .saturating_sub(self.completed.len() + self.completed_models.len())
    }

    pub fn completed(&self) -> usize {
        self.completed.len() + self.completed_models.len()
    }

    pub fn prepare(
        &mut self,
        request: HarnessRequestV1,
        authority: &AuthorityEvidenceV1,
        now: LogicalTime,
    ) -> Result<PreparedExecutionV1, RefusalV1> {
        if let Some(existing) = self.prepared_by_key.get(&request.idempotency_key) {
            return if existing.request == request {
                Ok(existing.clone())
            } else {
                Err(RefusalV1::IdempotencyConflict)
            };
        }
        if self.key_by_execution.contains_key(&request.execution_id) {
            return Err(RefusalV1::ExecutionConflict);
        }
        if self.in_flight() == self.limits.max_in_flight {
            return Err(RefusalV1::Capacity);
        }
        if authority.expires_at <= now {
            return Err(RefusalV1::AuthorityExpired);
        }
        if authority.subject != request.principal {
            return Err(RefusalV1::AuthoritySubjectMismatch);
        }
        if request
            .tools
            .iter()
            .any(|tool| !authority.tools.contains(tool))
        {
            return Err(RefusalV1::ToolNotAuthorized);
        }
        if request.context.len() > self.limits.max_context_references {
            return Err(RefusalV1::ContextLimit);
        }
        if request.tools.len() > self.limits.max_tools {
            return Err(RefusalV1::ToolLimit);
        }
        validate_budget(request.budget, self.limits)?;

        let prepared = PreparedExecutionV1 {
            request: request.clone(),
            authority_decision: authority.decision_id,
        };
        self.key_by_execution
            .insert(request.execution_id, request.idempotency_key);
        self.prepared_by_key
            .insert(request.idempotency_key, prepared.clone());
        Ok(prepared)
    }

    pub fn dispatch(
        &mut self,
        prepared: PreparedExecutionV1,
        receipt: ProviderReceiptV1,
    ) -> Result<HarnessResultV1, RefusalV1> {
        let Some(key) = self
            .key_by_execution
            .get(&prepared.request.execution_id)
            .copied()
        else {
            return Err(RefusalV1::UnknownExecution);
        };
        if self.prepared_by_key.get(&key) != Some(&prepared) {
            return Err(RefusalV1::PreparedExecutionMismatch);
        }
        if receipt.execution_id != prepared.request.execution_id {
            return Err(RefusalV1::ProviderReceiptMismatch);
        }
        if let Some(existing) = self.completed.get(&receipt.execution_id) {
            return if existing.receipt == receipt {
                Ok(existing.result.clone())
            } else {
                Err(RefusalV1::ProviderReceiptConflict)
            };
        }
        if self.completed_models.contains_key(&receipt.execution_id) {
            return Err(RefusalV1::ProviderReceiptConflict);
        }
        if receipt.output_bytes > prepared.request.budget.max_output_bytes {
            return Err(RefusalV1::OutputLimit);
        }
        if receipt.artifacts.len() > self.limits.max_artifacts {
            return Err(RefusalV1::ArtifactLimit);
        }
        let result = HarnessResultV1 {
            execution_id: receipt.execution_id,
            disposition: receipt.disposition,
            produced_artifacts: receipt.artifacts.clone(),
            output_bytes: receipt.output_bytes,
        };
        self.completed.insert(
            receipt.execution_id,
            CompletedExecution {
                receipt,
                result: result.clone(),
            },
        );
        Ok(result)
    }

    pub fn prepare_model_invocation(
        &self,
        prepared: &PreparedExecutionV1,
        provider: ProviderProfileSnapshotV1,
        context: Vec<ContextEvidenceV1>,
        messages: Vec<ModelMessageV1>,
        estimated_input_tokens: u64,
    ) -> Result<ModelInvocationV1, RefusalV1> {
        self.validate_prepared(prepared)?;
        if provider.harness_profile != prepared.request.profile {
            return Err(RefusalV1::ProviderProfileMismatch);
        }
        let requested: BTreeSet<_> = prepared.request.context.iter().copied().collect();
        let supplied: BTreeSet<_> = context.iter().map(|item| item.reference).collect();
        if requested.len() != prepared.request.context.len()
            || supplied.len() != context.len()
            || requested != supplied
            || context.iter().any(|item| {
                (item.kind == ContextKindV1::DendriteGrounding && item.grounding.is_none())
                    || (item.kind != ContextKindV1::DendriteGrounding && item.grounding.is_some())
            })
        {
            return Err(RefusalV1::ContextEvidenceMismatch);
        }
        let context_bytes = context
            .iter()
            .try_fold(0usize, |total, item| total.checked_add(item.bytes.len()))
            .ok_or(RefusalV1::ContextBytesLimit)?;
        if context_bytes > prepared.request.budget.max_context_bytes {
            return Err(RefusalV1::ContextBytesLimit);
        }
        if estimated_input_tokens > prepared.request.budget.max_input_tokens {
            return Err(RefusalV1::InputTokenLimit);
        }
        Ok(ModelInvocationV1 {
            execution_id: prepared.request.execution_id,
            provider,
            context,
            messages,
            tools: prepared.request.tools.clone(),
            continuation: None,
            estimated_input_tokens,
        })
    }

    pub fn prepare_model_continuation(
        &self,
        prepared: &PreparedExecutionV1,
        provider: ProviderProfileSnapshotV1,
        context: Vec<ContextEvidenceV1>,
        messages: Vec<ModelMessageV1>,
        estimated_input_tokens: u64,
        continuation: ModelContinuationV1,
    ) -> Result<ModelInvocationV1, RefusalV1> {
        let mut invocation = self.prepare_model_invocation(
            prepared,
            provider,
            context,
            messages,
            estimated_input_tokens,
        )?;
        if !invocation.provider.structured_tools
            || continuation.source_execution == invocation.execution_id
            || continuation.source_execution.into_bytes() == [0; 16]
            || continuation.source_output.len() > prepared.request.budget.max_output_bytes
            || continuation.source_tools.is_empty()
            || continuation
                .source_tools
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != continuation.source_tools.len()
            || continuation.results.is_empty()
            || continuation.results.len()
                > usize::try_from(prepared.request.budget.max_tool_calls)
                    .map_err(|_| RefusalV1::ToolCallLimit)?
        {
            return Err(RefusalV1::ToolCallMismatch);
        }
        let mut requests = BTreeSet::new();
        let mut correlations = BTreeSet::new();
        let mut output_bytes = 0_usize;
        for result in &continuation.results {
            output_bytes = output_bytes
                .checked_add(result.output.len())
                .ok_or(RefusalV1::OutputLimit)?;
            if result.request == [0; 16]
                || !continuation.source_tools.contains(&result.capability)
                || result.provider_correlation.is_empty()
                || result.provider_correlation.len() > 1_024
                || result.arguments.is_empty()
                || result.evidence_digest.into_bytes() == [0; 32]
                || result.output_digest.into_bytes() == [0; 32]
                || !requests.insert(result.request)
                || !correlations.insert(result.provider_correlation.as_slice())
            {
                return Err(RefusalV1::ToolCallMismatch);
            }
        }
        if output_bytes > prepared.request.budget.max_output_bytes {
            return Err(RefusalV1::OutputLimit);
        }
        invocation.continuation = Some(continuation);
        Ok(invocation)
    }

    pub fn dispatch_model(
        &mut self,
        prepared: PreparedExecutionV1,
        invocation: &ModelInvocationV1,
        receipt: ModelCompletionReceiptV1,
    ) -> Result<ModelHarnessResultV1, RefusalV1> {
        self.validate_prepared(&prepared)?;
        if invocation.execution_id != prepared.request.execution_id
            || receipt.execution_id != prepared.request.execution_id
            || invocation.tools != prepared.request.tools
        {
            return Err(RefusalV1::ProviderReceiptMismatch);
        }
        if invocation.provider.harness_profile != prepared.request.profile
            || receipt.provider_document_digest != invocation.provider.document_digest
        {
            return Err(RefusalV1::ProviderProfileMismatch);
        }
        if let Some(existing) = self.completed_models.get(&receipt.execution_id) {
            return if existing.receipt == receipt {
                Ok(existing.result.clone())
            } else {
                Err(RefusalV1::ProviderReceiptConflict)
            };
        }
        if self.completed.contains_key(&receipt.execution_id) {
            return Err(RefusalV1::ProviderReceiptConflict);
        }
        if receipt.input_tokens > prepared.request.budget.max_input_tokens {
            return Err(RefusalV1::InputTokenLimit);
        }
        if receipt.output_tokens > prepared.request.budget.max_output_tokens {
            return Err(RefusalV1::OutputTokenLimit);
        }
        if receipt.output.len() > prepared.request.budget.max_output_bytes {
            return Err(RefusalV1::OutputLimit);
        }
        if receipt.proposals.len() > self.limits.max_artifacts {
            return Err(RefusalV1::ProposalLimit);
        }
        let proposal_bytes = receipt
            .proposals
            .iter()
            .try_fold(0usize, |total, proposal| {
                total.checked_add(proposal.content_bytes())
            })
            .ok_or(RefusalV1::ProposalBytesLimit)?;
        if proposal_bytes > prepared.request.budget.max_output_bytes {
            return Err(RefusalV1::ProposalBytesLimit);
        }
        let mut tool_call_count = 0_u32;
        let mut tool_requests = BTreeSet::new();
        for proposal in &receipt.proposals {
            if let OutputProposalV1::ToolCall(call) = proposal {
                tool_call_count = tool_call_count
                    .checked_add(1)
                    .ok_or(RefusalV1::ToolCallLimit)?;
                if !invocation.provider.structured_tools
                    || call.request == [0; 16]
                    || call.provider_correlation.is_empty()
                    || call.provider_correlation.len() > 1_024
                    || call.arguments.is_empty()
                    || !invocation.tools.contains(&call.capability)
                {
                    return Err(RefusalV1::ToolCallMismatch);
                }
                if !tool_requests.insert(call.request) {
                    return Err(RefusalV1::DuplicateToolCall);
                }
            }
        }
        if tool_call_count > prepared.request.budget.max_tool_calls {
            return Err(RefusalV1::ToolCallLimit);
        }
        let result = ModelHarnessResultV1 {
            execution_id: receipt.execution_id,
            disposition: receipt.disposition,
            evidence_digest: receipt.evidence_digest,
            input_tokens: receipt.input_tokens,
            output_tokens: receipt.output_tokens,
            output: receipt.output.clone(),
            proposals: receipt.proposals.clone(),
        };
        self.completed_models.insert(
            receipt.execution_id,
            CompletedModelExecution {
                receipt,
                result: result.clone(),
            },
        );
        Ok(result)
    }

    fn validate_prepared(&self, prepared: &PreparedExecutionV1) -> Result<(), RefusalV1> {
        let Some(key) = self
            .key_by_execution
            .get(&prepared.request.execution_id)
            .copied()
        else {
            return Err(RefusalV1::UnknownExecution);
        };
        if self.prepared_by_key.get(&key) != Some(prepared) {
            return Err(RefusalV1::PreparedExecutionMismatch);
        }
        Ok(())
    }
}

fn validate_budget(budget: ExecutionBudgetV1, limits: Limits) -> Result<(), RefusalV1> {
    if budget.max_elapsed_millis == 0
        || budget.max_input_tokens == 0
        || budget.max_output_tokens == 0
        || budget.max_tool_calls == 0
        || budget.max_context_bytes == 0
        || budget.max_output_bytes == 0
    {
        return Err(RefusalV1::InvalidBudget);
    }
    if budget.max_elapsed_millis > limits.max_elapsed_millis
        || budget.max_input_tokens > limits.max_input_tokens
        || budget.max_output_tokens > limits.max_output_tokens
        || budget.max_tool_calls > limits.max_tool_calls
        || budget.max_context_bytes > limits.max_context_bytes
        || budget.max_output_bytes > limits.max_output_bytes
    {
        return Err(RefusalV1::BudgetLimit);
    }
    Ok(())
}
