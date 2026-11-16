//! Trusted outbound capability ports used by the native Daimon service.

pub mod agent;
pub mod presence;

use daimon_protocol::{
    ArtifactReferenceIdV1, ContextEvidenceV1, ExecuteRequestV1, ExecutionDispositionV1,
    ExecutionIdV1, ModelInvocationV1, ModelMessageV1, ModelProviderReceiptV1,
    ProviderProfileSnapshotV1, ToolCapabilityIdV1,
};

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedSessionV1 {
    pub principal: [u8; 16],
    pub authority_context: [u8; 16],
}

impl std::fmt::Debug for AuthenticatedSessionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSessionV1")
            .field("principal", &"<redacted>")
            .field("authority_context", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrantV1 {
    pub decision_id: [u8; 16],
    pub expires_at: u64,
    pub tools: Vec<ToolCapabilityIdV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRefusalV1 {
    Denied,
    Expired,
    Unavailable,
}

pub trait ExecutionAuthorizer {
    fn authorize(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        now: u64,
    ) -> Result<AuthorityGrantV1, AuthorityRefusalV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptRefusalV1 {
    NotCurrent,
    Unavailable,
}

pub trait AttemptValidator {
    fn validate(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
    ) -> Result<(), AttemptRefusalV1>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReceiptV1 {
    pub execution_id: ExecutionIdV1,
    pub disposition: ExecutionDispositionV1,
    pub output_bytes: usize,
    pub artifacts: Vec<ArtifactReferenceIdV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderOutcomeV1 {
    Receipt(ProviderReceiptV1),
    OutcomeUnknown,
}

pub trait Provider {
    fn execute(&mut self, request: &ExecuteRequestV1) -> ProviderOutcomeV1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileRefusalV1 {
    Unknown,
    Unavailable,
    Invalid,
}

/// Selects and freezes one credential-free provider profile for an execution.
pub trait ProviderProfileResolver {
    fn resolve_profile(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
    ) -> Result<ProviderProfileSnapshotV1, ProfileRefusalV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextRefusalV1 {
    Unavailable,
    InvalidEvidence,
    Limit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledModelInputV1 {
    pub context: Vec<ContextEvidenceV1>,
    pub messages: Vec<ModelMessageV1>,
    pub estimated_input_tokens: u64,
}

/// Resolves caller references through separately authorized context sources.
pub trait ContextAssembler {
    fn assemble(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: &ExecuteRequestV1,
        profile: &ProviderProfileSnapshotV1,
    ) -> Result<AssembledModelInputV1, ContextRefusalV1>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelProviderOutcomeV1 {
    Receipt(ModelProviderReceiptV1),
    OutcomeUnknown,
}

/// One terminal provider admission. Implementations must not retry implicitly.
pub trait ModelProvider {
    fn execute_model(&mut self, invocation: &ModelInvocationV1) -> ModelProviderOutcomeV1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredExecutionStateV1 {
    OutcomeUnknown,
    Completed(daimon_protocol::ExecutionResultV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredExecutionV1 {
    pub request: ExecuteRequestV1,
    pub authority_decision: [u8; 16],
    pub authority_expires_at: u64,
    pub authority_tools: Vec<ToolCapabilityIdV1>,
    pub prepared_at: u64,
    pub state: StoredExecutionStateV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceSnapshotV1 {
    pub executions: Vec<StoredExecutionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreCommitV1 {
    Committed,
    Indeterminate,
}

/// Durable service-state port. `Indeterminate` means the offered snapshot may
/// have committed and must never be followed by an external provider call.
pub trait ExecutionStore {
    type Error;

    fn load(&mut self) -> Result<Option<ServiceSnapshotV1>, Self::Error>;

    fn commit(&mut self, snapshot: &ServiceSnapshotV1) -> Result<StoreCommitV1, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredModelExecutionStateV1 {
    OutcomeUnknown,
    Completed(daimon_protocol::ModelExecutionResultV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredModelExecutionV1 {
    pub request: ExecuteRequestV1,
    pub authority_decision: [u8; 16],
    pub authority_expires_at: u64,
    pub authority_tools: Vec<ToolCapabilityIdV1>,
    pub prepared_at: u64,
    pub invocation: ModelInvocationV1,
    pub state: StoredModelExecutionStateV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelServiceSnapshotV1 {
    pub executions: Vec<StoredModelExecutionV1>,
}

/// Durable model-service state. An indeterminate commit fences provider admission.
pub trait ModelExecutionStore {
    type Error;

    fn load_model(&mut self) -> Result<Option<ModelServiceSnapshotV1>, Self::Error>;

    fn commit_model(
        &mut self,
        snapshot: &ModelServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error>;
}
