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

/// Deterministic reference harness. Provider invocation remains an adapter
/// effect represented only by an attributed `ProviderReceiptV1`.
pub struct Engine {
    limits: Limits,
    prepared_by_key: BTreeMap<IdempotencyKey, PreparedExecutionV1>,
    key_by_execution: BTreeMap<ExecutionId, IdempotencyKey>,
    completed: BTreeMap<ExecutionId, CompletedExecution>,
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
        })
    }

    pub fn in_flight(&self) -> usize {
        self.prepared_by_key
            .len()
            .saturating_sub(self.completed.len())
    }

    pub fn completed(&self) -> usize {
        self.completed.len()
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
