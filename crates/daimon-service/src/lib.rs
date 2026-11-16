//! Serialized native Daimon service with explicit authority, attempt and provider ports.
//!
//! It commits an outcome-unknown marker before provider dispatch and commits an
//! exact result before publication. Store uncertainty remains fenced.

pub mod agent;
pub mod model;

use daimon_harness as core;
use daimon_host::{
    AttemptValidator, AuthenticatedSessionV1, AuthorityRefusalV1, ExecutionAuthorizer,
    ExecutionStore, Provider, ProviderOutcomeV1, ServiceSnapshotV1, StoreCommitV1,
    StoredExecutionStateV1, StoredExecutionV1,
};
use daimon_protocol as protocol;
use std::{collections::BTreeMap, convert::Infallible};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceLimitsV1 {
    pub max_sessions: usize,
    pub max_executions: usize,
}

impl Default for ServiceLimitsV1 {
    fn default() -> Self {
        Self {
            max_sessions: 1_024,
            max_executions: 65_536,
        }
    }
}

#[derive(Clone)]
enum ExecutionState {
    OutcomeUnknown,
    Completed(protocol::ExecutionResultV1),
}

struct ExecutionEntry {
    request: protocol::ExecuteRequestV1,
    authority_decision: [u8; 16],
    authority_expires_at: u64,
    authority_tools: Vec<protocol::ToolCapabilityIdV1>,
    prepared_at: u64,
    state: ExecutionState,
}

#[derive(Default)]
pub struct VolatileStore {
    snapshot: Option<ServiceSnapshotV1>,
}

impl ExecutionStore for VolatileStore {
    type Error = Infallible;

    fn load(&mut self) -> Result<Option<ServiceSnapshotV1>, Self::Error> {
        Ok(self.snapshot.clone())
    }

    fn commit(&mut self, snapshot: &ServiceSnapshotV1) -> Result<StoreCommitV1, Self::Error> {
        self.snapshot = Some(snapshot.clone());
        Ok(StoreCommitV1::Committed)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RecoveryError<E> {
    InvalidConfiguration,
    Store(E),
    InvalidSnapshot(protocol::RefusalV1),
}

pub struct Service<A, T, P, S = VolatileStore> {
    engine: core::Engine,
    authorizer: A,
    attempts: T,
    provider: P,
    store: S,
    limits: ServiceLimitsV1,
    sessions: BTreeMap<protocol::SessionHandleV1, AuthenticatedSessionV1>,
    executions: BTreeMap<protocol::ExecutionIdV1, ExecutionEntry>,
    next_session: u64,
}

impl<A: ExecutionAuthorizer, T: AttemptValidator, P: Provider> Service<A, T, P, VolatileStore> {
    pub fn new(
        engine_limits: core::Limits,
        limits: ServiceLimitsV1,
        authorizer: A,
        attempts: T,
        provider: P,
    ) -> Option<Self> {
        Self::open(
            engine_limits,
            limits,
            authorizer,
            attempts,
            provider,
            VolatileStore::default(),
        )
        .ok()
    }
}

impl<A, T, P, S> Service<A, T, P, S>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    P: Provider,
    S: ExecutionStore,
{
    pub fn open(
        engine_limits: core::Limits,
        limits: ServiceLimitsV1,
        authorizer: A,
        attempts: T,
        provider: P,
        mut store: S,
    ) -> Result<Self, RecoveryError<S::Error>> {
        if limits.max_sessions == 0 || limits.max_executions == 0 {
            return Err(RecoveryError::InvalidConfiguration);
        }
        let snapshot = store.load().map_err(RecoveryError::Store)?;
        let mut service = Self {
            engine: core::Engine::try_new(engine_limits)
                .map_err(|_| RecoveryError::InvalidConfiguration)?,
            authorizer,
            attempts,
            provider,
            store,
            limits,
            sessions: BTreeMap::new(),
            executions: BTreeMap::new(),
            next_session: 0,
        };
        if let Some(snapshot) = snapshot {
            service.restore(snapshot)?;
        }
        Ok(service)
    }

    pub fn open_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<protocol::SessionHandleV1, protocol::RefusalV1> {
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(protocol::RefusalV1::Capacity);
        }
        let handle = protocol::SessionHandleV1(self.next_session);
        self.next_session = self
            .next_session
            .checked_add(1)
            .ok_or(protocol::RefusalV1::Exhausted)?;
        self.sessions.insert(handle, facts);
        Ok(handle)
    }

    pub fn close_session(&mut self, session: protocol::SessionHandleV1) -> bool {
        self.sessions.remove(&session).is_some()
    }

    pub fn execute(
        &mut self,
        session: protocol::SessionHandleV1,
        command: protocol::CommandV1,
    ) -> protocol::ReplyV1 {
        let Some(facts) = self.sessions.get(&session).cloned() else {
            return refused(protocol::RefusalV1::UnknownSession);
        };
        match command {
            protocol::CommandV1::Execute { request, now } => self.run(&facts, request, now),
            protocol::CommandV1::ReadPresence { .. } => {
                protocol::ReplyV1::Refused(protocol::RefusalV1::PresenceUnavailable)
            }
            protocol::CommandV1::Inspect { execution_id } => self.inspect(&facts, execution_id),
        }
    }

    pub fn into_parts(self) -> (A, T, P, S) {
        (self.authorizer, self.attempts, self.provider, self.store)
    }

    fn run(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: protocol::ExecuteRequestV1,
        now: u64,
    ) -> protocol::ReplyV1 {
        if request.principal.into_bytes() != session.principal {
            return refused(protocol::RefusalV1::PrincipalMismatch);
        }
        if let Some(entry) = self.executions.get(&request.execution_id) {
            if entry.request != request {
                return refused(protocol::RefusalV1::ExecutionConflict);
            }
            if let Err(error) = self.authorizer.authorize(session, &request, now) {
                return refused(authority_refusal(error));
            }
            return accepted(match &entry.state {
                ExecutionState::OutcomeUnknown => protocol::OutcomeV1::OutcomeUnknown {
                    execution_id: request.execution_id,
                },
                ExecutionState::Completed(result) => protocol::OutcomeV1::Executed(result.clone()),
            });
        }
        if self.executions.len() >= self.limits.max_executions {
            return refused(protocol::RefusalV1::Capacity);
        }
        let authority = match self.authorizer.authorize(session, &request, now) {
            Ok(authority) => authority,
            Err(error) => return refused(authority_refusal(error)),
        };
        if self.attempts.validate(session, &request).is_err() {
            return refused(protocol::RefusalV1::AttemptDenied);
        }
        let core_request = core_request(&request);
        let core_authority = core::AuthorityEvidenceV1::new(
            authority.decision_id,
            core::PrincipalId::new(session.principal),
            authority
                .tools
                .iter()
                .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
            core::LogicalTime(authority.expires_at),
        );
        let prepared =
            match self
                .engine
                .prepare(core_request, &core_authority, core::LogicalTime(now))
            {
                Ok(prepared) => prepared,
                Err(error) => return refused(core_refusal(error)),
            };
        self.executions.insert(
            request.execution_id,
            ExecutionEntry {
                request: request.clone(),
                authority_decision: authority.decision_id,
                authority_expires_at: authority.expires_at,
                authority_tools: authority.tools,
                prepared_at: now,
                state: ExecutionState::OutcomeUnknown,
            },
        );
        if !self.persist() {
            return accepted(protocol::OutcomeV1::OutcomeUnknown {
                execution_id: request.execution_id,
            });
        }
        let ProviderOutcomeV1::Receipt(receipt) = self.provider.execute(&request) else {
            return accepted(protocol::OutcomeV1::OutcomeUnknown {
                execution_id: request.execution_id,
            });
        };
        let core_receipt = core::ProviderReceiptV1::new(
            core::ExecutionId::new(receipt.execution_id.into_bytes()),
            disposition_to_core(receipt.disposition),
            receipt.output_bytes,
            receipt
                .artifacts
                .iter()
                .map(|artifact| core::ArtifactReferenceId::new(artifact.into_bytes()))
                .collect(),
        );
        let result = match self.engine.dispatch(prepared, core_receipt) {
            Ok(result) => result,
            Err(error) => return refused(core_refusal(error)),
        };
        let result = protocol::ExecutionResultV1 {
            execution_id: protocol::ExecutionIdV1::new(result.execution_id.into_bytes()),
            disposition: disposition_from_core(result.disposition),
            produced_artifacts: result
                .produced_artifacts
                .into_iter()
                .map(|artifact| protocol::ArtifactReferenceIdV1::new(artifact.into_bytes()))
                .collect(),
            output_bytes: result.output_bytes,
        };
        if let Some(entry) = self.executions.get_mut(&request.execution_id) {
            entry.state = ExecutionState::Completed(result.clone());
        }
        if self.persist() {
            accepted(protocol::OutcomeV1::Executed(result))
        } else {
            if let Some(entry) = self.executions.get_mut(&request.execution_id) {
                entry.state = ExecutionState::OutcomeUnknown;
            }
            accepted(protocol::OutcomeV1::OutcomeUnknown {
                execution_id: request.execution_id,
            })
        }
    }

    fn inspect(
        &self,
        session: &AuthenticatedSessionV1,
        execution_id: protocol::ExecutionIdV1,
    ) -> protocol::ReplyV1 {
        let Some(entry) = self.executions.get(&execution_id) else {
            return refused(protocol::RefusalV1::UnknownExecution);
        };
        if entry.request.principal.into_bytes() != session.principal {
            return refused(protocol::RefusalV1::PrincipalMismatch);
        }
        let phase = match entry.state {
            ExecutionState::OutcomeUnknown => protocol::ExecutionPhaseV1::OutcomeUnknown,
            ExecutionState::Completed(_) => protocol::ExecutionPhaseV1::Completed,
        };
        accepted(protocol::OutcomeV1::Status {
            execution_id,
            phase,
        })
    }

    fn persist(&mut self) -> bool {
        let snapshot = self.snapshot();
        matches!(self.store.commit(&snapshot), Ok(StoreCommitV1::Committed))
    }

    fn snapshot(&self) -> ServiceSnapshotV1 {
        ServiceSnapshotV1 {
            executions: self
                .executions
                .values()
                .map(|entry| StoredExecutionV1 {
                    request: entry.request.clone(),
                    authority_decision: entry.authority_decision,
                    authority_expires_at: entry.authority_expires_at,
                    authority_tools: entry.authority_tools.clone(),
                    prepared_at: entry.prepared_at,
                    state: match &entry.state {
                        ExecutionState::OutcomeUnknown => StoredExecutionStateV1::OutcomeUnknown,
                        ExecutionState::Completed(result) => {
                            StoredExecutionStateV1::Completed(result.clone())
                        }
                    },
                })
                .collect(),
        }
    }

    fn restore(&mut self, snapshot: ServiceSnapshotV1) -> Result<(), RecoveryError<S::Error>> {
        if snapshot.executions.len() > self.limits.max_executions {
            return Err(RecoveryError::InvalidSnapshot(
                protocol::RefusalV1::Capacity,
            ));
        }
        for stored in snapshot.executions {
            if self.executions.contains_key(&stored.request.execution_id) {
                return Err(RecoveryError::InvalidSnapshot(
                    protocol::RefusalV1::ExecutionConflict,
                ));
            }
            let authority = core::AuthorityEvidenceV1::new(
                stored.authority_decision,
                core::PrincipalId::new(stored.request.principal.into_bytes()),
                stored
                    .authority_tools
                    .iter()
                    .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
                core::LogicalTime(stored.authority_expires_at),
            );
            let prepared = self
                .engine
                .prepare(
                    core_request(&stored.request),
                    &authority,
                    core::LogicalTime(stored.prepared_at),
                )
                .map_err(|error| RecoveryError::InvalidSnapshot(core_refusal(error)))?;
            let state = match stored.state {
                StoredExecutionStateV1::OutcomeUnknown => ExecutionState::OutcomeUnknown,
                StoredExecutionStateV1::Completed(result) => {
                    if result.execution_id != stored.request.execution_id {
                        return Err(RecoveryError::InvalidSnapshot(
                            protocol::RefusalV1::ProviderReceiptMismatch,
                        ));
                    }
                    self.engine
                        .dispatch(prepared, core_receipt(&result))
                        .map_err(|error| RecoveryError::InvalidSnapshot(core_refusal(error)))?;
                    ExecutionState::Completed(result)
                }
            };
            self.executions.insert(
                stored.request.execution_id,
                ExecutionEntry {
                    request: stored.request,
                    authority_decision: stored.authority_decision,
                    authority_expires_at: stored.authority_expires_at,
                    authority_tools: stored.authority_tools,
                    prepared_at: stored.prepared_at,
                    state,
                },
            );
        }
        Ok(())
    }
}

fn core_request(request: &protocol::ExecuteRequestV1) -> core::HarnessRequestV1 {
    core::HarnessRequestV1::new(
        core::ExecutionId::new(request.execution_id.into_bytes()),
        core::TaskAttemptRefV1::new(
            request.task_attempt.task_key,
            request.task_attempt.task_incarnation,
            request.task_attempt.attempt_number,
        ),
        core::PrincipalId::new(request.principal.into_bytes()),
        core::HarnessProfileId::new(request.profile.into_bytes()),
        core::IdempotencyKey::new(request.idempotency_key.into_bytes()),
        request
            .context
            .iter()
            .map(|context| core::ContextReferenceId::new(context.into_bytes()))
            .collect(),
        request
            .tools
            .iter()
            .map(|tool| core::ToolCapabilityId::new(tool.into_bytes()))
            .collect(),
        core::ExecutionBudgetV1 {
            max_elapsed_millis: request.budget.max_elapsed_millis,
            max_input_tokens: request.budget.max_input_tokens,
            max_output_tokens: request.budget.max_output_tokens,
            max_tool_calls: request.budget.max_tool_calls,
            max_context_bytes: request.budget.max_context_bytes,
            max_output_bytes: request.budget.max_output_bytes,
        },
    )
}

fn core_receipt(result: &protocol::ExecutionResultV1) -> core::ProviderReceiptV1 {
    core::ProviderReceiptV1::new(
        core::ExecutionId::new(result.execution_id.into_bytes()),
        disposition_to_core(result.disposition),
        result.output_bytes,
        result
            .produced_artifacts
            .iter()
            .map(|artifact| core::ArtifactReferenceId::new(artifact.into_bytes()))
            .collect(),
    )
}

fn disposition_to_core(value: protocol::ExecutionDispositionV1) -> core::ExecutionDispositionV1 {
    match value {
        protocol::ExecutionDispositionV1::Completed => core::ExecutionDispositionV1::Completed,
        protocol::ExecutionDispositionV1::Failed => core::ExecutionDispositionV1::Failed,
        protocol::ExecutionDispositionV1::Cancelled => core::ExecutionDispositionV1::Cancelled,
        protocol::ExecutionDispositionV1::TimedOut => core::ExecutionDispositionV1::TimedOut,
        protocol::ExecutionDispositionV1::Uncertain => core::ExecutionDispositionV1::Uncertain,
    }
}

fn disposition_from_core(value: core::ExecutionDispositionV1) -> protocol::ExecutionDispositionV1 {
    match value {
        core::ExecutionDispositionV1::Completed => protocol::ExecutionDispositionV1::Completed,
        core::ExecutionDispositionV1::Failed => protocol::ExecutionDispositionV1::Failed,
        core::ExecutionDispositionV1::Cancelled => protocol::ExecutionDispositionV1::Cancelled,
        core::ExecutionDispositionV1::TimedOut => protocol::ExecutionDispositionV1::TimedOut,
        core::ExecutionDispositionV1::Uncertain => protocol::ExecutionDispositionV1::Uncertain,
    }
}

fn authority_refusal(value: AuthorityRefusalV1) -> protocol::RefusalV1 {
    match value {
        AuthorityRefusalV1::Expired => protocol::RefusalV1::AuthorityExpired,
        AuthorityRefusalV1::Denied | AuthorityRefusalV1::Unavailable => {
            protocol::RefusalV1::AuthorityDenied
        }
    }
}

fn core_refusal(value: core::RefusalV1) -> protocol::RefusalV1 {
    match value {
        core::RefusalV1::IdempotencyConflict => protocol::RefusalV1::IdempotencyConflict,
        core::RefusalV1::ExecutionConflict => protocol::RefusalV1::ExecutionConflict,
        core::RefusalV1::Capacity => protocol::RefusalV1::Capacity,
        core::RefusalV1::AuthorityExpired => protocol::RefusalV1::AuthorityExpired,
        core::RefusalV1::AuthoritySubjectMismatch => protocol::RefusalV1::PrincipalMismatch,
        core::RefusalV1::ToolNotAuthorized => protocol::RefusalV1::ToolNotAuthorized,
        core::RefusalV1::ContextLimit => protocol::RefusalV1::ContextLimit,
        core::RefusalV1::ToolLimit => protocol::RefusalV1::ToolLimit,
        core::RefusalV1::InvalidBudget => protocol::RefusalV1::InvalidBudget,
        core::RefusalV1::BudgetLimit => protocol::RefusalV1::BudgetLimit,
        core::RefusalV1::ProviderReceiptMismatch => protocol::RefusalV1::ProviderReceiptMismatch,
        core::RefusalV1::ProviderReceiptConflict => protocol::RefusalV1::ProviderReceiptConflict,
        core::RefusalV1::OutputLimit => protocol::RefusalV1::OutputLimit,
        core::RefusalV1::ArtifactLimit => protocol::RefusalV1::ArtifactLimit,
        core::RefusalV1::ProviderProfileMismatch | core::RefusalV1::ContextEvidenceMismatch => {
            protocol::RefusalV1::InvalidInput
        }
        core::RefusalV1::ContextBytesLimit => protocol::RefusalV1::ContextLimit,
        core::RefusalV1::InputTokenLimit | core::RefusalV1::OutputTokenLimit => {
            protocol::RefusalV1::BudgetLimit
        }
        core::RefusalV1::ProposalLimit => protocol::RefusalV1::ArtifactLimit,
        core::RefusalV1::ProposalBytesLimit => protocol::RefusalV1::OutputLimit,
        core::RefusalV1::ToolCallLimit
        | core::RefusalV1::ToolCallMismatch
        | core::RefusalV1::DuplicateToolCall => protocol::RefusalV1::InvalidInput,
        core::RefusalV1::UnknownExecution | core::RefusalV1::PreparedExecutionMismatch => {
            protocol::RefusalV1::UnknownExecution
        }
    }
}

fn accepted(outcome: protocol::OutcomeV1) -> protocol::ReplyV1 {
    protocol::ReplyV1::Accepted(outcome)
}

fn refused(refusal: protocol::RefusalV1) -> protocol::ReplyV1 {
    protocol::ReplyV1::Refused(refusal)
}
