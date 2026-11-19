//! Additive model-execution service family.
//!
//! Provider profiles and context are resolved by trusted ports. The service
//! commits an outcome-unknown marker containing the exact invocation before one
//! provider admission and commits the exact typed result before publication.

use daimon_harness as core;
use daimon_host::{
    AttemptValidator, AuthenticatedSessionV1, ContextAssembler, ExecutionAuthorizer,
    ModelExecutionStore, ModelProvider, ModelProviderOutcomeV1, ModelServiceSnapshotV1,
    ProviderProfileResolver, StoreCommitV1, StoredModelExecutionStateV1, StoredModelExecutionV1,
};
use daimon_protocol as protocol;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, convert::Infallible};

use crate::{
    ServiceLimitsV1, authority_refusal, core_refusal, core_request, disposition_from_core,
    disposition_to_core,
};

#[derive(Clone)]
enum ModelExecutionState {
    OutcomeUnknown,
    Completed(protocol::ModelExecutionResultV1),
}

struct ModelExecutionEntry {
    request: protocol::ExecuteRequestV1,
    authority_decision: [u8; 16],
    authority_expires_at: u64,
    authority_tools: Vec<protocol::ToolCapabilityIdV1>,
    prepared_at: u64,
    invocation: protocol::ModelInvocationV1,
    state: ModelExecutionState,
}

#[derive(Default)]
pub struct VolatileModelStore {
    snapshot: Option<ModelServiceSnapshotV1>,
}

impl ModelExecutionStore for VolatileModelStore {
    type Error = Infallible;

    fn load_model(&mut self) -> Result<Option<ModelServiceSnapshotV1>, Self::Error> {
        Ok(self.snapshot.clone())
    }

    fn commit_model(
        &mut self,
        snapshot: &ModelServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        self.snapshot = Some(snapshot.clone());
        Ok(StoreCommitV1::Committed)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ModelRecoveryError<E> {
    InvalidConfiguration,
    Store(E),
    InvalidSnapshot(protocol::RefusalV1),
}

pub struct ModelService<A, T, R, C, P, S = VolatileModelStore> {
    engine: core::Engine,
    authorizer: A,
    attempts: T,
    profiles: R,
    context: C,
    provider: P,
    store: S,
    limits: ServiceLimitsV1,
    sessions: BTreeMap<protocol::SessionHandleV1, AuthenticatedSessionV1>,
    executions: BTreeMap<protocol::ExecutionIdV1, ModelExecutionEntry>,
    next_session: u64,
}

impl<A, T, R, C, P> ModelService<A, T, R, C, P, VolatileModelStore>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: ProviderProfileResolver,
    C: ContextAssembler,
    P: ModelProvider,
{
    pub fn new(
        engine_limits: core::Limits,
        limits: ServiceLimitsV1,
        authorizer: A,
        attempts: T,
        profiles: R,
        context: C,
        provider: P,
    ) -> Option<Self> {
        Self::open(
            engine_limits,
            limits,
            authorizer,
            attempts,
            profiles,
            context,
            provider,
            VolatileModelStore::default(),
        )
        .ok()
    }
}

impl<A, T, R, C, P, S> ModelService<A, T, R, C, P, S>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: ProviderProfileResolver,
    C: ContextAssembler,
    P: ModelProvider,
    S: ModelExecutionStore,
{
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        engine_limits: core::Limits,
        limits: ServiceLimitsV1,
        authorizer: A,
        attempts: T,
        profiles: R,
        context: C,
        provider: P,
        mut store: S,
    ) -> Result<Self, ModelRecoveryError<S::Error>> {
        if limits.max_sessions == 0 || limits.max_executions == 0 {
            return Err(ModelRecoveryError::InvalidConfiguration);
        }
        let snapshot = store.load_model().map_err(ModelRecoveryError::Store)?;
        let mut service = Self {
            engine: core::Engine::try_new(engine_limits)
                .map_err(|_| ModelRecoveryError::InvalidConfiguration)?,
            authorizer,
            attempts,
            profiles,
            context,
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
        command: protocol::ModelCommandV1,
    ) -> protocol::ModelReplyV1 {
        let Some(facts) = self.sessions.get(&session).cloned() else {
            return refused(protocol::RefusalV1::UnknownSession);
        };
        match command {
            protocol::ModelCommandV1::Execute { request, now } => {
                self.run(&facts, request, None, now)
            }
            protocol::ModelCommandV1::Resume {
                request,
                source_execution,
                results,
                now,
            } => self.resume(&facts, request, source_execution, results, now),
            protocol::ModelCommandV1::Inspect { execution_id } => {
                self.inspect(&facts, execution_id)
            }
        }
    }

    pub fn into_parts(self) -> (A, T, R, C, P, S) {
        (
            self.authorizer,
            self.attempts,
            self.profiles,
            self.context,
            self.provider,
            self.store,
        )
    }

    fn run(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: protocol::ExecuteRequestV1,
        continuation: Option<protocol::ModelContinuationV1>,
        now: u64,
    ) -> protocol::ModelReplyV1 {
        if request.principal.into_bytes() != session.principal {
            return refused(protocol::RefusalV1::PrincipalMismatch);
        }
        if let Some(entry) = self.executions.get(&request.execution_id) {
            if entry.request != request || entry.invocation.continuation != continuation {
                return refused(protocol::RefusalV1::ExecutionConflict);
            }
            if let Err(error) = self.authorizer.authorize(session, &request, now) {
                return refused(authority_refusal(error));
            }
            return accepted(match &entry.state {
                ModelExecutionState::OutcomeUnknown => protocol::ModelOutcomeV1::OutcomeUnknown {
                    execution_id: request.execution_id,
                },
                ModelExecutionState::Completed(result) => {
                    protocol::ModelOutcomeV1::Executed(result.clone())
                }
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
        let prepared = match self.engine.prepare(
            core_request(&request),
            &core::AuthorityEvidenceV1::new(
                authority.decision_id,
                core::PrincipalId::new(session.principal),
                authority
                    .tools
                    .iter()
                    .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
                core::LogicalTime(authority.expires_at),
            ),
            core::LogicalTime(now),
        ) {
            Ok(prepared) => prepared,
            Err(error) => return refused(core_refusal(error)),
        };
        let profile = match self.profiles.resolve_profile(session, &request) {
            Ok(profile) => profile,
            Err(_) => return refused(protocol::RefusalV1::InvalidInput),
        };
        if continuation.as_ref().is_some_and(|value| {
            self.executions
                .get(&value.source_execution)
                .is_none_or(|source| source.invocation.provider != profile)
        }) {
            return refused(protocol::RefusalV1::InvalidInput);
        }
        let input = match self.context.assemble(session, &request, &profile) {
            Ok(input) => input,
            Err(_) => return refused(protocol::RefusalV1::InvalidInput),
        };
        let core_profile = match core_profile(&profile) {
            Ok(profile) => profile,
            Err(refusal) => return refused(refusal),
        };
        if continuation
            .as_ref()
            .is_some_and(|value| value.source_execution == request.execution_id)
        {
            return refused(protocol::RefusalV1::InvalidInput);
        }
        let prepared_invocation = match continuation.as_ref() {
            None => self.engine.prepare_model_invocation(
                &prepared,
                core_profile,
                input.context.iter().map(core_context).collect(),
                input.messages.iter().map(core_message).collect(),
                input.estimated_input_tokens,
            ),
            Some(value) => self.engine.prepare_model_continuation(
                &prepared,
                core_profile,
                input.context.iter().map(core_context).collect(),
                input.messages.iter().map(core_message).collect(),
                input.estimated_input_tokens,
                core_continuation(
                    value,
                    &self
                        .executions
                        .get(&value.source_execution)
                        .expect("continuation source validated before preparation")
                        .request
                        .tools,
                ),
            ),
        };
        let core_invocation = match prepared_invocation {
            Ok(invocation) => invocation,
            Err(error) => return refused(core_refusal(error)),
        };
        let invocation = protocol::ModelInvocationV1 {
            execution_id: request.execution_id,
            provider: profile,
            context: input.context,
            messages: input.messages,
            tools: request.tools.clone(),
            continuation,
            estimated_input_tokens: input.estimated_input_tokens,
        };
        self.executions.insert(
            request.execution_id,
            ModelExecutionEntry {
                request: request.clone(),
                authority_decision: authority.decision_id,
                authority_expires_at: authority.expires_at,
                authority_tools: authority.tools,
                prepared_at: now,
                invocation: invocation.clone(),
                state: ModelExecutionState::OutcomeUnknown,
            },
        );
        if !self.persist() {
            return unknown(request.execution_id);
        }
        let ModelProviderOutcomeV1::Receipt(receipt) = self.provider.execute_model(&invocation)
        else {
            return unknown(request.execution_id);
        };
        let result = match self.engine.dispatch_model(
            prepared,
            &core_invocation,
            core_model_receipt(&receipt),
        ) {
            Ok(result) => {
                protocol_model_result(result, protocol::model_invocation_evidence(&invocation))
            }
            Err(error) => return refused(core_refusal(error)),
        };
        if let Some(entry) = self.executions.get_mut(&request.execution_id) {
            entry.state = ModelExecutionState::Completed(result.clone());
        }
        if self.persist() {
            accepted(protocol::ModelOutcomeV1::Executed(result))
        } else {
            if let Some(entry) = self.executions.get_mut(&request.execution_id) {
                entry.state = ModelExecutionState::OutcomeUnknown;
            }
            unknown(request.execution_id)
        }
    }

    fn resume(
        &mut self,
        session: &AuthenticatedSessionV1,
        request: protocol::ExecuteRequestV1,
        source_execution: protocol::ExecutionIdV1,
        results: Vec<protocol::ResumeToolResultV1>,
        now: u64,
    ) -> protocol::ModelReplyV1 {
        let Some(source) = self.executions.get(&source_execution) else {
            return refused(protocol::RefusalV1::UnknownExecution);
        };
        let ModelExecutionState::Completed(source_result) = &source.state else {
            return refused(protocol::RefusalV1::InvalidInput);
        };
        if source.request.principal.into_bytes() != session.principal
            || request.principal != source.request.principal
            || request.task_attempt != source.request.task_attempt
            || request.profile != source.request.profile
            || request.context != source.request.context
            || request
                .tools
                .iter()
                .any(|tool| !source.request.tools.contains(tool))
            || !source.invocation.provider.structured_tools
        {
            return refused(protocol::RefusalV1::InvalidInput);
        }
        let mut supplied = BTreeMap::new();
        for result in results {
            if result.request == [0; 16]
                || result.evidence_digest.into_bytes() == [0; 32]
                || result.output_digest.into_bytes() == [0; 32]
                || <[u8; 32]>::from(Sha256::digest(&result.output))
                    != result.output_digest.into_bytes()
                || supplied.insert(result.request, result).is_some()
            {
                return refused(protocol::RefusalV1::InvalidInput);
            }
        }
        let calls: Vec<_> = source_result
            .proposals
            .iter()
            .filter_map(|proposal| match proposal {
                protocol::OutputProposalV1::ToolCall(call) => Some(call),
                _ => None,
            })
            .collect();
        if calls.is_empty() || calls.len() != supplied.len() {
            return refused(protocol::RefusalV1::InvalidInput);
        }
        let mut bound = Vec::new();
        if bound.try_reserve(calls.len()).is_err() {
            return refused(protocol::RefusalV1::Capacity);
        }
        for call in calls {
            let Some(result) = supplied.remove(&call.request) else {
                return refused(protocol::RefusalV1::InvalidInput);
            };
            bound.push(protocol::ModelToolResultV1 {
                request: call.request,
                capability: call.capability,
                provider_correlation: call.provider_correlation.clone(),
                arguments: call.arguments.clone(),
                evidence_digest: result.evidence_digest,
                output_digest: result.output_digest,
                output: result.output,
            });
        }
        self.run(
            session,
            request,
            Some(protocol::ModelContinuationV1 {
                source_execution,
                source_output: source_result.output.clone(),
                results: bound,
            }),
            now,
        )
    }

    fn inspect(
        &self,
        session: &AuthenticatedSessionV1,
        execution_id: protocol::ExecutionIdV1,
    ) -> protocol::ModelReplyV1 {
        let Some(entry) = self.executions.get(&execution_id) else {
            return refused(protocol::RefusalV1::UnknownExecution);
        };
        if entry.request.principal.into_bytes() != session.principal {
            return refused(protocol::RefusalV1::PrincipalMismatch);
        }
        accepted(protocol::ModelOutcomeV1::Status {
            execution_id,
            phase: match entry.state {
                ModelExecutionState::OutcomeUnknown => protocol::ExecutionPhaseV1::OutcomeUnknown,
                ModelExecutionState::Completed(_) => protocol::ExecutionPhaseV1::Completed,
            },
        })
    }

    fn persist(&mut self) -> bool {
        let snapshot = self.snapshot();
        matches!(
            self.store.commit_model(&snapshot),
            Ok(StoreCommitV1::Committed)
        )
    }

    fn snapshot(&self) -> ModelServiceSnapshotV1 {
        ModelServiceSnapshotV1 {
            executions: self
                .executions
                .values()
                .map(|entry| StoredModelExecutionV1 {
                    request: entry.request.clone(),
                    authority_decision: entry.authority_decision,
                    authority_expires_at: entry.authority_expires_at,
                    authority_tools: entry.authority_tools.clone(),
                    prepared_at: entry.prepared_at,
                    invocation: entry.invocation.clone(),
                    state: match &entry.state {
                        ModelExecutionState::OutcomeUnknown => {
                            StoredModelExecutionStateV1::OutcomeUnknown
                        }
                        ModelExecutionState::Completed(result) => {
                            StoredModelExecutionStateV1::Completed(result.clone())
                        }
                    },
                })
                .collect(),
        }
    }

    fn restore(
        &mut self,
        snapshot: ModelServiceSnapshotV1,
    ) -> Result<(), ModelRecoveryError<S::Error>> {
        if snapshot.executions.len() > self.limits.max_executions {
            return Err(ModelRecoveryError::InvalidSnapshot(
                protocol::RefusalV1::Capacity,
            ));
        }
        for stored in snapshot.executions {
            if self.executions.contains_key(&stored.request.execution_id) {
                return Err(ModelRecoveryError::InvalidSnapshot(
                    protocol::RefusalV1::ExecutionConflict,
                ));
            }
            if stored.invocation.execution_id != stored.request.execution_id {
                return Err(ModelRecoveryError::InvalidSnapshot(
                    protocol::RefusalV1::ProviderReceiptMismatch,
                ));
            }
            let prepared = self
                .engine
                .prepare(
                    core_request(&stored.request),
                    &core::AuthorityEvidenceV1::new(
                        stored.authority_decision,
                        core::PrincipalId::new(stored.request.principal.into_bytes()),
                        stored
                            .authority_tools
                            .iter()
                            .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
                        core::LogicalTime(stored.authority_expires_at),
                    ),
                    core::LogicalTime(stored.prepared_at),
                )
                .map_err(|error| ModelRecoveryError::InvalidSnapshot(core_refusal(error)))?;
            let profile = core_profile(&stored.invocation.provider)
                .map_err(ModelRecoveryError::InvalidSnapshot)?;
            let prepared_invocation = match stored.invocation.continuation.as_ref() {
                None => self.engine.prepare_model_invocation(
                    &prepared,
                    profile,
                    stored.invocation.context.iter().map(core_context).collect(),
                    stored
                        .invocation
                        .messages
                        .iter()
                        .map(core_message)
                        .collect(),
                    stored.invocation.estimated_input_tokens,
                ),
                Some(continuation) => {
                    let source_tools = self
                        .executions
                        .get(&continuation.source_execution)
                        .ok_or(ModelRecoveryError::InvalidSnapshot(
                            protocol::RefusalV1::InvalidInput,
                        ))?
                        .request
                        .tools
                        .clone();
                    self.engine.prepare_model_continuation(
                        &prepared,
                        profile,
                        stored.invocation.context.iter().map(core_context).collect(),
                        stored
                            .invocation
                            .messages
                            .iter()
                            .map(core_message)
                            .collect(),
                        stored.invocation.estimated_input_tokens,
                        core_continuation(continuation, &source_tools),
                    )
                }
            };
            let core_invocation = prepared_invocation
                .map_err(|error| ModelRecoveryError::InvalidSnapshot(core_refusal(error)))?;
            let state = match stored.state {
                StoredModelExecutionStateV1::OutcomeUnknown => ModelExecutionState::OutcomeUnknown,
                StoredModelExecutionStateV1::Completed(result) => {
                    if result.execution_id != stored.request.execution_id {
                        return Err(ModelRecoveryError::InvalidSnapshot(
                            protocol::RefusalV1::ProviderReceiptMismatch,
                        ));
                    }
                    let receipt = protocol::ModelProviderReceiptV1 {
                        execution_id: result.execution_id,
                        provider_document_digest: stored.invocation.provider.document_digest,
                        evidence_digest: result.evidence_digest,
                        disposition: result.disposition,
                        input_tokens: result.input_tokens,
                        output_tokens: result.output_tokens,
                        output: result.output.clone(),
                        proposals: result.proposals.clone(),
                    };
                    self.engine
                        .dispatch_model(prepared, &core_invocation, core_model_receipt(&receipt))
                        .map_err(|error| {
                            ModelRecoveryError::InvalidSnapshot(core_refusal(error))
                        })?;
                    ModelExecutionState::Completed(result)
                }
            };
            self.executions.insert(
                stored.request.execution_id,
                ModelExecutionEntry {
                    request: stored.request,
                    authority_decision: stored.authority_decision,
                    authority_expires_at: stored.authority_expires_at,
                    authority_tools: stored.authority_tools,
                    prepared_at: stored.prepared_at,
                    invocation: stored.invocation,
                    state,
                },
            );
        }
        if self
            .executions
            .values()
            .any(|entry| !valid_continuation_link(entry, &self.executions))
        {
            return Err(ModelRecoveryError::InvalidSnapshot(
                protocol::RefusalV1::InvalidInput,
            ));
        }
        Ok(())
    }
}

fn valid_continuation_link(
    entry: &ModelExecutionEntry,
    executions: &BTreeMap<protocol::ExecutionIdV1, ModelExecutionEntry>,
) -> bool {
    let Some(continuation) = &entry.invocation.continuation else {
        return true;
    };
    let Some(source) = executions.get(&continuation.source_execution) else {
        return false;
    };
    let ModelExecutionState::Completed(source_result) = &source.state else {
        return false;
    };
    if entry.request.principal != source.request.principal
        || entry.request.task_attempt != source.request.task_attempt
        || entry.request.profile != source.request.profile
        || entry.request.context != source.request.context
        || entry
            .request
            .tools
            .iter()
            .any(|tool| !source.request.tools.contains(tool))
        || entry.invocation.provider != source.invocation.provider
        || continuation.source_output != source_result.output
    {
        return false;
    }
    let calls: BTreeMap<_, _> = source_result
        .proposals
        .iter()
        .filter_map(|proposal| match proposal {
            protocol::OutputProposalV1::ToolCall(call) => Some((call.request, call)),
            _ => None,
        })
        .collect();
    calls.len() == continuation.results.len()
        && continuation.results.iter().all(|result| {
            calls.get(&result.request).is_some_and(|call| {
                result.capability == call.capability
                    && result.provider_correlation == call.provider_correlation
                    && result.arguments == call.arguments
                    && result.evidence_digest.into_bytes() != [0; 32]
                    && result.output_digest.into_bytes()
                        == <[u8; 32]>::from(Sha256::digest(&result.output))
            })
        })
}

fn core_profile(
    value: &protocol::ProviderProfileSnapshotV1,
) -> Result<core::ProviderProfileSnapshotV1, protocol::RefusalV1> {
    core::ProviderProfileSnapshotV1::try_new(
        core::ProviderProfileId::new(value.provider.into_bytes()),
        core::HarnessProfileId::new(value.harness_profile.into_bytes()),
        match value.wire {
            protocol::ProviderWireProfileV1::OpenAiChatCompletions => {
                core::ProviderWireProfileV1::OpenAiChatCompletions
            }
        },
        value.model.clone(),
        value.structured_tools,
        core::ContentDigestV1::new(value.document_digest.into_bytes()),
    )
    .map_err(|_| protocol::RefusalV1::InvalidInput)
}

fn core_context(value: &protocol::ContextEvidenceV1) -> core::ContextEvidenceV1 {
    core::ContextEvidenceV1 {
        reference: core::ContextReferenceId::new(value.reference.into_bytes()),
        kind: match value.kind {
            protocol::ContextKindV1::AgoraMessage => core::ContextKindV1::AgoraMessage,
            protocol::ContextKindV1::ChronosWork => core::ContextKindV1::ChronosWork,
            protocol::ContextKindV1::VellumDocument => core::ContextKindV1::VellumDocument,
            protocol::ContextKindV1::DendriteGrounding => core::ContextKindV1::DendriteGrounding,
        },
        bytes: value.bytes.clone(),
        source_digest: core::ContentDigestV1::new(value.source_digest.into_bytes()),
        grounding: value.grounding.map(|grounding| core::GroundingEvidenceV1 {
            depth: match grounding.depth {
                protocol::GroundingDepthV1::Ambient => core::GroundingDepthV1::Ambient,
                protocol::GroundingDepthV1::Activated => core::GroundingDepthV1::Activated,
                protocol::GroundingDepthV1::Reference => core::GroundingDepthV1::Reference,
            },
            grounding_digest: core::ContentDigestV1::new(grounding.grounding_digest.into_bytes()),
            surface_digest: core::ContentDigestV1::new(grounding.surface_digest.into_bytes()),
        }),
    }
}

fn core_message(value: &protocol::ModelMessageV1) -> core::ModelMessageV1 {
    core::ModelMessageV1 {
        role: match value.role {
            protocol::MessageRoleV1::System => core::MessageRoleV1::System,
            protocol::MessageRoleV1::User => core::MessageRoleV1::User,
            protocol::MessageRoleV1::Assistant => core::MessageRoleV1::Assistant,
            protocol::MessageRoleV1::Tool => core::MessageRoleV1::Tool,
        },
        content: value.content.clone(),
    }
}

fn core_model_receipt(value: &protocol::ModelProviderReceiptV1) -> core::ModelCompletionReceiptV1 {
    core::ModelCompletionReceiptV1 {
        execution_id: core::ExecutionId::new(value.execution_id.into_bytes()),
        provider_document_digest: core::ContentDigestV1::new(
            value.provider_document_digest.into_bytes(),
        ),
        evidence_digest: core::ContentDigestV1::new(value.evidence_digest.into_bytes()),
        disposition: disposition_to_core(value.disposition),
        input_tokens: value.input_tokens,
        output_tokens: value.output_tokens,
        output: value.output.clone(),
        proposals: value.proposals.iter().map(core_proposal).collect(),
    }
}

fn core_continuation(
    value: &protocol::ModelContinuationV1,
    source_tools: &[protocol::ToolCapabilityIdV1],
) -> core::ModelContinuationV1 {
    core::ModelContinuationV1 {
        source_execution: core::ExecutionId::new(value.source_execution.into_bytes()),
        source_output: value.source_output.clone(),
        source_tools: source_tools
            .iter()
            .map(|tool| core::ToolCapabilityId::new(tool.into_bytes()))
            .collect(),
        results: value
            .results
            .iter()
            .map(|result| core::ModelToolResultV1 {
                request: result.request,
                capability: core::ToolCapabilityId::new(result.capability.into_bytes()),
                provider_correlation: result.provider_correlation.clone(),
                arguments: result.arguments.clone(),
                evidence_digest: core::ContentDigestV1::new(result.evidence_digest.into_bytes()),
                output_digest: core::ContentDigestV1::new(result.output_digest.into_bytes()),
                output: result.output.clone(),
            })
            .collect(),
    }
}

fn core_proposal(value: &protocol::OutputProposalV1) -> core::OutputProposalV1 {
    match value {
        protocol::OutputProposalV1::AgoraMessage(proposal) => {
            core::OutputProposalV1::AgoraMessage(core::AgoraMessageProposalV1 {
                room: proposal.room,
                reply_to: proposal.reply_to,
                body: proposal.body.clone(),
            })
        }
        protocol::OutputProposalV1::VellumEdit(proposal) => {
            core::OutputProposalV1::VellumEdit(core::VellumEditProposalV1 {
                workspace: proposal.workspace,
                document: proposal.document,
                expected_revision: proposal.expected_revision,
                replacement: proposal.replacement.clone(),
            })
        }
        protocol::OutputProposalV1::ToolCall(proposal) => {
            core::OutputProposalV1::ToolCall(core::ToolCallProposalV1 {
                request: proposal.request,
                capability: core::ToolCapabilityId::new(proposal.capability.into_bytes()),
                provider_correlation: proposal.provider_correlation.clone(),
                arguments: proposal.arguments.clone(),
            })
        }
    }
}

fn protocol_model_result(
    value: core::ModelHarnessResultV1,
    invocation_evidence: protocol::ModelInvocationEvidenceV1,
) -> protocol::ModelExecutionResultV1 {
    protocol::ModelExecutionResultV1 {
        execution_id: protocol::ExecutionIdV1::new(value.execution_id.into_bytes()),
        disposition: disposition_from_core(value.disposition),
        evidence_digest: protocol::ContentDigestV1::new(value.evidence_digest.into_bytes()),
        invocation_evidence: Some(Box::new(invocation_evidence)),
        input_tokens: value.input_tokens,
        output_tokens: value.output_tokens,
        output: value.output,
        proposals: value.proposals.into_iter().map(protocol_proposal).collect(),
    }
}

fn protocol_proposal(value: core::OutputProposalV1) -> protocol::OutputProposalV1 {
    match value {
        core::OutputProposalV1::AgoraMessage(proposal) => {
            protocol::OutputProposalV1::AgoraMessage(protocol::AgoraMessageProposalV1 {
                room: proposal.room,
                reply_to: proposal.reply_to,
                body: proposal.body,
            })
        }
        core::OutputProposalV1::VellumEdit(proposal) => {
            protocol::OutputProposalV1::VellumEdit(protocol::VellumEditProposalV1 {
                workspace: proposal.workspace,
                document: proposal.document,
                expected_revision: proposal.expected_revision,
                replacement: proposal.replacement,
            })
        }
        core::OutputProposalV1::ToolCall(proposal) => {
            protocol::OutputProposalV1::ToolCall(protocol::ToolCallProposalV1 {
                request: proposal.request,
                capability: protocol::ToolCapabilityIdV1::new(proposal.capability.into_bytes()),
                provider_correlation: proposal.provider_correlation,
                arguments: proposal.arguments,
            })
        }
    }
}

fn accepted(outcome: protocol::ModelOutcomeV1) -> protocol::ModelReplyV1 {
    protocol::ModelReplyV1::Accepted(outcome)
}

fn refused(refusal: protocol::RefusalV1) -> protocol::ModelReplyV1 {
    protocol::ModelReplyV1::Refused(refusal)
}

fn unknown(execution_id: protocol::ExecutionIdV1) -> protocol::ModelReplyV1 {
    accepted(protocol::ModelOutcomeV1::OutcomeUnknown { execution_id })
}
