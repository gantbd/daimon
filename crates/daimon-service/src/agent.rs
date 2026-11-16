//! Volatile reference service for the additive interactive-agent contract.
//!
//! The service validates exact authority and current Chronos attempt before
//! session open, prompt dispatch, permission decisions, and explicit reattach.
//! Durable reopen restores idle resume-capable sessions as `ReattachRequired`,
//! while active-turn loss and ambiguous commits remain fenced outcome-unknown.
//! Cancellation and close are owner-scoped authority attenuation.

use crate::{authority_refusal, core_refusal, core_request};
use daimon_harness as core;
use daimon_host::agent::{
    AgentContextAssembler, AgentProfileResolver, AgentProvider, AgentProviderInvocationV1,
    AgentProviderOutcomeV1, AgentProviderReceiptV1, AgentServiceSnapshotV1, AgentSessionStore,
    StoredAgentOperationInputV1, StoredAgentOperationStateV1, StoredAgentOperationV1,
    StoredAgentPreparationV1, StoredAgentSessionV1,
};
use daimon_host::{AttemptValidator, AuthenticatedSessionV1, ExecutionAuthorizer, StoreCommitV1};
use daimon_protocol as protocol;
use daimon_protocol::agent::{
    AgentCommandV1, AgentEventPageV1, AgentEventRecordV1, AgentEventV1, AgentOpenRequestV1,
    AgentOutcomeV1, AgentProfileSnapshotV1, AgentRefusalV1, AgentReplyV1, AgentSessionPhaseV1,
    AgentSessionViewV1, AgentTurnRequestV1,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentServiceLimitsV1 {
    pub max_service_sessions: usize,
    pub max_agent_sessions: usize,
    pub max_events_per_page: u64,
}

impl Default for AgentServiceLimitsV1 {
    fn default() -> Self {
        Self {
            max_service_sessions: 1_024,
            max_agent_sessions: 4_096,
            max_events_per_page: 256,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
enum OperationInput {
    Reattach {
        expected_revision: u64,
        execution: protocol::ExecuteRequestV1,
    },
    Prompt(AgentTurnRequestV1),
    Permission {
        expected_revision: u64,
        execution: protocol::ExecuteRequestV1,
        decision: protocol::agent::AgentPermissionDecisionV1,
    },
    Advance {
        turn: protocol::AgentTurnIdV1,
        expected_revision: u64,
    },
    Cancel {
        turn: protocol::AgentTurnIdV1,
        expected_revision: u64,
    },
    Close {
        expected_revision: u64,
    },
}

#[derive(Clone, Copy)]
enum ReceiptExpectation {
    Open,
    Reattach,
    Turn(protocol::AgentTurnIdV1),
    Advance(protocol::AgentTurnIdV1),
    Cancel(protocol::AgentTurnIdV1),
    Close,
}

#[derive(Clone)]
enum OperationState {
    OutcomeUnknown,
    Completed(AgentSessionViewV1),
}

#[derive(Clone)]
struct OperationEntry {
    input: OperationInput,
    preparation: Option<StoredAgentPreparationV1>,
    state: OperationState,
}

struct AgentSessionEntry {
    request: AgentOpenRequestV1,
    open_preparation: StoredAgentPreparationV1,
    profile: AgentProfileSnapshotV1,
    revision: u64,
    phase: AgentSessionPhaseV1,
    active_turn: Option<protocol::AgentTurnIdV1>,
    capabilities: protocol::agent::AgentCapabilitiesV1,
    recovery: Option<daimon_host::agent::AgentProviderRecoveryV1>,
    events: Vec<AgentEventRecordV1>,
    operations: BTreeMap<protocol::IdempotencyKeyV1, OperationEntry>,
}

impl AgentSessionEntry {
    fn view(&self) -> AgentSessionViewV1 {
        AgentSessionViewV1 {
            session: self.request.session,
            revision: self.revision,
            phase: self.phase,
            profile_document_digest: self.profile.document_digest,
            active_turn: self.active_turn,
            last_event_cursor: self.events.last().map(|record| record.cursor),
            capabilities: self.capabilities,
        }
    }
}

#[derive(Default)]
pub struct VolatileAgentStore {
    snapshot: Option<AgentServiceSnapshotV1>,
}

impl AgentSessionStore for VolatileAgentStore {
    type Error = Infallible;

    fn load_agents(&mut self) -> Result<Option<AgentServiceSnapshotV1>, Self::Error> {
        Ok(self.snapshot.clone())
    }

    fn commit_agents(
        &mut self,
        snapshot: &AgentServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        self.snapshot = Some(snapshot.clone());
        Ok(StoreCommitV1::Committed)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AgentRecoveryError<E> {
    InvalidConfiguration,
    Store(E),
    InvalidSnapshot(AgentRefusalV1),
}

pub struct AgentService<A, T, R, C, P, S = VolatileAgentStore> {
    engine: core::Engine,
    authorizer: A,
    attempts: T,
    profiles: R,
    context: C,
    provider: P,
    store: S,
    limits: AgentServiceLimitsV1,
    service_sessions: BTreeMap<protocol::SessionHandleV1, AuthenticatedSessionV1>,
    agent_sessions: BTreeMap<protocol::AgentSessionIdV1, AgentSessionEntry>,
    next_service_session: u64,
}

impl<A, T, R, C, P> AgentService<A, T, R, C, P, VolatileAgentStore>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: AgentProfileResolver,
    C: AgentContextAssembler,
    P: AgentProvider,
{
    pub fn new(
        engine_limits: core::Limits,
        limits: AgentServiceLimitsV1,
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
            VolatileAgentStore::default(),
        )
        .ok()
    }
}

impl<A, T, R, C, P, S> AgentService<A, T, R, C, P, S>
where
    A: ExecutionAuthorizer,
    T: AttemptValidator,
    R: AgentProfileResolver,
    C: AgentContextAssembler,
    P: AgentProvider,
    S: AgentSessionStore,
{
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        engine_limits: core::Limits,
        limits: AgentServiceLimitsV1,
        authorizer: A,
        attempts: T,
        profiles: R,
        context: C,
        provider: P,
        mut store: S,
    ) -> Result<Self, AgentRecoveryError<S::Error>> {
        if limits.max_service_sessions == 0
            || limits.max_agent_sessions == 0
            || limits.max_events_per_page == 0
        {
            return Err(AgentRecoveryError::InvalidConfiguration);
        }
        let snapshot = store.load_agents().map_err(AgentRecoveryError::Store)?;
        let mut service = Self {
            engine: core::Engine::try_new(engine_limits)
                .map_err(|_| AgentRecoveryError::InvalidConfiguration)?,
            authorizer,
            attempts,
            profiles,
            context,
            provider,
            store,
            limits,
            service_sessions: BTreeMap::new(),
            agent_sessions: BTreeMap::new(),
            next_service_session: 0,
        };
        if let Some(snapshot) = snapshot {
            service.restore(snapshot)?;
        }
        Ok(service)
    }

    pub fn open_service_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<protocol::SessionHandleV1, AgentRefusalV1> {
        if self.service_sessions.len() >= self.limits.max_service_sessions {
            return Err(AgentRefusalV1::Capacity);
        }
        let handle = protocol::SessionHandleV1(self.next_service_session);
        self.next_service_session = self
            .next_service_session
            .checked_add(1)
            .ok_or(AgentRefusalV1::Capacity)?;
        self.service_sessions.insert(handle, facts);
        Ok(handle)
    }

    pub fn close_service_session(&mut self, session: protocol::SessionHandleV1) -> bool {
        self.service_sessions.remove(&session).is_some()
    }

    pub fn execute(
        &mut self,
        service_session: protocol::SessionHandleV1,
        command: AgentCommandV1,
    ) -> AgentReplyV1 {
        let Some(facts) = self.service_sessions.get(&service_session).cloned() else {
            return refused(AgentRefusalV1::UnknownServiceSession);
        };
        match command {
            AgentCommandV1::Open { request, now } => self.open_agent(&facts, request, now),
            AgentCommandV1::Prompt { request, now } => self.prompt(&facts, request, now),
            AgentCommandV1::Events {
                session,
                after,
                limit,
            } => self.events(&facts, session, after, limit),
            AgentCommandV1::Inspect { session } => self.inspect(&facts, session),
            AgentCommandV1::Reattach {
                session,
                expected_revision,
                execution,
                now,
            } => self.reattach(&facts, session, expected_revision, execution, now),
            AgentCommandV1::DecidePermission {
                session,
                expected_revision,
                execution,
                decision,
                now,
            } => {
                self.decide_permission(&facts, session, expected_revision, execution, decision, now)
            }
            AgentCommandV1::Advance {
                session,
                turn,
                expected_revision,
                idempotency_key,
                now,
            } => self.advance(
                &facts,
                session,
                turn,
                expected_revision,
                idempotency_key,
                now,
            ),
            AgentCommandV1::Cancel {
                session,
                turn,
                expected_revision,
                idempotency_key,
                now: _,
            } => self.cancel(&facts, session, turn, expected_revision, idempotency_key),
            AgentCommandV1::Close {
                session,
                expected_revision,
                idempotency_key,
                now: _,
            } => self.close(&facts, session, expected_revision, idempotency_key),
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

    fn open_agent(
        &mut self,
        facts: &AuthenticatedSessionV1,
        request: AgentOpenRequestV1,
        now: u64,
    ) -> AgentReplyV1 {
        if request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        if let Some(entry) = self.agent_sessions.get(&request.session) {
            if entry.request != request {
                return refused(AgentRefusalV1::SessionConflict);
            }
            let phase = entry.phase;
            let view = entry.view();
            if let Err(refusal) = self.authorize_prepare(facts, &request.execution, now, true) {
                return refused(refusal);
            }
            return match phase {
                AgentSessionPhaseV1::OutcomeUnknown => {
                    unknown(request.session, request.execution.idempotency_key)
                }
                _ => accepted(AgentOutcomeV1::Session(view)),
            };
        }
        if self.agent_sessions.len() >= self.limits.max_agent_sessions || !valid_open(&request) {
            return refused(AgentRefusalV1::Limit);
        }
        let open_preparation = match self.authorize_prepare(facts, &request.execution, now, false) {
            Ok(Some(preparation)) => preparation,
            Ok(None) => return refused(AgentRefusalV1::InvalidInput),
            Err(refusal) => return refused(refusal),
        };
        let profile = match self.profiles.resolve_agent_profile(facts, &request) {
            Ok(profile) if profile.harness_profile == request.execution.profile => profile,
            _ => return refused(AgentRefusalV1::InvalidInput),
        };
        let context = match self
            .context
            .assemble_agent_context(facts, &request, &profile)
        {
            Ok(context) => context,
            Err(_) => return refused(AgentRefusalV1::InvalidInput),
        };
        self.agent_sessions.insert(
            request.session,
            AgentSessionEntry {
                request: request.clone(),
                open_preparation,
                profile: profile.clone(),
                revision: 0,
                phase: AgentSessionPhaseV1::OutcomeUnknown,
                active_turn: None,
                capabilities: protocol::agent::AgentCapabilitiesV1::default(),
                recovery: None,
                events: Vec::new(),
                operations: BTreeMap::new(),
            },
        );
        if !self.persist() {
            return unknown(request.session, request.execution.idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Open {
            request: request.clone(),
            profile,
            context,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(request.session, request.execution.idempotency_key);
        };
        match self.admit_receipt(request.session, ReceiptExpectation::Open, receipt) {
            Ok(view) if self.persist() => accepted(AgentOutcomeV1::Session(view)),
            Ok(_) => {
                self.mark_session_unknown(request.session, None);
                unknown(request.session, request.execution.idempotency_key)
            }
            Err(refusal) => refused(refusal),
        }
    }

    fn prompt(
        &mut self,
        facts: &AuthenticatedSessionV1,
        request: AgentTurnRequestV1,
        now: u64,
    ) -> AgentReplyV1 {
        if request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let Some(entry) = self.agent_sessions.get(&request.session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal != request.execution.principal
            || entry.profile.harness_profile != request.execution.profile
        {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let replay = entry
            .operations
            .get(&request.execution.idempotency_key)
            .cloned();
        if let Some(operation) = replay {
            let OperationInput::Prompt(existing) = operation.input else {
                return refused(AgentRefusalV1::IdempotencyConflict);
            };
            if existing != request {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            if let Err(refusal) = self.authorize_prepare(facts, &request.execution, now, true) {
                return refused(refusal);
            }
            return match operation.state {
                OperationState::OutcomeUnknown => {
                    unknown(request.session, request.execution.idempotency_key)
                }
                OperationState::Completed(view) => accepted(AgentOutcomeV1::Session(view)),
            };
        }
        if request.expected_revision != entry.revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        if entry.phase != AgentSessionPhaseV1::Ready {
            return refused(AgentRefusalV1::Busy);
        }
        if entry
            .operations
            .values()
            .filter(|operation| matches!(operation.input, OperationInput::Prompt(_)))
            .count()
            >= usize::try_from(entry.request.budget.max_turns).unwrap_or(usize::MAX)
        {
            return refused(AgentRefusalV1::Limit);
        }
        if request.prompt.is_empty()
            || request.prompt.len() > entry.request.budget.max_prompt_bytes
            || protocol::ContentDigestV1::new(Sha256::digest(&request.prompt).into())
                != request.prompt_digest
        {
            return refused(AgentRefusalV1::InvalidInput);
        }
        let preparation = match self.authorize_prepare(facts, &request.execution, now, false) {
            Ok(Some(preparation)) => preparation,
            Ok(None) => return refused(AgentRefusalV1::InvalidInput),
            Err(refusal) => return refused(refusal),
        };
        let (profile, context) = {
            let entry = self.agent_sessions.get(&request.session).expect("checked");
            let profile = entry.profile.clone();
            let context = match self
                .context
                .assemble_agent_turn_context(facts, &request, &profile)
            {
                Ok(context) => context,
                Err(_) => return refused(AgentRefusalV1::InvalidInput),
            };
            (profile, context)
        };
        self.agent_sessions
            .get_mut(&request.session)
            .expect("checked")
            .operations
            .insert(
                request.execution.idempotency_key,
                OperationEntry {
                    input: OperationInput::Prompt(request.clone()),
                    preparation: Some(preparation),
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(request.session, request.execution.idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Prompt {
            request: request.clone(),
            profile,
            context,
            now,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(request.session, request.execution.idempotency_key);
        };
        let view = match self.admit_receipt(
            request.session,
            ReceiptExpectation::Turn(request.turn),
            receipt,
        ) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.agent_sessions
            .get_mut(&request.session)
            .expect("checked")
            .operations
            .get_mut(&request.execution.idempotency_key)
            .expect("inserted")
            .state = OperationState::Completed(view.clone());
        if self.persist() {
            accepted(AgentOutcomeV1::Session(view))
        } else {
            self.mark_operation_unknown(
                request.session,
                request.execution.idempotency_key,
                Some(request.turn),
            );
            unknown(request.session, request.execution.idempotency_key)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reattach(
        &mut self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        expected_revision: u64,
        execution: protocol::ExecuteRequestV1,
        now: u64,
    ) -> AgentReplyV1 {
        if execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if !same_reattach_scope(&entry.request.execution, &execution)
            || entry.profile.harness_profile != execution.profile
        {
            return refused(AgentRefusalV1::InvalidInput);
        }
        let input = OperationInput::Reattach {
            expected_revision,
            execution: execution.clone(),
        };
        if let Some(operation) = entry.operations.get(&execution.idempotency_key).cloned() {
            if operation.input != input {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            let current_phase = entry.phase;
            let current_view = entry.view();
            if let Err(refusal) = self.authorize_prepare(facts, &execution, now, true) {
                return refused(refusal);
            }
            return match operation.state {
                OperationState::OutcomeUnknown => unknown(session, execution.idempotency_key),
                OperationState::Completed(_)
                    if current_phase == AgentSessionPhaseV1::ReattachRequired =>
                {
                    // A completed reattach proves an older process binding. A
                    // later service reopen invalidates that ephemeral binding;
                    // replay is truthful but never redispatches it.
                    accepted(AgentOutcomeV1::Session(current_view))
                }
                OperationState::Completed(view) => accepted(AgentOutcomeV1::Session(view)),
            };
        }
        if entry.revision != expected_revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        if entry.phase != AgentSessionPhaseV1::ReattachRequired || entry.active_turn.is_some() {
            return refused(AgentRefusalV1::Busy);
        }
        if !entry.capabilities.resume_session {
            return refused(AgentRefusalV1::Unsupported);
        }
        let Some(recovery) = entry.recovery.clone() else {
            return refused(AgentRefusalV1::Unsupported);
        };
        let preparation = match self.authorize_prepare(facts, &execution, now, false) {
            Ok(Some(preparation)) => preparation,
            Ok(None) => return refused(AgentRefusalV1::InvalidInput),
            Err(refusal) => return refused(refusal),
        };
        let (original_open, profile, context) = {
            let entry = self.agent_sessions.get(&session).expect("checked");
            let original_open = entry.request.clone();
            let profile = entry.profile.clone();
            let context = match self
                .context
                .assemble_agent_context(facts, &original_open, &profile)
            {
                Ok(context) => context,
                Err(_) => return refused(AgentRefusalV1::InvalidInput),
            };
            (original_open, profile, context)
        };
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .insert(
                execution.idempotency_key,
                OperationEntry {
                    input,
                    preparation: Some(preparation),
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(session, execution.idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Reattach {
            session,
            execution: execution.clone(),
            original_open: Box::new(original_open),
            profile,
            context,
            recovery,
            now,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            self.mark_operation_unknown(session, execution.idempotency_key, None);
            let _ = self.persist();
            return unknown(session, execution.idempotency_key);
        };
        let view = match self.admit_receipt(session, ReceiptExpectation::Reattach, receipt) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .get_mut(&execution.idempotency_key)
            .expect("inserted")
            .state = OperationState::Completed(view.clone());
        if self.persist() {
            accepted(AgentOutcomeV1::Session(view))
        } else {
            self.mark_operation_unknown(session, execution.idempotency_key, None);
            unknown(session, execution.idempotency_key)
        }
    }

    fn inspect(
        &self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
    ) -> AgentReplyV1 {
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        accepted(AgentOutcomeV1::Session(entry.view()))
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_permission(
        &mut self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        expected_revision: u64,
        execution: protocol::ExecuteRequestV1,
        decision: protocol::agent::AgentPermissionDecisionV1,
        now: u64,
    ) -> AgentReplyV1 {
        if execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal != execution.principal
            || entry.profile.harness_profile != execution.profile
        {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let input = OperationInput::Permission {
            expected_revision,
            execution: execution.clone(),
            decision,
        };
        if let Some(operation) = entry.operations.get(&execution.idempotency_key).cloned() {
            if operation.input != input {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            if let Err(refusal) = self.authorize_prepare(facts, &execution, now, true) {
                return refused(refusal);
            }
            return match operation.state {
                OperationState::OutcomeUnknown => unknown(session, execution.idempotency_key),
                OperationState::Completed(view) => accepted(AgentOutcomeV1::Session(view)),
            };
        }
        if entry.revision != expected_revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        let Some(turn) = entry.active_turn else {
            return refused(AgentRefusalV1::UnknownTurn);
        };
        if entry.phase != AgentSessionPhaseV1::AwaitingPermission {
            return refused(AgentRefusalV1::Busy);
        }
        let Some(permission) = entry.events.iter().rev().find_map(|record| {
            if let AgentEventV1::Permission(permission) = &record.event
                && permission.request == decision.request
            {
                Some(permission)
            } else {
                None
            }
        }) else {
            return refused(AgentRefusalV1::UnknownPermissionRequest);
        };
        if permission.turn != turn
            || !permission
                .options
                .iter()
                .any(|option| option.id == decision.option)
        {
            return refused(AgentRefusalV1::UnknownPermissionOption);
        }
        let preparation = match self.authorize_prepare(facts, &execution, now, false) {
            Ok(Some(preparation)) => preparation,
            Ok(None) => return refused(AgentRefusalV1::InvalidInput),
            Err(refusal) => return refused(refusal),
        };
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .insert(
                execution.idempotency_key,
                OperationEntry {
                    input,
                    preparation: Some(preparation),
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(session, execution.idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::DecidePermission {
            session,
            execution: execution.clone(),
            decision,
            now,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(session, execution.idempotency_key);
        };
        let view = match self.admit_receipt(session, ReceiptExpectation::Turn(turn), receipt) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .get_mut(&execution.idempotency_key)
            .expect("inserted")
            .state = OperationState::Completed(view.clone());
        if self.persist() {
            accepted(AgentOutcomeV1::Session(view))
        } else {
            self.mark_operation_unknown(session, execution.idempotency_key, Some(turn));
            unknown(session, execution.idempotency_key)
        }
    }

    fn cancel(
        &mut self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        turn: protocol::AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: protocol::IdempotencyKeyV1,
    ) -> AgentReplyV1 {
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let input = OperationInput::Cancel {
            turn,
            expected_revision,
        };
        if let Some(operation) = entry.operations.get(&idempotency_key).cloned() {
            if operation.input != input {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            return replay_operation(session, idempotency_key, operation.state);
        }
        if entry.revision != expected_revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        if entry.active_turn != Some(turn) {
            return refused(AgentRefusalV1::UnknownTurn);
        }
        if !matches!(
            entry.phase,
            AgentSessionPhaseV1::TurnActive | AgentSessionPhaseV1::AwaitingPermission
        ) {
            return refused(AgentRefusalV1::Busy);
        }
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .insert(
                idempotency_key,
                OperationEntry {
                    input,
                    preparation: None,
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(session, idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Cancel {
            session,
            turn,
            idempotency_key,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(session, idempotency_key);
        };
        let view = match self.admit_receipt(session, ReceiptExpectation::Cancel(turn), receipt) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.complete_operation(session, idempotency_key, view)
    }

    fn advance(
        &mut self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        turn: protocol::AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: protocol::IdempotencyKeyV1,
        now: u64,
    ) -> AgentReplyV1 {
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let input = OperationInput::Advance {
            turn,
            expected_revision,
        };
        if let Some(operation) = entry.operations.get(&idempotency_key).cloned() {
            if operation.input != input {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            return replay_operation(session, idempotency_key, operation.state);
        }
        if entry.revision != expected_revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        if entry.active_turn != Some(turn) {
            return refused(AgentRefusalV1::UnknownTurn);
        }
        if entry.phase != AgentSessionPhaseV1::TurnActive {
            return refused(AgentRefusalV1::Busy);
        }
        if entry
            .operations
            .values()
            .filter(|operation| matches!(operation.input, OperationInput::Advance { .. }))
            .count()
            >= usize::try_from(entry.request.budget.max_events).unwrap_or(usize::MAX)
        {
            return refused(AgentRefusalV1::Limit);
        }
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .insert(
                idempotency_key,
                OperationEntry {
                    input,
                    preparation: None,
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(session, idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Advance {
            session,
            turn,
            idempotency_key,
            now,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(session, idempotency_key);
        };
        let view = match self.admit_receipt(session, ReceiptExpectation::Advance(turn), receipt) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.complete_operation(session, idempotency_key, view)
    }

    fn close(
        &mut self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        expected_revision: u64,
        idempotency_key: protocol::IdempotencyKeyV1,
    ) -> AgentReplyV1 {
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        let input = OperationInput::Close { expected_revision };
        if let Some(operation) = entry.operations.get(&idempotency_key).cloned() {
            if operation.input != input {
                return refused(AgentRefusalV1::IdempotencyConflict);
            }
            return replay_operation(session, idempotency_key, operation.state);
        }
        if entry.revision != expected_revision {
            return refused(AgentRefusalV1::RevisionConflict);
        }
        if entry.phase == AgentSessionPhaseV1::Closed {
            return refused(AgentRefusalV1::Closed);
        }
        if entry.phase != AgentSessionPhaseV1::Ready || entry.active_turn.is_some() {
            return refused(AgentRefusalV1::Busy);
        }
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .insert(
                idempotency_key,
                OperationEntry {
                    input,
                    preparation: None,
                    state: OperationState::OutcomeUnknown,
                },
            );
        if !self.persist() {
            return unknown(session, idempotency_key);
        }
        let invocation = AgentProviderInvocationV1::Close {
            session,
            idempotency_key,
        };
        let AgentProviderOutcomeV1::Receipt(receipt) = self.provider.invoke_agent(&invocation)
        else {
            return unknown(session, idempotency_key);
        };
        let view = match self.admit_receipt(session, ReceiptExpectation::Close, receipt) {
            Ok(view) => view,
            Err(refusal) => return refused(refusal),
        };
        self.complete_operation(session, idempotency_key, view)
    }

    fn complete_operation(
        &mut self,
        session: protocol::AgentSessionIdV1,
        idempotency_key: protocol::IdempotencyKeyV1,
        view: AgentSessionViewV1,
    ) -> AgentReplyV1 {
        self.agent_sessions
            .get_mut(&session)
            .expect("checked")
            .operations
            .get_mut(&idempotency_key)
            .expect("inserted")
            .state = OperationState::Completed(view.clone());
        if self.persist() {
            accepted(AgentOutcomeV1::Session(view))
        } else {
            let active_turn = view.active_turn;
            self.mark_operation_unknown(session, idempotency_key, active_turn);
            unknown(session, idempotency_key)
        }
    }

    fn events(
        &self,
        facts: &AuthenticatedSessionV1,
        session: protocol::AgentSessionIdV1,
        after: Option<u64>,
        limit: u64,
    ) -> AgentReplyV1 {
        let Some(entry) = self.agent_sessions.get(&session) else {
            return refused(AgentRefusalV1::UnknownAgentSession);
        };
        if entry.request.execution.principal.into_bytes() != facts.principal {
            return refused(AgentRefusalV1::PrincipalMismatch);
        }
        if limit == 0 || limit > self.limits.max_events_per_page {
            return refused(AgentRefusalV1::Limit);
        }
        let start = after.map_or(0, |cursor| cursor.saturating_add(1));
        let start = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .min(entry.events.len());
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let end = start.saturating_add(limit).min(entry.events.len());
        let entries = entry.events[start..end].to_vec();
        let next_after = (end < entry.events.len())
            .then(|| entries.last().map(|record| record.cursor))
            .flatten();
        accepted(AgentOutcomeV1::Events(AgentEventPageV1 {
            session,
            entries,
            next_after,
        }))
    }

    fn authorize_prepare(
        &mut self,
        facts: &AuthenticatedSessionV1,
        request: &protocol::ExecuteRequestV1,
        now: u64,
        replay: bool,
    ) -> Result<Option<StoredAgentPreparationV1>, AgentRefusalV1> {
        let authority = self
            .authorizer
            .authorize(facts, request, now)
            .map_err(|error| map_refusal(authority_refusal(error)))?;
        if replay {
            return Ok(None);
        }
        self.attempts
            .validate(facts, request)
            .map_err(|_| AgentRefusalV1::AttemptDenied)?;
        self.engine
            .prepare(
                core_request(request),
                &core::AuthorityEvidenceV1::new(
                    authority.decision_id,
                    core::PrincipalId::new(facts.principal),
                    authority
                        .tools
                        .iter()
                        .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
                    core::LogicalTime(authority.expires_at),
                ),
                core::LogicalTime(now),
            )
            .map_err(|error| map_refusal(core_refusal(error)))?;
        Ok(Some(StoredAgentPreparationV1 {
            authority_decision: authority.decision_id,
            authority_expires_at: authority.expires_at,
            authority_tools: authority.tools,
            prepared_at: now,
        }))
    }

    fn admit_receipt(
        &mut self,
        session: protocol::AgentSessionIdV1,
        expectation: ReceiptExpectation,
        receipt: AgentProviderReceiptV1,
    ) -> Result<AgentSessionViewV1, AgentRefusalV1> {
        let entry = self
            .agent_sessions
            .get_mut(&session)
            .ok_or(AgentRefusalV1::UnknownAgentSession)?;
        if receipt.session != session
            || receipt.provider_document_digest != entry.profile.document_digest
            || !valid_recovery_receipt(entry, expectation, &receipt)
            || !valid_phase(receipt.phase, receipt.active_turn, expectation)
            || !valid_events(
                entry,
                &receipt.events,
                expectation,
                receipt.phase,
                receipt.active_turn,
            )
        {
            entry.phase = AgentSessionPhaseV1::OutcomeUnknown;
            entry.active_turn = match expectation {
                ReceiptExpectation::Turn(turn)
                | ReceiptExpectation::Advance(turn)
                | ReceiptExpectation::Cancel(turn) => Some(turn),
                ReceiptExpectation::Open
                | ReceiptExpectation::Reattach
                | ReceiptExpectation::Close => None,
            };
            return Err(AgentRefusalV1::ProviderReceiptMismatch);
        }
        entry.events.extend(receipt.events);
        entry.revision = entry
            .revision
            .checked_add(1)
            .ok_or(AgentRefusalV1::Capacity)?;
        entry.phase = receipt.phase;
        entry.active_turn = receipt.active_turn;
        entry.capabilities = receipt.capabilities;
        entry.recovery = receipt.recovery;
        Ok(entry.view())
    }

    fn persist(&mut self) -> bool {
        let snapshot = self.snapshot();
        matches!(
            self.store.commit_agents(&snapshot),
            Ok(StoreCommitV1::Committed)
        )
    }

    fn snapshot(&self) -> AgentServiceSnapshotV1 {
        AgentServiceSnapshotV1 {
            sessions: self
                .agent_sessions
                .values()
                .map(|entry| StoredAgentSessionV1 {
                    request: entry.request.clone(),
                    open_preparation: entry.open_preparation.clone(),
                    profile: entry.profile.clone(),
                    revision: entry.revision,
                    phase: entry.phase,
                    active_turn: entry.active_turn,
                    capabilities: entry.capabilities,
                    recovery: entry.recovery.clone(),
                    events: entry.events.clone(),
                    operations: entry
                        .operations
                        .iter()
                        .map(|(idempotency_key, operation)| StoredAgentOperationV1 {
                            idempotency_key: *idempotency_key,
                            input: stored_operation_input(&operation.input),
                            preparation: operation.preparation.clone(),
                            state: match &operation.state {
                                OperationState::OutcomeUnknown => {
                                    StoredAgentOperationStateV1::OutcomeUnknown
                                }
                                OperationState::Completed(view) => {
                                    StoredAgentOperationStateV1::Completed(view.clone())
                                }
                            },
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn mark_session_unknown(
        &mut self,
        session: protocol::AgentSessionIdV1,
        active_turn: Option<protocol::AgentTurnIdV1>,
    ) {
        if let Some(entry) = self.agent_sessions.get_mut(&session) {
            entry.phase = AgentSessionPhaseV1::OutcomeUnknown;
            entry.active_turn = active_turn;
        }
    }

    fn mark_operation_unknown(
        &mut self,
        session: protocol::AgentSessionIdV1,
        idempotency_key: protocol::IdempotencyKeyV1,
        active_turn: Option<protocol::AgentTurnIdV1>,
    ) {
        if let Some(entry) = self.agent_sessions.get_mut(&session) {
            if let Some(operation) = entry.operations.get_mut(&idempotency_key) {
                operation.state = OperationState::OutcomeUnknown;
            }
            entry.phase = AgentSessionPhaseV1::OutcomeUnknown;
            entry.active_turn = active_turn;
        }
    }

    fn restore(
        &mut self,
        snapshot: AgentServiceSnapshotV1,
    ) -> Result<(), AgentRecoveryError<S::Error>> {
        if snapshot.sessions.len() > self.limits.max_agent_sessions {
            return Err(AgentRecoveryError::InvalidSnapshot(
                AgentRefusalV1::Capacity,
            ));
        }
        for stored in snapshot.sessions {
            let session = stored.request.session;
            if self.agent_sessions.contains_key(&session)
                || !valid_open(&stored.request)
                || stored.profile.harness_profile != stored.request.execution.profile
                || !valid_stored_session(&stored)
            {
                return Err(AgentRecoveryError::InvalidSnapshot(
                    AgentRefusalV1::InvalidInput,
                ));
            }
            restore_preparation(
                &mut self.engine,
                &stored.request.execution,
                &stored.open_preparation,
            )?;
            let recovered_phase = recovered_phase(&stored);
            let recovered_active_turn = recovered_active_turn(&stored);
            let mut operations = BTreeMap::new();
            for operation in stored.operations {
                if operations.contains_key(&operation.idempotency_key) {
                    return Err(AgentRecoveryError::InvalidSnapshot(
                        AgentRefusalV1::IdempotencyConflict,
                    ));
                }
                let input = restore_operation_input(operation.input);
                match (&input, operation.preparation.as_ref()) {
                    (OperationInput::Reattach { execution, .. }, Some(preparation))
                        if execution.idempotency_key == operation.idempotency_key =>
                    {
                        restore_preparation(&mut self.engine, execution, preparation)?;
                    }
                    (OperationInput::Prompt(request), Some(preparation))
                        if request.session == session
                            && request.execution.idempotency_key == operation.idempotency_key =>
                    {
                        restore_preparation(&mut self.engine, &request.execution, preparation)?;
                    }
                    (OperationInput::Permission { execution, .. }, Some(preparation))
                        if execution.idempotency_key == operation.idempotency_key =>
                    {
                        restore_preparation(&mut self.engine, execution, preparation)?;
                    }
                    (
                        OperationInput::Advance { .. }
                        | OperationInput::Cancel { .. }
                        | OperationInput::Close { .. },
                        None,
                    ) => {}
                    _ => {
                        return Err(AgentRecoveryError::InvalidSnapshot(
                            AgentRefusalV1::InvalidInput,
                        ));
                    }
                }
                let state = match operation.state {
                    StoredAgentOperationStateV1::OutcomeUnknown => OperationState::OutcomeUnknown,
                    StoredAgentOperationStateV1::Completed(view)
                        if valid_stored_view(
                            session,
                            stored.profile.document_digest,
                            stored.revision,
                            &view,
                        ) =>
                    {
                        OperationState::Completed(view)
                    }
                    StoredAgentOperationStateV1::Completed(_) => {
                        return Err(AgentRecoveryError::InvalidSnapshot(
                            AgentRefusalV1::ProviderReceiptMismatch,
                        ));
                    }
                };
                operations.insert(
                    operation.idempotency_key,
                    OperationEntry {
                        input,
                        preparation: operation.preparation,
                        state,
                    },
                );
            }
            self.agent_sessions.insert(
                session,
                AgentSessionEntry {
                    request: stored.request,
                    open_preparation: stored.open_preparation,
                    profile: stored.profile,
                    revision: stored.revision,
                    phase: recovered_phase,
                    active_turn: recovered_active_turn,
                    capabilities: stored.capabilities,
                    recovery: stored.recovery,
                    events: stored.events,
                    operations,
                },
            );
        }
        Ok(())
    }
}

fn stored_operation_input(input: &OperationInput) -> StoredAgentOperationInputV1 {
    match input {
        OperationInput::Reattach {
            expected_revision,
            execution,
        } => StoredAgentOperationInputV1::Reattach {
            expected_revision: *expected_revision,
            execution: execution.clone(),
        },
        OperationInput::Prompt(request) => StoredAgentOperationInputV1::Prompt(request.clone()),
        OperationInput::Permission {
            expected_revision,
            execution,
            decision,
        } => StoredAgentOperationInputV1::Permission {
            expected_revision: *expected_revision,
            execution: execution.clone(),
            decision: *decision,
        },
        OperationInput::Cancel {
            turn,
            expected_revision,
        } => StoredAgentOperationInputV1::Cancel {
            turn: *turn,
            expected_revision: *expected_revision,
        },
        OperationInput::Advance {
            turn,
            expected_revision,
        } => StoredAgentOperationInputV1::Advance {
            turn: *turn,
            expected_revision: *expected_revision,
        },
        OperationInput::Close { expected_revision } => StoredAgentOperationInputV1::Close {
            expected_revision: *expected_revision,
        },
    }
}

fn restore_operation_input(input: StoredAgentOperationInputV1) -> OperationInput {
    match input {
        StoredAgentOperationInputV1::Reattach {
            expected_revision,
            execution,
        } => OperationInput::Reattach {
            expected_revision,
            execution,
        },
        StoredAgentOperationInputV1::Prompt(request) => OperationInput::Prompt(request),
        StoredAgentOperationInputV1::Permission {
            expected_revision,
            execution,
            decision,
        } => OperationInput::Permission {
            expected_revision,
            execution,
            decision,
        },
        StoredAgentOperationInputV1::Cancel {
            turn,
            expected_revision,
        } => OperationInput::Cancel {
            turn,
            expected_revision,
        },
        StoredAgentOperationInputV1::Advance {
            turn,
            expected_revision,
        } => OperationInput::Advance {
            turn,
            expected_revision,
        },
        StoredAgentOperationInputV1::Close { expected_revision } => {
            OperationInput::Close { expected_revision }
        }
    }
}

fn restore_preparation<E>(
    engine: &mut core::Engine,
    request: &protocol::ExecuteRequestV1,
    preparation: &StoredAgentPreparationV1,
) -> Result<(), AgentRecoveryError<E>> {
    engine
        .prepare(
            core_request(request),
            &core::AuthorityEvidenceV1::new(
                preparation.authority_decision,
                core::PrincipalId::new(request.principal.into_bytes()),
                preparation
                    .authority_tools
                    .iter()
                    .map(|tool| core::ToolCapabilityId::new(tool.into_bytes())),
                core::LogicalTime(preparation.authority_expires_at),
            ),
            core::LogicalTime(preparation.prepared_at),
        )
        .map(|_| ())
        .map_err(|error| AgentRecoveryError::InvalidSnapshot(map_refusal(core_refusal(error))))
}

fn valid_stored_session(stored: &StoredAgentSessionV1) -> bool {
    let budget = stored.request.budget;
    let Ok(event_count) = u64::try_from(stored.events.len()) else {
        return false;
    };
    if event_count > budget.max_events
        || stored.events.iter().enumerate().any(|(index, record)| {
            record.cursor != u64::try_from(index).unwrap_or(u64::MAX)
                || event_bytes(&record.event) > budget.max_event_bytes
        })
    {
        return false;
    }
    let permissions = stored
        .events
        .iter()
        .filter(|record| matches!(record.event, AgentEventV1::Permission(_)))
        .count();
    if permissions > usize::try_from(budget.max_permission_requests).unwrap_or(usize::MAX) {
        return false;
    }
    if stored.recovery.as_ref().is_some_and(|recovery| {
        recovery.locator.is_empty()
            || recovery.locator.len() > daimon_host::agent::MAX_AGENT_PROVIDER_LOCATOR_BYTES
    }) || (stored.capabilities.resume_session != stored.recovery.is_some())
    {
        return false;
    }
    if match stored.phase {
        AgentSessionPhaseV1::TurnActive | AgentSessionPhaseV1::AwaitingPermission => {
            stored.active_turn.is_none()
        }
        AgentSessionPhaseV1::Ready
        | AgentSessionPhaseV1::ReattachRequired
        | AgentSessionPhaseV1::Closed => stored.active_turn.is_some(),
        AgentSessionPhaseV1::Opening => true,
        AgentSessionPhaseV1::OutcomeUnknown => false,
    } {
        return false;
    }
    let completed = stored
        .operations
        .iter()
        .filter(|operation| matches!(operation.state, StoredAgentOperationStateV1::Completed(_)))
        .count();
    let expected_revision = if stored.revision == 0 {
        0
    } else {
        u64::try_from(completed)
            .ok()
            .and_then(|value| value.checked_add(1))
            .unwrap_or(u64::MAX)
    };
    stored.revision == expected_revision
}

fn recovered_phase(stored: &StoredAgentSessionV1) -> AgentSessionPhaseV1 {
    match stored.phase {
        AgentSessionPhaseV1::Closed => AgentSessionPhaseV1::Closed,
        AgentSessionPhaseV1::Ready | AgentSessionPhaseV1::ReattachRequired
            if stored.capabilities.resume_session && stored.recovery.is_some() =>
        {
            AgentSessionPhaseV1::ReattachRequired
        }
        AgentSessionPhaseV1::Opening
        | AgentSessionPhaseV1::Ready
        | AgentSessionPhaseV1::ReattachRequired
        | AgentSessionPhaseV1::TurnActive
        | AgentSessionPhaseV1::AwaitingPermission
        | AgentSessionPhaseV1::OutcomeUnknown => AgentSessionPhaseV1::OutcomeUnknown,
    }
}

fn recovered_active_turn(stored: &StoredAgentSessionV1) -> Option<protocol::AgentTurnIdV1> {
    match stored.phase {
        AgentSessionPhaseV1::TurnActive
        | AgentSessionPhaseV1::AwaitingPermission
        | AgentSessionPhaseV1::OutcomeUnknown => stored.active_turn,
        AgentSessionPhaseV1::Opening
        | AgentSessionPhaseV1::Ready
        | AgentSessionPhaseV1::ReattachRequired
        | AgentSessionPhaseV1::Closed => None,
    }
}

fn same_reattach_scope(
    original: &protocol::ExecuteRequestV1,
    current: &protocol::ExecuteRequestV1,
) -> bool {
    original.task_attempt == current.task_attempt
        && original.principal == current.principal
        && original.profile == current.profile
        && original.context == current.context
        && original.tools == current.tools
}

fn valid_stored_view(
    session: protocol::AgentSessionIdV1,
    profile_document_digest: protocol::ContentDigestV1,
    current_revision: u64,
    view: &AgentSessionViewV1,
) -> bool {
    view.session == session
        && view.profile_document_digest == profile_document_digest
        && view.revision > 0
        && view.revision <= current_revision
}

fn valid_open(request: &AgentOpenRequestV1) -> bool {
    let budget = request.budget;
    budget.max_elapsed_millis > 0
        && budget.max_turns > 0
        && budget.max_events > 0
        && budget.max_event_bytes > 0
        && budget.max_prompt_bytes > 0
        && request
            .execution
            .context
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == request.execution.context.len()
}

fn valid_phase(
    phase: AgentSessionPhaseV1,
    active: Option<protocol::AgentTurnIdV1>,
    expectation: ReceiptExpectation,
) -> bool {
    match (phase, active, expectation) {
        (AgentSessionPhaseV1::Ready, None, ReceiptExpectation::Open) => true,
        (AgentSessionPhaseV1::Ready, None, ReceiptExpectation::Reattach) => true,
        (
            AgentSessionPhaseV1::Ready,
            None,
            ReceiptExpectation::Turn(_)
            | ReceiptExpectation::Advance(_)
            | ReceiptExpectation::Cancel(_),
        ) => true,
        (
            AgentSessionPhaseV1::TurnActive | AgentSessionPhaseV1::AwaitingPermission,
            Some(turn),
            ReceiptExpectation::Turn(expected)
            | ReceiptExpectation::Advance(expected)
            | ReceiptExpectation::Cancel(expected),
        ) => turn == expected,
        (AgentSessionPhaseV1::Closed, None, ReceiptExpectation::Close) => true,
        _ => false,
    }
}

fn valid_recovery_receipt(
    entry: &AgentSessionEntry,
    expectation: ReceiptExpectation,
    receipt: &AgentProviderReceiptV1,
) -> bool {
    let valid_locator = receipt.recovery.as_ref().is_some_and(|recovery| {
        !recovery.locator.is_empty()
            && recovery.locator.len() <= daimon_host::agent::MAX_AGENT_PROVIDER_LOCATOR_BYTES
    });
    match expectation {
        ReceiptExpectation::Open => {
            receipt.capabilities.resume_session == valid_locator
                && (!receipt.capabilities.resume_session || receipt.recovery.is_some())
        }
        ReceiptExpectation::Reattach => {
            receipt.phase == AgentSessionPhaseV1::Ready
                && receipt.capabilities == entry.capabilities
                && receipt.recovery == entry.recovery
                && valid_locator
        }
        ReceiptExpectation::Turn(_)
        | ReceiptExpectation::Advance(_)
        | ReceiptExpectation::Cancel(_) => receipt.recovery == entry.recovery,
        ReceiptExpectation::Close => receipt.recovery.is_none(),
    }
}

fn valid_events(
    entry: &AgentSessionEntry,
    events: &[AgentEventRecordV1],
    expectation: ReceiptExpectation,
    phase: AgentSessionPhaseV1,
    active_turn: Option<protocol::AgentTurnIdV1>,
) -> bool {
    let expected_turn = match expectation {
        ReceiptExpectation::Turn(turn)
        | ReceiptExpectation::Advance(turn)
        | ReceiptExpectation::Cancel(turn) => Some(turn),
        ReceiptExpectation::Open | ReceiptExpectation::Reattach | ReceiptExpectation::Close => None,
    };
    let Ok(total) = u64::try_from(entry.events.len().saturating_add(events.len())) else {
        return false;
    };
    if total > entry.request.budget.max_events {
        return false;
    }
    let start = u64::try_from(entry.events.len()).unwrap_or(u64::MAX);
    if events.iter().enumerate().any(|(index, record)| {
        record.cursor != start.saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
            || event_bytes(&record.event) > entry.request.budget.max_event_bytes
    }) {
        return false;
    }
    let existing_permission_count = entry
        .events
        .iter()
        .filter(|record| matches!(record.event, AgentEventV1::Permission(_)))
        .count();
    let permissions = events
        .iter()
        .filter_map(|record| match &record.event {
            AgentEventV1::Permission(request) => Some(request),
            _ => None,
        })
        .collect::<Vec<_>>();
    if existing_permission_count.saturating_add(permissions.len())
        > usize::try_from(entry.request.budget.max_permission_requests).unwrap_or(usize::MAX)
        || permissions.iter().any(|request| {
            request.options.is_empty()
                || request.turn != expected_turn.unwrap_or(request.turn)
                || request
                    .options
                    .iter()
                    .map(|option| option.id)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != request.options.len()
        })
    {
        return false;
    }
    let finished = events
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            if let AgentEventV1::TurnFinished { turn, .. } = record.event {
                Some((index, turn))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if finished.len() > 1
        || finished
            .first()
            .is_some_and(|(index, turn)| Some(*turn) != expected_turn || *index + 1 != events.len())
    {
        return false;
    }
    match (expectation, phase, active_turn) {
        (
            ReceiptExpectation::Open | ReceiptExpectation::Reattach,
            AgentSessionPhaseV1::Ready,
            None,
        ) => events.is_empty() && finished.is_empty(),
        (ReceiptExpectation::Close, AgentSessionPhaseV1::Closed, None) => {
            events.is_empty() && finished.is_empty()
        }
        (ReceiptExpectation::Turn(_), AgentSessionPhaseV1::Ready, None) => {
            events.last().is_some_and(|record| {
                matches!(
                    &record.event,
                    AgentEventV1::TurnFinished {
                        disposition,
                        stop_reason,
                        ..
                    } if valid_terminal(*disposition, *stop_reason)
                )
            })
        }
        (ReceiptExpectation::Advance(_), AgentSessionPhaseV1::Ready, None) => {
            events.last().is_some_and(|record| {
                matches!(
                    &record.event,
                    AgentEventV1::TurnFinished {
                        disposition,
                        stop_reason,
                        ..
                    } if valid_terminal(*disposition, *stop_reason)
                )
            })
        }
        (ReceiptExpectation::Cancel(turn), AgentSessionPhaseV1::Ready, None) => {
            events.last().is_some_and(|record| {
                matches!(
                    record.event,
                    AgentEventV1::TurnFinished {
                        turn: finished_turn,
                        disposition: protocol::ExecutionDispositionV1::Cancelled,
                        stop_reason: protocol::agent::AgentTurnStopReasonV1::Cancelled,
                        ..
                    } if finished_turn == turn
                )
            })
        }
        (ReceiptExpectation::Turn(turn), AgentSessionPhaseV1::AwaitingPermission, Some(active)) => {
            active == turn
                && finished.is_empty()
                && permissions
                    .last()
                    .is_some_and(|request| request.turn == turn)
        }
        (
            ReceiptExpectation::Advance(turn),
            AgentSessionPhaseV1::AwaitingPermission,
            Some(active),
        ) => {
            active == turn
                && finished.is_empty()
                && permissions
                    .last()
                    .is_some_and(|request| request.turn == turn)
        }
        (ReceiptExpectation::Turn(turn), AgentSessionPhaseV1::TurnActive, Some(active)) => {
            active == turn && finished.is_empty()
        }
        (ReceiptExpectation::Advance(turn), AgentSessionPhaseV1::TurnActive, Some(active)) => {
            active == turn && finished.is_empty()
        }
        _ => false,
    }
}

fn replay_operation(
    session: protocol::AgentSessionIdV1,
    idempotency_key: protocol::IdempotencyKeyV1,
    state: OperationState,
) -> AgentReplyV1 {
    match state {
        OperationState::OutcomeUnknown => unknown(session, idempotency_key),
        OperationState::Completed(view) => accepted(AgentOutcomeV1::Session(view)),
    }
}

fn valid_terminal(
    disposition: protocol::ExecutionDispositionV1,
    reason: protocol::agent::AgentTurnStopReasonV1,
) -> bool {
    matches!(
        (disposition, reason),
        (
            protocol::ExecutionDispositionV1::Completed,
            protocol::agent::AgentTurnStopReasonV1::EndTurn
        ) | (
            protocol::ExecutionDispositionV1::Cancelled,
            protocol::agent::AgentTurnStopReasonV1::Cancelled
        ) | (
            protocol::ExecutionDispositionV1::TimedOut,
            protocol::agent::AgentTurnStopReasonV1::TimedOut
        ) | (
            protocol::ExecutionDispositionV1::Failed,
            protocol::agent::AgentTurnStopReasonV1::Failed
        ) | (
            protocol::ExecutionDispositionV1::Uncertain,
            protocol::agent::AgentTurnStopReasonV1::Disconnected
                | protocol::agent::AgentTurnStopReasonV1::OutcomeUnknown
        )
    )
}

fn event_bytes(event: &AgentEventV1) -> usize {
    match event {
        AgentEventV1::AssistantMessage { bytes }
        | AgentEventV1::Thought { bytes }
        | AgentEventV1::Plan { bytes } => bytes.len(),
        AgentEventV1::ToolCall { title, detail } => title.len().saturating_add(detail.len()),
        AgentEventV1::Terminal { stream, bytes } => stream.len().saturating_add(bytes.len()),
        AgentEventV1::Permission(request) => request
            .capability
            .len()
            .saturating_add(request.description.len())
            .saturating_add(
                request
                    .options
                    .iter()
                    .map(|option| option.label.len())
                    .sum::<usize>(),
            ),
        AgentEventV1::FileChange { path, .. } | AgentEventV1::FileRead { path, .. } => path.len(),
        AgentEventV1::Usage { .. } | AgentEventV1::TurnFinished { .. } => 0,
    }
}

fn map_refusal(refusal: protocol::RefusalV1) -> AgentRefusalV1 {
    match refusal {
        protocol::RefusalV1::AuthorityDenied | protocol::RefusalV1::ToolNotAuthorized => {
            AgentRefusalV1::AuthorityDenied
        }
        protocol::RefusalV1::AuthorityExpired => AgentRefusalV1::AuthorityExpired,
        protocol::RefusalV1::AttemptDenied => AgentRefusalV1::AttemptDenied,
        protocol::RefusalV1::IdempotencyConflict | protocol::RefusalV1::ExecutionConflict => {
            AgentRefusalV1::IdempotencyConflict
        }
        protocol::RefusalV1::Capacity | protocol::RefusalV1::Exhausted => AgentRefusalV1::Capacity,
        _ => AgentRefusalV1::InvalidInput,
    }
}

fn accepted(outcome: AgentOutcomeV1) -> AgentReplyV1 {
    AgentReplyV1::Accepted(outcome)
}

fn refused(refusal: AgentRefusalV1) -> AgentReplyV1 {
    AgentReplyV1::Refused(refusal)
}

fn unknown(
    session: protocol::AgentSessionIdV1,
    idempotency_key: protocol::IdempotencyKeyV1,
) -> AgentReplyV1 {
    accepted(AgentOutcomeV1::OutcomeUnknown {
        session,
        idempotency_key,
    })
}
