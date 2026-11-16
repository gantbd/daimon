//! Daimon-owned exact-state guards for interactive agent operations.
//!
//! Each operation observes the selected session on the same authenticated port,
//! fences exact current state, and attempts the mutation once. A transport
//! failure is never retried because the effect may already have been committed.
#![forbid(unsafe_code)]

use daimon_client::{AgentReadOnlyClient, AgentServicePort, AgentSessionClient};
use daimon_protocol::agent::{
    AgentEventV1, AgentOutcomeV1, AgentPermissionDecisionV1, AgentPermissionOptionKindV1,
    AgentPermissionRequestV1, AgentRefusalV1, AgentReplyV1, AgentSessionPhaseV1,
    AgentSessionViewV1, AgentTurnRequestV1,
};
use daimon_protocol::{
    AgentPermissionOptionIdV1, AgentPermissionRequestIdV1, AgentSessionIdV1, AgentTurnIdV1,
    ContentDigestV1, ContextReferenceIdV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1,
    HarnessProfileIdV1, IdempotencyKeyV1, PrincipalIdV1, SessionHandleV1, TaskAttemptRefV1,
    ToolCapabilityIdV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const ADVANCE_CAPABILITY: &str = "agents.session.advance.v1";
pub const PROMPT_CAPABILITY: &str = "agents.session.prompt.v1";
pub const PERMISSION_CAPABILITY: &str = "agents.session.permission.v1";
pub const CANCEL_CAPABILITY: &str = "agents.session.cancel.v1";
pub const CAPABILITY: &str = ADVANCE_CAPABILITY;
pub const MAX_PROMPT_BYTES: usize = 1024 * 1024;
pub const MAX_CONTEXT_REFERENCES: usize = 64;
pub const MAX_TOOLS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptRequest {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub expected_revision: u64,
    pub execution: ExecuteRequestV1,
    pub prompt: Vec<u8>,
    pub now: u64,
}

impl PromptRequest {
    pub fn prompt_digest(&self) -> ContentDigestV1 {
        ContentDigestV1::new(Sha256::digest(&self.prompt).into())
    }

    pub fn execution_digest(&self) -> ContentDigestV1 {
        ContentDigestV1::new(digest_execution(&self.execution))
    }

    pub fn confirmation(&self) -> String {
        format!(
            "PROMPT DAIMON SESSION {} TURN {} REVISION {} DIGEST {} ENVELOPE {} KEY {} AT {}",
            hex(&self.session.into_bytes()),
            hex(&self.turn.into_bytes()),
            self.expected_revision,
            hex(&self.prompt_digest().into_bytes()),
            hex(&self.execution_digest().into_bytes()),
            hex(&self.execution.idempotency_key.into_bytes()),
            self.now,
        )
    }

    fn turn_request(&self) -> AgentTurnRequestV1 {
        AgentTurnRequestV1 {
            session: self.session,
            turn: self.turn,
            expected_revision: self.expected_revision,
            execution: self.execution.clone(),
            prompt_digest: self.prompt_digest(),
            prompt: self.prompt.clone(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PromptError<E> {
    InvalidPrompt,
    ConfirmationMismatch { required: String },
    ObservationTransport(E),
    ObservationRefused(AgentRefusalV1),
    InvalidObservation,
    SessionChanged { actual: AgentSessionViewV1 },
    MutationTransport(E),
    MutationRefused(AgentRefusalV1),
    InvalidMutationReply,
}

pub fn prompt<P: AgentServicePort>(
    service_session: SessionHandleV1,
    port: P,
    request: PromptRequest,
    confirmation: &str,
) -> Result<AgentOutcomeV1, PromptError<P::Error>> {
    if request.prompt.is_empty() || request.prompt.len() > MAX_PROMPT_BYTES {
        return Err(PromptError::InvalidPrompt);
    }
    let required = request.confirmation();
    if confirmation != required {
        return Err(PromptError::ConfirmationMismatch { required });
    }

    let mut observer = AgentReadOnlyClient::new(service_session, port);
    let current = match observer.inspect(request.session) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            view
        }
        Ok(AgentReplyV1::Accepted(_)) => return Err(PromptError::InvalidObservation),
        Ok(AgentReplyV1::Refused(refusal)) => {
            return Err(PromptError::ObservationRefused(refusal));
        }
        Err(error) => return Err(PromptError::ObservationTransport(error)),
    };
    if current.revision != request.expected_revision
        || current.phase != AgentSessionPhaseV1::Ready
        || current.active_turn.is_some()
    {
        return Err(PromptError::SessionChanged { actual: current });
    }

    let expected_key = request.execution.idempotency_key;
    let expected_session = request.session;
    let now = request.now;
    let turn = request.turn_request();
    let mut operator = AgentSessionClient::new(service_session, observer.into_port());
    match operator.prompt(turn, now) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == expected_session =>
        {
            Ok(AgentOutcomeV1::Session(view))
        }
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session,
            idempotency_key,
        })) if session == expected_session && idempotency_key == expected_key => {
            Ok(AgentOutcomeV1::OutcomeUnknown {
                session,
                idempotency_key,
            })
        }
        Ok(AgentReplyV1::Accepted(_)) => Err(PromptError::InvalidMutationReply),
        Ok(AgentReplyV1::Refused(refusal)) => Err(PromptError::MutationRefused(refusal)),
        Err(error) => Err(PromptError::MutationTransport(error)),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRequest {
    pub session: AgentSessionIdV1,
    pub expected_revision: u64,
    pub event_cursor: u64,
    pub permission_request: AgentPermissionRequestIdV1,
    pub option: AgentPermissionOptionIdV1,
    pub execution: ExecuteRequestV1,
    pub now: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PermissionError<E> {
    ObservationTransport(E),
    ObservationRefused(AgentRefusalV1),
    InvalidObservation,
    SessionChanged { actual: AgentSessionViewV1 },
    ChallengeChanged,
    ConfirmationMismatch { required: String },
    MutationTransport(E),
    MutationRefused(AgentRefusalV1),
    InvalidMutationReply,
}

pub fn decide_permission<P: AgentServicePort>(
    service_session: SessionHandleV1,
    port: P,
    request: PermissionRequest,
    confirmation: &str,
) -> Result<AgentOutcomeV1, PermissionError<P::Error>> {
    let mut observer = AgentReadOnlyClient::new(service_session, port);
    let current = match observer.inspect(request.session) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            view
        }
        Ok(AgentReplyV1::Accepted(_)) => return Err(PermissionError::InvalidObservation),
        Ok(AgentReplyV1::Refused(refusal)) => {
            return Err(PermissionError::ObservationRefused(refusal));
        }
        Err(error) => return Err(PermissionError::ObservationTransport(error)),
    };
    if current.revision != request.expected_revision
        || current.phase != AgentSessionPhaseV1::AwaitingPermission
        || current.active_turn.is_none()
    {
        return Err(PermissionError::SessionChanged { actual: current });
    }

    let after = request.event_cursor.checked_sub(1);
    let challenge = match observer.events(request.session, after, 1) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(page)))
            if page.session == request.session && page.entries.len() == 1 =>
        {
            let record = &page.entries[0];
            match &record.event {
                AgentEventV1::Permission(challenge)
                    if record.cursor == request.event_cursor
                        && challenge.request == request.permission_request
                        && Some(challenge.turn) == current.active_turn
                        && challenge
                            .options
                            .iter()
                            .any(|option| option.id == request.option) =>
                {
                    challenge.clone()
                }
                _ => return Err(PermissionError::ChallengeChanged),
            }
        }
        Ok(AgentReplyV1::Accepted(_)) => return Err(PermissionError::InvalidObservation),
        Ok(AgentReplyV1::Refused(refusal)) => {
            return Err(PermissionError::ObservationRefused(refusal));
        }
        Err(error) => return Err(PermissionError::ObservationTransport(error)),
    };
    let required = permission_confirmation(&request, &challenge);
    if confirmation != required {
        return Err(PermissionError::ConfirmationMismatch { required });
    }

    let expected_session = request.session;
    let expected_key = request.execution.idempotency_key;
    let mut operator = AgentSessionClient::new(service_session, observer.into_port());
    match operator.decide_permission(
        request.session,
        request.expected_revision,
        request.execution,
        AgentPermissionDecisionV1 {
            request: request.permission_request,
            option: request.option,
        },
        request.now,
    ) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == expected_session =>
        {
            Ok(AgentOutcomeV1::Session(view))
        }
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session,
            idempotency_key,
        })) if session == expected_session && idempotency_key == expected_key => {
            Ok(AgentOutcomeV1::OutcomeUnknown {
                session,
                idempotency_key,
            })
        }
        Ok(AgentReplyV1::Accepted(_)) => Err(PermissionError::InvalidMutationReply),
        Ok(AgentReplyV1::Refused(refusal)) => Err(PermissionError::MutationRefused(refusal)),
        Err(error) => Err(PermissionError::MutationTransport(error)),
    }
}

fn permission_confirmation(
    request: &PermissionRequest,
    challenge: &AgentPermissionRequestV1,
) -> String {
    format!(
        "DECIDE DAIMON PERMISSION SESSION {} REVISION {} CURSOR {} REQUEST {} OPTION {} CHALLENGE {} ENVELOPE {} KEY {} AT {}",
        hex(&request.session.into_bytes()),
        request.expected_revision,
        request.event_cursor,
        hex(&request.permission_request.into_bytes()),
        hex(&request.option.into_bytes()),
        hex(&digest_permission_challenge(challenge)),
        hex(&digest_execution(&request.execution)),
        hex(&request.execution.idempotency_key.into_bytes()),
        request.now,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptDocumentError {
    Malformed,
    UnsupportedSchema,
    InvalidIdentifier,
    Limit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptDocument {
    schema: u8,
    session: String,
    turn: String,
    expected_revision: u64,
    now: u64,
    execution: ExecutionDocument,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionDocument {
    schema: u8,
    session: String,
    expected_revision: u64,
    event_cursor: u64,
    permission_request: String,
    option: String,
    now: u64,
    execution: ExecutionDocument,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionDocument {
    execution_id: String,
    task_key: String,
    task_incarnation: u64,
    attempt_number: u32,
    principal: String,
    profile: String,
    idempotency_key: String,
    context: Vec<String>,
    tools: Vec<String>,
    budget: BudgetDocument,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetDocument {
    max_elapsed_millis: u64,
    max_input_tokens: u64,
    max_output_tokens: u64,
    max_tool_calls: u32,
    max_context_bytes: usize,
    max_output_bytes: usize,
}

/// Parses the shared, credential-free V1 operator document used by standalone
/// Daimon and Workbench. Prompt bytes are supplied separately so they never
/// need to appear in argv or the execution document.
pub fn parse_prompt_document(
    document: &[u8],
    prompt: Vec<u8>,
) -> Result<PromptRequest, PromptDocumentError> {
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES {
        return Err(PromptDocumentError::Limit);
    }
    let document: PromptDocument =
        serde_json::from_slice(document).map_err(|_| PromptDocumentError::Malformed)?;
    if document.schema != 1 {
        return Err(PromptDocumentError::UnsupportedSchema);
    }
    if document.execution.context.len() > MAX_CONTEXT_REFERENCES
        || document.execution.tools.len() > MAX_TOOLS
    {
        return Err(PromptDocumentError::Limit);
    }
    let execution = parse_execution(&document.execution)?;
    Ok(PromptRequest {
        session: AgentSessionIdV1::new(id16(&document.session)?),
        turn: AgentTurnIdV1::new(id16(&document.turn)?),
        expected_revision: document.expected_revision,
        execution,
        prompt,
        now: document.now,
    })
}

pub fn parse_permission_document(
    document: &[u8],
) -> Result<PermissionRequest, PromptDocumentError> {
    let document: PermissionDocument =
        serde_json::from_slice(document).map_err(|_| PromptDocumentError::Malformed)?;
    if document.schema != 1 {
        return Err(PromptDocumentError::UnsupportedSchema);
    }
    if document.execution.context.len() > MAX_CONTEXT_REFERENCES
        || document.execution.tools.len() > MAX_TOOLS
    {
        return Err(PromptDocumentError::Limit);
    }
    Ok(PermissionRequest {
        session: AgentSessionIdV1::new(id16(&document.session)?),
        expected_revision: document.expected_revision,
        event_cursor: document.event_cursor,
        permission_request: AgentPermissionRequestIdV1::new(id16(&document.permission_request)?),
        option: AgentPermissionOptionIdV1::new(id16(&document.option)?),
        execution: parse_execution(&document.execution)?,
        now: document.now,
    })
}

fn parse_execution(document: &ExecutionDocument) -> Result<ExecuteRequestV1, PromptDocumentError> {
    Ok(ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new(id16(&document.execution_id)?),
        task_attempt: TaskAttemptRefV1 {
            task_key: id16(&document.task_key)?,
            task_incarnation: document.task_incarnation,
            attempt_number: document.attempt_number,
        },
        principal: PrincipalIdV1::new(id16(&document.principal)?),
        profile: HarnessProfileIdV1::new(id16(&document.profile)?),
        idempotency_key: IdempotencyKeyV1::new(id16(&document.idempotency_key)?),
        context: document
            .context
            .iter()
            .map(|value| id16(value).map(ContextReferenceIdV1::new))
            .collect::<Result<Vec<_>, _>>()?,
        tools: document
            .tools
            .iter()
            .map(|value| id16(value).map(ToolCapabilityIdV1::new))
            .collect::<Result<Vec<_>, _>>()?,
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: document.budget.max_elapsed_millis,
            max_input_tokens: document.budget.max_input_tokens,
            max_output_tokens: document.budget.max_output_tokens,
            max_tool_calls: document.budget.max_tool_calls,
            max_context_bytes: document.budget.max_context_bytes,
            max_output_bytes: document.budget.max_output_bytes,
        },
    })
}

fn id16(value: &str) -> Result<[u8; 16], PromptDocumentError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PromptDocumentError::InvalidIdentifier);
    }
    let mut output = [0; 16];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| PromptDocumentError::InvalidIdentifier)?;
    }
    Ok(output)
}

fn digest_execution(request: &ExecuteRequestV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"daimon-execution-envelope-v1\0");
    digest.update(request.execution_id.into_bytes());
    digest.update(request.task_attempt.task_key);
    digest.update(request.task_attempt.task_incarnation.to_be_bytes());
    digest.update(request.task_attempt.attempt_number.to_be_bytes());
    digest.update(request.principal.into_bytes());
    digest.update(request.profile.into_bytes());
    digest.update(request.idempotency_key.into_bytes());
    digest.update((request.context.len() as u64).to_be_bytes());
    for reference in &request.context {
        digest.update(reference.into_bytes());
    }
    digest.update((request.tools.len() as u64).to_be_bytes());
    for tool in &request.tools {
        digest.update(tool.into_bytes());
    }
    digest.update(request.budget.max_elapsed_millis.to_be_bytes());
    digest.update(request.budget.max_input_tokens.to_be_bytes());
    digest.update(request.budget.max_output_tokens.to_be_bytes());
    digest.update(request.budget.max_tool_calls.to_be_bytes());
    digest.update((request.budget.max_context_bytes as u64).to_be_bytes());
    digest.update((request.budget.max_output_bytes as u64).to_be_bytes());
    digest.finalize().into()
}

fn digest_permission_challenge(challenge: &AgentPermissionRequestV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"daimon-permission-challenge-v1\0");
    digest.update(challenge.request.into_bytes());
    digest.update(challenge.turn.into_bytes());
    digest.update((challenge.capability.len() as u64).to_be_bytes());
    digest.update(&challenge.capability);
    digest.update((challenge.description.len() as u64).to_be_bytes());
    digest.update(&challenge.description);
    digest.update((challenge.options.len() as u64).to_be_bytes());
    for option in &challenge.options {
        digest.update(option.id.into_bytes());
        digest.update([match option.kind {
            AgentPermissionOptionKindV1::AllowOnce => 0,
            AgentPermissionOptionKindV1::AllowAlways => 1,
            AgentPermissionOptionKindV1::RejectOnce => 2,
            AgentPermissionOptionKindV1::RejectAlways => 3,
        }]);
        digest.update((option.label.len() as u64).to_be_bytes());
        digest.update(&option.label);
    }
    digest.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvanceRequest {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub expected_revision: u64,
    pub idempotency_key: IdempotencyKeyV1,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelRequest {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub expected_revision: u64,
    pub idempotency_key: IdempotencyKeyV1,
    pub now: u64,
}

impl CancelRequest {
    pub fn confirmation(self) -> String {
        format!(
            "CANCEL DAIMON SESSION {} TURN {} REVISION {} KEY {} AT {}",
            hex(&self.session.into_bytes()),
            hex(&self.turn.into_bytes()),
            self.expected_revision,
            hex(&self.idempotency_key.into_bytes()),
            self.now,
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CancelError<E> {
    ConfirmationMismatch { required: String },
    ObservationTransport(E),
    ObservationRefused(AgentRefusalV1),
    InvalidObservation,
    SessionChanged { actual: AgentSessionViewV1 },
    MutationTransport(E),
    MutationRefused(AgentRefusalV1),
    InvalidMutationReply,
}

pub fn cancel<P: AgentServicePort>(
    service_session: SessionHandleV1,
    port: P,
    request: CancelRequest,
    confirmation: &str,
) -> Result<AgentOutcomeV1, CancelError<P::Error>> {
    let required = request.confirmation();
    if confirmation != required {
        return Err(CancelError::ConfirmationMismatch { required });
    }

    let mut observer = AgentReadOnlyClient::new(service_session, port);
    let current = match observer.inspect(request.session) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            view
        }
        Ok(AgentReplyV1::Accepted(_)) => return Err(CancelError::InvalidObservation),
        Ok(AgentReplyV1::Refused(refusal)) => {
            return Err(CancelError::ObservationRefused(refusal));
        }
        Err(error) => return Err(CancelError::ObservationTransport(error)),
    };
    if current.revision != request.expected_revision
        || !matches!(
            current.phase,
            AgentSessionPhaseV1::TurnActive | AgentSessionPhaseV1::AwaitingPermission
        )
        || current.active_turn != Some(request.turn)
    {
        return Err(CancelError::SessionChanged { actual: current });
    }

    let mut operator = AgentSessionClient::new(service_session, observer.into_port());
    match operator.cancel(
        request.session,
        request.turn,
        request.expected_revision,
        request.idempotency_key,
        request.now,
    ) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            Ok(AgentOutcomeV1::Session(view))
        }
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session,
            idempotency_key,
        })) if session == request.session && idempotency_key == request.idempotency_key => {
            Ok(AgentOutcomeV1::OutcomeUnknown {
                session,
                idempotency_key,
            })
        }
        Ok(AgentReplyV1::Accepted(_)) => Err(CancelError::InvalidMutationReply),
        Ok(AgentReplyV1::Refused(refusal)) => Err(CancelError::MutationRefused(refusal)),
        Err(error) => Err(CancelError::MutationTransport(error)),
    }
}

impl AdvanceRequest {
    pub fn confirmation(self) -> String {
        format!(
            "ADVANCE DAIMON SESSION {} TURN {} REVISION {} KEY {} AT {}",
            hex(&self.session.into_bytes()),
            hex(&self.turn.into_bytes()),
            self.expected_revision,
            hex(&self.idempotency_key.into_bytes()),
            self.now,
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AdvanceError<E> {
    ConfirmationMismatch { required: String },
    ObservationTransport(E),
    ObservationRefused(AgentRefusalV1),
    InvalidObservation,
    SessionChanged { actual: AgentSessionViewV1 },
    MutationTransport(E),
    MutationRefused(AgentRefusalV1),
    InvalidMutationReply,
}

pub fn advance<P: AgentServicePort>(
    service_session: SessionHandleV1,
    port: P,
    request: AdvanceRequest,
    confirmation: &str,
) -> Result<AgentOutcomeV1, AdvanceError<P::Error>> {
    let required = request.confirmation();
    if confirmation != required {
        return Err(AdvanceError::ConfirmationMismatch { required });
    }

    let mut observer = AgentReadOnlyClient::new(service_session, port);
    let current = match observer.inspect(request.session) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            view
        }
        Ok(AgentReplyV1::Accepted(_)) => return Err(AdvanceError::InvalidObservation),
        Ok(AgentReplyV1::Refused(refusal)) => {
            return Err(AdvanceError::ObservationRefused(refusal));
        }
        Err(error) => return Err(AdvanceError::ObservationTransport(error)),
    };
    if current.revision != request.expected_revision
        || current.phase != AgentSessionPhaseV1::TurnActive
        || current.active_turn != Some(request.turn)
    {
        return Err(AdvanceError::SessionChanged { actual: current });
    }

    let mut operator = AgentSessionClient::new(service_session, observer.into_port());
    match operator.advance(
        request.session,
        request.turn,
        request.expected_revision,
        request.idempotency_key,
        request.now,
    ) {
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view)))
            if view.session == request.session =>
        {
            Ok(AgentOutcomeV1::Session(view))
        }
        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::OutcomeUnknown {
            session,
            idempotency_key,
        })) if session == request.session && idempotency_key == request.idempotency_key => {
            Ok(AgentOutcomeV1::OutcomeUnknown {
                session,
                idempotency_key,
            })
        }
        Ok(AgentReplyV1::Accepted(_)) => Err(AdvanceError::InvalidMutationReply),
        Ok(AgentReplyV1::Refused(refusal)) => Err(AdvanceError::MutationRefused(refusal)),
        Err(error) => Err(AdvanceError::MutationTransport(error)),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use daimon_protocol::{
        ContentDigestV1,
        agent::{
            AgentCapabilitiesV1, AgentCommandV1, AgentEventPageV1, AgentEventRecordV1,
            AgentPermissionOptionV1,
        },
    };

    use super::*;

    struct Port {
        commands: Rc<RefCell<Vec<AgentCommandV1>>>,
        replies: Vec<Result<AgentReplyV1, &'static str>>,
    }

    impl AgentServicePort for Port {
        type Error = &'static str;

        fn execute_agent(
            &mut self,
            _: SessionHandleV1,
            command: AgentCommandV1,
        ) -> Result<AgentReplyV1, Self::Error> {
            self.commands.borrow_mut().push(command);
            self.replies.remove(0)
        }
    }

    fn request() -> AdvanceRequest {
        AdvanceRequest {
            session: AgentSessionIdV1::new([7; 16]),
            turn: AgentTurnIdV1::new([8; 16]),
            expected_revision: 12,
            idempotency_key: IdempotencyKeyV1::new([9; 16]),
            now: 34,
        }
    }

    fn view(revision: u64, phase: AgentSessionPhaseV1) -> AgentSessionViewV1 {
        AgentSessionViewV1 {
            session: request().session,
            revision,
            phase,
            profile_document_digest: ContentDigestV1::new([3; 32]),
            active_turn: Some(request().turn),
            last_event_cursor: Some(2),
            capabilities: AgentCapabilitiesV1 {
                load_session: true,
                resume_session: true,
                permissions: true,
                filesystem_read: false,
                filesystem_write: false,
                terminal: false,
                session_modes: false,
                session_models: false,
            },
        }
    }

    fn prompt_request() -> PromptRequest {
        PromptRequest {
            session: AgentSessionIdV1::new([7; 16]),
            turn: AgentTurnIdV1::new([8; 16]),
            expected_revision: 12,
            execution: ExecuteRequestV1 {
                execution_id: ExecutionIdV1::new([10; 16]),
                task_attempt: TaskAttemptRefV1 {
                    task_key: [11; 16],
                    task_incarnation: 4,
                    attempt_number: 2,
                },
                principal: PrincipalIdV1::new([12; 16]),
                profile: HarnessProfileIdV1::new([13; 16]),
                idempotency_key: IdempotencyKeyV1::new([9; 16]),
                context: vec![ContextReferenceIdV1::new([14; 16])],
                tools: vec![ToolCapabilityIdV1::new([15; 16])],
                budget: ExecutionBudgetV1 {
                    max_elapsed_millis: 1_000,
                    max_input_tokens: 100,
                    max_output_tokens: 200,
                    max_tool_calls: 3,
                    max_context_bytes: 4_096,
                    max_output_bytes: 8_192,
                },
            },
            prompt: b"review the boundary".to_vec(),
            now: 34,
        }
    }

    fn permission_request() -> PermissionRequest {
        PermissionRequest {
            session: AgentSessionIdV1::new([7; 16]),
            expected_revision: 12,
            event_cursor: 5,
            permission_request: AgentPermissionRequestIdV1::new([21; 16]),
            option: AgentPermissionOptionIdV1::new([22; 16]),
            execution: prompt_request().execution,
            now: 34,
        }
    }

    fn cancel_request() -> CancelRequest {
        CancelRequest {
            session: request().session,
            turn: request().turn,
            expected_revision: request().expected_revision,
            idempotency_key: request().idempotency_key,
            now: request().now,
        }
    }

    fn challenge() -> AgentPermissionRequestV1 {
        AgentPermissionRequestV1 {
            request: permission_request().permission_request,
            turn: AgentTurnIdV1::new([8; 16]),
            capability: b"terminal.execute".to_vec(),
            description: b"run the selected formatter".to_vec(),
            options: vec![
                AgentPermissionOptionV1 {
                    id: permission_request().option,
                    kind: AgentPermissionOptionKindV1::AllowOnce,
                    label: b"Allow once".to_vec(),
                },
                AgentPermissionOptionV1 {
                    id: AgentPermissionOptionIdV1::new([23; 16]),
                    kind: AgentPermissionOptionKindV1::RejectOnce,
                    label: b"Reject".to_vec(),
                },
            ],
        }
    }

    fn permission_page(challenge: AgentPermissionRequestV1) -> AgentEventPageV1 {
        AgentEventPageV1 {
            session: permission_request().session,
            entries: vec![AgentEventRecordV1 {
                cursor: permission_request().event_cursor,
                event: AgentEventV1::Permission(challenge),
            }],
            next_after: None,
        }
    }

    #[test]
    fn exact_current_challenge_attempts_one_permission_decision() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let waiting = view(12, AgentSessionPhaseV1::AwaitingPermission);
        let active = view(13, AgentSessionPhaseV1::TurnActive);
        let required = permission_confirmation(&permission_request(), &challenge());
        assert_eq!(
            decide_permission(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(waiting))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(
                            permission_page(challenge()),
                        ))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(
                            active.clone(),
                        ))),
                    ],
                },
                permission_request(),
                &required,
            ),
            Ok(AgentOutcomeV1::Session(active))
        );
        assert!(matches!(
            commands.borrow()[0],
            AgentCommandV1::Inspect { .. }
        ));
        assert!(matches!(
            commands.borrow()[1],
            AgentCommandV1::Events { .. }
        ));
        let AgentCommandV1::DecidePermission { decision, .. } = commands.borrow()[2] else {
            panic!("permission decision expected");
        };
        assert_eq!(decision.request, permission_request().permission_request);
        assert_eq!(decision.option, permission_request().option);
        assert_eq!(commands.borrow().len(), 3);
    }

    #[test]
    fn permission_confirmation_and_challenge_fences_prevent_decision() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert!(matches!(
            decide_permission(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::AwaitingPermission,
                        )))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(
                            permission_page(challenge()),
                        ))),
                    ],
                },
                permission_request(),
                "decide",
            ),
            Err(PermissionError::ConfirmationMismatch { .. })
        ));
        assert_eq!(commands.borrow().len(), 2);

        let mut changed = challenge();
        changed.options[0].id = AgentPermissionOptionIdV1::new([31; 16]);
        assert!(matches!(
            decide_permission(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::AwaitingPermission,
                        )))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(
                            permission_page(changed),
                        ))),
                    ],
                },
                permission_request(),
                "decide",
            ),
            Err(PermissionError::ChallengeChanged)
        ));
        assert_eq!(commands.borrow().len(), 4);
    }

    #[test]
    fn lost_permission_reply_is_returned_without_retry() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let required = permission_confirmation(&permission_request(), &challenge());
        assert_eq!(
            decide_permission(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::AwaitingPermission,
                        )))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(
                            permission_page(challenge()),
                        ))),
                        Err("lost"),
                    ],
                },
                permission_request(),
                &required,
            ),
            Err(PermissionError::MutationTransport("lost"))
        );
        assert_eq!(commands.borrow().len(), 3);
    }

    #[test]
    fn exact_confirmation_and_ready_state_attempt_one_prompt() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let mut ready = view(12, AgentSessionPhaseV1::Ready);
        ready.active_turn = None;
        let active = view(13, AgentSessionPhaseV1::TurnActive);
        assert_eq!(
            prompt(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(
                            active.clone(),
                        ))),
                    ],
                },
                prompt_request(),
                &prompt_request().confirmation(),
            ),
            Ok(AgentOutcomeV1::Session(active))
        );
        assert!(matches!(
            commands.borrow()[0],
            AgentCommandV1::Inspect { .. }
        ));
        let AgentCommandV1::Prompt { request, now } = &commands.borrow()[1] else {
            panic!("prompt command expected");
        };
        assert_eq!(*now, 34);
        assert_eq!(request.prompt, b"review the boundary");
        assert_eq!(request.prompt_digest, prompt_request().prompt_digest());
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn prompt_confirmation_and_state_fences_prevent_dispatch() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert!(matches!(
            prompt(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![],
                },
                prompt_request(),
                "prompt",
            ),
            Err(PromptError::ConfirmationMismatch { .. })
        ));
        assert!(commands.borrow().is_empty());

        assert!(matches!(
            prompt(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                        12,
                        AgentSessionPhaseV1::TurnActive,
                    ))))],
                },
                prompt_request(),
                &prompt_request().confirmation(),
            ),
            Err(PromptError::SessionChanged { .. })
        ));
        assert_eq!(commands.borrow().len(), 1);
    }

    #[test]
    fn lost_prompt_reply_is_returned_without_redispatch() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let mut ready = view(12, AgentSessionPhaseV1::Ready);
        ready.active_turn = None;
        assert_eq!(
            prompt(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready))),
                        Err("lost"),
                    ],
                },
                prompt_request(),
                &prompt_request().confirmation(),
            ),
            Err(PromptError::MutationTransport("lost"))
        );
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn prompt_document_is_strict_bounded_and_binds_entire_execution_envelope() {
        let document = br#"{
            "schema":1,
            "session":"07070707070707070707070707070707",
            "turn":"08080808080808080808080808080808",
            "expected_revision":12,
            "now":34,
            "execution":{
                "execution_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "task_key":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "task_incarnation":4,
                "attempt_number":2,
                "principal":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "profile":"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
                "idempotency_key":"09090909090909090909090909090909",
                "context":["0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"],
                "tools":["0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"],
                "budget":{
                    "max_elapsed_millis":1000,
                    "max_input_tokens":100,
                    "max_output_tokens":200,
                    "max_tool_calls":3,
                    "max_context_bytes":4096,
                    "max_output_bytes":8192
                }
            }
        }"#;
        let parsed = parse_prompt_document(document, b"review the boundary".to_vec()).unwrap();
        assert_eq!(parsed, prompt_request());
        assert!(parsed.confirmation().contains(" ENVELOPE "));

        let changed_document = String::from_utf8(document.to_vec())
            .unwrap()
            .replace("\"max_output_tokens\":200", "\"max_output_tokens\":201");
        let changed =
            parse_prompt_document(changed_document.as_bytes(), b"review the boundary".to_vec())
                .unwrap();
        assert_ne!(parsed.execution_digest(), changed.execution_digest());

        let unknown = String::from_utf8(document.to_vec())
            .unwrap()
            .replace("\"schema\":1,", "\"schema\":1,\"extra\":true,");
        assert_eq!(
            parse_prompt_document(unknown.as_bytes(), b"review".to_vec()),
            Err(PromptDocumentError::Malformed)
        );
    }

    #[test]
    fn exact_confirmation_and_active_state_attempt_one_cancel() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let mut cancelled = view(13, AgentSessionPhaseV1::Ready);
        cancelled.active_turn = None;
        assert_eq!(
            cancel(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::AwaitingPermission,
                        )))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(
                            cancelled.clone(),
                        ))),
                    ],
                },
                cancel_request(),
                &cancel_request().confirmation(),
            ),
            Ok(AgentOutcomeV1::Session(cancelled))
        );
        assert!(matches!(
            commands.borrow()[0],
            AgentCommandV1::Inspect { .. }
        ));
        assert!(matches!(
            commands.borrow()[1],
            AgentCommandV1::Cancel { .. }
        ));
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn cancel_confirmation_and_state_fences_prevent_mutation() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert!(matches!(
            cancel(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![],
                },
                cancel_request(),
                "cancel",
            ),
            Err(CancelError::ConfirmationMismatch { .. })
        ));
        assert!(commands.borrow().is_empty());

        let mut ready = view(12, AgentSessionPhaseV1::Ready);
        ready.active_turn = None;
        assert!(matches!(
            cancel(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(ready,)))],
                },
                cancel_request(),
                &cancel_request().confirmation(),
            ),
            Err(CancelError::SessionChanged { .. })
        ));
        assert_eq!(commands.borrow().len(), 1);
    }

    #[test]
    fn lost_cancel_reply_is_returned_without_retry() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            cancel(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::TurnActive,
                        )))),
                        Err("lost"),
                    ],
                },
                cancel_request(),
                &cancel_request().confirmation(),
            ),
            Err(CancelError::MutationTransport("lost"))
        );
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn exact_confirmation_and_current_state_attempt_one_advance() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let completed = view(13, AgentSessionPhaseV1::Ready);
        assert_eq!(
            advance(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::TurnActive,
                        )))),
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(
                            completed.clone(),
                        ))),
                    ],
                },
                request(),
                &request().confirmation(),
            ),
            Ok(AgentOutcomeV1::Session(completed))
        );
        assert!(matches!(
            commands.borrow()[0],
            AgentCommandV1::Inspect { .. }
        ));
        assert!(matches!(
            commands.borrow()[1],
            AgentCommandV1::Advance { .. }
        ));
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn confirmation_and_state_fences_prevent_advance() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert!(matches!(
            advance(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![]
                },
                request(),
                "advance",
            ),
            Err(AdvanceError::ConfirmationMismatch { .. })
        ));
        assert!(commands.borrow().is_empty());

        assert!(matches!(
            advance(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                        11,
                        AgentSessionPhaseV1::TurnActive,
                    ))))],
                },
                request(),
                &request().confirmation(),
            ),
            Err(AdvanceError::SessionChanged { .. })
        ));
        assert_eq!(commands.borrow().len(), 1);
    }

    #[test]
    fn lost_mutation_reply_is_returned_without_retry() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            advance(
                SessionHandleV1(4),
                Port {
                    commands: Rc::clone(&commands),
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::TurnActive,
                        )))),
                        Err("lost"),
                    ],
                },
                request(),
                &request().confirmation(),
            ),
            Err(AdvanceError::MutationTransport("lost"))
        );
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn exact_outcome_unknown_evidence_is_preserved() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let unknown = AgentOutcomeV1::OutcomeUnknown {
            session: request().session,
            idempotency_key: request().idempotency_key,
        };
        assert_eq!(
            advance(
                SessionHandleV1(4),
                Port {
                    commands,
                    replies: vec![
                        Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view(
                            12,
                            AgentSessionPhaseV1::TurnActive,
                        )))),
                        Ok(AgentReplyV1::Accepted(unknown.clone())),
                    ],
                },
                request(),
                &request().confirmation(),
            ),
            Ok(unknown)
        );
    }
}
