//! Canonical bounded checkpoint for interactive agent-session state.

use crate::{CodecErrorV1, StoreErrorV1};
use daimon_host::{
    StoreCommitV1,
    agent::{
        AgentServiceSnapshotV1, AgentSessionStore, StoredAgentOperationInputV1,
        StoredAgentOperationStateV1, StoredAgentOperationV1, StoredAgentPreparationV1,
        StoredAgentSessionV1,
    },
};
use daimon_protocol::{self as protocol, agent::*};
use keystone_storage::{
    AcknowledgementStrength, CheckpointStore, CommitGate, CommitGateFailure, CommitGateRefusal,
};
use std::collections::BTreeSet;

const KEY: &str = "daimon-agent-service-v1";
const MAGIC: &[u8; 8] = b"DAIMONAC";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentStoreLimitsV1 {
    pub max_bytes: usize,
    pub max_sessions: usize,
    pub max_operations_per_session: usize,
    pub max_events_per_session: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_prompt_bytes: usize,
    pub max_event_bytes: usize,
    pub max_permission_options: usize,
}

impl Default for AgentStoreLimitsV1 {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_sessions: 4_096,
            max_operations_per_session: 4_096,
            max_events_per_session: 65_536,
            max_context_references: 64,
            max_tools: 64,
            max_prompt_bytes: 1024 * 1024,
            max_event_bytes: 1024 * 1024,
            max_permission_options: 16,
        }
    }
}

pub struct CheckpointAgentSessionStore<S> {
    backend: S,
    limits: AgentStoreLimitsV1,
    gate: Option<CommitGate>,
    require_existing: bool,
}

impl<S: CheckpointStore> CheckpointAgentSessionStore<S> {
    pub fn create(backend: S, limits: AgentStoreLimitsV1) -> Result<Self, StoreErrorV1<S::Error>> {
        validate_limits(limits).map_err(StoreErrorV1::Codec)?;
        let mut value = Self {
            backend,
            limits,
            gate: None,
            require_existing: false,
        };
        if value.load_agents()?.is_some() {
            return Err(StoreErrorV1::AlreadyInitialized);
        }
        match value.commit_agents(&AgentServiceSnapshotV1::default())? {
            StoreCommitV1::Committed => {
                value.require_existing = true;
                Ok(value)
            }
            StoreCommitV1::Indeterminate => Err(StoreErrorV1::InvalidReceipt),
        }
    }

    pub fn open_existing(
        backend: S,
        limits: AgentStoreLimitsV1,
    ) -> Result<Self, StoreErrorV1<S::Error>> {
        validate_limits(limits).map_err(StoreErrorV1::Codec)?;
        Ok(Self {
            backend,
            limits,
            gate: None,
            require_existing: true,
        })
    }

    pub fn into_inner(self) -> S {
        self.backend
    }
}

impl<S: CheckpointStore> AgentSessionStore for CheckpointAgentSessionStore<S> {
    type Error = StoreErrorV1<S::Error>;

    fn load_agents(&mut self) -> Result<Option<AgentServiceSnapshotV1>, Self::Error> {
        let checkpoint = self.backend.load(KEY).map_err(StoreErrorV1::Backend)?;
        let Some(checkpoint) = checkpoint else {
            self.gate = Some(CommitGate::new(None));
            return if self.require_existing {
                Err(StoreErrorV1::Missing)
            } else {
                Ok(None)
            };
        };
        if checkpoint.strength != AcknowledgementStrength::Durable {
            return Err(StoreErrorV1::WeakLoad);
        }
        let snapshot = decode(&checkpoint.bytes, self.limits).map_err(StoreErrorV1::Codec)?;
        self.gate = Some(CommitGate::new(Some(checkpoint.revision)));
        Ok(Some(snapshot))
    }

    fn commit_agents(
        &mut self,
        snapshot: &AgentServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        let bytes = encode(snapshot, self.limits).map_err(StoreErrorV1::Codec)?;
        let gate = self.gate.as_mut().ok_or(StoreErrorV1::NotLoaded)?;
        let expected = gate.confirmed_revision();
        let proposed = gate.next_revision().map_err(|error| match error {
            CommitGateRefusal::Fenced => StoreErrorV1::Fenced,
            CommitGateRefusal::RevisionExhausted => StoreErrorV1::RevisionExhausted,
        })?;
        match gate.resolve(
            proposed,
            self.backend.compare_exchange(KEY, expected, &bytes),
        ) {
            Ok(()) => Ok(StoreCommitV1::Committed),
            Err(CommitGateFailure::Indeterminate) => Ok(StoreCommitV1::Indeterminate),
            Err(CommitGateFailure::Store(error)) => Err(StoreErrorV1::Backend(error)),
            Err(CommitGateFailure::Refused(error)) => Err(StoreErrorV1::Refused(error)),
            Err(CommitGateFailure::InvalidReceipt) => Err(StoreErrorV1::InvalidReceipt),
        }
    }
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Writer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), CodecErrorV1> {
        if value.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(CodecErrorV1::Limit);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| CodecErrorV1::Capacity)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), CodecErrorV1> {
        self.raw(&[value])
    }

    fn number(&mut self, value: u64) -> Result<(), CodecErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn id(&mut self, value: [u8; 16]) -> Result<(), CodecErrorV1> {
        self.raw(&value)
    }

    fn digest(&mut self, value: [u8; 32]) -> Result<(), CodecErrorV1> {
        self.raw(&value)
    }

    fn field(&mut self, value: &[u8], maximum: usize) -> Result<(), CodecErrorV1> {
        if value.len() > maximum {
            return Err(CodecErrorV1::Limit);
        }
        self.raw(
            &u32::try_from(value.len())
                .map_err(|_| CodecErrorV1::Limit)?
                .to_be_bytes(),
        )?;
        self.raw(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: AgentStoreLimitsV1,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: AgentStoreLimitsV1) -> Result<Self, CodecErrorV1> {
        validate_limits(limits)?;
        if bytes.len() > limits.max_bytes {
            return Err(CodecErrorV1::Limit);
        }
        Ok(Self {
            bytes,
            position: 0,
            limits,
        })
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], CodecErrorV1> {
        let end = self.position.checked_add(N).ok_or(CodecErrorV1::Invalid)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecErrorV1::Truncated)?;
        self.position = end;
        value.try_into().map_err(|_| CodecErrorV1::Invalid)
    }

    fn byte(&mut self) -> Result<u8, CodecErrorV1> {
        Ok(self.raw::<1>()?[0])
    }

    fn number(&mut self) -> Result<u64, CodecErrorV1> {
        Ok(u64::from_be_bytes(self.raw()?))
    }

    fn id(&mut self) -> Result<[u8; 16], CodecErrorV1> {
        self.raw()
    }

    fn digest(&mut self) -> Result<[u8; 32], CodecErrorV1> {
        self.raw()
    }

    fn count(&mut self, maximum: usize, minimum_bytes: usize) -> Result<usize, CodecErrorV1> {
        let count = usize::try_from(self.number()?).map_err(|_| CodecErrorV1::Limit)?;
        if count > maximum
            || count
                .checked_mul(minimum_bytes)
                .is_none_or(|size| size > self.bytes.len().saturating_sub(self.position))
        {
            return Err(CodecErrorV1::Limit);
        }
        Ok(count)
    }

    fn field(&mut self, maximum: usize) -> Result<Vec<u8>, CodecErrorV1> {
        let count =
            usize::try_from(u32::from_be_bytes(self.raw()?)).map_err(|_| CodecErrorV1::Limit)?;
        if count > maximum || count > self.bytes.len().saturating_sub(self.position) {
            return Err(CodecErrorV1::Limit);
        }
        let end = self
            .position
            .checked_add(count)
            .ok_or(CodecErrorV1::Limit)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecErrorV1::Truncated)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(count)
            .map_err(|_| CodecErrorV1::Capacity)?;
        value.extend_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), CodecErrorV1> {
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(CodecErrorV1::Invalid)
    }
}

pub fn encode(
    snapshot: &AgentServiceSnapshotV1,
    limits: AgentStoreLimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    if snapshot.sessions.len() > limits.max_sessions {
        return Err(CodecErrorV1::Limit);
    }
    let mut writer = Writer::new(limits.max_bytes);
    writer.raw(MAGIC)?;
    writer.byte(1)?;
    writer.number(count(snapshot.sessions.len())?)?;
    let mut previous = None;
    for session in &snapshot.sessions {
        let identity = session.request.session.into_bytes();
        if previous.is_some_and(|value| value >= identity) {
            return Err(CodecErrorV1::Invalid);
        }
        previous = Some(identity);
        encode_session(&mut writer, session, limits)?;
    }
    Ok(writer.bytes)
}

pub fn decode(
    bytes: &[u8],
    limits: AgentStoreLimitsV1,
) -> Result<AgentServiceSnapshotV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits)?;
    if reader.raw::<8>()? != *MAGIC || reader.byte()? != 1 {
        return Err(CodecErrorV1::Invalid);
    }
    let session_count = reader.count(limits.max_sessions, 1)?;
    let mut sessions = Vec::new();
    sessions
        .try_reserve(session_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    let mut identities = BTreeSet::new();
    for _ in 0..session_count {
        let session = decode_session(&mut reader)?;
        if !identities.insert(session.request.session) {
            return Err(CodecErrorV1::Invalid);
        }
        sessions.push(session);
    }
    if sessions
        .windows(2)
        .any(|pair| pair[0].request.session >= pair[1].request.session)
    {
        return Err(CodecErrorV1::Invalid);
    }
    reader.finish()?;
    Ok(AgentServiceSnapshotV1 { sessions })
}

fn encode_session(
    writer: &mut Writer,
    session: &StoredAgentSessionV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    if session.operations.len() > limits.max_operations_per_session
        || session.events.len() > limits.max_events_per_session
    {
        return Err(CodecErrorV1::Limit);
    }
    encode_open_request(writer, &session.request, limits)?;
    encode_preparation(writer, &session.open_preparation, limits)?;
    encode_profile(writer, &session.profile)?;
    writer.number(session.revision)?;
    writer.byte(phase_tag(session.phase))?;
    encode_optional_id(
        writer,
        session.active_turn.map(protocol::AgentTurnIdV1::into_bytes),
    )?;
    writer.byte(capability_bits(session.capabilities))?;
    match &session.recovery {
        Some(recovery) => {
            writer.byte(1)?;
            writer.field(
                &recovery.locator,
                daimon_host::agent::MAX_AGENT_PROVIDER_LOCATOR_BYTES,
            )?;
        }
        None => writer.byte(0)?,
    }
    writer.number(count(session.events.len())?)?;
    for event in &session.events {
        writer.number(event.cursor)?;
        encode_event(writer, &event.event, limits)?;
    }
    writer.number(count(session.operations.len())?)?;
    let mut previous = None;
    for operation in &session.operations {
        let identity = operation.idempotency_key.into_bytes();
        if previous.is_some_and(|value| value >= identity) {
            return Err(CodecErrorV1::Invalid);
        }
        previous = Some(identity);
        encode_operation(writer, operation, limits)?;
    }
    Ok(())
}

fn decode_session(reader: &mut Reader<'_>) -> Result<StoredAgentSessionV1, CodecErrorV1> {
    let request = decode_open_request(reader)?;
    let open_preparation = decode_preparation(reader)?;
    let profile = decode_profile(reader)?;
    let revision = reader.number()?;
    let phase = decode_phase(reader.byte()?)?;
    let active_turn = decode_optional_id(reader)?.map(protocol::AgentTurnIdV1::new);
    let capabilities = decode_capabilities(reader.byte()?);
    let recovery = match reader.byte()? {
        0 => None,
        1 => Some(daimon_host::agent::AgentProviderRecoveryV1 {
            locator: reader.field(daimon_host::agent::MAX_AGENT_PROVIDER_LOCATOR_BYTES)?,
        }),
        _ => return Err(CodecErrorV1::Invalid),
    };
    let event_count = reader.count(reader.limits.max_events_per_session, 9)?;
    let mut events = Vec::new();
    events
        .try_reserve(event_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..event_count {
        events.push(AgentEventRecordV1 {
            cursor: reader.number()?,
            event: decode_event(reader)?,
        });
    }
    let operation_count = reader.count(reader.limits.max_operations_per_session, 17)?;
    let mut operations = Vec::new();
    operations
        .try_reserve(operation_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    let mut identities = BTreeSet::new();
    for _ in 0..operation_count {
        let operation = decode_operation(reader)?;
        if !identities.insert(operation.idempotency_key) {
            return Err(CodecErrorV1::Invalid);
        }
        operations.push(operation);
    }
    if operations
        .windows(2)
        .any(|pair| pair[0].idempotency_key >= pair[1].idempotency_key)
    {
        return Err(CodecErrorV1::Invalid);
    }
    Ok(StoredAgentSessionV1 {
        request,
        open_preparation,
        profile,
        revision,
        phase,
        active_turn,
        capabilities,
        recovery,
        events,
        operations,
    })
}

fn encode_open_request(
    writer: &mut Writer,
    request: &AgentOpenRequestV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    writer.id(request.session.into_bytes())?;
    encode_execute(writer, &request.execution, limits)?;
    writer.id(request.workspace)?;
    writer.number(request.budget.max_elapsed_millis)?;
    writer.number(u64::from(request.budget.max_turns))?;
    writer.number(request.budget.max_events)?;
    writer
        .number(u64::try_from(request.budget.max_event_bytes).map_err(|_| CodecErrorV1::Limit)?)?;
    writer
        .number(u64::try_from(request.budget.max_prompt_bytes).map_err(|_| CodecErrorV1::Limit)?)?;
    writer.number(u64::from(request.budget.max_permission_requests))
}

fn decode_open_request(reader: &mut Reader<'_>) -> Result<AgentOpenRequestV1, CodecErrorV1> {
    Ok(AgentOpenRequestV1 {
        session: protocol::AgentSessionIdV1::new(reader.id()?),
        execution: decode_execute(reader)?,
        workspace: reader.id()?,
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: reader.number()?,
            max_turns: u32::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
            max_events: reader.number()?,
            max_event_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
            max_prompt_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
            max_permission_requests: u32::try_from(reader.number()?)
                .map_err(|_| CodecErrorV1::Limit)?,
        },
    })
}

fn encode_profile(
    writer: &mut Writer,
    profile: &AgentProfileSnapshotV1,
) -> Result<(), CodecErrorV1> {
    writer.id(profile.provider.into_bytes())?;
    writer.id(profile.harness_profile.into_bytes())?;
    writer.byte(match profile.wire {
        AgentWireProfileV1::AgentClientProtocol => 0,
        AgentWireProfileV1::ClaudeAgentStreamJson => 1,
    })?;
    writer.digest(profile.command_digest.into_bytes())?;
    writer.digest(profile.policy_digest.into_bytes())?;
    writer.digest(profile.document_digest.into_bytes())
}

fn decode_profile(reader: &mut Reader<'_>) -> Result<AgentProfileSnapshotV1, CodecErrorV1> {
    let provider = protocol::ProviderProfileIdV1::new(reader.id()?);
    let harness_profile = protocol::HarnessProfileIdV1::new(reader.id()?);
    let wire = match reader.byte()? {
        0 => AgentWireProfileV1::AgentClientProtocol,
        1 => AgentWireProfileV1::ClaudeAgentStreamJson,
        _ => return Err(CodecErrorV1::Invalid),
    };
    Ok(AgentProfileSnapshotV1 {
        provider,
        harness_profile,
        wire,
        command_digest: protocol::ContentDigestV1::new(reader.digest()?),
        policy_digest: protocol::ContentDigestV1::new(reader.digest()?),
        document_digest: protocol::ContentDigestV1::new(reader.digest()?),
    })
}

fn encode_preparation(
    writer: &mut Writer,
    preparation: &StoredAgentPreparationV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    if preparation.authority_tools.len() > limits.max_tools {
        return Err(CodecErrorV1::Limit);
    }
    writer.id(preparation.authority_decision)?;
    writer.number(preparation.authority_expires_at)?;
    writer.number(count(preparation.authority_tools.len())?)?;
    for tool in &preparation.authority_tools {
        writer.id(tool.into_bytes())?;
    }
    writer.number(preparation.prepared_at)
}

fn decode_preparation(reader: &mut Reader<'_>) -> Result<StoredAgentPreparationV1, CodecErrorV1> {
    let authority_decision = reader.id()?;
    let authority_expires_at = reader.number()?;
    let count = reader.count(reader.limits.max_tools, 16)?;
    let mut authority_tools = Vec::new();
    authority_tools
        .try_reserve(count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..count {
        authority_tools.push(protocol::ToolCapabilityIdV1::new(reader.id()?));
    }
    Ok(StoredAgentPreparationV1 {
        authority_decision,
        authority_expires_at,
        authority_tools,
        prepared_at: reader.number()?,
    })
}

fn encode_execute(
    writer: &mut Writer,
    request: &protocol::ExecuteRequestV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    if request.context.len() > limits.max_context_references
        || request.tools.len() > limits.max_tools
    {
        return Err(CodecErrorV1::Limit);
    }
    writer.id(request.execution_id.into_bytes())?;
    writer.id(request.task_attempt.task_key)?;
    writer.number(request.task_attempt.task_incarnation)?;
    writer.number(u64::from(request.task_attempt.attempt_number))?;
    writer.id(request.principal.into_bytes())?;
    writer.id(request.profile.into_bytes())?;
    writer.id(request.idempotency_key.into_bytes())?;
    writer.number(count(request.context.len())?)?;
    for reference in &request.context {
        writer.id(reference.into_bytes())?;
    }
    writer.number(count(request.tools.len())?)?;
    for tool in &request.tools {
        writer.id(tool.into_bytes())?;
    }
    writer.number(request.budget.max_elapsed_millis)?;
    writer.number(request.budget.max_input_tokens)?;
    writer.number(request.budget.max_output_tokens)?;
    writer.number(u64::from(request.budget.max_tool_calls))?;
    writer.number(
        u64::try_from(request.budget.max_context_bytes).map_err(|_| CodecErrorV1::Limit)?,
    )?;
    writer.number(u64::try_from(request.budget.max_output_bytes).map_err(|_| CodecErrorV1::Limit)?)
}

fn decode_execute(reader: &mut Reader<'_>) -> Result<protocol::ExecuteRequestV1, CodecErrorV1> {
    let execution_id = protocol::ExecutionIdV1::new(reader.id()?);
    let task_attempt = protocol::TaskAttemptRefV1 {
        task_key: reader.id()?,
        task_incarnation: reader.number()?,
        attempt_number: u32::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
    };
    let principal = protocol::PrincipalIdV1::new(reader.id()?);
    let profile = protocol::HarnessProfileIdV1::new(reader.id()?);
    let idempotency_key = protocol::IdempotencyKeyV1::new(reader.id()?);
    let context_count = reader.count(reader.limits.max_context_references, 16)?;
    let mut context = Vec::new();
    context
        .try_reserve(context_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..context_count {
        context.push(protocol::ContextReferenceIdV1::new(reader.id()?));
    }
    let tool_count = reader.count(reader.limits.max_tools, 16)?;
    let mut tools = Vec::new();
    tools
        .try_reserve(tool_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..tool_count {
        tools.push(protocol::ToolCapabilityIdV1::new(reader.id()?));
    }
    Ok(protocol::ExecuteRequestV1 {
        execution_id,
        task_attempt,
        principal,
        profile,
        idempotency_key,
        context,
        tools,
        budget: protocol::ExecutionBudgetV1 {
            max_elapsed_millis: reader.number()?,
            max_input_tokens: reader.number()?,
            max_output_tokens: reader.number()?,
            max_tool_calls: u32::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
            max_context_bytes: usize::try_from(reader.number()?)
                .map_err(|_| CodecErrorV1::Limit)?,
            max_output_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
        },
    })
}

fn encode_operation(
    writer: &mut Writer,
    operation: &StoredAgentOperationV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    writer.id(operation.idempotency_key.into_bytes())?;
    match &operation.input {
        StoredAgentOperationInputV1::Reattach {
            expected_revision,
            execution,
        } => {
            writer.byte(5)?;
            writer.number(*expected_revision)?;
            encode_execute(writer, execution, limits)?;
        }
        StoredAgentOperationInputV1::Prompt(request) => {
            writer.byte(0)?;
            writer.id(request.session.into_bytes())?;
            writer.id(request.turn.into_bytes())?;
            writer.number(request.expected_revision)?;
            encode_execute(writer, &request.execution, limits)?;
            writer.digest(request.prompt_digest.into_bytes())?;
            writer.field(&request.prompt, limits.max_prompt_bytes)?;
        }
        StoredAgentOperationInputV1::Permission {
            expected_revision,
            execution,
            decision,
        } => {
            writer.byte(1)?;
            writer.number(*expected_revision)?;
            encode_execute(writer, execution, limits)?;
            writer.id(decision.request.into_bytes())?;
            writer.id(decision.option.into_bytes())?;
        }
        StoredAgentOperationInputV1::Advance {
            turn,
            expected_revision,
        } => {
            writer.byte(4)?;
            writer.id(turn.into_bytes())?;
            writer.number(*expected_revision)?;
        }
        StoredAgentOperationInputV1::Cancel {
            turn,
            expected_revision,
        } => {
            writer.byte(2)?;
            writer.id(turn.into_bytes())?;
            writer.number(*expected_revision)?;
        }
        StoredAgentOperationInputV1::Close { expected_revision } => {
            writer.byte(3)?;
            writer.number(*expected_revision)?;
        }
    }
    match &operation.preparation {
        Some(preparation) => {
            writer.byte(1)?;
            encode_preparation(writer, preparation, limits)?;
        }
        None => writer.byte(0)?,
    }
    match &operation.state {
        StoredAgentOperationStateV1::OutcomeUnknown => writer.byte(0),
        StoredAgentOperationStateV1::Completed(view) => {
            writer.byte(1)?;
            encode_view(writer, view)
        }
    }
}

fn decode_operation(reader: &mut Reader<'_>) -> Result<StoredAgentOperationV1, CodecErrorV1> {
    let idempotency_key = protocol::IdempotencyKeyV1::new(reader.id()?);
    let input = match reader.byte()? {
        0 => StoredAgentOperationInputV1::Prompt(AgentTurnRequestV1 {
            session: protocol::AgentSessionIdV1::new(reader.id()?),
            turn: protocol::AgentTurnIdV1::new(reader.id()?),
            expected_revision: reader.number()?,
            execution: decode_execute(reader)?,
            prompt_digest: protocol::ContentDigestV1::new(reader.digest()?),
            prompt: reader.field(reader.limits.max_prompt_bytes)?,
        }),
        1 => StoredAgentOperationInputV1::Permission {
            expected_revision: reader.number()?,
            execution: decode_execute(reader)?,
            decision: AgentPermissionDecisionV1 {
                request: protocol::AgentPermissionRequestIdV1::new(reader.id()?),
                option: protocol::AgentPermissionOptionIdV1::new(reader.id()?),
            },
        },
        2 => StoredAgentOperationInputV1::Cancel {
            turn: protocol::AgentTurnIdV1::new(reader.id()?),
            expected_revision: reader.number()?,
        },
        3 => StoredAgentOperationInputV1::Close {
            expected_revision: reader.number()?,
        },
        4 => StoredAgentOperationInputV1::Advance {
            turn: protocol::AgentTurnIdV1::new(reader.id()?),
            expected_revision: reader.number()?,
        },
        5 => StoredAgentOperationInputV1::Reattach {
            expected_revision: reader.number()?,
            execution: decode_execute(reader)?,
        },
        _ => return Err(CodecErrorV1::Invalid),
    };
    let preparation = match reader.byte()? {
        0 => None,
        1 => Some(decode_preparation(reader)?),
        _ => return Err(CodecErrorV1::Invalid),
    };
    let state = match reader.byte()? {
        0 => StoredAgentOperationStateV1::OutcomeUnknown,
        1 => StoredAgentOperationStateV1::Completed(decode_view(reader)?),
        _ => return Err(CodecErrorV1::Invalid),
    };
    Ok(StoredAgentOperationV1 {
        idempotency_key,
        input,
        preparation,
        state,
    })
}

fn encode_view(writer: &mut Writer, view: &AgentSessionViewV1) -> Result<(), CodecErrorV1> {
    writer.id(view.session.into_bytes())?;
    writer.number(view.revision)?;
    writer.byte(phase_tag(view.phase))?;
    writer.digest(view.profile_document_digest.into_bytes())?;
    encode_optional_id(
        writer,
        view.active_turn.map(protocol::AgentTurnIdV1::into_bytes),
    )?;
    encode_optional_number(writer, view.last_event_cursor)?;
    writer.byte(capability_bits(view.capabilities))
}

fn decode_view(reader: &mut Reader<'_>) -> Result<AgentSessionViewV1, CodecErrorV1> {
    Ok(AgentSessionViewV1 {
        session: protocol::AgentSessionIdV1::new(reader.id()?),
        revision: reader.number()?,
        phase: decode_phase(reader.byte()?)?,
        profile_document_digest: protocol::ContentDigestV1::new(reader.digest()?),
        active_turn: decode_optional_id(reader)?.map(protocol::AgentTurnIdV1::new),
        last_event_cursor: decode_optional_number(reader)?,
        capabilities: decode_capabilities(reader.byte()?),
    })
}

fn encode_event(
    writer: &mut Writer,
    event: &AgentEventV1,
    limits: AgentStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    if event_size(event) > limits.max_event_bytes {
        return Err(CodecErrorV1::Limit);
    }
    match event {
        AgentEventV1::AssistantMessage { bytes } => {
            writer.byte(0)?;
            writer.field(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Thought { bytes } => {
            writer.byte(1)?;
            writer.field(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Plan { bytes } => {
            writer.byte(2)?;
            writer.field(bytes, limits.max_event_bytes)
        }
        AgentEventV1::ToolCall { title, detail } => {
            writer.byte(3)?;
            writer.field(title, limits.max_event_bytes)?;
            writer.field(detail, limits.max_event_bytes)
        }
        AgentEventV1::Terminal { stream, bytes } => {
            writer.byte(4)?;
            writer.field(stream, limits.max_event_bytes)?;
            writer.field(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Permission(request) => {
            if request.options.is_empty() || request.options.len() > limits.max_permission_options {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(5)?;
            writer.id(request.request.into_bytes())?;
            writer.id(request.turn.into_bytes())?;
            writer.field(&request.capability, limits.max_event_bytes)?;
            writer.field(&request.description, limits.max_event_bytes)?;
            writer.number(count(request.options.len())?)?;
            for option in &request.options {
                writer.id(option.id.into_bytes())?;
                writer.byte(permission_kind_tag(option.kind))?;
                writer.field(&option.label, limits.max_event_bytes)?;
            }
            Ok(())
        }
        AgentEventV1::FileChange {
            path,
            content_digest,
        } => {
            writer.byte(6)?;
            writer.field(path, limits.max_event_bytes)?;
            writer.digest(content_digest.into_bytes())
        }
        AgentEventV1::Usage {
            input_tokens,
            output_tokens,
        } => {
            writer.byte(7)?;
            writer.number(*input_tokens)?;
            writer.number(*output_tokens)
        }
        AgentEventV1::TurnFinished {
            turn,
            disposition,
            stop_reason,
            output_digest,
        } => {
            writer.byte(8)?;
            writer.id(turn.into_bytes())?;
            writer.byte(disposition_tag(*disposition))?;
            writer.byte(stop_reason_tag(*stop_reason))?;
            encode_optional_digest(
                writer,
                output_digest.map(protocol::ContentDigestV1::into_bytes),
            )
        }
        AgentEventV1::FileRead {
            path,
            content_digest,
            content_bytes,
        } => {
            writer.byte(9)?;
            writer.field(path, limits.max_event_bytes)?;
            writer.digest(content_digest.into_bytes())?;
            writer.number(u64::try_from(*content_bytes).map_err(|_| CodecErrorV1::Limit)?)
        }
    }
}

fn decode_event(reader: &mut Reader<'_>) -> Result<AgentEventV1, CodecErrorV1> {
    let event = match reader.byte()? {
        0 => AgentEventV1::AssistantMessage {
            bytes: reader.field(reader.limits.max_event_bytes)?,
        },
        1 => AgentEventV1::Thought {
            bytes: reader.field(reader.limits.max_event_bytes)?,
        },
        2 => AgentEventV1::Plan {
            bytes: reader.field(reader.limits.max_event_bytes)?,
        },
        3 => AgentEventV1::ToolCall {
            title: reader.field(reader.limits.max_event_bytes)?,
            detail: reader.field(reader.limits.max_event_bytes)?,
        },
        4 => AgentEventV1::Terminal {
            stream: reader.field(reader.limits.max_event_bytes)?,
            bytes: reader.field(reader.limits.max_event_bytes)?,
        },
        5 => {
            let request = protocol::AgentPermissionRequestIdV1::new(reader.id()?);
            let turn = protocol::AgentTurnIdV1::new(reader.id()?);
            let capability = reader.field(reader.limits.max_event_bytes)?;
            let description = reader.field(reader.limits.max_event_bytes)?;
            let option_count = reader.count(reader.limits.max_permission_options, 21)?;
            if option_count == 0 {
                return Err(CodecErrorV1::Invalid);
            }
            let mut options = Vec::new();
            options
                .try_reserve(option_count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..option_count {
                options.push(AgentPermissionOptionV1 {
                    id: protocol::AgentPermissionOptionIdV1::new(reader.id()?),
                    kind: decode_permission_kind(reader.byte()?)?,
                    label: reader.field(reader.limits.max_event_bytes)?,
                });
            }
            AgentEventV1::Permission(AgentPermissionRequestV1 {
                request,
                turn,
                capability,
                description,
                options,
            })
        }
        6 => AgentEventV1::FileChange {
            path: reader.field(reader.limits.max_event_bytes)?,
            content_digest: protocol::ContentDigestV1::new(reader.digest()?),
        },
        7 => AgentEventV1::Usage {
            input_tokens: reader.number()?,
            output_tokens: reader.number()?,
        },
        8 => AgentEventV1::TurnFinished {
            turn: protocol::AgentTurnIdV1::new(reader.id()?),
            disposition: decode_disposition(reader.byte()?)?,
            stop_reason: decode_stop_reason(reader.byte()?)?,
            output_digest: decode_optional_digest(reader)?.map(protocol::ContentDigestV1::new),
        },
        9 => AgentEventV1::FileRead {
            path: reader.field(reader.limits.max_event_bytes)?,
            content_digest: protocol::ContentDigestV1::new(reader.digest()?),
            content_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
        },
        _ => return Err(CodecErrorV1::Invalid),
    };
    if event_size(&event) > reader.limits.max_event_bytes {
        return Err(CodecErrorV1::Limit);
    }
    Ok(event)
}

fn event_size(event: &AgentEventV1) -> usize {
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

fn encode_optional_id(writer: &mut Writer, value: Option<[u8; 16]>) -> Result<(), CodecErrorV1> {
    writer.byte(u8::from(value.is_some()))?;
    if let Some(value) = value {
        writer.id(value)?;
    }
    Ok(())
}

fn decode_optional_id(reader: &mut Reader<'_>) -> Result<Option<[u8; 16]>, CodecErrorV1> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(reader.id()?)),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn encode_optional_number(writer: &mut Writer, value: Option<u64>) -> Result<(), CodecErrorV1> {
    writer.byte(u8::from(value.is_some()))?;
    if let Some(value) = value {
        writer.number(value)?;
    }
    Ok(())
}

fn decode_optional_number(reader: &mut Reader<'_>) -> Result<Option<u64>, CodecErrorV1> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(reader.number()?)),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn encode_optional_digest(
    writer: &mut Writer,
    value: Option<[u8; 32]>,
) -> Result<(), CodecErrorV1> {
    writer.byte(u8::from(value.is_some()))?;
    if let Some(value) = value {
        writer.digest(value)?;
    }
    Ok(())
}

fn decode_optional_digest(reader: &mut Reader<'_>) -> Result<Option<[u8; 32]>, CodecErrorV1> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(reader.digest()?)),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn capability_bits(value: AgentCapabilitiesV1) -> u8 {
    u8::from(value.load_session)
        | (u8::from(value.resume_session) << 1)
        | (u8::from(value.permissions) << 2)
        | (u8::from(value.filesystem_read) << 3)
        | (u8::from(value.filesystem_write) << 4)
        | (u8::from(value.terminal) << 5)
        | (u8::from(value.session_modes) << 6)
        | (u8::from(value.session_models) << 7)
}

fn decode_capabilities(value: u8) -> AgentCapabilitiesV1 {
    AgentCapabilitiesV1 {
        load_session: value & 1 != 0,
        resume_session: value & 2 != 0,
        permissions: value & 4 != 0,
        filesystem_read: value & 8 != 0,
        filesystem_write: value & 16 != 0,
        terminal: value & 32 != 0,
        session_modes: value & 64 != 0,
        session_models: value & 128 != 0,
    }
}

fn phase_tag(value: AgentSessionPhaseV1) -> u8 {
    match value {
        AgentSessionPhaseV1::Opening => 0,
        AgentSessionPhaseV1::Ready => 1,
        AgentSessionPhaseV1::ReattachRequired => 6,
        AgentSessionPhaseV1::TurnActive => 2,
        AgentSessionPhaseV1::AwaitingPermission => 3,
        AgentSessionPhaseV1::OutcomeUnknown => 4,
        AgentSessionPhaseV1::Closed => 5,
    }
}

fn decode_phase(value: u8) -> Result<AgentSessionPhaseV1, CodecErrorV1> {
    match value {
        0 => Ok(AgentSessionPhaseV1::Opening),
        1 => Ok(AgentSessionPhaseV1::Ready),
        2 => Ok(AgentSessionPhaseV1::TurnActive),
        3 => Ok(AgentSessionPhaseV1::AwaitingPermission),
        4 => Ok(AgentSessionPhaseV1::OutcomeUnknown),
        5 => Ok(AgentSessionPhaseV1::Closed),
        6 => Ok(AgentSessionPhaseV1::ReattachRequired),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn permission_kind_tag(value: AgentPermissionOptionKindV1) -> u8 {
    match value {
        AgentPermissionOptionKindV1::AllowOnce => 0,
        AgentPermissionOptionKindV1::AllowAlways => 1,
        AgentPermissionOptionKindV1::RejectOnce => 2,
        AgentPermissionOptionKindV1::RejectAlways => 3,
    }
}

fn decode_permission_kind(value: u8) -> Result<AgentPermissionOptionKindV1, CodecErrorV1> {
    match value {
        0 => Ok(AgentPermissionOptionKindV1::AllowOnce),
        1 => Ok(AgentPermissionOptionKindV1::AllowAlways),
        2 => Ok(AgentPermissionOptionKindV1::RejectOnce),
        3 => Ok(AgentPermissionOptionKindV1::RejectAlways),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn disposition_tag(value: protocol::ExecutionDispositionV1) -> u8 {
    match value {
        protocol::ExecutionDispositionV1::Completed => 0,
        protocol::ExecutionDispositionV1::Cancelled => 1,
        protocol::ExecutionDispositionV1::TimedOut => 2,
        protocol::ExecutionDispositionV1::Failed => 3,
        protocol::ExecutionDispositionV1::Uncertain => 4,
    }
}

fn decode_disposition(value: u8) -> Result<protocol::ExecutionDispositionV1, CodecErrorV1> {
    match value {
        0 => Ok(protocol::ExecutionDispositionV1::Completed),
        1 => Ok(protocol::ExecutionDispositionV1::Cancelled),
        2 => Ok(protocol::ExecutionDispositionV1::TimedOut),
        3 => Ok(protocol::ExecutionDispositionV1::Failed),
        4 => Ok(protocol::ExecutionDispositionV1::Uncertain),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn stop_reason_tag(value: AgentTurnStopReasonV1) -> u8 {
    match value {
        AgentTurnStopReasonV1::EndTurn => 0,
        AgentTurnStopReasonV1::Cancelled => 1,
        AgentTurnStopReasonV1::TimedOut => 2,
        AgentTurnStopReasonV1::Failed => 3,
        AgentTurnStopReasonV1::Disconnected => 4,
        AgentTurnStopReasonV1::OutcomeUnknown => 5,
    }
}

fn decode_stop_reason(value: u8) -> Result<AgentTurnStopReasonV1, CodecErrorV1> {
    match value {
        0 => Ok(AgentTurnStopReasonV1::EndTurn),
        1 => Ok(AgentTurnStopReasonV1::Cancelled),
        2 => Ok(AgentTurnStopReasonV1::TimedOut),
        3 => Ok(AgentTurnStopReasonV1::Failed),
        4 => Ok(AgentTurnStopReasonV1::Disconnected),
        5 => Ok(AgentTurnStopReasonV1::OutcomeUnknown),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn count(value: usize) -> Result<u64, CodecErrorV1> {
    u64::try_from(value).map_err(|_| CodecErrorV1::Limit)
}

fn validate_limits(limits: AgentStoreLimitsV1) -> Result<(), CodecErrorV1> {
    if limits.max_bytes < 9
        || limits.max_sessions == 0
        || limits.max_operations_per_session == 0
        || limits.max_events_per_session == 0
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_prompt_bytes == 0
        || limits.max_event_bytes == 0
        || limits.max_permission_options == 0
    {
        Err(CodecErrorV1::InvalidLimits)
    } else {
        Ok(())
    }
}
