//! Canonical bounded V1 wire codec for interactive agent sessions.

use daimon_protocol::{agent::*, *};

const MAGIC: &[u8; 8] = b"DAIMONA1";
const REQUEST: u8 = 1;
const REPLY: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentWireLimitsV1 {
    pub max_frame_bytes: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_prompt_bytes: usize,
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_permission_options: usize,
}

impl Default for AgentWireLimitsV1 {
    fn default() -> Self {
        Self {
            max_frame_bytes: 4 * 1024 * 1024,
            max_context_references: 64,
            max_tools: 64,
            max_prompt_bytes: 1024 * 1024,
            max_events: 256,
            max_event_bytes: 1024 * 1024,
            max_permission_options: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRequestFrameV1 {
    pub service_session: SessionHandleV1,
    pub command: AgentCommandV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentWireCodecErrorV1 {
    Limit,
    Malformed,
    Unsupported,
    Capacity,
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Writer {
    fn new(limit: usize, kind: u8) -> Result<Self, AgentWireCodecErrorV1> {
        if limit < 9 {
            return Err(AgentWireCodecErrorV1::Limit);
        }
        let mut writer = Self {
            bytes: Vec::new(),
            limit,
        };
        writer.raw(MAGIC)?;
        writer.byte(kind)?;
        Ok(writer)
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), AgentWireCodecErrorV1> {
        if value.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(AgentWireCodecErrorV1::Limit);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), AgentWireCodecErrorV1> {
        self.raw(&[value])
    }

    fn boolean(&mut self, value: bool) -> Result<(), AgentWireCodecErrorV1> {
        self.byte(u8::from(value))
    }

    fn u32(&mut self, value: usize) -> Result<(), AgentWireCodecErrorV1> {
        self.raw(
            &u32::try_from(value)
                .map_err(|_| AgentWireCodecErrorV1::Limit)?
                .to_be_bytes(),
        )
    }

    fn u64(&mut self, value: u64) -> Result<(), AgentWireCodecErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn id(&mut self, value: [u8; 16]) -> Result<(), AgentWireCodecErrorV1> {
        self.raw(&value)
    }

    fn digest(&mut self, value: [u8; 32]) -> Result<(), AgentWireCodecErrorV1> {
        self.raw(&value)
    }

    fn bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), AgentWireCodecErrorV1> {
        if value.len() > maximum {
            return Err(AgentWireCodecErrorV1::Limit);
        }
        self.u32(value.len())?;
        self.raw(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: AgentWireLimitsV1,
}

impl<'a> Reader<'a> {
    fn new(
        bytes: &'a [u8],
        limits: AgentWireLimitsV1,
        kind: u8,
    ) -> Result<Self, AgentWireCodecErrorV1> {
        validate_limits(limits)?;
        if bytes.len() > limits.max_frame_bytes {
            return Err(AgentWireCodecErrorV1::Limit);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes.get(8) != Some(&kind) {
            return Err(AgentWireCodecErrorV1::Unsupported);
        }
        Ok(Self {
            bytes,
            position: 9,
            limits,
        })
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], AgentWireCodecErrorV1> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(AgentWireCodecErrorV1::Malformed)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentWireCodecErrorV1::Malformed)?;
        self.position = end;
        value
            .try_into()
            .map_err(|_| AgentWireCodecErrorV1::Malformed)
    }

    fn byte(&mut self) -> Result<u8, AgentWireCodecErrorV1> {
        Ok(self.raw::<1>()?[0])
    }

    fn boolean(&mut self) -> Result<bool, AgentWireCodecErrorV1> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AgentWireCodecErrorV1::Malformed),
        }
    }

    fn u32(&mut self) -> Result<usize, AgentWireCodecErrorV1> {
        usize::try_from(u32::from_be_bytes(self.raw()?)).map_err(|_| AgentWireCodecErrorV1::Limit)
    }

    fn u64(&mut self) -> Result<u64, AgentWireCodecErrorV1> {
        Ok(u64::from_be_bytes(self.raw()?))
    }

    fn id(&mut self) -> Result<[u8; 16], AgentWireCodecErrorV1> {
        self.raw()
    }

    fn digest(&mut self) -> Result<[u8; 32], AgentWireCodecErrorV1> {
        self.raw()
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, AgentWireCodecErrorV1> {
        let count = self.u32()?;
        if count > maximum || count > self.bytes.len().saturating_sub(self.position) {
            return Err(AgentWireCodecErrorV1::Limit);
        }
        let end = self
            .position
            .checked_add(count)
            .ok_or(AgentWireCodecErrorV1::Malformed)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(AgentWireCodecErrorV1::Malformed)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(count)
            .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
        value.extend_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), AgentWireCodecErrorV1> {
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(AgentWireCodecErrorV1::Malformed)
    }
}

pub fn encode_agent_request(
    frame: &AgentRequestFrameV1,
    limits: AgentWireLimitsV1,
) -> Result<Vec<u8>, AgentWireCodecErrorV1> {
    validate_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, REQUEST)?;
    writer.u64(frame.service_session.0)?;
    encode_command(&mut writer, &frame.command, limits)?;
    Ok(writer.bytes)
}

pub fn decode_agent_request(
    bytes: &[u8],
    limits: AgentWireLimitsV1,
) -> Result<AgentRequestFrameV1, AgentWireCodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REQUEST)?;
    let service_session = SessionHandleV1(reader.u64()?);
    let command = decode_command(&mut reader)?;
    reader.finish()?;
    Ok(AgentRequestFrameV1 {
        service_session,
        command,
    })
}

pub fn encode_agent_reply(
    reply: &AgentReplyV1,
    limits: AgentWireLimitsV1,
) -> Result<Vec<u8>, AgentWireCodecErrorV1> {
    validate_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, REPLY)?;
    match reply {
        AgentReplyV1::Accepted(outcome) => {
            writer.byte(0)?;
            encode_outcome(&mut writer, outcome, limits)?;
        }
        AgentReplyV1::Refused(refusal) => {
            writer.byte(1)?;
            writer.byte(refusal_tag(*refusal))?;
        }
    }
    Ok(writer.bytes)
}

pub fn decode_agent_reply(
    bytes: &[u8],
    limits: AgentWireLimitsV1,
) -> Result<AgentReplyV1, AgentWireCodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REPLY)?;
    let reply = match reader.byte()? {
        0 => AgentReplyV1::Accepted(decode_outcome(&mut reader)?),
        1 => AgentReplyV1::Refused(decode_refusal(reader.byte()?)?),
        _ => return Err(AgentWireCodecErrorV1::Malformed),
    };
    reader.finish()?;
    Ok(reply)
}

fn encode_command(
    writer: &mut Writer,
    command: &AgentCommandV1,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentWireCodecErrorV1> {
    match command {
        AgentCommandV1::Open { request, now } => {
            writer.byte(1)?;
            writer.u64(*now)?;
            writer.id(request.session.into_bytes())?;
            encode_execute(writer, &request.execution, limits)?;
            writer.id(request.workspace)?;
            encode_budget(writer, request.budget)
        }
        AgentCommandV1::Prompt { request, now } => {
            writer.byte(2)?;
            writer.u64(*now)?;
            writer.id(request.session.into_bytes())?;
            writer.id(request.turn.into_bytes())?;
            writer.u64(request.expected_revision)?;
            encode_execute(writer, &request.execution, limits)?;
            writer.digest(request.prompt_digest.into_bytes())?;
            writer.bytes(&request.prompt, limits.max_prompt_bytes)
        }
        AgentCommandV1::Events {
            session,
            after,
            limit,
        } => {
            writer.byte(3)?;
            writer.id(session.into_bytes())?;
            encode_optional_u64(writer, *after)?;
            writer.u64(*limit)
        }
        AgentCommandV1::Inspect { session } => {
            writer.byte(4)?;
            writer.id(session.into_bytes())
        }
        AgentCommandV1::Reattach {
            session,
            expected_revision,
            execution,
            now,
        } => {
            writer.byte(9)?;
            writer.u64(*now)?;
            writer.id(session.into_bytes())?;
            writer.u64(*expected_revision)?;
            encode_execute(writer, execution, limits)
        }
        AgentCommandV1::DecidePermission {
            session,
            expected_revision,
            execution,
            decision,
            now,
        } => {
            writer.byte(5)?;
            writer.u64(*now)?;
            writer.id(session.into_bytes())?;
            writer.u64(*expected_revision)?;
            encode_execute(writer, execution, limits)?;
            writer.id(decision.request.into_bytes())?;
            writer.id(decision.option.into_bytes())
        }
        AgentCommandV1::Advance {
            session,
            turn,
            expected_revision,
            idempotency_key,
            now,
        } => {
            writer.byte(8)?;
            writer.u64(*now)?;
            writer.id(session.into_bytes())?;
            writer.id(turn.into_bytes())?;
            writer.u64(*expected_revision)?;
            writer.id(idempotency_key.into_bytes())
        }
        AgentCommandV1::Cancel {
            session,
            turn,
            expected_revision,
            idempotency_key,
            now,
        } => {
            writer.byte(6)?;
            writer.u64(*now)?;
            writer.id(session.into_bytes())?;
            writer.id(turn.into_bytes())?;
            writer.u64(*expected_revision)?;
            writer.id(idempotency_key.into_bytes())
        }
        AgentCommandV1::Close {
            session,
            expected_revision,
            idempotency_key,
            now,
        } => {
            writer.byte(7)?;
            writer.u64(*now)?;
            writer.id(session.into_bytes())?;
            writer.u64(*expected_revision)?;
            writer.id(idempotency_key.into_bytes())
        }
    }
}

fn decode_command(reader: &mut Reader<'_>) -> Result<AgentCommandV1, AgentWireCodecErrorV1> {
    Ok(match reader.byte()? {
        1 => {
            let now = reader.u64()?;
            let session = AgentSessionIdV1::new(reader.id()?);
            let execution = decode_execute(reader)?;
            let workspace = reader.id()?;
            let budget = decode_budget(reader)?;
            AgentCommandV1::Open {
                request: AgentOpenRequestV1 {
                    session,
                    execution,
                    workspace,
                    budget,
                },
                now,
            }
        }
        2 => {
            let now = reader.u64()?;
            let session = AgentSessionIdV1::new(reader.id()?);
            let turn = AgentTurnIdV1::new(reader.id()?);
            let expected_revision = reader.u64()?;
            let execution = decode_execute(reader)?;
            let prompt_digest = ContentDigestV1::new(reader.digest()?);
            let prompt = reader.bytes(reader.limits.max_prompt_bytes)?;
            AgentCommandV1::Prompt {
                request: AgentTurnRequestV1 {
                    session,
                    turn,
                    expected_revision,
                    execution,
                    prompt_digest,
                    prompt,
                },
                now,
            }
        }
        3 => AgentCommandV1::Events {
            session: AgentSessionIdV1::new(reader.id()?),
            after: decode_optional_u64(reader)?,
            limit: reader.u64()?,
        },
        4 => AgentCommandV1::Inspect {
            session: AgentSessionIdV1::new(reader.id()?),
        },
        5 => {
            let now = reader.u64()?;
            let session = AgentSessionIdV1::new(reader.id()?);
            let expected_revision = reader.u64()?;
            let execution = decode_execute(reader)?;
            let decision = AgentPermissionDecisionV1 {
                request: AgentPermissionRequestIdV1::new(reader.id()?),
                option: AgentPermissionOptionIdV1::new(reader.id()?),
            };
            AgentCommandV1::DecidePermission {
                session,
                expected_revision,
                execution,
                decision,
                now,
            }
        }
        6 => {
            let now = reader.u64()?;
            AgentCommandV1::Cancel {
                session: AgentSessionIdV1::new(reader.id()?),
                turn: AgentTurnIdV1::new(reader.id()?),
                expected_revision: reader.u64()?,
                idempotency_key: IdempotencyKeyV1::new(reader.id()?),
                now,
            }
        }
        7 => {
            let now = reader.u64()?;
            AgentCommandV1::Close {
                session: AgentSessionIdV1::new(reader.id()?),
                expected_revision: reader.u64()?,
                idempotency_key: IdempotencyKeyV1::new(reader.id()?),
                now,
            }
        }
        8 => {
            let now = reader.u64()?;
            AgentCommandV1::Advance {
                session: AgentSessionIdV1::new(reader.id()?),
                turn: AgentTurnIdV1::new(reader.id()?),
                expected_revision: reader.u64()?,
                idempotency_key: IdempotencyKeyV1::new(reader.id()?),
                now,
            }
        }
        9 => {
            let now = reader.u64()?;
            AgentCommandV1::Reattach {
                session: AgentSessionIdV1::new(reader.id()?),
                expected_revision: reader.u64()?,
                execution: decode_execute(reader)?,
                now,
            }
        }
        _ => return Err(AgentWireCodecErrorV1::Malformed),
    })
}

fn encode_execute(
    writer: &mut Writer,
    request: &ExecuteRequestV1,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentWireCodecErrorV1> {
    if request.context.len() > limits.max_context_references
        || request.tools.len() > limits.max_tools
    {
        return Err(AgentWireCodecErrorV1::Limit);
    }
    writer.id(request.execution_id.into_bytes())?;
    writer.id(request.task_attempt.task_key)?;
    writer.u64(request.task_attempt.task_incarnation)?;
    writer.u64(u64::from(request.task_attempt.attempt_number))?;
    writer.id(request.principal.into_bytes())?;
    writer.id(request.profile.into_bytes())?;
    writer.id(request.idempotency_key.into_bytes())?;
    writer.u32(request.context.len())?;
    for reference in &request.context {
        writer.id(reference.into_bytes())?;
    }
    writer.u32(request.tools.len())?;
    for tool in &request.tools {
        writer.id(tool.into_bytes())?;
    }
    writer.u64(request.budget.max_elapsed_millis)?;
    writer.u64(request.budget.max_input_tokens)?;
    writer.u64(request.budget.max_output_tokens)?;
    writer.u64(u64::from(request.budget.max_tool_calls))?;
    writer.u64(
        u64::try_from(request.budget.max_context_bytes)
            .map_err(|_| AgentWireCodecErrorV1::Limit)?,
    )?;
    writer.u64(
        u64::try_from(request.budget.max_output_bytes).map_err(|_| AgentWireCodecErrorV1::Limit)?,
    )
}

fn decode_execute(reader: &mut Reader<'_>) -> Result<ExecuteRequestV1, AgentWireCodecErrorV1> {
    let execution_id = ExecutionIdV1::new(reader.id()?);
    let task_attempt = TaskAttemptRefV1 {
        task_key: reader.id()?,
        task_incarnation: reader.u64()?,
        attempt_number: u32::try_from(reader.u64()?).map_err(|_| AgentWireCodecErrorV1::Limit)?,
    };
    let principal = PrincipalIdV1::new(reader.id()?);
    let profile = HarnessProfileIdV1::new(reader.id()?);
    let idempotency_key = IdempotencyKeyV1::new(reader.id()?);
    let context_count = bounded_count(reader, reader.limits.max_context_references, 16)?;
    let mut context = Vec::new();
    context
        .try_reserve(context_count)
        .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
    for _ in 0..context_count {
        context.push(ContextReferenceIdV1::new(reader.id()?));
    }
    let tool_count = bounded_count(reader, reader.limits.max_tools, 16)?;
    let mut tools = Vec::new();
    tools
        .try_reserve(tool_count)
        .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
    for _ in 0..tool_count {
        tools.push(ToolCapabilityIdV1::new(reader.id()?));
    }
    Ok(ExecuteRequestV1 {
        execution_id,
        task_attempt,
        principal,
        profile,
        idempotency_key,
        context,
        tools,
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: reader.u64()?,
            max_input_tokens: reader.u64()?,
            max_output_tokens: reader.u64()?,
            max_tool_calls: u32::try_from(reader.u64()?)
                .map_err(|_| AgentWireCodecErrorV1::Limit)?,
            max_context_bytes: usize::try_from(reader.u64()?)
                .map_err(|_| AgentWireCodecErrorV1::Limit)?,
            max_output_bytes: usize::try_from(reader.u64()?)
                .map_err(|_| AgentWireCodecErrorV1::Limit)?,
        },
    })
}

fn encode_budget(
    writer: &mut Writer,
    budget: AgentSessionBudgetV1,
) -> Result<(), AgentWireCodecErrorV1> {
    writer.u64(budget.max_elapsed_millis)?;
    writer.u64(u64::from(budget.max_turns))?;
    writer.u64(budget.max_events)?;
    writer.u64(u64::try_from(budget.max_event_bytes).map_err(|_| AgentWireCodecErrorV1::Limit)?)?;
    writer
        .u64(u64::try_from(budget.max_prompt_bytes).map_err(|_| AgentWireCodecErrorV1::Limit)?)?;
    writer.u64(u64::from(budget.max_permission_requests))
}

fn decode_budget(reader: &mut Reader<'_>) -> Result<AgentSessionBudgetV1, AgentWireCodecErrorV1> {
    Ok(AgentSessionBudgetV1 {
        max_elapsed_millis: reader.u64()?,
        max_turns: u32::try_from(reader.u64()?).map_err(|_| AgentWireCodecErrorV1::Limit)?,
        max_events: reader.u64()?,
        max_event_bytes: usize::try_from(reader.u64()?)
            .map_err(|_| AgentWireCodecErrorV1::Limit)?,
        max_prompt_bytes: usize::try_from(reader.u64()?)
            .map_err(|_| AgentWireCodecErrorV1::Limit)?,
        max_permission_requests: u32::try_from(reader.u64()?)
            .map_err(|_| AgentWireCodecErrorV1::Limit)?,
    })
}

fn encode_outcome(
    writer: &mut Writer,
    outcome: &AgentOutcomeV1,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentWireCodecErrorV1> {
    match outcome {
        AgentOutcomeV1::Session(view) => {
            writer.byte(1)?;
            encode_view(writer, view)
        }
        AgentOutcomeV1::Events(page) => {
            if page.entries.len() > limits.max_events {
                return Err(AgentWireCodecErrorV1::Limit);
            }
            writer.byte(2)?;
            writer.id(page.session.into_bytes())?;
            writer.u32(page.entries.len())?;
            for record in &page.entries {
                writer.u64(record.cursor)?;
                encode_event(writer, &record.event, limits)?;
            }
            encode_optional_u64(writer, page.next_after)
        }
        AgentOutcomeV1::OutcomeUnknown {
            session,
            idempotency_key,
        } => {
            writer.byte(3)?;
            writer.id(session.into_bytes())?;
            writer.id(idempotency_key.into_bytes())
        }
    }
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<AgentOutcomeV1, AgentWireCodecErrorV1> {
    Ok(match reader.byte()? {
        1 => AgentOutcomeV1::Session(decode_view(reader)?),
        2 => {
            let session = AgentSessionIdV1::new(reader.id()?);
            let count = bounded_count(reader, reader.limits.max_events, 9)?;
            let mut entries = Vec::new();
            entries
                .try_reserve(count)
                .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
            for _ in 0..count {
                entries.push(AgentEventRecordV1 {
                    cursor: reader.u64()?,
                    event: decode_event(reader)?,
                });
            }
            AgentOutcomeV1::Events(AgentEventPageV1 {
                session,
                entries,
                next_after: decode_optional_u64(reader)?,
            })
        }
        3 => AgentOutcomeV1::OutcomeUnknown {
            session: AgentSessionIdV1::new(reader.id()?),
            idempotency_key: IdempotencyKeyV1::new(reader.id()?),
        },
        _ => return Err(AgentWireCodecErrorV1::Malformed),
    })
}

fn encode_view(
    writer: &mut Writer,
    view: &AgentSessionViewV1,
) -> Result<(), AgentWireCodecErrorV1> {
    writer.id(view.session.into_bytes())?;
    writer.u64(view.revision)?;
    writer.byte(phase_tag(view.phase))?;
    writer.digest(view.profile_document_digest.into_bytes())?;
    encode_optional_id(writer, view.active_turn.map(AgentTurnIdV1::into_bytes))?;
    encode_optional_u64(writer, view.last_event_cursor)?;
    writer.byte(capability_bits(view.capabilities))
}

fn decode_view(reader: &mut Reader<'_>) -> Result<AgentSessionViewV1, AgentWireCodecErrorV1> {
    Ok(AgentSessionViewV1 {
        session: AgentSessionIdV1::new(reader.id()?),
        revision: reader.u64()?,
        phase: decode_phase(reader.byte()?)?,
        profile_document_digest: ContentDigestV1::new(reader.digest()?),
        active_turn: decode_optional_id(reader)?.map(AgentTurnIdV1::new),
        last_event_cursor: decode_optional_u64(reader)?,
        capabilities: decode_capabilities(reader.byte()?)?,
    })
}

fn encode_event(
    writer: &mut Writer,
    event: &AgentEventV1,
    limits: AgentWireLimitsV1,
) -> Result<(), AgentWireCodecErrorV1> {
    if event_size(event) > limits.max_event_bytes {
        return Err(AgentWireCodecErrorV1::Limit);
    }
    match event {
        AgentEventV1::AssistantMessage { bytes } => {
            writer.byte(1)?;
            writer.bytes(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Thought { bytes } => {
            writer.byte(2)?;
            writer.bytes(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Plan { bytes } => {
            writer.byte(3)?;
            writer.bytes(bytes, limits.max_event_bytes)
        }
        AgentEventV1::ToolCall { title, detail } => {
            writer.byte(4)?;
            writer.bytes(title, limits.max_event_bytes)?;
            writer.bytes(detail, limits.max_event_bytes)
        }
        AgentEventV1::Terminal { stream, bytes } => {
            writer.byte(5)?;
            writer.bytes(stream, limits.max_event_bytes)?;
            writer.bytes(bytes, limits.max_event_bytes)
        }
        AgentEventV1::Permission(request) => {
            if request.options.is_empty() || request.options.len() > limits.max_permission_options {
                return Err(AgentWireCodecErrorV1::Limit);
            }
            writer.byte(6)?;
            writer.id(request.request.into_bytes())?;
            writer.id(request.turn.into_bytes())?;
            writer.bytes(&request.capability, limits.max_event_bytes)?;
            writer.bytes(&request.description, limits.max_event_bytes)?;
            writer.u32(request.options.len())?;
            for option in &request.options {
                writer.id(option.id.into_bytes())?;
                writer.byte(permission_kind_tag(option.kind))?;
                writer.bytes(&option.label, limits.max_event_bytes)?;
            }
            Ok(())
        }
        AgentEventV1::FileChange {
            path,
            content_digest,
        } => {
            writer.byte(7)?;
            writer.bytes(path, limits.max_event_bytes)?;
            writer.digest(content_digest.into_bytes())
        }
        AgentEventV1::Usage {
            input_tokens,
            output_tokens,
        } => {
            writer.byte(8)?;
            writer.u64(*input_tokens)?;
            writer.u64(*output_tokens)
        }
        AgentEventV1::TurnFinished {
            turn,
            disposition,
            stop_reason,
            output_digest,
        } => {
            writer.byte(9)?;
            writer.id(turn.into_bytes())?;
            writer.byte(disposition_tag(*disposition))?;
            writer.byte(stop_reason_tag(*stop_reason))?;
            encode_optional_digest(writer, output_digest.map(ContentDigestV1::into_bytes))
        }
        AgentEventV1::FileRead {
            path,
            content_digest,
            content_bytes,
        } => {
            writer.byte(10)?;
            writer.bytes(path, limits.max_event_bytes)?;
            writer.digest(content_digest.into_bytes())?;
            writer.u64(u64::try_from(*content_bytes).map_err(|_| AgentWireCodecErrorV1::Limit)?)
        }
    }
}

fn decode_event(reader: &mut Reader<'_>) -> Result<AgentEventV1, AgentWireCodecErrorV1> {
    let event = match reader.byte()? {
        1 => AgentEventV1::AssistantMessage {
            bytes: reader.bytes(reader.limits.max_event_bytes)?,
        },
        2 => AgentEventV1::Thought {
            bytes: reader.bytes(reader.limits.max_event_bytes)?,
        },
        3 => AgentEventV1::Plan {
            bytes: reader.bytes(reader.limits.max_event_bytes)?,
        },
        4 => AgentEventV1::ToolCall {
            title: reader.bytes(reader.limits.max_event_bytes)?,
            detail: reader.bytes(reader.limits.max_event_bytes)?,
        },
        5 => AgentEventV1::Terminal {
            stream: reader.bytes(reader.limits.max_event_bytes)?,
            bytes: reader.bytes(reader.limits.max_event_bytes)?,
        },
        6 => {
            let request = AgentPermissionRequestIdV1::new(reader.id()?);
            let turn = AgentTurnIdV1::new(reader.id()?);
            let capability = reader.bytes(reader.limits.max_event_bytes)?;
            let description = reader.bytes(reader.limits.max_event_bytes)?;
            let count = bounded_count(reader, reader.limits.max_permission_options, 21)?;
            if count == 0 {
                return Err(AgentWireCodecErrorV1::Malformed);
            }
            let mut options = Vec::new();
            options
                .try_reserve(count)
                .map_err(|_| AgentWireCodecErrorV1::Capacity)?;
            for _ in 0..count {
                options.push(AgentPermissionOptionV1 {
                    id: AgentPermissionOptionIdV1::new(reader.id()?),
                    kind: decode_permission_kind(reader.byte()?)?,
                    label: reader.bytes(reader.limits.max_event_bytes)?,
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
        7 => AgentEventV1::FileChange {
            path: reader.bytes(reader.limits.max_event_bytes)?,
            content_digest: ContentDigestV1::new(reader.digest()?),
        },
        8 => AgentEventV1::Usage {
            input_tokens: reader.u64()?,
            output_tokens: reader.u64()?,
        },
        9 => AgentEventV1::TurnFinished {
            turn: AgentTurnIdV1::new(reader.id()?),
            disposition: decode_disposition(reader.byte()?)?,
            stop_reason: decode_stop_reason(reader.byte()?)?,
            output_digest: decode_optional_digest(reader)?.map(ContentDigestV1::new),
        },
        10 => AgentEventV1::FileRead {
            path: reader.bytes(reader.limits.max_event_bytes)?,
            content_digest: ContentDigestV1::new(reader.digest()?),
            content_bytes: usize::try_from(reader.u64()?)
                .map_err(|_| AgentWireCodecErrorV1::Limit)?,
        },
        _ => return Err(AgentWireCodecErrorV1::Malformed),
    };
    if event_size(&event) > reader.limits.max_event_bytes {
        return Err(AgentWireCodecErrorV1::Limit);
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

fn bounded_count(
    reader: &mut Reader<'_>,
    maximum: usize,
    minimum_item_bytes: usize,
) -> Result<usize, AgentWireCodecErrorV1> {
    let count = reader.u32()?;
    if count > maximum
        || count
            .checked_mul(minimum_item_bytes)
            .is_none_or(|bytes| bytes > reader.bytes.len().saturating_sub(reader.position))
    {
        return Err(AgentWireCodecErrorV1::Limit);
    }
    Ok(count)
}

fn encode_optional_u64(
    writer: &mut Writer,
    value: Option<u64>,
) -> Result<(), AgentWireCodecErrorV1> {
    writer.boolean(value.is_some())?;
    if let Some(value) = value {
        writer.u64(value)?;
    }
    Ok(())
}

fn decode_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, AgentWireCodecErrorV1> {
    if reader.boolean()? {
        Ok(Some(reader.u64()?))
    } else {
        Ok(None)
    }
}

fn encode_optional_id(
    writer: &mut Writer,
    value: Option<[u8; 16]>,
) -> Result<(), AgentWireCodecErrorV1> {
    writer.boolean(value.is_some())?;
    if let Some(value) = value {
        writer.id(value)?;
    }
    Ok(())
}

fn decode_optional_id(reader: &mut Reader<'_>) -> Result<Option<[u8; 16]>, AgentWireCodecErrorV1> {
    if reader.boolean()? {
        Ok(Some(reader.id()?))
    } else {
        Ok(None)
    }
}

fn encode_optional_digest(
    writer: &mut Writer,
    value: Option<[u8; 32]>,
) -> Result<(), AgentWireCodecErrorV1> {
    writer.boolean(value.is_some())?;
    if let Some(value) = value {
        writer.digest(value)?;
    }
    Ok(())
}

fn decode_optional_digest(
    reader: &mut Reader<'_>,
) -> Result<Option<[u8; 32]>, AgentWireCodecErrorV1> {
    if reader.boolean()? {
        Ok(Some(reader.digest()?))
    } else {
        Ok(None)
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

fn decode_capabilities(value: u8) -> Result<AgentCapabilitiesV1, AgentWireCodecErrorV1> {
    Ok(AgentCapabilitiesV1 {
        load_session: value & 1 != 0,
        resume_session: value & 2 != 0,
        permissions: value & 4 != 0,
        filesystem_read: value & 8 != 0,
        filesystem_write: value & 16 != 0,
        terminal: value & 32 != 0,
        session_modes: value & 64 != 0,
        session_models: value & 128 != 0,
    })
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

fn decode_phase(value: u8) -> Result<AgentSessionPhaseV1, AgentWireCodecErrorV1> {
    match value {
        0 => Ok(AgentSessionPhaseV1::Opening),
        1 => Ok(AgentSessionPhaseV1::Ready),
        2 => Ok(AgentSessionPhaseV1::TurnActive),
        3 => Ok(AgentSessionPhaseV1::AwaitingPermission),
        4 => Ok(AgentSessionPhaseV1::OutcomeUnknown),
        5 => Ok(AgentSessionPhaseV1::Closed),
        6 => Ok(AgentSessionPhaseV1::ReattachRequired),
        _ => Err(AgentWireCodecErrorV1::Malformed),
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

fn decode_permission_kind(value: u8) -> Result<AgentPermissionOptionKindV1, AgentWireCodecErrorV1> {
    match value {
        0 => Ok(AgentPermissionOptionKindV1::AllowOnce),
        1 => Ok(AgentPermissionOptionKindV1::AllowAlways),
        2 => Ok(AgentPermissionOptionKindV1::RejectOnce),
        3 => Ok(AgentPermissionOptionKindV1::RejectAlways),
        _ => Err(AgentWireCodecErrorV1::Malformed),
    }
}

fn disposition_tag(value: ExecutionDispositionV1) -> u8 {
    match value {
        ExecutionDispositionV1::Completed => 0,
        ExecutionDispositionV1::Cancelled => 1,
        ExecutionDispositionV1::TimedOut => 2,
        ExecutionDispositionV1::Failed => 3,
        ExecutionDispositionV1::Uncertain => 4,
    }
}

fn decode_disposition(value: u8) -> Result<ExecutionDispositionV1, AgentWireCodecErrorV1> {
    match value {
        0 => Ok(ExecutionDispositionV1::Completed),
        1 => Ok(ExecutionDispositionV1::Cancelled),
        2 => Ok(ExecutionDispositionV1::TimedOut),
        3 => Ok(ExecutionDispositionV1::Failed),
        4 => Ok(ExecutionDispositionV1::Uncertain),
        _ => Err(AgentWireCodecErrorV1::Malformed),
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

fn decode_stop_reason(value: u8) -> Result<AgentTurnStopReasonV1, AgentWireCodecErrorV1> {
    match value {
        0 => Ok(AgentTurnStopReasonV1::EndTurn),
        1 => Ok(AgentTurnStopReasonV1::Cancelled),
        2 => Ok(AgentTurnStopReasonV1::TimedOut),
        3 => Ok(AgentTurnStopReasonV1::Failed),
        4 => Ok(AgentTurnStopReasonV1::Disconnected),
        5 => Ok(AgentTurnStopReasonV1::OutcomeUnknown),
        _ => Err(AgentWireCodecErrorV1::Malformed),
    }
}

fn refusal_tag(value: AgentRefusalV1) -> u8 {
    match value {
        AgentRefusalV1::UnknownServiceSession => 0,
        AgentRefusalV1::PrincipalMismatch => 1,
        AgentRefusalV1::UnknownAgentSession => 2,
        AgentRefusalV1::UnknownTurn => 3,
        AgentRefusalV1::UnknownPermissionRequest => 4,
        AgentRefusalV1::UnknownPermissionOption => 5,
        AgentRefusalV1::RevisionConflict => 6,
        AgentRefusalV1::AuthorityDenied => 7,
        AgentRefusalV1::AuthorityExpired => 8,
        AgentRefusalV1::AttemptDenied => 9,
        AgentRefusalV1::IdempotencyConflict => 10,
        AgentRefusalV1::SessionConflict => 11,
        AgentRefusalV1::TurnConflict => 12,
        AgentRefusalV1::ProviderReceiptMismatch => 13,
        AgentRefusalV1::ProviderReceiptConflict => 14,
        AgentRefusalV1::Busy => 15,
        AgentRefusalV1::Capacity => 16,
        AgentRefusalV1::Limit => 17,
        AgentRefusalV1::Unsupported => 18,
        AgentRefusalV1::InvalidInput => 19,
        AgentRefusalV1::Closed => 20,
    }
}

fn decode_refusal(value: u8) -> Result<AgentRefusalV1, AgentWireCodecErrorV1> {
    match value {
        0 => Ok(AgentRefusalV1::UnknownServiceSession),
        1 => Ok(AgentRefusalV1::PrincipalMismatch),
        2 => Ok(AgentRefusalV1::UnknownAgentSession),
        3 => Ok(AgentRefusalV1::UnknownTurn),
        4 => Ok(AgentRefusalV1::UnknownPermissionRequest),
        5 => Ok(AgentRefusalV1::UnknownPermissionOption),
        6 => Ok(AgentRefusalV1::RevisionConflict),
        7 => Ok(AgentRefusalV1::AuthorityDenied),
        8 => Ok(AgentRefusalV1::AuthorityExpired),
        9 => Ok(AgentRefusalV1::AttemptDenied),
        10 => Ok(AgentRefusalV1::IdempotencyConflict),
        11 => Ok(AgentRefusalV1::SessionConflict),
        12 => Ok(AgentRefusalV1::TurnConflict),
        13 => Ok(AgentRefusalV1::ProviderReceiptMismatch),
        14 => Ok(AgentRefusalV1::ProviderReceiptConflict),
        15 => Ok(AgentRefusalV1::Busy),
        16 => Ok(AgentRefusalV1::Capacity),
        17 => Ok(AgentRefusalV1::Limit),
        18 => Ok(AgentRefusalV1::Unsupported),
        19 => Ok(AgentRefusalV1::InvalidInput),
        20 => Ok(AgentRefusalV1::Closed),
        _ => Err(AgentWireCodecErrorV1::Malformed),
    }
}

fn validate_limits(limits: AgentWireLimitsV1) -> Result<(), AgentWireCodecErrorV1> {
    if limits.max_frame_bytes < 9
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_prompt_bytes == 0
        || limits.max_events == 0
        || limits.max_event_bytes == 0
        || limits.max_permission_options == 0
    {
        return Err(AgentWireCodecErrorV1::Limit);
    }
    Ok(())
}
