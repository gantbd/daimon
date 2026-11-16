//! Canonical bounded V1 codec for Daimon requests, replies and session handshakes.

#![forbid(unsafe_code)]

pub mod agent;

use daimon_protocol::*;

const MAGIC: &[u8; 8] = b"DAIMONW1";
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const SESSION_OPENED: u8 = 3;
const MODEL_REQUEST: u8 = 4;
const MODEL_REPLY: u8 = 5;
const MODEL_REPLY_V2: u8 = 6;
const MODEL_REPLY_V3: u8 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitsV1 {
    pub max_frame_bytes: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_artifacts: usize,
}

impl Default for LimitsV1 {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_context_references: 64,
            max_tools: 64,
            max_artifacts: 64,
        }
    }
}

/// Independent limits for the additive model-execution frame family.
///
/// Keeping these limits separate prevents a model-output increase from
/// silently widening the legacy artifact execution protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLimitsV1 {
    pub max_frame_bytes: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_output_bytes: usize,
    pub max_proposals: usize,
    pub max_proposal_bytes: usize,
}

impl Default for ModelLimitsV1 {
    fn default() -> Self {
        Self {
            max_frame_bytes: 4 * 1024 * 1024,
            max_context_references: 64,
            max_tools: 64,
            max_output_bytes: 1024 * 1024,
            max_proposals: 64,
            max_proposal_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecErrorV1 {
    Limit,
    Malformed,
    Unsupported,
    Capacity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFrameV1 {
    pub session: SessionHandleV1,
    pub command: CommandV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRequestFrameV1 {
    pub session: SessionHandleV1,
    pub command: ModelCommandV1,
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Writer {
    fn new(limit: usize, kind: u8) -> Result<Self, CodecErrorV1> {
        if limit < 9 {
            return Err(CodecErrorV1::Limit);
        }
        let mut value = Self {
            bytes: Vec::new(),
            limit,
        };
        value.raw(MAGIC)?;
        value.byte(kind)?;
        Ok(value)
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), CodecErrorV1> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(CodecErrorV1::Limit);
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| CodecErrorV1::Capacity)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), CodecErrorV1> {
        self.raw(&[value])
    }

    fn u32(&mut self, value: usize) -> Result<(), CodecErrorV1> {
        self.raw(
            &u32::try_from(value)
                .map_err(|_| CodecErrorV1::Limit)?
                .to_be_bytes(),
        )
    }

    fn u64(&mut self, value: u64) -> Result<(), CodecErrorV1> {
        self.raw(&value.to_be_bytes())
    }

    fn id(&mut self, value: [u8; 16]) -> Result<(), CodecErrorV1> {
        self.raw(&value)
    }

    fn digest(&mut self, value: [u8; 32]) -> Result<(), CodecErrorV1> {
        self.raw(&value)
    }

    fn bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), CodecErrorV1> {
        if value.len() > maximum {
            return Err(CodecErrorV1::Limit);
        }
        self.u32(value.len())?;
        self.raw(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: LimitsV1,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: LimitsV1, kind: u8) -> Result<Self, CodecErrorV1> {
        validate_limits(limits)?;
        if bytes.len() > limits.max_frame_bytes {
            return Err(CodecErrorV1::Limit);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes.get(8) != Some(&kind) {
            return Err(CodecErrorV1::Unsupported);
        }
        Ok(Self {
            bytes,
            position: 9,
            limits,
        })
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], CodecErrorV1> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(CodecErrorV1::Malformed)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecErrorV1::Malformed)?;
        self.position = end;
        value.try_into().map_err(|_| CodecErrorV1::Malformed)
    }

    fn byte(&mut self) -> Result<u8, CodecErrorV1> {
        Ok(self.raw::<1>()?[0])
    }

    fn u32(&mut self) -> Result<usize, CodecErrorV1> {
        usize::try_from(u32::from_be_bytes(self.raw()?)).map_err(|_| CodecErrorV1::Limit)
    }

    fn u64(&mut self) -> Result<u64, CodecErrorV1> {
        Ok(u64::from_be_bytes(self.raw()?))
    }

    fn id(&mut self) -> Result<[u8; 16], CodecErrorV1> {
        self.raw()
    }

    fn digest(&mut self) -> Result<[u8; 32], CodecErrorV1> {
        self.raw()
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, CodecErrorV1> {
        let count = self.u32()?;
        if count > maximum || count > self.bytes.len().saturating_sub(self.position) {
            return Err(CodecErrorV1::Limit);
        }
        let end = self
            .position
            .checked_add(count)
            .ok_or(CodecErrorV1::Malformed)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecErrorV1::Malformed)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(count)
            .map_err(|_| CodecErrorV1::Capacity)?;
        value.extend_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn ids<T>(
        &mut self,
        maximum: usize,
        make: impl Fn([u8; 16]) -> T,
    ) -> Result<Vec<T>, CodecErrorV1> {
        let count = self.u32()?;
        if count > maximum
            || count
                .checked_mul(16)
                .is_none_or(|bytes| bytes > self.bytes.len().saturating_sub(self.position))
        {
            return Err(CodecErrorV1::Limit);
        }
        let mut values = Vec::new();
        values
            .try_reserve(count)
            .map_err(|_| CodecErrorV1::Capacity)?;
        for _ in 0..count {
            values.push(make(self.id()?));
        }
        Ok(values)
    }

    fn finish(self) -> Result<(), CodecErrorV1> {
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(CodecErrorV1::Malformed)
    }
}

pub fn encode_request(frame: &RequestFrameV1, limits: LimitsV1) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, REQUEST)?;
    writer.u64(frame.session.0)?;
    match &frame.command {
        CommandV1::Execute { request, now } => {
            writer.byte(1)?;
            writer.u64(*now)?;
            encode_execute(&mut writer, request, limits)?;
        }
        CommandV1::ReadPresence { limit } => {
            if !(1..=daimon_protocol::MAX_PRESENCE_ENTRIES).contains(limit) {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(3)?;
            writer.byte(*limit)?;
        }
        CommandV1::Inspect { execution_id } => {
            writer.byte(2)?;
            writer.id(execution_id.into_bytes())?;
        }
    }
    Ok(writer.bytes)
}

pub fn decode_request(bytes: &[u8], limits: LimitsV1) -> Result<RequestFrameV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REQUEST)?;
    let session = SessionHandleV1(reader.u64()?);
    let command = match reader.byte()? {
        1 => {
            let now = reader.u64()?;
            CommandV1::Execute {
                request: decode_execute(&mut reader)?,
                now,
            }
        }
        2 => CommandV1::Inspect {
            execution_id: ExecutionIdV1::new(reader.id()?),
        },
        3 => {
            let limit = reader.byte()?;
            if !(1..=daimon_protocol::MAX_PRESENCE_ENTRIES).contains(&limit) {
                return Err(CodecErrorV1::Limit);
            }
            CommandV1::ReadPresence { limit }
        }
        _ => return Err(CodecErrorV1::Malformed),
    };
    reader.finish()?;
    Ok(RequestFrameV1 { session, command })
}

pub fn encode_reply(reply: &ReplyV1, limits: LimitsV1) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, REPLY)?;
    match reply {
        ReplyV1::Accepted(outcome) => {
            writer.byte(0)?;
            encode_outcome(&mut writer, outcome, limits)?;
        }
        ReplyV1::Refused(refusal) => {
            writer.byte(1)?;
            writer.byte(refusal_tag(*refusal))?;
        }
    }
    Ok(writer.bytes)
}

pub fn decode_reply(bytes: &[u8], limits: LimitsV1) -> Result<ReplyV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REPLY)?;
    let reply = match reader.byte()? {
        0 => ReplyV1::Accepted(decode_outcome(&mut reader)?),
        1 => ReplyV1::Refused(decode_refusal(reader.byte()?)?),
        _ => return Err(CodecErrorV1::Malformed),
    };
    reader.finish()?;
    Ok(reply)
}

pub fn encode_model_request(
    frame: &ModelRequestFrameV1,
    limits: ModelLimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_model_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, MODEL_REQUEST)?;
    writer.u64(frame.session.0)?;
    match &frame.command {
        ModelCommandV1::Execute { request, now } => {
            writer.byte(1)?;
            writer.u64(*now)?;
            encode_execute(&mut writer, request, legacy_limits(limits))?;
        }
        ModelCommandV1::Inspect { execution_id } => {
            writer.byte(2)?;
            writer.id(execution_id.into_bytes())?;
        }
        ModelCommandV1::Resume {
            request,
            source_execution,
            results,
            now,
        } => {
            if results.len() > limits.max_proposals {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(3)?;
            writer.u64(*now)?;
            encode_execute(&mut writer, request, legacy_limits(limits))?;
            writer.id(source_execution.into_bytes())?;
            writer.u32(results.len())?;
            for result in results {
                writer.id(result.request)?;
                writer.digest(result.evidence_digest.into_bytes())?;
                writer.digest(result.output_digest.into_bytes())?;
                writer.bytes(&result.output, limits.max_output_bytes)?;
            }
        }
    }
    Ok(writer.bytes)
}

pub fn decode_model_request(
    bytes: &[u8],
    limits: ModelLimitsV1,
) -> Result<ModelRequestFrameV1, CodecErrorV1> {
    validate_model_limits(limits)?;
    let mut reader = Reader::new(bytes, legacy_limits(limits), MODEL_REQUEST)?;
    let session = SessionHandleV1(reader.u64()?);
    let command = match reader.byte()? {
        1 => {
            let now = reader.u64()?;
            ModelCommandV1::Execute {
                request: decode_execute(&mut reader)?,
                now,
            }
        }
        2 => ModelCommandV1::Inspect {
            execution_id: ExecutionIdV1::new(reader.id()?),
        },
        3 => {
            let now = reader.u64()?;
            let request = decode_execute(&mut reader)?;
            let source_execution = ExecutionIdV1::new(reader.id()?);
            let count = reader.u32()?;
            if count > limits.max_proposals {
                return Err(CodecErrorV1::Limit);
            }
            let mut results = Vec::new();
            results
                .try_reserve(count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..count {
                results.push(ResumeToolResultV1 {
                    request: reader.id()?,
                    evidence_digest: ContentDigestV1::new(reader.digest()?),
                    output_digest: ContentDigestV1::new(reader.digest()?),
                    output: reader.bytes(limits.max_output_bytes)?,
                });
            }
            ModelCommandV1::Resume {
                request,
                source_execution,
                results,
                now,
            }
        }
        _ => return Err(CodecErrorV1::Malformed),
    };
    reader.finish()?;
    Ok(ModelRequestFrameV1 { session, command })
}

pub fn encode_model_reply(
    reply: &ModelReplyV1,
    limits: ModelLimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_model_limits(limits)?;
    let native_tools = reply_has_tool_calls(reply);
    let kind = if native_tools {
        MODEL_REPLY_V3
    } else {
        MODEL_REPLY
    };
    let mut writer = Writer::new(limits.max_frame_bytes, kind)?;
    match reply {
        ModelReplyV1::Accepted(outcome) => {
            writer.byte(0)?;
            encode_model_outcome(&mut writer, outcome, limits, native_tools)?;
        }
        ModelReplyV1::Refused(refusal) => {
            writer.byte(1)?;
            writer.byte(refusal_tag(*refusal))?;
        }
    }
    Ok(writer.bytes)
}

pub fn decode_model_reply(
    bytes: &[u8],
    limits: ModelLimitsV1,
) -> Result<ModelReplyV1, CodecErrorV1> {
    validate_model_limits(limits)?;
    let (native_tools, provider_correlation) = match bytes.get(8).copied() {
        Some(MODEL_REPLY) => (false, false),
        Some(MODEL_REPLY_V2) => (true, false),
        Some(MODEL_REPLY_V3) => (true, true),
        _ => return Err(CodecErrorV1::Malformed),
    };
    let mut reader = Reader::new(
        bytes,
        legacy_limits(limits),
        if provider_correlation {
            MODEL_REPLY_V3
        } else if native_tools {
            MODEL_REPLY_V2
        } else {
            MODEL_REPLY
        },
    )?;
    let reply = match reader.byte()? {
        0 => ModelReplyV1::Accepted(decode_model_outcome(
            &mut reader,
            limits,
            native_tools,
            provider_correlation,
        )?),
        1 => ModelReplyV1::Refused(decode_refusal(reader.byte()?)?),
        _ => return Err(CodecErrorV1::Malformed),
    };
    reader.finish()?;
    if native_tools != reply_has_tool_calls(&reply) {
        return Err(CodecErrorV1::Malformed);
    }
    Ok(reply)
}

pub fn encode_session_opened(
    session: SessionHandleV1,
    limits: LimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    let mut writer = Writer::new(limits.max_frame_bytes, SESSION_OPENED)?;
    writer.u64(session.0)?;
    Ok(writer.bytes)
}

pub fn decode_session_opened(
    bytes: &[u8],
    limits: LimitsV1,
) -> Result<SessionHandleV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, SESSION_OPENED)?;
    let session = SessionHandleV1(reader.u64()?);
    reader.finish()?;
    Ok(session)
}

fn encode_execute(
    writer: &mut Writer,
    request: &ExecuteRequestV1,
    limits: LimitsV1,
) -> Result<(), CodecErrorV1> {
    if request.context.len() > limits.max_context_references
        || request.tools.len() > limits.max_tools
    {
        return Err(CodecErrorV1::Limit);
    }
    writer.id(request.execution_id.into_bytes())?;
    writer.id(request.task_attempt.task_key)?;
    writer.u64(request.task_attempt.task_incarnation)?;
    writer.u64(u64::from(request.task_attempt.attempt_number))?;
    writer.id(request.principal.into_bytes())?;
    writer.id(request.profile.into_bytes())?;
    writer.id(request.idempotency_key.into_bytes())?;
    encode_ids(writer, &request.context, |value| value.into_bytes())?;
    encode_ids(writer, &request.tools, |value| value.into_bytes())?;
    writer.u64(request.budget.max_elapsed_millis)?;
    writer.u64(request.budget.max_input_tokens)?;
    writer.u64(request.budget.max_output_tokens)?;
    writer.u64(u64::from(request.budget.max_tool_calls))?;
    writer
        .u64(u64::try_from(request.budget.max_context_bytes).map_err(|_| CodecErrorV1::Limit)?)?;
    writer.u64(u64::try_from(request.budget.max_output_bytes).map_err(|_| CodecErrorV1::Limit)?)
}

fn decode_execute(reader: &mut Reader<'_>) -> Result<ExecuteRequestV1, CodecErrorV1> {
    Ok(ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new(reader.id()?),
        task_attempt: TaskAttemptRefV1 {
            task_key: reader.id()?,
            task_incarnation: reader.u64()?,
            attempt_number: u32::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        },
        principal: PrincipalIdV1::new(reader.id()?),
        profile: HarnessProfileIdV1::new(reader.id()?),
        idempotency_key: IdempotencyKeyV1::new(reader.id()?),
        context: reader.ids(
            reader.limits.max_context_references,
            ContextReferenceIdV1::new,
        )?,
        tools: reader.ids(reader.limits.max_tools, ToolCapabilityIdV1::new)?,
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: reader.u64()?,
            max_input_tokens: reader.u64()?,
            max_output_tokens: reader.u64()?,
            max_tool_calls: u32::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
            max_context_bytes: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
            max_output_bytes: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        },
    })
}

fn encode_outcome(
    writer: &mut Writer,
    outcome: &OutcomeV1,
    limits: LimitsV1,
) -> Result<(), CodecErrorV1> {
    match outcome {
        OutcomeV1::Presence { entries, truncated } => {
            if entries.len() > usize::from(daimon_protocol::MAX_PRESENCE_ENTRIES) {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(4)?;
            writer.byte(u8::from(*truncated))?;
            writer.byte(entries.len() as u8)?;
            for entry in entries {
                writer.id(entry.agent)?;
                writer.u64(entry.age_millis)?;
                writer.byte(u8::from(entry.stale))?;
            }
            Ok(())
        }
        OutcomeV1::Executed(result) => {
            if result.produced_artifacts.len() > limits.max_artifacts {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(1)?;
            writer.id(result.execution_id.into_bytes())?;
            writer.byte(disposition_tag(result.disposition))?;
            writer.u64(u64::try_from(result.output_bytes).map_err(|_| CodecErrorV1::Limit)?)?;
            encode_ids(writer, &result.produced_artifacts, |value| {
                value.into_bytes()
            })
        }
        OutcomeV1::OutcomeUnknown { execution_id } => {
            writer.byte(2)?;
            writer.id(execution_id.into_bytes())
        }
        OutcomeV1::Status {
            execution_id,
            phase,
        } => {
            writer.byte(3)?;
            writer.id(execution_id.into_bytes())?;
            writer.byte(match phase {
                ExecutionPhaseV1::OutcomeUnknown => 0,
                ExecutionPhaseV1::Completed => 1,
            })
        }
    }
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<OutcomeV1, CodecErrorV1> {
    fn boolean(reader: &mut Reader<'_>) -> Result<bool, CodecErrorV1> {
        match reader.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecErrorV1::Malformed),
        }
    }
    Ok(match reader.byte()? {
        4 => {
            let truncated = boolean(reader)?;
            let count = reader.byte()?;
            if count > daimon_protocol::MAX_PRESENCE_ENTRIES {
                return Err(CodecErrorV1::Limit);
            }
            let mut entries = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                entries.push(daimon_protocol::PresenceEntryV1 {
                    agent: reader.id()?,
                    age_millis: reader.u64()?,
                    stale: boolean(reader)?,
                });
            }
            OutcomeV1::Presence { entries, truncated }
        }
        1 => OutcomeV1::Executed(ExecutionResultV1 {
            execution_id: ExecutionIdV1::new(reader.id()?),
            disposition: decode_disposition(reader.byte()?)?,
            output_bytes: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
            produced_artifacts: reader
                .ids(reader.limits.max_artifacts, ArtifactReferenceIdV1::new)?,
        }),
        2 => OutcomeV1::OutcomeUnknown {
            execution_id: ExecutionIdV1::new(reader.id()?),
        },
        3 => OutcomeV1::Status {
            execution_id: ExecutionIdV1::new(reader.id()?),
            phase: match reader.byte()? {
                0 => ExecutionPhaseV1::OutcomeUnknown,
                1 => ExecutionPhaseV1::Completed,
                _ => return Err(CodecErrorV1::Malformed),
            },
        },
        _ => return Err(CodecErrorV1::Malformed),
    })
}

fn encode_model_outcome(
    writer: &mut Writer,
    outcome: &ModelOutcomeV1,
    limits: ModelLimitsV1,
    native_tools: bool,
) -> Result<(), CodecErrorV1> {
    match outcome {
        ModelOutcomeV1::Executed(result) => {
            if result.proposals.len() > limits.max_proposals {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(1)?;
            writer.id(result.execution_id.into_bytes())?;
            writer.byte(disposition_tag(result.disposition))?;
            writer.digest(result.evidence_digest.into_bytes())?;
            writer.u64(result.input_tokens)?;
            writer.u64(result.output_tokens)?;
            writer.bytes(&result.output, limits.max_output_bytes)?;
            writer.u32(result.proposals.len())?;
            for proposal in &result.proposals {
                match proposal {
                    OutputProposalV1::AgoraMessage(proposal) => {
                        writer.byte(1)?;
                        writer.id(proposal.room)?;
                        writer.id(proposal.reply_to)?;
                        writer.bytes(&proposal.body, limits.max_proposal_bytes)?;
                    }
                    OutputProposalV1::VellumEdit(proposal) => {
                        writer.byte(2)?;
                        writer.id(proposal.workspace)?;
                        writer.id(proposal.document)?;
                        writer.u64(proposal.expected_revision)?;
                        writer.bytes(&proposal.replacement, limits.max_proposal_bytes)?;
                    }
                    OutputProposalV1::ToolCall(proposal) => {
                        if !native_tools {
                            return Err(CodecErrorV1::Malformed);
                        }
                        writer.byte(3)?;
                        writer.id(proposal.request)?;
                        writer.id(proposal.capability.into_bytes())?;
                        writer.bytes(&proposal.provider_correlation, limits.max_proposal_bytes)?;
                        writer.bytes(&proposal.arguments, limits.max_proposal_bytes)?;
                    }
                }
            }
            Ok(())
        }
        ModelOutcomeV1::OutcomeUnknown { execution_id } => {
            writer.byte(2)?;
            writer.id(execution_id.into_bytes())
        }
        ModelOutcomeV1::Status {
            execution_id,
            phase,
        } => {
            writer.byte(3)?;
            writer.id(execution_id.into_bytes())?;
            writer.byte(match phase {
                ExecutionPhaseV1::OutcomeUnknown => 0,
                ExecutionPhaseV1::Completed => 1,
            })
        }
    }
}

fn decode_model_outcome(
    reader: &mut Reader<'_>,
    limits: ModelLimitsV1,
    native_tools: bool,
    provider_correlation: bool,
) -> Result<ModelOutcomeV1, CodecErrorV1> {
    Ok(match reader.byte()? {
        1 => {
            let execution_id = ExecutionIdV1::new(reader.id()?);
            let disposition = decode_disposition(reader.byte()?)?;
            let evidence_digest = ContentDigestV1::new(reader.digest()?);
            let input_tokens = reader.u64()?;
            let output_tokens = reader.u64()?;
            let output = reader.bytes(limits.max_output_bytes)?;
            let count = reader.u32()?;
            if count > limits.max_proposals
                || count > reader.bytes.len().saturating_sub(reader.position)
            {
                return Err(CodecErrorV1::Limit);
            }
            let mut proposals = Vec::new();
            proposals
                .try_reserve(count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..count {
                proposals.push(match reader.byte()? {
                    1 => OutputProposalV1::AgoraMessage(AgoraMessageProposalV1 {
                        room: reader.id()?,
                        reply_to: reader.id()?,
                        body: reader.bytes(limits.max_proposal_bytes)?,
                    }),
                    2 => OutputProposalV1::VellumEdit(VellumEditProposalV1 {
                        workspace: reader.id()?,
                        document: reader.id()?,
                        expected_revision: reader.u64()?,
                        replacement: reader.bytes(limits.max_proposal_bytes)?,
                    }),
                    3 if native_tools => OutputProposalV1::ToolCall(ToolCallProposalV1 {
                        request: reader.id()?,
                        capability: ToolCapabilityIdV1::new(reader.id()?),
                        provider_correlation: if provider_correlation {
                            reader.bytes(limits.max_proposal_bytes)?
                        } else {
                            Vec::new()
                        },
                        arguments: reader.bytes(limits.max_proposal_bytes)?,
                    }),
                    _ => return Err(CodecErrorV1::Malformed),
                });
            }
            ModelOutcomeV1::Executed(ModelExecutionResultV1 {
                execution_id,
                disposition,
                evidence_digest,
                input_tokens,
                output_tokens,
                output,
                proposals,
            })
        }
        2 => ModelOutcomeV1::OutcomeUnknown {
            execution_id: ExecutionIdV1::new(reader.id()?),
        },
        3 => ModelOutcomeV1::Status {
            execution_id: ExecutionIdV1::new(reader.id()?),
            phase: match reader.byte()? {
                0 => ExecutionPhaseV1::OutcomeUnknown,
                1 => ExecutionPhaseV1::Completed,
                _ => return Err(CodecErrorV1::Malformed),
            },
        },
        _ => return Err(CodecErrorV1::Malformed),
    })
}

fn reply_has_tool_calls(reply: &ModelReplyV1) -> bool {
    matches!(
        reply,
        ModelReplyV1::Accepted(ModelOutcomeV1::Executed(result))
            if result.proposals.iter().any(|proposal| matches!(proposal, OutputProposalV1::ToolCall(_)))
    )
}

fn encode_ids<T>(
    writer: &mut Writer,
    values: &[T],
    bytes: impl Fn(&T) -> [u8; 16],
) -> Result<(), CodecErrorV1> {
    writer.u32(values.len())?;
    for value in values {
        writer.id(bytes(value))?;
    }
    Ok(())
}

fn disposition_tag(value: ExecutionDispositionV1) -> u8 {
    match value {
        ExecutionDispositionV1::Completed => 0,
        ExecutionDispositionV1::Failed => 1,
        ExecutionDispositionV1::Cancelled => 2,
        ExecutionDispositionV1::TimedOut => 3,
        ExecutionDispositionV1::Uncertain => 4,
    }
}

fn decode_disposition(value: u8) -> Result<ExecutionDispositionV1, CodecErrorV1> {
    Ok(match value {
        0 => ExecutionDispositionV1::Completed,
        1 => ExecutionDispositionV1::Failed,
        2 => ExecutionDispositionV1::Cancelled,
        3 => ExecutionDispositionV1::TimedOut,
        4 => ExecutionDispositionV1::Uncertain,
        _ => return Err(CodecErrorV1::Malformed),
    })
}

fn refusal_tag(value: RefusalV1) -> u8 {
    match value {
        RefusalV1::UnknownSession => 0,
        RefusalV1::PrincipalMismatch => 1,
        RefusalV1::AuthorityDenied => 2,
        RefusalV1::AuthorityExpired => 3,
        RefusalV1::AttemptDenied => 4,
        RefusalV1::IdempotencyConflict => 5,
        RefusalV1::ExecutionConflict => 6,
        RefusalV1::Capacity => 7,
        RefusalV1::InvalidBudget => 8,
        RefusalV1::BudgetLimit => 9,
        RefusalV1::ToolNotAuthorized => 10,
        RefusalV1::ContextLimit => 11,
        RefusalV1::ToolLimit => 12,
        RefusalV1::ProviderReceiptMismatch => 13,
        RefusalV1::ProviderReceiptConflict => 14,
        RefusalV1::OutputLimit => 15,
        RefusalV1::ArtifactLimit => 16,
        RefusalV1::UnknownExecution => 17,
        RefusalV1::InvalidInput => 18,
        RefusalV1::Exhausted => 19,
        RefusalV1::PresenceUnavailable => 20,
    }
}

fn decode_refusal(value: u8) -> Result<RefusalV1, CodecErrorV1> {
    Ok(match value {
        0 => RefusalV1::UnknownSession,
        1 => RefusalV1::PrincipalMismatch,
        2 => RefusalV1::AuthorityDenied,
        3 => RefusalV1::AuthorityExpired,
        4 => RefusalV1::AttemptDenied,
        5 => RefusalV1::IdempotencyConflict,
        6 => RefusalV1::ExecutionConflict,
        7 => RefusalV1::Capacity,
        8 => RefusalV1::InvalidBudget,
        9 => RefusalV1::BudgetLimit,
        10 => RefusalV1::ToolNotAuthorized,
        11 => RefusalV1::ContextLimit,
        12 => RefusalV1::ToolLimit,
        13 => RefusalV1::ProviderReceiptMismatch,
        14 => RefusalV1::ProviderReceiptConflict,
        15 => RefusalV1::OutputLimit,
        16 => RefusalV1::ArtifactLimit,
        17 => RefusalV1::UnknownExecution,
        18 => RefusalV1::InvalidInput,
        19 => RefusalV1::Exhausted,
        20 => RefusalV1::PresenceUnavailable,
        _ => return Err(CodecErrorV1::Malformed),
    })
}

fn validate_limits(limits: LimitsV1) -> Result<(), CodecErrorV1> {
    if limits.max_frame_bytes < 9
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_artifacts == 0
    {
        Err(CodecErrorV1::Limit)
    } else {
        Ok(())
    }
}

fn validate_model_limits(limits: ModelLimitsV1) -> Result<(), CodecErrorV1> {
    if limits.max_frame_bytes < 9
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_output_bytes == 0
        || limits.max_proposals == 0
        || limits.max_proposal_bytes == 0
        || limits.max_output_bytes > limits.max_frame_bytes
        || limits.max_proposal_bytes > limits.max_frame_bytes
    {
        Err(CodecErrorV1::Limit)
    } else {
        Ok(())
    }
}

fn legacy_limits(limits: ModelLimitsV1) -> LimitsV1 {
    LimitsV1 {
        max_frame_bytes: limits.max_frame_bytes,
        max_context_references: limits.max_context_references,
        max_tools: limits.max_tools,
        // Model frames never decode legacy artifacts, but Reader owns the
        // legacy limits and requires every dimension to be non-zero.
        max_artifacts: 1,
    }
}
