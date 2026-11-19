//! Canonical bounded checkpoint for the additive model-execution service.

use crate::{CodecErrorV1, StoreErrorV1};
use daimon_host::{
    ModelExecutionStore, ModelServiceSnapshotV1, StoreCommitV1, StoredModelExecutionStateV1,
    StoredModelExecutionV1,
};
use daimon_protocol as protocol;
use keystone_codec::{DecodeLimits, Decoder};
use keystone_storage::{
    AcknowledgementStrength, CheckpointStore, CommitGate, CommitGateFailure, CommitGateRefusal,
};
use std::collections::BTreeSet;

const KEY: &str = "daimon-model-service-v1";
const MAGIC: &[u8; 8] = b"DAIMONM4";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelStoreLimitsV1 {
    pub max_bytes: usize,
    pub max_executions: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_model_bytes: usize,
    pub max_context_bytes: usize,
    pub max_messages: usize,
    pub max_message_bytes: usize,
    pub max_output_bytes: usize,
    pub max_proposals: usize,
    pub max_proposal_bytes: usize,
}

impl Default for ModelStoreLimitsV1 {
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            max_executions: 65_536,
            max_context_references: 64,
            max_tools: 64,
            max_model_bytes: 4 * 1024,
            max_context_bytes: 1024 * 1024,
            max_messages: 256,
            max_message_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_proposals: 64,
            max_proposal_bytes: 1024 * 1024,
        }
    }
}

pub struct CheckpointModelExecutionStore<S> {
    backend: S,
    limits: ModelStoreLimitsV1,
    gate: Option<CommitGate>,
    require_existing: bool,
}

impl<S: CheckpointStore> CheckpointModelExecutionStore<S> {
    pub fn create(backend: S, limits: ModelStoreLimitsV1) -> Result<Self, StoreErrorV1<S::Error>> {
        validate_limits(limits).map_err(StoreErrorV1::Codec)?;
        let mut value = Self {
            backend,
            limits,
            gate: None,
            require_existing: false,
        };
        if value.load_model()?.is_some() {
            return Err(StoreErrorV1::AlreadyInitialized);
        }
        match value.commit_model(&ModelServiceSnapshotV1::default())? {
            StoreCommitV1::Committed => {
                value.require_existing = true;
                Ok(value)
            }
            StoreCommitV1::Indeterminate => Err(StoreErrorV1::InvalidReceipt),
        }
    }

    pub fn open_existing(
        backend: S,
        limits: ModelStoreLimitsV1,
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

impl<S: CheckpointStore> ModelExecutionStore for CheckpointModelExecutionStore<S> {
    type Error = StoreErrorV1<S::Error>;

    fn load_model(&mut self) -> Result<Option<ModelServiceSnapshotV1>, Self::Error> {
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

    fn commit_model(
        &mut self,
        snapshot: &ModelServiceSnapshotV1,
    ) -> Result<StoreCommitV1, Self::Error> {
        let bytes = encode(snapshot, self.limits).map_err(StoreErrorV1::Codec)?;
        let gate = self.gate.as_mut().ok_or(StoreErrorV1::NotLoaded)?;
        let expected = gate.confirmed_revision();
        let proposed = gate.next_revision().map_err(|error| match error {
            CommitGateRefusal::Fenced => StoreErrorV1::Fenced,
            CommitGateRefusal::RevisionExhausted => StoreErrorV1::RevisionExhausted,
        })?;
        let outcome = self.backend.compare_exchange(KEY, expected, &bytes);
        match gate.resolve(proposed, outcome) {
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

    fn field(&mut self, value: &[u8], maximum: usize) -> Result<(), CodecErrorV1> {
        if value.len() > maximum {
            return Err(CodecErrorV1::Limit);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve(value.len().saturating_add(4))
            .map_err(|_| CodecErrorV1::Capacity)?;
        keystone_codec::encode_bytes(&mut encoded, value).map_err(|_| CodecErrorV1::Limit)?;
        self.raw(&encoded)
    }

    fn id(&mut self, value: [u8; 16]) -> Result<(), CodecErrorV1> {
        self.field(&value, 16)
    }

    fn digest(&mut self, value: [u8; 32]) -> Result<(), CodecErrorV1> {
        self.field(&value, 32)
    }
}

struct Reader<'a> {
    decoder: Decoder<'a>,
    allocation_capacity: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: ModelStoreLimitsV1) -> Result<Self, CodecErrorV1> {
        let per_execution = 64usize
            .checked_add(limits.max_context_references.saturating_mul(5))
            .and_then(|value| value.checked_add(limits.max_tools.saturating_mul(2)))
            .and_then(|value| value.checked_add(limits.max_messages.saturating_mul(2)))
            .and_then(|value| value.checked_add(limits.max_proposals.saturating_mul(4)))
            .ok_or(CodecErrorV1::Limit)?;
        let max_fields = limits
            .max_executions
            .checked_mul(per_execution)
            .and_then(|value| value.checked_add(2))
            .ok_or(CodecErrorV1::Limit)?;
        let max_field_bytes = [
            32,
            limits.max_model_bytes,
            limits.max_context_bytes,
            limits.max_message_bytes,
            limits.max_output_bytes,
            limits.max_proposal_bytes,
        ]
        .into_iter()
        .max()
        .ok_or(CodecErrorV1::InvalidLimits)?;
        Ok(Self {
            decoder: Decoder::new(
                bytes,
                DecodeLimits {
                    max_input_bytes: limits.max_bytes,
                    max_field_bytes,
                    max_fields,
                },
            )
            .map_err(|_| CodecErrorV1::Limit)?,
            allocation_capacity: bytes.len(),
        })
    }

    fn byte(&mut self) -> Result<u8, CodecErrorV1> {
        self.decoder.read_u8().map_err(|_| CodecErrorV1::Truncated)
    }

    fn number(&mut self) -> Result<u64, CodecErrorV1> {
        self.decoder
            .read_u64_be()
            .map_err(|_| CodecErrorV1::Truncated)
    }

    fn field(&mut self, maximum: usize) -> Result<Vec<u8>, CodecErrorV1> {
        let value = self
            .decoder
            .read_bytes()
            .map_err(|_| CodecErrorV1::Truncated)?;
        if value.len() > maximum {
            return Err(CodecErrorV1::Limit);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| CodecErrorV1::Capacity)?;
        owned.extend_from_slice(value);
        Ok(owned)
    }

    fn id(&mut self) -> Result<[u8; 16], CodecErrorV1> {
        self.field(16)?
            .try_into()
            .map_err(|_| CodecErrorV1::Invalid)
    }

    fn digest(&mut self) -> Result<[u8; 32], CodecErrorV1> {
        self.field(32)?
            .try_into()
            .map_err(|_| CodecErrorV1::Invalid)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, CodecErrorV1> {
        let count = usize::try_from(self.number()?).map_err(|_| CodecErrorV1::Limit)?;
        if count > maximum.min(self.allocation_capacity) {
            return Err(CodecErrorV1::Limit);
        }
        Ok(count)
    }

    fn finish(&self) -> Result<(), CodecErrorV1> {
        self.decoder
            .is_finished()
            .then_some(())
            .ok_or(CodecErrorV1::Invalid)
    }
}

pub fn encode(
    snapshot: &ModelServiceSnapshotV1,
    limits: ModelStoreLimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    if snapshot.executions.len() > limits.max_executions {
        return Err(CodecErrorV1::Limit);
    }
    let mut writer = Writer::new(limits.max_bytes);
    writer.field(MAGIC, MAGIC.len())?;
    writer.byte(4)?;
    writer.number(count(snapshot.executions.len())?)?;
    let mut previous = None;
    for execution in &snapshot.executions {
        let current = execution.request.execution_id.into_bytes();
        if previous.is_some_and(|value| value >= current) {
            return Err(CodecErrorV1::Invalid);
        }
        previous = Some(current);
        encode_execution(&mut writer, execution, limits)?;
    }
    Ok(writer.bytes)
}

pub fn decode(
    bytes: &[u8],
    limits: ModelStoreLimitsV1,
) -> Result<ModelServiceSnapshotV1, CodecErrorV1> {
    validate_limits(limits)?;
    let mut reader = Reader::new(bytes, limits)?;
    if reader.field(MAGIC.len())? != MAGIC || reader.byte()? != 4 {
        return Err(CodecErrorV1::Invalid);
    }
    let execution_count = reader.count(limits.max_executions)?;
    let mut executions = Vec::new();
    executions
        .try_reserve(execution_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    let mut previous = None;
    for _ in 0..execution_count {
        let execution = decode_execution(&mut reader, limits)?;
        let current = execution.request.execution_id.into_bytes();
        if previous.is_some_and(|value| value >= current) {
            return Err(CodecErrorV1::Invalid);
        }
        previous = Some(current);
        executions.push(execution);
    }
    reader.finish()?;
    Ok(ModelServiceSnapshotV1 { executions })
}

fn encode_execution(
    writer: &mut Writer,
    execution: &StoredModelExecutionV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    let request = &execution.request;
    let invocation = &execution.invocation;
    if request.context.len() > limits.max_context_references
        || request.tools.len() > limits.max_tools
        || execution.authority_tools.len() > limits.max_tools
        || request.task_attempt.attempt_number == 0
        || !valid_budget(request.budget)
        || invocation.execution_id != request.execution_id
        || invocation.provider.harness_profile != request.profile
        || invocation.context.len() > limits.max_context_references
        || invocation.messages.len() > limits.max_messages
        || invocation.estimated_input_tokens > request.budget.max_input_tokens
    {
        return Err(CodecErrorV1::Invalid);
    }
    validate_context_shape(request, invocation, limits)?;

    encode_request(writer, request)?;
    writer.id(execution.authority_decision)?;
    writer.number(execution.authority_expires_at)?;
    encode_tool_ids(writer, &execution.authority_tools)?;
    writer.number(execution.prepared_at)?;
    encode_invocation(writer, invocation, limits)?;
    match &execution.state {
        StoredModelExecutionStateV1::OutcomeUnknown => writer.byte(0),
        StoredModelExecutionStateV1::Completed(result) => {
            validate_result(request, invocation, result, limits)?;
            writer.byte(1)?;
            encode_result(writer, result, limits)
        }
    }
}

fn decode_execution(
    reader: &mut Reader<'_>,
    limits: ModelStoreLimitsV1,
) -> Result<StoredModelExecutionV1, CodecErrorV1> {
    let request = decode_request(reader, limits)?;
    let authority_decision = reader.id()?;
    let authority_expires_at = reader.number()?;
    let authority_tools = decode_tool_ids(reader, limits.max_tools)?;
    let prepared_at = reader.number()?;
    let invocation = decode_invocation(reader, limits)?;
    if invocation.execution_id != request.execution_id
        || invocation.provider.harness_profile != request.profile
        || invocation.estimated_input_tokens > request.budget.max_input_tokens
    {
        return Err(CodecErrorV1::Invalid);
    }
    validate_context_shape(&request, &invocation, limits)?;
    let state = match reader.byte()? {
        0 => StoredModelExecutionStateV1::OutcomeUnknown,
        1 => {
            let result = decode_result(reader, limits, &invocation)?;
            validate_result(&request, &invocation, &result, limits)?;
            StoredModelExecutionStateV1::Completed(result)
        }
        _ => return Err(CodecErrorV1::Invalid),
    };
    Ok(StoredModelExecutionV1 {
        request,
        authority_decision,
        authority_expires_at,
        authority_tools,
        prepared_at,
        invocation,
        state,
    })
}

fn encode_request(
    writer: &mut Writer,
    request: &protocol::ExecuteRequestV1,
) -> Result<(), CodecErrorV1> {
    writer.id(request.execution_id.into_bytes())?;
    writer.id(request.task_attempt.task_key)?;
    writer.number(request.task_attempt.task_incarnation)?;
    writer.number(u64::from(request.task_attempt.attempt_number))?;
    writer.id(request.principal.into_bytes())?;
    writer.id(request.profile.into_bytes())?;
    writer.id(request.idempotency_key.into_bytes())?;
    encode_context_ids(writer, &request.context)?;
    encode_tool_ids(writer, &request.tools)?;
    encode_budget(writer, request.budget)
}

fn decode_request(
    reader: &mut Reader<'_>,
    limits: ModelStoreLimitsV1,
) -> Result<protocol::ExecuteRequestV1, CodecErrorV1> {
    let execution_id = protocol::ExecutionIdV1::new(reader.id()?);
    let task_attempt = protocol::TaskAttemptRefV1 {
        task_key: reader.id()?,
        task_incarnation: reader.number()?,
        attempt_number: u32::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
    };
    if task_attempt.attempt_number == 0 {
        return Err(CodecErrorV1::Invalid);
    }
    let request = protocol::ExecuteRequestV1 {
        execution_id,
        task_attempt,
        principal: protocol::PrincipalIdV1::new(reader.id()?),
        profile: protocol::HarnessProfileIdV1::new(reader.id()?),
        idempotency_key: protocol::IdempotencyKeyV1::new(reader.id()?),
        context: decode_context_ids(reader, limits.max_context_references)?,
        tools: decode_tool_ids(reader, limits.max_tools)?,
        budget: decode_budget(reader)?,
    };
    Ok(request)
}

fn encode_invocation(
    writer: &mut Writer,
    invocation: &protocol::ModelInvocationV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    writer.id(invocation.execution_id.into_bytes())?;
    let provider = &invocation.provider;
    writer.id(provider.provider.into_bytes())?;
    writer.id(provider.harness_profile.into_bytes())?;
    writer.byte(match provider.wire {
        protocol::ProviderWireProfileV1::OpenAiChatCompletions => 0,
    })?;
    writer.field(&provider.model, limits.max_model_bytes)?;
    writer.byte(u8::from(provider.structured_tools))?;
    writer.digest(provider.document_digest.into_bytes())?;
    writer.number(count(invocation.context.len())?)?;
    for evidence in &invocation.context {
        encode_evidence(writer, evidence, limits)?;
    }
    encode_tool_ids(writer, &invocation.tools)?;
    writer.number(count(invocation.messages.len())?)?;
    for message in &invocation.messages {
        writer.byte(role_tag(message.role))?;
        writer.field(&message.content, limits.max_message_bytes)?;
    }
    match &invocation.continuation {
        None => writer.byte(0)?,
        Some(continuation) => {
            writer.byte(1)?;
            writer.id(continuation.source_execution.into_bytes())?;
            writer.field(&continuation.source_output, limits.max_output_bytes)?;
            writer.number(count(continuation.results.len())?)?;
            for result in &continuation.results {
                writer.id(result.request)?;
                writer.id(result.capability.into_bytes())?;
                writer.field(&result.provider_correlation, limits.max_proposal_bytes)?;
                writer.field(&result.arguments, limits.max_proposal_bytes)?;
                writer.digest(result.evidence_digest.into_bytes())?;
                writer.digest(result.output_digest.into_bytes())?;
                writer.field(&result.output, limits.max_output_bytes)?;
            }
        }
    }
    writer.number(invocation.estimated_input_tokens)
}

fn decode_invocation(
    reader: &mut Reader<'_>,
    limits: ModelStoreLimitsV1,
) -> Result<protocol::ModelInvocationV1, CodecErrorV1> {
    let execution_id = protocol::ExecutionIdV1::new(reader.id()?);
    let provider = protocol::ProviderProfileSnapshotV1 {
        provider: protocol::ProviderProfileIdV1::new(reader.id()?),
        harness_profile: protocol::HarnessProfileIdV1::new(reader.id()?),
        wire: match reader.byte()? {
            0 => protocol::ProviderWireProfileV1::OpenAiChatCompletions,
            _ => return Err(CodecErrorV1::Invalid),
        },
        model: reader.field(limits.max_model_bytes)?,
        structured_tools: boolean(reader)?,
        document_digest: protocol::ContentDigestV1::new(reader.digest()?),
    };
    let context_count = reader.count(limits.max_context_references)?;
    let mut context = Vec::new();
    context
        .try_reserve(context_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..context_count {
        context.push(decode_evidence(reader, limits)?);
    }
    let tools = decode_tool_ids(reader, limits.max_tools)?;
    let message_count = reader.count(limits.max_messages)?;
    let mut messages = Vec::new();
    messages
        .try_reserve(message_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..message_count {
        messages.push(protocol::ModelMessageV1 {
            role: decode_role(reader.byte()?)?,
            content: reader.field(limits.max_message_bytes)?,
        });
    }
    let continuation = match reader.byte()? {
        0 => None,
        1 => {
            let source_execution = protocol::ExecutionIdV1::new(reader.id()?);
            let source_output = reader.field(limits.max_output_bytes)?;
            let count = reader.count(limits.max_proposals)?;
            let mut results = Vec::new();
            results
                .try_reserve(count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..count {
                results.push(protocol::ModelToolResultV1 {
                    request: reader.id()?,
                    capability: protocol::ToolCapabilityIdV1::new(reader.id()?),
                    provider_correlation: reader.field(limits.max_proposal_bytes)?,
                    arguments: reader.field(limits.max_proposal_bytes)?,
                    evidence_digest: protocol::ContentDigestV1::new(reader.digest()?),
                    output_digest: protocol::ContentDigestV1::new(reader.digest()?),
                    output: reader.field(limits.max_output_bytes)?,
                });
            }
            Some(protocol::ModelContinuationV1 {
                source_execution,
                source_output,
                results,
            })
        }
        _ => return Err(CodecErrorV1::Invalid),
    };
    Ok(protocol::ModelInvocationV1 {
        execution_id,
        provider,
        context,
        tools,
        messages,
        continuation,
        estimated_input_tokens: reader.number()?,
    })
}

fn encode_evidence(
    writer: &mut Writer,
    evidence: &protocol::ContextEvidenceV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    writer.id(evidence.reference.into_bytes())?;
    writer.byte(context_kind_tag(evidence.kind))?;
    writer.field(&evidence.bytes, limits.max_context_bytes)?;
    writer.digest(evidence.source_digest.into_bytes())?;
    match evidence.grounding {
        None => writer.byte(0),
        Some(grounding) => {
            writer.byte(1)?;
            writer.byte(match grounding.depth {
                protocol::GroundingDepthV1::Ambient => 0,
                protocol::GroundingDepthV1::Activated => 1,
                protocol::GroundingDepthV1::Reference => 2,
            })?;
            writer.digest(grounding.grounding_digest.into_bytes())?;
            writer.digest(grounding.surface_digest.into_bytes())
        }
    }
}

fn decode_evidence(
    reader: &mut Reader<'_>,
    limits: ModelStoreLimitsV1,
) -> Result<protocol::ContextEvidenceV1, CodecErrorV1> {
    let reference = protocol::ContextReferenceIdV1::new(reader.id()?);
    let kind = decode_context_kind(reader.byte()?)?;
    let bytes = reader.field(limits.max_context_bytes)?;
    let source_digest = protocol::ContentDigestV1::new(reader.digest()?);
    let grounding = match reader.byte()? {
        0 => None,
        1 => Some(protocol::GroundingEvidenceV1 {
            depth: match reader.byte()? {
                0 => protocol::GroundingDepthV1::Ambient,
                1 => protocol::GroundingDepthV1::Activated,
                2 => protocol::GroundingDepthV1::Reference,
                _ => return Err(CodecErrorV1::Invalid),
            },
            grounding_digest: protocol::ContentDigestV1::new(reader.digest()?),
            surface_digest: protocol::ContentDigestV1::new(reader.digest()?),
        }),
        _ => return Err(CodecErrorV1::Invalid),
    };
    if (kind == protocol::ContextKindV1::DendriteGrounding) != grounding.is_some() {
        return Err(CodecErrorV1::Invalid);
    }
    Ok(protocol::ContextEvidenceV1 {
        reference,
        kind,
        bytes,
        source_digest,
        grounding,
    })
}

fn encode_result(
    writer: &mut Writer,
    result: &protocol::ModelExecutionResultV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    writer.id(result.execution_id.into_bytes())?;
    writer.byte(disposition_tag(result.disposition))?;
    writer.digest(result.evidence_digest.into_bytes())?;
    writer.number(result.input_tokens)?;
    writer.number(result.output_tokens)?;
    writer.field(&result.output, limits.max_output_bytes)?;
    writer.number(count(result.proposals.len())?)?;
    for proposal in &result.proposals {
        match proposal {
            protocol::OutputProposalV1::AgoraMessage(proposal) => {
                writer.byte(1)?;
                writer.id(proposal.room)?;
                writer.id(proposal.reply_to)?;
                writer.field(&proposal.body, limits.max_proposal_bytes)?;
            }
            protocol::OutputProposalV1::VellumEdit(proposal) => {
                writer.byte(2)?;
                writer.id(proposal.workspace)?;
                writer.id(proposal.document)?;
                writer.number(proposal.expected_revision)?;
                writer.field(&proposal.replacement, limits.max_proposal_bytes)?;
            }
            protocol::OutputProposalV1::ToolCall(proposal) => {
                writer.byte(3)?;
                writer.id(proposal.request)?;
                writer.id(proposal.capability.into_bytes())?;
                writer.field(&proposal.provider_correlation, limits.max_proposal_bytes)?;
                writer.field(&proposal.arguments, limits.max_proposal_bytes)?;
            }
        }
    }
    Ok(())
}

fn decode_result(
    reader: &mut Reader<'_>,
    limits: ModelStoreLimitsV1,
    invocation: &protocol::ModelInvocationV1,
) -> Result<protocol::ModelExecutionResultV1, CodecErrorV1> {
    let execution_id = protocol::ExecutionIdV1::new(reader.id()?);
    let disposition = decode_disposition(reader.byte()?)?;
    let evidence_digest = protocol::ContentDigestV1::new(reader.digest()?);
    let input_tokens = reader.number()?;
    let output_tokens = reader.number()?;
    let output = reader.field(limits.max_output_bytes)?;
    let proposal_count = reader.count(limits.max_proposals)?;
    let mut proposals = Vec::new();
    proposals
        .try_reserve(proposal_count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..proposal_count {
        proposals.push(match reader.byte()? {
            1 => protocol::OutputProposalV1::AgoraMessage(protocol::AgoraMessageProposalV1 {
                room: reader.id()?,
                reply_to: reader.id()?,
                body: reader.field(limits.max_proposal_bytes)?,
            }),
            2 => protocol::OutputProposalV1::VellumEdit(protocol::VellumEditProposalV1 {
                workspace: reader.id()?,
                document: reader.id()?,
                expected_revision: reader.number()?,
                replacement: reader.field(limits.max_proposal_bytes)?,
            }),
            3 => protocol::OutputProposalV1::ToolCall(protocol::ToolCallProposalV1 {
                request: reader.id()?,
                capability: protocol::ToolCapabilityIdV1::new(reader.id()?),
                provider_correlation: reader.field(limits.max_proposal_bytes)?,
                arguments: reader.field(limits.max_proposal_bytes)?,
            }),
            _ => return Err(CodecErrorV1::Invalid),
        });
    }
    Ok(protocol::ModelExecutionResultV1 {
        execution_id,
        disposition,
        evidence_digest,
        invocation_evidence: Some(Box::new(protocol::model_invocation_evidence(invocation))),
        input_tokens,
        output_tokens,
        output,
        proposals,
    })
}

fn validate_context_shape(
    request: &protocol::ExecuteRequestV1,
    invocation: &protocol::ModelInvocationV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    let requested: BTreeSet<_> = request.context.iter().copied().collect();
    let supplied: BTreeSet<_> = invocation
        .context
        .iter()
        .map(|evidence| evidence.reference)
        .collect();
    let context_bytes = invocation
        .context
        .iter()
        .try_fold(0usize, |total, evidence| {
            total.checked_add(evidence.bytes.len())
        })
        .ok_or(CodecErrorV1::Limit)?;
    if requested.len() != request.context.len()
        || supplied.len() != invocation.context.len()
        || requested != supplied
        || invocation.tools != request.tools
        || invocation.tools.len() > limits.max_tools
        || context_bytes > limits.max_context_bytes
        || context_bytes > request.budget.max_context_bytes
        || invocation.context.iter().any(|evidence| {
            (evidence.kind == protocol::ContextKindV1::DendriteGrounding)
                != evidence.grounding.is_some()
        })
        || invocation
            .messages
            .iter()
            .any(|message| message.content.len() > limits.max_message_bytes)
        || invocation
            .continuation
            .as_ref()
            .is_some_and(|continuation| {
                continuation.source_execution.into_bytes() == [0; 16]
                    || continuation.source_execution == invocation.execution_id
                    || continuation.source_output.len() > limits.max_output_bytes
                    || continuation.results.is_empty()
                    || continuation.results.len() > limits.max_proposals
                    || continuation.results.iter().any(|result| {
                        result.request == [0; 16]
                            || !invocation.tools.contains(&result.capability)
                            || result.provider_correlation.is_empty()
                            || result.provider_correlation.len() > 1_024
                            || result.arguments.is_empty()
                            || result.arguments.len() > limits.max_proposal_bytes
                            || result.output.len() > limits.max_output_bytes
                    })
            })
    {
        return Err(CodecErrorV1::Invalid);
    }
    Ok(())
}

fn validate_result(
    request: &protocol::ExecuteRequestV1,
    invocation: &protocol::ModelInvocationV1,
    result: &protocol::ModelExecutionResultV1,
    limits: ModelStoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    let proposal_bytes = result
        .proposals
        .iter()
        .try_fold(0usize, |total, proposal| {
            let bytes = match proposal {
                protocol::OutputProposalV1::AgoraMessage(value) => value.body.len(),
                protocol::OutputProposalV1::VellumEdit(value) => value.replacement.len(),
                protocol::OutputProposalV1::ToolCall(value) => value.arguments.len(),
            };
            total.checked_add(bytes)
        })
        .ok_or(CodecErrorV1::Limit)?;
    if result.execution_id != request.execution_id
        || result.invocation_evidence.as_deref()
            != Some(&protocol::model_invocation_evidence(invocation))
        || result.input_tokens > request.budget.max_input_tokens
        || result.output_tokens > request.budget.max_output_tokens
        || result.output.len() > limits.max_output_bytes
        || result.output.len() > request.budget.max_output_bytes
        || result.proposals.len() > limits.max_proposals
        || proposal_bytes > limits.max_proposal_bytes
        || proposal_bytes > request.budget.max_output_bytes
    {
        return Err(CodecErrorV1::Invalid);
    }
    Ok(())
}

fn encode_context_ids(
    writer: &mut Writer,
    values: &[protocol::ContextReferenceIdV1],
) -> Result<(), CodecErrorV1> {
    writer.number(count(values.len())?)?;
    for value in values {
        writer.id(value.into_bytes())?;
    }
    Ok(())
}

fn decode_context_ids(
    reader: &mut Reader<'_>,
    maximum: usize,
) -> Result<Vec<protocol::ContextReferenceIdV1>, CodecErrorV1> {
    let count = reader.count(maximum)?;
    let mut values = Vec::new();
    values
        .try_reserve(count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..count {
        values.push(protocol::ContextReferenceIdV1::new(reader.id()?));
    }
    Ok(values)
}

fn encode_tool_ids(
    writer: &mut Writer,
    values: &[protocol::ToolCapabilityIdV1],
) -> Result<(), CodecErrorV1> {
    writer.number(count(values.len())?)?;
    for value in values {
        writer.id(value.into_bytes())?;
    }
    Ok(())
}

fn decode_tool_ids(
    reader: &mut Reader<'_>,
    maximum: usize,
) -> Result<Vec<protocol::ToolCapabilityIdV1>, CodecErrorV1> {
    let count = reader.count(maximum)?;
    let mut values = Vec::new();
    values
        .try_reserve(count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..count {
        values.push(protocol::ToolCapabilityIdV1::new(reader.id()?));
    }
    Ok(values)
}

fn encode_budget(
    writer: &mut Writer,
    budget: protocol::ExecutionBudgetV1,
) -> Result<(), CodecErrorV1> {
    writer.number(budget.max_elapsed_millis)?;
    writer.number(budget.max_input_tokens)?;
    writer.number(budget.max_output_tokens)?;
    writer.number(u64::from(budget.max_tool_calls))?;
    writer.number(count(budget.max_context_bytes)?)?;
    writer.number(count(budget.max_output_bytes)?)
}

fn decode_budget(reader: &mut Reader<'_>) -> Result<protocol::ExecutionBudgetV1, CodecErrorV1> {
    let budget = protocol::ExecutionBudgetV1 {
        max_elapsed_millis: reader.number()?,
        max_input_tokens: reader.number()?,
        max_output_tokens: reader.number()?,
        max_tool_calls: u32::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
        max_context_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
        max_output_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
    };
    if valid_budget(budget) {
        Ok(budget)
    } else {
        Err(CodecErrorV1::Invalid)
    }
}

fn valid_budget(budget: protocol::ExecutionBudgetV1) -> bool {
    budget.max_elapsed_millis != 0
        && budget.max_input_tokens != 0
        && budget.max_output_tokens != 0
        && budget.max_context_bytes != 0
        && budget.max_output_bytes != 0
}

fn boolean(reader: &mut Reader<'_>) -> Result<bool, CodecErrorV1> {
    match reader.byte()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecErrorV1::Invalid),
    }
}

fn context_kind_tag(kind: protocol::ContextKindV1) -> u8 {
    match kind {
        protocol::ContextKindV1::AgoraMessage => 0,
        protocol::ContextKindV1::ChronosWork => 1,
        protocol::ContextKindV1::VellumDocument => 2,
        protocol::ContextKindV1::DendriteGrounding => 3,
    }
}

fn decode_context_kind(value: u8) -> Result<protocol::ContextKindV1, CodecErrorV1> {
    Ok(match value {
        0 => protocol::ContextKindV1::AgoraMessage,
        1 => protocol::ContextKindV1::ChronosWork,
        2 => protocol::ContextKindV1::VellumDocument,
        3 => protocol::ContextKindV1::DendriteGrounding,
        _ => return Err(CodecErrorV1::Invalid),
    })
}

fn role_tag(role: protocol::MessageRoleV1) -> u8 {
    match role {
        protocol::MessageRoleV1::System => 0,
        protocol::MessageRoleV1::User => 1,
        protocol::MessageRoleV1::Assistant => 2,
        protocol::MessageRoleV1::Tool => 3,
    }
}

fn decode_role(value: u8) -> Result<protocol::MessageRoleV1, CodecErrorV1> {
    Ok(match value {
        0 => protocol::MessageRoleV1::System,
        1 => protocol::MessageRoleV1::User,
        2 => protocol::MessageRoleV1::Assistant,
        3 => protocol::MessageRoleV1::Tool,
        _ => return Err(CodecErrorV1::Invalid),
    })
}

fn disposition_tag(value: protocol::ExecutionDispositionV1) -> u8 {
    match value {
        protocol::ExecutionDispositionV1::Completed => 0,
        protocol::ExecutionDispositionV1::Failed => 1,
        protocol::ExecutionDispositionV1::Cancelled => 2,
        protocol::ExecutionDispositionV1::TimedOut => 3,
        protocol::ExecutionDispositionV1::Uncertain => 4,
    }
}

fn decode_disposition(value: u8) -> Result<protocol::ExecutionDispositionV1, CodecErrorV1> {
    Ok(match value {
        0 => protocol::ExecutionDispositionV1::Completed,
        1 => protocol::ExecutionDispositionV1::Failed,
        2 => protocol::ExecutionDispositionV1::Cancelled,
        3 => protocol::ExecutionDispositionV1::TimedOut,
        4 => protocol::ExecutionDispositionV1::Uncertain,
        _ => return Err(CodecErrorV1::Invalid),
    })
}

fn count(value: usize) -> Result<u64, CodecErrorV1> {
    u64::try_from(value).map_err(|_| CodecErrorV1::Limit)
}

fn validate_limits(limits: ModelStoreLimitsV1) -> Result<(), CodecErrorV1> {
    if limits.max_bytes == 0
        || limits.max_executions == 0
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_model_bytes == 0
        || limits.max_context_bytes == 0
        || limits.max_messages == 0
        || limits.max_message_bytes == 0
        || limits.max_output_bytes == 0
        || limits.max_proposals == 0
        || limits.max_proposal_bytes == 0
        || [
            limits.max_model_bytes,
            limits.max_context_bytes,
            limits.max_message_bytes,
            limits.max_output_bytes,
            limits.max_proposal_bytes,
        ]
        .into_iter()
        .any(|maximum| maximum > limits.max_bytes)
    {
        Err(CodecErrorV1::InvalidLimits)
    } else {
        Ok(())
    }
}
