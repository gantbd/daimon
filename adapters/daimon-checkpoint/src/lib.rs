//! Canonical bounded service-state checkpoint over Keystone's storage protocol.

#![forbid(unsafe_code)]

pub mod agent;
pub mod model;

use daimon_host::{
    ExecutionStore, ServiceSnapshotV1, StoreCommitV1, StoredExecutionStateV1, StoredExecutionV1,
};
use daimon_protocol as protocol;
use keystone_codec::{DecodeLimits, Decoder};
use keystone_storage::{
    AcknowledgementStrength, CheckpointStore, CommitGate, CommitGateFailure, CommitGateRefusal,
    StoreRefusal,
};

const KEY: &str = "daimon-service-v1";
const MAGIC: &[u8; 8] = b"DAIMONST";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimitsV1 {
    pub max_bytes: usize,
    pub max_executions: usize,
    pub max_context_references: usize,
    pub max_tools: usize,
    pub max_artifacts: usize,
}

impl Default for StoreLimitsV1 {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_executions: 65_536,
            max_context_references: 64,
            max_tools: 64,
            max_artifacts: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecErrorV1 {
    InvalidLimits,
    Limit,
    Capacity,
    Invalid,
    Truncated,
}

#[derive(Debug, Eq, PartialEq)]
pub enum StoreErrorV1<E> {
    Backend(E),
    Codec(CodecErrorV1),
    AlreadyInitialized,
    Missing,
    WeakLoad,
    NotLoaded,
    Fenced,
    RevisionExhausted,
    Refused(StoreRefusal),
    InvalidReceipt,
}

pub struct CheckpointExecutionStore<S> {
    backend: S,
    limits: StoreLimitsV1,
    gate: Option<CommitGate>,
    require_existing: bool,
}

impl<S: CheckpointStore> CheckpointExecutionStore<S> {
    pub fn create(backend: S, limits: StoreLimitsV1) -> Result<Self, StoreErrorV1<S::Error>> {
        validate_limits(limits).map_err(StoreErrorV1::Codec)?;
        let mut value = Self {
            backend,
            limits,
            gate: None,
            require_existing: false,
        };
        if value.load()?.is_some() {
            return Err(StoreErrorV1::AlreadyInitialized);
        }
        match value.commit(&ServiceSnapshotV1::default())? {
            StoreCommitV1::Committed => {
                value.require_existing = true;
                Ok(value)
            }
            StoreCommitV1::Indeterminate => Err(StoreErrorV1::InvalidReceipt),
        }
    }

    pub fn open_existing(
        backend: S,
        limits: StoreLimitsV1,
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

impl<S: CheckpointStore> ExecutionStore for CheckpointExecutionStore<S> {
    type Error = StoreErrorV1<S::Error>;

    fn load(&mut self) -> Result<Option<ServiceSnapshotV1>, Self::Error> {
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

    fn commit(&mut self, snapshot: &ServiceSnapshotV1) -> Result<StoreCommitV1, Self::Error> {
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
    max: usize,
}

impl Writer {
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }

    fn reserve(&mut self, amount: usize) -> Result<(), CodecErrorV1> {
        if self
            .bytes
            .len()
            .checked_add(amount)
            .is_none_or(|length| length > self.max)
        {
            return Err(CodecErrorV1::Limit);
        }
        self.bytes
            .try_reserve(amount)
            .map_err(|_| CodecErrorV1::Capacity)
    }

    fn byte(&mut self, value: u8) -> Result<(), CodecErrorV1> {
        self.reserve(1)?;
        self.bytes.push(value);
        Ok(())
    }

    fn number(&mut self, value: u64) -> Result<(), CodecErrorV1> {
        self.reserve(8)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn field(&mut self, value: &[u8]) -> Result<(), CodecErrorV1> {
        self.reserve(value.len().checked_add(4).ok_or(CodecErrorV1::Limit)?)?;
        keystone_codec::encode_bytes(&mut self.bytes, value).map_err(|_| CodecErrorV1::Limit)
    }

    fn id(&mut self, value: [u8; 16]) -> Result<(), CodecErrorV1> {
        self.field(&value)
    }
}

struct Reader<'a> {
    decoder: Decoder<'a>,
    identity_capacity: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: StoreLimitsV1) -> Result<Self, CodecErrorV1> {
        let per_execution = limits
            .max_context_references
            .checked_add(limits.max_tools.saturating_mul(2))
            .and_then(|value| value.checked_add(limits.max_artifacts))
            .and_then(|value| value.checked_add(32))
            .ok_or(CodecErrorV1::Limit)?;
        let fields = limits
            .max_executions
            .checked_mul(per_execution)
            .and_then(|value| value.checked_add(4))
            .ok_or(CodecErrorV1::Limit)?;
        Ok(Self {
            decoder: Decoder::new(
                bytes,
                DecodeLimits {
                    max_input_bytes: limits.max_bytes,
                    max_field_bytes: 16,
                    max_fields: fields,
                },
            )
            .map_err(|_| CodecErrorV1::Limit)?,
            identity_capacity: bytes.len() / 20,
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

    fn id(&mut self) -> Result<[u8; 16], CodecErrorV1> {
        self.decoder
            .read_bytes()
            .map_err(|_| CodecErrorV1::Truncated)?
            .try_into()
            .map_err(|_| CodecErrorV1::Invalid)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, CodecErrorV1> {
        let count = usize::try_from(self.number()?).map_err(|_| CodecErrorV1::Limit)?;
        if count > maximum.min(self.identity_capacity) {
            return Err(CodecErrorV1::Limit);
        }
        Ok(count)
    }

    fn ids<T>(
        &mut self,
        maximum: usize,
        make: impl Fn([u8; 16]) -> T,
    ) -> Result<Vec<T>, CodecErrorV1> {
        let count = self.count(maximum)?;
        let mut values = Vec::new();
        values
            .try_reserve(count)
            .map_err(|_| CodecErrorV1::Capacity)?;
        for _ in 0..count {
            values.push(make(self.id()?));
        }
        Ok(values)
    }

    fn finish(&self) -> Result<(), CodecErrorV1> {
        if self.decoder.is_finished() {
            Ok(())
        } else {
            Err(CodecErrorV1::Invalid)
        }
    }
}

pub fn encode(
    snapshot: &ServiceSnapshotV1,
    limits: StoreLimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    validate_limits(limits)?;
    if snapshot.executions.len() > limits.max_executions {
        return Err(CodecErrorV1::Limit);
    }
    let mut writer = Writer::new(limits.max_bytes);
    writer.field(MAGIC)?;
    writer.byte(1)?;
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

pub fn decode(bytes: &[u8], limits: StoreLimitsV1) -> Result<ServiceSnapshotV1, CodecErrorV1> {
    validate_limits(limits)?;
    let mut reader = Reader::new(bytes, limits)?;
    if reader
        .decoder
        .read_bytes()
        .map_err(|_| CodecErrorV1::Truncated)?
        != MAGIC
        || reader.byte()? != 1
    {
        return Err(CodecErrorV1::Invalid);
    }
    let count = reader.count(limits.max_executions)?;
    let mut executions = Vec::new();
    executions
        .try_reserve(count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    let mut previous = None;
    for _ in 0..count {
        let execution = decode_execution(&mut reader, limits)?;
        let current = execution.request.execution_id.into_bytes();
        if previous.is_some_and(|value| value >= current) {
            return Err(CodecErrorV1::Invalid);
        }
        previous = Some(current);
        executions.push(execution);
    }
    reader.finish()?;
    Ok(ServiceSnapshotV1 { executions })
}

fn encode_execution(
    writer: &mut Writer,
    execution: &StoredExecutionV1,
    limits: StoreLimitsV1,
) -> Result<(), CodecErrorV1> {
    let request = &execution.request;
    if request.context.len() > limits.max_context_references
        || request.tools.len() > limits.max_tools
        || execution.authority_tools.len() > limits.max_tools
        || request.task_attempt.attempt_number == 0
        || !valid_budget(request.budget)
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
    encode_ids(writer, &request.context, |value| value.into_bytes())?;
    encode_ids(writer, &request.tools, |value| value.into_bytes())?;
    encode_budget(writer, request.budget)?;
    writer.id(execution.authority_decision)?;
    writer.number(execution.authority_expires_at)?;
    encode_ids(writer, &execution.authority_tools, |value| {
        value.into_bytes()
    })?;
    writer.number(execution.prepared_at)?;
    match &execution.state {
        StoredExecutionStateV1::OutcomeUnknown => writer.byte(0),
        StoredExecutionStateV1::Completed(result) => {
            if result.execution_id != request.execution_id
                || result.produced_artifacts.len() > limits.max_artifacts
                || result.output_bytes > request.budget.max_output_bytes
            {
                return Err(CodecErrorV1::Invalid);
            }
            writer.byte(1)?;
            writer.id(result.execution_id.into_bytes())?;
            writer.byte(disposition_tag(result.disposition))?;
            writer.number(count(result.output_bytes)?)?;
            encode_ids(writer, &result.produced_artifacts, |value| {
                value.into_bytes()
            })
        }
    }
}

fn decode_execution(
    reader: &mut Reader<'_>,
    limits: StoreLimitsV1,
) -> Result<StoredExecutionV1, CodecErrorV1> {
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
        context: reader.ids(
            limits.max_context_references,
            protocol::ContextReferenceIdV1::new,
        )?,
        tools: reader.ids(limits.max_tools, protocol::ToolCapabilityIdV1::new)?,
        budget: decode_budget(reader)?,
    };
    let authority_decision = reader.id()?;
    let authority_expires_at = reader.number()?;
    let authority_tools = reader.ids(limits.max_tools, protocol::ToolCapabilityIdV1::new)?;
    let prepared_at = reader.number()?;
    let state = match reader.byte()? {
        0 => StoredExecutionStateV1::OutcomeUnknown,
        1 => {
            let result = protocol::ExecutionResultV1 {
                execution_id: protocol::ExecutionIdV1::new(reader.id()?),
                disposition: decode_disposition(reader.byte()?)?,
                output_bytes: usize::try_from(reader.number()?).map_err(|_| CodecErrorV1::Limit)?,
                produced_artifacts: reader
                    .ids(limits.max_artifacts, protocol::ArtifactReferenceIdV1::new)?,
            };
            if result.execution_id != execution_id {
                return Err(CodecErrorV1::Invalid);
            }
            StoredExecutionStateV1::Completed(result)
        }
        _ => return Err(CodecErrorV1::Invalid),
    };
    Ok(StoredExecutionV1 {
        request,
        authority_decision,
        authority_expires_at,
        authority_tools,
        prepared_at,
        state,
    })
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
    if !valid_budget(budget) {
        return Err(CodecErrorV1::Invalid);
    }
    Ok(budget)
}

fn valid_budget(budget: protocol::ExecutionBudgetV1) -> bool {
    budget.max_elapsed_millis != 0
        && budget.max_input_tokens != 0
        && budget.max_output_tokens != 0
        && budget.max_tool_calls != 0
        && budget.max_context_bytes != 0
        && budget.max_output_bytes != 0
}

fn encode_ids<T>(
    writer: &mut Writer,
    values: &[T],
    bytes: impl Fn(&T) -> [u8; 16],
) -> Result<(), CodecErrorV1> {
    writer.number(count(values.len())?)?;
    for value in values {
        writer.id(bytes(value))?;
    }
    Ok(())
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

fn validate_limits(limits: StoreLimitsV1) -> Result<(), CodecErrorV1> {
    if limits.max_bytes == 0
        || limits.max_executions == 0
        || limits.max_context_references == 0
        || limits.max_tools == 0
        || limits.max_artifacts == 0
    {
        Err(CodecErrorV1::InvalidLimits)
    } else {
        Ok(())
    }
}
