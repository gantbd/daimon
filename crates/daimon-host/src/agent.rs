//! Trusted ports for interactive agent-session composition.
//!
//! Provider receipts are observations, not workflow authority. Implementations
//! must perform at most one external admission for one invocation.

use crate::{AuthenticatedSessionV1, ContextRefusalV1, ProfileRefusalV1};
use daimon_protocol::agent::{
    AgentCapabilitiesV1, AgentEventRecordV1, AgentOpenRequestV1, AgentPermissionDecisionV1,
    AgentProfileSnapshotV1, AgentSessionPhaseV1, AgentSessionViewV1, AgentTurnRequestV1,
};
use daimon_protocol::{AgentSessionIdV1, AgentTurnIdV1, ExecuteRequestV1, IdempotencyKeyV1};
use daimon_protocol::{ContentDigestV1, ContextEvidenceV1, ToolCapabilityIdV1};

pub const MAX_AGENT_PROVIDER_LOCATOR_BYTES: usize = 4_096;

/// Provider-owned durable session locator. It is checkpointed inside Daimon's
/// trusted host boundary and never exposed as a public session identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProviderRecoveryV1 {
    pub locator: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentFileReadRequestV1 {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub workspace: [u8; 16],
    pub execution: ExecuteRequestV1,
    /// Caller-supplied logical time from the exact provider continuation that
    /// observed this callback. Governors must use it for fresh authority checks.
    pub now: u64,
    pub path: Vec<u8>,
    pub line: Option<u64>,
    pub limit: Option<u64>,
}

impl std::fmt::Debug for AgentFileReadRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentFileReadRequestV1")
            .field("session", &self.session)
            .field("turn", &self.turn)
            .field("workspace", &"<opaque>")
            .field("execution", &self.execution)
            .field("now", &self.now)
            .field("path", &"<redacted>")
            .field("line", &self.line)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentFileReadReceiptV1 {
    /// Safe workspace-relative path retained as provider evidence.
    pub path: Vec<u8>,
    pub content: Vec<u8>,
    pub content_digest: ContentDigestV1,
}

impl std::fmt::Debug for AgentFileReadReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentFileReadReceiptV1")
            .field("path", &"<redacted>")
            .field(
                "content",
                &format_args!("<{} bytes redacted>", self.content.len()),
            )
            .field("content_digest", &self.content_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentFileReadRefusalV1 {
    Invalid,
    Denied,
    Limit,
    Failed,
}

/// Use-time client-filesystem mediation for ACP providers. Implementations own
/// scope, authority and attempt validation; adapter capability advertisement is
/// false unless this port affirms the exact frozen open binding.
pub trait AgentClientFileReader {
    fn supports_agent_file_read(
        &self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> bool;

    fn read_agent_file(
        &mut self,
        request: &AgentFileReadRequestV1,
    ) -> Result<AgentFileReadReceiptV1, AgentFileReadRefusalV1>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentTerminalCreateRequestV1 {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub workspace: [u8; 16],
    pub execution: ExecuteRequestV1,
    /// Logical time of the provider continuation issuing the create request.
    pub now: u64,
    pub command: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
    pub cwd: Vec<u8>,
    pub output_byte_limit: Option<u64>,
}

impl std::fmt::Debug for AgentTerminalCreateRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentTerminalCreateRequestV1")
            .field("session", &self.session)
            .field("turn", &self.turn)
            .field("workspace", &"<opaque>")
            .field("execution", &self.execution)
            .field("now", &self.now)
            .field("command", &"<redacted>")
            .field(
                "arguments",
                &format_args!("<{} redacted>", self.arguments.len()),
            )
            .field(
                "environment",
                &format_args!("<{} redacted>", self.environment.len()),
            )
            .field("cwd", &"<redacted>")
            .field("output_byte_limit", &self.output_byte_limit)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTerminalCreatedV1 {
    /// Host-owned, session-scoped opaque handle. It is never executable text.
    pub terminal_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTerminalExitV1 {
    pub exit_code: Option<i32>,
    /// ACP v1 signal name (for example `SIGTERM`), not a platform number.
    pub signal: Option<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentTerminalOutputV1 {
    pub output: Vec<u8>,
    pub truncated: bool,
    pub exit: Option<AgentTerminalExitV1>,
}

impl std::fmt::Debug for AgentTerminalOutputV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentTerminalOutputV1")
            .field(
                "output",
                &format_args!("<{} bytes redacted>", self.output.len()),
            )
            .field("truncated", &self.truncated)
            .field("exit", &self.exit)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTerminalRefusalV1 {
    Invalid,
    Denied,
    Capacity,
    NotFound,
    Failed,
}

/// Session-owned ACP terminal mediation. Creation is a fresh external effect
/// and implementations must re-check exact authority and attempt at `now`.
/// All other operations are confined to the returned session-owned handle.
pub trait AgentClientTerminal {
    fn supports_agent_terminal(
        &self,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> bool;

    fn create_agent_terminal(
        &mut self,
        request: &AgentTerminalCreateRequestV1,
    ) -> Result<AgentTerminalCreatedV1, AgentTerminalRefusalV1>;

    fn output_agent_terminal(
        &mut self,
        session: AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<AgentTerminalOutputV1, AgentTerminalRefusalV1>;

    /// `None` means the handle is still running; this call must not block.
    fn poll_agent_terminal_exit(
        &mut self,
        session: AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<Option<AgentTerminalExitV1>, AgentTerminalRefusalV1>;

    fn kill_agent_terminal(
        &mut self,
        session: AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1>;

    fn release_agent_terminal(
        &mut self,
        session: AgentSessionIdV1,
        terminal_id: &[u8],
    ) -> Result<(), AgentTerminalRefusalV1>;

    fn release_agent_terminals(&mut self, session: AgentSessionIdV1);
}

pub trait AgentProfileResolver {
    fn resolve_agent_profile(
        &mut self,
        service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
    ) -> Result<AgentProfileSnapshotV1, ProfileRefusalV1>;
}

pub trait AgentContextAssembler {
    fn assemble_agent_context(
        &mut self,
        service_session: &AuthenticatedSessionV1,
        request: &AgentOpenRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<ContextEvidenceV1>, ContextRefusalV1>;

    fn assemble_agent_turn_context(
        &mut self,
        service_session: &AuthenticatedSessionV1,
        request: &AgentTurnRequestV1,
        profile: &AgentProfileSnapshotV1,
    ) -> Result<Vec<ContextEvidenceV1>, ContextRefusalV1>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentProviderInvocationV1 {
    Open {
        request: AgentOpenRequestV1,
        profile: AgentProfileSnapshotV1,
        context: Vec<ContextEvidenceV1>,
    },
    Reattach {
        session: AgentSessionIdV1,
        execution: ExecuteRequestV1,
        original_open: Box<AgentOpenRequestV1>,
        profile: AgentProfileSnapshotV1,
        context: Vec<ContextEvidenceV1>,
        recovery: AgentProviderRecoveryV1,
        now: u64,
    },
    Prompt {
        request: AgentTurnRequestV1,
        profile: AgentProfileSnapshotV1,
        context: Vec<ContextEvidenceV1>,
        now: u64,
    },
    DecidePermission {
        session: AgentSessionIdV1,
        execution: daimon_protocol::ExecuteRequestV1,
        decision: AgentPermissionDecisionV1,
        now: u64,
    },
    Advance {
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    },
    Cancel {
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        idempotency_key: IdempotencyKeyV1,
    },
    Close {
        session: AgentSessionIdV1,
        idempotency_key: IdempotencyKeyV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProviderReceiptV1 {
    pub session: AgentSessionIdV1,
    pub provider_document_digest: ContentDigestV1,
    pub phase: AgentSessionPhaseV1,
    pub active_turn: Option<AgentTurnIdV1>,
    pub capabilities: AgentCapabilitiesV1,
    pub recovery: Option<AgentProviderRecoveryV1>,
    pub events: Vec<AgentEventRecordV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentProviderOutcomeV1 {
    Receipt(AgentProviderReceiptV1),
    OutcomeUnknown,
}

pub trait AgentProvider {
    /// Performs one provider admission. Implementations must not retry
    /// implicitly after a write or ambiguous process/transport outcome.
    fn invoke_agent(&mut self, invocation: &AgentProviderInvocationV1) -> AgentProviderOutcomeV1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredAgentOperationInputV1 {
    Reattach {
        expected_revision: u64,
        execution: ExecuteRequestV1,
    },
    Prompt(AgentTurnRequestV1),
    Permission {
        expected_revision: u64,
        execution: ExecuteRequestV1,
        decision: AgentPermissionDecisionV1,
    },
    Advance {
        turn: AgentTurnIdV1,
        expected_revision: u64,
    },
    Cancel {
        turn: AgentTurnIdV1,
        expected_revision: u64,
    },
    Close {
        expected_revision: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredAgentOperationStateV1 {
    OutcomeUnknown,
    Completed(AgentSessionViewV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAgentPreparationV1 {
    pub authority_decision: [u8; 16],
    pub authority_expires_at: u64,
    pub authority_tools: Vec<ToolCapabilityIdV1>,
    pub prepared_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAgentOperationV1 {
    pub idempotency_key: IdempotencyKeyV1,
    pub input: StoredAgentOperationInputV1,
    /// Present for authority-bearing prompt and permission operations; absent
    /// for cancel and close authority attenuations.
    pub preparation: Option<StoredAgentPreparationV1>,
    pub state: StoredAgentOperationStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAgentSessionV1 {
    pub request: AgentOpenRequestV1,
    pub open_preparation: StoredAgentPreparationV1,
    pub profile: AgentProfileSnapshotV1,
    pub revision: u64,
    pub phase: AgentSessionPhaseV1,
    pub active_turn: Option<AgentTurnIdV1>,
    pub capabilities: AgentCapabilitiesV1,
    pub recovery: Option<AgentProviderRecoveryV1>,
    pub events: Vec<AgentEventRecordV1>,
    pub operations: Vec<StoredAgentOperationV1>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentServiceSnapshotV1 {
    pub sessions: Vec<StoredAgentSessionV1>,
}

/// Durable agent state. An indeterminate commit fences provider admission.
pub trait AgentSessionStore {
    type Error;

    fn load_agents(&mut self) -> Result<Option<AgentServiceSnapshotV1>, Self::Error>;

    fn commit_agents(
        &mut self,
        snapshot: &AgentServiceSnapshotV1,
    ) -> Result<crate::StoreCommitV1, Self::Error>;
}
