//! Provider-neutral contract for interactive agent sessions.
//!
//! This family is additive to terminal model execution. ACP is the first wire
//! profile, not a source of workflow authority.

use super::{
    AgentPermissionOptionIdV1, AgentPermissionRequestIdV1, AgentSessionIdV1, AgentTurnIdV1,
    ContentDigestV1, ContextKindV1, ContextReferenceIdV1, ExecuteRequestV1, ExecutionDispositionV1,
    ExecutionIdV1, GroundingEvidenceV1, HarnessProfileIdV1, IdempotencyKeyV1, ProviderProfileIdV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentWireProfileV1 {
    AgentClientProtocol,
    /// Claude Code's bidirectional Agent SDK NDJSON/control transport. This is
    /// deliberately distinct from ACP even though both are process transports.
    ClaudeAgentStreamJson,
}

/// Credential-free policy frozen before an agent process or remote session is
/// admitted. `command_digest` identifies administrator-owned launch material;
/// argv and secrets do not cross the public protocol.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentProfileSnapshotV1 {
    pub provider: ProviderProfileIdV1,
    pub harness_profile: HarnessProfileIdV1,
    pub wire: AgentWireProfileV1,
    pub command_digest: ContentDigestV1,
    pub policy_digest: ContentDigestV1,
    pub document_digest: ContentDigestV1,
}

impl std::fmt::Debug for AgentProfileSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentProfileSnapshotV1")
            .field("provider", &self.provider)
            .field("harness_profile", &self.harness_profile)
            .field("wire", &self.wire)
            .field("command_digest", &self.command_digest)
            .field("policy_digest", &self.policy_digest)
            .field("document_digest", &self.document_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentCapabilitiesV1 {
    pub load_session: bool,
    pub resume_session: bool,
    pub permissions: bool,
    pub filesystem_read: bool,
    pub filesystem_write: bool,
    pub terminal: bool,
    pub session_modes: bool,
    pub session_models: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentSessionBudgetV1 {
    pub max_elapsed_millis: u64,
    pub max_turns: u32,
    pub max_events: u64,
    pub max_event_bytes: usize,
    pub max_prompt_bytes: usize,
    pub max_permission_requests: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentOpenRequestV1 {
    pub session: AgentSessionIdV1,
    /// Opening a provider process/session is an execution effect and therefore
    /// carries the same exact authority, attempt, profile and idempotency input
    /// as any later turn.
    pub execution: ExecuteRequestV1,
    pub workspace: [u8; 16],
    pub budget: AgentSessionBudgetV1,
}

impl std::fmt::Debug for AgentOpenRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentOpenRequestV1")
            .field("session", &self.session)
            .field("execution", &self.execution)
            .field("workspace", &"<opaque>")
            .field("budget", &self.budget)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentTurnRequestV1 {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub expected_revision: u64,
    /// Reuses Daimon's exact principal/profile/attempt/authority/budget input.
    pub execution: ExecuteRequestV1,
    pub prompt_digest: ContentDigestV1,
    pub prompt: Vec<u8>,
}

impl std::fmt::Debug for AgentTurnRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentTurnRequestV1")
            .field("session", &self.session)
            .field("turn", &self.turn)
            .field("expected_revision", &self.expected_revision)
            .field("execution", &self.execution)
            .field("prompt_digest", &self.prompt_digest)
            .field("prompt_bytes", &self.prompt.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentPermissionOptionKindV1 {
    AllowOnce,
    AllowAlways,
    RejectOnce,
    RejectAlways,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPermissionOptionV1 {
    pub id: AgentPermissionOptionIdV1,
    pub kind: AgentPermissionOptionKindV1,
    pub label: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPermissionRequestV1 {
    pub request: AgentPermissionRequestIdV1,
    pub turn: AgentTurnIdV1,
    pub capability: Vec<u8>,
    pub description: Vec<u8>,
    pub options: Vec<AgentPermissionOptionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentPermissionDecisionV1 {
    pub request: AgentPermissionRequestIdV1,
    pub option: AgentPermissionOptionIdV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSessionPhaseV1 {
    Opening,
    Ready,
    /// Canonical session state is durable, but no live provider-process binding
    /// exists. Only an explicitly authorized `Reattach` may leave this phase.
    ReattachRequired,
    TurnActive,
    AwaitingPermission,
    OutcomeUnknown,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTurnStopReasonV1 {
    EndTurn,
    Cancelled,
    TimedOut,
    Failed,
    Disconnected,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventV1 {
    AssistantMessage {
        bytes: Vec<u8>,
    },
    Thought {
        bytes: Vec<u8>,
    },
    Plan {
        bytes: Vec<u8>,
    },
    ToolCall {
        title: Vec<u8>,
        detail: Vec<u8>,
    },
    Terminal {
        stream: Vec<u8>,
        bytes: Vec<u8>,
    },
    Permission(AgentPermissionRequestV1),
    FileChange {
        path: Vec<u8>,
        content_digest: ContentDigestV1,
    },
    FileRead {
        path: Vec<u8>,
        content_digest: ContentDigestV1,
        content_bytes: usize,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    TurnFinished {
        turn: AgentTurnIdV1,
        disposition: ExecutionDispositionV1,
        stop_reason: AgentTurnStopReasonV1,
        output_digest: Option<ContentDigestV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEventRecordV1 {
    pub cursor: u64,
    pub event: AgentEventV1,
}

/// Content-free identity of one context item admitted by Daimon for an exact
/// agent execution. The source digest binds the bytes retained by the context
/// owner; the bytes themselves remain outside public session telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentContextManifestEntryV1 {
    pub reference: ContextReferenceIdV1,
    pub kind: ContextKindV1,
    pub source_digest: ContentDigestV1,
    pub content_bytes: usize,
    pub grounding: Option<GroundingEvidenceV1>,
}

/// Daimon-owned receipt for the exact context identities admitted to one
/// successful provider operation. It is kept outside the provider event stream
/// so provider and service cursors cannot impersonate or collide with each
/// other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentContextReceiptV1 {
    pub execution: ExecutionIdV1,
    pub manifest_digest: ContentDigestV1,
    pub entries: Vec<AgentContextManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSessionViewV1 {
    pub session: AgentSessionIdV1,
    pub revision: u64,
    pub phase: AgentSessionPhaseV1,
    pub profile_document_digest: ContentDigestV1,
    pub active_turn: Option<AgentTurnIdV1>,
    pub last_event_cursor: Option<u64>,
    pub last_context: Option<AgentContextReceiptV1>,
    pub capabilities: AgentCapabilitiesV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEventPageV1 {
    pub session: AgentSessionIdV1,
    pub entries: Vec<AgentEventRecordV1>,
    pub next_after: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentCommandV1 {
    Open {
        request: AgentOpenRequestV1,
        now: u64,
    },
    Prompt {
        request: AgentTurnRequestV1,
        now: u64,
    },
    Events {
        session: AgentSessionIdV1,
        after: Option<u64>,
        limit: u64,
    },
    Inspect {
        session: AgentSessionIdV1,
    },
    /// Re-establishes an idle retained provider binding without replaying
    /// conversation history or submitting another prompt.
    Reattach {
        session: AgentSessionIdV1,
        expected_revision: u64,
        execution: ExecuteRequestV1,
        now: u64,
    },
    DecidePermission {
        session: AgentSessionIdV1,
        expected_revision: u64,
        /// Permission choice is a separately authorized exact execution, not
        /// authority inherited from provider text or from the original turn.
        execution: ExecuteRequestV1,
        decision: AgentPermissionDecisionV1,
        now: u64,
    },
    /// Drains one bounded slice of an already-authorized active provider turn.
    /// This observes/advances existing work and grants no new execution authority.
    Advance {
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    },
    Cancel {
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    },
    Close {
        session: AgentSessionIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentOutcomeV1 {
    Session(AgentSessionViewV1),
    Events(AgentEventPageV1),
    OutcomeUnknown {
        session: AgentSessionIdV1,
        idempotency_key: IdempotencyKeyV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRefusalV1 {
    UnknownServiceSession,
    PrincipalMismatch,
    UnknownAgentSession,
    UnknownTurn,
    UnknownPermissionRequest,
    UnknownPermissionOption,
    RevisionConflict,
    AuthorityDenied,
    AuthorityExpired,
    AttemptDenied,
    IdempotencyConflict,
    SessionConflict,
    TurnConflict,
    ProviderReceiptMismatch,
    ProviderReceiptConflict,
    Busy,
    Capacity,
    Limit,
    Unsupported,
    InvalidInput,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentReplyV1 {
    Accepted(AgentOutcomeV1),
    Refused(AgentRefusalV1),
}
