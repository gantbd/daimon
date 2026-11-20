//! Capability-shaped clients bound to one authenticated Daimon service session.

#[cfg(all(unix, feature = "unix"))]
pub mod unix;

use daimon_protocol::agent::{
    AgentCommandV1, AgentEventPageV1, AgentOpenRequestV1, AgentOutcomeV1,
    AgentPermissionDecisionV1, AgentReplyV1, AgentResultBindingV1, AgentSessionViewV1,
    AgentTurnRequestV1,
};
use daimon_protocol::{AgentSessionIdV1, AgentTurnIdV1, IdempotencyKeyV1};
use daimon_protocol::{
    CommandV1, ExecuteRequestV1, ExecutionIdV1, ExecutionPhaseV1, ModelCommandV1, ModelOutcomeV1,
    ModelReplyV1, OutcomeV1, RefusalV1, ReplyV1, ResumeToolResultV1, SessionHandleV1,
};

pub trait ServicePort {
    type Error;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error>;
}

/// Independent port for the additive model-execution protocol family.
pub trait ModelServicePort {
    type Error;

    fn execute_model(
        &mut self,
        session: SessionHandleV1,
        command: ModelCommandV1,
    ) -> Result<ModelReplyV1, Self::Error>;
}

/// Independent port for interactive agent sessions. It is not an alias for
/// terminal model execution.
pub trait AgentServicePort {
    type Error;

    fn execute_agent(
        &mut self,
        session: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error>;
}

pub struct AgentSessionClient<P> {
    service_session: SessionHandleV1,
    port: P,
}

impl<P: AgentServicePort> AgentSessionClient<P> {
    pub const fn new(service_session: SessionHandleV1, port: P) -> Self {
        Self {
            service_session,
            port,
        }
    }

    pub fn open(
        &mut self,
        request: AgentOpenRequestV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port
            .execute_agent(self.service_session, AgentCommandV1::Open { request, now })
    }

    pub fn prompt(
        &mut self,
        request: AgentTurnRequestV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Prompt { request, now },
        )
    }

    pub fn decide_permission(
        &mut self,
        session: AgentSessionIdV1,
        expected_revision: u64,
        execution: ExecuteRequestV1,
        decision: AgentPermissionDecisionV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::DecidePermission {
                session,
                expected_revision,
                execution,
                decision,
                now,
            },
        )
    }

    pub fn reattach(
        &mut self,
        session: AgentSessionIdV1,
        expected_revision: u64,
        execution: ExecuteRequestV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Reattach {
                session,
                expected_revision,
                execution,
                now,
            },
        )
    }

    pub fn cancel(
        &mut self,
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Cancel {
                session,
                turn,
                expected_revision,
                idempotency_key,
                now,
            },
        )
    }

    pub fn advance(
        &mut self,
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Advance {
                session,
                turn,
                expected_revision,
                idempotency_key,
                now,
            },
        )
    }

    pub fn close(
        &mut self,
        session: AgentSessionIdV1,
        expected_revision: u64,
        idempotency_key: IdempotencyKeyV1,
        now: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Close {
                session,
                expected_revision,
                idempotency_key,
                now,
            },
        )
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

pub struct AgentReadOnlyClient<P> {
    service_session: SessionHandleV1,
    port: P,
}

impl<P: AgentServicePort> AgentReadOnlyClient<P> {
    pub const fn new(service_session: SessionHandleV1, port: P) -> Self {
        Self {
            service_session,
            port,
        }
    }

    pub fn inspect(&mut self, session: AgentSessionIdV1) -> Result<AgentReplyV1, P::Error> {
        self.port
            .execute_agent(self.service_session, AgentCommandV1::Inspect { session })
    }

    pub fn events(
        &mut self,
        session: AgentSessionIdV1,
        after: Option<u64>,
        limit: u64,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Events {
                session,
                after,
                limit,
            },
        )
    }

    pub fn result(
        &mut self,
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
    ) -> Result<AgentReplyV1, P::Error> {
        self.port.execute_agent(
            self.service_session,
            AgentCommandV1::Result { session, turn },
        )
    }

    pub fn current_view(&mut self, session: AgentSessionIdV1) -> Option<AgentSessionViewV1> {
        match self.inspect(session) {
            Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Session(view))) => Some(view),
            _ => None,
        }
    }

    pub fn event_page(
        &mut self,
        session: AgentSessionIdV1,
        after: Option<u64>,
        limit: u64,
    ) -> Option<AgentEventPageV1> {
        match self.events(session, after, limit) {
            Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Events(page))) => Some(page),
            _ => None,
        }
    }

    pub fn result_binding(
        &mut self,
        session: AgentSessionIdV1,
        turn: AgentTurnIdV1,
    ) -> Option<AgentResultBindingV1> {
        match self.result(session, turn) {
            Ok(AgentReplyV1::Accepted(AgentOutcomeV1::Result(binding))) => Some(binding),
            _ => None,
        }
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

pub struct ExecutionClient<P> {
    session: SessionHandleV1,
    port: P,
}

impl<P: ServicePort> ExecutionClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self { session, port }
    }

    pub fn execute(&mut self, request: ExecuteRequestV1, now: u64) -> Result<ReplyV1, P::Error> {
        self.port
            .execute(self.session, CommandV1::Execute { request, now })
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

pub struct ModelExecutionClient<P> {
    session: SessionHandleV1,
    port: P,
}

impl<P: ModelServicePort> ModelExecutionClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self { session, port }
    }

    pub fn execute(
        &mut self,
        request: ExecuteRequestV1,
        now: u64,
    ) -> Result<ModelReplyV1, P::Error> {
        self.port
            .execute_model(self.session, ModelCommandV1::Execute { request, now })
    }

    pub fn resume(
        &mut self,
        request: ExecuteRequestV1,
        source_execution: ExecutionIdV1,
        results: Vec<ResumeToolResultV1>,
        now: u64,
    ) -> Result<ModelReplyV1, P::Error> {
        self.port.execute_model(
            self.session,
            ModelCommandV1::Resume {
                request,
                source_execution,
                results,
                now,
            },
        )
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

/// Current status as disclosed to the authenticated client session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatusV1 {
    Observed(ExecutionPhaseV1),
    Missing,
    Denied,
    Unavailable,
}

pub struct ReadOnlyClient<P> {
    session: SessionHandleV1,
    port: P,
}

pub struct ModelReadOnlyClient<P> {
    session: SessionHandleV1,
    port: P,
}

impl<P: ModelServicePort> ModelReadOnlyClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self { session, port }
    }

    pub fn inspect(&mut self, execution_id: ExecutionIdV1) -> Result<ModelReplyV1, P::Error> {
        self.port
            .execute_model(self.session, ModelCommandV1::Inspect { execution_id })
    }

    pub fn inspect_status(&mut self, expected: ExecutionIdV1) -> ExecutionStatusV1 {
        match self.inspect(expected) {
            Ok(ModelReplyV1::Accepted(ModelOutcomeV1::Status {
                execution_id,
                phase,
            })) if execution_id == expected => ExecutionStatusV1::Observed(phase),
            Ok(ModelReplyV1::Refused(RefusalV1::UnknownExecution)) => ExecutionStatusV1::Missing,
            Ok(ModelReplyV1::Refused(
                RefusalV1::UnknownSession
                | RefusalV1::PrincipalMismatch
                | RefusalV1::AuthorityDenied
                | RefusalV1::AuthorityExpired,
            )) => ExecutionStatusV1::Denied,
            _ => ExecutionStatusV1::Unavailable,
        }
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

impl<P: ServicePort> ReadOnlyClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self { session, port }
    }

    pub fn inspect(&mut self, execution_id: ExecutionIdV1) -> Result<ReplyV1, P::Error> {
        self.port
            .execute(self.session, CommandV1::Inspect { execution_id })
    }

    pub fn read_presence(&mut self, limit: u8) -> Result<ReplyV1, P::Error> {
        self.port
            .execute(self.session, CommandV1::ReadPresence { limit })
    }

    pub fn inspect_status(&mut self, expected: ExecutionIdV1) -> ExecutionStatusV1 {
        match self.inspect(expected) {
            Ok(ReplyV1::Accepted(OutcomeV1::Status {
                execution_id,
                phase,
            })) if execution_id == expected => ExecutionStatusV1::Observed(phase),
            Ok(ReplyV1::Refused(RefusalV1::UnknownExecution)) => ExecutionStatusV1::Missing,
            Ok(ReplyV1::Refused(
                RefusalV1::UnknownSession
                | RefusalV1::PrincipalMismatch
                | RefusalV1::AuthorityDenied
                | RefusalV1::AuthorityExpired,
            )) => ExecutionStatusV1::Denied,
            _ => ExecutionStatusV1::Unavailable,
        }
    }

    pub fn into_port(self) -> P {
        self.port
    }
}
