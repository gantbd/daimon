//! Daimon-owned exact-state guards for interactive agent operations.
//!
//! An advance observes the selected session on the same authenticated port,
//! fences the exact active turn and revision, and attempts the mutation once.
//! A transport failure is never retried because the provider slice may already
//! have been committed.
#![forbid(unsafe_code)]

use daimon_client::{AgentReadOnlyClient, AgentServicePort, AgentSessionClient};
use daimon_protocol::agent::{
    AgentOutcomeV1, AgentRefusalV1, AgentReplyV1, AgentSessionPhaseV1, AgentSessionViewV1,
};
use daimon_protocol::{AgentSessionIdV1, AgentTurnIdV1, IdempotencyKeyV1, SessionHandleV1};

pub const CAPABILITY: &str = "agents.session.advance.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvanceRequest {
    pub session: AgentSessionIdV1,
    pub turn: AgentTurnIdV1,
    pub expected_revision: u64,
    pub idempotency_key: IdempotencyKeyV1,
    pub now: u64,
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
        agent::{AgentCapabilitiesV1, AgentCommandV1},
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
