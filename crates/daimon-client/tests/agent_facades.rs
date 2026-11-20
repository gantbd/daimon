use daimon_client::{AgentReadOnlyClient, AgentServicePort, AgentSessionClient};
use daimon_protocol::agent::{
    AgentCapabilitiesV1, AgentCommandV1, AgentEventPageV1, AgentOpenRequestV1, AgentOutcomeV1,
    AgentPermissionDecisionV1, AgentReplyV1, AgentResultBindingV1, AgentSessionBudgetV1,
    AgentSessionPhaseV1, AgentSessionViewV1, AgentTurnRequestV1, AgentTurnStopReasonV1,
};
use daimon_protocol::{
    AgentPermissionOptionIdV1, AgentPermissionRequestIdV1, AgentSessionIdV1, AgentTurnIdV1,
    ContentDigestV1, ContextReferenceIdV1, ExecuteRequestV1, ExecutionBudgetV1, ExecutionIdV1,
    HarnessProfileIdV1, IdempotencyKeyV1, PrincipalIdV1, SessionHandleV1, TaskAttemptRefV1,
};
use std::{cell::RefCell, convert::Infallible, rc::Rc};

struct Port {
    commands: Rc<RefCell<Vec<(SessionHandleV1, AgentCommandV1)>>>,
}

impl AgentServicePort for Port {
    type Error = Infallible;

    fn execute_agent(
        &mut self,
        service_session: SessionHandleV1,
        command: AgentCommandV1,
    ) -> Result<AgentReplyV1, Self::Error> {
        self.commands
            .borrow_mut()
            .push((service_session, command.clone()));
        let session = AgentSessionIdV1::new([1; 16]);
        Ok(match command {
            AgentCommandV1::Events { .. } => {
                AgentReplyV1::Accepted(AgentOutcomeV1::Events(AgentEventPageV1 {
                    session,
                    entries: Vec::new(),
                    next_after: None,
                }))
            }
            AgentCommandV1::Result { turn, .. } => {
                AgentReplyV1::Accepted(AgentOutcomeV1::Result(AgentResultBindingV1 {
                    session,
                    turn,
                    execution: ExecutionIdV1::new([10; 16]),
                    task_attempt: TaskAttemptRefV1 {
                        task_key: [10; 16],
                        task_incarnation: 1,
                        attempt_number: 1,
                    },
                    principal: PrincipalIdV1::new([3; 16]),
                    profile: HarnessProfileIdV1::new([4; 16]),
                    operation: IdempotencyKeyV1::new([11; 16]),
                    authority_decision: [13; 16],
                    authority_expires_at: 100,
                    prompt_digest: ContentDigestV1::new([12; 32]),
                    context_manifest_digest: ContentDigestV1::new([14; 32]),
                    event_start_cursor: 1,
                    terminal_cursor: 2,
                    terminal_revision: 2,
                    disposition: daimon_protocol::ExecutionDispositionV1::Completed,
                    stop_reason: AgentTurnStopReasonV1::EndTurn,
                    output_digest: Some(ContentDigestV1::new([15; 32])),
                }))
            }
            _ => AgentReplyV1::Accepted(AgentOutcomeV1::Session(AgentSessionViewV1 {
                session,
                revision: 1,
                phase: AgentSessionPhaseV1::Ready,
                profile_document_digest: ContentDigestV1::new([2; 32]),
                active_turn: None,
                last_event_cursor: None,
                last_context: None,
                capabilities: AgentCapabilitiesV1::default(),
            })),
        })
    }
}

fn port(commands: &Rc<RefCell<Vec<(SessionHandleV1, AgentCommandV1)>>>) -> Port {
    Port {
        commands: Rc::clone(commands),
    }
}

fn open_request() -> AgentOpenRequestV1 {
    AgentOpenRequestV1 {
        session: AgentSessionIdV1::new([1; 16]),
        execution: execution_request([9; 16], [6; 16]),
        workspace: [5; 16],
        budget: AgentSessionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_turns: 4,
            max_events: 64,
            max_event_bytes: 4_096,
            max_prompt_bytes: 1_024,
            max_permission_requests: 4,
        },
    }
}

fn turn_request() -> AgentTurnRequestV1 {
    AgentTurnRequestV1 {
        session: AgentSessionIdV1::new([1; 16]),
        turn: AgentTurnIdV1::new([8; 16]),
        expected_revision: 1,
        execution: execution_request([10; 16], [11; 16]),
        prompt_digest: ContentDigestV1::new([12; 32]),
        prompt: b"review this boundary".to_vec(),
    }
}

fn execution_request(execution: [u8; 16], idempotency: [u8; 16]) -> ExecuteRequestV1 {
    ExecuteRequestV1 {
        execution_id: ExecutionIdV1::new(execution),
        task_attempt: TaskAttemptRefV1 {
            task_key: [10; 16],
            task_incarnation: 1,
            attempt_number: 1,
        },
        principal: PrincipalIdV1::new([3; 16]),
        profile: HarnessProfileIdV1::new([4; 16]),
        idempotency_key: IdempotencyKeyV1::new(idempotency),
        context: vec![ContextReferenceIdV1::new([7; 16])],
        tools: Vec::new(),
        budget: ExecutionBudgetV1 {
            max_elapsed_millis: 1_000,
            max_input_tokens: 100,
            max_output_tokens: 100,
            max_tool_calls: 0,
            max_context_bytes: 4_096,
            max_output_bytes: 4_096,
        },
    }
}

#[test]
fn mutation_facade_preserves_exact_revision_identity_and_decision() {
    let commands = Rc::new(RefCell::new(Vec::new()));
    let mut client = AgentSessionClient::new(SessionHandleV1(13), port(&commands));
    client.open(open_request(), 20).unwrap();
    client.prompt(turn_request(), 21).unwrap();
    client
        .decide_permission(
            AgentSessionIdV1::new([1; 16]),
            2,
            execution_request([14; 16], [15; 16]),
            AgentPermissionDecisionV1 {
                request: AgentPermissionRequestIdV1::new([16; 16]),
                option: AgentPermissionOptionIdV1::new([17; 16]),
            },
            22,
        )
        .unwrap();
    client
        .reattach(
            AgentSessionIdV1::new([1; 16]),
            3,
            execution_request([19; 16], [20; 16]),
            23,
        )
        .unwrap();
    client
        .advance(
            AgentSessionIdV1::new([1; 16]),
            AgentTurnIdV1::new([8; 16]),
            4,
            IdempotencyKeyV1::new([18; 16]),
            24,
        )
        .unwrap();

    let captured = commands.borrow();
    assert_eq!(captured.len(), 5);
    assert!(matches!(
        captured[0],
        (SessionHandleV1(13), AgentCommandV1::Open { now: 20, .. })
    ));
    assert!(matches!(
        captured[1],
        (SessionHandleV1(13), AgentCommandV1::Prompt { now: 21, .. })
    ));
    let AgentCommandV1::DecidePermission {
        expected_revision,
        decision,
        now,
        ..
    } = &captured[2].1
    else {
        panic!("permission decision expected")
    };
    assert_eq!(*expected_revision, 2);
    assert_eq!(decision.request.into_bytes(), [16; 16]);
    assert_eq!(decision.option.into_bytes(), [17; 16]);
    assert_eq!(*now, 22);
    assert!(matches!(
        captured[3],
        (
            SessionHandleV1(13),
            AgentCommandV1::Reattach {
                expected_revision: 3,
                now: 23,
                ..
            }
        )
    ));
    assert!(matches!(
        captured[4],
        (
            SessionHandleV1(13),
            AgentCommandV1::Advance {
                expected_revision: 4,
                now: 24,
                ..
            }
        )
    ));
}

#[test]
fn read_only_facade_exposes_views_pages_and_owner_result_bindings_without_mutation_commands() {
    let commands = Rc::new(RefCell::new(Vec::new()));
    let mut client = AgentReadOnlyClient::new(SessionHandleV1(17), port(&commands));
    let session = AgentSessionIdV1::new([1; 16]);
    assert_eq!(client.current_view(session).unwrap().revision, 1);
    assert!(
        client
            .event_page(session, Some(8), 16)
            .unwrap()
            .entries
            .is_empty()
    );
    let turn = AgentTurnIdV1::new([8; 16]);
    let binding = client.result_binding(session, turn).unwrap();
    assert_eq!(binding.turn, turn);
    assert_eq!(binding.task_attempt.task_key, [10; 16]);

    let captured = commands.borrow();
    assert!(matches!(captured[0].1, AgentCommandV1::Inspect { .. }));
    assert!(matches!(
        captured[1].1,
        AgentCommandV1::Events {
            after: Some(8),
            limit: 16,
            ..
        }
    ));
    assert!(matches!(
        captured[2].1,
        AgentCommandV1::Result { turn, .. } if turn == AgentTurnIdV1::new([8; 16])
    ));
}

#[test]
fn prompt_debug_is_content_safe() {
    let debug = format!("{:?}", turn_request());
    assert!(debug.contains("prompt_bytes: 20"));
    assert!(!debug.contains("review this boundary"));
}
